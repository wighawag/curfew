// Package enforce owns the nftables ruleset. It is the ONLY thing that writes
// to the curfew table.
//
// Three properties are deliberate and load-bearing:
//
//   - ApplyDesired replaces the WHOLE table in a single netlink transaction,
//     rather than surgically editing it. There is no partial rebuild to get
//     wrong and no window in which the household is unprotected. Measured to
//     work, including carrying live timeout-set elements, in
//     work/notes/findings/google-nftables-drives-the-kernel-and-replaces-rulesets-atomically.md
//
//   - Because of that whole-table replace, live TICKETS are read back off the
//     kernel and re-emitted with their remaining deadlines inside the same
//     transaction. Without that step every reconcile tick would silently reset
//     every ticket, so a 15-minute ticket would never expire.
//
//   - Nothing here swallows an error. The defining failure of the shell
//     implementation this replaces was reporting success while enforcing
//     nothing, because every nft call ended in 2>/dev/null. Every failure
//     below is returned.
//
// The rule ORDER inside the policy chain is not written here at all: it is
// contract.Tiers, walked in order, so that this package and the UI cannot
// disagree about what outranks what. The decision behind that order is
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md.
package enforce

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/wighawag/curfew/internal/contract"
)

// The object names live in internal/contract because internal/deploy needs
// them too, and the laptop binary may not import this package.
const (
	TableName        = contract.Table
	AllowedSet       = contract.AllowedSet
	BlockedSet       = contract.BlockedSet
	ManualBlockedSet = contract.ManualBlockedSet
	TicketSet        = contract.TicketSet
	PolicyChain      = contract.PolicyChain
	BaseChain        = contract.BaseChain
	HookPriority     = contract.HookPriority
)

// MaxTicket caps how long a single ticket may last. A grant with no ceiling is
// not a time-limited grant, and a fat-fingered duration should not be able to
// become an accidental permanent hole above the schedule.
const MaxTicket = 12 * time.Hour

// Config names the interfaces the policy applies between. Both are required:
// guessing them is how the original implementation silently matched nothing
// when the WAN device turned out to be pppoe-wan rather than eth1.
type Config struct {
	LANInterface string
	WANInterface string
}

func (c Config) validate() error {
	if c.LANInterface == "" {
		return errors.New("LAN interface not set")
	}
	if c.WANInterface == "" {
		return errors.New("WAN interface not set")
	}
	return nil
}

// Desired is the whole ruleset the policy layer wants, one MAC list per tier
// that is computed rather than lived.
//
// There is deliberately NO ticket field. A ticket is live kernel state with a
// deadline the kernel owns: it is read back and carried across a rebuild, not
// re-derived from config. Putting it here would invite a caller to "re-apply"
// tickets, which is precisely how their deadlines would get reset.
type Desired struct {
	// Allowed is every registered MAC.
	Allowed []string
	// Blocked is every MAC blocked by a schedule window or an exhausted
	// budget: the reasons the system COMPUTES.
	Blocked []string
	// Manual is every MAC blocked by a parent until they say otherwise: the
	// reason the system STORES.
	Manual []string
}

// forSet returns the MACs belonging to one tier's set.
//
// The unknown-tier case is an error rather than an empty list on purpose:
// adding a tier to contract.Tiers without teaching this function about it
// would otherwise ship a rule matching a permanently empty set, which is a
// silently-disabled policy of exactly the kind this project exists to remove.
func (d Desired) forSet(name string) ([]string, error) {
	switch name {
	case contract.AllowedSet:
		return d.Allowed, nil
	case contract.BlockedSet:
		return d.Blocked, nil
	case contract.ManualBlockedSet:
		return d.Manual, nil
	default:
		return nil, fmt.Errorf("no desired state is computed for set %q: "+
			"a tier was added to contract.Tiers without wiring it up here", name)
	}
}

// Enforcer applies rulesets. The zero value is not usable; use New.
type Enforcer struct {
	cfg  Config
	conn *nftables.Conn
}

// New opens a netlink connection to the kernel's nftables subsystem.
func New(cfg Config) (*Enforcer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("opening netlink connection: %w", err)
	}
	return &Enforcer{cfg: cfg, conn: conn}, nil
}

// ifname renders an interface name as nftables expects it: a fixed 16-byte
// NUL-padded buffer.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func (e *Enforcer) tableRef() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
}

// exists reports whether our table is present. Needed because queueing a
// delete for a table that does not exist fails the whole batch with ENOENT.
func (e *Enforcer) exists() (bool, error) {
	tables, err := e.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}

// lookupSet finds a set by name, reporting absence separately from failure.
//
// GetSetByName reports both as an error, and the two must not be confused
// here: "the ticket set is not there" is a normal state during a rebuild,
// while "netlink is broken" must never be read as "there are no tickets".
func (e *Enforcer) lookupSet(name string) (*nftables.Set, bool, error) {
	sets, err := e.conn.GetSets(e.tableRef())
	if err != nil {
		return nil, false, fmt.Errorf("listing sets in %s: %w", TableName, err)
	}
	for _, s := range sets {
		if s.Name == name {
			return s, true, nil
		}
	}
	return nil, false, nil
}

func parseMACs(list []string, what string) ([][]byte, error) {
	out := make([][]byte, 0, len(list))
	for _, m := range list {
		hw, err := net.ParseMAC(m)
		if err != nil {
			return nil, fmt.Errorf("%s entry %q: %w", what, m, err)
		}
		if len(hw) != 6 {
			return nil, fmt.Errorf("%s entry %q: want a 6-octet MAC, got %d octets", what, m, len(hw))
		}
		out = append(out, []byte(hw))
	}
	return out, nil
}

// ApplyDesired makes the firewall match d exactly, replacing the whole table in
// one transaction and carrying live tickets across with their remaining time.
//
// Passing empty lists is meaningful and allowed: an empty allowlist means
// nothing in the house reaches the internet, which is what an empty registry
// genuinely implies.
func (e *Enforcer) ApplyDesired(d Desired) error {
	parsed := make(map[string][][]byte, len(contract.Tiers))
	for _, tier := range contract.Tiers {
		if tier.KernelTimeout {
			// Live state, not desired state. Handled by the carry-over below.
			continue
		}
		list, err := d.forSet(tier.Set)
		if err != nil {
			return err
		}
		macs, err := parseMACs(list, tier.Set)
		if err != nil {
			return err
		}
		parsed[tier.Set] = macs
	}

	present, err := e.exists()
	if err != nil {
		return err
	}

	// Read the live tickets BEFORE the table goes, so they can be re-emitted
	// with the time they have left. Skipping this would reset every ticket on
	// every reconcile tick, which makes a 15-minute grant permanent.
	carried := map[string][]nftables.SetElement{}
	if present {
		for _, tier := range contract.Tiers {
			if !tier.KernelTimeout {
				continue
			}
			live, err := e.liveElements(tier.Set)
			if err != nil {
				return err
			}
			carried[tier.Set] = withoutMACs(live, parsed[contract.ManualBlockedSet])
		}
	}

	t := e.tableRef()
	if present {
		// Delete and rebuild inside the SAME batch, so the ruleset is swapped
		// rather than removed and then recreated.
		e.conn.DelTable(t)
	}
	t = e.conn.AddTable(t)

	sets := make(map[string]*nftables.Set, len(contract.Tiers))
	for _, tier := range contract.Tiers {
		set := &nftables.Set{
			Table: t, Name: tier.Set, KeyType: nftables.TypeEtherAddr,
			HasTimeout: tier.KernelTimeout,
		}
		var elements []nftables.SetElement
		if tier.KernelTimeout {
			elements = carried[tier.Set]
		} else {
			for _, k := range parsed[tier.Set] {
				elements = append(elements, nftables.SetElement{Key: k})
			}
		}
		if err := e.conn.AddSet(set, elements); err != nil {
			return fmt.Errorf("building %s: %w", tier.Set, err)
		}
		sets[tier.Set] = set
	}

	policy := e.conn.AddChain(&nftables.Chain{Table: t, Name: PolicyChain})

	// The ordering contract, walked in order. The terminal drop must be LAST,
	// because a rule after a terminal verdict is unreachable, which is one of
	// the defects this rewrite exists to remove.
	for _, tier := range contract.Tiers {
		set := sets[tier.Set]
		verdict := expr.VerdictDrop
		if tier.Accept {
			verdict = expr.VerdictAccept
		}
		e.conn.AddRule(&nftables.Rule{Table: t, Chain: policy, Exprs: []expr.Any{
			// ether saddr lives at offset 6, length 6, of the link-layer header.
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			&expr.Verdict{Kind: verdict},
		}})
	}
	e.conn.AddRule(&nftables.Rule{Table: t, Chain: policy, Exprs: []expr.Any{
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})

	prio := nftables.ChainPriority(HookPriority)
	pol := nftables.ChainPolicyAccept
	base := e.conn.AddChain(&nftables.Chain{
		Table:    t,
		Name:     BaseChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &prio,
		Policy:   &pol,
	})

	// Narrow to LAN-to-WAN before jumping. Without this the policy would also
	// apply to LAN-to-LAN traffic, so an unregistered device could not reach
	// the printer, which is not what "no internet" is supposed to mean.
	e.conn.AddRule(&nftables.Rule{Table: t, Chain: base, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(e.cfg.LANInterface)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(e.cfg.WANInterface)},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: PolicyChain},
	}})

	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}
	return nil
}

// liveElements reads a timeout set's current members and returns them ready to
// be re-added with the time they have LEFT rather than the time they were
// granted.
//
// Elements with no time left, and elements carrying no deadline at all, are
// dropped. That direction is chosen deliberately: a carried element with a
// zero timeout would become PERMANENT, so a ticket that lost its deadline
// would silently outrank the schedule forever. Lapsing a moment early is
// recoverable; never lapsing is the bug this system exists to prevent.
func (e *Enforcer) liveElements(setName string) ([]nftables.SetElement, error) {
	set, ok, err := e.lookupSet(setName)
	if err != nil {
		return nil, err
	}
	if !ok {
		// The table predates this set, or was built by hand. There is nothing
		// live to carry.
		return nil, nil
	}
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("reading %s elements: %w", setName, err)
	}
	var out []nftables.SetElement
	for _, el := range elements {
		if el.Expires <= 0 {
			continue
		}
		out = append(out, nftables.SetElement{Key: el.Key, Timeout: el.Expires})
	}
	return out, nil
}

// withoutMACs drops any element whose key is in exclude.
//
// This is what makes "a manual block cancels a ticket" structural rather than
// a step someone can forget: a MAC a parent has blocked cannot come out of a
// rebuild still holding a ticket, whichever path put the ticket there.
func withoutMACs(elements []nftables.SetElement, exclude [][]byte) []nftables.SetElement {
	if len(exclude) == 0 {
		return elements
	}
	var out []nftables.SetElement
	for _, el := range elements {
		if slices.ContainsFunc(exclude, func(k []byte) bool { return slices.Equal(k, el.Key) }) {
			continue
		}
		out = append(out, el)
	}
	return out
}

// GrantTicket gives these MACs internet access for d, using a KERNEL timeout.
//
// Nothing is scheduled, saved or remembered: when the kernel reclaims the
// element the profile falls back to whatever reasons are live at that moment.
// That is the whole design of a ticket, and it is why a ticket cannot survive
// a reboot and is not supposed to.
//
// It fails loudly when the table is absent rather than creating one. A
// non-owner that quietly builds a bare table is the exact mechanism by which
// the previous system reported success while enforcing nothing.
func (e *Enforcer) GrantTicket(macs []string, d time.Duration) error {
	if len(macs) == 0 {
		return errors.New("a ticket needs at least one device")
	}
	if d <= 0 {
		return fmt.Errorf("a ticket needs a positive duration, got %s", d)
	}
	if d > MaxTicket {
		return fmt.Errorf("a ticket may not last longer than %s, got %s", MaxTicket, d)
	}
	keys, err := parseMACs(macs, "ticket")
	if err != nil {
		return err
	}
	present, err := e.exists()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("table %s is not present, so no ticket can be issued: "+
			"the ruleset is not being enforced at all", TableName)
	}
	set, ok, err := e.lookupSet(TicketSet)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("set %s is missing from table %s, so no ticket can be issued",
			TicketSet, TableName)
	}
	elements := make([]nftables.SetElement, 0, len(keys))
	for _, k := range keys {
		elements = append(elements, nftables.SetElement{Key: k, Timeout: d})
	}
	if err := e.conn.SetAddElements(set, elements); err != nil {
		return fmt.Errorf("granting ticket: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("granting ticket: %w", err)
	}
	return nil
}

// CancelTickets ends any live ticket for these MACs immediately.
//
// A table that is not there means there is no ticket to cancel, which is a
// success rather than a failure: the caller's next reconcile rebuilds the
// ruleset from desired state, and that state has no tickets in it.
func (e *Enforcer) CancelTickets(macs []string) error {
	keys, err := parseMACs(macs, "ticket")
	if err != nil {
		return err
	}
	present, err := e.exists()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	set, ok, err := e.lookupSet(TicketSet)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	live, err := e.conn.GetSetElements(set)
	if err != nil {
		return fmt.Errorf("reading %s elements: %w", TicketSet, err)
	}
	// Delete only what is actually there. Deleting an absent element fails the
	// whole batch, which would turn "this profile had no ticket" into "the
	// block could not be applied".
	var doomed []nftables.SetElement
	for _, el := range live {
		if slices.ContainsFunc(keys, func(k []byte) bool { return slices.Equal(k, el.Key) }) {
			doomed = append(doomed, nftables.SetElement{Key: el.Key})
		}
	}
	if len(doomed) == 0 {
		return nil
	}
	if err := e.conn.SetDeleteElements(set, doomed); err != nil {
		return fmt.Errorf("cancelling tickets: %w", err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("cancelling tickets: %w", err)
	}
	return nil
}

// Tickets reports the live tickets and how long the KERNEL says each has left.
//
// The remaining time is the kernel's own countdown rather than a number this
// process tracks in parallel, so it cannot drift, and it survives a restart of
// this process just as the ticket itself does.
func (e *Enforcer) Tickets() (map[string]time.Duration, error) {
	out := map[string]time.Duration{}
	present, err := e.exists()
	if err != nil {
		return nil, err
	}
	if !present {
		return out, nil
	}
	set, ok, err := e.lookupSet(TicketSet)
	if err != nil {
		return nil, err
	}
	if !ok {
		return out, nil
	}
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("reading %s elements: %w", TicketSet, err)
	}
	for _, el := range elements {
		if el.Expires <= 0 {
			continue
		}
		out[net.HardwareAddr(el.Key).String()] = el.Expires
	}
	return out, nil
}

// Allowlist reads back what the FIREWALL currently allows, which is the only
// trustworthy answer to "what is allowed". Per
// docs/adr/0004-tests-assert-on-the-packet-path.md the firewall is ground truth
// and the config file is commentary, so status is derived from here and never
// from the registry.
func (e *Enforcer) Allowlist() ([]string, error) {
	return e.readSet(AllowedSet)
}

func (e *Enforcer) readSet(name string) ([]string, error) {
	set, err := e.conn.GetSetByName(e.tableRef(), name)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("reading %s elements: %w", name, err)
	}
	out := make([]string, 0, len(elements))
	for _, el := range elements {
		out = append(out, net.HardwareAddr(el.Key).String())
	}
	sort.Strings(out)
	return out, nil
}

// Blocked reads back the MACs the FIREWALL is currently dropping by schedule or
// budget. Status comes from here, never from the config, per ADR 0004.
func (e *Enforcer) Blocked() ([]string, error) {
	return e.readSet(BlockedSet)
}

// ManualBlocked reads back the MACs the FIREWALL is currently dropping because
// a parent said so. It is a separate set from Blocked because it sits on the
// other side of the ticket accept, per ADR 0006, and a status derived only
// from Blocked would report a manually blocked profile as allowed.
func (e *Enforcer) ManualBlocked() ([]string, error) {
	return e.readSet(ManualBlockedSet)
}

// Teardown removes the whole table, restoring unrestricted forwarding. This is
// the recovery operation: it restores CONNECTIVITY, not policy.
func (e *Enforcer) Teardown() error {
	present, err := e.exists()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	e.conn.DelTable(e.tableRef())
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("removing table %s: %w", TableName, err)
	}
	return nil
}

// EnsureApplied makes the firewall match d, but only writes when it already
// differs, so a steady state costs a read rather than a ruleset rewrite.
// It reports whether it had to change anything.
//
// Live tickets are deliberately NOT part of the comparison. They are kernel
// state with their own deadlines, they are carried across any rewrite this
// function does trigger, and treating them as drift would rewrite the ruleset
// every tick for as long as a ticket lasts.
//
// An UNREADABLE firewall counts as drift. The table may be missing entirely
// (deleted by hand, by a recovery path, or never created), and that is the
// case where re-applying matters most. An earlier version returned the read
// error here, which meant the self-healing loop did nothing precisely when the
// ruleset had been wiped: found by an end-to-end test that deleted the table
// and watched enforcement stay gone.
func (e *Enforcer) EnsureApplied(d Desired) (bool, error) {
	same := func(want []string, read func() ([]string, error)) (bool, error) {
		got, err := read()
		if err != nil {
			return false, err
		}
		w := append([]string(nil), want...)
		sort.Strings(w)
		sort.Strings(got)
		return slices.Equal(w, got), nil
	}
	for _, check := range []struct {
		want []string
		read func() ([]string, error)
	}{
		{d.Allowed, e.Allowlist},
		{d.Blocked, e.Blocked},
		{d.Manual, e.ManualBlocked},
	} {
		ok, err := same(check.want, check.read)
		if err != nil {
			return true, e.ApplyDesired(d)
		}
		if !ok {
			return true, e.ApplyDesired(d)
		}
	}
	return false, nil
}
