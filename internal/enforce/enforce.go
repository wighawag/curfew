// Package enforce owns the nftables ruleset. It is the ONLY thing that writes
// to the parental_control table.
//
// Two properties are deliberate and load-bearing:
//
//   - Apply replaces the WHOLE table in a single netlink transaction, rather
//     than surgically editing it. There is no partial rebuild to get wrong and
//     no window in which the household is unprotected. Measured to work,
//     including carrying live timeout-set elements, in
//     work/notes/findings/google-nftables-drives-the-kernel-and-replaces-rulesets-atomically.md
//
//   - Nothing here swallows an error. The defining failure of the shell
//     implementation this replaces was reporting success while enforcing
//     nothing, because every nft call ended in 2>/dev/null. Every failure
//     below is returned.
//
// The rule ORDER inside the policy chain is a decision recorded in
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md.
// Only the allowlist tier is built today; the blocking tiers slot in above it.
package enforce

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	// TableName is the dedicated table. It is deliberately separate from
	// OpenWrt's fw4 so the two never mix.
	TableName = "parental_control"
	// AllowedSet holds every registered MAC.
	AllowedSet = "allowed_macs"
	// PolicyChain holds the ordering contract.
	PolicyChain = "parental"
	// BaseChain is the hooked chain that narrows to LAN-to-WAN.
	BaseChain = "forward"
	// HookPriority runs this table ahead of fw4 without mixing into it.
	HookPriority = -10
)

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

// Apply makes the firewall match the given allowlist exactly, replacing the
// whole table in one transaction. Passing an empty list is meaningful and
// allowed: it means nothing is allowed out, which is what an empty registry
// genuinely implies.
func (e *Enforcer) Apply(macs []string) error {
	parsed := make([][]byte, 0, len(macs))
	for _, m := range macs {
		hw, err := net.ParseMAC(m)
		if err != nil {
			return fmt.Errorf("allowlist entry %q: %w", m, err)
		}
		if len(hw) != 6 {
			return fmt.Errorf("allowlist entry %q: want a 6-octet MAC, got %d octets", m, len(hw))
		}
		parsed = append(parsed, []byte(hw))
	}

	present, err := e.exists()
	if err != nil {
		return err
	}

	t := e.tableRef()
	if present {
		// Delete and rebuild inside the SAME batch, so the ruleset is swapped
		// rather than removed and then recreated.
		e.conn.DelTable(t)
	}
	t = e.conn.AddTable(t)

	allowed := &nftables.Set{
		Table:   t,
		Name:    AllowedSet,
		KeyType: nftables.TypeEtherAddr,
	}
	elements := make([]nftables.SetElement, 0, len(parsed))
	for _, p := range parsed {
		elements = append(elements, nftables.SetElement{Key: p})
	}
	if err := e.conn.AddSet(allowed, elements); err != nil {
		return fmt.Errorf("building %s: %w", AllowedSet, err)
	}

	policy := e.conn.AddChain(&nftables.Chain{Table: t, Name: PolicyChain})

	// The ordering contract. Registered devices are accepted; everything else
	// reaching this chain is dropped. The terminal drop must be LAST, because a
	// rule after a terminal verdict is unreachable, which is one of the defects
	// this rewrite exists to remove.
	e.conn.AddRule(&nftables.Rule{Table: t, Chain: policy, Exprs: []expr.Any{
		// ether saddr lives at offset 6, length 6, of the link-layer header.
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
		&expr.Lookup{SourceRegister: 1, SetName: allowed.Name, SetID: allowed.ID},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
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

// Allowlist reads back what the FIREWALL currently allows, which is the only
// trustworthy answer to "what is allowed". Per
// docs/adr/0004-tests-assert-on-the-packet-path.md the firewall is ground truth
// and the config file is commentary, so status is derived from here and never
// from the registry.
func (e *Enforcer) Allowlist() ([]string, error) {
	set, err := e.conn.GetSetByName(e.tableRef(), AllowedSet)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", AllowedSet, err)
	}
	elements, err := e.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("reading %s elements: %w", AllowedSet, err)
	}
	out := make([]string, 0, len(elements))
	for _, el := range elements {
		out = append(out, net.HardwareAddr(el.Key).String())
	}
	return out, nil
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

// EnsureApplied makes the firewall match want, but only writes when it already
// differs, so a steady state costs a read rather than a ruleset rewrite.
// It reports whether it had to change anything.
//
// An UNREADABLE firewall counts as drift. The table may be missing entirely
// (deleted by hand, by a recovery path, or never created), and that is the
// case where re-applying matters most. An earlier version returned the read
// error here, which meant the self-healing loop did nothing precisely when the
// ruleset had been wiped: found by an end-to-end test that deleted the table
// and watched enforcement stay gone.
func (e *Enforcer) EnsureApplied(want []string) (bool, error) {
	got, err := e.Allowlist()
	if err != nil {
		return true, e.Apply(want)
	}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	wanted := append([]string(nil), want...)
	sort.Strings(wanted)
	if slices.Equal(sorted, wanted) {
		return false, nil
	}
	return true, e.Apply(wanted)
}
