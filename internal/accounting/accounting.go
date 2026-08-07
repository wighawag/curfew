// Package accounting measures how much a profile actually used the internet,
// with nftables counters, and is structurally incapable of affecting a packet.
//
// It owns a table of its OWN, separate from the enforcement table, and both
// halves of that sentence are load-bearing:
//
//   - Separate, because internal/enforce replaces the whole enforcement table
//     on every apply and would zero any counter living in it. Measured: a
//     named counter in the curfew table is gone after one apply; the same
//     counter in this table is untouched.
//
//   - Counter rules only, hooked at contract.AccountingPriority, which is
//     AFTER enforcement's contract.HookPriority. A packet a drop tier already
//     rejected never reaches this chain, so a blocked device's retries cannot
//     burn a child's allowance (ADR 0001), and no rule here carries a verdict,
//     so nothing here can change what happens to a packet (measured on the
//     packet path, both directions of that claim).
//
// It counts LAN-to-WAN traffic by SOURCE MAC, mirroring the enforcement match
// exactly. The download direction is deliberately not counted, because it
// cannot be attributed to a device at all at this hook: measured, a 1 MiB
// download moved a WAN-to-LAN counter matching the client's `ether daddr` by 0
// bytes while the same rule without the MAC match moved by 1066928, since the
// LAN-side link-layer header does not exist yet at the forward hook. See
// docs/adr/0009-the-budget-continuity-model.md for what that means for the
// threshold.
package accounting

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/wighawag/curfew/internal/contract"
)

// Config names the interfaces to account between. They are the same two the
// enforcement chain narrows to, and for the same reason: guessing them is how
// a rule silently matches nothing.
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

// Accountant owns the accounting table. Use New.
type Accountant struct {
	cfg  Config
	conn *nftables.Conn
	// shape is the profile-to-MACs mapping the current table was built from,
	// so an unchanged household costs a comparison rather than a rebuild. That
	// matters more than it looks: a rebuild zeroes every counter, so rebuilding
	// on every tick would mean usage never accumulated at all, while every
	// individual read still looked plausible.
	shape map[string][]string
	// generation increments on every rebuild, so the sampler KNOWS the
	// counters were reset instead of inferring it from a backwards reading.
	generation uint64
}

// New opens a netlink connection for accounting.
func New(cfg Config) (*Accountant, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("opening netlink connection: %w", err)
	}
	return &Accountant{cfg: cfg, conn: conn}, nil
}

// Generation reports how many times the counters have been reset by a rebuild.
func (a *Accountant) Generation() uint64 { return a.generation }

// CounterName maps a profile name to an nftables object name.
//
// It is exported because a human debugging a router will want to run
// `nft list counters` and match what they see to a child, so an ordinary name
// like "Eli" stays readable as `profile_eli`. Case is folded rather than
// escaped for exactly that reason: the household's own config capitalises its
// profiles, and hashing every one of them would trade the whole benefit for a
// collision that normalise already catches loudly.
//
// A name that cannot be folded losslessly (punctuation, spaces, or one long
// enough to be truncated) DOES get a hash suffix, because those are the cases
// where two different names would otherwise land on one counter and two
// children would silently share a budget. The genuinely ambiguous case that
// remains, two profiles differing only in case, is refused by normalise rather
// than papered over here. Counter names of 255 characters were measured to be
// accepted on the test kernel; the cap is far below that because older kernels
// used a much smaller limit.
func CounterName(profile string) string {
	const maxBody = 40
	var b strings.Builder
	clean := true
	for _, r := range profile {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune('_')
			clean = false
		}
	}
	body := b.String()
	if len(body) > maxBody {
		body = body[:maxBody]
		clean = false
	}
	if clean {
		return "profile_" + body
	}
	sum := sha256.Sum256([]byte(profile))
	return "profile_" + body + "_" + hex.EncodeToString(sum[:4])
}

func (a *Accountant) tableRef() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: contract.AccountingTable}
}

func (a *Accountant) exists() (bool, error) {
	tables, err := a.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == contract.AccountingTable {
			return true, nil
		}
	}
	return false, nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

// normalise returns a comparable copy of a shape: lowercase MACs, sorted,
// deduplicated, and profiles with no devices dropped.
func normalise(profiles map[string][]string) (map[string][]string, error) {
	out := make(map[string][]string, len(profiles))
	seenCounter := map[string]string{}
	for name, macs := range profiles {
		counter := CounterName(name)
		if other, clash := seenCounter[counter]; clash {
			// Reachable in exactly one way: two profiles differing only in
			// case. Loud rather than tolerated, because two children silently
			// sharing one counter would burn each other's allowance and look
			// like a mystery from every surface that reports it.
			return nil, fmt.Errorf("profiles %q and %q both account to counter %q, "+
				"so they would share one budget: rename one so they differ by more than case",
				other, name, counter)
		}
		seenCounter[counter] = name
		clean := make([]string, 0, len(macs))
		seen := map[string]bool{}
		for _, m := range macs {
			hw, err := net.ParseMAC(strings.TrimSpace(m))
			if err != nil {
				return nil, fmt.Errorf("profile %q device %q: %w", name, m, err)
			}
			if len(hw) != 6 {
				return nil, fmt.Errorf("profile %q device %q: want a 6-octet MAC", name, m)
			}
			s := hw.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			clean = append(clean, s)
		}
		if len(clean) == 0 {
			// A profile with no devices has nothing to count, and a counter
			// nothing writes to would read as a permanently idle child.
			continue
		}
		sort.Strings(clean)
		out[name] = clean
	}
	return out, nil
}

func sameShape(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, macs := range a {
		other, ok := b[name]
		if !ok || !slices.Equal(macs, other) {
			return false
		}
	}
	return true
}

// EnsureShape makes the accounting table count exactly these profiles, and
// writes NOTHING when it already does.
//
// It reports whether it rebuilt, which is the same thing as reporting that
// every counter has just been zeroed.
func (a *Accountant) EnsureShape(profiles map[string][]string) (bool, error) {
	want, err := normalise(profiles)
	if err != nil {
		return false, err
	}
	present, err := a.exists()
	if err != nil {
		return false, err
	}
	if present && a.shape != nil && sameShape(a.shape, want) {
		return false, nil
	}
	// A table that exists but whose shape we do not know (this process just
	// started, or somebody edited it) is rebuilt rather than trusted. That
	// costs one skipped interval and buys certainty about what is counted.
	if err := a.rebuild(want, present); err != nil {
		return false, err
	}
	a.shape = want
	a.generation++
	return true, nil
}

func (a *Accountant) rebuild(shape map[string][]string, present bool) error {
	t := a.tableRef()
	if present {
		// Delete and recreate in the SAME batch, so accounting is swapped
		// rather than removed and then rebuilt.
		a.conn.DelTable(t)
	}
	t = a.conn.AddTable(t)

	for _, name := range slices.Sorted(maps.Keys(shape)) {
		a.conn.AddObj(&nftables.CounterObj{Table: t, Name: CounterName(name)})
	}

	prio := nftables.ChainPriority(contract.AccountingPriority)
	pol := nftables.ChainPolicyAccept
	chain := a.conn.AddChain(&nftables.Chain{
		Table:    t,
		Name:     contract.AccountingChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &prio,
		Policy:   &pol,
	})

	for _, name := range slices.Sorted(maps.Keys(shape)) {
		counter := CounterName(name)
		for _, mac := range shape[name] {
			hw, err := net.ParseMAC(mac)
			if err != nil {
				return fmt.Errorf("profile %q device %q: %w", name, mac, err)
			}
			// LAN to WAN, this device's source MAC, count. No verdict: the
			// rule falls through, the chain's policy accepts, and nothing here
			// can decide anything about the packet.
			a.conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(a.cfg.LANInterface)},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(a.cfg.WANInterface)},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(hw)},
				&expr.Objref{Type: int(nftables.ObjTypeCounter), Name: counter},
			}})
		}
	}
	if err := a.conn.Flush(); err != nil {
		return fmt.Errorf("building the accounting table: %w", err)
	}
	return nil
}

// Read returns each profile's CUMULATIVE upstream byte total.
//
// Cumulative, not per-interval: turning that into "was this interval active?"
// is budget.Sampler's job, and the separation is deliberate, because the
// subtraction is where the reboot and rebuild cases have to be handled and
// they are much easier to test without a kernel.
func (a *Accountant) Read() (map[string]uint64, error) {
	out := map[string]uint64{}
	present, err := a.exists()
	if err != nil {
		return nil, err
	}
	if !present {
		return out, nil
	}
	objs, err := a.conn.GetObjects(a.tableRef())
	if err != nil {
		return nil, fmt.Errorf("reading counters in %s: %w", contract.AccountingTable, err)
	}
	byCounter := map[string]uint64{}
	for _, o := range objs {
		c, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		byCounter[c.Name] = c.Bytes
	}
	for name := range a.shape {
		if v, ok := byCounter[CounterName(name)]; ok {
			out[name] = v
		}
	}
	return out, nil
}

// Teardown removes the accounting table.
//
// Nothing depends on this for connectivity: the table carries no verdict, so
// leaving it in place cannot block anything, which is why the documented
// escape hatch (`nft delete table inet curfew`) is still complete on its own.
// Measured: with the accounting table still present and the enforcement table
// deleted, a client reaches the internet.
func (a *Accountant) Teardown() error {
	present, err := a.exists()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	a.conn.DelTable(a.tableRef())
	if err := a.conn.Flush(); err != nil {
		return fmt.Errorf("removing table %s: %w", contract.AccountingTable, err)
	}
	a.shape = nil
	a.generation++
	return nil
}
