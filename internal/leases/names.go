package leases

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnsnames"
)

// Local DNS names, the dnsmasq half.
//
// dnsmasq answers each device's local DNS names itself, A only, with the
// device's fixed address, so the names resolve after `panic-off` hands port 53
// back to dnsmasq and on a router with no AdGuard at all. They are rendered
// per docs/adr/0013 into dhcp.@dnsmasq[0]'s `address` list (the answer) and
// `server` list (local-only, so AAAA and every other type get no answer and
// are NOT forwarded upstream; an address line alone forwards them, measured).
//
// They ride the SAME uci transaction as the pins (one backup, one commit, one
// reload, one liveness check, one rollback, under the DHCP config lock), for
// two reasons: a second transaction would be a second reload and a second
// rollback window every tick, and a name follows its device's fixed address,
// so a `set-ip` move must rewrite the pin and the answer together.
//
// Ownership is the ledger (internal/dnsledger, docs/adr/0014), because a uci
// list entry is a bare string that cannot say who wrote it.

// The uci lists curfew writes local names into.
const (
	ListAddress = "address"
	ListServer  = "server"
	dnsmasqSec  = "dhcp.@dnsmasq[0]"
)

// NameTarget is one local DNS name the router should answer this pass: valid
// against the router's own config, on a device whose fixed address IS pinned.
// The AdGuard half answers exactly these too.
type NameTarget struct {
	MAC  string
	Name string
	IP   string
}

// NameRefusal is a stored name the router will not answer, and why.
type NameRefusal struct {
	MAC, Name, Reason string
}

// NameYield is a name dnsmasq will not answer because an entry curfew did not
// write already answers the same domain.
type NameYield struct {
	Name, List, Entry string
}

// NamesPlan is what one pass decided about local names on the dnsmasq side.
type NamesPlan struct {
	Targets  []NameTarget
	Refused  []NameRefusal
	Yielded  []NameYield
	Warnings []string
	// Unclaimed are entries identical to what curfew wants that it did not
	// write. They are left alone and not claimed (docs/adr/0014); the name
	// still resolves.
	Unclaimed []string
	// Kept are duplicates of a curfew entry that curfew therefore cannot
	// delete without deleting somebody else's copy too.
	Kept     []string
	Commands []string
	// WriteAhead is the ledger to save BEFORE applying: everything curfew may
	// own once the commands have run, so a crash cannot orphan a record.
	WriteAhead []dnsledger.DnsmasqEntry
	// Final is the ledger after a successful apply: exactly what curfew owns
	// and is present.
	Final []dnsledger.DnsmasqEntry
	// Changed lists the names whose dnsmasq entries this pass changes.
	Changed []string
}

// PlanNames decides the dnsmasq entries for every device's local names.
//
// devices are the devices AS REGISTERED (their Fixed is the household's
// choice, before screening); pinned is the address each MAC is actually pinned
// at this pass. A name is answered only when the two agree, so a fixed address
// Reconcile refused (a clash) never gets a name pointing at an address the
// device does not hold.
func PlanNames(devices []Device, pinned map[string]string, ctx dnsnames.Context,
	address, server []string, ledger *dnsledger.Ledger) NamesPlan {

	var p NamesPlan
	var checkDevs []dnsnames.Device
	for _, d := range devices {
		if len(d.DNSNames) == 0 {
			continue
		}
		label := d.MAC
		if d.Name != "" {
			label = fmt.Sprintf("%s (%s)", d.Name, d.MAC)
		}
		checkDevs = append(checkDevs, dnsnames.Device{MAC: normaliseMAC(d.MAC), Label: label,
			Fixed: strings.TrimSpace(d.Fixed), Names: d.DNSNames})
	}
	fixedOf := map[string]string{}
	for _, d := range checkDevs {
		fixedOf[d.MAC] = d.Fixed
	}
	type target struct {
		NameTarget
		n dnsnames.Name
	}
	var targets []target
	for _, r := range dnsnames.Check(checkDevs, ctx) {
		if len(r.Errors) > 0 {
			p.Refused = append(p.Refused, NameRefusal{MAC: r.MAC, Name: r.Name, Reason: strings.Join(r.Errors, "; ")})
			continue
		}
		p.Warnings = append(p.Warnings, r.Warnings...)
		fixed := fixedOf[r.MAC]
		if pinned[r.MAC] != fixed {
			p.Refused = append(p.Refused, NameRefusal{MAC: r.MAC, Name: r.Name, Reason: fmt.Sprintf(
				"its fixed address %s is not pinned this pass, so the name would point at an "+
					"address the device does not hold", fixed)})
			continue
		}
		n, _ := dnsnames.Parse(r.Name)
		targets = append(targets, target{NameTarget{MAC: r.MAC, Name: n.String(), IP: fixed}, n})
	}

	count := map[dnsledger.DnsmasqEntry]int{}
	var present []dnsledger.DnsmasqEntry
	for _, v := range address {
		e := dnsledger.DnsmasqEntry{List: ListAddress, Value: v}
		if count[e] == 0 {
			present = append(present, e)
		}
		count[e]++
	}
	for _, v := range server {
		e := dnsledger.DnsmasqEntry{List: ListServer, Value: v}
		if count[e] == 0 {
			present = append(present, e)
		}
		count[e]++
	}
	owned := func(e dnsledger.DnsmasqEntry) bool { return count[e] > 0 && ledger.HasDnsmasq(e) }

	keep := map[dnsledger.DnsmasqEntry]bool{}
	var adds []dnsledger.DnsmasqEntry
	for _, t := range targets {
		want := []dnsledger.DnsmasqEntry{
			{List: ListAddress, Value: t.n.DnsmasqAddress(t.IP)},
			{List: ListServer, Value: t.n.DnsmasqServer()},
		}
		wanted := map[dnsledger.DnsmasqEntry]bool{want[0]: true, want[1]: true}
		yielded := false
		for _, e := range present {
			if owned(e) || wanted[e] {
				continue
			}
			for _, dom := range dnsnames.DomainsOf(e.Value) {
				if dom == t.n.DnsmasqDomain() {
					p.Yielded = append(p.Yielded, NameYield{Name: t.Name, List: e.List, Entry: e.Value})
					yielded = true
				}
			}
		}
		p.Targets = append(p.Targets, t.NameTarget)
		if yielded {
			continue
		}
		for _, e := range want {
			switch {
			case owned(e):
				keep[e] = true
			case count[e] > 0:
				p.Unclaimed = append(p.Unclaimed, fmt.Sprintf("%s %s", e.List, e.Value))
			default:
				adds = append(adds, e)
				keep[e] = true
				p.Changed = appendOnce(p.Changed, t.Name)
			}
		}
	}

	var dels []dnsledger.DnsmasqEntry
	for _, e := range present {
		if !owned(e) || keep[e] {
			continue
		}
		if count[e] > 1 {
			// One copy is somebody else's, and uci cannot delete just ours.
			p.Kept = append(p.Kept, fmt.Sprintf("%s %s", e.List, e.Value))
			keep[e] = true
			continue
		}
		dels = append(dels, e)
	}
	sortEntries(dels)
	sortEntries(adds)
	for _, e := range dels {
		p.Commands = append(p.Commands, fmt.Sprintf("uci del_list %s.%s=%s", dnsmasqSec, e.List, shellQuote(e.Value)))
		for _, dom := range dnsnames.DomainsOf(e.Value) {
			p.Changed = appendOnce(p.Changed, dom)
		}
	}
	for _, e := range adds {
		p.Commands = append(p.Commands, fmt.Sprintf("uci add_list %s.%s=%s", dnsmasqSec, e.List, shellQuote(e.Value)))
	}

	// Write-ahead: everything already recorded, plus what is about to be
	// added. Nothing is forgotten until it is gone.
	wa := map[dnsledger.DnsmasqEntry]bool{}
	for _, e := range ledger.Dnsmasq {
		wa[e] = true
	}
	for _, e := range adds {
		wa[e] = true
	}
	for e := range wa {
		p.WriteAhead = append(p.WriteAhead, e)
	}
	// After success: what curfew owns and is present, i.e. what it kept plus
	// what it added. Ledger entries no longer present are pruned here.
	for e := range keep {
		if ledger.HasDnsmasq(e) || containsEntry(adds, e) {
			p.Final = append(p.Final, e)
		}
	}
	sortEntries(p.WriteAhead)
	sortEntries(p.Final)
	sort.Strings(p.Changed)
	return p
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func containsEntry(list []dnsledger.DnsmasqEntry, e dnsledger.DnsmasqEntry) bool {
	for _, x := range list {
		if x == e {
			return true
		}
	}
	return false
}

func sortEntries(es []dnsledger.DnsmasqEntry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].List != es[j].List {
			return es[i].List < es[j].List
		}
		return es[i].Value < es[j].Value
	})
}
