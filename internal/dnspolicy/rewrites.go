package dnspolicy

import (
	"fmt"
	"sort"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnsnames"
	"github.com/wighawag/curfew/internal/leases"
)

// Local DNS names, the AdGuard half.
//
// AdGuard answers a device's local DNS names while it holds port 53, with
// rewrites curfew creates and owns. It answers EXACTLY the names the DHCP pass
// decided to answer (leases.NamesPlan.Targets: valid against the router's
// config, on a device whose fixed address is pinned), so the two resolvers
// cannot disagree about which names exist. Rendering is docs/adr/0013's: "x"
// is the pair x and *.x, "*.x" is *.x, answer the fixed address, A only (an
// A-only rewrite already answers AAAA and HTTPS with NODATA and does not
// forward them, measured).
//
// It runs on the tick, like the client objects, and that is safe for the same
// reason (ADR 0011, scope not frequency): it writes only to rewrites the
// ledger says curfew created, and only on a difference. A rewrite carries no
// marker of its own (docs/adr/0014).

// RewriteAPI is the part of AdGuard's API the rewrites need.
type RewriteAPI interface {
	Rewrites() ([]adguard.RewriteObject, error)
	AddRewrite(domain, answer string) error
	DeleteRewrite(domain, answer string) error
	UpdateRewrite(domain, oldAnswer, newAnswer string, enabled bool) error
	RewritesEnabled() (bool, error)
	FilteringEnabled() (bool, error)
	Clients() ([]adguard.ClientObject, error)
}

// RewriteReport is what one rewrite pass did, and what it could not do.
type RewriteReport struct {
	Added, Updated, Removed []string
	// Yielded are names a rewrite curfew did not create already answers.
	Yielded []string
	// Unclaimed are household rewrites identical to curfew's, left and not
	// claimed.
	Unclaimed []string
	// Kept are curfew rewrites duplicated by a household one, which cannot be
	// deleted without deleting both.
	Kept []string
	// Disabled are wanted rewrites that exist but are switched off in
	// AdGuard, so AdGuard does not answer them. Reported, never re-enabled.
	Disabled []string
	// Bypass says who gets NO rewrites at all, measured: everyone when
	// rewrites or filtering are off globally, and any client with its own
	// settings and filtering off. Reported, never changed.
	Bypass []string
	// Final is the AdGuard half of the ledger after this pass.
	Final []dnsledger.Rewrite
}

// Changed reports whether AdGuard was written to.
func (r RewriteReport) Changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

func rw(domain, answer string) dnsledger.Rewrite {
	return dnsledger.Rewrite{Domain: domain, Answer: answer}
}

// ReconcileRewrites makes AdGuard's rewrites match the targets, touching only
// rewrites in the ledger. save is called with the write-ahead ledger BEFORE
// any write, and its failure stops the pass before AdGuard is touched.
func ReconcileRewrites(api RewriteAPI, targets []leases.NameTarget, ledger *dnsledger.Ledger,
	save func([]dnsledger.Rewrite) error) (RewriteReport, error) {

	var rep RewriteReport
	list, err := api.Rewrites()
	if err != nil {
		return rep, err
	}
	// count includes DISABLED rewrites, because AdGuard's delete removes
	// every identical copy whether enabled or not; enabled says whether any
	// copy actually answers. A disabled rewrite answers nothing (it is how a
	// household switches one off), so it neither blocks curfew's name nor
	// stands in for it.
	count := map[dnsledger.Rewrite]int{}
	enabled := map[dnsledger.Rewrite]bool{}
	var present []dnsledger.Rewrite
	for _, o := range list {
		r := rw(dnsnames.Canonical(o.Domain), o.Answer)
		if count[r] == 0 {
			present = append(present, r)
		}
		count[r]++
		if o.Enabled == nil || *o.Enabled {
			enabled[r] = true
		}
	}
	owned := func(r dnsledger.Rewrite) bool { return count[r] > 0 && ledger.HasRewrite(r) }

	keep := map[dnsledger.Rewrite]bool{}
	type move struct{ from, to dnsledger.Rewrite }
	var adds []dnsledger.Rewrite
	var moves []move
	moved := map[dnsledger.Rewrite]bool{}
	for _, t := range targets {
		n, err := dnsnames.Parse(t.Name)
		if err != nil {
			continue // the DHCP pass only hands over valid names
		}
		var want []dnsledger.Rewrite
		wantDom := map[string]bool{}
		for _, d := range n.AdGuardDomains() {
			want = append(want, rw(d, t.IP))
			wantDom[d] = true
		}
		yielded := false
		for _, o := range present {
			if wantDom[o.Domain] && !owned(o) && o.Answer != t.IP && enabled[o] {
				rep.Yielded = append(rep.Yielded, fmt.Sprintf("%s (AdGuard already rewrites %s to %s)",
					t.Name, o.Domain, o.Answer))
				yielded = true
			}
		}
		if yielded {
			continue
		}
		for _, w := range want {
			switch {
			case owned(w):
				keep[w] = true
				if !enabled[w] {
					// Somebody switched curfew's own rewrite off. Respected,
					// not fought: it is reported, and kept as curfew's.
					rep.Disabled = append(rep.Disabled, w.Domain+" -> "+w.Answer)
				}
			case count[w] > 0 && enabled[w]:
				rep.Unclaimed = append(rep.Unclaimed, w.Domain+" -> "+w.Answer)
			case count[w] > 0:
				// Only a DISABLED household copy exists. Adding curfew's own
				// would make two identical rewrites that can never be removed
				// separately, so nothing is added and the household is told.
				rep.Disabled = append(rep.Disabled, w.Domain+" -> "+w.Answer+
					" (a rewrite curfew did not create, switched off; enable or delete it in AdGuard)")
			default:
				// A curfew rewrite for the same domain at another address is
				// this device moving: replace it in place.
				var from *dnsledger.Rewrite
				for _, o := range present {
					if o.Domain == w.Domain && owned(o) && !moved[o] && count[o] == 1 {
						o := o
						from = &o
						break
					}
				}
				if from != nil {
					moves = append(moves, move{*from, w})
					moved[*from] = true
				} else {
					adds = append(adds, w)
				}
				keep[w] = true
			}
		}
	}
	var dels []dnsledger.Rewrite
	for _, o := range present {
		if !owned(o) || keep[o] || moved[o] {
			continue
		}
		if count[o] > 1 {
			rep.Kept = append(rep.Kept, o.Domain+" -> "+o.Answer)
			keep[o] = true
			continue
		}
		dels = append(dels, o)
	}

	// Write ahead: what is recorded already, plus everything about to exist.
	wa := map[dnsledger.Rewrite]bool{}
	for _, r := range ledger.AdGuard {
		wa[r] = true
	}
	for _, a := range adds {
		wa[a] = true
	}
	for _, m := range moves {
		wa[m.to] = true
	}
	var writeAhead []dnsledger.Rewrite
	for r := range wa {
		writeAhead = append(writeAhead, r)
	}
	sortRewrites(writeAhead)
	if len(adds)+len(moves)+len(dels) > 0 && !sameRewrites(ledger.AdGuard, writeAhead) {
		if err := save(writeAhead); err != nil {
			return rep, fmt.Errorf("recording the DNS rewrites before writing them: %w", err)
		}
	}

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, m := range moves {
		on := enabled[m.from]
		err := api.UpdateRewrite(m.to.Domain, m.from.Answer, m.to.Answer, on)
		note(err)
		if err == nil {
			rep.Updated = append(rep.Updated, fmt.Sprintf("%s: %s -> %s", m.to.Domain, m.from.Answer, m.to.Answer))
			if !on {
				rep.Disabled = append(rep.Disabled, m.to.Domain+" -> "+m.to.Answer+
					" (moved with the device, and still switched off as the household left it)")
			}
		}
	}
	for _, a := range adds {
		err := api.AddRewrite(a.Domain, a.Answer)
		note(err)
		if err == nil {
			rep.Added = append(rep.Added, a.Domain+" -> "+a.Answer)
		}
	}
	for _, d := range dels {
		err := api.DeleteRewrite(d.Domain, d.Answer)
		note(err)
		if err == nil {
			rep.Removed = append(rep.Removed, d.Domain+" -> "+d.Answer)
		}
	}

	// The ledger afterwards is what curfew wrote and AdGuard now holds. It is
	// read back rather than assumed, so a write that half-failed can neither
	// orphan a record nor leave a claim on one that is gone.
	rep.Final = writeAhead
	if after, err := api.Rewrites(); err == nil {
		now := map[dnsledger.Rewrite]bool{}
		for _, o := range after {
			now[rw(dnsnames.Canonical(o.Domain), o.Answer)] = true
		}
		rep.Final = nil
		for _, r := range writeAhead {
			if now[r] {
				rep.Final = append(rep.Final, r)
			}
		}
	}
	if len(targets) > 0 {
		rep.Bypass = bypass(api)
	}
	return rep, firstErr
}

// bypass reports who gets no rewrites, from AdGuard's own settings.
func bypass(api RewriteAPI) []string {
	var out []string
	if on, err := api.RewritesEnabled(); err == nil && !on {
		out = append(out, "DNS rewrites are switched off in AdGuard, so it answers none of the "+
			"local names for anyone (dnsmasq still does after panic-off)")
	}
	if on, err := api.FilteringEnabled(); err == nil && !on {
		out = append(out, "filtering is off in AdGuard, which also turns rewrites off for every client")
	}
	if clients, err := api.Clients(); err == nil {
		var names []string
		for _, c := range clients {
			if !adguard.OwnedClient(c.Name) && !c.UseGlobalSettings && !c.FilteringEnabled {
				names = append(names, c.Name)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, fmt.Sprintf("the AdGuard client %q has filtering off, so it gets no "+
				"rewrites and asks upstream for the local names (it sees any public record instead)", n))
		}
	}
	return out
}

func sortRewrites(rs []dnsledger.Rewrite) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Domain != rs[j].Domain {
			return rs[i].Domain < rs[j].Domain
		}
		return rs[i].Answer < rs[j].Answer
	})
}
