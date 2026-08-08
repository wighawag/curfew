// Package dnspolicy turns per-profile, time-windowed DNS restrictions into the
// AdGuard objects that enforce them, and reconciles the two.
//
// It is the DNS-side counterpart of internal/policy, and it keeps that
// package's central discipline: desired state is recomputed from the config
// and the clock on every pass, nothing is remembered between passes, and a
// missed boundary is therefore impossible rather than merely unlikely.
//
// # Why this reconciles on a tick when ADR 0010 says AdGuard is reconciled on action
//
// ADR 0010 decided AdGuard is reconciled on action rather than continuously,
// because AdGuard's config persists and a human edits it, so a continuous
// reconciler would revert a change made in AdGuard's own UI. Time-windowed
// rules need something to happen at a boundary, so that tension has to be
// resolved rather than ignored.
//
// It is resolved by SCOPE, not by frequency. This reconciler only ever reads,
// writes or deletes objects curfew itself created: clients named
// "curfew-<profile>" and the single filter list curfew serves. It cannot touch
// a household's own client, list, exception or rule, because every write goes
// through a guard that refuses an unowned name. That is precisely the boundary
// that already works between curfew's nftables table and fw4, and it is what
// makes running every minute safe where a whole-config reconciler would not be.
//
// Nothing here is written unless the desired state DIFFERS from what AdGuard
// currently holds, so a household that changes nothing sees no writes at all.
package dnspolicy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/lanhosts"
	"github.com/wighawag/curfew/internal/schedule"
)

// Desired is the whole AdGuard-side desired state at one moment.
type Desired struct {
	// Clients are the client objects curfew should hold, by AdGuard client
	// name. Only profiles that actually have restrictions configured get one,
	// so a household not using the feature sees no curfew objects at all.
	Clients map[string]adguard.ClientObject
	// FilterList is the text curfew-daemon should be serving right now.
	FilterList string
	// Unresolved names profiles that have restrictions but no device address
	// to attach them to, so the restriction cannot apply. This is the
	// fail-open case and it must be REPORTED rather than left silent.
	Unresolved []string
	// PartiallyResolved names profiles where SOME devices have no address, so
	// the restriction applies to the child on one device and not another.
	PartiallyResolved []string
}

// Compute works out what AdGuard should hold at t.
//
// pinned is MAC to the IPv4 address curfew's own static leases fix, and it is
// the ONLY source of IPv4 here. observed is what the LAN currently shows, and
// only its IPv6 half is used. That split is the safety asymmetry made
// structural: a stale IPv4 is dangerous because DHCP reissues addresses and a
// rule would land on the WRONG CHILD, so IPv4 comes from configuration curfew
// owns; a stale IPv6 privacy address is nearly harmless because its interface
// identifier is 64 random bits, so it can come from observation.
func Compute(ps *schedule.Profiles, pinned map[string]string,
	observed map[string]lanhosts.Addresses, t time.Time) Desired {

	d := Desired{Clients: map[string]adguard.ClientObject{}}
	var rules []string

	profiles := append([]schedule.Profile(nil), ps.Profiles...)
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	for _, p := range profiles {
		if len(p.Restrictions) == 0 {
			continue
		}
		name := adguard.ClientName(p.Name)

		ids := []string{}
		withAddress, without := 0, 0
		for _, mac := range p.Devices {
			mac = strings.ToLower(mac)
			has := false
			if ip := pinned[mac]; ip != "" {
				ids = append(ids, ip)
				has = true
			}
			for _, v6 := range observed[mac].IPv6 {
				ids = append(ids, v6)
				has = true
			}
			if has {
				withAddress++
			} else {
				without++
			}
		}
		sort.Strings(ids)

		if len(ids) == 0 {
			// Nothing to key a rule on. Emitting a client with no ids would
			// create an object that matches nothing while looking, in
			// AdGuard's UI and in curfew's own reports, exactly like one that
			// works.
			d.Unresolved = append(d.Unresolved, p.Name)
			continue
		}
		if without > 0 && withAddress > 0 {
			d.PartiallyResolved = append(d.PartiallyResolved, p.Name)
		}

		services := p.BlockedServicesAt(t)
		d.Clients[name] = adguard.ClientObject{
			Name:                     name,
			IDs:                      ids,
			BlockedServices:          services,
			UseGlobalBlockedServices: len(services) == 0,
			UseGlobalSettings:        true,
			FilteringEnabled:         true,
		}

		// The DoH bootstrap block is NOT window-gated, deliberately. A child
		// sets a DoH endpoint once and it persists, so letting them resolve it
		// at 07:00 defeats a restriction that starts at 08:00. It is applied to
		// every profile that has restrictions configured, and to nobody else.
		if ps.DoHBootstrapBlocked() {
			for _, domain := range DoHBootstrapDomains {
				rules = append(rules, fmt.Sprintf("||%s^$client=%s", domain, name))
			}
		}

		for _, domain := range ps.BlockedDomainsAt(p, t) {
			// $client references the client by NAME, so the rule text does not
			// change when a phone rotates an IPv6 address. That keeps list
			// refreshes tied to POLICY changes (a window boundary, an edit)
			// rather than to address churn, which would otherwise re-fetch the
			// list several times a day per device.
			rules = append(rules, fmt.Sprintf("||%s^$client=%s", domain, name))
		}
	}

	sort.Strings(rules)
	d.FilterList = renderList(rules)
	sort.Strings(d.Unresolved)
	sort.Strings(d.PartiallyResolved)
	return d
}

// renderList produces the filter list curfew serves.
//
// The header is addressed to a person who has found this list in AdGuard's UI
// and is wondering what writes it. It carries no timestamp deliberately: a
// timestamp would make the content differ on every render, so every tick would
// look like a change and trigger a refetch.
func renderList(rules []string) string {
	var b strings.Builder
	b.WriteString("! Title: curfew (managed)\n")
	b.WriteString("! This list is generated by curfew-daemon and re-fetched when a\n")
	b.WriteString("! restriction window opens or closes. Editing it here has no effect:\n")
	b.WriteString("! change the profile's restrictions in curfew instead.\n")
	b.WriteString("! Your own rules belong in AdGuard's Custom filtering rules, which\n")
	b.WriteString("! curfew never touches.\n")
	if len(rules) == 0 {
		b.WriteString("! No restrictions are active right now.\n")
		return b.String()
	}
	for _, r := range rules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return b.String()
}

// Report says what a reconcile did, in terms a person can check.
type Report struct {
	ClientsAdded   []string
	ClientsUpdated []string
	ClientsRemoved []string
	// ListChanged is set when the served filter list text changed, which is
	// what a window boundary looks like from here.
	ListChanged bool
	// ListRegistered is set when AdGuard was subscribed to curfew's list for
	// the first time.
	ListRegistered bool
	// Refreshed records that AdGuard was told to re-fetch, which is what makes
	// a boundary prompt rather than eventual: without it AdGuard's own update
	// interval is 24 hours.
	Refreshed bool
	Unresolved,
	PartiallyResolved []string
}

// Changed reports whether anything at all was written.
func (r Report) Changed() bool {
	return len(r.ClientsAdded)+len(r.ClientsUpdated)+len(r.ClientsRemoved) > 0 ||
		r.ListChanged || r.ListRegistered
}

// API is the slice of AdGuard's REST interface this package needs. It is an
// interface so the decision logic can be tested without a running AdGuard;
// the DNS-path tests deliberately use the real one.
type API interface {
	Clients() ([]adguard.ClientObject, error)
	AddClient(adguard.ClientObject) error
	UpdateClient(adguard.ClientObject) error
	DeleteClient(name string) error
	Filters() ([]adguard.FilterList, error)
	AddFilterURL(name, url string) error
	RefreshFilters() error
	// Services is AdGuard's built-in catalogue, so a UI can offer what THIS
	// AdGuard knows about rather than a list compiled into curfew that drifts
	// from it.
	Services() ([]string, error)
}

// Reconcile makes AdGuard hold the desired state, writing only on a difference.
//
// listURL is where curfew-daemon serves its list. served is the text the
// daemon is now serving, which the caller has already swapped in: the order
// matters, because AdGuard fetches the URL during both add_url and refresh, so
// the new content has to be in place before either is called.
func Reconcile(api API, d Desired, listURL string, listChanged bool) (Report, error) {
	report := Report{
		ListChanged:       listChanged,
		Unresolved:        d.Unresolved,
		PartiallyResolved: d.PartiallyResolved,
	}

	existing, err := api.Clients()
	if err != nil {
		return report, err
	}
	have := map[string]adguard.ClientObject{}
	for _, c := range existing {
		// Only curfew's own objects are even considered. A household's client
		// for the same device is invisible to this loop, so it can be neither
		// updated nor deleted.
		if adguard.OwnedClient(c.Name) {
			have[c.Name] = c
		}
	}

	names := make([]string, 0, len(d.Clients))
	for name := range d.Clients {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		want := d.Clients[name]
		current, exists := have[name]
		switch {
		case !exists:
			if err := api.AddClient(want); err != nil {
				return report, err
			}
			report.ClientsAdded = append(report.ClientsAdded, name)
		case !want.SameAs(current):
			if err := api.UpdateClient(want); err != nil {
				return report, err
			}
			report.ClientsUpdated = append(report.ClientsUpdated, name)
		}
	}

	// Remove curfew clients that no longer correspond to a restricted profile,
	// so a deleted profile does not leave a rule keyed to somebody's address.
	stale := make([]string, 0, len(have))
	for name := range have {
		if _, wanted := d.Clients[name]; !wanted {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		if err := api.DeleteClient(name); err != nil {
			return report, err
		}
		report.ClientsRemoved = append(report.ClientsRemoved, name)
	}

	// Make sure AdGuard is subscribed to the list curfew serves.
	filters, err := api.Filters()
	if err != nil {
		return report, err
	}
	registered := false
	for _, f := range filters {
		if f.URL == listURL {
			registered = true
			break
		}
	}
	if !registered {
		if err := api.AddFilterURL(adguard.FilterListName, listURL); err != nil {
			return report, err
		}
		report.ListRegistered = true
		// add_url fetches as part of validating, so the content is already in.
		return report, nil
	}
	if listChanged {
		if err := api.RefreshFilters(); err != nil {
			return report, err
		}
		report.Refreshed = true
	}
	return report, nil
}
