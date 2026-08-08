package schedule

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Per-profile, time-windowed DNS restrictions.
//
// This is the "no streaming between 08:00 and 10:00" half of the system, and
// it is deliberately a DIFFERENT thing from a blocked window. A blocked window
// takes a child off the internet entirely and is enforced in nftables by MAC.
// A restriction leaves them online and removes some domains, and is enforced
// in AdGuard by IP. The two are layered, not alternatives: a child can have
// internet from 08:00 to 22:00 and no streaming from 08:00 to 10:00.
//
// Windows are reused from this package rather than expressed in AdGuard's own
// scheduler. AdGuard has one (blocked_services_schedule, storing milliseconds
// since midnight with a timezone) and it is deliberately not used: it applies
// only to the built-in service catalogue and not to arbitrary domains, and a
// second scheduler with different semantics is the split ownership ADR 0010
// exists to avoid. Window already handles day selectors, overnight windows and
// timezones, and is tested for all three.

// Restriction is a named set of DNS restrictions that applies during windows.
type Restriction struct {
	// Name is what a parent calls it: "no streaming", "no games".
	Name string `json:"name"`
	// Services are ids from AdGuard's BUILT-IN catalogue (youtube, tiktok,
	// netflix, roblox, discord and so on). Preferred over Lists because the
	// catalogue is maintained upstream and survives domain churn, where a
	// household's own list rots silently as services add domains.
	Services []string `json:"services,omitempty"`
	// Lists names entries in Profiles.BlockLists: domain lists the household
	// authored. They live in curfew's own configuration so they travel with
	// push and pull, rather than depending on AdGuard's file being the source
	// of truth.
	Lists []string `json:"lists,omitempty"`
	// Windows are when this restriction applies. Empty means ALWAYS, which is
	// how a permanent restriction is expressed without inventing a 00:00 to
	// 23:59 window that reads as a mistake.
	Windows []Window `json:"windows,omitempty"`
}

// ActiveAt reports whether this restriction applies at t.
func (r Restriction) ActiveAt(t time.Time) bool {
	if len(r.Windows) == 0 {
		return true
	}
	for _, w := range r.Windows {
		if w.Contains(t) {
			return true
		}
	}
	return false
}

// Validate reports why a restriction is unusable.
func (r Restriction) Validate(knownLists map[string]bool) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a restriction needs a name")
	}
	if len(r.Services) == 0 && len(r.Lists) == 0 {
		// A restriction that restricts nothing is the shape ADR 0003 names as
		// the smell that motivated splitting devices from profiles: a field
		// that cannot mean anything. Refuse it rather than apply it as a no-op
		// that looks like protection.
		return fmt.Errorf("restriction %q blocks nothing: give it services or lists", r.Name)
	}
	for _, s := range r.Services {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("restriction %q has an empty service name", r.Name)
		}
	}
	for _, l := range r.Lists {
		if !knownLists[l] {
			// Refused at the door rather than silently ignored. A restriction
			// naming a list that does not exist would apply nothing while
			// reading, on the page and in the file, exactly like one that does.
			return fmt.Errorf("restriction %q names block list %q, which is not defined "+
				"in block_lists", r.Name, l)
		}
	}
	for i, w := range r.Windows {
		if err := w.Validate(); err != nil {
			return fmt.Errorf("restriction %q window %d: %w", r.Name, i+1, err)
		}
	}
	return nil
}

// ActiveRestrictions returns the profile's restrictions that apply at t.
func (p Profile) ActiveRestrictions(t time.Time) []Restriction {
	var out []Restriction
	for _, r := range p.Restrictions {
		if r.ActiveAt(t) {
			out = append(out, r)
		}
	}
	return out
}

// BlockedServicesAt is the union of catalogue services this profile should
// have blocked at t, sorted so the result is stable and can be compared
// against what AdGuard holds without looking like a change every pass.
func (p Profile) BlockedServicesAt(t time.Time) []string {
	seen := map[string]bool{}
	for _, r := range p.ActiveRestrictions(t) {
		for _, s := range r.Services {
			seen[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// BlockedDomainsAt is the union of domains from the profile's active custom
// lists at t, resolved through the household's block_lists.
func (ps *Profiles) BlockedDomainsAt(p Profile, t time.Time) []string {
	seen := map[string]bool{}
	for _, r := range p.ActiveRestrictions(t) {
		for _, name := range r.Lists {
			for _, d := range ps.BlockLists[name] {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" {
					seen[d] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// AnyRestrictions reports whether any profile has a restriction configured at
// all, so the daemon can say plainly that it is doing nothing rather than
// appearing to manage AdGuard while managing nothing.
func (ps *Profiles) AnyRestrictions() bool {
	for _, p := range ps.Profiles {
		if len(p.Restrictions) > 0 {
			return true
		}
	}
	return false
}

// validateRestrictions checks every profile's restrictions and the block lists
// they name. Called from Profiles.Validate.
func (ps *Profiles) validateRestrictions() []string {
	var problems []string
	known := make(map[string]bool, len(ps.BlockLists))
	for name, domains := range ps.BlockLists {
		if strings.TrimSpace(name) == "" {
			problems = append(problems, "a block list has no name")
			continue
		}
		known[name] = true
		if len(domains) == 0 {
			problems = append(problems, fmt.Sprintf("block list %q is empty", name))
		}
		for _, d := range domains {
			if strings.ContainsAny(d, " \t/^|$") {
				// These are AdGuard rule syntax characters. A domain carrying
				// one would be silently reinterpreted as a different rule, and
				// a rule that means something other than what was typed is the
				// busybox-crond failure in another costume.
				problems = append(problems, fmt.Sprintf(
					"block list %q entry %q is not a plain domain name", name, d))
			}
		}
	}
	for _, p := range ps.Profiles {
		names := map[string]bool{}
		for _, r := range p.Restrictions {
			if names[r.Name] {
				problems = append(problems, fmt.Sprintf(
					"profile %q has two restrictions called %q", p.Name, r.Name))
			}
			names[r.Name] = true
			if err := r.Validate(known); err != nil {
				problems = append(problems, fmt.Sprintf("profile %q: %v", p.Name, err))
			}
		}
	}
	return problems
}
