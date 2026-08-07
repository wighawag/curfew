package httpui

import (
	"fmt"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/contract"
)

// firewallState is what the kernel is doing right now: one membership list per
// tier of the ordering contract, plus the kernel's own countdown for tickets.
//
// It is read once per request and then asked about each device, rather than
// each page component reading the firewall for itself. That matters for more
// than speed: two reads a moment apart can straddle a ticket expiring, and a
// page that says "blocked" in one column and "23 seconds left" in another is
// the kind of small lie this project keeps having to remove.
type firewallState struct {
	member  map[string]map[string]bool
	tickets map[string]time.Duration
}

// readFirewall loads every tier's membership.
//
// The unknown-tier case is an error rather than an empty set: adding a tier to
// contract.Tiers without teaching the UI to read it would otherwise render a
// device's state by silently skipping a rule that is really there, which is
// exactly the class of quiet wrongness ADR 0004 exists to stop.
func (s *Server) readFirewall() (*firewallState, error) {
	f := &firewallState{member: map[string]map[string]bool{}}
	for _, tier := range contract.Tiers {
		var macs []string
		var err error
		switch tier.Set {
		case contract.AllowedSet:
			macs, err = s.firewall.Allowlist()
		case contract.BlockedSet:
			macs, err = s.firewall.Blocked()
		case contract.ManualBlockedSet:
			macs, err = s.firewall.ManualBlocked()
		case contract.TicketSet:
			f.tickets, err = s.firewall.Tickets()
			for m := range f.tickets {
				macs = append(macs, m)
			}
		default:
			return nil, fmt.Errorf("the page cannot read tier %q: "+
				"a tier was added to contract.Tiers without wiring it up here", tier.Set)
		}
		if err != nil {
			return nil, err
		}
		set := make(map[string]bool, len(macs))
		for _, m := range macs {
			set[m] = true
		}
		f.member[tier.Set] = set
	}
	return f, nil
}

// verdict answers what the firewall will actually do to a packet from this MAC,
// by walking contract.Tiers IN ORDER, exactly as the chain does.
//
// Walking the shared list rather than restating the precedence is what stops
// the page and the ruleset drifting apart: reordering the tiers changes both
// the chain and this answer, so the packet-path tests are a check on the
// page's story too. The reason returned is the tier that decided, or empty
// when nothing matched and the terminal drop applies.
func (f *firewallState) verdict(mac string) (allowed bool, reason string) {
	for _, tier := range contract.Tiers {
		if f.member[tier.Set][mac] {
			return tier.Accept, tier.Reason
		}
	}
	return false, ""
}

// ticketLeft reports the shortest time left on any of these MACs' tickets, and
// whether every one of them has one.
//
// The shortest rather than the longest, because a profile is only free for as
// long as its most-nearly-expired device: they are granted together, so they
// differ by milliseconds, and rounding the wrong way would show a minute of
// access that is not there.
func (f *firewallState) ticketLeft(macs []string) (time.Duration, bool) {
	if len(macs) == 0 {
		return 0, false
	}
	var shortest time.Duration
	for i, m := range macs {
		d, ok := f.tickets[m]
		if !ok {
			return 0, false
		}
		if i == 0 || d < shortest {
			shortest = d
		}
	}
	return shortest, true
}

// budgetLines renders a profile's allowance, and what its devices actually
// sent in the last accounting interval.
//
// The observed figure is shown for EVERY profile, including those with no
// budget at all, and that is the point of it rather than an oversight: the
// activity threshold's default is an unvalidated guess, ADR 0001 requires it
// to be calibrated against real IDLE devices, and the idle devices in a house
// are exactly the ones nobody has given a budget. Without this line a
// household has no way to replace the guess with a measurement.
func budgetLines(b budget.Status, interval time.Duration) (allowance, observed string) {
	if !b.Limits.Unlimited() {
		parts := []string{fmt.Sprintf("used %s today", humanDuration(b.Used))}
		if b.DailyOK {
			parts = append(parts, fmt.Sprintf("%s of %s left",
				humanDuration(b.DailyLeft), b.Limits.Daily))
		}
		if b.SessionOK {
			parts = append(parts, fmt.Sprintf("%s of this stretch's %s left",
				humanDuration(b.SessionLeft), b.Limits.Continuous))
		}
		allowance = strings.Join(parts, " \u00b7 ")
	}
	if b.ObservedOK && interval > 0 {
		state := "idle"
		if b.ObservedActive {
			state = "counted as use"
		}
		observed = fmt.Sprintf("last %s: %s upstream (%s)",
			humanInterval(interval), humanBytes(b.ObservedBytes), state)
	}
	return allowance, observed
}

// humanInterval renders a sampling interval, which unlike a budget may be well
// under a minute in a test.
func humanInterval(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}
	return humanDuration(d)
}

// humanBytes renders a byte count. Exact below a kilobyte, because the numbers
// that matter for calibration are the small ones a sleeping phone produces.
func humanBytes(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

// humanDuration renders a duration the way a parent would say it. It rounds
// DOWN, so the page never promises time that has already gone.
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}
