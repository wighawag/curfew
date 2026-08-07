// Package budget is the daily time budget: how much of it a profile has spent,
// whether that spending has run out, and when the day starts again.
//
// It is PURE. It reads no files, opens no netlink socket and consults no
// clock of its own: every function takes the time it should use. That is what
// makes the continuity model below testable at the level it is hard at, which
// is the state machine, rather than only at the level it is slow at, which is
// the packet path.
//
// Three properties are load-bearing and are decided in
// docs/adr/0009-the-budget-continuity-model.md:
//
//   - A budget minute counts ACTUAL USE, per
//     docs/adr/0001-budget-counts-actual-use-gated-by-a-threshold.md. Nothing
//     here advances with the clock; usage only moves when a caller reports an
//     interval whose traffic exceeded the activity threshold.
//
//   - Everything is DERIVED from persisted counters plus the clock, and
//     nothing is fired at an edge. The daily rollover is a question ("which
//     budget day is it right now?"), not an event at 03:00, so a missed tick
//     cannot lose a night and a reset time pointed at an hour that does not
//     exist on a daylight-saving day still rolls over exactly once.
//
//   - The reset that starts a new day zeroes only state this package owns. It
//     cannot clear a manual block or a bedtime window, because it cannot see
//     them. The old implementation called unblock unconditionally on rollover
//     and silently cancelled bedtime; that is structurally impossible here.
package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that reads and writes as a human string in JSON
// ("4h", "30m", "2h30m").
//
// A bare number is REFUSED rather than guessed at. The legacy config wrote
// `eli|240` meaning 240 minutes, and a JSON `240` could as easily be seconds;
// a budget silently out by a factor of sixty is exactly the class of quiet
// wrongness this project exists to remove, so the parse says what to write
// instead.
type Duration time.Duration

// D is a shorthand for building a Duration in code and in tests.
func D(d time.Duration) Duration { return Duration(d) }

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String renders the duration the way a person writes it: "4h" rather than
// Go's "4h0m0s", which reads like three separate numbers on a form.
//
// It still round-trips through ParseDuration, which is what lets the same
// value be shown in an input box, typed back, and saved unchanged.
func (d Duration) String() string {
	s := time.Duration(d).String()
	switch {
	case strings.HasSuffix(s, "h0m0s"):
		return strings.TrimSuffix(s, "0m0s")
	case strings.HasSuffix(s, "m0s"):
		return strings.TrimSuffix(s, "0s")
	}
	return s
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON reads a duration string, and refuses a bare number.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		var n float64
		if json.Unmarshal(data, &n) == nil {
			return fmt.Errorf("a budget must carry its unit: write %q rather than %s, "+
				"because a bare number could be minutes or seconds and a budget that is "+
				"wrong by a factor of sixty looks like a working budget", fmt.Sprintf("%gm", n), string(data))
		}
		return fmt.Errorf("a budget must be a duration string such as \"4h\" or \"30m\", got %s", string(data))
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// ParseDuration reads a duration a person typed. An empty string is zero,
// which is how a form clears a limit and how "unlimited" is expressed.
//
// A bare number is REFUSED here too, and for the same reason as in JSON: on a
// form labelled "daily", typing 4 could mean four hours and typing 240 could
// mean 240 minutes, and a budget silently wrong by a factor of sixty still
// looks like a working budget. The error says what to type instead.
func ParseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return 0, fmt.Errorf("%q needs a unit: write %qh for hours or %qm for minutes", s, s, s)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (write it like \"4h\", \"90m\" or \"2h30m\")", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("%q is negative", s)
	}
	return Duration(v), nil
}

// Form renders a duration for a text input: empty when unset, so a form shows
// a blank box for "no limit" rather than "0s", which reads as "no time at all".
func (d Duration) Form() string {
	if d == 0 {
		return ""
	}
	return d.String()
}

// Limits is one profile's budget, and every field is optional. A profile whose
// limits are all zero is UNLIMITED, which is what a profile with no budget
// configured means and what a parent, a printer and a camera all need.
//
// Continuous, Gap and ResetGap are a GROUP: set all three or none. Each is
// meaningless without the others (see Validate), and a field that quietly
// means nothing is how the legacy config ended up giving a printer a budget.
type Limits struct {
	// Daily is the total usage allowed in one budget day.
	Daily Duration `json:"daily,omitempty"`
	// Continuous is the usage allowed in one unbroken session.
	Continuous Duration `json:"continuous,omitempty"`
	// Gap is the inactivity that ENDS a session. Below it, use is still the
	// same session. Reaching it ends the session at no cost: the next use
	// starts a fresh one with the continuous allowance full again.
	Gap Duration `json:"gap,omitempty"`
	// ResetGap is how long a profile must wait, after EXHAUSTING the
	// continuous allowance, before it may use budget again. It is wall-clock
	// (see ADR 0009), and it is the price of being cut off rather than of
	// stopping.
	ResetGap Duration `json:"reset_gap,omitempty"`
}

// Unlimited reports whether this profile has no budget at all.
func (l Limits) Unlimited() bool { return l == Limits{} }

// HasContinuity reports whether the session model applies to this profile.
func (l Limits) HasContinuity() bool { return l.Continuous > 0 }

// Validate refuses a set of limits that cannot mean what it looks like it
// means. Every rule here exists because the configuration would otherwise be
// silently inert or silently perverse, and this repo has already been bitten
// once by a config field that quietly meant the opposite of what was written
// (see work/notes/findings/busybox-crond-treats-a-bad-time-field-as-a-wildcard.md).
func (l Limits) Validate() error {
	var problems []string
	for _, f := range []struct {
		name string
		v    Duration
	}{
		{"daily", l.Daily}, {"continuous", l.Continuous},
		{"gap", l.Gap}, {"reset_gap", l.ResetGap},
	} {
		if f.v < 0 {
			problems = append(problems, fmt.Sprintf("%s is negative", f.name))
		}
	}
	group := 0
	for _, v := range []Duration{l.Continuous, l.Gap, l.ResetGap} {
		if v > 0 {
			group++
		}
	}
	if group != 0 && group != 3 {
		problems = append(problems,
			"continuous, gap and reset_gap must be set together or not at all: "+
				"a continuous allowance with no gap means a session can never end by stopping, "+
				"a continuous allowance with no reset_gap costs nothing to exhaust, "+
				"and a gap or reset_gap with no continuous allowance is a field that does nothing")
	}
	if l.Continuous > 0 && l.Daily > 0 && l.Continuous > l.Daily {
		problems = append(problems, fmt.Sprintf(
			"continuous (%s) is longer than daily (%s), so the continuous allowance can never be reached",
			l.Continuous, l.Daily))
	}
	// The one that inverts an incentive rather than merely doing nothing. If
	// waiting out the penalty is cheaper than simply stopping, the best play
	// is always to burn to exhaustion, and the gap threshold becomes a trap
	// for the child who stops voluntarily.
	if l.Continuous > 0 && l.ResetGap < l.Gap {
		problems = append(problems, fmt.Sprintf(
			"reset_gap (%s) is shorter than gap (%s), which makes being cut off cheaper "+
				"than stopping voluntarily; set reset_gap to at least gap",
			l.ResetGap, l.Gap))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// DefaultResetTime is when the budget day rolls over. Not midnight, because
// children are awake at midnight and a day that ends mid-evening-session is
// not the day a household means.
const DefaultResetTime = "03:00"

// DefaultActivityThreshold is how many bytes of traffic in a minute count as
// "actually using the internet".
//
// IT IS A GUESS. ADR 0001 requires it to be calibrated against real idle
// household devices, and that cannot be done in a container: it needs an
// evening of watching this household's own phones. What IS measured is the
// scale it lives on. Accounting counts UPSTREAM bytes only (see ADR 0009), and
// on the packet-path harness a 1 MiB download produced 14169 upstream bytes, a
// ratio of 1.35%, while a single small page fetch produced 850 and an idle
// client produced exactly 0. So 50 KiB/min is roughly 3.7 MB/min of download,
// or about 500 kbps sustained: below SD video, above music-only streaming, and
// far above a phone sending keepalives.
//
// Both ends of that justification are extrapolation from one topology. Treat
// this number as a starting point to be tuned, not as a measurement. The
// home page reports each profile's observed rate so it can be tuned against
// the devices actually in the house.
const DefaultActivityThreshold = 50 * 1024

// Settings are the budget knobs that belong to the HOUSEHOLD rather than to a
// child. Both are global by decision, recorded in ADR 0009: the reset time is
// the boundary of "a day", which cannot sensibly differ between two children
// under one roof, and the threshold is a property of how devices behave.
type Settings struct {
	// ResetTime is "HH:MM" in the router's timezone. Empty means
	// DefaultResetTime.
	ResetTime string `json:"reset_time,omitempty"`
	// ActivityThresholdBytesPerMinute is the traffic above which a minute
	// counts as use. Zero means DefaultActivityThreshold.
	ActivityThresholdBytesPerMinute uint64 `json:"activity_threshold_bytes_per_minute,omitempty"`
}

// resetTime returns the configured reset time, or the default.
func (s Settings) resetTime() string {
	if strings.TrimSpace(s.ResetTime) == "" {
		return DefaultResetTime
	}
	return s.ResetTime
}

// Threshold returns the configured activity threshold, or the default.
func (s Settings) Threshold() uint64 {
	if s.ActivityThresholdBytesPerMinute == 0 {
		return DefaultActivityThreshold
	}
	return s.ActivityThresholdBytesPerMinute
}

// Validate checks the settings are usable.
func (s Settings) Validate() error {
	if _, err := parseHHMM(s.resetTime()); err != nil {
		return fmt.Errorf("reset_time: %w", err)
	}
	return nil
}

func parseHHMM(v string) (int, error) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time %q (want HH:MM)", v)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour in %q (0-23)", v)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute in %q (0-59)", v)
	}
	return h*60 + m, nil
}

// DayFormat is how a budget day is written down.
const DayFormat = "2006-01-02"

// Day answers "which budget day are we in right now?", which is a QUESTION
// asked of the clock and never an event fired at the reset time.
//
// It returns the date the current budget day STARTED on, so with a 03:00 reset
// both 02:00 and 22:00 on the 8th belong to days named "the 7th" and "the 8th"
// respectively. Deriving it this way is what makes the reset unmissable: a
// daemon that was down across 03:00, or a reset time pointed at an hour that
// does not exist on a spring-forward day, still gets exactly one rollover,
// because there is no edge to miss.
//
// t must already be in the household's location; callers hold the zone.
func (s Settings) Day(t time.Time) string {
	reset, err := parseHHMM(s.resetTime())
	if err != nil {
		// Validate refuses this at load time. If it somehow gets here, falling
		// back to the default is better than picking a random day.
		reset, _ = parseHHMM(DefaultResetTime)
	}
	if t.Hour()*60+t.Minute() < reset {
		t = t.AddDate(0, 0, -1)
	}
	return t.Format(DayFormat)
}

// State is one profile's live budget state. It is PERSISTED: see the
// authoritative list in internal/blockstate.
//
// What is NOT here is as deliberate as what is. There is no "blocked" flag and
// no stored reason: whether the budget blocks is DERIVED from these counters
// against the limits on every check, per the enforcement spec, so nothing can
// latch and nothing needs restoring. And there is no previous counter reading,
// because the nftables counter it would baseline does not survive a reboot
// either; that lives in memory, in Sampler.
type State struct {
	// Usage is the total active time in the current budget day.
	Usage Duration `json:"usage,omitempty"`
	// Session is the active time in the current unbroken session.
	Session Duration `json:"session,omitempty"`
	// LastActive is when this profile last had traffic above the threshold.
	// It is what the gap threshold is measured from.
	LastActive time.Time `json:"last_active,omitempty"`
	// CooldownUntil is the wall-clock moment the profile may use budget again
	// after exhausting its continuous allowance. Zero means no cooldown.
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}

// Zero reports whether there is nothing worth persisting.
func (s State) Zero() bool { return s == State{} }

// Advance applies ONE observed accounting interval to a profile's state.
//
// active is whether the traffic that SURVIVED ENFORCEMENT in this interval
// exceeded the activity threshold; elapsed is how long the interval really
// was, taken from the clock rather than assumed, so an irregular tick charges
// what it actually observed.
//
// The whole continuity model lives in these few lines, and the shape of it is
// argued in ADR 0009. In summary: a session ends two ways, and only one of
// them costs anything.
func Advance(s State, l Limits, now time.Time, elapsed time.Duration, active bool) State {
	if l.Unlimited() {
		// A profile with no budget accrues NOTHING, rather than accruing a
		// counter nothing will ever read. Accounting still runs for it, so its
		// observed byte rate is still reported for threshold calibration, but
		// that lives in memory and never reaches the state file: a printer must
		// not grow persisted budget state, which is the shape ADR 0003 names as
		// the smell that motivated splitting devices from profiles.
		return State{}
	}
	// Cooldown expiry is DERIVED here too, not fired. Passing the moment is
	// what refills the continuous allowance, and it refills FULLY: a partial
	// refill would need a rate nobody specified and would make the fifth
	// session of the day shorter than the first for no reason a child could
	// predict.
	if !s.CooldownUntil.IsZero() && !now.Before(s.CooldownUntil) {
		s.CooldownUntil = time.Time{}
		s.Session = 0
		s.LastActive = time.Time{}
	}
	if !active || elapsed <= 0 {
		// An idle interval costs nothing. Note there is deliberately no
		// "end the session now" step here: the session ending is derived from
		// LastActive on the next ACTIVE interval, so an idle daemon, a missed
		// tick and a sleeping house all behave the same.
		return s
	}

	// The global budget burns whenever traffic survives enforcement. That
	// includes traffic under a live ticket, which is the decided behaviour: a
	// ticketed child does burn budget, and no bookkeeping marks it.
	s.Usage += Duration(elapsed)

	if !s.CooldownUntil.IsZero() {
		// Traffic during a cooldown means a ticket is overriding the budget
		// block. The session is already spent and stays spent: the cooldown
		// runs on wall-clock and a ticket neither pauses nor cancels it.
		s.LastActive = now
		return s
	}

	if !l.HasContinuity() {
		// A daily-only budget has no session to track, and tracking one anyway
		// would persist a number nothing can read.
		return s
	}

	// A session ends NATURALLY when the gap threshold of inactivity has
	// passed, and that costs nothing at all. Only exhausting the continuous
	// allowance costs a reset gap; if stopping cost one too, the gap threshold
	// would punish the child who stops voluntarily.
	if l.Gap > 0 && !s.LastActive.IsZero() && now.Sub(s.LastActive) >= l.Gap.Std() {
		s.Session = 0
	}
	s.Session += Duration(elapsed)
	s.LastActive = now

	if s.Session >= l.Continuous {
		s.CooldownUntil = now.Add(l.ResetGap.Std())
	}
	return s
}

// Reason is why the budget is blocking, in words a page can show.
type Reason string

// The two ways a budget blocks.
const (
	// ReasonDaily means the whole day's allowance is spent.
	ReasonDaily Reason = "daily budget spent"
	// ReasonContinuous means the unbroken-session allowance is spent and the
	// reset gap has not yet elapsed.
	ReasonContinuous Reason = "continuous budget spent"
)

// Blocked derives whether the budget blocks this profile RIGHT NOW.
//
// It is recomputed from the counters on every check and never stored, which is
// what makes a bare unblock unable to stick against it (deliberately: giving
// more time is a ticket) and what makes the daily reset structurally incapable
// of clearing a reason it does not own.
func Blocked(s State, l Limits, now time.Time) (bool, Reason) {
	if l.Daily > 0 && s.Usage >= l.Daily {
		return true, ReasonDaily
	}
	if l.Continuous > 0 && !s.CooldownUntil.IsZero() && now.Before(s.CooldownUntil) {
		return true, ReasonContinuous
	}
	return false, ""
}

// Status is everything a page needs to say about one profile's allowance.
//
// It lives in THIS package, which depends on nothing, rather than in the
// policy layer, so that the HTTP surface can render a budget without importing
// the package that can rewrite a firewall. That split is the same one
// separation_test.go pins for the laptop binary, kept voluntarily here.
type Status struct {
	// Limits are what this profile is allowed.
	Limits Limits
	// Used is how much of the day has been spent.
	Used time.Duration
	// DailyLeft and SessionLeft are the remaining allowances. The OK flags are
	// false when that allowance is unlimited, which is different from zero
	// remaining and must not render as "0m left".
	DailyLeft   time.Duration
	DailyOK     bool
	SessionLeft time.Duration
	SessionOK   bool
	// Blocked and Reason are the DERIVED budget reason: recomputed from the
	// counters here, never stored, exactly as the enforcement path recomputes
	// it.
	Blocked bool
	Reason  Reason
	// CooldownLeft is how long until a spent continuous allowance refills.
	CooldownLeft time.Duration
	// ObservedBytes is the traffic measured in the last accounting interval,
	// and ObservedOK says whether there was one.
	//
	// This is on the page for ONE reason: the activity threshold's default is
	// an unvalidated guess (see DefaultActivityThreshold), and ADR 0001
	// requires it to be calibrated against real idle household devices. This
	// is how a household does that: watch a device that is doing nothing, see
	// what it actually sends, and set the threshold above it.
	ObservedBytes  uint64
	ObservedOK     bool
	ObservedActive bool
}

// Remaining reports how much of each allowance is left, for a page to show.
// A zero limit means unlimited and reports zero remaining with ok false.
func Remaining(s State, l Limits) (daily time.Duration, dailyOK bool,
	session time.Duration, sessionOK bool) {
	if l.Daily > 0 {
		dailyOK = true
		daily = l.Daily.Std() - s.Usage.Std()
		if daily < 0 {
			daily = 0
		}
	}
	if l.Continuous > 0 {
		sessionOK = true
		session = l.Continuous.Std() - s.Session.Std()
		if session < 0 {
			session = 0
		}
	}
	return
}
