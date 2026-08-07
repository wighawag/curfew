package budget

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The continuity model of docs/adr/0009-the-budget-continuity-model.md,
// asserted at the level it is hard at. These are unit tests on purpose: the
// state machine is where the edges live, and the packet path is where the
// wiring lives. Both are covered, in the place each is actually testable.

func at(hhmm string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", "2026-08-07 "+hhmm)
	if err != nil {
		panic(err)
	}
	return t
}

// household is the worked example from the brief: 4h a day, 2h at a stretch,
// a stretch ends after 10m of not using it, and burning the 2h costs 30m.
var household = Limits{
	Daily: D(4 * time.Hour), Continuous: D(2 * time.Hour),
	Gap: D(10 * time.Minute), ResetGap: D(30 * time.Minute),
}

// drive runs a sequence of intervals and returns the resulting state.
func drive(s State, l Limits, start time.Time, step time.Duration, n int, active bool) (State, time.Time) {
	now := start
	for range n {
		now = now.Add(step)
		s = Advance(s, l, now, step, active)
	}
	return s, now
}

func TestAnIdleProfileBurnsNothing(t *testing.T) {
	s, _ := drive(State{}, household, at("09:00"), time.Minute, 600, false)
	if s.Usage != 0 {
		t.Errorf("ten hours of an idle household burned %s of budget; a budget minute counts USE", s.Usage)
	}
	if !s.Zero() {
		t.Errorf("an idle profile should have nothing worth persisting, got %+v", s)
	}
}

func TestActiveMinutesBurnBudgetAndBlockAtTheLimit(t *testing.T) {
	s, now := drive(State{}, Limits{Daily: D(4 * time.Hour)}, at("09:00"), time.Minute, 239, true)
	if blocked, _ := Blocked(s, Limits{Daily: D(4 * time.Hour)}, now); blocked {
		t.Fatalf("blocked after %s of a 4h budget", s.Usage)
	}
	s, now = drive(s, Limits{Daily: D(4 * time.Hour)}, now, time.Minute, 1, true)
	blocked, reason := Blocked(s, Limits{Daily: D(4 * time.Hour)}, now)
	if !blocked {
		t.Errorf("still allowed after %s of a 4h budget", s.Usage)
	}
	if reason != ReasonDaily {
		t.Errorf("reason = %q, want %q", reason, ReasonDaily)
	}
}

// The bug being replaced, asserted directly: the legacy budget-check
// incremented every minute from midnight, so `eli|240` meant "blocked at
// 04:00" whether or not a device was even switched on.
func TestWallClockTimeAloneNeverExhaustsABudget(t *testing.T) {
	l := Limits{Daily: D(4 * time.Hour)}
	// A whole day passes. Nobody uses the internet.
	s, now := drive(State{}, l, at("00:00"), time.Minute, 1439, false)
	if blocked, _ := Blocked(s, l, now); blocked {
		t.Error("a day of wall-clock time exhausted a budget nobody spent")
	}
}

func TestASessionEndsAfterTheGapAndRefillsInFull(t *testing.T) {
	// An hour and a half of use, then a long pause, then more use.
	s, now := drive(State{}, household, at("09:00"), time.Minute, 90, true)
	if s.Session.Std() != 90*time.Minute {
		t.Fatalf("session = %s, want 1h30m", s.Session)
	}
	// A pause longer than the gap: no intervals are reported at all, because
	// an idle interval reports nothing. The session end is derived on the next
	// ACTIVE interval, which is what makes an idle daemon behave the same.
	now = now.Add(11 * time.Minute)
	s = Advance(s, household, now, time.Minute, true)
	if s.Session.Std() != time.Minute {
		t.Errorf("after a gap longer than the threshold the session should restart, got %s", s.Session)
	}
	if s.Usage.Std() != 91*time.Minute {
		t.Errorf("the pause must not affect the DAILY usage, got %s", s.Usage)
	}
	if blocked, _ := Blocked(s, household, now); blocked {
		t.Error("ending a session naturally must cost nothing")
	}
}

func TestAPauseShorterThanTheGapIsTheSameSession(t *testing.T) {
	s, now := drive(State{}, household, at("09:00"), time.Minute, 30, true)
	now = now.Add(9 * time.Minute) // below the 10m threshold
	s = Advance(s, household, now, time.Minute, true)
	if s.Session.Std() != 31*time.Minute {
		t.Errorf("a pause below the gap threshold must not end the session, got %s", s.Session)
	}
}

func TestExhaustingTheContinuousAllowanceCostsTheResetGap(t *testing.T) {
	s, now := drive(State{}, household, at("09:00"), time.Minute, 120, true)
	blocked, reason := Blocked(s, household, now)
	if !blocked {
		t.Fatalf("two hours at a stretch must block, session=%s", s.Session)
	}
	if reason != ReasonContinuous {
		t.Errorf("reason = %q, want %q", reason, ReasonContinuous)
	}
	// The daily budget still has two hours in it, which is the whole point of
	// having two knobs.
	if s.Usage.Std() != 2*time.Hour {
		t.Errorf("usage = %s, want 2h", s.Usage)
	}

	// Still blocked 29 minutes later.
	if blocked, _ := Blocked(s, household, now.Add(29*time.Minute)); !blocked {
		t.Error("the reset gap must still be in force after 29 of its 30 minutes")
	}
	// Free 30 minutes later, with the continuous allowance refilled in FULL.
	after := now.Add(30 * time.Minute)
	if blocked, _ := Blocked(s, household, after); blocked {
		t.Error("the reset gap must have elapsed after 30 minutes")
	}
	s = Advance(s, household, after, time.Minute, true)
	if s.Session.Std() != time.Minute {
		t.Errorf("the continuous allowance must refill in full, session = %s", s.Session)
	}
	if s.Usage.Std() != 2*time.Hour+time.Minute {
		t.Errorf("the daily usage must survive the cooldown, got %s", s.Usage)
	}
}

// The reset gap is WALL-CLOCK, not inactivity. This is the assertion that
// distinguishes the two readings: the profile is blocked throughout, so no
// traffic can be observed, and the cooldown must still end.
func TestTheResetGapIsWallClockAndEndsWithNoObservationAtAll(t *testing.T) {
	s, now := drive(State{}, household, at("09:00"), time.Minute, 120, true)
	if blocked, _ := Blocked(s, household, now); !blocked {
		t.Fatal("must start out blocked")
	}
	// Not one interval is reported for the whole cooldown, because a blocked
	// profile's traffic never reaches the counter.
	if blocked, _ := Blocked(s, household, now.Add(31*time.Minute)); blocked {
		t.Error("the cooldown never ended, so it was waiting for an observation that cannot arrive")
	}
}

// A ticket burns both allowances and does not cut the cooldown short.
func TestTrafficDuringACooldownBurnsTheDayButNotTheSession(t *testing.T) {
	s, now := drive(State{}, household, at("09:00"), time.Minute, 120, true)
	cooldown := s.CooldownUntil
	// A parent issues a ticket, so traffic survives enforcement again.
	s, now = drive(s, household, now, time.Minute, 10, true)
	if s.Usage.Std() != 2*time.Hour+10*time.Minute {
		t.Errorf("a ticketed child must still burn the DAILY budget, usage = %s", s.Usage)
	}
	if !s.CooldownUntil.Equal(cooldown) {
		t.Errorf("a ticket must not move the cooldown: %s then %s", cooldown, s.CooldownUntil)
	}
	if s.Session < household.Continuous {
		t.Errorf("the session must stay exhausted during a cooldown, got %s", s.Session)
	}
	// And when the cooldown ends the session refills, rather than the ticket
	// having laundered a fresh one early.
	if blocked, _ := Blocked(s, household, now.Add(21*time.Minute)); blocked {
		t.Error("the cooldown should have ended 30 minutes after it began")
	}
	_ = now
}

func TestTheDailyLimitStillBitesWhileSessionsRotate(t *testing.T) {
	// Four sessions of an hour each, separated by long pauses, is 4h of use
	// and never touches the continuous allowance.
	s := State{}
	now := at("08:00")
	for range 4 {
		s, now = drive(s, household, now, time.Minute, 60, true)
		now = now.Add(20 * time.Minute)
	}
	if s.Usage.Std() != 4*time.Hour {
		t.Fatalf("usage = %s, want 4h", s.Usage)
	}
	blocked, reason := Blocked(s, household, now)
	if !blocked || reason != ReasonDaily {
		t.Errorf("blocked=%v reason=%q, want the DAILY limit to bite", blocked, reason)
	}
}

func TestAnUnlimitedProfileIsNeverBlocked(t *testing.T) {
	s, now := drive(State{}, Limits{}, at("09:00"), time.Minute, 1000, true)
	if blocked, _ := Blocked(s, Limits{}, now); blocked {
		t.Error("a profile with no budget must be unlimited")
	}
	if !s.Zero() {
		t.Errorf("an unlimited profile should accumulate nothing worth persisting, got %+v", s)
	}
}

func TestIrregularIntervalsChargeWhatTheyObserved(t *testing.T) {
	l := Limits{Daily: D(time.Hour)}
	s := Advance(State{}, l, at("09:00"), 5*time.Minute, true)
	if s.Usage.Std() != 5*time.Minute {
		t.Errorf("a five minute interval must charge five minutes, got %s", s.Usage)
	}
	s = Advance(s, l, at("09:06"), 30*time.Second, true)
	if s.Usage.Std() != 5*time.Minute+30*time.Second {
		t.Errorf("usage = %s, want 5m30s", s.Usage)
	}
}

// ---- the day ----

func TestTheBudgetDayRollsOverAtTheResetTimeNotMidnight(t *testing.T) {
	s := Settings{}
	if got := s.Day(at("02:59")); got != "2026-08-06" {
		t.Errorf("at 02:59 the budget day should still be the 6th, got %s", got)
	}
	if got := s.Day(at("03:00")); got != "2026-08-07" {
		t.Errorf("at 03:00 the budget day should be the 7th, got %s", got)
	}
	if got := s.Day(at("23:59")); got != "2026-08-07" {
		t.Errorf("at 23:59 the budget day should be the 7th, got %s", got)
	}
	// Midnight is deliberately NOT a boundary: children are awake at midnight.
	if s.Day(at("23:59")) != s.Day(at("00:30").AddDate(0, 0, 1)) {
		t.Error("23:59 and 00:30 the next morning must be the same budget day")
	}
}

func TestTheResetTimeIsConfigurable(t *testing.T) {
	s := Settings{ResetTime: "06:00"}
	if got := s.Day(at("05:59")); got != "2026-08-06" {
		t.Errorf("got %s, want the previous day before a 06:00 reset", got)
	}
	if got := s.Day(at("06:00")); got != "2026-08-07" {
		t.Errorf("got %s, want the current day at a 06:00 reset", got)
	}
}

// The reset time must be derived, never fired, and this is why: on a
// spring-forward day the configured hour may not exist at all. A scheduled
// event at 02:30 would never run; a question asked of the clock still gets
// exactly one rollover, at the jump.
func TestAResetTimeInsideAMissingHourStillRollsOverExactlyOnce(t *testing.T) {
	// Europe/London springs forward at 01:00 GMT on 2026-03-29: 01:00 to 02:00
	// does not exist. Configure the reset inside that hour.
	loc, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Skipf("no tzdata in this test binary: %v", err)
	}
	s := Settings{ResetTime: "01:30"}
	before := time.Date(2026, 3, 29, 0, 59, 0, 0, loc)
	after := before.Add(2 * time.Minute) // 02:01 BST, the instant past the jump
	if h, m := after.Hour(), after.Minute(); h != 2 || m != 1 {
		t.Fatalf("the fixture assumes a spring-forward at 01:00; got %02d:%02d", h, m)
	}
	if got := s.Day(before); got != "2026-03-28" {
		t.Errorf("before the jump the budget day should be the 28th, got %s", got)
	}
	if got := s.Day(after); got != "2026-03-29" {
		t.Errorf("after the jump the budget day should be the 29th, got %s", got)
	}
}

// ---- validation ----

func TestValidateRefusesAResetGapWeakerThanStopping(t *testing.T) {
	l := Limits{Continuous: D(2 * time.Hour), Gap: D(10 * time.Minute), ResetGap: D(5 * time.Minute)}
	err := l.Validate()
	if err == nil {
		t.Fatal("a reset gap shorter than the gap threshold makes being cut off cheaper than stopping, and must be refused")
	}
	if !strings.Contains(err.Error(), "reset_gap") {
		t.Errorf("the message must name the field to fix, got %v", err)
	}
	// Equal is allowed: it is the weakest penalty that is not perverse.
	l.ResetGap = l.Gap
	if err := l.Validate(); err != nil {
		t.Errorf("reset_gap == gap must be allowed, got %v", err)
	}
}

func TestValidateRefusesAHalfConfiguredContinuityGroup(t *testing.T) {
	for _, l := range []Limits{
		{Continuous: D(time.Hour)},
		{Continuous: D(time.Hour), Gap: D(time.Minute)},
		{Gap: D(time.Minute)},
		{ResetGap: D(time.Minute)},
		{Continuous: D(time.Hour), ResetGap: D(time.Minute)},
	} {
		if err := l.Validate(); err == nil {
			t.Errorf("%+v must be refused: a field that quietly does nothing is how a printer got a budget", l)
		}
	}
	if err := household.Validate(); err != nil {
		t.Errorf("the worked example must be valid, got %v", err)
	}
	if err := (Limits{Daily: D(time.Hour)}).Validate(); err != nil {
		t.Errorf("a daily-only budget must be valid, got %v", err)
	}
	if err := (Limits{}).Validate(); err != nil {
		t.Errorf("an empty budget means unlimited and must be valid, got %v", err)
	}
}

func TestValidateRefusesAContinuousAllowanceThatCanNeverBeReached(t *testing.T) {
	l := Limits{Daily: D(time.Hour), Continuous: D(2 * time.Hour),
		Gap: D(time.Minute), ResetGap: D(time.Minute)}
	if err := l.Validate(); err == nil {
		t.Error("continuous longer than daily can never be reached, and must be refused")
	}
}

func TestSettingsRefuseAnImpossibleResetTime(t *testing.T) {
	for _, v := range []string{"24:00", "3", "03:60", "aa:bb", "-1:00"} {
		if err := (Settings{ResetTime: v}).Validate(); err == nil {
			t.Errorf("reset_time %q must be refused rather than reinterpreted", v)
		}
	}
	if err := (Settings{}).Validate(); err != nil {
		t.Errorf("the default reset time must be valid, got %v", err)
	}
}

// ---- config encoding ----

func TestABareNumberIsRefusedRatherThanGuessedAt(t *testing.T) {
	var l Limits
	err := json.Unmarshal([]byte(`{"daily": 240}`), &l)
	if err == nil {
		t.Fatal("a bare 240 could be minutes or seconds; guessing is how a budget ends up wrong by a factor of sixty")
	}
	if !strings.Contains(err.Error(), "240m") {
		t.Errorf("the message must show what to write instead, got %v", err)
	}
}

func TestLimitsRoundTripThroughJSON(t *testing.T) {
	data, err := json.Marshal(household)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Limits
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
	if back != household {
		t.Errorf("round trip changed the budget: %+v -> %s -> %+v", household, data, back)
	}
	var empty Limits
	if err := json.Unmarshal([]byte(`{}`), &empty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if !empty.Unlimited() {
		t.Error("a profile with no budget fields must be unlimited")
	}
}

func TestRemainingNeverGoesNegative(t *testing.T) {
	s := State{Usage: D(5 * time.Hour), Session: D(3 * time.Hour)}
	daily, dailyOK, session, sessionOK := Remaining(s, household)
	if !dailyOK || daily != 0 {
		t.Errorf("daily left = %s (ok=%v), want 0", daily, dailyOK)
	}
	if !sessionOK || session != 0 {
		t.Errorf("session left = %s (ok=%v), want 0", session, sessionOK)
	}
	_, dailyOK, _, sessionOK = Remaining(State{}, Limits{})
	if dailyOK || sessionOK {
		t.Error("an unlimited profile has no remaining allowance to report")
	}
}

// Durations are shown in input boxes and typed back, so how they RENDER is
// part of the config surface rather than cosmetics: "4h0m0s" in a text box
// reads like three numbers and invites someone to "fix" it.
func TestDurationsRenderTheWayAPersonWritesThem(t *testing.T) {
	for in, want := range map[time.Duration]string{
		4 * time.Hour:                "4h",
		2*time.Hour + 30*time.Minute: "2h30m",
		10 * time.Minute:             "10m",
		30 * time.Second:             "30s",
		time.Minute + 30*time.Second: "1m30s",
		time.Hour + 30*time.Second:   "1h0m30s",
	} {
		if got := D(in).String(); got != want {
			t.Errorf("D(%s).String() = %q, want %q", in, got, want)
		}
		// The load-bearing half: whatever it renders as must parse back to
		// the same value, or showing a budget in a form and saving it would
		// change it.
		back, err := ParseDuration(D(in).String())
		if err != nil {
			t.Errorf("%q does not parse back: %v", D(in).String(), err)
			continue
		}
		if back != D(in) {
			t.Errorf("%s rendered as %q and parsed back as %s", in, D(in).String(), back)
		}
	}
	if got := D(0).Form(); got != "" {
		t.Errorf("an unset limit must render as an empty box, got %q", got)
	}
}
