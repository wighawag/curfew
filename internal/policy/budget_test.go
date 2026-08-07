package policy

import (
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// Unit tests for how the policy layer WIRES budgets in: which set the reason
// lands in, when the day rolls over, and what a tick does to the state file.
// What a budget MEANS is tested in internal/budget, and what the kernel does
// about it is tested with packets.

// fakeAccountant is a DUMB double: it hands back whatever counters it was
// given and remembers nothing about budgets.
//
// It reproduces no rule from the production code, which is a deliberate
// constraint learned here: a double that re-implements the thing under test
// will happily agree with a broken implementation. Everything load-bearing
// about the real accountant (that a blocked device's traffic never reaches it,
// that a rebuild zeroes it, that a counter is cumulative) is asserted against
// the REAL one in the packet-path tests.
type fakeAccountant struct {
	counters   map[string]uint64
	generation uint64
	shapes     int
}

// EnsureShape brings a counter into existence for every shaped profile, at
// zero, which is what the real accountant does: a counter rule exists from the
// moment the table is built, and reads as 0 until traffic moves it. Getting
// that wrong in the double would hide the sampler's first-reading behaviour
// behind a permanently-absent counter.
func (f *fakeAccountant) EnsureShape(profiles map[string][]string) (bool, error) {
	f.shapes++
	if f.counters == nil {
		f.counters = map[string]uint64{}
	}
	for name, macs := range profiles {
		if len(macs) == 0 {
			continue
		}
		if _, ok := f.counters[name]; !ok {
			f.counters[name] = 0
		}
	}
	return false, nil
}
func (f *fakeAccountant) Read() (map[string]uint64, error) {
	out := map[string]uint64{}
	for k, v := range f.counters {
		out[k] = v
	}
	return out, nil
}
func (f *fakeAccountant) Generation() uint64 { return f.generation }

// send adds bytes to a profile's cumulative counter, the way real traffic does.
func (f *fakeAccountant) send(profile string, bytes uint64) {
	if f.counters == nil {
		f.counters = map[string]uint64{}
	}
	f.counters[profile] += bytes
}

const testMAC = "aa:bb:cc:dd:ee:0a"

// budgetCore builds a core with one budgeted profile and a controllable clock.
func budgetCore(t *testing.T, limits budget.Limits, now *time.Time) (
	*Core, *fakeAccountant, *memState, *fakeFirewall) {
	t.Helper()
	reg := &registry.Registry{}
	if err := reg.Add(testMAC, "phone"); err != nil {
		t.Fatal(err)
	}
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{testMAC}, Budget: limits},
	}}
	st := &memState{st: &blockstate.State{ManualBlocked: []string{}}}
	fw := &fakeFirewall{}
	acct := &fakeAccountant{}
	core := New(memRegistry{reg}, memSchedule{ps}, st, fw, time.UTC, nil).
		WithAccounting(acct, time.Minute, 50*1024)
	core.now = func() time.Time { return *now }
	return core, acct, st, fw
}

// A spent budget must land in the SAME set the schedule uses, so a ticket can
// override it by chain position and no new tier is needed.
func TestASpentBudgetJoinsTheScheduleBlockSetAndNotTheManualOne(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	core, acct, _, fw := budgetCore(t, budget.Limits{Daily: budget.D(2 * time.Minute)}, &now)

	if err := core.Tick(); err != nil { // baseline sample
		t.Fatalf("Tick: %v", err)
	}
	for range 3 {
		acct.send("eli", 900*1024)
		now = now.Add(time.Minute)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}
	if !contains(fw.last.Blocked, testMAC) {
		t.Errorf("a spent budget must block via the schedule set, got Blocked=%v", fw.last.Blocked)
	}
	if contains(fw.last.Manual, testMAC) {
		t.Error("a spent budget must NOT use the manual tier: a manual block outranks a ticket, " +
			"so a child could never be given more time")
	}
	if !contains(fw.last.Allowed, testMAC) {
		t.Error("the device is still registered and must stay on the allowlist")
	}
}

// The rollover, driven through the whole layer: crossing the reset time zeroes
// usage and lets the child back online.
func TestTheBudgetDayRollsOverAndTheChildComesBackOnline(t *testing.T) {
	now := time.Date(2026, 8, 7, 22, 0, 0, 0, time.UTC)
	core, acct, st, fw := budgetCore(t, budget.Limits{Daily: budget.D(2 * time.Minute)}, &now)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	for range 3 {
		acct.send("eli", 900*1024)
		now = now.Add(time.Minute)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}
	if !contains(fw.last.Blocked, testMAC) {
		t.Fatal("the budget should be spent before the rollover is tested")
	}

	// 02:59 the next morning: still the same budget day, still blocked. This
	// is the control that stops the test passing merely because time moved.
	now = time.Date(2026, 8, 8, 2, 59, 0, 0, time.UTC)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !contains(fw.last.Blocked, testMAC) {
		t.Error("the budget day must not roll over before the reset time")
	}

	// 03:00: a new day.
	now = time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if contains(fw.last.Blocked, testMAC) {
		t.Error("the budget day rolled over but the child is still blocked")
	}
	if st.st.BudgetDay != "2026-08-08" {
		t.Errorf("the day marker was not advanced, got %q", st.st.BudgetDay)
	}
}

// The reset must not unblock anything it does not own. The old implementation
// called unblock unconditionally on rollover and silently cleared bedtime.
func TestTheDailyResetLeavesAManualBlockStanding(t *testing.T) {
	now := time.Date(2026, 8, 7, 22, 0, 0, 0, time.UTC)
	core, acct, st, fw := budgetCore(t, budget.Limits{Daily: budget.D(time.Minute)}, &now)
	if err := core.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	acct.send("eli", 900*1024)
	now = now.Add(time.Minute)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	now = time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !st.st.IsBlocked("eli") {
		t.Error("the daily reset cleared a manual block, which it does not own")
	}
	if !contains(fw.last.Manual, testMAC) {
		t.Error("the manual block stopped being enforced after the daily reset")
	}
}

// Reconcile is called on every button press. If it advanced the budget, a
// parent tapping around would burn a child's afternoon.
func TestReconcileDoesNotAdvanceTheBudget(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	core, acct, st, _ := budgetCore(t, budget.Limits{Daily: budget.D(2 * time.Minute)}, &now)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	for range 50 {
		acct.send("eli", 900*1024)
		now = now.Add(time.Minute)
		if err := core.Reconcile(); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if used := st.st.Budget["eli"].Usage; used != 0 {
		t.Errorf("fifty reconciles burned %s of budget; only a tick may account", used)
	}
}

// An unlimited profile must reach neither the state file nor the block set,
// however much traffic it generates.
func TestAnUnlimitedProfileIsNeverBlockedAndWritesNoState(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	core, acct, st, fw := budgetCore(t, budget.Limits{}, &now)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	for range 20 {
		acct.send("eli", 9*1024*1024)
		now = now.Add(time.Minute)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}
	if contains(fw.last.Blocked, testMAC) {
		t.Error("a profile with no budget must be unlimited")
	}
	if len(st.st.Budget) != 0 {
		t.Errorf("a profile with no budget must not accrue persisted state, got %+v", st.st.Budget)
	}
}

// Accounting must cover EVERY profile, not only budgeted ones, or a household
// has no way to see what an idle device sends and the activity threshold can
// only ever be the guess it ships with.
func TestAccountingCoversProfilesWithNoBudget(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	core, acct, _, _ := budgetCore(t, budget.Limits{}, &now)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	acct.send("eli", 4096)
	now = now.Add(time.Minute)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	status, err := core.BudgetStatus()
	if err != nil {
		t.Fatalf("BudgetStatus: %v", err)
	}
	got := status["eli"]
	if !got.ObservedOK || got.ObservedBytes != 4096 {
		t.Errorf("an unbudgeted profile must still report what it sent, got %+v", got)
	}
	if got.ObservedActive {
		t.Error("4 KB in a minute is below a 50 KB threshold and must read as idle")
	}
}

// Accounting failing must not take enforcement down with it: a budget that
// cannot be measured should leave bedtime running.
func TestAccountingFailureStillLeavesEnforcementRunning(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	core, _, _, fw := budgetCore(t, budget.Limits{Daily: budget.D(time.Hour)}, &now)
	core.accountant = brokenAccountant{}
	if err := core.Tick(); err != nil {
		t.Errorf("a broken accountant must not fail the whole tick, got %v", err)
	}
	if !contains(fw.last.Allowed, testMAC) {
		t.Error("enforcement did not run after accounting failed")
	}
}

type brokenAccountant struct{}

func (brokenAccountant) EnsureShape(map[string][]string) (bool, error) {
	return false, errBroken
}
func (brokenAccountant) Read() (map[string]uint64, error) { return nil, errBroken }
func (brokenAccountant) Generation() uint64               { return 0 }

var errBroken = errNotWorking{}

type errNotWorking struct{}

func (errNotWorking) Error() string { return "netlink is broken" }

// contains is shared with the packet-path tests in this package.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// An OpenWrt router has no RTC and boots at the epoch, so the clock jumping
// BACKWARDS is a routine event, not a corner case.
//
// blockstate.RollOver refuses to move the day marker back, which protects the
// counters from being zeroed. That is only half the job: the accounting path
// also READS the counters under a day key, and reading them under the wrong
// (earlier) day returns zero state, so the next write would overwrite a spent
// allowance with a fresh one. The guard has to hold on both paths or it holds
// on neither.
func TestAClockThatJumpsBackwardsDoesNotHandBackASpentAllowance(t *testing.T) {
	now := time.Date(2026, 8, 7, 20, 0, 0, 0, time.UTC)
	core, acct, st, fw := budgetCore(t, budget.Limits{Daily: budget.D(2 * time.Minute)}, &now)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	for range 3 {
		acct.send("eli", 900*1024)
		now = now.Add(time.Minute)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}
	if !contains(fw.last.Blocked, testMAC) {
		t.Fatal("the budget should be spent before the clock is moved")
	}
	spent := st.st.Budget["eli"].Usage

	// The power cut: the box comes back believing it is 1970.
	now = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick with a backwards clock: %v", err)
	}
	if got := st.st.Budget["eli"].Usage; got != spent {
		t.Errorf("a backwards clock rewrote the usage counter: %s became %s", spent, got)
	}
	if st.st.BudgetDay != "2026-08-07" {
		t.Errorf("the day marker moved backwards to %q", st.st.BudgetDay)
	}
	if !contains(fw.last.Blocked, testMAC) {
		t.Error("a backwards clock handed a spent allowance back and put the child online")
	}

	// And once the clock is right again, the day still rolls over normally, so
	// the guard is not simply "never roll over".
	now = time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if contains(fw.last.Blocked, testMAC) {
		t.Error("the next real budget day never arrived")
	}
}
