package blockstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/budget"
)

func TestAMissingFileIsEmptyStateSoAFirstRunNeedsNoBootstrap(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err != nil {
		t.Fatalf("a missing state file must not be an error: %v", err)
	}
	if len(s.ManualBlocked) != 0 {
		t.Errorf("want empty state, got %+v", s)
	}
}

// A file that exists but cannot be parsed must NOT read as "nobody is
// blocked". That would lift every manual block at the quietest possible
// moment, which is the failure this file exists to prevent.
func TestACorruptFileIsAnErrorRatherThanAnEmptyBlocklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"manual_blocked": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err == nil {
		t.Fatalf("a half-written state file must be refused, got %+v", s)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error should name the file, got %q", err)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"tia", "eli"}}); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsBlocked("eli") || !got.IsBlocked("tia") {
		t.Errorf("both profiles should come back blocked, got %+v", got)
	}
	if got.IsBlocked("dad") {
		t.Error("nobody else should be blocked")
	}
	// Sorted on the way in and out, so the file does not churn on every write
	// and a diff means something changed.
	if got.ManualBlocked[0] != "eli" {
		t.Errorf("want a stable order, got %v", got.ManualBlocked)
	}
}

func TestSaveCreatesTheDirectoryAndLeavesNoTempFileBehind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "curfew")
	path := filepath.Join(dir, "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"eli"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("an atomic write must leave exactly the state file, got %v", names)
	}
}

// Each operation touches exactly the reason it owns, which is the whole point
// of the reason set in ADR 0006.
func TestUnblockRemovesOnlyThatProfile(t *testing.T) {
	s := &State{}
	if !s.Block("eli") {
		t.Error("blocking a fresh profile must report a change")
	}
	if s.Block("eli") {
		t.Error("blocking twice must report no change, so nothing is rewritten")
	}
	s.Block("tia")
	if !s.Unblock("eli") {
		t.Error("unblocking must report a change")
	}
	if s.IsBlocked("eli") {
		t.Error("eli should be free")
	}
	if !s.IsBlocked("tia") {
		t.Error("unblocking eli must not touch tia")
	}
	if s.Unblock("nobody") {
		t.Error("unblocking a profile that was not blocked must report no change")
	}
}

// The location is load-bearing, not incidental: /etc/config/ is the only
// directory OpenWrt's sysupgrade preserves (measured; see
// work/notes/findings/openwrt-etc-config-preserved-across-sysupgrade.md).
// Anywhere else and a firmware upgrade silently frees every grounded child.
func TestTheDefaultPathIsWhereASysupgradePreservesIt(t *testing.T) {
	const keep = "/etc/config/"
	if !strings.HasPrefix(DefaultPath, keep) {
		t.Errorf("DefaultPath = %q, but only %s survives a sysupgrade", DefaultPath, keep)
	}
}

// The suite must never write to the real location. A test that quietly edited
// /etc/config/curfew/state.json would be editing a live router's state on a
// developer machine, and would also pass for the wrong reason.
func TestTheSuiteNeverTouchesTheRealStateFile(t *testing.T) {
	before, beforeErr := os.Stat(DefaultPath)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"eli"}}); err != nil {
		t.Fatal(err)
	}
	after, afterErr := os.Stat(DefaultPath)
	if (beforeErr == nil) != (afterErr == nil) {
		t.Fatalf("%s appeared or vanished during the test", DefaultPath)
	}
	if beforeErr == nil && after.ModTime() != before.ModTime() {
		t.Errorf("%s was modified by a test", DefaultPath)
	}
}

// The budget members of the authoritative persisted-state list. Each of these
// is a case where losing the value silently hands a child internet back.

func TestBudgetStateSurvivesARoundTripToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	when := time.Date(2026, 8, 7, 19, 30, 0, 0, time.UTC)
	st := &State{
		ManualBlocked: []string{"tia"},
		BudgetDay:     "2026-08-07",
		Budget: map[string]budget.State{"eli": {
			Usage: budget.D(90 * time.Minute), Session: budget.D(20 * time.Minute),
			LastActive: when, CooldownUntil: when.Add(30 * time.Minute),
		}},
	}
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := back.Budget["eli"]
	if got.Usage != st.Budget["eli"].Usage || got.Session != st.Budget["eli"].Session {
		t.Errorf("usage or session lost across a restart: %+v", got)
	}
	if !got.LastActive.Equal(when) {
		t.Errorf("last_active lost: %v", got.LastActive)
	}
	if !got.CooldownUntil.Equal(when.Add(30 * time.Minute)) {
		t.Errorf("cooldown lost: %v", got.CooldownUntil)
	}
	if back.BudgetDay != "2026-08-07" {
		t.Errorf("the day marker is what stops a reboot looking like a new day, got %q", back.BudgetDay)
	}
	// And the manual block is still there, because they are separate members
	// and neither write touches the other.
	if !back.IsBlocked("tia") {
		t.Error("the manual block was lost when budget state was added")
	}
}

func TestBudgetForAppliesTheRolloverAsADerivation(t *testing.T) {
	st := &State{BudgetDay: "2026-08-07",
		Budget: map[string]budget.State{"eli": {Usage: budget.D(4 * time.Hour)}}}
	if got := st.BudgetFor("eli", "2026-08-07"); got.Usage == 0 {
		t.Error("within the same budget day the usage must stand")
	}
	// A new day, and nothing has written the zero down yet. The derivation
	// must already see it, which is what makes a daemon that was down across
	// the reset time still start the new day correctly.
	if got := st.BudgetFor("eli", "2026-08-08"); got.Usage != 0 {
		t.Errorf("a new budget day must read as zero usage before any tick writes it, got %s", got.Usage)
	}
}

func TestRollOverClearsOnlyWhatTheBudgetOwns(t *testing.T) {
	st := &State{ManualBlocked: []string{"eli"}, BudgetDay: "2026-08-07",
		Budget: map[string]budget.State{"eli": {Usage: budget.D(4 * time.Hour)}}}
	if !st.RollOver("2026-08-08") {
		t.Fatal("a new day must roll over")
	}
	if len(st.Budget) != 0 {
		t.Errorf("the rollover must zero the budget counters, got %+v", st.Budget)
	}
	// The defect being replaced: the old implementation called unblock
	// unconditionally on rollover and silently cancelled bedtime.
	if !st.IsBlocked("eli") {
		t.Error("the daily reset lifted a manual block, which it does not own")
	}
	if st.RollOver("2026-08-08") {
		t.Error("rolling over to the same day again must be a no-op")
	}
}

// A router with no RTC boots at the epoch. A backwards rollover would hand
// every child a fresh allowance on every power cut, which is the exact
// reboot-grants-internet defect this file exists to prevent.
func TestRollOverRefusesToGoBackwards(t *testing.T) {
	st := &State{BudgetDay: "2026-08-07",
		Budget: map[string]budget.State{"eli": {Usage: budget.D(4 * time.Hour)}}}
	if st.RollOver("1970-01-01") {
		t.Error("a clock that jumped backwards must not start a new budget day")
	}
	if st.Budget["eli"].Usage == 0 {
		t.Error("a backwards clock wiped a spent allowance")
	}
	if st.BudgetDay != "2026-08-07" {
		t.Errorf("the day marker moved backwards to %q", st.BudgetDay)
	}
	// Forward still works, so the guard is not simply "never roll over".
	if !st.RollOver("2026-08-08") {
		t.Error("a forward rollover must still happen")
	}
}

func TestSetBudgetStoresZeroStateAsAbsence(t *testing.T) {
	st := &State{}
	if !st.SetBudget("eli", budget.State{Usage: budget.D(time.Minute)}) {
		t.Error("a new value is a change")
	}
	if st.SetBudget("eli", budget.State{Usage: budget.D(time.Minute)}) {
		t.Error("an unchanged value must not report a change, or the file is rewritten every tick")
	}
	if !st.SetBudget("eli", budget.State{}) {
		t.Error("dropping back to zero is a change")
	}
	if _, present := st.Budget["eli"]; present {
		t.Error("zero state must be stored as absence, so an idle household writes nothing")
	}
}

func TestForgetBudgetDropsProfilesThatNoLongerExist(t *testing.T) {
	st := &State{Budget: map[string]budget.State{
		"eli": {Usage: budget.D(time.Hour)}, "ghost": {Usage: budget.D(time.Hour)},
	}}
	if !st.ForgetBudget(map[string]bool{"eli": true}) {
		t.Error("a departed profile is a change")
	}
	if _, present := st.Budget["ghost"]; present {
		t.Error("a deleted profile's counters must not survive to be inherited by a reused name")
	}
	if _, present := st.Budget["eli"]; !present {
		t.Error("a live profile's counters must be kept")
	}
}

// A state file written before budgets existed must still load. Refusing it
// would take the household's manual blocks down on the first upgrade.
func TestAStateFileFromBeforeBudgetsStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"manual_blocked":["eli"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatalf("an older state file must still load, got %v", err)
	}
	if !st.IsBlocked("eli") {
		t.Error("the manual block was lost")
	}
	if st.BudgetDay != "" || len(st.Budget) != 0 {
		t.Errorf("an older file has no budget state, got day=%q budget=%+v", st.BudgetDay, st.Budget)
	}
}

func TestEffectiveDayRefusesToAddressAnEarlierDay(t *testing.T) {
	st := &State{BudgetDay: "2026-08-07"}
	if got := st.EffectiveDay("1970-01-01"); got != "2026-08-07" {
		t.Errorf("a backwards clock must keep addressing the stored day, got %q", got)
	}
	if got := st.EffectiveDay("2026-08-07"); got != "2026-08-07" {
		t.Errorf("the same day must be itself, got %q", got)
	}
	if got := st.EffectiveDay("2026-08-08"); got != "2026-08-08" {
		t.Errorf("a forward clock must address the new day, got %q", got)
	}
	// A first run has no stored day, so whatever the clock says is right.
	empty := &State{}
	if got := empty.EffectiveDay("2026-08-07"); got != "2026-08-07" {
		t.Errorf("with no stored day the clock decides, got %q", got)
	}
}

// ---- delayed blocks ----

// A delayed block is a DECISION with a deadline, so it belongs on disk for
// exactly the reason a manual block does: a reboot must not cancel it. This is
// the round trip that proves the deadline itself survives, not just its
// existence.
func TestADelayedBlockSurvivesARoundTripToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	due := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	s := &State{}
	if !s.ArmBlock("eli", due) {
		t.Error("arming a delayed block must report a change")
	}
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, armed := back.PendingBlockAt("eli")
	if !armed {
		t.Fatal("the delayed block did not survive the round trip, so a reboot cancels it")
	}
	if !got.Equal(due) {
		t.Errorf("the deadline changed across the round trip: want %s, got %s", due, got)
	}
}

// Last tap wins, which is what a parent means by tapping again.
func TestArmingAgainReplacesTheDeadline(t *testing.T) {
	first := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	second := first.Add(-20 * time.Minute)
	s := &State{}
	s.ArmBlock("eli", first)
	if !s.ArmBlock("eli", second) {
		t.Error("re-arming to a different deadline must report a change")
	}
	if got, _ := s.PendingBlockAt("eli"); !got.Equal(second) {
		t.Errorf("the second tap did not win: want %s, got %s", second, got)
	}
	if s.ArmBlock("eli", second) {
		t.Error("re-arming to the SAME deadline must report no change, so nothing is rewritten")
	}
}

// Due is a DERIVATION from the clock, so a daemon that was down across the
// deadline still finds the block waiting for it rather than having missed it.
func TestDueReportsEveryDeadlineThatHasPassedHoweverLongAgo(t *testing.T) {
	now := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	s := &State{}
	s.ArmBlock("eli", now.Add(-3*time.Hour)) // the daemon was down all evening
	s.ArmBlock("tia", now.Add(time.Minute))  // not yet
	due := s.DueBlocks(now)
	if len(due) != 1 || due[0] != "eli" {
		t.Fatalf("a deadline that passed while the daemon was down was missed: %v", due)
	}
	// Exactly at the deadline counts, or a block can fall through the gap
	// between two ticks.
	if due := s.DueBlocks(now.Add(time.Minute)); len(due) != 2 {
		t.Errorf("a deadline exactly reached is not due: %v", due)
	}
}

func TestCancellingADelayedBlockLeavesEveryOtherProfileArmed(t *testing.T) {
	at := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	s := &State{}
	s.ArmBlock("eli", at)
	s.ArmBlock("tia", at)
	if !s.CancelBlock("eli") {
		t.Error("cancelling must report a change")
	}
	if _, armed := s.PendingBlockAt("eli"); armed {
		t.Error("eli is still armed")
	}
	if _, armed := s.PendingBlockAt("tia"); !armed {
		t.Error("cancelling eli disarmed tia")
	}
	if s.CancelBlock("nobody") {
		t.Error("cancelling nothing must report no change")
	}
}

// Blocking now makes a pending block meaningless, and leaving it armed would
// fire it later against a profile a parent may have unblocked in between.
func TestBlockingNowDisarmsAPendingBlock(t *testing.T) {
	s := &State{}
	s.ArmBlock("eli", time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC))
	if !s.Block("eli") {
		t.Fatal("blocking must report a change")
	}
	if _, armed := s.PendingBlockAt("eli"); armed {
		t.Error("a pending block survived an immediate block, so it will fire again later")
	}
}

// Unblock must NOT disarm a pending block. It removes exactly the one reason
// it owns (ADR 0006), and a parent lifting an unrelated grounding at 19:00
// must not silently cancel the countdown they set for 20:00.
func TestUnblockLeavesAPendingBlockArmed(t *testing.T) {
	s := &State{}
	s.Block("eli")
	s.ArmBlock("eli", time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC))
	s.Unblock("eli")
	if _, armed := s.PendingBlockAt("eli"); !armed {
		t.Error("unblocking silently cancelled a delayed block")
	}
}

func TestForgetPendingDropsProfilesThatNoLongerExist(t *testing.T) {
	at := time.Date(2026, 3, 4, 20, 30, 0, 0, time.UTC)
	s := &State{}
	s.ArmBlock("eli", at)
	s.ArmBlock("gone", at)
	if !s.ForgetPending(map[string]bool{"eli": true}) {
		t.Error("dropping a deleted profile must report a change")
	}
	if _, armed := s.PendingBlockAt("gone"); armed {
		t.Error("a deleted profile's countdown can still fire under a reused name")
	}
	if _, armed := s.PendingBlockAt("eli"); !armed {
		t.Error("a live profile was forgotten too")
	}
}

// A state file written by an older curfew has no pending_block key at all.
func TestAStateFileFromBeforeDelayedBlocksStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"manual_blocked":["eli"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsBlocked("eli") {
		t.Error("upgrading lost a manual block")
	}
	if _, armed := s.PendingBlockAt("eli"); armed {
		t.Error("a file with no pending_block key produced one")
	}
}
