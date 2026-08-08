//go:build linux

package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/accounting"
	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/netnstest"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// Packet-path tests for the daily time budget, driven end to end: real config
// files, the real policy core, the real netlink enforcer, the REAL nftables
// counters, and real packets.
//
// Nothing here fakes the counter. The counter is the component most likely to
// be wrong (it is cumulative, it lives in a table another package rebuilds
// underneath it, and it goes backwards on a reboot), so a test that stubbed it
// would prove only that the arithmetic in internal/budget works, which the
// unit tests already prove without a kernel.
//
// The accounting interval and the activity threshold are injected so a budget
// can be driven to exhaustion in seconds rather than hours. The MECHANISM is
// untouched by that: the same sampler, the same counters, the same packets.

// budgetHousehold writes a household where eli has a budget and dad does not.
// dad is the control throughout: every assertion that eli lost the internet
// needs a device that did not, or a broken ruleset reads as a working budget.
func budgetHousehold(t *testing.T, eli budget.Limits) (reg, sched, state string) {
	t.Helper()
	dir := t.TempDir()
	reg = filepath.Join(dir, "devices.json")
	sched = filepath.Join(dir, "profiles.json")
	state = filepath.Join(dir, "state.json")

	r := &registry.Registry{}
	for _, m := range []string{eliMAC, dadMAC} {
		if err := r.Add(m, ""); err != nil {
			t.Fatalf("Add(%s): %v", m, err)
		}
	}
	if err := registry.Save(reg, r); err != nil {
		t.Fatalf("saving registry: %v", err)
	}
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{eliMAC}, Windows: []schedule.Window{}, Budget: eli},
		{Name: "dad", Devices: []string{dadMAC}, Windows: []schedule.Window{}},
	}}
	if err := schedule.Save(sched, ps); err != nil {
		t.Fatalf("saving schedule: %v", err)
	}
	return reg, sched, state
}

// testInterval is short enough to exhaust a budget in a test and long enough
// that a sample is not taken twice for one burst of traffic.
const testInterval = 400 * time.Millisecond

// testThreshold is well above the noise a bare reachability probe makes and
// well below what netnstest.Burn generates, so "active" is unambiguous at any
// plausible test speed.
const testThreshold = 32 * 1024

func bootWithBudget(t *testing.T, reg, sched, state string) *Core {
	t.Helper()
	fw, err := enforce.New(enforce.Config{
		LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf,
	})
	if err != nil {
		t.Fatalf("enforce.New: %v", err)
	}
	acct, err := accounting.New(accounting.Config{
		LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf,
	})
	if err != nil {
		t.Fatalf("accounting.New: %v", err)
	}
	t.Cleanup(func() { _ = acct.Teardown() })
	core := New(registry.FileStore{Path: reg}, schedule.FileStore{Path: sched},
		blockstate.FileStore{Path: state}, fw, time.UTC, nil)
	return core.WithAccounting(acct, testInterval, testThreshold)
}

// burnFrom generates real upstream traffic from a MAC and reports whether it
// got through.
func burnFrom(t *testing.T, net *netnstest.Topology, mac string) bool {
	t.Helper()
	net.SetClientMAC(mac)
	return net.Burn()
}

// THE test the brief asks for: drive real traffic until the allowance is spent
// and assert the device stops reaching the internet, with a device that still
// has budget as the control.
func TestPacketPathABudgetRunsOutAndTheChildGoesOffline(t *testing.T) {
	net := netnstest.Require(t)
	reg, sched, state := budgetHousehold(t, budget.Limits{Daily: budget.D(2 * testInterval)})
	core := bootWithBudget(t, reg, sched, state)

	if err := core.Tick(); err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	// Baseline, mandatory: both devices reach the internet before any budget
	// is spent. A topology fault makes every probe read unreachable, which is
	// indistinguishable from a perfect budget.
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline: eli must reach the internet before their budget is spent")
	}
	if !burnFrom(t, net, dadMAC) {
		t.Fatal("baseline: dad must reach the internet")
	}

	spent := false
	for range 12 {
		time.Sleep(testInterval)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if !burnFrom(t, net, eliMAC) {
			spent = true
			break
		}
	}
	if !spent {
		t.Fatal("eli's budget never ran out: real traffic did not exhaust a two-interval allowance")
	}

	// The control. Without it, a ruleset that blocked the whole household
	// would pass this test as a perfectly working budget.
	if !burnFrom(t, net, dadMAC) {
		t.Error("dad has no budget and must still reach the internet; eli's block was not about the budget")
	}

	// And it is the BUDGET reason doing it, in the set the schedule uses,
	// rather than a manual block having appeared from somewhere.
	st, err := blockstate.Load(state)
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if len(st.ManualBlocked) != 0 {
		t.Errorf("a spent budget must not write a manual block, got %v", st.ManualBlocked)
	}
	d, err := core.Desired()
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if !contains(d.Blocked, eliMAC) {
		t.Errorf("eli should be in the schedule/budget block set, got Blocked=%v", d.Blocked)
	}
	if contains(d.Manual, eliMAC) {
		t.Error("a budget block must not use the manual tier: a child could not then be ticketed out of it")
	}
}

// The budget reason is DERIVED, so it survives a restart with no restore step
// and without ever having been written down as a reason.
func TestPacketPathASpentBudgetSurvivesARestartWithoutBeingStoredAsAReason(t *testing.T) {
	net := netnstest.Require(t)
	reg, sched, state := budgetHousehold(t, budget.Limits{Daily: budget.D(2 * testInterval)})
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline: eli must start out online")
	}
	if !spendBudget(t, net, core) {
		t.Fatal("eli's budget never ran out")
	}

	// A restart: the enforcement table is gone with the kernel's, the
	// accounting counters are gone with it, and a brand new process reads the
	// same files. Nothing carried over in memory.
	net.DeleteTable()
	net.DeleteAccountingTable()
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("with the tables gone everything should flow, or the assertion below proves nothing")
	}
	rebooted := bootWithBudget(t, reg, sched, state)
	if err := rebooted.Tick(); err != nil {
		t.Fatalf("Tick after restart: %v", err)
	}
	if burnFrom(t, net, eliMAC) {
		t.Error("a restart handed back a spent allowance: the usage counter did not survive")
	}
	// Control: the profile with no budget comes back online, so the block
	// above is the budget rather than a restart that blocked everyone.
	if !burnFrom(t, net, dadMAC) {
		t.Error("dad must be online after the restart")
	}
}

// A ticket overrides a budget block by chain position, and the block reapplies
// when it lapses with no bookkeeping at all. This already works via ADR 0006's
// ordering; it is asserted here because the budget is the reason that most
// needs it, and because nothing else would notice if it broke.
func TestPacketPathATicketOverridesASpentBudgetAndTheBlockReturnsWhenItLapses(t *testing.T) {
	net := netnstest.Require(t)
	reg, sched, state := budgetHousehold(t, budget.Limits{Daily: budget.D(2 * testInterval)})
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline")
	}
	if !spendBudget(t, net, core) {
		t.Fatal("eli's budget never ran out")
	}

	granted := 5 * time.Second
	if err := core.GrantTicket("eli", granted); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	deadline := time.Now().Add(granted)
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("a ticket must override a spent budget")
	}
	// A tick during the ticket must not cancel it, which is the defect the
	// legacy budget-check had: it re-blocked every minute and killed a freshly
	// issued ticket within 60 seconds.
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick during a live ticket: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("a budget check killed a live ticket")
	}

	time.Sleep(time.Until(deadline) + time.Second)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick after the ticket lapsed: %v", err)
	}
	if burnFrom(t, net, eliMAC) {
		t.Error("the budget block did not come back when the ticket lapsed")
	}
}

// The continuity model on the packet path: the CONTINUOUS allowance blocks
// while the daily allowance still has plenty left, and the reset gap ends on
// wall-clock time with no traffic observable at all.
func TestPacketPathTheContinuousAllowanceBlocksAndTheResetGapEndsIt(t *testing.T) {
	net := netnstest.Require(t)
	limits := budget.Limits{
		Daily:      budget.D(time.Hour), // deliberately huge: it must not be what blocks
		Continuous: budget.D(2 * testInterval),
		Gap:        budget.D(time.Second),
		ResetGap:   budget.D(8 * time.Second),
	}
	reg, sched, state := budgetHousehold(t, limits)
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline: eli must start out online")
	}
	if !spendBudget(t, net, core) {
		t.Fatal("the continuous allowance never ran out")
	}
	blockedAt := time.Now()

	// The control that separates the two allowances: the DAILY budget is
	// nowhere near spent, so what blocked eli can only be the continuous one.
	status, err := core.BudgetStatus()
	if err != nil {
		t.Fatalf("BudgetStatus: %v", err)
	}
	if got := status["eli"]; got.Reason != budget.ReasonContinuous {
		t.Errorf("reason = %q, want %q (used %s of a 1h daily budget)",
			got.Reason, budget.ReasonContinuous, got.Used)
	}
	if status["eli"].Used > 10*time.Second {
		t.Errorf("the daily budget should be almost untouched, used %s", status["eli"].Used)
	}

	// Wait out the reset gap. Not one packet of eli's survives enforcement in
	// the meantime, which is exactly why the cooldown has to be wall-clock:
	// there is no activity to observe the end of.
	time.Sleep(time.Until(blockedAt.Add(9 * time.Second)))
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick after the reset gap: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Error("the reset gap elapsed but the child is still blocked: the cooldown is waiting for something it can never see")
	}
	// And the allowance refilled in FULL, so the next stretch is a whole one.
	status, err = core.BudgetStatus()
	if err != nil {
		t.Fatalf("BudgetStatus: %v", err)
	}
	if left := status["eli"].SessionLeft; left < testInterval {
		t.Errorf("the continuous allowance refilled to only %s of %s",
			left, limits.Continuous)
	}
}

// An idle household must burn nothing. This is the defect being replaced,
// asserted with packets: the legacy budget-check incremented every minute from
// midnight, so a 4h budget meant "blocked at 04:00" whether or not a device
// was even switched on.
func TestPacketPathAnIdleProfileBurnsNoBudget(t *testing.T) {
	net := netnstest.Require(t)
	reg, sched, state := budgetHousehold(t, budget.Limits{Daily: budget.D(2 * testInterval)})
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	net.SetClientMAC(eliMAC)

	// Far more ticks than the allowance is worth. No traffic is generated.
	for range 12 {
		time.Sleep(testInterval)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}
	status, err := core.BudgetStatus()
	if err != nil {
		t.Fatalf("BudgetStatus: %v", err)
	}
	if used := status["eli"].Used; used != 0 {
		t.Errorf("an idle profile burned %s of budget across %s of wall-clock time",
			used, 12*testInterval)
	}
	if !net.Reaches() {
		t.Error("an idle child was blocked: the budget is counting wall-clock time, not use")
	}
}

// spendBudget drives real traffic until the profile stops getting through.
func spendBudget(t *testing.T, net *netnstest.Topology, core *Core) bool {
	t.Helper()
	for range 12 {
		time.Sleep(testInterval)
		if err := core.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if !burnFrom(t, net, eliMAC) {
			return true
		}
	}
	return false
}

// A ticket must override the CONTINUOUS block too, not just the daily one.
//
// The existing ticket test uses a daily-only budget, so the combination a
// parent actually meets at 9pm -- "the stretch ran out, give them twenty more
// minutes" -- was never asserted on the packet path. Reported from the live
// router: when the continuous block triggered, a ticket did not let the child
// back online.
func TestPacketPathATicketOverridesTheContinuousBlock(t *testing.T) {
	net := netnstest.Require(t)
	limits := budget.Limits{
		Daily:      budget.D(time.Hour), // huge on purpose: must not be what blocks
		Continuous: budget.D(2 * testInterval),
		Gap:        budget.D(time.Second),
		ResetGap:   budget.D(10 * time.Minute), // long: the ticket, not the gap, must unblock
	}
	reg, sched, state := budgetHousehold(t, limits)
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline: eli must start out online")
	}
	if !spendBudget(t, net, core) {
		t.Fatal("the continuous allowance never ran out")
	}

	// The control: it really is the CONTINUOUS allowance blocking, with the
	// daily one barely touched, so a pass below cannot be the daily budget
	// quietly doing something else.
	status, err := core.BudgetStatus()
	if err != nil {
		t.Fatalf("BudgetStatus: %v", err)
	}
	if got := status["eli"].Reason; got != budget.ReasonContinuous {
		t.Fatalf("reason = %q, want %q", got, budget.ReasonContinuous)
	}

	if err := core.GrantTicket("eli", 20*time.Second); err != nil {
		t.Fatalf("GrantTicket during a continuous block: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("a ticket did NOT override the continuous block: the child is still offline")
	}
	// And a tick during the ticket must not kill it, since the cooldown is
	// still running and the reconcile recomputes the same block every minute.
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick during a live ticket: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Error("a reconcile during the cooldown killed a live ticket")
	}
}

// A daemon RESTART must not kill a live ticket.
//
// From the live router's log: a ticket was granted at 11:40:41 while the
// profile was in a continuous cooldown, the daemon restarted 34 seconds later,
// and the parent then blocked/unblocked and re-ticketed, which is what someone
// does when a ticket appears not to have worked. A ticket is kernel state that
// is MEANT to survive anything except its own deadline, so a restart taking it
// away would be exactly the reported symptom.
func TestPacketPathADaemonRestartDoesNotKillALiveTicketDuringACooldown(t *testing.T) {
	net := netnstest.Require(t)
	limits := budget.Limits{
		Daily:      budget.D(time.Hour),
		Continuous: budget.D(2 * testInterval),
		Gap:        budget.D(time.Second),
		ResetGap:   budget.D(10 * time.Minute),
	}
	reg, sched, state := budgetHousehold(t, limits)
	core := bootWithBudget(t, reg, sched, state)
	if err := core.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("baseline: eli must start out online")
	}
	if !spendBudget(t, net, core) {
		t.Fatal("the continuous allowance never ran out")
	}
	if err := core.GrantTicket("eli", 30*time.Second); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Fatal("the ticket did not take effect at all")
	}

	// The restart: a brand new Core over the same files, exactly as procd
	// would start one, including the boot-time Tick the daemon performs
	// before it serves anything.
	restarted := bootWithBudget(t, reg, sched, state)
	if err := restarted.Tick(); err != nil {
		t.Fatalf("Tick after restart: %v", err)
	}
	if !burnFrom(t, net, eliMAC) {
		t.Error("a daemon restart killed a live ticket: the child goes offline " +
			"and the parent sees a ticket that did nothing")
	}
}
