package policy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

const (
	eliPhone  = "aa:bb:cc:dd:ee:01"
	eliLaptop = "aa:bb:cc:dd:ee:02"
	dadPhone  = "aa:bb:cc:dd:ee:03"
)

// fakeFirewall records what it was asked to enforce, and NOTHING else.
//
// It deliberately does not reproduce any of the enforcer's own behaviour: not
// the precedence, and not the rule that a rebuild drops a ticket for a
// manually blocked MAC. An earlier version of this double did reproduce that
// rule, and it hid a real defect: with the cancellation removed from Block,
// every test here still passed, because the double was quietly doing the
// core's job for it. What the enforcer does is settled in internal/enforce,
// with packets.
type fakeFirewall struct {
	last     enforce.Desired
	applies  int
	tickets  map[string]time.Duration
	grants   int
	cancels  int
	applyErr error
	grantErr error
}

func (f *fakeFirewall) EnsureApplied(d enforce.Desired) (bool, error) {
	f.applies++
	if f.applyErr != nil {
		return false, f.applyErr
	}
	f.last = d
	return true, nil
}

func (f *fakeFirewall) GrantTicket(macs []string, d time.Duration) error {
	if f.grantErr != nil {
		return f.grantErr
	}
	f.grants++
	if f.tickets == nil {
		f.tickets = map[string]time.Duration{}
	}
	for _, m := range macs {
		f.tickets[m] = d
	}
	return nil
}

func (f *fakeFirewall) CancelTickets(macs []string) error {
	f.cancels++
	for _, m := range macs {
		delete(f.tickets, m)
	}
	return nil
}

type memRegistry struct{ reg *registry.Registry }

func (m memRegistry) Load() (*registry.Registry, error) { return m.reg, nil }

type memSchedule struct{ ps *schedule.Profiles }

func (m memSchedule) Load() (*schedule.Profiles, error) { return m.ps, nil }

type memState struct {
	st      *blockstate.State
	saveErr error
	saves   int
}

// Load and Save copy EVERY member of the persisted state. The authoritative
// list of those members is the blockstate.State type itself; a double that
// quietly drops one would make a spent budget vanish on every read, so the
// core would keep handing back an allowance the file had already recorded.
func (m *memState) Load() (*blockstate.State, error) {
	if m.st == nil {
		return &blockstate.State{ManualBlocked: []string{}}, nil
	}
	return copyState(m.st), nil
}

func (m *memState) Save(s *blockstate.State) error {
	m.saves++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.st = copyState(s)
	return nil
}

func copyState(s *blockstate.State) *blockstate.State {
	cp := &blockstate.State{
		ManualBlocked: append([]string(nil), s.ManualBlocked...),
		BudgetDay:     s.BudgetDay,
	}
	if s.Budget != nil {
		cp.Budget = map[string]budget.State{}
		for k, v := range s.Budget {
			cp.Budget[k] = v
		}
	}
	if s.PendingBlock != nil {
		cp.PendingBlock = map[string]time.Time{}
		for k, v := range s.PendingBlock {
			cp.PendingBlock[k] = v
		}
	}
	return cp
}

// household is the standard fixture: eli with two devices and a bedtime, dad
// with one device and no schedule.
func household(t *testing.T) (*Core, *fakeFirewall, *memState) {
	t.Helper()
	reg := memRegistry{reg: &registry.Registry{Devices: []registry.Device{
		{MAC: eliPhone, Name: "eli phone"},
		{MAC: eliLaptop, Name: "eli laptop"},
		{MAC: dadPhone, Name: "dad"},
	}}}
	sched := memSchedule{ps: &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{eliPhone, eliLaptop}, Windows: []schedule.Window{
			{Days: schedule.AllDays, Start: "22:00", End: "08:00"},
		}},
		{Name: "dad", Devices: []string{dadPhone}},
	}}}
	st := &memState{}
	fw := &fakeFirewall{}
	c := New(reg, sched, st, fw, time.UTC, nil)
	return c, fw, st
}

// at pins the clock, so a schedule-dependent assertion does not depend on when
// the suite happens to run.
func at(c *Core, hhmm string) {
	parsed, err := time.Parse("15:04", hhmm)
	if err != nil {
		panic(err)
	}
	c.now = func() time.Time {
		return time.Date(2026, 3, 4, parsed.Hour(), parsed.Minute(), 0, 0, time.UTC)
	}
}

func has(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

func TestDesiredBlocksAProfileInsideItsWindow(t *testing.T) {
	c, _, _ := household(t)
	at(c, "23:30")
	d, err := c.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if !has(d.Blocked, eliPhone) || !has(d.Blocked, eliLaptop) {
		t.Errorf("both of eli's devices should be schedule-blocked at 23:30, got %v", d.Blocked)
	}
	if has(d.Blocked, dadPhone) {
		t.Error("dad has no window and must not be blocked")
	}
	if len(d.Manual) != 0 {
		t.Errorf("nobody was blocked by hand, got %v", d.Manual)
	}
	// Control: the same schedule outside the window blocks nobody, so the
	// assertion above is about the window and not about everything.
	at(c, "12:00")
	d, err = c.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Blocked) != 0 {
		t.Errorf("nobody should be blocked at noon, got %v", d.Blocked)
	}
}

func TestBlockPutsEveryDeviceOfTheProfileInTheManualTier(t *testing.T) {
	c, fw, st := household(t)
	at(c, "12:00")
	if err := c.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !has(fw.last.Manual, eliPhone) || !has(fw.last.Manual, eliLaptop) {
		t.Errorf("both of eli's devices must be manually blocked, got %v", fw.last.Manual)
	}
	if has(fw.last.Manual, dadPhone) {
		t.Error("blocking eli must not touch dad")
	}
	if len(fw.last.Blocked) != 0 {
		t.Errorf("a manual block belongs in the manual tier, not the schedule one: %v", fw.last.Blocked)
	}
	if st.st == nil || !st.st.IsBlocked("eli") {
		t.Errorf("the decision must be PERSISTED, or a reboot lifts it: %+v", st.st)
	}
}

// The scenario ADR 0006 was written for, and the only one on which the reason
// set and a scalar with precedence were measured to differ.
func TestUnblockLeavesABedtimeWindowInForce(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "23:00")
	if err := c.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if err := c.Unblock("eli"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if len(fw.last.Manual) != 0 {
		t.Errorf("the manual reason should be gone, got %v", fw.last.Manual)
	}
	if !has(fw.last.Blocked, eliPhone) {
		t.Error("lifting a manual block at 23:00 handed the child the rest of the night: " +
			"the schedule reason must survive, since unblock removes only the reason it owns")
	}
	// Control: outside the window the same unblock really does free them, so
	// the assertion above is about the window rather than about unblock being
	// broken.
	at(c, "12:00")
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(fw.last.Blocked) != 0 || len(fw.last.Manual) != 0 {
		t.Errorf("at noon with no manual block nothing should be blocked: %+v", fw.last)
	}
}

func TestBlockCancelsALiveTicketSoUnblockCannotResurrectIt(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "23:00")
	if err := c.GrantTicket("eli", 30*time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if len(fw.tickets) != 2 {
		t.Fatalf("the ticket must reach both devices first, got %v", fw.tickets)
	}
	if err := c.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if len(fw.tickets) != 0 {
		t.Errorf("blocking must cancel the live ticket, got %v", fw.tickets)
	}
	if err := c.Unblock("eli"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if len(fw.tickets) != 0 {
		t.Errorf("unblocking resurrected a cancelled ticket: %v", fw.tickets)
	}
}

// Unblock-then-ticket is the deliberate two-call gesture of ADR 0006. Fusing
// them would mean a parent who wanted to give thirty minutes silently cleared
// an indefinite block as well.
func TestATicketIsRefusedWhileAManualBlockIsInForce(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "23:00")
	if err := c.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	err := c.GrantTicket("eli", 30*time.Minute)
	if err == nil {
		t.Fatal("a ticket must not be issued to a profile that is blocked until a parent lifts it")
	}
	if !strings.Contains(err.Error(), "Unblock first") {
		t.Errorf("the refusal must tell the parent what to do instead, got %q", err)
	}
	if fw.grants != 0 {
		t.Error("nothing should have reached the firewall")
	}

	// The two-call gesture then works, and the ticket lapses back to the
	// SCHEDULE rather than to the block that was deliberately cleared.
	if err := c.Unblock("eli"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if err := c.GrantTicket("eli", 30*time.Minute); err != nil {
		t.Fatalf("GrantTicket after unblock: %v", err)
	}
	if len(fw.tickets) != 2 {
		t.Errorf("both devices should hold a ticket, got %v", fw.tickets)
	}
	if !has(fw.last.Blocked, eliPhone) {
		t.Error("the underlying bedtime must still be in the ruleset, so the ticket lapses back to it")
	}
}

// A ticket while a window is active is the whole point: it is only the MANUAL
// reason a ticket cannot override.
func TestATicketIsAllowedForAScheduleBlockedProfile(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "23:00")
	// The daemon has already reconciled, so the bedtime block is in the
	// ruleset before the parent taps a duration.
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	applies := fw.applies
	if err := c.GrantTicket("eli", 30*time.Minute); err != nil {
		t.Fatalf("a schedule-blocked profile must be ticketable: %v", err)
	}
	if fw.grants != 1 {
		t.Error("the grant should have reached the firewall")
	}
	if !has(fw.last.Blocked, eliPhone) {
		t.Error("the schedule block must remain in place underneath the ticket")
	}
	// A grant is an ADDITION to a live set, not a rewrite. Rewriting here
	// would be harmless but pointless work; more importantly it shows the
	// ticket is not being expressed as desired state, which is what would
	// make it survive its own expiry.
	if fw.applies != applies {
		t.Error("granting a ticket must not rebuild the ruleset: it adds a kernel-timeout element")
	}
}

func TestOperationsOnAnUnknownProfileFailRatherThanDoNothingQuietly(t *testing.T) {
	c, fw, st := household(t)
	at(c, "12:00")
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"block", func() error { return c.Block("nobody") }},
		{"unblock", func() error { return c.Unblock("nobody") }},
		{"ticket", func() error { return c.GrantTicket("nobody", time.Minute) }},
	} {
		if err := op.run(); err == nil {
			t.Errorf("%s on an unknown profile must be an error", op.name)
		}
	}
	if st.saves != 0 || fw.grants != 0 {
		t.Error("nothing should have been written for a profile that does not exist")
	}
}

func TestATicketForAProfileWithNoDevicesIsRefused(t *testing.T) {
	reg := memRegistry{reg: &registry.Registry{}}
	sched := memSchedule{ps: &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}}
	fw := &fakeFirewall{}
	c := New(reg, sched, &memState{}, fw, time.UTC, nil)
	if err := c.GrantTicket("eli", time.Minute); err == nil {
		t.Error("a ticket that would grant nothing must say so rather than appear to work")
	}
	if fw.grants != 0 {
		t.Error("nothing should have reached the firewall")
	}
}

// Re-blocking an already-blocked profile must still cancel a ticket.
//
// This is the case the enforcer's own safety net cannot catch: nothing about
// the desired state has changed, so a drift-driven reconcile writes nothing at
// all, and a ticket that appeared out of band would sit there until it lapsed,
// ready to free the child the moment the parent lifted the block.
func TestReBlockingStillCancelsATicket(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "12:00")
	if err := c.Block("eli"); err != nil {
		t.Fatal(err)
	}
	fw.tickets = map[string]time.Duration{eliPhone: time.Hour}
	if err := c.Block("eli"); err != nil {
		t.Fatal(err)
	}
	if len(fw.tickets) != 0 {
		t.Errorf("re-blocking left a live ticket in place: %v", fw.tickets)
	}
}

func TestBlockingTwiceIsIdempotentAndDoesNotRewriteState(t *testing.T) {
	c, _, st := household(t)
	at(c, "12:00")
	if err := c.Block("eli"); err != nil {
		t.Fatal(err)
	}
	saves := st.saves
	if err := c.Block("eli"); err != nil {
		t.Fatalf("re-blocking must not fail: %v", err)
	}
	if st.saves != saves {
		t.Error("state should be written only when a value CHANGES")
	}
	if !st.st.IsBlocked("eli") {
		t.Error("eli must still be blocked")
	}
}

// A failure to enforce must never be reported as success, and must say what
// actually happened to the parent's decision.
func TestBlockReportsAFirewallFailureLoudly(t *testing.T) {
	c, fw, st := household(t)
	at(c, "12:00")
	fw.applyErr = errors.New("netlink is unhappy")
	err := c.Block("eli")
	if err == nil {
		t.Fatal("a firewall failure must not be swallowed")
	}
	if !strings.Contains(err.Error(), "NOT updated") {
		t.Errorf("the error must say the firewall was not updated, got %q", err)
	}
	// The decision is still recorded, so the next reconcile enforces it rather
	// than the parent's instruction vanishing along with the error.
	if !st.st.IsBlocked("eli") {
		t.Error("the decision must survive a failed apply, or the next tick will not fix it")
	}
}

func TestManuallyBlockedReportsIntent(t *testing.T) {
	c, _, _ := household(t)
	at(c, "12:00")
	if err := c.Block("eli"); err != nil {
		t.Fatal(err)
	}
	got, err := c.ManuallyBlocked()
	if err != nil {
		t.Fatal(err)
	}
	if !got["eli"] || got["dad"] {
		t.Errorf("ManuallyBlocked() = %v, want eli only", got)
	}
}

// A manual block acts on the PROFILE, so a device added afterwards is blocked
// too. Storing MACs instead of the profile name would leave the new device
// online while the page said the child was blocked.
func TestADeviceAddedToABlockedProfileIsBlockedToo(t *testing.T) {
	reg := memRegistry{reg: &registry.Registry{Devices: []registry.Device{{MAC: eliPhone}}}}
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Devices: []string{eliPhone}}}}
	fw := &fakeFirewall{}
	c := New(reg, memSchedule{ps: ps}, &memState{}, fw, time.UTC, nil)
	if err := c.Block("eli"); err != nil {
		t.Fatal(err)
	}
	if len(fw.last.Manual) != 1 {
		t.Fatalf("one device to start with, got %v", fw.last.Manual)
	}
	ps.Profiles[0].Devices = append(ps.Profiles[0].Devices, eliLaptop)
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliLaptop) {
		t.Errorf("a device added to a blocked profile must be blocked as well, got %v", fw.last.Manual)
	}
}

// Two parents tapping at once must not lose one of the two decisions.
//
// The page is served to every phone in the house, so simultaneous requests are
// ordinary rather than exotic, and each operation is a read-modify-write of
// one file. Without serialisation the second write is built on a snapshot
// taken before the first, and one child silently stays online.
func TestConcurrentBlocksDoNotLoseADecision(t *testing.T) {
	// Enough profiles at once that the unserialised version loses one every
	// time rather than occasionally. A race test that fails one run in four is
	// a test that reports green while the defect ships.
	var names []string
	ps := &schedule.Profiles{}
	reg := &registry.Registry{}
	for i := range 12 {
		name := string(rune('a' + i))
		mac := fmt.Sprintf("aa:bb:cc:dd:ee:%02d", i+1)
		names = append(names, name)
		if err := reg.Add(mac, name); err != nil {
			t.Fatal(err)
		}
		ps.Profiles = append(ps.Profiles, schedule.Profile{Name: name, Devices: []string{mac}})
	}
	st := &memState{}
	c := New(memRegistry{reg: reg}, memSchedule{ps: ps}, st, &fakeFirewall{}, time.UTC, nil)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := c.Block(name); err != nil {
				t.Errorf("Block(%s): %v", name, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, name := range names {
		if !st.st.IsBlocked(name) {
			t.Errorf("a simultaneous block was lost: %q is not blocked, state is %+v", name, st.st)
		}
	}
}

// ---- delayed blocks ----

// THE test for the feature: armed, nothing changes yet; deadline passes, every
// device goes into the manual tier; and it stays there until a parent lifts it.
func TestADelayedBlockLandsAtItsDeadlineAndStaysUntilLifted(t *testing.T) {
	c, fw, st := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}

	// BASELINE: arming changes nothing about what the firewall is doing.
	// Without this, a test that only checked the end state would pass against
	// an implementation that blocked immediately.
	if has(fw.last.Manual, eliPhone) {
		t.Fatalf("arming a delayed block cut the child off at once: %+v", fw.last)
	}
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Fatalf("a tick before the deadline applied the block early: %+v", fw.last)
	}

	// The deadline arrives.
	at(c, "19:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliPhone) || !has(fw.last.Manual, eliLaptop) {
		t.Errorf("the delayed block did not land on every device: %+v", fw.last)
	}
	// It became the ordinary manual block, which is what makes it survive a
	// reboot and outlast a ticket.
	if !st.st.IsBlocked("eli") {
		t.Error("the block that landed was not recorded as a manual block")
	}
	if _, armed := st.st.PendingBlockAt("eli"); armed {
		t.Error("the countdown is still armed, so it will fire again after an unblock")
	}
	// CONTROL: the other profile is untouched.
	if has(fw.last.Manual, dadPhone) {
		t.Errorf("a delayed block for eli blocked dad too: %+v", fw.last)
	}

	// It is off until LIFTED, not until the next tick.
	at(c, "20:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliPhone) {
		t.Errorf("the block lifted itself: %+v", fw.last)
	}
	if err := c.Unblock("eli"); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Errorf("unblocking did not lift it: %+v", fw.last)
	}
}

// A deadline that passed while the daemon was down must still land. This is
// the difference between deriving the block from the clock and firing it from
// a timer, and a timer is what an OpenWrt router with no RTC punishes.
func TestADeadlineThatPassedWhileTheDaemonWasDownStillLands(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Three hours later, the daemon's first pass since.
	at(c, "22:15")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliPhone) {
		t.Errorf("a deadline missed by an outage was lost: %+v", fw.last)
	}
}

// A router with no RTC boots at the epoch. The block must land LATE rather
// than never, and it must not land EARLY on every profile at once.
func TestAClockThatBootsAtTheEpochDelaysTheBlockRatherThanLosingIt(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return time.Unix(0, 0).UTC() }
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Errorf("a router that booted at the epoch fired the block anyway: %+v", fw.last)
	}
	// And once the clock is right, it lands.
	at(c, "19:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliPhone) {
		t.Errorf("the block never landed after the clock was corrected: %+v", fw.last)
	}
}

// Manual outranks a ticket (ADR 0006), so a delayed block that lands must
// cancel one, exactly as an immediate block does. Otherwise a child with
// twenty minutes of ticket left rides straight through their bedtime.
func TestADelayedBlockThatLandsCancelsALiveTicket(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "19:00")
	if err := c.GrantTicket("eli", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if fw.cancels != 0 {
		t.Fatalf("baseline: arming must not cancel the ticket it is not yet overriding")
	}
	at(c, "19:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if fw.cancels == 0 {
		t.Error("the delayed block landed on top of a live ticket without cancelling it")
	}
}

// Last tap wins, which is the rule the page promises.
func TestArmingAgainReplacesTheEarlierDeadline(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockIn("eli", time.Hour); err != nil {
		t.Fatal(err)
	}
	at(c, "19:15")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Errorf("the replaced ten-minute deadline fired anyway: %+v", fw.last)
	}
	at(c, "20:00")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if !has(fw.last.Manual, eliPhone) {
		t.Errorf("the deadline that replaced it never fired: %+v", fw.last)
	}
}

func TestCancellingADelayedBlockStopsItLanding(t *testing.T) {
	c, fw, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.CancelBlockIn("eli"); err != nil {
		t.Fatal(err)
	}
	at(c, "19:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Errorf("a cancelled countdown fired anyway: %+v", fw.last)
	}
}

func TestADelayedBlockIsRefusedWhereItWouldDoNothing(t *testing.T) {
	c, _, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("nobody", 30*time.Minute); err == nil {
		t.Error("arming a block for a profile that does not exist must fail loudly")
	}
	if err := c.BlockIn("eli", 0); err == nil {
		t.Error("a delay of zero is not a delayed block; it must be refused")
	}
	if err := c.BlockIn("eli", -time.Minute); err == nil {
		t.Error("a negative delay must be refused")
	}
	if err := c.BlockIn("dad", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.Block("dad"); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockIn("dad", 30*time.Minute); err == nil {
		t.Error("arming a countdown for a profile that is ALREADY blocked must be refused, " +
			"or it would fire against an unblock the parent makes in between")
	}
}

// A state write that fails must not leave the firewall enforcing a block
// nothing recorded, and must not take the rest of enforcement down with it.
func TestAPendingBlockThatCannotBePersistedIsNotEnforcedAndDoesNotStopTheRest(t *testing.T) {
	c, fw, st := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	st.saveErr = errors.New("read-only filesystem")
	at(c, "23:30") // inside eli's bedtime window, so there IS other work to do
	if err := c.Tick(); err != nil {
		t.Fatalf("a state write failure must not fail the whole pass: %v", err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Error("a block was enforced that could not be recorded, so a reboot would lose it")
	}
	if !has(fw.last.Blocked, eliPhone) {
		t.Errorf("the bedtime window stopped being enforced because of it: %+v", fw.last)
	}
}

func TestPendingBlocksAreReportedForThePage(t *testing.T) {
	c, _, _ := household(t)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	pending, err := c.PendingBlocks()
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 3, 4, 19, 30, 0, 0, time.UTC)
	if got, armed := pending["eli"]; !armed || !got.Equal(want) {
		t.Errorf("the page cannot see the countdown: %v", pending)
	}
	if _, armed := pending["dad"]; armed {
		t.Error("a profile with no countdown was reported as having one")
	}
}

// A deleted profile's countdown must not fire against whoever reuses the name.
func TestADeletedProfilesCountdownIsForgotten(t *testing.T) {
	reg := memRegistry{reg: &registry.Registry{Devices: []registry.Device{
		{MAC: eliPhone, Name: "eli phone"},
	}}}
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{eliPhone}},
	}}
	st := &memState{}
	fw := &fakeFirewall{}
	c := New(reg, memSchedule{ps: ps}, st, fw, time.UTC, nil)
	at(c, "19:00")
	if err := c.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatal(err)
	}

	// The profile is deleted, and later somebody creates one with the same
	// name for a different child.
	ps.Profiles = nil
	at(c, "19:10")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	ps.Profiles = []schedule.Profile{{Name: "eli", Devices: []string{eliPhone}}}
	at(c, "19:30")
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}
	if has(fw.last.Manual, eliPhone) {
		t.Errorf("a deleted profile's countdown fired against its replacement: %+v", fw.last)
	}
}
