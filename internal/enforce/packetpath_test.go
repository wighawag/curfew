//go:build linux

package enforce

import (
	"os"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/netnstest"
)

// Packet-path tests for the ordering contract.
//
// Per docs/adr/0004-tests-assert-on-the-packet-path.md, a claim about
// enforcement is only credible if a real packet was sent and observed. Set
// membership is what looked perfect while the old system enforced nothing.
//
// The topology comes from internal/netnstest, needs NET_ADMIN and SYS_ADMIN,
// and is skipped when unavailable. The gate runs these in the OpenWrt test
// image (see docker/).

const (
	allowedMAC = "aa:bb:cc:dd:ee:01"
	secondMAC  = "aa:bb:cc:dd:ee:02"
	unknownMAC = "aa:bb:cc:dd:ee:99"
)

func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := New(Config{LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// allow is the common case: these MACs registered, nothing blocked.
func allow(macs ...string) Desired { return Desired{Allowed: macs} }

func TestPacketPathBaselineForwards(t *testing.T) {
	// Mandatory, not redundant. A topology fault makes every probe read
	// unreachable, so a suite without this reports a flawless pass while
	// testing nothing at all.
	net := netnstest.Require(t)
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Fatal("baseline: the topology does not forward with no rules applied, so no result below would mean anything")
	}
}

func TestPacketPathAllowlistedDeviceReachesTheInternet(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Fatal("baseline failed before the rules were applied")
	}
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Error("a registered device must still reach the internet")
	}
}

func TestPacketPathUnknownDeviceIsDropped(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(unknownMAC)
	if net.Reaches() {
		t.Error("an unregistered device reached the internet: the allowlist is not enforcing")
	}
	// Control: the same ruleset must still let the registered device through,
	// which rules out "everything is blocked" passing as success.
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Error("the registered device was blocked too, so the drop above proves nothing")
	}
}

func TestPacketPathRemovingADeviceRevokesAccess(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Fatal("device should start out allowed")
	}
	if err := e.ApplyDesired(Desired{}); err != nil {
		t.Fatalf("ApplyDesired(empty): %v", err)
	}
	if net.Reaches() {
		t.Error("after removal the device must lose internet access")
	}
}

// Re-applying is the boot path and the reconcile path. It must converge rather
// than tear a hole: the original system's equivalent step is what silently
// unblocked every profile after a reboot.
func TestPacketPathReapplyIsIdempotent(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(unknownMAC)
	for i := range 3 {
		if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
			t.Fatalf("ApplyDesired #%d: %v", i, err)
		}
		if net.Reaches() {
			t.Fatalf("after apply #%d an unregistered device reached the internet", i)
		}
	}
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Error("the registered device should still be allowed after repeated applies")
	}
}

func TestAllowlistIsReadBackFromTheFirewall(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	got, err := e.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist: %v", err)
	}
	if len(got) != 1 || got[0] != allowedMAC {
		t.Errorf("Allowlist() = %v, want [%s]", got, allowedMAC)
	}
}

func TestTeardownRestoresConnectivity(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(unknownMAC)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Fatal("the unknown device should be blocked before teardown")
	}
	if err := e.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !net.Reaches() {
		t.Error("teardown must restore connectivity; it is the recovery path")
	}
	// Tearing down twice must not error, or recovery becomes conditional on
	// state the operator cannot see.
	if err := e.Teardown(); err != nil {
		t.Errorf("Teardown must be idempotent, got %v", err)
	}
}

func TestApplyRejectsAnInvalidMACRatherThanSkippingIt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	e, err := New(Config{LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf})
	if err != nil {
		t.Skipf("no netlink here: %v", err)
	}
	if err := e.ApplyDesired(allow("not-a-mac")); err == nil {
		t.Error("an invalid MAC must fail the whole apply, not be silently dropped from the allowlist")
	}
	if err := e.ApplyDesired(Desired{Manual: []string{"not-a-mac"}}); err == nil {
		t.Error("an invalid MAC in the manual block list must fail the apply too")
	}
}

func TestNewRequiresBothInterfaces(t *testing.T) {
	if _, err := New(Config{LANInterface: "br-lan"}); err == nil {
		t.Error("a missing WAN interface must be an error, not a guess")
	}
	if _, err := New(Config{WANInterface: "wan"}); err == nil {
		t.Error("a missing LAN interface must be an error, not a guess")
	}
}

// A tier added to the contract without a desired-state source must fail
// LOUDLY. Silently emitting a rule that matches a permanently empty set is a
// disabled policy that looks enabled, which is this project's whole subject.
func TestDesiredRefusesATierItCannotCompute(t *testing.T) {
	if _, err := (Desired{}).forSet("guest_macs"); err == nil {
		t.Error("an unknown tier must be an error, not an empty set")
	}
}

// Self-healing must work when the table is GONE, not just when it drifted.
// This is the regression guard for a real bug: the reconcile loop read the
// allowlist first and returned the error when the table was missing, so it
// never re-applied in the one situation that most needs it. Found end to end,
// by deleting the table and watching enforcement stay gone.
func TestEnsureAppliedRecoversFromADeletedTable(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(unknownMAC)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Fatal("the unknown device should be blocked to begin with")
	}

	net.DeleteTable()
	if !net.Reaches() {
		t.Fatal("with the table gone everything should flow; otherwise this test proves nothing")
	}

	changed, err := e.EnsureApplied(allow(allowedMAC))
	if err != nil {
		t.Fatalf("EnsureApplied after the table was deleted: %v", err)
	}
	if !changed {
		t.Error("a missing table must count as drift and be re-applied")
	}
	if net.Reaches() {
		t.Error("enforcement did not come back after the table was deleted")
	}
}

func TestEnsureAppliedDoesNothingWhenAlreadyCorrect(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	changed, err := e.EnsureApplied(allow(allowedMAC))
	if err != nil {
		t.Fatalf("EnsureApplied: %v", err)
	}
	if changed {
		t.Error("a steady state must not rewrite the ruleset every tick")
	}
}

// A manual block is its own tier, so drift in it must be seen. Without this
// case a manual block wiped out of the ruleset by hand would never heal.
func TestEnsureAppliedSeesDriftInTheManualTier(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	changed, err := e.EnsureApplied(Desired{Allowed: []string{allowedMAC}, Manual: []string{allowedMAC}})
	if err != nil {
		t.Fatalf("EnsureApplied: %v", err)
	}
	if !changed {
		t.Fatal("adding a manual block is drift and must be applied")
	}
	got, err := e.ManualBlocked()
	if err != nil {
		t.Fatalf("ManualBlocked: %v", err)
	}
	if len(got) != 1 || got[0] != allowedMAC {
		t.Errorf("ManualBlocked() = %v, want [%s]", got, allowedMAC)
	}
}

// A scheduled block must beat the allowlist: being a registered device does
// not save you from your bedtime. This is the ordering contract of ADR 0006
// asserted with real packets rather than by reading the ruleset.
func TestPacketPathScheduledBlockOutranksTheAllowlist(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Fatal("registered and outside any window: should reach the internet")
	}

	// Same device, now inside a blocked window.
	if err := e.ApplyDesired(Desired{Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Error("a registered device inside its window must be blocked")
	}

	// And the window ending restores it, with no bookkeeping.
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Error("leaving the window must restore access")
	}
}

func TestPacketPathBlockingOneProfileLeavesAnotherAlone(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC, secondMAC}, Blocked: []string{secondMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Error("the unblocked device must still reach the internet")
	}
	net.SetClientMAC(secondMAC)
	if net.Reaches() {
		t.Error("the blocked device must not")
	}
}

func TestBlockedIsReadBackFromTheFirewall(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	got, err := e.Blocked()
	if err != nil {
		t.Fatalf("Blocked: %v", err)
	}
	if len(got) != 1 || got[0] != allowedMAC {
		t.Errorf("Blocked() = %v, want [%s]", got, allowedMAC)
	}
}

// A manual block drops a registered device, and only that device.
func TestPacketPathManualBlockDropsARegisteredDevice(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC, secondMAC}, Manual: []string{allowedMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(allowedMAC)
	if net.Reaches() {
		t.Error("a manually blocked device must not reach the internet")
	}
	// Control: another registered device is untouched, so the drop above is
	// the manual block and not a broken ruleset.
	net.SetClientMAC(secondMAC)
	if !net.Reaches() {
		t.Error("blocking one profile must leave another alone")
	}
}

// Story 8 of the enforcement spec: a ticket frees a profile that a window is
// currently blocking.
func TestPacketPathTicketOverridesAScheduleBlock(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Fatal("inside a window the profile should start out blocked")
	}
	if err := e.GrantTicket([]string{allowedMAC}, time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if !net.Reaches() {
		t.Error("a ticket must override a schedule block")
	}
}

// Assertion 14c of the enforcement spec, titled precisely: a MANUAL block
// outranks a live ticket. A schedule-blocked profile CAN be ticketed, which
// the test above asserts, so this must not be generalised into "a blocked
// profile cannot be ticketed" or it would destroy that.
func TestPacketPathManualBlockOutranksALiveTicket(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	// A ticket, live and working, is the control: without it the drop below
	// would prove only that something is broken.
	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if err := e.GrantTicket([]string{allowedMAC}, 2*time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if !net.Reaches() {
		t.Fatal("the ticket must work first, or the manual block below proves nothing")
	}

	// Now put the SAME MAC in the manual set directly, with nft, leaving the
	// ticket untouched. This is the state the chain order exists to decide,
	// constructed deliberately: the policy layer refuses to produce it, and the
	// ruleset must still get it right.
	net.MustRun(netnstest.F("nft add element inet %s %s { %s }",
		TableName, ManualBlockedSet, allowedMAC))
	live, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	if _, ok := live[allowedMAC]; !ok {
		t.Fatal("the ticket must still be live, or this asserts precedence over nothing")
	}
	if net.Reaches() {
		t.Error("a manual block must outrank a live ticket: a child must not be able to ticket their way out of being grounded")
	}
}

// Assertion 14d: a manual block CANCELS a live ticket, so lifting the block
// later cannot resurrect it.
func TestPacketPathManualBlockCancelsALiveTicketSoUnblockCannotResurrectIt(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	blockedByWindow := Desired{Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC}}
	if err := e.ApplyDesired(blockedByWindow); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if err := e.GrantTicket([]string{allowedMAC}, 5*time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if !net.Reaches() {
		t.Fatal("the ticket must work first, or nothing below proves anything")
	}

	// The parent blocks. The ticket must go, not merely be outranked.
	if err := e.CancelTickets([]string{allowedMAC}); err != nil {
		t.Fatalf("CancelTickets: %v", err)
	}
	manual := Desired{Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC}, Manual: []string{allowedMAC}}
	if err := e.ApplyDesired(manual); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Fatal("a manually blocked profile must be unreachable")
	}

	// The parent lifts the block. The window is still in force, so the child
	// stays offline: the ticket must not come back to life.
	if err := e.ApplyDesired(blockedByWindow); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Error("unblocking resurrected the cancelled ticket: the child is online inside their bedtime window")
	}
	live, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("the ticket set should be empty after a block, got %v", live)
	}

	// Control: the profile is reachable again once the window itself ends, so
	// the unreachability above was the schedule and not a wedged ruleset.
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Error("with no reason left the profile must be reachable, or the assertions above prove nothing")
	}
}

// Story 10: the ticket ends by itself, with no background process. Nothing in
// this test cancels anything; the kernel reclaims the element.
func TestPacketPathTicketLapsesOnItsOwn(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	if err := e.ApplyDesired(Desired{
		Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	granted := 4 * time.Second
	if err := e.GrantTicket([]string{allowedMAC}, granted); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	deadline := time.Now().Add(granted)
	if !net.Reaches() {
		t.Fatal("the ticket must work while it lasts, or its expiry proves nothing")
	}
	time.Sleep(time.Until(deadline) + time.Second)
	if net.Reaches() {
		t.Error("the ticket did not lapse: the profile is still reachable after its deadline")
	}
}

// The load-bearing one. Apply replaces the WHOLE table, so a reconcile tick
// has to carry live tickets across with the time they have LEFT. Getting this
// wrong in either direction is invisible to any set-membership assertion:
// dropping them cuts a child off mid-ticket, and re-granting the original
// duration makes a 15-minute ticket last forever.
func TestTicketSurvivesRepeatedReconcilesAndStillExpiresOnTime(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	net.SetClientMAC(allowedMAC)

	want := Desired{Allowed: []string{allowedMAC}, Blocked: []string{allowedMAC}}
	if err := e.ApplyDesired(want); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	granted := 8 * time.Second
	if err := e.GrantTicket([]string{allowedMAC}, granted); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	deadline := time.Now().Add(granted)

	// Reconcile hard, the way a tight reconcile loop would, and check halfway
	// through that the ticket is still doing its job.
	checked := false
	for time.Now().Before(deadline.Add(-2 * time.Second)) {
		if err := e.ApplyDesired(want); err != nil {
			t.Fatalf("reconcile during a live ticket: %v", err)
		}
		if !checked && time.Now().After(deadline.Add(-6*time.Second)) {
			if !net.Reaches() {
				t.Fatal("a reconcile dropped the live ticket: the child lost access mid-ticket")
			}
			checked = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !checked {
		t.Fatal("the mid-ticket reachability check never ran, so this test proves nothing")
	}

	time.Sleep(time.Until(deadline) + time.Second)
	if net.Reaches() {
		t.Error("the ticket outlived its deadline: each reconcile must carry the REMAINING time, not re-grant the original duration")
	}
}

// The kernel owns the countdown, and Tickets reports the kernel's own number
// rather than one this process tracks in parallel.
func TestTicketsReportTheKernelsOwnCountdown(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if err := e.GrantTicket([]string{allowedMAC}, 30*time.Second); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	first, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	left, ok := first[allowedMAC]
	if !ok {
		t.Fatalf("Tickets() = %v, want an entry for %s", first, allowedMAC)
	}
	if left <= 0 || left > 30*time.Second {
		t.Errorf("remaining time %s is not a countdown from 30s", left)
	}

	time.Sleep(2 * time.Second)
	second, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	if second[allowedMAC] >= left {
		t.Errorf("the countdown did not move: %s then %s", left, second[allowedMAC])
	}

	// And it survives a whole-table replace with its deadline intact, rather
	// than being reset to the duration it was granted for.
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	after, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	if after[allowedMAC] > second[allowedMAC] {
		t.Errorf("the rebuild reset the ticket clock: %s before, %s after",
			second[allowedMAC], after[allowedMAC])
	}
}

// A rebuild must never carry a ticket for a MAC the parent has just blocked,
// whichever path put that ticket there. This is the structural half of "a
// block cancels a ticket": even a ticket granted by something that skipped the
// core cannot outlive the next apply.
func TestARebuildDropsATicketForAManuallyBlockedMAC(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if err := e.GrantTicket([]string{allowedMAC}, 5*time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if err := e.ApplyDesired(Desired{Allowed: []string{allowedMAC}, Manual: []string{allowedMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	live, err := e.Tickets()
	if err != nil {
		t.Fatalf("Tickets: %v", err)
	}
	if _, ok := live[allowedMAC]; ok {
		t.Error("a manually blocked MAC kept its ticket across a rebuild, so a later unblock would resurrect it")
	}
}

// Fail loudly rather than build a bare table. A non-owner quietly creating the
// table is the precise mechanism by which the previous system reported success
// while enforcing nothing.
func TestGrantTicketRefusesWhenTheRulesetIsNotThere(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.DeleteTable()
	if err := e.GrantTicket([]string{allowedMAC}, time.Minute); err == nil {
		t.Error("issuing a ticket with no ruleset in place must fail loudly, not appear to work")
	}
	// Cancelling, by contrast, is a no-op: there is nothing live to cancel,
	// and failing here would turn "this profile had no ticket" into "the block
	// could not be applied".
	if err := e.CancelTickets([]string{allowedMAC}); err != nil {
		t.Errorf("cancelling with no ruleset should be a no-op, got %v", err)
	}
}

func TestGrantTicketRejectsDurationsThatAreNotTickets(t *testing.T) {
	netnstest.Require(t)
	e := newTestEnforcer(t)
	if err := e.ApplyDesired(allow(allowedMAC)); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if err := e.GrantTicket([]string{allowedMAC}, 0); err == nil {
		t.Error("a zero-length ticket must be refused, not granted forever")
	}
	if err := e.GrantTicket([]string{allowedMAC}, MaxTicket+time.Minute); err == nil {
		t.Error("a ticket longer than the cap must be refused: an unbounded grant is not a ticket")
	}
	if err := e.GrantTicket(nil, time.Minute); err == nil {
		t.Error("a ticket for no devices must be refused rather than silently granting nothing")
	}
}
