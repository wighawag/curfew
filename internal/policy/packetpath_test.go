//go:build linux

package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/netnstest"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// Packet-path tests for the POLICY layer, driven end to end: real files, the
// real core, the real netlink enforcer, and a real packet.
//
// The claims here are the ones a unit test cannot make honestly. "A manual
// block survives a reboot" is a statement about a file, a fresh process and
// the kernel together, and it is the headline defect of the system this
// replaces: after a reboot, blocks silently evaporated while every state file
// and log line still said the child was blocked.

// onDisk builds a household whose config and state live in real files under a
// temp directory, the way they do on the router.
func onDisk(t *testing.T, macs ...string) (regPath, schedPath, statePath string) {
	t.Helper()
	dir := t.TempDir()
	regPath = filepath.Join(dir, "devices.json")
	schedPath = filepath.Join(dir, "profiles.json")
	statePath = filepath.Join(dir, "state.json")

	reg := &registry.Registry{}
	for _, m := range macs {
		if err := reg.Add(m, ""); err != nil {
			t.Fatalf("Add(%s): %v", m, err)
		}
	}
	if err := registry.Save(regPath, reg); err != nil {
		t.Fatalf("saving registry: %v", err)
	}
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{macs[0]}, Windows: []schedule.Window{}},
	}}
	if len(macs) > 1 {
		ps.Profiles = append(ps.Profiles, schedule.Profile{
			Name: "dad", Devices: []string{macs[1]}, Windows: []schedule.Window{},
		})
	}
	if err := schedule.Save(schedPath, ps); err != nil {
		t.Fatalf("saving schedule: %v", err)
	}
	return regPath, schedPath, statePath
}

// boot builds a core exactly as the daemon does at startup: nothing carried
// over in memory, everything read back off disk.
func boot(t *testing.T, regPath, schedPath, statePath string) *Core {
	t.Helper()
	fw, err := enforce.New(enforce.Config{
		LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf,
	})
	if err != nil {
		t.Fatalf("enforce.New: %v", err)
	}
	return New(registry.FileStore{Path: regPath}, schedule.FileStore{Path: schedPath},
		blockstate.FileStore{Path: statePath}, fw, time.UTC, nil)
}

const (
	eliMAC = "aa:bb:cc:dd:ee:01"
	dadMAC = "aa:bb:cc:dd:ee:03"
)

// The defect this whole project exists to remove, asserted with a packet: a
// reboot must not hand a grounded child their internet back.
func TestPacketPathAManualBlockSurvivesAReboot(t *testing.T) {
	net := netnstest.Require(t)
	regPath, schedPath, statePath := onDisk(t, eliMAC, dadMAC)

	core := boot(t, regPath, schedPath, statePath)
	if err := core.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline: a registered device with no block must reach the internet")
	}
	if err := core.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if net.Reaches() {
		t.Fatal("a manually blocked profile must be offline before we test whether it stays that way")
	}

	// The reboot: the ruleset is gone with the kernel's tables, and a brand
	// new process reads the same files.
	net.DeleteTable()
	if !net.Reaches() {
		t.Fatal("with the table gone everything should flow, or the assertion below proves nothing")
	}
	rebooted := boot(t, regPath, schedPath, statePath)
	if err := rebooted.Reconcile(); err != nil {
		t.Fatalf("Reconcile after reboot: %v", err)
	}
	if net.Reaches() {
		t.Error("a reboot silently unblocked a grounded child: the manual block was not restored")
	}

	// Control: the other profile was never blocked and must come back online,
	// which rules out "the reboot blocked everyone" passing as success.
	net.SetClientMAC(dadMAC)
	if !net.Reaches() {
		t.Error("an unblocked profile must reach the internet after the reboot")
	}
}

// A ticket is MEANT to die with the router. Persisting one would resurrect a
// grant whose entire point is that it runs out.
func TestPacketPathATicketDoesNotSurviveAReboot(t *testing.T) {
	net := netnstest.Require(t)
	regPath, schedPath, statePath := onDisk(t, eliMAC, dadMAC)

	// Block eli by schedule, using a window that covers the whole day, so the
	// only thing that can let them out is the ticket.
	allDay(t, schedPath)

	core := boot(t, regPath, schedPath, statePath)
	if err := core.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if net.Reaches() {
		t.Fatal("the window should block eli before the ticket is issued")
	}
	if err := core.GrantTicket("eli", 10*time.Minute); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	if !net.Reaches() {
		t.Fatal("the ticket must work, or its disappearance below proves nothing")
	}

	net.DeleteTable()
	rebooted := boot(t, regPath, schedPath, statePath)
	if err := rebooted.Reconcile(); err != nil {
		t.Fatalf("Reconcile after reboot: %v", err)
	}
	if net.Reaches() {
		t.Error("a ticket survived a reboot: it must die with the kernel state it lives in")
	}
	// And nothing wrote it down anywhere, which is what makes that true.
	data, err := os.ReadFile(statePath)
	if err == nil && len(data) > 0 {
		st, err := blockstate.Load(statePath)
		if err != nil {
			t.Fatalf("state unreadable: %v", err)
		}
		if len(st.ManualBlocked) != 0 {
			t.Errorf("a ticket must not be recorded as a block: %+v", st)
		}
	}
}

// The whole gesture a parent performs on their phone, end to end: unblock,
// then ticket, then watch the block come back when the ticket runs out.
func TestPacketPathUnblockThenTicketThenTheWindowTakesOverAgain(t *testing.T) {
	net := netnstest.Require(t)
	regPath, schedPath, statePath := onDisk(t, eliMAC, dadMAC)
	allDay(t, schedPath)

	core := boot(t, regPath, schedPath, statePath)
	if err := core.Block("eli"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if net.Reaches() {
		t.Fatal("a blocked profile must be offline to begin with")
	}
	// The first half of the gesture. It is refused as one call on purpose.
	if err := core.GrantTicket("eli", 4*time.Second); err == nil {
		t.Fatal("ticketing a manually blocked profile must be refused, not fused with an unblock")
	}
	if err := core.Unblock("eli"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if net.Reaches() {
		t.Fatal("unblocking must leave the all-day window in force")
	}
	if err := core.GrantTicket("eli", 4*time.Second); err != nil {
		t.Fatalf("GrantTicket: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	if !net.Reaches() {
		t.Fatal("the ticket must free the profile from the window")
	}
	time.Sleep(time.Until(deadline) + time.Second)
	if net.Reaches() {
		t.Error("the profile stayed online after the ticket lapsed: expiry must fall back to the window")
	}
}

// allDay rewrites the schedule so eli is blocked at every hour of every day,
// which makes a ticket the only possible reason they could be online.
func allDay(t *testing.T, schedPath string) {
	t.Helper()
	ps, err := schedule.Load(schedPath)
	if err != nil {
		t.Fatalf("loading schedule: %v", err)
	}
	p, ok := ps.Find("eli")
	if !ok {
		t.Fatal("fixture has no eli")
	}
	p.Windows = []schedule.Window{{Days: schedule.AllDays, Start: "00:00", End: "23:59"}}
	if err := schedule.Save(schedPath, ps); err != nil {
		t.Fatalf("saving schedule: %v", err)
	}
}

// A delayed block, on the packet path and across a reboot.
//
// Two claims a unit test cannot make honestly. Before the deadline the child is
// genuinely still online, with real packets, so "it changed nothing yet" is not
// merely a statement about a struct. And a router that reboots during the
// countdown still applies it, because a decision on disk is the only kind that
// survives a power cut: a timer in memory would hand the child the rest of
// their evening.
func TestPacketPathADelayedBlockSurvivesARebootAndLandsOnTime(t *testing.T) {
	net := netnstest.Require(t)
	regPath, schedPath, statePath := onDisk(t, eliMAC, dadMAC)

	core := boot(t, regPath, schedPath, statePath)
	core.now = func() time.Time { return time.Date(2026, 3, 4, 19, 0, 0, 0, time.UTC) }
	if err := core.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline: a registered device with no block must reach the internet")
	}

	if err := core.BlockIn("eli", 30*time.Minute); err != nil {
		t.Fatalf("BlockIn: %v", err)
	}
	if err := core.Reconcile(); err != nil {
		t.Fatalf("Reconcile after arming: %v", err)
	}
	// The point of the feature: nothing happens yet, to real packets.
	if !net.Reaches() {
		t.Fatal("arming a delayed block cut the child off immediately")
	}

	// The reboot, mid-countdown: tables gone, fresh process, same files. The
	// clock is set past the deadline, which is also what a router that was off
	// over the deadline looks like from here.
	net.DeleteTable()
	if !net.Reaches() {
		t.Fatal("with the table gone everything should flow, or the assertion below proves nothing")
	}
	rebooted := boot(t, regPath, schedPath, statePath)
	rebooted.now = func() time.Time { return time.Date(2026, 3, 4, 19, 30, 0, 0, time.UTC) }
	if err := rebooted.Reconcile(); err != nil {
		t.Fatalf("Reconcile after reboot: %v", err)
	}
	if net.Reaches() {
		t.Error("a delayed block armed before a reboot never landed, so the countdown died " +
			"with the router")
	}

	// It is off until LIFTED: what landed is an ordinary manual block, so it
	// must survive the NEXT reboot too, exactly as one made by hand does.
	net.DeleteTable()
	again := boot(t, regPath, schedPath, statePath)
	again.now = func() time.Time { return time.Date(2026, 3, 4, 21, 0, 0, 0, time.UTC) }
	if err := again.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if net.Reaches() {
		t.Error("the block that landed did not survive a reboot, so it was not a real manual block")
	}

	// CONTROL: the other profile is online throughout, which rules out "the
	// reboot blocked everyone" passing as success.
	net.SetClientMAC(dadMAC)
	if !net.Reaches() {
		t.Error("a profile with no countdown was blocked too")
	}

	// And a parent can lift it, which is the only way it ends.
	net.SetClientMAC(eliMAC)
	if err := again.Unblock("eli"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if !net.Reaches() {
		t.Error("lifting the block that landed did not put the child back online")
	}
}
