//go:build linux

package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Packet-path tests for the allowlist.
//
// Per docs/adr/0004-tests-assert-on-the-packet-path.md, a claim about
// enforcement is only credible if a real packet was sent and observed. Set
// membership is what looked perfect while the old system enforced nothing.
//
// These build a LAN -> router -> WAN topology out of network namespaces, so
// they need NET_ADMIN and SYS_ADMIN and are skipped when unavailable. They run
// in the OpenWrt test image (see docker/), which is where the gate runs them.

const (
	lanIf      = "br-lan-t"
	wanIf      = "wan-t"
	routerLAN  = "10.99.1.1"
	clientIP   = "10.99.1.2"
	routerWAN  = "10.99.2.1"
	internetIP = "10.99.2.2"
	pageBody   = "PACKET-PATH-OK"
	allowedMAC = "aa:bb:cc:dd:ee:01"
	unknownMAC = "aa:bb:cc:dd:ee:99"
)

// runCmd executes a fully-formed shell command. It is deliberately NOT
// printf-like: callers format first, so vet can keep checking their format
// strings instead of losing track of them behind a wrapper.
func runCmd(t *testing.T, cmd string) (string, error) {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func mustRun(t *testing.T, cmd string) {
	t.Helper()
	out, err := runCmd(t, cmd)
	if err != nil {
		t.Fatalf("command failed: %s\n%s\n%v", cmd, out, err)
	}
}

// inNS builds a command that runs inside a network namespace.
func inNS(ns, format string, args ...any) string {
	return "nsenter --net=/var/run/netns/" + ns + " " + fmt.Sprintf(format, args...)
}

// f is a short alias for building a command string.
func f(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// requireTopology builds the namespaces, or skips when the environment cannot.
func requireTopology(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("packet-path tests need root (NET_ADMIN, SYS_ADMIN)")
	}
	if _, err := runCmd(t, "ip netns list"); err != nil {
		t.Skip("ip cannot do netns here; run this in the OpenWrt test image")
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Skip("nsenter unavailable")
	}

	teardown(t)
	t.Cleanup(func() { teardown(t) })

	mustRun(t, "mkdir -p /var/run/netns")
	mustRun(t, "ip netns add client")
	mustRun(t, "ip netns add internet")

	// LAN side.
	mustRun(t, f("ip link add %s type bridge", lanIf))
	mustRun(t, f("ip addr add %s/24 dev %s", routerLAN, lanIf))
	mustRun(t, f("ip link set %s up", lanIf))
	mustRun(t, "ip link add veth-lan type veth peer name cl0")
	mustRun(t, f("ip link set veth-lan master %s", lanIf))
	mustRun(t, "ip link set veth-lan up")
	mustRun(t, "ip link set cl0 netns client")
	mustRun(t, inNS("client", "ip addr add %s/24 dev cl0", clientIP))
	mustRun(t, inNS("client", "ip link set cl0 up"))
	mustRun(t, inNS("client", "ip link set lo up"))
	mustRun(t, inNS("client", "ip route add default via %s", routerLAN))

	// WAN side. The router-side end carries the name the rules match on.
	mustRun(t, f("ip link add %s type veth peer name inet0", wanIf))
	mustRun(t, f("ip addr add %s/24 dev %s", routerWAN, wanIf))
	mustRun(t, f("ip link set %s up", wanIf))
	mustRun(t, "ip link set inet0 netns internet")
	mustRun(t, inNS("internet", "ip addr add %s/24 dev inet0", internetIP))
	mustRun(t, inNS("internet", "ip link set inet0 up"))
	mustRun(t, inNS("internet", "ip link set lo up"))
	mustRun(t, inNS("internet", "ip route add default via %s", routerWAN))

	// Forwarding is the CONTAINER's job to set (docker/docker-compose.yml does
	// it via sysctls at creation; /proc/sys is read-only at runtime). Assert it
	// rather than skipping: we are already root in a netns-capable environment,
	// so forwarding being off is a broken harness, and skipping here would let
	// the gate report green while every packet assertion silently vanished.
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		t.Fatalf("cannot read ip_forward: %v", err)
	} else if strings.TrimSpace(string(data)) != "1" {
		t.Fatal("net.ipv4.ip_forward is not 1; the test container must enable forwarding, " +
			"otherwise every probe reads unreachable and a broken firewall looks perfect")
	}

	// The internet host. No -f: a foreground server would hold the test
	// runner's stdout open and hang the suite after the last test passes.
	mustRun(t, "mkdir -p /tmp/mr-docroot")
	mustRun(t, f("printf '%%s' %s > /tmp/mr-docroot/index.html", pageBody))
	mustRun(t, inNS("internet", "/usr/sbin/uhttpd -h /tmp/mr-docroot -p %s:80", internetIP)+" >/dev/null 2>&1 </dev/null")

	ready := false
	for range 20 {
		if _, err := runCmd(t, f("wget -q -T 1 -O /dev/null http://%s/", internetIP)); err == nil {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("the internet host never became ready; the topology is broken, so every result below would read as blocked")
	}
}

func teardown(t *testing.T) {
	t.Helper()
	_, _ = runCmd(t, "pgrep -f 'uhttpd -h /tmp/mr-docroot' | xargs -r kill 2>/dev/null")
	_, _ = runCmd(t, "ip netns delete client 2>/dev/null")
	_, _ = runCmd(t, "ip netns delete internet 2>/dev/null")
	_, _ = runCmd(t, f("ip link delete %s 2>/dev/null", lanIf))
	_, _ = runCmd(t, f("ip link delete %s 2>/dev/null", wanIf))
	_, _ = runCmd(t, f("nft delete table inet %s 2>/dev/null", TableName))
	_, _ = runCmd(t, "rm -rf /tmp/mr-docroot")
}

func setClientMAC(t *testing.T, mac string) {
	t.Helper()
	mustRun(t, inNS("client", "ip link set cl0 down"))
	mustRun(t, inNS("client", "ip link set cl0 address %s", mac))
	mustRun(t, inNS("client", "ip link set cl0 up"))
	// Bringing the link down DELETES the default route. Without re-adding it
	// every probe reads unreachable for a routing reason, which is
	// indistinguishable from a perfect firewall.
	_, _ = runCmd(t, inNS("client", "ip route add default via %s 2>/dev/null", routerLAN))
	_, _ = runCmd(t, inNS("client", "ip neigh flush all 2>/dev/null"))
	_, _ = runCmd(t, f("ip neigh flush dev %s 2>/dev/null", lanIf))
}

// reaches sends a real packet and reports whether it arrived.
func reaches(t *testing.T) bool {
	t.Helper()
	out, err := runCmd(t, inNS("client", "wget -q -T 3 -O - http://%s/", internetIP))
	return err == nil && strings.Contains(out, pageBody)
}

func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := New(Config{LANInterface: lanIf, WANInterface: wanIf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestPacketPathBaselineForwards(t *testing.T) {
	// Mandatory, not redundant. A topology fault makes every probe read
	// unreachable, so a suite without this reports a flawless pass while
	// testing nothing at all.
	requireTopology(t)
	setClientMAC(t, allowedMAC)
	if !reaches(t) {
		t.Fatal("baseline: the topology does not forward with no rules applied, so no result below would mean anything")
	}
}

func TestPacketPathAllowlistedDeviceReachesTheInternet(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, allowedMAC)
	if !reaches(t) {
		t.Fatal("baseline failed before the rules were applied")
	}
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !reaches(t) {
		t.Error("a registered device must still reach the internet")
	}
}

func TestPacketPathUnknownDeviceIsDropped(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	setClientMAC(t, unknownMAC)
	if reaches(t) {
		t.Error("an unregistered device reached the internet: the allowlist is not enforcing")
	}
	// Control: the same ruleset must still let the registered device through,
	// which rules out "everything is blocked" passing as success.
	setClientMAC(t, allowedMAC)
	if !reaches(t) {
		t.Error("the registered device was blocked too, so the drop above proves nothing")
	}
}

func TestPacketPathRemovingADeviceRevokesAccess(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, allowedMAC)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !reaches(t) {
		t.Fatal("device should start out allowed")
	}
	if err := e.Apply(nil); err != nil {
		t.Fatalf("Apply(empty): %v", err)
	}
	if reaches(t) {
		t.Error("after removal the device must lose internet access")
	}
}

// Re-applying is the boot path and the reconcile path. It must converge rather
// than tear a hole: the original system's equivalent step is what silently
// unblocked every profile after a reboot.
func TestPacketPathReapplyIsIdempotent(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, unknownMAC)
	for i := range 3 {
		if err := e.Apply([]string{allowedMAC}); err != nil {
			t.Fatalf("Apply #%d: %v", i, err)
		}
		if reaches(t) {
			t.Fatalf("after apply #%d an unregistered device reached the internet", i)
		}
	}
	setClientMAC(t, allowedMAC)
	if !reaches(t) {
		t.Error("the registered device should still be allowed after repeated applies")
	}
}

func TestAllowlistIsReadBackFromTheFirewall(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
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
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, unknownMAC)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if reaches(t) {
		t.Fatal("the unknown device should be blocked before teardown")
	}
	if err := e.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !reaches(t) {
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
	e, err := New(Config{LANInterface: lanIf, WANInterface: wanIf})
	if err != nil {
		t.Skipf("no netlink here: %v", err)
	}
	if err := e.Apply([]string{"not-a-mac"}); err == nil {
		t.Error("an invalid MAC must fail the whole apply, not be silently dropped from the allowlist")
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

// Self-healing must work when the table is GONE, not just when it drifted.
// This is the regression guard for a real bug: the reconcile loop read the
// allowlist first and returned the error when the table was missing, so it
// never re-applied in the one situation that most needs it. Found end to end,
// by deleting the table and watching enforcement stay gone.
func TestEnsureAppliedRecoversFromADeletedTable(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, unknownMAC)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if reaches(t) {
		t.Fatal("the unknown device should be blocked to begin with")
	}

	mustRun(t, f("nft delete table inet %s", TableName))
	if !reaches(t) {
		t.Fatal("with the table gone everything should flow; otherwise this test proves nothing")
	}

	changed, err := e.EnsureApplied([]string{allowedMAC})
	if err != nil {
		t.Fatalf("EnsureApplied after the table was deleted: %v", err)
	}
	if !changed {
		t.Error("a missing table must count as drift and be re-applied")
	}
	if reaches(t) {
		t.Error("enforcement did not come back after the table was deleted")
	}
}

func TestEnsureAppliedDoesNothingWhenAlreadyCorrect(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	if err := e.Apply([]string{allowedMAC}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	changed, err := e.EnsureApplied([]string{allowedMAC})
	if err != nil {
		t.Fatalf("EnsureApplied: %v", err)
	}
	if changed {
		t.Error("a steady state must not rewrite the ruleset every tick")
	}
}

// A scheduled block must beat the allowlist: being a registered device does
// not save you from your bedtime. This is the ordering contract of ADR 0006
// asserted with real packets rather than by reading the ruleset.
func TestPacketPathScheduledBlockOutranksTheAllowlist(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	setClientMAC(t, allowedMAC)

	if err := e.ApplyState([]string{allowedMAC}, nil); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	if !reaches(t) {
		t.Fatal("registered and outside any window: should reach the internet")
	}

	// Same device, now inside a blocked window.
	if err := e.ApplyState([]string{allowedMAC}, []string{allowedMAC}); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	if reaches(t) {
		t.Error("a registered device inside its window must be blocked")
	}

	// And the window ending restores it, with no bookkeeping.
	if err := e.ApplyState([]string{allowedMAC}, nil); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	if !reaches(t) {
		t.Error("leaving the window must restore access")
	}
}

func TestPacketPathBlockingOneProfileLeavesAnotherAlone(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	other := "aa:bb:cc:dd:ee:02"
	if err := e.ApplyState([]string{allowedMAC, other}, []string{other}); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	setClientMAC(t, allowedMAC)
	if !reaches(t) {
		t.Error("the unblocked device must still reach the internet")
	}
	setClientMAC(t, other)
	if reaches(t) {
		t.Error("the blocked device must not")
	}
}

func TestBlockedIsReadBackFromTheFirewall(t *testing.T) {
	requireTopology(t)
	e := newTestEnforcer(t)
	if err := e.ApplyState([]string{allowedMAC}, []string{allowedMAC}); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	got, err := e.Blocked()
	if err != nil {
		t.Fatalf("Blocked: %v", err)
	}
	if len(got) != 1 || got[0] != allowedMAC {
		t.Errorf("Blocked() = %v, want [%s]", got, allowedMAC)
	}
}
