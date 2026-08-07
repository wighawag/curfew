//go:build linux

// Package netnstest builds a real LAN -> router -> WAN topology out of network
// namespaces, so a test can send an actual packet from a chosen source MAC and
// observe whether it arrived.
//
// It exists as its own package, rather than as a helper inside one test file,
// because more than one layer needs to make claims about enforcement and every
// one of those claims has to be settled the same way: with a packet. Per
// docs/adr/0004-tests-assert-on-the-packet-path.md, set membership and ruleset
// text are what looked perfect while the old system enforced nothing.
//
// It needs NET_ADMIN and SYS_ADMIN and skips when they are unavailable, so an
// ordinary `go test ./...` on a laptop passes without pretending to have
// tested enforcement. The gate runs it inside the OpenWrt image (see docker/).
package netnstest

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/contract"
)

// The topology. The router-side interface names are what the ruleset matches
// on, so tests must configure the enforcer with LANIf and WANIf.
const (
	LANIf      = "br-lan-t"
	WANIf      = "wan-t"
	RouterLAN  = "10.99.1.1"
	ClientIP   = "10.99.1.2"
	RouterWAN  = "10.99.2.1"
	InternetIP = "10.99.2.2"
	pageBody   = "PACKET-PATH-OK"
)

// Topology is a live LAN-to-WAN test network.
type Topology struct{ t *testing.T }

// Run executes a fully-formed shell command. It is deliberately NOT
// printf-like: callers format first, so vet can keep checking their format
// strings instead of losing track of them behind a wrapper.
func run(t *testing.T, cmd string) (string, error) {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

// Run executes a shell command on the router side, returning its output.
func (n *Topology) Run(cmd string) (string, error) { return run(n.t, cmd) }

// MustRun executes a shell command and fails the test if it does not succeed.
func (n *Topology) MustRun(cmd string) {
	n.t.Helper()
	mustRun(n.t, cmd)
}

func mustRun(t *testing.T, cmd string) {
	t.Helper()
	out, err := run(t, cmd)
	if err != nil {
		t.Fatalf("command failed: %s\n%s\n%v", cmd, out, err)
	}
}

// InNS builds a command that runs inside a network namespace.
func InNS(ns, format string, args ...any) string {
	return "nsenter --net=/var/run/netns/" + ns + " " + fmt.Sprintf(format, args...)
}

// F is a short alias for building a command string.
func F(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// Require builds the namespaces, or skips when the environment cannot.
//
// It tears the topology down again on cleanup, and it deletes the curfew table
// too, so one test's ruleset can never be the reason the next one passes.
func Require(t *testing.T) *Topology {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("packet-path tests need root (NET_ADMIN, SYS_ADMIN)")
	}
	if _, err := run(t, "ip netns list"); err != nil {
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
	mustRun(t, F("ip link add %s type bridge", LANIf))
	mustRun(t, F("ip addr add %s/24 dev %s", RouterLAN, LANIf))
	mustRun(t, F("ip link set %s up", LANIf))
	mustRun(t, "ip link add veth-lan type veth peer name cl0")
	mustRun(t, F("ip link set veth-lan master %s", LANIf))
	mustRun(t, "ip link set veth-lan up")
	mustRun(t, "ip link set cl0 netns client")
	mustRun(t, InNS("client", "ip addr add %s/24 dev cl0", ClientIP))
	mustRun(t, InNS("client", "ip link set cl0 up"))
	mustRun(t, InNS("client", "ip link set lo up"))
	mustRun(t, InNS("client", "ip route add default via %s", RouterLAN))

	// WAN side. The router-side end carries the name the rules match on.
	mustRun(t, F("ip link add %s type veth peer name inet0", WANIf))
	mustRun(t, F("ip addr add %s/24 dev %s", RouterWAN, WANIf))
	mustRun(t, F("ip link set %s up", WANIf))
	mustRun(t, "ip link set inet0 netns internet")
	mustRun(t, InNS("internet", "ip addr add %s/24 dev inet0", InternetIP))
	mustRun(t, InNS("internet", "ip link set inet0 up"))
	mustRun(t, InNS("internet", "ip link set lo up"))
	mustRun(t, InNS("internet", "ip route add default via %s", RouterWAN))

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
	mustRun(t, F("printf '%%s' %s > /tmp/mr-docroot/index.html", pageBody))
	mustRun(t, InNS("internet", "/usr/sbin/uhttpd -h /tmp/mr-docroot -p %s:80", InternetIP)+" >/dev/null 2>&1 </dev/null")

	ready := false
	for range 20 {
		if _, err := run(t, F("wget -q -T 1 -O /dev/null http://%s/", InternetIP)); err == nil {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("the internet host never became ready; the topology is broken, so every result below would read as blocked")
	}
	return &Topology{t: t}
}

func teardown(t *testing.T) {
	t.Helper()
	_, _ = run(t, "pgrep -f 'uhttpd -h /tmp/mr-docroot' | xargs -r kill 2>/dev/null")
	_, _ = run(t, "ip netns delete client 2>/dev/null")
	_, _ = run(t, "ip netns delete internet 2>/dev/null")
	_, _ = run(t, F("ip link delete %s 2>/dev/null", LANIf))
	_, _ = run(t, F("ip link delete %s 2>/dev/null", WANIf))
	_, _ = run(t, F("nft delete table inet %s 2>/dev/null", contract.Table))
	_, _ = run(t, "rm -rf /tmp/mr-docroot")
}

// SetClientMAC gives the client a source MAC of the caller's choosing, which is
// what makes a per-device claim testable at all.
func (n *Topology) SetClientMAC(mac string) {
	n.t.Helper()
	mustRun(n.t, InNS("client", "ip link set cl0 down"))
	mustRun(n.t, InNS("client", "ip link set cl0 address %s", mac))
	mustRun(n.t, InNS("client", "ip link set cl0 up"))
	// Bringing the link down DELETES the default route. Without re-adding it
	// every probe reads unreachable for a routing reason, which is
	// indistinguishable from a perfect firewall.
	_, _ = run(n.t, InNS("client", "ip route add default via %s 2>/dev/null", RouterLAN))
	_, _ = run(n.t, InNS("client", "ip neigh flush all 2>/dev/null"))
	_, _ = run(n.t, F("ip neigh flush dev %s 2>/dev/null", LANIf))
}

// Reaches sends a real packet and reports whether it arrived.
func (n *Topology) Reaches() bool {
	n.t.Helper()
	out, err := run(n.t, InNS("client", "wget -q -T 3 -O - http://%s/", InternetIP))
	return err == nil && strings.Contains(out, pageBody)
}

// DeleteTable removes the curfew table, simulating a recovery path or a fresh
// boot before anything has been applied.
func (n *Topology) DeleteTable() {
	n.t.Helper()
	mustRun(n.t, F("nft delete table inet %s", contract.Table))
}
