//go:build linux

package deploy

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/dhcplock"
	"github.com/wighawag/curfew/internal/leases"
)

// The race the DHCP config lock exists to close, run for real: real uci, a
// real /etc/config/dhcp, the real lock, and the real daemon transaction
// (leases.Apply) against the real takeover step (moveDnsmasqTo54). Only the
// two things this image cannot do are replayed: there is no procd, so
// `/etc/init.d/dnsmasq` is answered "ok", and the liveness probe is scripted
// so the daemon's transaction is FORCED into a slow rollback.
//
// The interleaving that hurts: the daemon backs up /etc/config/dhcp, commits
// a pin, and while it is deciding dnsmasq is dead the takeover moves dnsmasq
// to 54; the daemon then restores its backup, which says 53. AdGuard holds 53,
// so on a real router dnsmasq could not start at all.

func requireRealUCI(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"uci", "flock", "mkfifo"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s; run this in the OpenWrt test image", tool)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to write /etc/config")
	}
}

// Includes the two lists local DNS names will live in, so the same test pins
// that moving dnsmasq never touches them.
const raceDHCP = `
config dnsmasq
	option rebind_protection '1'
	option local '/lan/'
	list address '/*.lan.example.test/192.168.1.122'
	list server '/*.lan.example.test/'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	list dhcp_option '42,192.168.1.1'
`

func writeRaceDHCP(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll("/etc/config", 0o755); err != nil {
		t.Fatal(err)
	}
	prev, prevErr := os.ReadFile("/etc/config/dhcp")
	if err := os.WriteFile("/etc/config/dhcp", []byte(raceDHCP), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll("/tmp/.uci")
	_ = os.RemoveAll(leases.StageDir)
	t.Cleanup(func() {
		if prevErr == nil {
			_ = os.WriteFile("/etc/config/dhcp", prev, 0o644)
		} else {
			_ = os.Remove("/etc/config/dhcp")
		}
		_ = os.RemoveAll("/tmp/.uci")
	})
}

func uciGet(t *testing.T, key string) string {
	t.Helper()
	out, _ := exec.Command("sh", "-c", "uci -q get "+key).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// routerShell runs everything in the real shell except what needs procd.
type routerShell struct {
	// onLiveness, when set, answers the daemon's `pgrep dnsmasq`.
	onLiveness func() string
}

func (s *routerShell) Run(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "/etc/init.d/dnsmasq"):
		return "", nil
	case strings.HasPrefix(cmd, "pgrep dnsmasq") && s.onLiveness != nil:
		return s.onLiveness(), nil
	case strings.HasPrefix(cmd, "logread"):
		return "", nil
	}
	out, err := exec.Command("sh", "-c", cmd).Output()
	return string(out), err
}
func (s *routerShell) Upload(string, string) error   { return nil }
func (s *routerShell) Download(string, string) error { return nil }

// race runs a daemon pin transaction that is forced to roll back slowly, and
// starts the takeover's move the moment the daemon has committed. It returns
// the port uci holds afterwards.
func race(t *testing.T) string {
	t.Helper()
	writeRaceDHCP(t)

	var once sync.Once
	committed := make(chan struct{})
	rolledBack := false
	var mu sync.Mutex
	daemon := &routerShell{}
	daemon.onLiveness = func() string {
		mu.Lock()
		defer mu.Unlock()
		if rolledBack {
			return "yes\n"
		}
		once.Do(func() {
			close(committed)
			// Long enough for an unserialised move to land inside the
			// daemon's transaction.
			mu.Unlock()
			time.Sleep(2 * time.Second)
			mu.Lock()
		})
		return "no\n"
	}
	wrapped := &rollbackSpy{routerShell: daemon, mark: func() {
		mu.Lock()
		rolledBack = true
		mu.Unlock()
	}}

	done := make(chan error, 1)
	go func() {
		_, err := leases.Apply(wrapped, leases.Plan{Commands: []string{
			"uci set dhcp.curfew_aabbccddeeff=host",
			"uci set dhcp.curfew_aabbccddeeff.mac='aa:bb:cc:dd:ee:ff'",
			"uci set dhcp.curfew_aabbccddeeff.ip='192.168.1.150'",
		}})
		done <- err
	}()

	select {
	case <-committed:
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon transaction never reached its liveness check")
	}
	if _, err := moveDnsmasqTo54(&routerShell{}, "192.168.1.1"); err != nil {
		t.Fatalf("moving dnsmasq: %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("the daemon transaction was meant to be forced into a rollback")
	}
	return uciGet(t, "dhcp.@dnsmasq[0].port")
}

// rollbackSpy notices the daemon restoring its backup, after which the
// replayed dnsmasq is "alive" again so the rollback itself succeeds.
type rollbackSpy struct {
	*routerShell
	mark func()
}

func (r *rollbackSpy) Run(cmd string) (string, error) {
	if strings.Contains(cmd, "cp /tmp/dhcp.curfew-rollback /etc/config/dhcp") {
		defer r.mark()
	}
	return r.routerShell.Run(cmd)
}

func TestTheDHCPLockStopsADaemonRollbackUndoingTheTakeover(t *testing.T) {
	requireRealUCI(t)
	if port := race(t); port != "54" {
		t.Fatalf("after the race dnsmasq's port is %q, not 54: a daemon rollback undid the takeover", port)
	}
	if got := uciGet(t, "dhcp.@dnsmasq[0].address"); got != "/*.lan.example.test/192.168.1.122" {
		t.Errorf("the address list changed: %q", got)
	}
	if got := uciGet(t, "dhcp.lan.dhcp_option"); !strings.Contains(got, "42,192.168.1.1") ||
		!strings.Contains(got, "6,192.168.1.1") {
		t.Errorf("the DHCP options are not what the takeover set: %q", got)
	}
}

// The control: the same race with the takeover's lock removed really does
// lose the move. Without this, the test above would pass just as happily if
// the interleaving it stages never happened.
func TestWithoutTheLockTheRaceReallyLosesTheTakeover(t *testing.T) {
	requireRealUCI(t)
	saved := lockDHCP
	lockDHCP = func(Runner) (dhcplock.Release, error) { return func() {}, nil }
	t.Cleanup(func() { lockDHCP = saved })
	if port := race(t); port == "54" {
		t.Fatal("with no lock the takeover's move survived, so the race test stages nothing")
	}
}

// Moving dnsmasq to 54 and back must not touch the lists local DNS names
// live in, byte for byte.
func TestMovingDnsmasqLeavesAddressAndServerListsAlone(t *testing.T) {
	requireRealUCI(t)
	writeRaceDHCP(t)
	want := func() string {
		out, _ := exec.Command("sh", "-c", "uci show dhcp | grep -E '\\.(address|server)='").CombinedOutput()
		return string(out)
	}
	before := want()
	if !strings.Contains(before, "address=") || !strings.Contains(before, "server=") {
		t.Fatalf("the fixture has no lists to protect:\n%s", before)
	}
	opts, err := moveDnsmasqTo54(&routerShell{}, "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := want(); got != before {
		t.Errorf("moving to 54 changed the lists:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	if err := restoreDnsmasqTo53(&routerShell{}, opts); err != nil {
		t.Fatal(err)
	}
	if got := want(); got != before {
		t.Errorf("restoring to 53 changed the lists:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}
