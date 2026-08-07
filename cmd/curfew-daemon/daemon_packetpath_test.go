//go:build linux

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/netnstest"
)

// The daemon's own boot path, end to end, with a real packet.
//
// Everything below this file is proven elsewhere: internal/policy proves that
// a manual block read off disk produces a blocking ruleset, and
// internal/enforce proves the ruleset drops the packet. What NOTHING else
// covers is this binary's startup order, and that is exactly where the system
// being replaced failed: it came up, reported success, and enforced nothing.
// A reordering here that served the page before applying the ruleset, or that
// skipped reading the state file, would pass every other test in the repo.

// daemonBinary finds the binary the acceptance runner cross-built.
func daemonBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{".acceptance/curfew-daemon", "../../.acceptance/curfew-daemon"} {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skip("no built daemon at .acceptance/curfew-daemon; run ./docker/acceptance.sh")
	return ""
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestDaemonEnforcesAPersistedManualBlockBeforeItServes starts the daemon the
// way procd does, against a state file that says a profile is blocked, and
// sends a packet.
func TestDaemonEnforcesAPersistedManualBlockBeforeItServes(t *testing.T) {
	net := netnstest.Require(t)
	bin := daemonBinary(t)

	const blocked = "aa:bb:cc:dd:ee:01"
	const free = "aa:bb:cc:dd:ee:03"
	dir := t.TempDir()
	regPath := filepath.Join(dir, "devices.json")
	profPath := filepath.Join(dir, "profiles.json")
	statePath := filepath.Join(dir, "state.json")

	write(t, regPath, fmt.Sprintf(`{"devices":[{"mac":%q},{"mac":%q}]}`, blocked, free))
	write(t, profPath, fmt.Sprintf(
		`{"profiles":[{"name":"eli","devices":[%q],"windows":[]},{"name":"dad","devices":[%q],"windows":[]}]}`,
		blocked, free))
	// The state a parent left behind before the power cut.
	write(t, statePath, `{"manual_blocked":["eli"]}`)

	cmd := exec.Command(bin,
		"-registry", regPath, "-profiles", profPath, "-state", statePath,
		"-lan", netnstest.LANIf, "-wan", netnstest.WANIf,
		"-listen", "127.0.0.1:18080", "-user", "parent", "-password", "hunter2",
		"-timezone", "UTC", "-reconcile", "2s")
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Probe with Go's own HTTP client rather than wget. busybox wget exits
	// non-zero on the 401 this page correctly returns, and uclient-fetch does
	// not replay a request body after a challenge, so a shell probe here would
	// be measuring the fetcher rather than the daemon.
	status := func(path, user, pass string) int {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18080"+path, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Wait for it to be serving, which it does only AFTER applying the
	// ruleset. If it never gets there, say what it said rather than timing out
	// silently.
	up := false
	for range 50 {
		if status("/", "", "") != 0 {
			up = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !up {
		t.Fatalf("the daemon never started serving. Its output was:\n%s", out.String())
	}

	net.SetClientMAC(blocked)
	if net.Reaches() {
		t.Error("the daemon came up and left a manually blocked profile online: " +
			"a power cut at bedtime would silently grant internet")
	}
	// Control: the profile nobody blocked must be online, so the drop above is
	// the manual block rather than a daemon that blocks everything.
	net.SetClientMAC(free)
	if !net.Reaches() {
		t.Errorf("an unblocked profile lost its internet. The daemon said:\n%s", out.String())
	}

	// And the page it serves is password-gated, which is the other half of
	// stopping a child freeing themselves: this page is reachable BY the
	// device being blocked, because blocking acts on forwarded traffic.
	if got := status("/", "", ""); got != http.StatusUnauthorized {
		t.Errorf("the home page answered an unauthenticated request with %d, want 401", got)
	}
	// The control, without which a server that rejects EVERYTHING would pass
	// as secure.
	if got := status("/", "parent", "hunter2"); got != http.StatusOK {
		t.Errorf("an authenticated request got %d, want 200", got)
	}
}
