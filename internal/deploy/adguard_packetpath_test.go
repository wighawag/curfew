//go:build linux

package deploy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
)

// End-to-end tests for AdGuard adoption, against a REAL AdGuard.
//
// The claim being tested is a security one: an AdGuard with no admin account
// serves its whole REST API to any device on the LAN, and curfew closes that.
// A claim like this cannot be settled by checking that a file now contains a
// bcrypt hash. It is settled by asking the running server, which is what a
// child's phone would ask, and getting refused.
//
// This is the DNS-side equivalent of the packet-path rule in
// docs/adr/0004-tests-assert-on-the-packet-path.md: assert on what the thing
// actually does, not on what its configuration says.

// localRunner runs commands here rather than over ssh, so the container plays
// the part of the router. It is deliberately dumb: it shells out and reports
// what happened, and knows nothing about AdGuard.
type localRunner struct{ t *testing.T }

func (l localRunner) Run(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func (l localRunner) Upload(local, remote string) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(remote), 0o755); err != nil {
		return err
	}
	return os.WriteFile(remote, data, 0o644)
}

func (l localRunner) Download(remote, local string) error {
	data, err := os.ReadFile(remote)
	if err != nil {
		return err
	}
	return os.WriteFile(local, data, 0o644)
}

// openConfig is what legacy/scripts/setup-adguard.sh leaves on a router, plus
// a hand-made exception of the kind ADR 0002 records being destroyed by a
// reinstall.
const openConfig = `http:
  address: 127.0.0.1:3000
  session_ttl: 1h
users: []
dns:
  bind_hosts: [127.0.0.1]
  port: 53
  upstream_dns: ["127.0.0.1:5454"]
  bootstrap_dns: ["127.0.0.1:5454"]
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
  serve_plain_dns: true
  cache_size: 4194304
schema_version: 34
filters: []
whitelist_filters: []
user_rules:
- '@@||eth.limo^'
dhcp: {enabled: false}
filtering: {filtering_enabled: true, protection_enabled: true, blocking_mode: nxdomain}
`

func requireAdGuard(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(adguard.BinaryPath); err != nil {
		t.Skipf("no AdGuard at %s; run this in the test image", adguard.BinaryPath)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to write /opt and restart services")
	}
}

// placeConfig puts a config where the router keeps it and starts AdGuard on it.
func placeConfig(t *testing.T, config string) {
	t.Helper()
	_, _ = exec.Command("sh", "-c", "killall AdGuardHome 2>/dev/null").CombinedOutput()
	time.Sleep(300 * time.Millisecond)
	if err := os.MkdirAll("/opt/AdGuardHome", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adguard.ConfigPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	start(t)
	t.Cleanup(func() {
		_, _ = exec.Command("sh", "-c", "killall AdGuardHome 2>/dev/null").CombinedOutput()
		os.Remove(adguard.ConfigPath)
		os.Remove(adguard.ConfigPath + ".curfew-backup")
	})
}

func start(t *testing.T) {
	t.Helper()
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"%s -c %s -w /opt/AdGuardHome --no-check-update >/tmp/agh.log 2>&1 &",
		adguard.BinaryPath, adguard.ConfigPath))
	if err := cmd.Run(); err != nil {
		t.Fatalf("starting AdGuard: %v", err)
	}
	for range 60 {
		if resp, err := http.Get("http://127.0.0.1:3000/control/status"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	log, _ := os.ReadFile("/tmp/agh.log")
	t.Fatalf("AdGuard never came up:\n%s", log)
}

// ask makes the request a device on the LAN would make.
func ask(t *testing.T, user, pass string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:3000/control/status", nil)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// disableFiltering is the attack: turn off protection for the whole house.
func disableFiltering(t *testing.T) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:3000/control/protection",
		strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// The headline claim, asserted as an attack that stops working.
func TestAdoptingAnOpenAdGuardStopsAChildTurningFilteringOff(t *testing.T) {
	requireAdGuard(t)
	placeConfig(t, openConfig)

	// BASELINE, and it is the whole point of the test: right now, with the
	// config the legacy script writes, an unauthenticated request from
	// anywhere on the LAN turns off filtering for the household. If this ever
	// stops being true, the assertion below proves nothing.
	if code := disableFiltering(t); code != http.StatusOK {
		t.Fatalf("baseline: an open AdGuard should accept the attack, got %d", code)
	}
	t.Log("baseline confirmed: an unauthenticated request DID disable filtering")

	report, err := SetupAdGuard(localRunner{t}, AdGuardOptions{
		Enabled: true, User: "parent", Password: "hunter2", RouterIP: "127.0.0.1",
		DNSTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SetupAdGuard: %v", err)
	}
	if !report.SecuredNow {
		t.Errorf("the report must say the API was closed, got %+v", report)
	}
	if !report.Verified {
		t.Error("the report must record that it VERIFIED the result, not assumed it")
	}

	// The attack must now fail.
	if code := disableFiltering(t); code == http.StatusOK {
		t.Error("a child on the LAN can still turn off filtering for the whole house")
	}
	if code := ask(t, "", ""); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", code)
	}
	// The control, without which "secure" could just mean "broken": the right
	// password must still work.
	if code := ask(t, "parent", "hunter2"); code != http.StatusOK {
		t.Errorf("authenticated status = %d, want 200; the admin page is now unusable", code)
	}
	if code := ask(t, "parent", "wrong"); code == http.StatusOK {
		t.Error("a wrong password was accepted")
	}
}

// Adoption must not destroy what a household built up. This is the defect
// ADR 0002 recorded: a panic-off plus reinstall cycle silently discarded
// hand-made exceptions.
func TestAdoptionKeepsExistingRulesAndConfig(t *testing.T) {
	requireAdGuard(t)
	placeConfig(t, openConfig)

	if _, err := SetupAdGuard(localRunner{t}, AdGuardOptions{
		Enabled: true, User: "parent", Password: "hunter2", RouterIP: "127.0.0.1",
		DNSTimeout: 30 * time.Second,
	}); err != nil {
		t.Fatalf("SetupAdGuard: %v", err)
	}
	data, err := os.ReadFile(adguard.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "eth.limo") {
		t.Errorf("adoption destroyed a hand-made exception:\n%s", data)
	}
	if !strings.Contains(string(data), "schema_version") {
		t.Errorf("adoption destroyed unrelated settings:\n%s", data)
	}
	// And a backup was kept, because this is the one file curfew edits that
	// another program owns.
	if _, err := os.Stat(adguard.ConfigPath + ".curfew-backup"); err != nil {
		t.Errorf("no backup of the config curfew edited: %v", err)
	}
}

// An AdGuard somebody already secured must be adopted untouched, including
// keeping THEIR password rather than being reset to ours.
func TestAdoptionLeavesAnExistingLoginAlone(t *testing.T) {
	requireAdGuard(t)
	// bcrypt hash of "theirs".
	const theirs = "$2b$10$32T5BB8IatZ.k3EPYyY0cupJk3UcPHYhEHTtf9q0urb/gPVH5Hqqi"
	secured := strings.Replace(openConfig, "users: []",
		"users:\n- name: someone\n  password: "+theirs, 1)
	placeConfig(t, secured)

	// Adopting somebody's AdGuard means being given THEIR login, which is what
	// -adguard-user and -adguard-password are for.
	report, err := SetupAdGuard(localRunner{t}, AdGuardOptions{
		Enabled: true, User: "someone", Password: "theirs", RouterIP: "127.0.0.1",
		DNSTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("SetupAdGuard: %v", err)
	}
	if report.SecuredNow {
		t.Error("curfew changed authentication on an AdGuard that already had it")
	}
	if !report.AlreadySecured {
		t.Errorf("the report should say it found an existing account, got %+v", report)
	}
	data, _ := os.ReadFile(adguard.ConfigPath)
	if !strings.Contains(string(data), "name: someone") {
		t.Errorf("the household's own login was replaced:\n%s", data)
	}
	if strings.Contains(string(data), "name: parent") {
		t.Errorf("curfew added its own account to an AdGuard that already had one:\n%s", data)
	}
	if !report.Verified {
		t.Error("adoption must still verify the credentials it was given actually work")
	}
}

// -no-adguard must mean exactly that: nothing is read, nothing is written.
func TestNoAdGuardTouchesNothing(t *testing.T) {
	requireAdGuard(t)
	placeConfig(t, openConfig)
	before, _ := os.ReadFile(adguard.ConfigPath)

	report, err := SetupAdGuard(localRunner{t}, AdGuardOptions{Enabled: false})
	if err != nil {
		t.Fatalf("SetupAdGuard: %v", err)
	}
	if !report.Skipped {
		t.Errorf("want a skipped report, got %+v", report)
	}
	after, _ := os.ReadFile(adguard.ConfigPath)
	if string(before) != string(after) {
		t.Error("-no-adguard modified the config anyway")
	}
}

// A missing password must be refused before anything is touched, because the
// whole operation exists to stop AdGuard being unauthenticated.
func TestSetupRefusesAnEmptyPassword(t *testing.T) {
	requireAdGuard(t)
	placeConfig(t, openConfig)
	before, _ := os.ReadFile(adguard.ConfigPath)

	if _, err := SetupAdGuard(localRunner{t}, AdGuardOptions{Enabled: true, User: "parent"}); err == nil {
		t.Fatal("an empty AdGuard password must be refused")
	}
	after, _ := os.ReadFile(adguard.ConfigPath)
	if string(before) != string(after) {
		t.Error("a refused setup modified the config anyway")
	}
}

// Verification must FAIL when the server is still open, rather than reporting
// success because the file looks right. This is the difference between
// checking a config and checking a system.
func TestVerificationCatchesAServerThatDidNotReload(t *testing.T) {
	requireAdGuard(t)
	placeConfig(t, openConfig)

	// Edit the file exactly as adoption does, but do NOT restart AdGuard, so
	// the running server is still open while the config says otherwise.
	hash, err := adguard.HashPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(adguard.ConfigPath)
	edited, changed, err := adguard.EnsureUser(data, "parent", hash)
	if err != nil || !changed {
		t.Fatalf("EnsureUser: %v changed=%v", err, changed)
	}
	os.WriteFile(adguard.ConfigPath, edited, 0o644)

	var report AdGuardReport
	err = verifyAdGuard(localRunner{t}, AdGuardOptions{User: "parent", Password: "hunter2"}, &report)
	if err == nil {
		t.Error("verification passed against a server that is still answering everyone")
	}
	if report.Verified {
		t.Error("the report claims verification succeeded")
	}
}
