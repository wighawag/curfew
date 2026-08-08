//go:build linux

package adguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Applying a category change against a REAL AdGuard, asserted on the DNS path.
//
// The claim is not "the config file changed": that is settled by the unit
// tests. The claim here is that the household's resolver is answering
// differently afterwards and is still answering at all, which is the only form
// of "it worked" worth having, and it is what a config edit plus a restart can
// get wrong in ways no amount of string comparison would notice.

func requireAdGuard(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(BinaryPath); err != nil {
		t.Skipf("no AdGuard at %s; run this in the test image", BinaryPath)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to write /opt and drive services")
	}
}

func sh(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

// localRunner is the real shell, which is what the daemon uses on the router.
type localRunner struct{ ran []string }

func (l *localRunner) Run(cmd string) (string, error) {
	l.ran = append(l.ran, cmd)
	return sh(cmd)
}

// resolverProbe is the real thing the daemon uses: it asks the resolver.
type resolverProbe struct{}

func (resolverProbe) Serving() bool { return resolves("curfew-probe.invalid") != "timeout" }

// resolves sends a real query to 127.0.0.1:53 and says what came back.
func resolves(name string) string {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", "127.0.0.1:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := res.LookupHost(ctx, name)
	if err == nil {
		return "resolved:" + strings.Join(addrs, ",")
	}
	var dnsErr *net.DNSError
	if ok := asDNSError(err, &dnsErr); ok && !dnsErr.IsTimeout && !dnsErr.IsTemporary {
		return "blocked"
	}
	return "timeout"
}

func asDNSError(err error, target **net.DNSError) bool {
	e, ok := err.(*net.DNSError)
	if ok {
		*target = e
	}
	return ok
}

// startAdGuardWith brings up a real AdGuard on a config, through an init
// script at the path curfew's own code drives, so the sequence under test is
// the sequence that runs on the router.
func startAdGuardWith(t *testing.T, config string) {
	t.Helper()
	_, _ = sh("killall AdGuardHome dnsmasq 2>/dev/null")
	time.Sleep(300 * time.Millisecond)

	// An offline fixture upstream, so a name that resolves proves a rule was
	// NOT applied rather than proving the internet is reachable.
	// EVERY name the test asks about is answered here, including the ones a
	// filter list is expected to block. That is what makes "blocked" mean the
	// list did it: with an upstream that had no answer either, a control
	// asserting a name is still blocked would pass with no list loaded at all,
	// and a mutation that deleted the household's own list would go unnoticed.
	// It did, until this line was fixed.
	if out, err := sh("dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces " +
		"--listen-address=127.0.0.1 --address=/blocked.example/10.9.9.9 " +
		"--address=/theirs.example/10.9.9.7 " +
		"--address=/allowed.example/10.9.9.8"); err != nil {
		t.Fatalf("fixture upstream: %s %v", out, err)
	}
	if err := os.MkdirAll("/opt/AdGuardHome", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	// A plain init script rather than procd's: the container has no procd
	// supervising anything, and what is under test is curfew's own sequence
	// (stop, write, start, prove it is serving, roll back if it is not), not
	// OpenWrt's service manager.
	// Every verb the real init script has, RESTART INCLUDED. Leaving that one
	// out cost an hour: these test binaries share one container, and a later
	// one drives `/etc/init.d/adguardhome restart` through the adoption path.
	// A script that silently exits 0 on a verb it does not implement made that
	// test fail with a message about AdGuard not picking up its config, which
	// is a true statement about a fault this file caused.
	script := fmt.Sprintf(`#!/bin/sh
start() { %s -c %s -w /opt/AdGuardHome --no-check-update >>/tmp/agh-apply.log 2>&1 & }
stop() { killall AdGuardHome 2>/dev/null; sleep 1; }
case "$1" in
  start) start ;;
  stop) stop ;;
  restart|reload) stop; start ;;
  enable|disable) ;;
  *) echo "unknown verb: $1" >&2; exit 1 ;;
esac
exit 0
`, BinaryPath, ConfigPath)
	if err := os.MkdirAll("/etc/init.d", 0o755); err != nil {
		t.Fatal(err)
	}
	previous, hadPrevious := os.ReadFile("/etc/init.d/adguardhome")
	if err := os.WriteFile("/etc/init.d/adguardhome", []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sh("killall AdGuardHome dnsmasq 2>/dev/null")
		os.Remove(ConfigPath)
		os.Remove(ConfigPath + backupSuffix)
		// Put the container back as it was found. These binaries share one
		// machine, and a fixture left lying around is a failure charged to
		// whichever test runs next.
		if hadPrevious == nil {
			_ = os.WriteFile("/etc/init.d/adguardhome", previous, 0o755)
		} else {
			os.Remove("/etc/init.d/adguardhome")
		}
	})

	if _, err := sh("/etc/init.d/adguardhome start"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if resolves("allowed.example") != "timeout" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	log, _ := os.ReadFile("/tmp/agh-apply.log")
	t.Fatalf("AdGuard never served DNS:\n%s", log)
}

// seedFilterCache writes the rule text AdGuard keeps for each subscribed list,
// named after the list's id, which is where AdGuard reads its rules from at
// startup.
//
// Without this the test would be measuring AdGuard's DOWNLOAD schedule rather
// than curfew's edit: a config naming a URL it has never fetched carries no
// rules until an update runs, so nothing would be filtered and the baseline
// would be meaningless. On the live router these files are exactly what is
// present, which is why seeding them is the faithful setup rather than a
// convenience.
func seedFilterCache(t *testing.T, byID map[int]string) {
	t.Helper()
	if err := os.MkdirAll("/opt/AdGuardHome/data/filters", 0o755); err != nil {
		t.Fatal(err)
	}
	for id, body := range byID {
		path := fmt.Sprintf("/opt/AdGuardHome/data/filters/%d.txt", id)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(path) })
	}
}

// applyConfig is a real AdGuard config carrying a category list that blocks a
// name the fixture upstream would otherwise answer, plus a list of the
// household's own that must survive.
func applyConfig(t *testing.T, categoryList, householdList string) string {
	t.Helper()
	return fmt.Sprintf(`http:
  address: 0.0.0.0:3000
  session_ttl: 720h
users:
- name: parent
  password: $2a$10$.6bIAEMTEJaj5v0.XcVKu.75uMSX5Bt9JWmgR/7rwyVfqBSPod4u6
dns:
  bind_hosts:
  - 127.0.0.1
  port: 53
  upstream_dns:
  - 127.0.0.1:5454
  bootstrap_dns:
  - 127.0.0.1:5454
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
  serve_plain_dns: true
schema_version: 34
filters:
  - enabled: true
    url: %s
    name: Malware
    id: 3
  - enabled: true
    url: %s
    name: The household's own list
    id: 99
whitelist_filters: []
user_rules:
- '@@||handwritten.example^'
dhcp:
  enabled: false
filtering:
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
`, categoryList, householdList)
}

// THE test: removing a category must actually stop that list filtering, and
// must leave the household with a working resolver and its own list intact.
func TestApplyingACategoryRemovalChangesWhatTheResolverAnswers(t *testing.T) {
	requireAdGuard(t)

	// The lists are served over HTTP by the test, so it needs no internet and
	// the 56 MB original is not downloaded. The catalogue is pointed at that
	// server, which means the ownership rule under test is the REAL one:
	// CategoryURL("Malware") is what ends up in the config.
	const catRules = "! Title: pretend malware list\n||blocked.example^\n"
	const houseRules = "! Title: the household's own\n||theirs.example^\n"
	catURL, houseURL := serveLists(t, catRules, houseRules)
	seedFilterCache(t, map[int]string{3: catRules, 99: houseRules})

	startAdGuardWith(t, applyConfig(t, catURL, houseURL))

	// BASELINE: the category list really is filtering, and the household's own
	// list really is too. Without both, everything below proves nothing.
	if got := resolves("blocked.example"); got != "blocked" {
		t.Fatalf("baseline: the category list is not in force, got %s", got)
	}
	if got := resolves("theirs.example"); got != "blocked" {
		t.Fatalf("baseline: the household's own list is not in force, got %s", got)
	}
	if got := resolves("allowed.example"); !strings.HasPrefix(got, "resolved") {
		t.Fatalf("baseline: the fixture upstream is not answering, got %s", got)
	}

	r := &localRunner{}
	report, err := ApplyCategories(r, resolverProbe{}, ConfigPath, nil, 90*time.Second)
	if err != nil {
		t.Fatalf("ApplyCategories: %v", err)
	}
	if !report.Changed || len(report.Removed) != 1 || report.Removed[0] != "Malware" {
		t.Fatalf("the report does not describe the change: %+v", report)
	}

	// THE ASSERTION: the resolver answers differently now.
	if got := resolves("blocked.example"); !strings.HasPrefix(got, "resolved") {
		t.Errorf("the category was removed but its rules are still filtering: %s", got)
	}
	// CONTROLS: the household keeps everything that was not curfew's to take.
	if got := resolves("theirs.example"); got != "blocked" {
		t.Errorf("removing a category also removed the household's own list: %s", got)
	}
	if got := resolves("allowed.example"); !strings.HasPrefix(got, "resolved") {
		t.Errorf("the resolver is not answering ordinary queries after the restart: %s", got)
	}
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "handwritten.example") {
		t.Errorf("the household's own custom rule was destroyed:\n%s", data)
	}
	// The downtime is measured, since the settings page quotes it to a person.
	t.Logf("DNS was down for %s", report.Downtime.Round(time.Second))
	if report.Downtime <= 0 {
		t.Error("no downtime was measured, so the page would quote a meaningless number")
	}
}

// A config AdGuard will not start on must be rolled back, and the household
// must end up with a working resolver rather than a broken one and a message.
func TestAConfigAdGuardRefusesLeavesTheHouseholdResolvingAgain(t *testing.T) {
	requireAdGuard(t)

	const catRules = "! Title: pretend\n||blocked.example^\n"
	const houseRules = "! Title: theirs\n||theirs.example^\n"
	catURL, houseURL := serveLists(t, catRules, houseRules)
	seedFilterCache(t, map[int]string{3: catRules, 99: houseRules})

	startAdGuardWith(t, applyConfig(t, catURL, houseURL))
	if got := resolves("allowed.example"); !strings.HasPrefix(got, "resolved") {
		t.Fatalf("baseline: no working resolver to begin with, got %s", got)
	}

	// Sabotage the start so the new config cannot come up, which is what a
	// config AdGuard rejects looks like from curfew's side: the service is
	// started, it does not serve, and nothing else says why.
	if err := os.WriteFile("/etc/init.d/adguardhome",
		[]byte("#!/bin/sh\ncase \"$1\" in stop) killall AdGuardHome 2>/dev/null; sleep 1;; esac\nexit 0\n"),
		0o755); err != nil {
		t.Fatal(err)
	}

	r := &localRunner{}
	_, err := ApplyCategories(r, resolverProbe{}, ConfigPath, nil, 3*time.Second)
	if err == nil {
		t.Fatal("AdGuard never came back and the caller was told it was fine")
	}
	// The previous config is back on disk, ready for the next start.
	data, readErr := os.ReadFile(ConfigPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(data), "name: Malware") {
		t.Errorf("the previous config was not restored:\n%s", data)
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Errorf("the error does not say what state things are in: %v", err)
	}
}

// serveLists publishes a category list and a household list over HTTP, and
// points curfew's catalogue at the first, so CategoryURL("Malware") really is
// the URL in the config under test.
func serveLists(t *testing.T, category, household string) (catURL, houseURL string) {
	t.Helper()
	cat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(category))
	}))
	house := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(household))
	}))
	old := CategorySource
	CategorySource = cat.URL + "/"
	t.Cleanup(func() {
		CategorySource = old
		cat.Close()
		house.Close()
	})
	return CategoryURL("Malware"), house.URL + "/theirs.txt"
}
