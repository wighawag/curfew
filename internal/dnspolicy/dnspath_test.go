//go:build linux

package dnspolicy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
	"github.com/wighawag/curfew/internal/shellrun"
)

// End-to-end tests for per-profile, time-windowed DNS restrictions, against a
// REAL AdGuard.
//
// This is the DNS-side equivalent of the packet-path rule in
// docs/adr/0004-tests-assert-on-the-packet-path.md. A claim that a profile is
// restricted is only credible if a real query FROM THAT CLIENT'S ADDRESS was
// sent and the answer observed. Nothing here inspects a filter list, a client
// object or a config file to decide whether it worked.
//
// What is real: AdGuard, the DNS queries and their source addresses, the HTTP
// server curfew serves its filter list from, uci and the static lease writing,
// and the dnsmasq lease file. What is REPLAYED: the IPv6 neighbour table,
// because an address in the kernel's neighbour table is by definition NOT a
// local address, so it could not also be the source of a query. Its parsing is
// pinned separately against real router output in internal/lanhosts.
//
// The upstream is an offline fixture on another port, exactly as
// legacy/test/adguard.bats argues: against a real upstream an unreachable name
// returns NXDOMAIN anyway, so a broken filter would read identically to a
// working one.

const (
	aghAPI = "127.0.0.1:3000"
	aghPwd = "hunter2"
	// bcrypt of "hunter2".
	aghHash = "$2a$10$.6bIAEMTEJaj5v0.XcVKu.75uMSX5Bt9JWmgR/7rwyVfqBSPod4u6"

	// The DNS server address AdGuard binds for IPv6, and the client addresses
	// queries genuinely come from.
	v6Server = "fd00:c0ff:ee::1"
	v6EliA   = "fd00:c0ff:ee::a1" // eli's phone, over IPv6
	v6EliB   = "fd00:c0ff:ee::a2" // eli's laptop, over IPv6
	v6Tia    = "fd00:c0ff:ee::b1" // the CONTROL profile, over IPv6

	v4Server = "127.0.0.1"
	v4Eli    = "127.0.0.2" // eli's phone, over IPv4
	v4Tia    = "127.0.0.3" // the control profile, over IPv4

	macEliPhone  = "14:e0:1d:6a:9c:6c"
	macEliLaptop = "04:92:26:1e:6b:55"
	macTia       = "f0:d7:aa:da:66:35"
)

func sh(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func requireAdGuard(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(adguard.BinaryPath); err != nil {
		t.Skipf("no AdGuard at %s; run this in the test image", adguard.BinaryPath)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to add addresses and write /opt")
	}
}

// resolveFrom sends a real DNS query from a chosen source address.
func resolveFrom(src, dst, name string) (string, error) {
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second, LocalAddr: &net.UDPAddr{IP: net.ParseIP(src)}}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dst, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := res.LookupHost(ctx, name)
	if err != nil {
		return "", err
	}
	return strings.Join(addrs, ","), nil
}

// blocked reports whether a name is filtered for this source address.
//
// It retries briefly. The single query is the evidence; the retry is only
// there because a UDP query on a loopback-heavy container occasionally times
// out, and a timeout is neither "blocked" nor "resolved". A timeout that never
// resolves is reported as an error by the caller rather than counted as a
// block, which is the distinction that stops a broken rig reading as a perfect
// filter.
func lookupVerdict(t *testing.T, src, dst, name string) string {
	t.Helper()
	var lastErr error
	for range 6 {
		got, err := resolveFrom(src, dst, name)
		if err == nil {
			return "RESOLVED:" + got
		}
		lastErr = err
		if strings.Contains(err.Error(), "no such host") {
			return "BLOCKED"
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "ERROR:" + lastErr.Error()
}

func mustResolve(t *testing.T, what, src, dst, name string) {
	t.Helper()
	if v := lookupVerdict(t, src, dst, name); !strings.HasPrefix(v, "RESOLVED") {
		t.Errorf("%s: %s from %s should RESOLVE, got %s", what, name, src, v)
	}
}

func mustBlock(t *testing.T, what, src, dst, name string) {
	t.Helper()
	if v := lookupVerdict(t, src, dst, name); v != "BLOCKED" {
		t.Errorf("%s: %s from %s should be BLOCKED, got %s", what, name, src, v)
	}
}

// startAdGuard brings up a real AdGuard over an offline fixture upstream.
func startAdGuard(t *testing.T) {
	t.Helper()
	_, _ = sh("killall AdGuardHome dnsmasq 2>/dev/null")
	time.Sleep(300 * time.Millisecond)

	for _, a := range []string{v6Server, v6EliA, v6EliB, v6Tia} {
		_, _ = sh("ip -6 addr add " + a + "/128 dev lo 2>/dev/null")
	}
	for _, a := range []string{v4Eli, v4Tia} {
		_, _ = sh("ip addr add " + a + "/8 dev lo 2>/dev/null")
	}

	if out, err := sh("dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces " +
		"--listen-address=127.0.0.1 --address=/twitch.tv/10.9.9.9 " +
		"--address=/homework.example/10.9.9.8 --address=/youtube.com/10.9.9.7 " +
		"--address=/use-application-dns.net/10.9.9.6 --address=/cloudflare-dns.com/10.9.9.5 " +
		"--address=/opensea.io/10.9.9.4"); err != nil {
		t.Fatalf("fixture upstream: %s %v", out, err)
	}

	conf := fmt.Sprintf(`http:
  address: 0.0.0.0:3000
  session_ttl: 720h
users:
- name: parent
  password: %s
dns:
  bind_hosts:
  - 127.0.0.1
  - %s
  port: 53
  upstream_dns:
  - 127.0.0.1:5454
  bootstrap_dns:
  - 127.0.0.1:5454
  filtering_enabled: true
  protection_enabled: true
  cache_size: 4194304
  blocking_mode: nxdomain
  serve_plain_dns: true
schema_version: 34
filters: []
whitelist_filters: []
user_rules:
- '@@||handwritten.example^'
dhcp:
  enabled: false
clients:
  runtime_sources:
    whois: false
    arp: false
    rdns: false
    dhcp: false
    hosts: false
  persistent:
  - name: Dad laptop
    ids:
    - 127.0.0.9
    use_global_settings: true
    use_global_blocked_services: true
    filtering_enabled: true
filtering:
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
`, aghHash, v6Server)
	if err := os.MkdirAll("/opt/AdGuardHome", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adguard.ConfigPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh(fmt.Sprintf("%s -c %s -w /opt/AdGuardHome --no-check-update >/tmp/agh-dns.log 2>&1 &",
		adguard.BinaryPath, adguard.ConfigPath)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sh("killall AdGuardHome dnsmasq 2>/dev/null")
		os.Remove(adguard.ConfigPath)
	})

	// AdGuard serves its admin API about two seconds after starting and only
	// attempts the DNS bind about forty-three seconds later on a real router,
	// so waiting for the API is NOT waiting for DNS. Wait for a real answer.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := resolveFrom(v6EliA, v6Server, "twitch.tv"); err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	log, _ := os.ReadFile("/tmp/agh-dns.log")
	t.Fatalf("AdGuard never answered DNS:\n%s", log)
}

// replayingRunner passes uci and everything else through to the real shell,
// and answers ONLY the IPv6 neighbour query from a fixture.
//
// It is deliberately dumb: it matches on the command text and returns a canned
// string that came off the live router. It encodes no rule about addresses,
// ownership or restrictions, so it cannot agree with a broken implementation.
type replayingRunner struct {
	neigh string
	ran   []string
}

func (r *replayingRunner) Run(cmd string) (string, error) {
	r.ran = append(r.ran, cmd)
	if strings.Contains(cmd, "ip -6 neigh") {
		return r.neigh, nil
	}
	return shellrun.Local{}.Run(cmd)
}

// eliAndTia is the worked example plus its control. eli gets no streaming
// between 08:00 and 10:00; tia has restrictions configured but on a window
// that is never open during this test, so she is the second client that must
// keep resolving while eli is blocked.
func eliAndTia() *schedule.Profiles {
	return &schedule.Profiles{
		Profiles: []schedule.Profile{
			{
				Name:    "eli",
				Devices: []string{macEliPhone, macEliLaptop},
				Restrictions: []schedule.Restriction{{
					Name:     "no streaming",
					Services: []string{"youtube"},
					Lists:    []string{"no_streaming"},
					Windows:  []schedule.Window{{Days: schedule.AllDays, Start: "08:00", End: "10:00"}},
				}},
			},
			{
				Name:    "tia",
				Devices: []string{macTia},
				Restrictions: []schedule.Restriction{{
					Name:     "no streaming",
					Services: []string{"youtube"},
					Lists:    []string{"no_streaming"},
					Windows:  []schedule.Window{{Days: schedule.AllDays, Start: "03:00", End: "04:00"}},
				}},
			},
		},
		BlockLists: map[string][]string{"no_streaming": {"twitch.tv"}},
	}
}

type memRegistry struct{ reg *registry.Registry }

func (m memRegistry) Load() (*registry.Registry, error) { return m.reg, nil }

type memSchedule struct{ ps *schedule.Profiles }

func (m memSchedule) Load() (*schedule.Profiles, error) { return m.ps, nil }

// newManagerUnderTest wires a Manager to the real AdGuard, with the clock and
// the LAN observation under the test's control.
func newManagerUnderTest(t *testing.T) (*Manager, *httptest.Server) {
	t.Helper()

	// A real dnsmasq lease file: this is the ONLY source of IPv4 identity.
	leaseFile := t.TempDir() + "/dhcp.leases"
	if err := os.WriteFile(leaseFile, []byte(fmt.Sprintf(
		"1786220000 %s %s * *\n1786220001 %s %s * *\n",
		macEliPhone, v4Eli, macTia, v4Tia)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Real neighbour-table output, in the router's own format. eli's laptop
	// appears here with NO IPv4 lease above, which is the measured real case
	// on the live router.
	neigh := fmt.Sprintf(""+
		"%s lladdr %s used 0/0/0 probes 1 STALE\n"+
		"%s lladdr %s used 0/0/0 probes 1 STALE\n"+
		"%s lladdr %s used 0/0/0 probes 1 STALE\n"+
		"fd00:c0ff:ee::dead  used 0/0/0 probes 3 FAILED\n",
		v6EliA, macEliPhone, v6EliB, macEliLaptop, v6Tia, macTia)

	runner := &replayingRunner{neigh: neigh}

	var m *Manager
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, m.FilterList())
	}))
	t.Cleanup(list.Close)

	m = NewManager(Config{
		Registry: memRegistry{&registry.Registry{Devices: []registry.Device{
			{MAC: macEliPhone, Name: "eli phone"},
			{MAC: macEliLaptop, Name: "eli laptop"},
			{MAC: macTia, Name: "tia phone"},
		}}},
		Schedule:     memSchedule{eliAndTia()},
		Runner:       runner,
		API:          adguard.NewClient(aghAPI, "parent", aghPwd),
		ListURL:      list.URL + FilterListPath,
		LANInterface: "br-lan",
		LeasePath:    leaseFile,
		Location:     time.UTC,
	})
	return m, list
}

func atClock(hhmm string) time.Time {
	t, err := time.Parse("2006-01-02 15:04 MST", "2026-08-10 "+hhmm+" UTC")
	if err != nil {
		panic(err)
	}
	return t
}

// THE test. A restriction is only real if a query from the child's own address
// is actually refused, and only correct if it lifts again afterwards.
func TestARestrictionAppliesInsideItsWindowOverBothAddressFamilies(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	m, _ := newManagerUnderTest(t)

	// BASELINE. Everything resolves before any restriction exists. Without
	// this, a broken rig or a dead upstream would make every assertion below
	// pass while testing nothing.
	mustResolve(t, "baseline", v4Eli, v4Server, "twitch.tv")
	mustResolve(t, "baseline", v6EliA, v6Server, "twitch.tv")
	mustResolve(t, "baseline", v6EliB, v6Server, "twitch.tv")
	mustResolve(t, "baseline", v6Tia, v6Server, "twitch.tv")
	mustResolve(t, "baseline", v6EliA, v6Server, "youtube.com")
	mustResolve(t, "baseline", v6EliA, v6Server, "homework.example")
	t.Log("baseline confirmed: nothing is filtered yet")

	// Move into eli's no-streaming window and reconcile.
	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick inside the window: %v", err)
	}

	// The custom domain list, over BOTH families. More than half of this
	// household's real DNS queries arrive over IPv6, so an IPv4-only rule
	// would look built and do nothing.
	mustBlock(t, "custom list over IPv4", v4Eli, v4Server, "twitch.tv")
	mustBlock(t, "custom list over IPv6", v6EliA, v6Server, "twitch.tv")
	// The device with NO IPv4 lease at all, reachable only by IPv6. This is
	// the case that would silently escape a design keyed to leases alone.
	mustBlock(t, "device with no IPv4 lease", v6EliB, v6Server, "twitch.tv")

	// AdGuard's built-in service catalogue, the preferred source.
	mustBlock(t, "catalogue service", v6EliA, v6Server, "youtube.com")

	// CONTROLS. Without these, a rule that blocked everything would pass every
	// assertion above.
	mustResolve(t, "control: another profile", v6Tia, v6Server, "twitch.tv")
	mustResolve(t, "control: another profile", v4Tia, v4Server, "youtube.com")
	mustResolve(t, "control: another domain", v6EliA, v6Server, "homework.example")

	// Now leave the window. A restriction that never lifts is as wrong as one
	// that never applies, and this direction is the one a suite forgets.
	m.now = func() time.Time { return atClock("11:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick outside the window: %v", err)
	}
	mustResolve(t, "after the window", v4Eli, v4Server, "twitch.tv")
	mustResolve(t, "after the window", v6EliA, v6Server, "twitch.tv")
	mustResolve(t, "after the window", v6EliB, v6Server, "twitch.tv")
	mustResolve(t, "after the window", v6EliA, v6Server, "youtube.com")
}

// curfew must own only its own AdGuard objects. A household's own client, its
// own filter list and its own custom rules must all survive a reconcile.
func TestReconcileLeavesTheHouseholdsOwnAdGuardAlone(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	api := adguard.NewClient(aghAPI, "parent", aghPwd)

	// The household's own client comes from AdGuard's own config, which is
	// how it would really be there: somebody set it up in the UI. Confirm it
	// IS there first, or the survival assertion below proves nothing.
	before, err := api.Clients()
	if err != nil {
		t.Fatal(err)
	}
	if !hasClient(before, "Dad laptop") {
		t.Fatalf("baseline: the household's own client is not present to begin with: %+v", before)
	}

	m, _ := newManagerUnderTest(t)
	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	clients, err := api.Clients()
	if err != nil {
		t.Fatal(err)
	}
	if !hasClient(clients, "Dad laptop") {
		t.Error("curfew DELETED the household's own AdGuard client")
	}
	for _, c := range clients {
		if c.Name == "Dad laptop" && (len(c.IDs) != 1 || c.IDs[0] != "127.0.0.9") {
			t.Errorf("the household's own client was modified: %+v", c)
		}
	}
	// The control: curfew did do its own work, so this is not passing because
	// the reconcile did nothing at all.
	if !hasClient(clients, "curfew-eli") {
		t.Errorf("curfew's own client was never created: %+v", clients)
	}

	// The household's hand-written exception must survive, in the running
	// server and in the file AdGuard owns.
	data, err := os.ReadFile(adguard.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "handwritten.example") {
		t.Errorf("a hand-written custom rule was destroyed:\n%s", data)
	}
}

// Running twice with nothing changed must write nothing at all. Without this,
// a reconcile that rewrote its objects every minute would look identical from
// outside while hammering AdGuard and re-fetching the list all day.
func TestASecondTickWithNothingChangedWritesNothing(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	m, _ := newManagerUnderTest(t)
	m.now = func() time.Time { return atClock("09:00") }

	if err := m.Tick(); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if !m.LastReport().Changed() {
		t.Fatal("the first tick should have created curfew's objects")
	}
	if err := m.Tick(); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if r := m.LastReport(); r.Changed() {
		t.Errorf("a converged system was written to anyway: %+v", r)
	}
}

// disableFilter switches a subscribed list off through AdGuard's own API,
// without going through the code under test.
func disableFilter(t *testing.T, url string) {
	t.Helper()
	body := fmt.Sprintf(`{"url":%q,"whitelist":false,"data":{"name":%q,"url":%q,"enabled":false}}`,
		url, adguard.FilterListName, url)
	req, err := http.NewRequest(http.MethodPost,
		"http://"+aghAPI+"/control/filtering/set_url", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("parent", aghPwd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("disabling %s: HTTP %d: %s", url, resp.StatusCode, out)
	}
}

func hasClient(clients []adguard.ClientObject, name string) bool {
	for _, c := range clients {
		if c.Name == name {
			return true
		}
	}
	return false
}

// The DoH bootstrap block, on the DNS path. Asserted the same way as
// everything else: a real query from the child's own address, with a baseline
// and a control, rather than a look at the generated list.
func TestDoHEndpointsAreUnresolvableForARestrictedChild(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	m, _ := newManagerUnderTest(t)

	// BASELINE. The fixture upstream answers this, so it resolves until a rule
	// exists. Without it the assertions below would pass against a resolver
	// that simply cannot reach anything.
	mustResolve(t, "baseline", v6EliA, v6Server, "cloudflare-dns.com")
	mustResolve(t, "baseline", v6Tia, v6Server, "cloudflare-dns.com")

	// MEASURED, and not a curfew claim: AdGuard blocks Firefox's canary
	// domain ITSELF, out of the box, with no rule from anyone. Recorded here
	// because it is the opposite of what the code comment in doh.go would lead
	// you to assume, and because it means curfew's own canary entry is
	// belt-and-braces rather than the load-bearing part.
	if v := lookupVerdict(t, v6EliA, v6Server, "use-application-dns.net"); v != "BLOCKED" {
		t.Errorf("AdGuard no longer blocks the Firefox canary by itself (got %s); "+
			"curfew's own rule now carries that on its own, which is fine, but the "+
			"comment in doh.go should be corrected", v)
	}

	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	mustBlock(t, "DoH endpoint over IPv6", v6EliA, v6Server, "cloudflare-dns.com")
	mustBlock(t, "DoH endpoint over IPv4", v4Eli, v4Server, "cloudflare-dns.com")
	// A subdomain, which is what a browser preset actually uses. The rule is
	// written against the base domain and must cover it.
	mustBlock(t, "DoH endpoint subdomain", v6EliA, v6Server, "mozilla.cloudflare-dns.com")

	// CONTROL: tia's restriction window is closed, but the DoH block is not
	// window-gated, so she is blocked too. What must still resolve is an
	// ordinary domain, and a profile that is not restricted at all.
	mustResolve(t, "control: an ordinary domain", v6EliA, v6Server, "homework.example")

	// And leaving the window must NOT lift the DoH block, or a child could
	// set up DoH at 11:00 and use it at 09:00 tomorrow.
	m.now = func() time.Time { return atClock("11:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	mustResolve(t, "after the window", v6EliA, v6Server, "twitch.tv")
	mustBlock(t, "DoH stays blocked after the window", v6EliA, v6Server, "cloudflare-dns.com")
}

// A household with NO restrictions must not get a filter list at all.
//
// Two live faults sit behind this. AdGuard REFUSES a list containing no rules
// ("invalid (maybe it points to blank page?)"), so curfew logged a failure
// every minute for hours and the DNS half never started. And registering a
// list at all forces AdGuard to rebuild its whole filtering engine, which on
// the real router took it from 555 MB to 883 MB on a 1010 MB box with no swap
// and got it OOM-killed, taking the household's DNS with it. A list that says
// nothing is not worth either.
func TestAHouseholdWithNoRestrictionsGetsNoFilterListAtAll(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)

	m, _ := newManagerUnderTest(t)
	m.schedule = memSchedule{&schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{macEliPhone}},
	}}}
	m.now = func() time.Time { return atClock("09:00") }

	if err := m.Tick(); err != nil {
		t.Fatalf("a household with no restrictions must reconcile cleanly: %v", err)
	}
	if err := m.Tick(); err != nil {
		t.Fatalf("the second pass failed: %v", err)
	}

	api := adguard.NewClient(aghAPI, "parent", aghPwd)
	filters, err := api.Filters()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range filters {
		if strings.HasSuffix(f.URL, FilterListPath) {
			t.Errorf("curfew registered a filter list with nothing in it, "+
				"forcing a filter-engine rebuild for no reason: %+v", f)
		}
	}

	// THE CONTROL: give the household a restriction and the list IS
	// registered, so this is not passing because registration is broken.
	m.schedule = memSchedule{eliAndTia()}
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick with a restriction: %v", err)
	}
	filters, err = api.Filters()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range filters {
		if strings.HasSuffix(f.URL, FilterListPath) {
			found = true
		}
	}
	if !found {
		t.Errorf("a household that DOES have restrictions never got its list: %+v", filters)
	}
}

// A household exception must beat a block that came from a DIFFERENT filter
// list, which is the only case that matters: the false positives this exists
// for come from the big category lists, not from anything curfew wrote.
//
// Measured on the live router: opensea.io is blocked by the Porn list and
// eth.limo by the Malware list, both of which curfew itself installs.
func TestAnAllowedDomainOverridesABlockFromAnotherList(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	api := adguard.NewClient(aghAPI, "parent", aghPwd)

	// A second subscribed list playing the part of blocklistproject's Porn
	// list, blocking a name this household actually wants.
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "! Title: pretend category list\n||opensea.io^\n")
	}))
	defer blocked.Close()
	if err := api.AddFilterURL("pretend category list", blocked.URL+"/list.txt"); err != nil {
		t.Fatalf("setting up the blocking list: %v", err)
	}

	// BASELINE: it really is blocked, by that other list, before curfew says
	// anything. Without this the assertion below would pass against a name
	// that was never blocked at all.
	if v := lookupVerdict(t, v6EliA, v6Server, "opensea.io"); v != "BLOCKED" {
		t.Fatalf("baseline: opensea.io should be blocked by the category list, got %s", v)
	}

	m, _ := newManagerUnderTest(t)
	ps := eliAndTia()
	ps.AllowedDomains = []string{"opensea.io"}
	m.schedule = memSchedule{ps}
	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	mustResolve(t, "household exception", v6EliA, v6Server, "opensea.io")
	mustResolve(t, "household exception over IPv4", v4Eli, v4Server, "opensea.io")
	// The control: the exception must not switch filtering off wholesale. The
	// child's own restriction is still in force.
	mustBlock(t, "control: the restriction still applies", v6EliA, v6Server, "twitch.tv")
}

// Publishing a change to curfew's own list must not re-download the
// household's blocklists.
//
// This is the assertion that would have prevented a measured outage. On
// 2026-08-08 at 13:16 a parent saved two always-allowed sites; curfew changed
// its own 63-byte list and called POST /control/filtering/refresh, which has
// no per-list scope and re-fetched all eight subscribed lists, 108 MB of them,
// into an engine rebuild. AdGuard reached 876 MB on a 1010 MB box with no
// swap, the kernel killed it, and the LAN had no resolver from 13:16:22 until
// 13:17:50.
//
// The evidence here is a household list that COUNTS its own fetches, because
// the defect is invisible in every other way: the rule lands correctly either
// route, and only the router's memory can tell the difference.
func TestPublishingCurfewsListDoesNotRefetchTheHouseholdsLists(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	api := adguard.NewClient(aghAPI, "parent", aghPwd)

	var fetches atomic.Int64
	household := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		io.WriteString(w, "! Title: pretend category list\n||opensea.io^\n")
	}))
	defer household.Close()
	if err := api.AddFilterURL("pretend category list", household.URL+"/list.txt"); err != nil {
		t.Fatalf("setting up the household's list: %v", err)
	}

	// BASELINE: the counter works and the list is really in force. Without
	// this, "it was not re-fetched" could mean the server was never asked for
	// anything at all.
	if n := fetches.Load(); n != 1 {
		t.Fatalf("baseline: the household's list should have been fetched once on add_url, got %d", n)
	}
	if v := lookupVerdict(t, v6EliA, v6Server, "opensea.io"); v != "BLOCKED" {
		t.Fatalf("baseline: the household's list is not in force, got %s", v)
	}

	m, _ := newManagerUnderTest(t)
	ps := eliAndTia()
	m.schedule = memSchedule{ps}
	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("registering tick: %v", err)
	}
	registered := fetches.Load()

	// Now the exact action that caused the outage: a parent saves an
	// always-allowed site, which changes curfew's list and nothing else.
	ps.AllowedDomains = []string{"opensea.io"}
	if err := m.Tick(); err != nil {
		t.Fatalf("publishing tick: %v", err)
	}
	if !m.LastReport().Refreshed {
		t.Fatalf("baseline: the changed list was never published at all: %+v", m.LastReport())
	}

	// It really was published: the exception beats the household's block.
	mustResolve(t, "the exception was published", v6EliA, v6Server, "opensea.io")

	// THE ASSERTION: and the household's 108 MB were left alone while doing it.
	if n := fetches.Load(); n != registered {
		t.Errorf("publishing curfew's own list re-fetched the household's list %d time(s); "+
			"on the live router that is 108 MB of re-download and an engine rebuild that "+
			"OOM-killed AdGuard", n-registered)
	}
}

// A curfew list found DISABLED must be switched back on.
//
// Publishing one list means disabling and re-enabling it, so a daemon that
// dies in between leaves curfew's list off in AdGuard, and every exception in
// it silently stops applying. Asserted on the DNS path, from the child's own
// address, because that is the only place "the exception applies" is true.
func TestACurfewListLeftDisabledInAdGuardIsSwitchedBackOn(t *testing.T) {
	requireAdGuard(t)
	startAdGuard(t)
	api := adguard.NewClient(aghAPI, "parent", aghPwd)

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "! Title: pretend category list\n||opensea.io^\n")
	}))
	defer blocked.Close()
	if err := api.AddFilterURL("pretend category list", blocked.URL+"/list.txt"); err != nil {
		t.Fatalf("setting up the blocking list: %v", err)
	}

	m, list := newManagerUnderTest(t)
	ps := eliAndTia()
	ps.AllowedDomains = []string{"opensea.io"}
	m.schedule = memSchedule{ps}
	m.now = func() time.Time { return atClock("09:00") }
	if err := m.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	mustResolve(t, "baseline: the exception applies", v6EliA, v6Server, "opensea.io")

	// Simulate the daemon dying half way through publishing.
	disableFilter(t, list.URL+FilterListPath)
	if v := lookupVerdict(t, v6EliA, v6Server, "opensea.io"); v != "BLOCKED" {
		t.Fatalf("baseline: disabling curfew's list should have removed the exception, got %s", v)
	}

	// Nothing about the household's configuration changed, so only the
	// disabled list can bring curfew back.
	if err := m.Tick(); err != nil {
		t.Fatalf("recovering tick: %v", err)
	}
	mustResolve(t, "after recovery", v6EliA, v6Server, "opensea.io")
}
