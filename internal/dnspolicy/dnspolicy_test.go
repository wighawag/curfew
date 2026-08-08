package dnspolicy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/lanhosts"
	"github.com/wighawag/curfew/internal/schedule"
)

// The worked example from the brief: eli has internet from 08:00 to 22:00
// (nftables, by MAC, already working) and additionally no streaming between
// 08:00 and 10:00 (AdGuard, by IP, the thing being built).
func eliProfiles() *schedule.Profiles {
	return &schedule.Profiles{
		Profiles: []schedule.Profile{{
			Name:    "eli",
			Devices: []string{"14:e0:1d:6a:9c:6c", "04:92:26:1e:6b:55"},
			Restrictions: []schedule.Restriction{{
				Name:     "no streaming",
				Services: []string{"youtube", "netflix"},
				Lists:    []string{"no_streaming"},
				Windows: []schedule.Window{{
					Days:  schedule.AllDays,
					Start: "08:00", End: "10:00",
				}},
			}},
		}},
		BlockLists: map[string][]string{
			"no_streaming": {"twitch.tv", "iplayer.bbc.co.uk"},
		},
	}
}

func at(hhmm string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", "2026-08-10 "+hhmm)
	if err != nil {
		panic(err)
	}
	return t
}

var eliAddrs = map[string]lanhosts.Addresses{
	"14:e0:1d:6a:9c:6c": {IPv6: []string{"fd96:17c2:5378:0:df0c:d02b:894a:72f"}},
	"04:92:26:1e:6b:55": {IPv6: []string{"fd96:17c2:5378:0:75fc:3167:87c6:8b1e"}},
}

var eliPinned = map[string]string{
	"14:e0:1d:6a:9c:6c": "192.168.1.123",
}

func TestInsideTheWindowTheRestrictionIsDesired(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))

	c, ok := d.Clients["curfew-eli"]
	if !ok {
		t.Fatalf("no client for eli, got %+v", d.Clients)
	}
	if !contains(c.BlockedServices, "youtube") || !contains(c.BlockedServices, "netflix") {
		t.Errorf("catalogue services not blocked: %v", c.BlockedServices)
	}
	if c.UseGlobalBlockedServices {
		t.Error("use_global_blocked_services must be false or the per-client list is ignored")
	}
	if !strings.Contains(d.FilterList, "||twitch.tv^$client=curfew-eli") {
		t.Errorf("the custom domain rule is missing:\n%s", d.FilterList)
	}
	// BOTH families must be present, or the restriction silently misses every
	// query the device sends over the other one. Measured on the live router:
	// more than half of recent DNS queries arrive over IPv6.
	if !contains(c.IDs, "192.168.1.123") {
		t.Errorf("the pinned IPv4 lease is missing from the ids: %v", c.IDs)
	}
	if !contains(c.IDs, "fd96:17c2:5378:0:df0c:d02b:894a:72f") {
		t.Errorf("the observed IPv6 address is missing from the ids: %v", c.IDs)
	}
}

// The other half of the window, and the one a test suite usually forgets. A
// restriction that never lifts is as wrong as one that never applies.
func TestOutsideTheWindowNothingIsRestricted(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("11:00"))

	c, ok := d.Clients["curfew-eli"]
	if !ok {
		t.Fatal("the client should still exist, holding the addresses")
	}
	if len(c.BlockedServices) != 0 {
		t.Errorf("services still blocked outside the window: %v", c.BlockedServices)
	}
	if !c.UseGlobalBlockedServices {
		t.Error("with nothing blocked, the client should defer to the global setting")
	}
	if strings.Contains(d.FilterList, "twitch.tv") {
		t.Errorf("the domain rule survived past the window:\n%s", d.FilterList)
	}
}

// The safety property, asserted directly: IPv4 comes ONLY from the pinned
// lease. An observed IPv4 must never reach AdGuard, because DHCP reissues
// addresses and a stale one would restrict the WRONG CHILD.
func TestObservedIPv4NeverBecomesAClientID(t *testing.T) {
	observed := map[string]lanhosts.Addresses{
		// A device with an observed IPv4 that curfew has NOT pinned.
		"14:e0:1d:6a:9c:6c": {IPv4: "192.168.1.99", IPv6: []string{"fd96::1"}},
	}
	d := Compute(eliProfiles(), map[string]string{}, observed, at("09:00"))
	c := d.Clients["curfew-eli"]
	if contains(c.IDs, "192.168.1.99") {
		t.Errorf("an observed, unpinned IPv4 address reached AdGuard: %v", c.IDs)
	}
	// The control: the IPv6 address from the same observation IS used, so this
	// is a deliberate split rather than the observation being ignored wholesale.
	if !contains(c.IDs, "fd96::1") {
		t.Errorf("the observed IPv6 address should still be used: %v", c.IDs)
	}
}

// A profile whose devices have no address at all cannot be restricted. It must
// say so rather than create an object that matches nothing.
func TestAProfileWithNoKnownAddressIsReportedNotFaked(t *testing.T) {
	d := Compute(eliProfiles(), map[string]string{}, map[string]lanhosts.Addresses{}, at("09:00"))
	if len(d.Clients) != 0 {
		t.Errorf("a client was created with no addresses: %+v", d.Clients)
	}
	if len(d.Unresolved) != 1 || d.Unresolved[0] != "eli" {
		t.Errorf("the profile must be reported as unresolved, got %v", d.Unresolved)
	}
	if strings.Contains(d.FilterList, "twitch.tv") {
		t.Errorf("a rule was emitted for a client that does not exist:\n%s", d.FilterList)
	}
}

// The partial case is the one most likely to look fine and behave badly: the
// restriction applies on the phone and not on the laptop.
func TestAProfileWithSomeDevicesUnaddressedIsReported(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned,
		map[string]lanhosts.Addresses{"14:e0:1d:6a:9c:6c": {IPv6: []string{"fd96::1"}}}, at("09:00"))
	if len(d.PartiallyResolved) != 1 || d.PartiallyResolved[0] != "eli" {
		t.Errorf("want eli reported as partially resolved, got %v", d.PartiallyResolved)
	}
	// And it must still restrict what it CAN, since fail-open on the
	// refinement means covering the devices that are known.
	if len(d.Clients) != 1 {
		t.Errorf("the addressable device should still be covered: %+v", d.Clients)
	}
}

// A household not using restrictions must get no curfew objects at all.
func TestAProfileWithNoRestrictionsGetsNoAdGuardObject(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "ronan", Devices: []string{"14:e0:1d:6a:9c:6c"}},
	}}
	d := Compute(ps, eliPinned, eliAddrs, at("09:00"))
	if len(d.Clients) != 0 {
		t.Errorf("curfew created an AdGuard client for a profile with no restrictions: %+v", d.Clients)
	}
}

// The list text must be stable across passes, or every tick looks like a
// window boundary and re-fetches the list several times a minute.
func TestTheRenderedListIsStableAcrossPasses(t *testing.T) {
	a := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	b := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:30"))
	if a.FilterList != b.FilterList {
		t.Errorf("the list changed between two passes inside the same window:\n%q\n%q",
			a.FilterList, b.FilterList)
	}
}

// An IPv6 address rotating must NOT change the served list, because the rules
// reference the client by name. If it did, a phone would trigger a list
// refetch several times a day.
func TestARotatedIPv6AddressDoesNotChangeTheServedList(t *testing.T) {
	before := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	rotated := map[string]lanhosts.Addresses{
		"14:e0:1d:6a:9c:6c": {IPv6: []string{"fd96:17c2:5378:0:aaaa:bbbb:cccc:dddd"}},
		"04:92:26:1e:6b:55": {IPv6: []string{"fd96:17c2:5378:0:75fc:3167:87c6:8b1e"}},
	}
	after := Compute(eliProfiles(), eliPinned, rotated, at("09:00"))
	if before.FilterList != after.FilterList {
		t.Error("a rotated privacy address changed the filter list, which would " +
			"re-fetch it several times a day per device")
	}
	// But the client object MUST change, or the new address is unrestricted.
	if before.Clients["curfew-eli"].SameAs(after.Clients["curfew-eli"]) {
		t.Error("the client object did not pick up the rotated address")
	}
}

// ---- reconcile ----

func TestReconcileWritesNothingWhenAdGuardAlreadyAgrees(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	api := &fakeAPI{
		clients: []adguard.ClientObject{d.Clients["curfew-eli"]},
		filters: []adguard.FilterList{{URL: "http://192.168.1.1:8080/x.txt"}},
	}
	report, err := Reconcile(api, d, "http://192.168.1.1:8080/x.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed() {
		t.Errorf("a converged AdGuard was written to anyway: %+v", report)
	}
	if api.wrote {
		t.Errorf("writes were issued: %v", api.calls)
	}
}

// THE control for this package: a household's own AdGuard client must survive
// a reconcile untouched. This is the same class of assertion as the foreign
// uci entry, and the same class of bug that the previous stage's gate missed.
func TestAHouseholdsOwnAdGuardClientIsNeverTouched(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	theirs := adguard.ClientObject{Name: "Dad's laptop", IDs: []string{"192.168.1.221"},
		BlockedServices: []string{"facebook"}}
	api := &fakeAPI{clients: []adguard.ClientObject{theirs}}

	if _, err := Reconcile(api, d, "http://192.168.1.1:8080/x.txt", true); err != nil {
		t.Fatal(err)
	}
	for _, c := range api.calls {
		if strings.Contains(c, "Dad's laptop") {
			t.Errorf("curfew acted on the household's own client: %q", c)
		}
	}
	if api.deleted["Dad's laptop"] {
		t.Error("curfew DELETED the household's own AdGuard client")
	}
	// The control: it did do its own work, so this is not passing because
	// nothing happened at all.
	if len(api.added) == 0 {
		t.Errorf("curfew's own client was never created: %v", api.calls)
	}
}

// The API guard itself, at the level below: even asked directly, a write to an
// unowned client must be refused.
func TestTheClientAPIRefusesToTouchAnUnownedName(t *testing.T) {
	c := adguard.NewClient("127.0.0.1:3000", "parent", "x")
	if err := c.DeleteClient("Dad's laptop"); err == nil {
		t.Error("deleting an unowned client must be refused before any request is made")
	}
	if err := c.UpdateClient(adguard.ClientObject{Name: "Dad's laptop"}); err == nil {
		t.Error("updating an unowned client must be refused")
	}
}

func TestAStaleCurfewClientIsRemoved(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	api := &fakeAPI{clients: []adguard.ClientObject{
		d.Clients["curfew-eli"],
		{Name: "curfew-deleted-profile", IDs: []string{"192.168.1.9"}},
	}}
	report, err := Reconcile(api, d, "http://192.168.1.1:8080/x.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if !api.deleted["curfew-deleted-profile"] {
		t.Errorf("a curfew client for a profile that no longer exists was left behind: %v", api.calls)
	}
	if len(report.ClientsRemoved) != 1 {
		t.Errorf("the removal should be reported: %+v", report)
	}
}

func TestTheListIsRegisteredWhenAdGuardDoesNotHaveIt(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	api := &fakeAPI{}
	report, err := Reconcile(api, d, "http://192.168.1.1:8080/curfew.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ListRegistered {
		t.Errorf("the filter list was never subscribed: %v", api.calls)
	}
	// add_url fetches as part of validating, so a refresh on top would be a
	// redundant second fetch.
	if report.Refreshed {
		t.Error("a freshly added list should not also be refreshed")
	}
}

func TestAWindowBoundaryRefreshesTheList(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	api := &fakeAPI{
		clients: []adguard.ClientObject{d.Clients["curfew-eli"]},
		filters: []adguard.FilterList{{URL: "http://192.168.1.1:8080/curfew.txt"}},
	}
	report, err := Reconcile(api, d, "http://192.168.1.1:8080/curfew.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Refreshed {
		t.Error("a changed list must be refreshed, or AdGuard picks it up in up to 24 hours")
	}
}

// A failure to reach AdGuard must surface, not be swallowed into a report that
// says everything is fine.
func TestAnAPIFailureIsReportedRatherThanSwallowed(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	api := &fakeAPI{failList: true}
	if _, err := Reconcile(api, d, "http://x/y.txt", false); err == nil {
		t.Fatal("an unreachable AdGuard must be an error")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// fakeAPI records what it was asked. It is deliberately dumb: it stores and
// replays, and encodes none of the decision logic under test, so it cannot
// agree with a broken implementation.
type fakeAPI struct {
	clients  []adguard.ClientObject
	filters  []adguard.FilterList
	calls    []string
	added    []string
	deleted  map[string]bool
	wrote    bool
	failList bool
}

func (f *fakeAPI) Clients() ([]adguard.ClientObject, error) {
	if f.failList {
		return nil, errors.New("connection refused")
	}
	f.calls = append(f.calls, "list")
	return f.clients, nil
}

func (f *fakeAPI) AddClient(c adguard.ClientObject) error {
	f.calls = append(f.calls, "add "+c.Name)
	f.added = append(f.added, c.Name)
	f.wrote = true
	return nil
}

func (f *fakeAPI) UpdateClient(c adguard.ClientObject) error {
	f.calls = append(f.calls, "update "+c.Name)
	f.wrote = true
	return nil
}

func (f *fakeAPI) DeleteClient(name string) error {
	f.calls = append(f.calls, "delete "+name)
	if f.deleted == nil {
		f.deleted = map[string]bool{}
	}
	f.deleted[name] = true
	f.wrote = true
	return nil
}

func (f *fakeAPI) Filters() ([]adguard.FilterList, error) {
	f.calls = append(f.calls, "filters")
	return f.filters, nil
}

func (f *fakeAPI) AddFilterURL(name, url string) error {
	f.calls = append(f.calls, "add_url "+url)
	f.wrote = true
	return nil
}

func (f *fakeAPI) RefreshFilters() error {
	f.calls = append(f.calls, "refresh")
	return nil
}

// A restriction a child can route around with two taps in browser settings is
// not a restriction. Blocking the DoH endpoint hostnames is the cheap half of
// closing that, and it must be on by default.
func TestDoHBootstrapIsBlockedForRestrictedProfilesByDefault(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("09:00"))
	// Firefox's canary specifically: NXDOMAIN here disables its automatic DoH.
	if !strings.Contains(d.FilterList, "||use-application-dns.net^$client=curfew-eli") {
		t.Errorf("the Firefox canary is not blocked:\n%s", d.FilterList)
	}
	if !strings.Contains(d.FilterList, "||cloudflare-dns.com^$client=curfew-eli") {
		t.Errorf("a well-known DoH endpoint is not blocked:\n%s", d.FilterList)
	}
}

// It must apply OUTSIDE the window too. A child sets a DoH endpoint once and
// it persists, so letting them resolve it at 07:00 defeats a restriction that
// begins at 08:00.
func TestDoHBootstrapIsBlockedOutsideTheWindowToo(t *testing.T) {
	d := Compute(eliProfiles(), eliPinned, eliAddrs, at("11:00"))
	if !strings.Contains(d.FilterList, "use-application-dns.net") {
		t.Errorf("DoH is resolvable outside the window, which defeats the next one:\n%s", d.FilterList)
	}
	// The control: the actual restriction IS lifted, so this is not just
	// "everything is always blocked".
	if strings.Contains(d.FilterList, "twitch.tv") {
		t.Errorf("the streaming rule survived past its window:\n%s", d.FilterList)
	}
}

// A household that turns it off must have that respected, and a profile with
// no restrictions must never be touched by it.
func TestDoHBootstrapCanBeTurnedOffAndNeverTouchesUnrestrictedProfiles(t *testing.T) {
	off := false
	ps := eliProfiles()
	ps.BlockDoHBootstrap = &off
	d := Compute(ps, eliPinned, eliAddrs, at("09:00"))
	if strings.Contains(d.FilterList, "use-application-dns.net") {
		t.Errorf("block_doh_bootstrap=false was ignored:\n%s", d.FilterList)
	}
	// The control: the real restriction still applies, so turning DoH blocking
	// off has not turned everything off.
	if !strings.Contains(d.FilterList, "twitch.tv") {
		t.Errorf("turning off DoH blocking also removed the restriction:\n%s", d.FilterList)
	}

	// A parent's profile, with no restrictions at all, gets nothing.
	plain := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "ronan", Devices: []string{"14:e0:1d:6a:9c:6c"}},
	}}
	d = Compute(plain, eliPinned, eliAddrs, at("09:00"))
	if strings.Contains(d.FilterList, "use-application-dns.net") {
		t.Errorf("an unrestricted profile had DoH blocked:\n%s", d.FilterList)
	}
}
