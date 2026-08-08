package httpui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/lanhosts"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// The pending list is the answer to "the router already knows every address on
// this LAN, so why am I typing one in by hand?". These tests fix what it is
// allowed to show, and the two things it must never do: trust what a device
// says about itself, and let an enrolment quietly produce a device that
// belongs to no profile and is therefore restricted by nothing.

func newPendingServer(t *testing.T, devices []registry.Device, profiles []schedule.Profile,
	seen map[string]lanhosts.Sighting, seenErr error) (*Server, *memStore, *fakeSchedule, *fakeFirewall) {
	t.Helper()
	store := &memStore{reg: &registry.Registry{Devices: devices}}
	sch := &fakeSchedule{ps: &schedule.Profiles{Profiles: profiles}}
	fw := &fakeFirewall{}
	for _, d := range devices {
		fw.live = append(fw.live, d.MAC)
	}
	srv, _ := assemble(store, sch, &memState{}, fw, "", "", time.Local)
	srv.UseLANSightings(func() (map[string]lanhosts.Sighting, error) { return seen, seenErr })
	return srv, store, sch, fw
}

func getPage(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: want 200, got %d: %s", path, rec.Code, rec.Body)
	}
	return rec
}

func TestPendingShowsWhatTheRouterHasSeenAndTheRegistryDoesNot(t *testing.T) {
	srv, _, _, _ := newPendingServer(t,
		[]registry.Device{{MAC: "f8:25:51:09:38:38", Name: "printer"}},
		nil,
		map[string]lanhosts.Sighting{
			"f8:25:51:09:38:38": {MAC: "f8:25:51:09:38:38", IPv4: "192.168.1.10", Leased: true},
			"aa:bb:cc:dd:ee:01": {MAC: "aa:bb:cc:dd:ee:01", IPv4: "192.168.1.42",
				Hostname: "elis-phone", Leased: true},
		}, nil)

	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	if !strings.Contains(body, "aa:bb:cc:dd:ee:01") {
		t.Errorf("the unknown device is missing from the page:\n%s", body)
	}
	if !strings.Contains(body, "elis-phone") {
		t.Errorf("the claimed hostname is the only thing that lets a person recognise " +
			"their own device, and it is missing")
	}
	if !strings.Contains(body, "192.168.1.42") {
		t.Errorf("the address is missing")
	}
	// The printer IS in the registry, so it must not be offered for enrolment
	// a second time. Counting occurrences would be brittle; what matters is
	// that it is not in the pending section.
	if strings.Contains(pendingSection(body), "f8:25:51:09:38:38") {
		t.Errorf("a registered device must not appear as pending:\n%s", body)
	}
}

// A device with a static address, or one whose lease lapsed, has no lease line
// at all. It is exactly the device an admin needs to find, so a list built
// only from leases would miss the case it exists for.
func TestPendingIncludesADeviceWithNoLease(t *testing.T) {
	srv, _, _, _ := newPendingServer(t, nil, nil, map[string]lanhosts.Sighting{
		"aa:bb:cc:dd:ee:02": {MAC: "aa:bb:cc:dd:ee:02", IPv4: "192.168.1.99", Leased: false},
	}, nil)
	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	if !strings.Contains(body, "aa:bb:cc:dd:ee:02") {
		t.Fatalf("a device seen without a lease is missing:\n%s", body)
	}
	if !strings.Contains(body, "no DHCP lease") {
		t.Errorf("the page should say the device never completed DHCP, since that " +
			"changes what the admin is looking at")
	}
}

func TestPendingFlagsARandomisedAddress(t *testing.T) {
	srv, _, _, _ := newPendingServer(t, nil, nil, map[string]lanhosts.Sighting{
		"aa:bb:cc:dd:ee:03": {MAC: "aa:bb:cc:dd:ee:03", Hostname: "phone", Leased: true},
		"f8:25:51:09:38:38": {MAC: "f8:25:51:09:38:38", Hostname: "printer", Leased: true},
	}, nil)
	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	var randomised, vendor string
	for _, r := range pendingRows(body) {
		if strings.Contains(r, "aa:bb:cc:dd:ee:03") {
			randomised = r
		}
		if strings.Contains(r, "f8:25:51:09:38:38") {
			vendor = r
		}
	}
	if randomised == "" || vendor == "" {
		t.Fatalf("both devices should be pending:\n%s", body)
	}
	if !strings.Contains(randomised, "randomised") {
		t.Errorf("a locally administered address should be flagged:\n%s", randomised)
	}
	if strings.Contains(vendor, "randomised") {
		t.Errorf("a vendor address must not be flagged:\n%s", vendor)
	}
}

// Nothing in this feature decides who has internet, so every way it can fail
// degrades to "no pending devices" rather than to an error page. A page that
// 500s because the neighbour table could not be read would remove the one
// screen that explains why a device is offline.
func TestPendingIsAbsentRatherThanBrokenWithoutAnObserver(t *testing.T) {
	store := &memStore{reg: &registry.Registry{}}
	srv, _ := assemble(store, &fakeSchedule{}, &memState{}, &fakeFirewall{}, "", "", time.Local)
	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	if strings.Contains(body, "Seen on the network") {
		t.Errorf("with no observer wired up the section should be absent, not empty:\n%s", body)
	}
}

func TestPendingSurvivesAnObserverThatFails(t *testing.T) {
	srv, _, _, _ := newPendingServer(t, nil, nil, nil, errors.New("ip: not found"))
	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	if !strings.Contains(body, "Add a device") {
		t.Errorf("the rest of the page must still render:\n%s", body)
	}
}

func TestEnrolFromPendingRegistersAndJoinsTheProfile(t *testing.T) {
	srv, store, sch, fw := newPendingServer(t, nil,
		[]schedule.Profile{{Name: "eli"}},
		map[string]lanhosts.Sighting{
			"aa:bb:cc:dd:ee:04": {MAC: "aa:bb:cc:dd:ee:04", Hostname: "elis-phone", Leased: true},
		}, nil)

	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"aa:bb:cc:dd:ee:04"}, "name": {"eli phone"}, "profile": {"p:eli"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if len(store.reg.Devices) != 1 || store.reg.Devices[0].Name != "eli phone" {
		t.Fatalf("device not registered: %+v", store.reg.Devices)
	}
	p, ok := sch.ps.Find("eli")
	if !ok || len(p.Devices) != 1 || p.Devices[0] != "aa:bb:cc:dd:ee:04" {
		t.Fatalf("device not added to the profile: %+v", sch.ps.Profiles)
	}
	if len(fw.live) != 1 || fw.live[0] != "aa:bb:cc:dd:ee:04" {
		t.Fatalf("firewall not reconciled: %v", fw.live)
	}
}

// Registering into a profile that does not exist must leave NOTHING behind.
// The dangerous half-outcome is a device registered but in no profile, which
// is an ungoverned device with permanently unrestricted access: strictly more
// internet than the admin asked for.
func TestEnrolIntoAnUnknownProfileRegistersNothing(t *testing.T) {
	srv, store, sch, fw := newPendingServer(t, nil,
		[]schedule.Profile{{Name: "eli"}}, nil, nil)

	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"aa:bb:cc:dd:ee:05"}, "profile": {"p:nobody"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want the error carried in a redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("want the error surfaced, got %q", loc)
	}
	if len(store.reg.Devices) != 0 {
		t.Errorf("a refused enrolment must register nothing, got %+v", store.reg.Devices)
	}
	if p, _ := sch.ps.Find("eli"); len(p.Devices) != 0 {
		t.Errorf("a refused enrolment must not touch another profile: %+v", p.Devices)
	}
	if len(fw.live) != 0 {
		t.Errorf("a refused enrolment must not reach the firewall: %v", fw.live)
	}
}

func TestEnrolWithNoProfileIsAllowedButExplicit(t *testing.T) {
	srv, store, _, fw := newPendingServer(t, nil, []schedule.Profile{{Name: "eli"}}, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"f8:25:51:09:38:38"}, "name": {"printer"}, "profile": {"none"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if len(store.reg.Devices) != 1 {
		t.Fatalf("the printer should register: %+v", store.reg.Devices)
	}
	if len(fw.live) != 1 {
		t.Fatalf("firewall not reconciled: %v", fw.live)
	}
}

// The form is what stops a distracted admin creating an ungoverned device by
// tabbing past a select. It must have no pre-selected valid answer, and it
// must say what "no profile" costs.
func TestTheEnrolFormForcesAChoiceAndSaysWhatNoProfileMeans(t *testing.T) {
	srv, _, _, _ := newPendingServer(t, nil,
		[]schedule.Profile{{Name: "eli"}, {Name: "tia"}},
		map[string]lanhosts.Sighting{
			"aa:bb:cc:dd:ee:06": {MAC: "aa:bb:cc:dd:ee:06", Leased: true},
		}, nil)
	body := getPage(t, srv.Handler(), "/devices/").Body.String()
	if !strings.Contains(body, `name="profile" required`) {
		t.Errorf("the profile select must be required:\n%s", body)
	}
	if !strings.Contains(body, `value="p:eli"`) || !strings.Contains(body, `value="p:tia"`) {
		t.Errorf("every profile should be offered:\n%s", body)
	}
	if !strings.Contains(body, `value="none"`) {
		t.Errorf("no-profile must be an option that has to be picked:\n%s", body)
	}
	if !strings.Contains(body, "always allowed") {
		t.Errorf("the page must say what choosing no profile means:\n%s", body)
	}
}

// A profile called "none" would collide with the sentinel if profile names
// were used as select values directly. They are prefixed instead, so the
// collision cannot happen; this pins that.
func TestAProfileCalledNoneIsNotConfusedWithNoProfile(t *testing.T) {
	srv, store, sch, _ := newPendingServer(t, nil,
		[]schedule.Profile{{Name: "none"}}, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"aa:bb:cc:dd:ee:07"}, "profile": {"p:none"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	p, _ := sch.ps.Find("none")
	if len(p.Devices) != 1 {
		t.Fatalf("the device should have joined the profile literally called none: %+v", p.Devices)
	}
	if len(store.reg.Devices) != 1 {
		t.Fatalf("device not registered: %+v", store.reg.Devices)
	}
}

func TestEnrolRejectsAnUnparseableProfileChoice(t *testing.T) {
	srv, store, _, _ := newPendingServer(t, nil, []schedule.Profile{{Name: "eli"}}, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"aa:bb:cc:dd:ee:08"}, "profile": {"eli"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want the error carried in a redirect, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 0 {
		t.Errorf("nothing should be registered from an unreadable choice: %+v", store.reg.Devices)
	}
}

// pendingSection isolates the pending table so an assertion about it cannot
// accidentally pass on text from the registered-devices table above it.
func pendingSection(body string) string {
	const marker = "Seen on the network"
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	return body[i:]
}

// pendingRows cuts the pending table into rows, ENDING each at its closing
// tag. Splitting on the opening tag alone leaves the last "row" carrying every
// paragraph that follows the table, and the explanatory text down there
// mentions randomised addresses: a per-row assertion would then pass for a
// device that was never flagged.
func pendingRows(body string) []string {
	var out []string
	for _, r := range strings.Split(pendingSection(body), "<tr") {
		if end := strings.Index(r, "</tr>"); end >= 0 {
			out = append(out, r[:end])
		}
	}
	return out
}
