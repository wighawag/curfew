package httpui

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// fakeFirewall stands in for nftables so the UI is testable without a kernel.
type fakeSchedule struct{ ps *schedule.Profiles }

func (f *fakeSchedule) Load() (*schedule.Profiles, error) {
	if f.ps == nil {
		return &schedule.Profiles{Profiles: []schedule.Profile{}}, nil
	}
	cp := &schedule.Profiles{Profiles: append([]schedule.Profile(nil), f.ps.Profiles...)}
	return cp, nil
}
func (f *fakeSchedule) Save(ps *schedule.Profiles) error {
	f.ps = &schedule.Profiles{Profiles: append([]schedule.Profile(nil), ps.Profiles...)}
	return nil
}

type fakeFirewall struct {
	live      []string
	blocked   []string
	applyErr  error
	readErr   error
	applyCall int
}

func (f *fakeFirewall) Apply(macs []string) error {
	f.applyCall++
	if f.applyErr != nil {
		return f.applyErr
	}
	f.live = append([]string(nil), macs...)
	return nil
}

func (f *fakeFirewall) Allowlist() ([]string, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return append([]string(nil), f.live...), nil
}

func (f *fakeFirewall) Blocked() ([]string, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return append([]string(nil), f.blocked...), nil
}

type memStore struct {
	reg     *registry.Registry
	saveErr error
}

func (m *memStore) Load() (*registry.Registry, error) {
	cp := &registry.Registry{Devices: append([]registry.Device(nil), m.reg.Devices...)}
	return cp, nil
}

func (m *memStore) Save(r *registry.Registry) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.reg = &registry.Registry{Devices: append([]registry.Device(nil), r.Devices...)}
	return nil
}

func newTestServer(t *testing.T, devices []registry.Device, live []string) (*Server, *memStore, *fakeFirewall) {
	t.Helper()
	store := &memStore{reg: &registry.Registry{Devices: devices}}
	fw := &fakeFirewall{live: live}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(store, &fakeSchedule{}, fw, log, "", "", time.Local, nil), store, fw
}

func post(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAddDeviceRegistersAndEnforces(t *testing.T) {
	srv, store, fw := newTestServer(t, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{
		"mac": {"AA:BB:CC:DD:EE:01"}, "name": {"eli phone"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303 redirect, got %d: %s", rec.Code, rec.Body)
	}
	if len(store.reg.Devices) != 1 || store.reg.Devices[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("device not registered canonically: %+v", store.reg.Devices)
	}
	if store.reg.Devices[0].Name != "eli phone" {
		t.Errorf("name not saved: %+v", store.reg.Devices[0])
	}
	if len(fw.live) != 1 || fw.live[0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("firewall not reconciled: %v", fw.live)
	}
}

func TestAddDeviceWithoutNameIsAllowed(t *testing.T) {
	srv, store, fw := newTestServer(t, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{"mac": {"aa:bb:cc:dd:ee:02"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 1 || store.reg.Devices[0].Name != "" {
		t.Fatalf("anonymous device should register: %+v", store.reg.Devices)
	}
	if len(fw.live) != 1 {
		t.Fatalf("firewall not reconciled: %v", fw.live)
	}
}

func TestAddDeviceRejectsBadMACWithoutTouchingFirewall(t *testing.T) {
	srv, store, fw := newTestServer(t, nil, nil)
	rec := post(t, srv.Handler(), "/devices", url.Values{"mac": {"nonsense"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect carrying the error, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("want the error surfaced in the redirect, got %q", loc)
	}
	if len(store.reg.Devices) != 0 {
		t.Errorf("nothing should be registered: %+v", store.reg.Devices)
	}
	if fw.applyCall != 0 {
		t.Errorf("the firewall must not be touched for an invalid MAC, called %d times", fw.applyCall)
	}
}

// The headline regression guard for this whole project: if the firewall cannot
// be updated, the response must NOT claim success.
func TestAddDeviceFailsLoudlyWhenTheFirewallFails(t *testing.T) {
	srv, _, fw := newTestServer(t, nil, nil)
	fw.applyErr = errors.New("netlink is unhappy")
	rec := post(t, srv.Handler(), "/devices", url.Values{"mac": {"aa:bb:cc:dd:ee:03"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when enforcement fails, got %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "NOT updated") {
		t.Errorf("the response must say the firewall was not updated, got %q", rec.Body.String())
	}
}

func TestGetCannotMutate(t *testing.T) {
	srv, store, _ := newTestServer(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/devices?mac=aa:bb:cc:dd:ee:04", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405 for a GET mutation, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 0 {
		t.Errorf("a GET must never register a device: %+v", store.reg.Devices)
	}
}

// Drift must be visible. A device in the registry that the firewall does not
// actually allow has to read as not allowed, or the page becomes the same
// comforting lie the shell implementation told.
func TestViewReportsTheFirewallNotTheRegistry(t *testing.T) {
	srv, _, _ := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "registered but not enforced"}},
		nil, // the firewall allows nothing
	)
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var body struct {
		Devices []DeviceView `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Devices) != 1 {
		t.Fatalf("want 1 device, got %+v", body.Devices)
	}
	if body.Devices[0].Allowed {
		t.Error("a registered device the firewall does not allow must report allowed=false")
	}
}

func TestViewFlagsAMACTheFirewallAllowsButNobodyRegistered(t *testing.T) {
	srv, _, _ := newTestServer(t, nil, []string{"aa:bb:cc:dd:ee:09"})
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var body struct {
		Devices []DeviceView `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Devices) != 1 || !body.Devices[0].Unregistered {
		t.Fatalf("an unregistered allowed MAC must be flagged: %+v", body.Devices)
	}
}

func TestAuthGatesEverythingWhenConfigured(t *testing.T) {
	store := &memStore{reg: &registry.Registry{}}
	fw := &fakeFirewall{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(store, &fakeSchedule{}, fw, log, "parent", "hunter2", time.Local, nil)
	h := srv.Handler()

	for _, path := range []string{"/", "/devices/", "/api/devices"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: want 401, got %d", path, rec.Code)
		}
	}

	// The mutating route matters most: it is what grants network access.
	rec := post(t, h, "/devices", url.Values{"mac": {"aa:bb:cc:dd:ee:05"}})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /devices unauthenticated: want 401, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 0 {
		t.Error("an unauthenticated POST must not register anything")
	}

	// The control: correct credentials must WORK, or "401 for everything"
	// would pass this test while the page was simply broken.
	req := httptest.NewRequest(http.MethodPost, "/devices",
		strings.NewReader(url.Values{"mac": {"aa:bb:cc:dd:ee:05"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("parent", "hunter2")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("authenticated POST: want 303, got %d: %s", rec.Code, rec.Body)
	}
	if len(store.reg.Devices) != 1 {
		t.Error("an authenticated POST should register the device")
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	store := &memStore{reg: &registry.Registry{}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(store, &fakeSchedule{}, &fakeFirewall{}, log, "parent", "hunter2", time.Local, nil)
	req := httptest.NewRequest(http.MethodGet, "/devices/", nil)
	req.SetBasicAuth("parent", "wrong")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for a wrong password, got %d", rec.Code)
	}
}

func TestIndexRendersDevices(t *testing.T) {
	srv, _, _ := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		[]string{"aa:bb:cc:dd:ee:01"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "eli phone") || !strings.Contains(body, "aa:bb:cc:dd:ee:01") {
		t.Errorf("page should list the device, got:\n%s", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("want no-store, got %q", rec.Header().Get("Cache-Control"))
	}
}

func TestRenameDevice(t *testing.T) {
	srv, store, fw := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "old"}},
		[]string{"aa:bb:cc:dd:ee:01"})
	before := fw.applyCall
	rec := post(t, srv.Handler(), "/devices/rename", url.Values{
		"mac": {"aa:bb:cc:dd:ee:01"}, "name": {"eli laptop"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if store.reg.Devices[0].Name != "eli laptop" {
		t.Errorf("name not saved: %+v", store.reg.Devices[0])
	}
	// A name is metadata. Touching the ruleset for it would put enforcement at
	// risk for an operation that cannot affect who has internet.
	if fw.applyCall != before {
		t.Errorf("renaming must not touch the firewall, Apply called %d times", fw.applyCall-before)
	}
	if store.reg.Devices[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("the MAC must not change: %+v", store.reg.Devices[0])
	}
}

func TestRenameUnknownDeviceDoesNotInsert(t *testing.T) {
	srv, store, _ := newTestServer(t, nil, nil)
	rec := post(t, srv.Handler(), "/devices/rename", url.Values{
		"mac": {"aa:bb:cc:dd:ee:09"}, "name": {"ghost"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect carrying the error, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 0 {
		t.Errorf("a rename must never register a new device: %+v", store.reg.Devices)
	}
}

func TestRenameRejectsGET(t *testing.T) {
	srv, store, _ := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "old"}}, nil)
	req := httptest.NewRequest(http.MethodGet, "/devices/rename?mac=aa:bb:cc:dd:ee:01&name=hacked", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
	if store.reg.Devices[0].Name != "old" {
		t.Error("a GET must not rename anything")
	}
}

func TestRenameIsAuthenticated(t *testing.T) {
	store := &memStore{reg: &registry.Registry{Devices: []registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "old"}}}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(store, &fakeSchedule{}, &fakeFirewall{}, log, "parent", "hunter2", time.Local, nil)
	rec := post(t, srv.Handler(), "/devices/rename", url.Values{
		"mac": {"aa:bb:cc:dd:ee:01"}, "name": {"intruder"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if store.reg.Devices[0].Name != "old" {
		t.Error("an unauthenticated rename must change nothing")
	}
}

func TestIndexOffersARenameFormForRegisteredDevicesOnly(t *testing.T) {
	srv, _, _ := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli"}},
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:99"}) // ...:99 is unregistered
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `action="/devices/rename"`) {
		t.Error("registered devices should get a rename form")
	}
	if strings.Count(body, `action="/devices/rename"`) != 1 {
		t.Errorf("only the registered device should be renameable, got %d forms",
			strings.Count(body, `action="/devices/rename"`))
	}
	if !strings.Contains(body, "not in the registry") {
		t.Error("the unregistered MAC should still be flagged rather than made nameable")
	}
}

func TestRemoveDeviceRevokesAccess(t *testing.T) {
	srv, store, fw := newTestServer(t,
		[]registry.Device{
			{MAC: "aa:bb:cc:dd:ee:01", Name: "keep"},
			{MAC: "aa:bb:cc:dd:ee:02", Name: "drop"},
		},
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
	rec := post(t, srv.Handler(), "/devices/remove", url.Values{"mac": {"aa:bb:cc:dd:ee:02"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if len(store.reg.Devices) != 1 || store.reg.Devices[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("wrong device removed: %+v", store.reg.Devices)
	}
	// The firewall MUST be reconciled: saying "removed" while the device keeps
	// its internet is the exact failure this project exists to remove.
	if len(fw.live) != 1 || fw.live[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("allowlist not reconciled after removal: %v", fw.live)
	}
}

func TestRemoveFailsLoudlyWhenTheFirewallFails(t *testing.T) {
	srv, _, fw := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}, []string{"aa:bb:cc:dd:ee:01"})
	fw.applyErr = errors.New("netlink is unhappy")
	rec := post(t, srv.Handler(), "/devices/remove", url.Values{"mac": {"aa:bb:cc:dd:ee:01"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "may still have access") {
		t.Errorf("the response must warn the device may still be online, got %q", rec.Body.String())
	}
}

func TestRemoveUnknownDeviceIsAnError(t *testing.T) {
	srv, store, fw := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}, []string{"aa:bb:cc:dd:ee:01"})
	before := fw.applyCall
	rec := post(t, srv.Handler(), "/devices/remove", url.Values{"mac": {"aa:bb:cc:dd:ee:09"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect carrying the error, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 1 {
		t.Error("nothing should have been removed")
	}
	if fw.applyCall != before {
		t.Error("the firewall must not be touched when nothing was removed")
	}
}

func TestRemoveRejectsGETAndRequiresAuth(t *testing.T) {
	srv, store, _ := newTestServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}, nil)
	req := httptest.NewRequest(http.MethodGet, "/devices/remove?mac=aa:bb:cc:dd:ee:01", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405 for a GET removal, got %d", rec.Code)
	}
	if len(store.reg.Devices) != 1 {
		t.Fatal("a GET must never remove a device")
	}

	authStore := &memStore{reg: &registry.Registry{Devices: []registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authed := New(authStore, &fakeSchedule{}, &fakeFirewall{}, log, "parent", "hunter2", time.Local, nil)
	rec = post(t, authed.Handler(), "/devices/remove", url.Values{"mac": {"aa:bb:cc:dd:ee:01"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if len(authStore.reg.Devices) != 1 {
		t.Error("an unauthenticated removal must change nothing")
	}
}

func newProfileServer(t *testing.T, devices []registry.Device, ps *schedule.Profiles,
	allowed, blocked []string) (*Server, *fakeSchedule, *fakeFirewall) {
	t.Helper()
	store := &memStore{reg: &registry.Registry{Devices: devices}}
	sch := &fakeSchedule{ps: ps}
	fw := &fakeFirewall{live: allowed, blocked: blocked}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A reconcile that mirrors the daemon's: recompute from the schedule and
	// push it into the fake firewall, so tests see what a user would.
	reconcile := func() error {
		cur, err := sch.Load()
		if err != nil {
			return err
		}
		fw.blocked = cur.BlockedMACs(time.Now().In(time.Local))
		return nil
	}
	return New(store, sch, fw, log, "", "", time.Local, reconcile), sch, fw
}

func TestHomeListsProfilesWithStatus(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"},
			Windows: []schedule.Window{{Days: schedule.AllDays, Start: "22:00", End: "08:00"}}},
		{Name: "adults", Devices: []string{"aa:bb:cc:dd:ee:02"}},
	}}
	srv, _, _ := newProfileServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}, {MAC: "aa:bb:cc:dd:ee:02", Name: "dad"}},
		ps,
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
		[]string{"aa:bb:cc:dd:ee:01"}) // firewall says eli is blocked
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"eli", "adults", "22:00 to 08:00, every day (overnight)"} {
		if !strings.Contains(body, want) {
			t.Errorf("home should mention %q", want)
		}
	}
	assertWholePage(t, rec)
}

// assertWholePage is the control this file was missing.
//
// html/template writes as it goes, so a template error halfway through used to
// leave a 200 with a truncated body. A real bug shipped that way: everything
// after the first profile's first window silently vanished, including the
// add-window and create-profile forms, while status checks and any assertion
// on a string near the top of the page still passed. Checking the page is
// COMPLETE is what makes that visible.
func assertWholePage(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "</html>") {
		t.Fatalf("the page is truncated, so the template failed mid-render:\n...%s",
			tail(rec.Body.String(), 200))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// The exact shape of the shipped bug: a profile WITH a window must render its
// remove form and everything after it.
func TestHomeRendersCompletelyWithWindowsAndOffersBothForms(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}, Windows: []schedule.Window{
			{Days: schedule.AllDays, Start: "22:00", End: "08:00"},
			{Days: []schedule.Day{schedule.Mon}, Start: "12:00", End: "13:00"},
		}},
		{Name: "tia", Windows: []schedule.Window{
			{Days: []schedule.Day{schedule.Wed, schedule.Fri}, Start: "14:00", End: "16:00"}}},
	}}
	srv, _, _ := newProfileServer(t, []registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}, ps, nil, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)

	body := rec.Body.String()
	// One add-window form per profile, and the create form, must all survive.
	if got := strings.Count(body, `action="/profiles/window/add"`); got != 2 {
		t.Errorf("want an add-window form for each of the 2 profiles, got %d", got)
	}
	if got := strings.Count(body, `action="/profiles/create"`); got != 1 {
		t.Errorf("want the create-profile form, got %d", got)
	}
	// Each window needs a remove form carrying its OWN profile name.
	if got := strings.Count(body, `action="/profiles/window/remove"`); got != 3 {
		t.Errorf("want a remove form per window (3), got %d", got)
	}
	if !strings.Contains(body, `name="name" value="eli"`) || !strings.Contains(body, `name="name" value="tia"`) {
		t.Error("remove forms must carry the profile they belong to, not the page data")
	}
}

// A template that cannot render must be a 500, never a plausible-looking
// partial page.
func TestBrokenTemplateFailsLoudlyInsteadOfTruncating(t *testing.T) {
	srv, _, _ := newProfileServer(t, nil, &schedule.Profiles{}, nil, nil)
	broken := template.Must(template.New("x").Parse(`<p>{{.NoSuchField}}</p>`))
	rec := httptest.NewRecorder()
	srv.render(rec, broken, homeData{}, "test")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<p>") {
		t.Error("no partial output should reach the client")
	}
}

// Status must come from the firewall, not from re-evaluating the schedule.
// If the two disagree the page must SAY so, because that gap is the failure
// this whole project exists to make visible.
func TestHomeSurfacesDriftBetweenScheduleAndFirewall(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
	}}
	// No window says block, yet the firewall is blocking it.
	srv, _, _ := newProfileServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}}, ps,
		[]string{"aa:bb:cc:dd:ee:01"}, []string{"aa:bb:cc:dd:ee:01"})
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !views[0].Drifted() {
		t.Fatal("a firewall block with no window behind it is drift and must be reported")
	}
	if !strings.Contains(views[0].Reason, "no window") {
		t.Errorf("the reason should explain the drift, got %q", views[0].Reason)
	}
}

func TestCreateAndDeleteProfile(t *testing.T) {
	srv, sch, _ := newProfileServer(t, nil, &schedule.Profiles{}, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/create", url.Values{"name": {"eli"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if _, ok := sch.ps.Find("eli"); !ok {
		t.Fatal("profile not created")
	}
	rec = post(t, srv.Handler(), "/profiles/create", url.Values{"name": {"eli"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Error("creating a duplicate profile should be refused with an error")
	}
	rec = post(t, srv.Handler(), "/profiles/delete", url.Values{"name": {"eli"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if len(sch.ps.Profiles) != 0 {
		t.Error("profile not deleted")
	}
}

func TestAddWindowWithDays(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "tia"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"tia"}, "start": {"14:00"}, "end": {"16:00"}, "day": {"wed", "fri"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	p, _ := sch.ps.Find("tia")
	if len(p.Windows) != 1 {
		t.Fatalf("window not added: %+v", p.Windows)
	}
	w := p.Windows[0]
	if w.Start != "14:00" || w.End != "16:00" || len(w.Days) != 2 {
		t.Errorf("window wrong: %+v", w)
	}
	if !w.Contains(time.Date(2026, 8, 5, 15, 0, 0, 0, time.Local)) { // a Wednesday
		t.Error("the saved window should block on Wednesday afternoon")
	}
}

func TestAddSecondWindowSoNightAndLunchCoexist(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)
	post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"eli"}, "start": {"22:00"}, "end": {"08:00"},
		"day": {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}})
	post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"eli"}, "start": {"12:00"}, "end": {"13:00"},
		"day": {"mon", "tue", "wed", "thu", "fri"}})
	p, _ := sch.ps.Find("eli")
	if len(p.Windows) != 2 {
		t.Fatalf("want both windows, got %+v", p.Windows)
	}
	monday := time.Date(2026, 8, 3, 0, 0, 0, 0, time.Local)
	if !p.BlockedAt(monday.Add(23 * time.Hour)) {
		t.Error("night window should block")
	}
	if !p.BlockedAt(monday.Add(12*time.Hour + 30*time.Minute)) {
		t.Error("lunch window should block")
	}
	if p.BlockedAt(monday.Add(15 * time.Hour)) {
		t.Error("mid-afternoon should be free")
	}
}

// A rejected window must never reach the file, or the daemon would refuse to
// load its own schedule on the next restart.
func TestAddWindowRejectsNonsenseWithoutSaving(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"eli"}, "start": {"22:00"}, "end": {"08:00"}}) // no days
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Error("a window with no days should be refused")
	}
	p, _ := sch.ps.Find("eli")
	if len(p.Windows) != 0 {
		t.Errorf("nothing should have been saved: %+v", p.Windows)
	}
}

func TestRemoveWindow(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Windows: []schedule.Window{
		{Days: schedule.AllDays, Start: "22:00", End: "08:00"},
		{Days: []schedule.Day{schedule.Mon}, Start: "12:00", End: "13:00"},
	}}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/window/remove", url.Values{"name": {"eli"}, "index": {"0"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	p, _ := sch.ps.Find("eli")
	if len(p.Windows) != 1 || p.Windows[0].Start != "12:00" {
		t.Fatalf("wrong window removed: %+v", p.Windows)
	}
	// An out-of-range index must be refused rather than panicking.
	rec = post(t, srv.Handler(), "/profiles/window/remove", url.Values{"name": {"eli"}, "index": {"9"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Error("an out-of-range window index should be an error")
	}
}

func TestSetProfileMembership(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}}}}
	srv, sch, _ := newProfileServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01"}, {MAC: "aa:bb:cc:dd:ee:02"}}, ps, nil, nil)
	post(t, srv.Handler(), "/profiles/devices", url.Values{
		"name": {"eli"}, "mac": {"aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:02"}})
	p, _ := sch.ps.Find("eli")
	if len(p.Devices) != 2 || p.Devices[1] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("membership not set canonically: %+v", p.Devices)
	}
	// Unchecking everything must be possible: a profile with no devices is
	// legitimate, and an empty form must not be read as "no change".
	post(t, srv.Handler(), "/profiles/devices", url.Values{"name": {"eli"}})
	p, _ = sch.ps.Find("eli")
	if len(p.Devices) != 0 {
		t.Errorf("membership should be clearable, got %+v", p.Devices)
	}
}

func TestScheduleMutationsRequireAuthAndPOST(t *testing.T) {
	store := &memStore{reg: &registry.Registry{}}
	sch := &fakeSchedule{ps: &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(store, sch, &fakeFirewall{}, log, "parent", "hunter2", time.Local, nil)
	for _, path := range []string{
		"/profiles/create", "/profiles/delete", "/profiles/devices",
		"/profiles/window/add", "/profiles/window/remove",
	} {
		rec := post(t, srv.Handler(), path, url.Values{"name": {"eli"}})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: want 401, got %d", path, rec.Code)
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth("parent", "hunter2")
		rec2 := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec2, req)
		if rec2.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s via GET: want 405, got %d", path, rec2.Code)
		}
	}
	if len(sch.ps.Profiles) != 1 {
		t.Error("nothing should have changed")
	}
}

// Adding a window must take effect immediately. Waiting for the next tick left
// the page honestly but alarmingly reporting "should be blocked right now, but
// is not" for up to a minute after the button was pressed, which reads as a
// broken system.
func TestAddingAWindowAppliesItImmediately(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Devices: []string{mac}}}}
	srv, _, fw := newProfileServer(t, []registry.Device{{MAC: mac}}, ps, []string{mac}, nil)

	now := time.Now().In(time.Local)
	day := strings.ToLower(now.Format("Mon"))
	from := now.Add(-1 * time.Hour).Format("15:04")
	to := now.Add(1 * time.Hour).Format("15:04")

	rec := post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"eli"}, "day": {day}, "start": {from}, "end": {to}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if len(fw.blocked) != 1 || fw.blocked[0] != mac {
		t.Fatalf("the firewall should already be blocking, got %v", fw.blocked)
	}

	// And the page must therefore NOT report drift.
	views, err := srv.profileViews(time.Now().In(time.Local))
	if err != nil {
		t.Fatal(err)
	}
	if views[0].Drifted() {
		t.Errorf("no drift should be reported straight after a change: %q", views[0].Reason)
	}
}

// Schedules are evaluated in the CONFIGURED zone, not the process default.
// On OpenWrt the default is UTC, so a 22:00 window would fire an hour out in
// British summer time and nothing would say so.
func TestSchedulesUseTheConfiguredTimezone(t *testing.T) {
	london, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Skipf("no tzdata in this test binary: %v", err)
	}
	mac := "aa:bb:cc:dd:ee:01"
	// A window covering 12:00-13:00 London time.
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name: "eli", Devices: []string{mac},
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "12:00", End: "13:00"}},
	}}}
	store := &memStore{reg: &registry.Registry{Devices: []registry.Device{{MAC: mac}}}}
	sch := &fakeSchedule{ps: ps}
	fw := &fakeFirewall{live: []string{mac}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(store, sch, fw, log, "", "", london, nil)

	// 11:20 UTC is 12:20 in London during BST: inside the window.
	utcNoonish := time.Date(2026, 7, 3, 11, 20, 0, 0, time.UTC)
	views, err := srv.profileViews(utcNoonish.In(london))
	if err != nil {
		t.Fatal(err)
	}
	if !views[0].ShouldBeBlocked {
		t.Error("12:20 London is inside a 12:00-13:00 window; evaluating in UTC is the bug this guards")
	}
	// And 12:20 UTC is 13:20 London: outside.
	views, err = srv.profileViews(time.Date(2026, 7, 3, 12, 20, 0, 0, time.UTC).In(london))
	if err != nil {
		t.Fatal(err)
	}
	if views[0].ShouldBeBlocked {
		t.Error("13:20 London is outside the window")
	}
}

// A freshly created profile has no devices, so there is no MAC to block and
// "should be blocked" is satisfied vacuously. Reporting drift there was a real
// bug: every new profile tripped it the moment a window was added, before any
// device had been assigned, which reads as a broken system.
func TestProfileWithNoDevicesNeverReportsDrift(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name:    "brand-new",
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "00:00", End: "23:59"}},
	}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := views[0]
	if !v.ShouldBeBlocked {
		t.Fatal("the window covers now, so the schedule should say blocked")
	}
	if v.Drifted() {
		t.Errorf("a profile with no devices cannot drift, got reason %q", v.Reason)
	}
	if !v.NeedsDevices || v.Warning == "" {
		t.Error("a profile with no devices should carry a warning")
	}
	// The badge must report the schedule's verdict. Flattening this to
	// "allowed" concealed the fact that a window was active.
	if v.StateLabel != "no devices, would be blocked" {
		t.Errorf("badge should state what would happen, got %q", v.StateLabel)
	}
}

func TestEmptyProfileOutsideAWindowSaysWouldBeAllowed(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if views[0].StateLabel != "no devices, would be allowed" {
		t.Errorf("got %q", views[0].StateLabel)
	}
}

func TestBadgeLabelsForTheOrdinaryStates(t *testing.T) {
	// The control: the empty-profile wording must not have leaked into the
	// normal cases.
	mac := "aa:bb:cc:dd:ee:01"
	blockedPS := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name: "eli", Devices: []string{mac},
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "00:00", End: "23:59"}}}}}
	srv, _, _ := newProfileServer(t, []registry.Device{{MAC: mac}}, blockedPS, []string{mac}, []string{mac})
	views, _ := srv.profileViews(time.Now())
	if views[0].StateLabel != "blocked" || views[0].StateClass != "off" {
		t.Errorf("blocked profile: got %q/%q", views[0].StateLabel, views[0].StateClass)
	}

	freePS := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Devices: []string{mac}}}}
	srv2, _, _ := newProfileServer(t, []registry.Device{{MAC: mac}}, freePS, []string{mac}, nil)
	views2, _ := srv2.profileViews(time.Now())
	if views2[0].StateLabel != "allowed" || views2[0].StateClass != "on" {
		t.Errorf("allowed profile: got %q/%q", views2[0].StateLabel, views2[0].StateClass)
	}
}

// A schedule with nothing to apply it to enforces nothing while looking
// configured. That must be warned about whether or not a window happens to be
// active at the moment you look.
func TestProfileWithWindowsButNoDevicesWarnsOutsideTheWindowToo(t *testing.T) {
	// A window that is definitely NOT active now.
	now := time.Now()
	dead := now.Add(3 * time.Hour)
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name: "eli",
		Windows: []schedule.Window{{
			Days:  []schedule.Day{schedule.Day(strings.ToLower(dead.Format("Mon")))},
			Start: dead.Format("15:04"), End: dead.Add(time.Hour).Format("15:04"),
		}},
	}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	views, err := srv.profileViews(now)
	if err != nil {
		t.Fatal(err)
	}
	v := views[0]
	if v.ShouldBeBlocked {
		t.Skip("the generated window happens to cover now; not the case under test")
	}
	if !v.NeedsDevices {
		t.Fatal("the warning must not depend on a window being active")
	}
	if !strings.Contains(v.Warning, "block nothing") {
		t.Errorf("the warning should say the windows do nothing, got %q", v.Warning)
	}
	if v.Drifted() {
		t.Error("still not drift")
	}
}

func TestProfileWithDevicesCarriesNoWarning(t *testing.T) {
	// The control: without this, "always warn" would pass the tests above.
	mac := "aa:bb:cc:dd:ee:01"
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli", Devices: []string{mac}}}}
	srv, _, _ := newProfileServer(t, []registry.Device{{MAC: mac}}, ps, []string{mac}, nil)
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if views[0].NeedsDevices || views[0].Warning != "" {
		t.Errorf("a profile with devices must not be warned about: %q", views[0].Warning)
	}
}

func TestHomeRendersTheNoDevicesWarning(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name:    "eli",
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "22:00", End: "08:00"}},
	}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	if !strings.Contains(rec.Body.String(), "no devices assigned") {
		t.Error("the warning should be visible on the page, not only in the struct")
	}
}

// The opposite failure: counting "any device blocked" as blocked would let a
// half-enforced bedtime read as fine, which is a child online on their laptop
// while their phone is cut off.
func TestPartiallyBlockedProfileIsDrift(t *testing.T) {
	m1, m2 := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name: "eli", Devices: []string{m1, m2},
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "00:00", End: "23:59"}},
	}}}
	srv, _, _ := newProfileServer(t,
		[]registry.Device{{MAC: m1}, {MAC: m2}}, ps,
		[]string{m1, m2}, []string{m1}) // only one of the two is blocked
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := views[0]
	if !v.Partial {
		t.Error("one of two devices blocked is partial enforcement")
	}
	if !v.Drifted() {
		t.Error("partial enforcement must be reported as drift")
	}
	if v.Blocked {
		t.Error("a profile is only blocked when EVERY device is")
	}
	if !strings.Contains(v.Reason, "1 of 2") {
		t.Errorf("the reason should say how many, got %q", v.Reason)
	}
}

func TestFullyBlockedProfileIsNotDrift(t *testing.T) {
	m1, m2 := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{
		Name: "eli", Devices: []string{m1, m2},
		Windows: []schedule.Window{{Days: schedule.AllDays, Start: "00:00", End: "23:59"}},
	}}}
	srv, _, _ := newProfileServer(t,
		[]registry.Device{{MAC: m1}, {MAC: m2}}, ps, []string{m1, m2}, []string{m1, m2})
	views, err := srv.profileViews(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if views[0].Drifted() || !views[0].Blocked {
		t.Errorf("every device blocked inside a window is correct, got drift=%v reason=%q",
			views[0].Drifted(), views[0].Reason)
	}
}

// The add-window form must arrive with every day ticked.
//
// The alternative, treating "no days" as "every day", is rejected on purpose:
// an unspecified field silently meaning everything is the exact busybox crond
// behaviour that made the old schedules untrustworthy, and `"days": []` would
// read as "never" to anyone opening the config.
func TestAddWindowFormDefaultsToEveryDayTicked(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	body := rec.Body.String()
	for _, d := range schedule.AllDays {
		want := `name="day" value="` + string(d) + `" checked`
		if !strings.Contains(body, want) {
			t.Errorf("%s should be ticked by default", d)
		}
	}
	if got := strings.Count(body, `name="day"`); got != len(schedule.AllDays) {
		t.Errorf("want %d day checkboxes, got %d", len(schedule.AllDays), got)
	}
}

// And unticking them all is still refused, with a message that says what to do.
func TestSubmittingNoDaysIsStillAnError(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/window/add", url.Values{
		"name": {"eli"}, "start": {"22:00"}, "end": {"08:00"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatal("a window with no days must be refused, not silently made every-day")
	}
	if !strings.Contains(loc, "tick+the+days") && !strings.Contains(loc, "tick%20the%20days") {
		t.Errorf("the error should say what to do, got %q", loc)
	}
	p, _ := sch.ps.Find("eli")
	if len(p.Windows) != 0 {
		t.Error("nothing should have been saved")
	}
}
