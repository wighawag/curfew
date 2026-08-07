package httpui

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/registry"
)

// fakeFirewall stands in for nftables so the UI is testable without a kernel.
type fakeFirewall struct {
	live      []string
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
	return New(store, fw, log, "", ""), store, fw
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
	srv := New(store, fw, log, "parent", "hunter2")
	h := srv.Handler()

	for _, path := range []string{"/", "/api/devices"} {
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
	srv := New(store, &fakeFirewall{}, log, "parent", "hunter2")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
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
	srv := New(store, &fakeFirewall{}, log, "parent", "hunter2")
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
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
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
	authed := New(authStore, &fakeFirewall{}, log, "parent", "hunter2")
	rec = post(t, authed.Handler(), "/devices/remove", url.Values{"mac": {"aa:bb:cc:dd:ee:01"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if len(authStore.reg.Devices) != 1 {
		t.Error("an unauthenticated removal must change nothing")
	}
}
