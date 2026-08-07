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

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/policy"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// These tests drive the REAL policy layer, with only the kernel replaced by a
// double. A hand-written fake core would let the page and the rules it is
// supposed to reflect drift apart, which is the failure mode this project
// keeps rediscovering, so the UI is tested against the same block, unblock and
// ticket semantics the daemon runs.

// fakeFirewall stands in for nftables so the UI is testable without a kernel.
type fakeSchedule struct{ ps *schedule.Profiles }

// Load and Save copy EVERY field, including the household budget settings.
// A double that quietly drops a field is not a dumb double, it is a double
// with an opinion: it would make a budget setting that never reaches the
// policy layer look like one that works.
func (f *fakeSchedule) Load() (*schedule.Profiles, error) {
	if f.ps == nil {
		return &schedule.Profiles{Profiles: []schedule.Profile{}}, nil
	}
	cp := *f.ps
	cp.Profiles = append([]schedule.Profile(nil), f.ps.Profiles...)
	return &cp, nil
}
func (f *fakeSchedule) Save(ps *schedule.Profiles) error {
	cp := *ps
	cp.Profiles = append([]schedule.Profile(nil), ps.Profiles...)
	f.ps = &cp
	return nil
}

// fakeFirewall is an in-memory stand-in for nftables: four sets and a ticket
// timer, and no behaviour of its own.
//
// Keeping the enforcer's logic OUT of the double is deliberate, and was
// learned here: a version of this double that reproduced the rule "a rebuild
// drops a ticket for a manually blocked MAC" made the tests pass with that
// rule deleted from the code. The page derives a device's state by walking
// contract.Tiers, so if the double also encoded an order, a wrong order could
// agree with itself and pass. What the chain does to a packet is settled in
// internal/enforce, with packets.
type fakeFirewall struct {
	live      []string
	blocked   []string
	manual    []string
	tickets   map[string]time.Duration
	applyErr  error
	readErr   error
	grantErr  error
	applyCall int
	grants    int
	cancels   int
}

func (f *fakeFirewall) EnsureApplied(d enforce.Desired) (bool, error) {
	f.applyCall++
	if f.applyErr != nil {
		return false, f.applyErr
	}
	f.live = append([]string(nil), d.Allowed...)
	f.blocked = append([]string(nil), d.Blocked...)
	f.manual = append([]string(nil), d.Manual...)
	return true, nil
}

func (f *fakeFirewall) GrantTicket(macs []string, d time.Duration) error {
	if f.grantErr != nil {
		return f.grantErr
	}
	f.grants++
	if f.tickets == nil {
		f.tickets = map[string]time.Duration{}
	}
	for _, m := range macs {
		f.tickets[m] = d
	}
	return nil
}

func (f *fakeFirewall) CancelTickets(macs []string) error {
	f.cancels++
	for _, m := range macs {
		delete(f.tickets, m)
	}
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

func (f *fakeFirewall) ManualBlocked() ([]string, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return append([]string(nil), f.manual...), nil
}

func (f *fakeFirewall) Tickets() (map[string]time.Duration, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	out := map[string]time.Duration{}
	for m, d := range f.tickets {
		out[m] = d
	}
	return out, nil
}

// memState is the persisted block state, in memory.
type memState struct {
	st      *blockstate.State
	saveErr error
}

// Load copies every member of the persisted state (the authoritative list is
// the blockstate.State type itself). Dropping the budget members here would
// make a spent allowance vanish on every read, so the page would show a fresh
// budget while the firewall blocked the child.
func (m *memState) Load() (*blockstate.State, error) {
	if m.st == nil {
		return &blockstate.State{ManualBlocked: []string{}}, nil
	}
	cp := &blockstate.State{
		ManualBlocked: append([]string(nil), m.st.ManualBlocked...),
		BudgetDay:     m.st.BudgetDay,
	}
	if m.st.Budget != nil {
		cp.Budget = map[string]budget.State{}
		for k, v := range m.st.Budget {
			cp.Budget[k] = v
		}
	}
	return cp, nil
}

func (m *memState) Save(s *blockstate.State) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	cp := &blockstate.State{
		ManualBlocked: append([]string(nil), s.ManualBlocked...),
		BudgetDay:     s.BudgetDay,
	}
	if s.Budget != nil {
		cp.Budget = map[string]budget.State{}
		for k, v := range s.Budget {
			cp.Budget[k] = v
		}
	}
	m.st = cp
	return nil
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
	srv, _ := assemble(store, &fakeSchedule{}, &memState{}, fw, "", "", time.Local)
	return srv, store, fw
}

// assemble wires the page to the real policy core over in-memory stores.
func assemble(store *memStore, sch *fakeSchedule, st *memState, fw *fakeFirewall,
	user, password string, loc *time.Location) (*Server, *policy.Core) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core := policy.New(store, sch, st, fw, loc, log)
	return New(store, sch, fw, core, log, user, password, loc), core
}

func newAuthedServer(store *memStore, fw *fakeFirewall) *Server {
	srv, _ := assemble(store, &fakeSchedule{}, &memState{}, fw, "parent", "hunter2", time.Local)
	return srv
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
	h := newAuthedServer(store, fw).Handler()

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
	srv := newAuthedServer(store, &fakeFirewall{})
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
	srv := newAuthedServer(store, &fakeFirewall{})
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
	authed := newAuthedServer(authStore, &fakeFirewall{})
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
	srv, _, sch, fw := newProfileServerWithState(t, devices, ps, allowed, blocked, nil)
	return srv, sch, fw
}

// newProfileServerWithState is the same, plus the persisted manual blocks and
// the state store the test can inspect afterwards.
func newProfileServerWithState(t *testing.T, devices []registry.Device, ps *schedule.Profiles,
	allowed, blocked, manuallyBlocked []string) (*Server, *memState, *fakeSchedule, *fakeFirewall) {
	t.Helper()
	store := &memStore{reg: &registry.Registry{Devices: devices}}
	sch := &fakeSchedule{ps: ps}
	fw := &fakeFirewall{live: allowed, blocked: blocked}
	st := &memState{}
	if manuallyBlocked != nil {
		st.st = &blockstate.State{ManualBlocked: manuallyBlocked}
	}
	srv, _ := assemble(store, sch, st, fw, "", "", time.Local)
	return srv, st, sch, fw
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
	// "nothing" rather than "no window": with manual blocks in the model, the
	// absent explanation could be either a window or a parent's decision.
	if !strings.Contains(views[0].Reason, "nothing says it should be") {
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
	st := &memState{}
	fw := &fakeFirewall{}
	srv, _ := assemble(store, sch, st, fw, "parent", "hunter2", time.Local)
	// The ticket and block routes are on this list for the reason ADR 0006
	// gives: this page is served BY the router, so it is reachable by the very
	// device being blocked. A measured attack had a blocked child load the
	// unauthenticated page and issue itself a ticket.
	for _, path := range []string{
		"/profiles/create", "/profiles/delete", "/profiles/devices",
		"/profiles/window/add", "/profiles/window/remove",
		"/profiles/block", "/profiles/unblock", "/profiles/ticket",
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
	if st.st != nil {
		t.Errorf("an unauthenticated request must not record a block: %+v", st.st)
	}
	if fw.grants != 0 {
		t.Errorf("an unauthenticated request must not issue a ticket, got %d", fw.grants)
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
	srv, _ := assemble(store, sch, &memState{}, fw, "", "", london)

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

// --- manual blocks and tickets -------------------------------------------
//
// Every page assertion below ends in assertWholePage. A template error halfway
// down leaves a 200 with a truncated body, and a real bug shipped here that
// way: the status near the top looked right while the forms below it had
// silently vanished.

func eliHousehold() *schedule.Profiles {
	return &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"},
			Windows: []schedule.Window{{Days: schedule.AllDays, Start: "22:00", End: "08:00"}}},
		{Name: "dad", Devices: []string{"aa:bb:cc:dd:ee:02"}},
	}}
}

func eliDevices() []registry.Device {
	return []registry.Device{
		{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"},
		{MAC: "aa:bb:cc:dd:ee:02", Name: "dad phone"},
	}
}

func getHome(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	return rec
}

func TestHomeOffersABlockButtonAndTicketDurations(t *testing.T) {
	srv, _, _ := newProfileServer(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil)
	body := getHome(t, srv).Body.String()

	if got := strings.Count(body, `action="/profiles/block"`); got != 2 {
		t.Errorf("want a block button for each of the 2 profiles, got %d", got)
	}
	if strings.Contains(body, `action="/profiles/unblock"`) {
		t.Error("nothing is blocked, so no unblock button should be offered")
	}
	// Four durations per profile, and each must carry its OWN profile name:
	// a shared name here would block or ticket the wrong child.
	if got := strings.Count(body, `action="/profiles/ticket"`); got != 2*len(ticketDurations) {
		t.Errorf("want %d ticket buttons, got %d", 2*len(ticketDurations), got)
	}
	if !strings.Contains(body, `name="minutes" value="30"`) {
		t.Error("the 30 minute tap should be there")
	}
	for _, name := range []string{"eli", "dad"} {
		if !strings.Contains(body, `<input type="hidden" name="name" value="`+name+`">`) {
			t.Errorf("the controls must carry the profile they belong to, %q missing", name)
		}
	}
}

func TestBlockingFromThePageEnforcesItAndSwapsTheControls(t *testing.T) {
	srv, st, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/block", url.Values{"name": {"eli"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("unexpected error: %s", loc)
	}
	if st.st == nil || !st.st.IsBlocked("eli") {
		t.Errorf("the decision must be persisted, got %+v", st.st)
	}
	if len(fw.manual) != 1 || fw.manual[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("eli's device must be in the manual tier of the firewall, got %v", fw.manual)
	}

	body := getHome(t, srv).Body.String()
	if !strings.Contains(body, "unblock eli") {
		t.Error("a blocked profile must offer the way back")
	}
	// Ticket buttons for eli must be gone: a ticket cannot lift this block, so
	// offering one would be a button that does nothing.
	if got := strings.Count(body, `action="/profiles/ticket"`); got != len(ticketDurations) {
		t.Errorf("only dad should still offer tickets, got %d buttons", got)
	}
	if !strings.Contains(body, "Unblock first") {
		t.Error("the page should say why the ticket buttons are gone")
	}
}

// The trap ADR 0006 names: a status derived without a manual_blocked_macs case
// reads a manually blocked profile as ALLOWED.
func TestAManuallyBlockedProfileNeverReadsAsAllowed(t *testing.T) {
	srv, _, _, _ := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil, []string{"eli"})
	if err := srv.core.Reconcile(); err != nil {
		t.Fatal(err)
	}
	noon := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	views, err := srv.profileViews(noon)
	if err != nil {
		t.Fatal(err)
	}
	eli, dad := views[1], views[0] // sorted by name: adults/dad first
	if eli.Name != "eli" || dad.Name != "dad" {
		t.Fatalf("fixture confusion: %s, %s", views[0].Name, views[1].Name)
	}
	if !eli.Blocked {
		t.Error("a manually blocked profile must read as blocked, not allowed")
	}
	if eli.Devices[0].Allowed {
		t.Error("its device must read as not allowed")
	}
	if eli.StateLabel != "blocked by you" {
		t.Errorf("the badge should name the reason, got %q", eli.StateLabel)
	}
	// It is NOT drift: the firewall and the parent's decision agree.
	if eli.Drifted() {
		t.Errorf("a manual block is intended state, not drift: %q", eli.Reason)
	}
	// Control: the profile nobody blocked still reads as allowed.
	if dad.Blocked || !dad.Devices[0].Allowed {
		t.Error("the unblocked profile must still read as allowed")
	}
}

func TestATicketFromThePageIsGrantedAndShown(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/ticket", url.Values{
		"name": {"eli"}, "minutes": {"30"}})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("unexpected error: %s", loc)
	}
	if fw.tickets["aa:bb:cc:dd:ee:01"] != 30*time.Minute {
		t.Fatalf("the ticket must reach the firewall, got %v", fw.tickets)
	}
	if fw.tickets["aa:bb:cc:dd:ee:02"] != 0 {
		t.Error("ticketing eli must not ticket dad")
	}

	// The page shows the KERNEL's remaining time, rounded down, so it can
	// never promise time that has already gone.
	fw.tickets["aa:bb:cc:dd:ee:01"] = 23*time.Minute + 45*time.Second
	body := getHome(t, srv).Body.String()
	if !strings.Contains(body, "23m left") {
		t.Errorf("the page should show the time left, got:\n%s", body)
	}
}

// A ticket inside a bedtime window is the point of a ticket. The page must
// read that as intended, not as the firewall disagreeing with the schedule.
func TestATicketedProfileInsideItsWindowIsNotDrift(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
		[]string{"aa:bb:cc:dd:ee:01"}, nil)
	fw.tickets = map[string]time.Duration{"aa:bb:cc:dd:ee:01": 25 * time.Minute}

	bedtime := time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	views, err := srv.profileViews(bedtime)
	if err != nil {
		t.Fatal(err)
	}
	eli := views[1]
	if eli.Name != "eli" {
		t.Fatalf("fixture confusion: %+v", eli.Name)
	}
	if eli.Blocked {
		t.Error("a live ticket must show the profile as reachable")
	}
	if eli.Drifted() {
		t.Errorf("a ticket overriding a window is intended, not drift: %q", eli.Reason)
	}
	if !strings.Contains(eli.Reason, "then the window takes over again") {
		t.Errorf("the page should say the window resumes on expiry, got %q", eli.Reason)
	}
	// And once it lapses, with no bookkeeping anywhere, the window is back.
	fw.tickets = nil
	views, err = srv.profileViews(bedtime)
	if err != nil {
		t.Fatal(err)
	}
	if !views[1].Blocked || views[1].Drifted() {
		t.Errorf("after expiry the window must simply apply again, got %+v", views[1].StateLabel)
	}
}

func TestATicketWithNonsenseMinutesIsRefused(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)
	for _, bad := range []string{"", "soon", "-5", "0"} {
		rec := post(t, srv.Handler(), "/profiles/ticket", url.Values{
			"name": {"eli"}, "minutes": {bad}})
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
			t.Errorf("minutes=%q should be refused, got %q", bad, loc)
		}
	}
	if fw.grants != 0 {
		t.Errorf("nothing should have been granted, got %d", fw.grants)
	}
}

func TestAFailedTicketIsReportedRatherThanClaimed(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)
	fw.grantErr = errors.New("table curfew is not present")
	rec := post(t, srv.Handler(), "/profiles/ticket", url.Values{
		"name": {"eli"}, "minutes": {"30"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatalf("a firewall failure must be surfaced, got %q", loc)
	}
	if !strings.Contains(loc, "not+present") && !strings.Contains(loc, "not%20present") {
		t.Errorf("the message should say what went wrong, got %q", loc)
	}
}

func TestBlockingAnUnknownProfileIsAnError(t *testing.T) {
	srv, st, _, _ := newProfileServerWithState(t, eliDevices(), eliHousehold(), nil, nil, nil)
	rec := post(t, srv.Handler(), "/profiles/block", url.Values{"name": {"ghost"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("want the error surfaced, got %q", loc)
	}
	if st.st != nil && len(st.st.ManualBlocked) != 0 {
		t.Errorf("nothing should have been recorded: %+v", st.st)
	}
}

// A persisted decision must not outlive the profile it was about, or a profile
// later recreated under the same name comes back mysteriously blocked.
func TestDeletingAProfileClearsItsManualBlock(t *testing.T) {
	srv, st, sch, _ := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01"}, nil, []string{"eli"})
	rec := post(t, srv.Handler(), "/profiles/delete", url.Values{"name": {"eli"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if _, ok := sch.ps.Find("eli"); ok {
		t.Fatal("the profile should be gone")
	}
	if st.st.IsBlocked("eli") {
		t.Error("the manual block must go with the profile")
	}
}

// The devices page answers "can this device reach the internet", which is the
// whole chain, not membership of the allowlist.
func TestTheDevicePageReportsTheWholeChain(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil, []string{"eli"})
	if err := srv.core.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(fw.manual) != 1 {
		t.Fatalf("fixture: eli should be manually blocked, got %v", fw.manual)
	}
	devices, err := srv.view()
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]DeviceView{}
	for _, d := range devices {
		byMAC[d.MAC] = d
	}
	if byMAC["aa:bb:cc:dd:ee:01"].Allowed {
		t.Error("a registered but manually blocked device must not read as allowed")
	}
	if !byMAC["aa:bb:cc:dd:ee:02"].Allowed {
		t.Error("the other device must still read as allowed, or the check above proves nothing")
	}
}

// A ticket for a device that is not on the allowlist still gets it out: the
// ticket accept sits above the allowlist. Asserted here because the page must
// tell the same story the chain does.
func TestTheDevicePageShowsATicketedDeviceAsAllowed(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		nil, nil, nil)
	fw.tickets = map[string]time.Duration{"aa:bb:cc:dd:ee:01": time.Minute}
	devices, err := srv.view()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		if d.MAC == "aa:bb:cc:dd:ee:01" && !d.Allowed {
			t.Error("a device with a live ticket reaches the internet, so the page must say so")
		}
		if d.MAC == "aa:bb:cc:dd:ee:02" && d.Allowed {
			t.Error("a device with no ticket and no allowlist entry must read as blocked")
		}
	}
}

func TestHumanDurationRoundsDownAndNeverPromisesTimeThatIsGone(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "under a minute"},
		{59*time.Second + 999*time.Millisecond, "under a minute"},
		{time.Minute, "1m"},
		{89 * time.Second, "1m"},
		{25*time.Minute + 59*time.Second, "25m"},
		{time.Hour, "1h"},
		{90 * time.Minute, "1h 30m"},
		{2 * time.Hour, "2h"},
	} {
		if got := humanDuration(c.in); got != c.want {
			t.Errorf("humanDuration(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The page must reach the same verdict the chain does, on the one state where
// the tiers disagree: a MAC in BOTH the manual set and the ticket set.
//
// The core refuses to create that state, so this is about the page never
// contradicting the kernel if it arises anyway (a race, or something writing
// the set out of band). It is also what makes the tier order load-bearing for
// this file: reordering contract.Tiers breaks this test and the packet-path
// test in internal/enforce together.
func TestThePageAgreesWithTheChainWhenAMACIsInBothSets(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, nil, []string{"eli"})
	if err := srv.core.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// A ticket that should lose to the manual block.
	fw.tickets = map[string]time.Duration{"aa:bb:cc:dd:ee:01": 20 * time.Minute}

	noon := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	views, err := srv.profileViews(noon)
	if err != nil {
		t.Fatal(err)
	}
	eli := views[1]
	if eli.Name != "eli" {
		t.Fatalf("fixture confusion: %q", eli.Name)
	}
	if !eli.Blocked {
		t.Error("a manual block outranks a ticket in the chain, so the page must say blocked")
	}
	if strings.Contains(eli.StateLabel, "ticket") {
		t.Errorf("the badge must not advertise a ticket that the chain is ignoring, got %q", eli.StateLabel)
	}
	// Control: without the manual block the same ticket does free them, so the
	// assertion above is about precedence rather than tickets being ignored.
	fw.manual = nil
	views, err = srv.profileViews(noon)
	if err != nil {
		t.Fatal(err)
	}
	if views[1].Blocked {
		t.Error("with the manual block gone the ticket must let them out")
	}
}

// Right answer, wrong reason.
//
// A profile a parent blocked indefinitely, which the firewall is only holding
// down with a bedtime window, is OFFLINE, so a status that only asks
// "blocked?" reports everything as fine. It is not fine: at 08:00 the window
// lifts and the child is online while the page still says a parent blocked
// them. The page has to compare the manual tier itself, not just the verdict.
func TestAManualBlockTheFirewallIsNotEnforcingIsDrift(t *testing.T) {
	srv, _, _, fw := newProfileServerWithState(t, eliDevices(), eliHousehold(),
		[]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"},
		[]string{"aa:bb:cc:dd:ee:01"}, // held down by the WINDOW only
		[]string{"eli"})               // but a parent blocked them indefinitely
	fw.manual = nil

	bedtime := time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	views, err := srv.profileViews(bedtime)
	if err != nil {
		t.Fatal(err)
	}
	eli := views[1]
	if eli.Name != "eli" {
		t.Fatalf("fixture confusion: %q", eli.Name)
	}
	if !eli.Blocked {
		t.Fatal("the window has them offline, which is what makes this trap quiet")
	}
	if !eli.Drifted() {
		t.Error("a manual block the firewall is not enforcing must be reported, " +
			"even though the profile happens to be offline for another reason")
	}
	if !strings.Contains(eli.Reason, "not enforcing") {
		t.Errorf("the reason must name the disagreement, got %q", eli.Reason)
	}

	// Control: once the firewall really is enforcing it, the same state is not
	// drift, so the check above is about the disagreement and not about manual
	// blocks always looking wrong.
	fw.manual = []string{"aa:bb:cc:dd:ee:01"}
	views, err = srv.profileViews(bedtime)
	if err != nil {
		t.Fatal(err)
	}
	if views[1].Drifted() {
		t.Errorf("an enforced manual block is not drift: %q", views[1].Reason)
	}
}
