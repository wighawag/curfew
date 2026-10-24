package httpui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/leases"
	"github.com/wighawag/curfew/internal/registry"
)

// The devices page sets and clears a device's FIXED ADDRESS, validated on the
// router with the same checks `curfew push` runs (leases.Survey.CheckFixed),
// so the page and the CLI cannot disagree about what is allowed.

const (
	shyrka  = "84:47:09:84:8e:b2"
	printer = "f8:25:51:09:38:38"
)

func routerSurvey(t *testing.T) leases.Survey {
	t.Helper()
	lan, err := leases.ParseLAN("network.lan.ipaddr='192.168.1.1/24'\n",
		"dhcp.lan=dhcp\ndhcp.lan.start='100'\ndhcp.lan.limit='150'\ndhcp.lan.leasetime='12h'\n")
	if err != nil {
		t.Fatal(err)
	}
	return leases.Survey{
		LAN: lan,
		Hosts: []leases.Host{
			{Section: "@host[0]", MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.11", Name: "their-nas"},
			{Section: leases.SectionFor(shyrka), MAC: shyrka, IP: "192.168.1.226"},
		},
		Leases: []leases.Lease{{MAC: shyrka, IP: "192.168.1.226", Expires: time.Now().Add(6 * time.Hour)}},
		Now:    time.Now(),
	}
}

func fixedServer(t *testing.T, devices []registry.Device) (*Server, *memStore) {
	t.Helper()
	srv, store, _ := newTestServer(t, devices, nil)
	s := routerSurvey(t)
	srv.UseAddresses(func() (leases.Survey, error) { return s, nil })
	return srv, store
}

func location(rec *httptest.ResponseRecorder) string {
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("error") + "|" + u.Query().Get("notice")
}

func TestThePageSetsAFixedAddressAndSaysWhenTheDeviceMoves(t *testing.T) {
	srv, store := fixedServer(t, []registry.Device{{MAC: shyrka, Name: "shyrka"}})
	rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "ip": {"192.168.1.150"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if store.reg.Devices[0].IP != "192.168.1.150" {
		t.Fatalf("the fixed address was not saved: %+v", store.reg.Devices)
	}
	loc := location(rec)
	for _, want := range []string{"inside the DHCP pool", "next DHCP renewal", "192.168.1.226"} {
		if !strings.Contains(loc, want) {
			t.Errorf("the notice should say %q, got %q", want, loc)
		}
	}
}

// Same refusals as push, and nothing saved.
func TestThePageRefusesWhatThePushWouldRefuse(t *testing.T) {
	for ip, why := range map[string]string{
		"192.168.1.11":  "@host[0]",   // a foreign entry already reserves it
		"192.168.1.1":   "the router", // the router's own address
		"192.168.1.255": "broadcast",
		"10.0.0.5":      "outside",
		"nonsense":      "not an IPv4",
	} {
		srv, store := fixedServer(t, []registry.Device{{MAC: shyrka, Name: "shyrka"}})
		rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "ip": {ip}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: want a redirect carrying the error, got %d", ip, rec.Code)
		}
		if store.reg.Devices[0].IP != "" {
			t.Errorf("%s: a refused address was saved", ip)
		}
		if !strings.Contains(location(rec), why) {
			t.Errorf("%s: want the reason to mention %q, got %q", ip, why, location(rec))
		}
	}
}

func TestThePageRefusesAnotherDevicesFixedAddress(t *testing.T) {
	srv, store := fixedServer(t, []registry.Device{
		{MAC: shyrka, Name: "shyrka"}, {MAC: printer, Name: "printer", IP: "192.168.1.150"},
	})
	rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "ip": {"192.168.1.150"}})
	if store.reg.Devices[0].IP != "" {
		t.Error("a duplicate fixed address was saved")
	}
	if !strings.Contains(location(rec), printer) {
		t.Errorf("the refusal should name the holder, got %q", location(rec))
	}
}

func TestThePageClearsAFixedAddressWithoutAskingTheRouter(t *testing.T) {
	srv, store, _ := newTestServer(t, []registry.Device{{MAC: shyrka, Name: "shyrka", IP: "192.168.1.150"}}, nil)
	srv.UseAddresses(func() (leases.Survey, error) { return leases.Survey{}, errors.New("uci is gone") })
	rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "clear": {"1"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if store.reg.Devices[0].IP != "" {
		t.Errorf("clear did not clear: %+v", store.reg.Devices[0])
	}
}

// Without the router's view nothing can be validated, so nothing is accepted.
func TestThePageRefusesToSetAnAddressItCannotCheck(t *testing.T) {
	srv, store, _ := newTestServer(t, []registry.Device{{MAC: shyrka, Name: "shyrka"}}, nil)
	rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "ip": {"192.168.1.150"}})
	if store.reg.Devices[0].IP != "" {
		t.Error("an unchecked address was saved")
	}
	if location(rec) == "|" {
		t.Error("the refusal must be explained")
	}
}

func TestThePageNeverRegistersADeviceBySettingItsAddress(t *testing.T) {
	srv, store := fixedServer(t, nil)
	post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {shyrka}, "ip": {"192.168.1.150"}})
	if len(store.reg.Devices) != 0 {
		t.Errorf("setting an address registered a device: %+v", store.reg.Devices)
	}
}

func TestSettingAnAddressRejectsGET(t *testing.T) {
	srv, store := fixedServer(t, []registry.Device{{MAC: shyrka, Name: "shyrka"}})
	req := httptest.NewRequest(http.MethodGet, "/devices/ip?mac="+shyrka+"&ip=192.168.1.150", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || store.reg.Devices[0].IP != "" {
		t.Errorf("a GET changed an address: %d %+v", rec.Code, store.reg.Devices[0])
	}
}

func TestThePageShowsTheFixedAndThePinnedAddress(t *testing.T) {
	srv, _ := fixedServer(t, []registry.Device{
		{MAC: shyrka, Name: "shyrka"}, {MAC: printer, Name: "printer", IP: "192.168.1.10"},
	})
	req := httptest.NewRequest(http.MethodGet, "/devices/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `value="192.168.1.10"`) {
		t.Errorf("the printer's fixed address is not shown:\n%s", body)
	}
	if !strings.Contains(body, "192.168.1.226") {
		t.Errorf("shyrka's current pin is not shown:\n%s", body)
	}
	if !strings.Contains(body, `action="/devices/ip"`) {
		t.Error("there is no form to set an address")
	}
}
