package httpui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/dnsnames"
	"github.com/wighawag/curfew/internal/registry"
)

// The devices page adds and removes LOCAL DNS NAMES with the same rules
// `curfew push` runs (internal/dnsnames), against the router's own config.

const igcMAC = "38:05:25:3a:b0:70"

func namesServer(t *testing.T, devices []registry.Device) (*Server, *memStore) {
	t.Helper()
	srv, store, _ := newTestServer(t, devices, nil)
	srv.UseNameContext(func() (dnsnames.Context, error) {
		return dnsnames.Context{Known: true, LocalDomains: []string{"lan"},
			RouterHostnames: []string{"0.openwrt.pool.ntp.org"}}, nil
	})
	return srv, store
}

func igcDevice(names ...string) registry.Device {
	return registry.Device{MAC: igcMAC, Name: "workstation igc", IP: "192.168.1.122", DNSNames: names}
}

func TestThePageAddsALocalDNSName(t *testing.T) {
	srv, store := namesServer(t, []registry.Device{igcDevice()})
	rec := post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"*.LAN.telemaque.ska.sh"}, "action": {"add"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if got := strings.Join(store.reg.Devices[0].DNSNames, ","); got != "*.lan.telemaque.ska.sh" {
		t.Fatalf("not saved canonically: %q", got)
	}
	if loc := location(rec); !strings.Contains(loc, "-> 192.168.1.122") {
		t.Errorf("the notice should say what it answers: %q", loc)
	}
}

func TestThePageShowsWarnings(t *testing.T) {
	srv, _ := namesServer(t, []registry.Device{igcDevice()})
	rec := post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"ska.sh"}, "action": {"add"}})
	if !strings.Contains(location(rec), "every name in ska.sh") {
		t.Errorf("the two-label warning was not shown: %q", location(rec))
	}
}

// The same refusals as push, including the router-context ones the CLI alone
// cannot make, and nothing saved.
func TestThePageRefusesWhatPushWouldRefuse(t *testing.T) {
	for name, why := range map[string]string{
		"printer.lan":     "local domain",
		"*.pool.ntp.org":  "the router itself",
		"*.sh":            "top-level domain",
		"bad_name.ex.com": "only letters",
		"x.local":         "mDNS",
	} {
		srv, store := namesServer(t, []registry.Device{igcDevice()})
		rec := post(t, srv.Handler(), "/devices/dns-name",
			url.Values{"mac": {igcMAC}, "name": {name}, "action": {"add"}})
		if len(store.reg.Devices[0].DNSNames) != 0 {
			t.Errorf("%s: a refused name was saved", name)
		}
		if !strings.Contains(location(rec), why) {
			t.Errorf("%s: want the reason to mention %q, got %q", name, why, location(rec))
		}
	}
}

func TestThePageRefusesANameWithoutAFixedAddress(t *testing.T) {
	d := igcDevice()
	d.IP = ""
	srv, store := namesServer(t, []registry.Device{d})
	rec := post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"*.lan.telemaque.ska.sh"}, "action": {"add"}})
	if len(store.reg.Devices[0].DNSNames) != 0 || !strings.Contains(location(rec), "fixed address") {
		t.Errorf("want a refusal about the fixed address: %q %+v", location(rec), store.reg.Devices[0])
	}
}

func TestThePageRemovesANameEvenWhenTheRouterCannotBeRead(t *testing.T) {
	srv, store, _ := newTestServer(t, []registry.Device{igcDevice("*.lan.telemaque.ska.sh", "nas.home.arpa")}, nil)
	srv.UseNameContext(func() (dnsnames.Context, error) { return dnsnames.Context{}, errors.New("uci is gone") })
	post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"nas.home.arpa"}, "action": {"remove"}})
	if got := strings.Join(store.reg.Devices[0].DNSNames, ","); got != "*.lan.telemaque.ska.sh" {
		t.Errorf("remove did not remove: %q", got)
	}
}

func TestThePageRefusesToAddANameItCannotCheck(t *testing.T) {
	srv, store, _ := newTestServer(t, []registry.Device{igcDevice()}, nil)
	rec := post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"*.lan.telemaque.ska.sh"}, "action": {"add"}})
	if len(store.reg.Devices[0].DNSNames) != 0 || location(rec) == "|" {
		t.Errorf("an unchecked name was saved, or not explained: %q", location(rec))
	}
}

func TestThePageRefusesToClearTheFixedAddressOfADeviceWithNames(t *testing.T) {
	srv, store := namesServer(t, []registry.Device{igcDevice("*.lan.telemaque.ska.sh")})
	rec := post(t, srv.Handler(), "/devices/ip", url.Values{"mac": {igcMAC}, "clear": {"1"}})
	if store.reg.Devices[0].IP != "192.168.1.122" || !strings.Contains(location(rec), "remove-dns-name") {
		t.Errorf("clear must be refused while names exist: %q %+v", location(rec), store.reg.Devices[0])
	}
}

func TestThePageNeverRegistersADeviceByNamingIt(t *testing.T) {
	srv, store := namesServer(t, nil)
	post(t, srv.Handler(), "/devices/dns-name",
		url.Values{"mac": {igcMAC}, "name": {"*.lan.telemaque.ska.sh"}, "action": {"add"}})
	if len(store.reg.Devices) != 0 {
		t.Errorf("naming registered a device: %+v", store.reg.Devices)
	}
}

func TestThePageShowsTheNames(t *testing.T) {
	srv, _ := namesServer(t, []registry.Device{igcDevice("*.lan.telemaque.ska.sh"), {MAC: shyrka, Name: "shyrka"}})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<code>*.lan.telemaque.ska.sh</code>") {
		t.Errorf("the name is not shown:\n%s", body)
	}
	if !strings.Contains(body, "needs a fixed address") {
		t.Errorf("a device without a fixed address should say why it cannot be named:\n%s", body)
	}
}

func TestNamingRejectsGET(t *testing.T) {
	srv, store := namesServer(t, []registry.Device{igcDevice()})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/devices/dns-name?mac="+igcMAC+"&name=a.home.arpa&action=add", nil))
	if rec.Code != http.StatusMethodNotAllowed || len(store.reg.Devices[0].DNSNames) != 0 {
		t.Errorf("a GET changed names: %d", rec.Code)
	}
}
