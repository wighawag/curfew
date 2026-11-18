package main

import (
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/registry"
)

// `curfew add-dns-name` / `remove-dns-name` edit ONLY the local device file.
// These tests point them at a temp file, so the real config/local is never
// read or written.

const igc = "38:05:25:3a:b0:70"

func loadNames(t *testing.T, path, mac string) string {
	t.Helper()
	r, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Devices {
		if d.MAC == mac {
			return strings.Join(d.DNSNames, ",")
		}
	}
	t.Fatalf("%s vanished", mac)
	return ""
}

func TestAddDNSNameByDeviceNameEditsTheLocalFileAndExplains(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: igc, Name: "workstation igc", IP: "192.168.1.122"})
	msg, err := addDNSName(path, "workstation igc", "*.lan.telemaque.ska.sh")
	if err != nil {
		t.Fatal(err)
	}
	if got := loadNames(t, path, igc); got != "*.lan.telemaque.ska.sh" {
		t.Errorf("not saved: %q", got)
	}
	for _, want := range []string{
		"*.lan.telemaque.ska.sh -> 192.168.1.122",
		"not lan.telemaque.ska.sh itself",
		"A only",
		"curfew push",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message should say %q:\n%s", want, msg)
		}
	}
}

func TestAddDNSNameRefusesWithoutAFixedAddressAndWritesNothing(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: igc, Name: "workstation igc"})
	if _, err := addDNSName(path, "workstation igc", "*.lan.telemaque.ska.sh"); err == nil ||
		!strings.Contains(err.Error(), "set-ip") {
		t.Errorf("want a refusal pointing at set-ip, got %v", err)
	}
	if got := loadNames(t, path, igc); got != "" {
		t.Errorf("a refused name was written: %q", got)
	}
}

func TestAddDNSNamePrintsWarnings(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: igc, Name: "workstation igc", IP: "192.168.1.122"})
	msg, err := addDNSName(path, igc, "ska.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "warning:") || !strings.Contains(msg, "every name in ska.sh") {
		t.Errorf("the two-label warning was not shown:\n%s", msg)
	}
}

func TestRemoveDNSName(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: igc, Name: "workstation igc", IP: "192.168.1.122",
		DNSNames: []string{"*.lan.telemaque.ska.sh", "nas.home.arpa"}})
	msg, err := removeDNSName(path, "workstation igc", "NAS.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	if got := loadNames(t, path, igc); got != "*.lan.telemaque.ska.sh" {
		t.Errorf("wrong set after removal: %q", got)
	}
	if !strings.Contains(msg, "curfew push") {
		t.Errorf("the message should say how to apply it: %q", msg)
	}
	if _, err := removeDNSName(path, "workstation igc", "nas.home.arpa"); err == nil {
		t.Error("removing a name the device does not have must be an error")
	}
}

func TestSetIPClearIsRefusedWhileTheDeviceHasNames(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: igc, Name: "workstation igc", IP: "192.168.1.122",
		DNSNames: []string{"*.lan.telemaque.ska.sh"}})
	if _, err := setIP(path, "workstation igc", "", true); err == nil ||
		!strings.Contains(err.Error(), "remove-dns-name") {
		t.Errorf("want a refusal pointing at remove-dns-name, got %v", err)
	}
	if got := loadIP(t, path, igc); got != "192.168.1.122" {
		t.Errorf("the address changed anyway: %q", got)
	}
}

func TestDNSNameArgsAcceptFlagsEitherSideAndRefuseTheWrongCount(t *testing.T) {
	a, err := parseDNSNameArgs("add-dns-name", []string{"-registry", "/tmp/x.json", "igc", "*.a.example"})
	if err != nil || a.registry != "/tmp/x.json" || a.ref != "igc" || a.name != "*.a.example" {
		t.Errorf("got %+v %v", a, err)
	}
	a, err = parseDNSNameArgs("add-dns-name", []string{"igc", "*.a.example", "--registry=/tmp/y.json"})
	if err != nil || a.registry != "/tmp/y.json" {
		t.Errorf("got %+v %v", a, err)
	}
	for _, bad := range [][]string{{}, {"igc"}, {"igc", "a.example", "b.example"}, {"-x", "igc", "a.example"}} {
		if _, err := parseDNSNameArgs("add-dns-name", bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := parseDNSNameArgs("add-dns-name", nil); err == nil || !strings.Contains(err.Error(), "quote") {
		t.Errorf("the usage should say to quote the '*': %v", err)
	}
}

// ---- push ----

const routerDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].rebind_protection='1'
dhcp.@dnsmasq[0].local='/lan/'
dhcp.@dnsmasq[0].domain='lan'
dhcp.@dnsmasq[0].port='54'
`

const routerSystem = `system.ntp=timeserver
system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'
`

type uciRunner struct{ dhcp, system string }

func (u uciRunner) Run(cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "show dhcp"):
		return u.dhcp, nil
	case strings.Contains(cmd, "show system"):
		return u.system, nil
	}
	return "", nil
}

func namedRegistry(names ...string) *registry.Registry {
	return &registry.Registry{Devices: []registry.Device{
		{MAC: igc, Name: "workstation igc", IP: "192.168.1.122", DNSNames: names},
	}}
}

func pushNames(t *testing.T, dhcp string, local, remote *registry.Registry) (errs, notes []string) {
	t.Helper()
	ctx, addr, srv, err := readNameContext(uciRunner{dhcp: dhcp, system: routerSystem})
	if err != nil {
		t.Fatal(err)
	}
	return checkPushNames(ctx, addr, srv, local, remote)
}

func TestPushAcceptsTheHouseholdsNameAndSaysWhatChanges(t *testing.T) {
	errs, notes := pushNames(t, routerDHCP, namedRegistry("*.lan.telemaque.ska.sh"), &registry.Registry{})
	if len(errs) != 0 {
		t.Fatalf("refused: %v", errs)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "*.lan.telemaque.ska.sh -> 192.168.1.122") {
		t.Errorf("no change note: %v", notes)
	}
	// Pushing the same thing again is silent.
	_, notes = pushNames(t, routerDHCP, namedRegistry("*.lan.telemaque.ska.sh"), namedRegistry("*.lan.telemaque.ska.sh"))
	if len(notes) != 0 {
		t.Errorf("an unchanged name produced notes: %v", notes)
	}
}

func TestPushRefusesANameTheRouterContextForbids(t *testing.T) {
	for _, n := range []string{"printer.lan", "*.pool.ntp.org"} {
		errs, _ := pushNames(t, routerDHCP, namedRegistry(n), &registry.Registry{})
		if len(errs) == 0 {
			t.Errorf("%s was accepted against the router's own config", n)
		}
	}
	// A hand-edited file with a name on a device that has no fixed address.
	reg := namedRegistry("*.lan.telemaque.ska.sh")
	reg.Devices[0].IP = ""
	if errs, _ := pushNames(t, routerDHCP, reg, &registry.Registry{}); len(errs) == 0 {
		t.Error("a name with no fixed address was accepted")
	}
}

func TestPushReportsAForeignDnsmasqEntryForTheSameDomain(t *testing.T) {
	dhcp := routerDHCP + `dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.99'
dhcp.@dnsmasq[0].server='/*.lan.telemaque.ska.sh/'
`
	errs, notes := pushNames(t, dhcp, namedRegistry("*.lan.telemaque.ska.sh"), &registry.Registry{})
	if len(errs) != 0 {
		t.Fatalf("a foreign entry is reported, not refused: %v", errs)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "192.168.1.99") || !strings.Contains(joined, "leaves it alone") {
		t.Errorf("the foreign entry was not reported:\n%s", joined)
	}
	// curfew's own entries, exactly as it writes them, are not foreign.
	dhcp = routerDHCP + `dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.122'
dhcp.@dnsmasq[0].server='/*.lan.telemaque.ska.sh/'
`
	_, notes = pushNames(t, dhcp, namedRegistry("*.lan.telemaque.ska.sh"), &registry.Registry{})
	if strings.Contains(strings.Join(notes, "\n"), "already has") {
		t.Errorf("curfew's own entries were reported as foreign: %v", notes)
	}
}

func TestPushRefusesAnOldDaemonWhenAnyDNSNameIsSet(t *testing.T) {
	if err := requireDNSNamesSupport(false, namedRegistry("*.lan.telemaque.ska.sh"), "root@r"); err == nil ||
		!strings.Contains(err.Error(), "curfew update root@r") {
		t.Errorf("want a refusal naming curfew update, got %v", err)
	}
	if err := requireDNSNamesSupport(false, namedRegistry(), "root@r"); err != nil {
		t.Errorf("no names, no refusal: %v", err)
	}
	if err := requireDNSNamesSupport(true, namedRegistry("*.lan.telemaque.ska.sh"), "root@r"); err != nil {
		t.Errorf("a new daemon must be accepted: %v", err)
	}
}

// Push's "the router changed since your last sync" refusal is registry.Equal,
// so a names-only change on the router must make it refuse.
func TestARouterSideNamesChangeCountsAsAChangeSinceTheLastSync(t *testing.T) {
	base := namedRegistry()
	remote := namedRegistry("nas.home.arpa")
	if registry.Equal(remote, base) {
		t.Error("push would overwrite names added on the router without --force")
	}
}
