package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for LOCAL DNS NAMES carried on a device. See
// work/specs/tasked/local-dns-names-for-a-device.md and docs/adr/0013.

func withNames(r *Registry, mac string, ns ...string) *Registry {
	for i := range r.Devices {
		if r.Devices[i].MAC == mac {
			r.Devices[i].DNSNames = ns
		}
	}
	return r
}

func dnsOf(r *Registry, mac string) string {
	for _, d := range r.Devices {
		if d.MAC == mac {
			return strings.Join(d.DNSNames, ",")
		}
	}
	return "(absent)"
}

func workstation() *Registry {
	return withIP(reg(m1, "workstation igc"), m1, "192.168.1.122")
}

func TestAddAndRemoveALocalDNSName(t *testing.T) {
	r := workstation()
	warn, err := r.AddDNSName(m1, " *.LAN.telemaque.ska.sh. ")
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 0 {
		t.Errorf("unexpected warnings: %v", warn)
	}
	if got := dnsOf(r, m1); got != "*.lan.telemaque.ska.sh" {
		t.Errorf("the name was not stored canonically: %q", got)
	}
	if _, err := r.AddDNSName(m1, "*.lan.telemaque.ska.sh"); err == nil {
		t.Error("adding the same name twice must be refused, not silently ignored")
	}
	if err := r.RemoveDNSName(m1, "*.LAN.telemaque.ska.sh"); err != nil {
		t.Fatal(err)
	}
	if got := dnsOf(r, m1); got != "" {
		t.Errorf("the name was not removed: %q", got)
	}
	if err := r.RemoveDNSName(m1, "*.lan.telemaque.ska.sh"); err == nil {
		t.Error("removing a name the device does not have must be an error")
	}
}

func TestDNSNameMutationsAreStrictAboutTheMAC(t *testing.T) {
	r := workstation()
	if _, err := r.AddDNSName(m2, "nas.home.arpa"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound from add, got %v", err)
	}
	if err := r.RemoveDNSName(m2, "nas.home.arpa"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound from remove, got %v", err)
	}
	if len(r.Devices) != 1 {
		t.Errorf("a mutation inserted a device: %+v", r.Devices)
	}
}

func TestANameNeedsAFixedAddressAndPinsIt(t *testing.T) {
	r := reg(m1, "workstation igc")
	if _, err := r.AddDNSName(m1, "*.lan.telemaque.ska.sh"); err == nil ||
		!strings.Contains(err.Error(), "curfew set-ip") {
		t.Errorf("a name without a fixed address must be refused, pointing at set-ip: %v", err)
	}
	r = workstation()
	if _, err := r.AddDNSName(m1, "*.lan.telemaque.ska.sh"); err != nil {
		t.Fatal(err)
	}
	err := r.SetIP(m1, "")
	if err == nil || !strings.Contains(err.Error(), "remove-dns-name") {
		t.Errorf("clearing the fixed address of a device with names must be refused: %v", err)
	}
	if ips(r)[m1] != "192.168.1.122" {
		t.Error("a refused clear changed the address anyway")
	}
	// Changing it is fine: the names follow it.
	if err := r.SetIP(m1, "192.168.1.123"); err != nil {
		t.Errorf("moving a named device must be allowed: %v", err)
	}
}

func TestAddRefusesAnInvalidOrOverlappingName(t *testing.T) {
	r := withIP(withNames(workstation(), m1, "*.lan.telemaque.ska.sh"), m1, "192.168.1.122")
	r.Devices = append(r.Devices, Device{MAC: m2, Name: "shyrka", IP: "192.168.1.150"})
	for _, bad := range []string{"nas.lan.telemaque.ska.sh", "*.sh", "bad_name.example", "x.local"} {
		if _, err := r.AddDNSName(m2, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !strings.Contains(func() string { _, e := r.AddDNSName(m2, "nas.lan.telemaque.ska.sh"); return e.Error() }(),
		"workstation igc") {
		t.Error("an overlap must name the device that already has it")
	}
	if dnsOf(r, m2) != "" {
		t.Errorf("a refused name was stored: %q", dnsOf(r, m2))
	}
	warn, err := r.AddDNSName(m2, "example.com")
	if err != nil || len(warn) == 0 {
		t.Errorf("a whole registrable domain is a warning, not a refusal: %v %v", warn, err)
	}
}

func TestDNSNamesSurviveASaveLoadRoundTripCanonically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	raw := `{"devices":[{"mac":"38:05:25:3A:B0:70","name":"workstation igc","ip":"192.168.1.122",` +
		`"dns_names":["Nas.Home.Arpa.","*.lan.telemaque.ska.sh","nas.home.arpa","bad_name.example"]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatalf("a bad stored name must not refuse the whole allowlist: %v", err)
	}
	got := strings.Join(r.Devices[0].DNSNames, ",")
	if got != "*.lan.telemaque.ska.sh,bad_name.example,nas.home.arpa" {
		t.Errorf("load did not canonicalise (and keep the bad one): %q", got)
	}
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"dns_names"`) {
		t.Errorf("the field was not saved:\n%s", data)
	}
	r2, _ := Load(path)
	if !Equal(r, r2) {
		t.Error("a round trip changed the registry")
	}
	// A device without names writes no field at all.
	r2.Devices[0].DNSNames = nil
	_ = Save(path, r2)
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "dns_names") {
		t.Errorf("an empty set must be omitted:\n%s", data)
	}
}

func TestMergeNamesSetOnOneSideAreTaken(t *testing.T) {
	base := workstation()
	local := withNames(workstation(), m1, "*.lan.telemaque.ska.sh")
	merged, conflicts := Merge3(base, local, workstation())
	if len(conflicts) != 0 || dnsOf(merged, m1) != "*.lan.telemaque.ska.sh" {
		t.Errorf("laptop-side names lost: %+v %+v", merged.Devices, conflicts)
	}
	merged, conflicts = Merge3(base, workstation(), local)
	if len(conflicts) != 0 || dnsOf(merged, m1) != "*.lan.telemaque.ska.sh" {
		t.Errorf("router-side names lost: %+v %+v", merged.Devices, conflicts)
	}
}

func TestMergeNamesHereAndARenameThereBothApply(t *testing.T) {
	base := workstation()
	local := withNames(workstation(), m1, "*.lan.telemaque.ska.sh")
	remote := workstation()
	remote.Devices[0].Name = "telemaque"
	merged, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 0 {
		t.Fatalf("names and a rename are independent edits: %+v", conflicts)
	}
	if names(merged)[m1] != "telemaque" || dnsOf(merged, m1) != "*.lan.telemaque.ska.sh" ||
		ips(merged)[m1] != "192.168.1.122" {
		t.Errorf("want every edit kept: %+v", merged.Devices)
	}
}

func TestMergeConflictWhenBothSidesChangeTheNamesDifferently(t *testing.T) {
	base := withNames(workstation(), m1, "a.home.arpa")
	local := withNames(workstation(), m1, "a.home.arpa", "b.home.arpa")
	remote := withNames(workstation(), m1, "c.home.arpa")
	_, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 1 || conflicts[0].Kind != BothChangedDNSNames {
		t.Fatalf("want one BothChangedDNSNames conflict, got %+v", conflicts)
	}
	out := RenderConflicts(conflicts)
	for _, want := range []string{"local DNS names", "a.home.arpa", "a.home.arpa, b.home.arpa", "c.home.arpa"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report should show %q:\n%s", want, out)
		}
	}
	// The same change on both sides is agreement, not a conflict.
	_, conflicts = Merge3(base, local, withNames(workstation(), m1, "a.home.arpa", "b.home.arpa"))
	if len(conflicts) != 0 {
		t.Errorf("identical edits conflicted: %+v", conflicts)
	}
}

func TestEqualSeesANamesOnlyDifference(t *testing.T) {
	if Equal(workstation(), withNames(workstation(), m1, "nas.home.arpa")) {
		t.Error("a names-only change must count as a change, or push would silently overwrite it")
	}
}

func TestMergeConflictWhenOneSideRemovesAndTheOtherAddsNames(t *testing.T) {
	_, conflicts := Merge3(workstation(), reg(), withNames(workstation(), m1, "nas.home.arpa"))
	if len(conflicts) != 1 || conflicts[0].Kind != RemovedAndRenamed {
		t.Fatalf("want a removed-on-one-side conflict, got %+v", conflicts)
	}
}
