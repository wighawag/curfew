package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the FIXED ADDRESS: a user-chosen IPv4 address carried on a device.
// See work/specs/proposed/fixed-address-per-device.md and docs/adr/0012.

func withIP(r *Registry, mac, ip string) *Registry {
	for i := range r.Devices {
		if r.Devices[i].MAC == mac {
			r.Devices[i].IP = ip
		}
	}
	return r
}

func ips(r *Registry) map[string]string {
	m := map[string]string{}
	for _, d := range r.Devices {
		m[d.MAC] = d.IP
	}
	return m
}

func TestSetIPSetsAndClearsTheFixedAddress(t *testing.T) {
	r := reg(m1, "shyrka")
	if err := r.SetIP("AA-BB-CC-00-00-01", "192.168.1.150"); err != nil {
		t.Fatal(err)
	}
	if got := ips(r)[m1]; got != "192.168.1.150" {
		t.Errorf("fixed address not set, got %q", got)
	}
	if names(r)[m1] != "shyrka" {
		t.Error("setting an address must not touch the name")
	}
	if err := r.SetIP(m1, ""); err != nil {
		t.Fatal(err)
	}
	if got := ips(r)[m1]; got != "" {
		t.Errorf("clearing left %q", got)
	}
}

// Strict like Rename: setting an address on an unknown MAC must not quietly
// register it, because registering is handing out internet access.
func TestSetIPRefusesAnUnregisteredMAC(t *testing.T) {
	r := reg(m1, "shyrka")
	err := r.SetIP(m2, "192.168.1.150")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if len(r.Devices) != 1 {
		t.Errorf("SetIP inserted a device: %+v", r.Devices)
	}
}

func TestSetIPCanonicalisesAndRefusesNonIPv4(t *testing.T) {
	r := reg(m1, "shyrka")
	for _, bad := range []string{"192.168.1", "192.168.1.256", "fd00::1", "shyrka", "192.168.1.150/24"} {
		if err := r.SetIP(m1, bad); err == nil {
			t.Errorf("%q was accepted as a fixed IPv4 address", bad)
		}
	}
	if ips(r)[m1] != "" {
		t.Errorf("a refused address was stored: %q", ips(r)[m1])
	}
	// An IPv4-mapped IPv6 spelling is still the same IPv4 address.
	if err := r.SetIP(m1, " ::ffff:192.168.1.150 "); err != nil {
		t.Fatal(err)
	}
	if got := ips(r)[m1]; got != "192.168.1.150" {
		t.Errorf("want the canonical dotted quad, got %q", got)
	}
}

// Two devices may not be given one address. The router-side checks cover
// host entries; this covers the file itself, so a typo is caught on the laptop.
func TestSetIPRefusesAnAddressAnotherDeviceAlreadyHas(t *testing.T) {
	r := withIP(reg(m1, "shyrka", m2, "printer"), m2, "192.168.1.150")
	err := r.SetIP(m1, "192.168.1.150")
	if err == nil {
		t.Fatal("a duplicate fixed address was accepted")
	}
	if !strings.Contains(err.Error(), m2) && !strings.Contains(err.Error(), "printer") {
		t.Errorf("the refusal should name who already has it: %v", err)
	}
	// Re-setting a device's own address is not a duplicate.
	if err := r.SetIP(m2, "192.168.1.150"); err != nil {
		t.Errorf("re-setting the same address on the same device was refused: %v", err)
	}
}

func TestResolveFindsADeviceByMACOrByName(t *testing.T) {
	r := reg(m1, "shyrka", m2, "Printer")
	for ref, want := range map[string]string{
		"AA:BB:CC:00:00:01": m1,
		"shyrka":            m1,
		"printer":           m2, // case-insensitive
		" Printer ":         m2,
	} {
		got, err := r.Resolve(ref)
		if err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	if _, err := r.Resolve("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown name should be ErrNotFound, got %v", err)
	}
}

// Names are free text and not unique, so an ambiguous one must be refused
// rather than resolved to whichever device happens to come first.
func TestResolveRefusesAnAmbiguousName(t *testing.T) {
	r := reg(m1, "phone", m2, "phone")
	_, err := r.Resolve("phone")
	if err == nil {
		t.Fatal("an ambiguous name resolved")
	}
	if !strings.Contains(err.Error(), m1) || !strings.Contains(err.Error(), m2) {
		t.Errorf("the refusal should list the candidates: %v", err)
	}
}

func TestTheFixedAddressSurvivesASaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	r := withIP(reg(m1, "shyrka", m2, "tv"), m1, "192.168.1.150")
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), `"ip"`) != 1 {
		t.Errorf("want ip written only where set (omitempty):\n%s", data)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if ips(got)[m1] != "192.168.1.150" || ips(got)[m2] != "" {
		t.Errorf("round trip lost the fixed address: %+v", got.Devices)
	}
}

// A hand-edited bad address must not stop the registry loading: the registry
// IS the allowlist, and failing to load it would take the household offline
// over a field that only matters to DHCP. It is kept as written and refused
// later, by the checks that run before any uci write.
func TestLoadKeepsAnUnparseableAddressRatherThanFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	body := `{"devices":[{"mac":"AA:BB:CC:00:00:01","ip":"not-an-ip"},{"mac":"aa:bb:cc:00:00:02","ip":"::ffff:192.168.1.9"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("a bad fixed address made the whole allowlist unloadable: %v", err)
	}
	if ips(got)[m1] != "not-an-ip" {
		t.Errorf("want the bad value kept for the checks to refuse, got %q", ips(got)[m1])
	}
	if ips(got)[m2] != "192.168.1.9" {
		t.Errorf("a parseable address should be canonicalised on load, got %q", ips(got)[m2])
	}
}

// ---- merge ----

func TestMergeAFixedAddressSetOnOneSideIsTaken(t *testing.T) {
	base := reg(m1, "shyrka")
	local := withIP(reg(m1, "shyrka"), m1, "192.168.1.150")
	remote := reg(m1, "shyrka")
	merged, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 0 {
		t.Fatalf("want a clean merge, got %+v", conflicts)
	}
	if ips(merged)[m1] != "192.168.1.150" {
		t.Errorf("the local address was lost: %+v", merged.Devices)
	}
	// And the other direction.
	merged, conflicts = Merge3(base, reg(m1, "shyrka"), local)
	if len(conflicts) != 0 || ips(merged)[m1] != "192.168.1.150" {
		t.Errorf("the router's address was lost: %+v %+v", merged.Devices, conflicts)
	}
}

// Different FIELDS changed on different sides are not a conflict.
func TestMergeARenameHereAndAnAddressThereBothApply(t *testing.T) {
	base := reg(m1, "box")
	local := reg(m1, "shyrka")                            // renamed on the laptop
	remote := withIP(reg(m1, "box"), m1, "192.168.1.150") // address set on the router
	merged, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 0 {
		t.Fatalf("a rename and an address change are independent, got %+v", conflicts)
	}
	if names(merged)[m1] != "shyrka" || ips(merged)[m1] != "192.168.1.150" {
		t.Errorf("want both edits, got %+v", merged.Devices)
	}
}

func TestMergeClearingOnOneSideIsTaken(t *testing.T) {
	base := withIP(reg(m1, "shyrka"), m1, "192.168.1.150")
	local := reg(m1, "shyrka") // cleared on the laptop
	remote := withIP(reg(m1, "shyrka"), m1, "192.168.1.150")
	merged, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 0 || ips(merged)[m1] != "" {
		t.Errorf("a clear on one side should apply: %+v %+v", merged.Devices, conflicts)
	}
}

func TestMergeConflictWhenBothSidesChangeTheAddressDifferently(t *testing.T) {
	base := withIP(reg(m1, "shyrka"), m1, "192.168.1.150")
	local := withIP(reg(m1, "shyrka"), m1, "192.168.1.151")
	remote := withIP(reg(m1, "shyrka"), m1, "192.168.1.152")
	_, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 1 || conflicts[0].Kind != BothChangedIP {
		t.Fatalf("want one BothChangedIP conflict, got %+v", conflicts)
	}
	c := conflicts[0]
	if c.BaseIP != "192.168.1.150" || c.LocalIP != "192.168.1.151" || c.RemoteIP != "192.168.1.152" {
		t.Errorf("the conflict should carry all three addresses: %+v", c)
	}
	out := RenderConflicts(conflicts)
	for _, want := range []string{"192.168.1.150", "192.168.1.151", "192.168.1.152"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report should name %s:\n%s", want, out)
		}
	}
}

// Removing a device on one side while the other gave it an address is the
// same danger as removed-and-renamed: either answer silently loses something.
func TestMergeConflictWhenOneSideRemovesAndTheOtherSetsAnAddress(t *testing.T) {
	base := reg(m1, "shyrka")
	_, conflicts := Merge3(base, reg(), withIP(reg(m1, "shyrka"), m1, "192.168.1.150"))
	if len(conflicts) != 1 || conflicts[0].Kind != RemovedAndRenamed {
		t.Fatalf("want a removed-on-one-side conflict, got %+v", conflicts)
	}
}

func TestEqualSeesAnAddressOnlyDifference(t *testing.T) {
	a := reg(m1, "shyrka")
	b := withIP(reg(m1, "shyrka"), m1, "192.168.1.150")
	if Equal(a, b) {
		t.Error("an address-only change must count as a change, or push would " +
			"silently overwrite an address set on the router")
	}
}
