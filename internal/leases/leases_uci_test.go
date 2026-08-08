//go:build linux

package leases

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Round-trip tests against REAL uci, in the OpenWrt image.
//
// The unit tests pin the decision logic against fixtures. These pin the thing
// fixtures cannot: that the commands curfew emits are accepted by the uci that
// is actually on the router, that re-reading afterwards sees what was written,
// and above all that the household's own entry is still there.
//
// That last one is the point. The previous stage's gate stayed green while
// `uci delete dhcp.lan.dhcp_option` destroyed every DHCP option the household
// had set, because nothing asserted on configuration the code was not supposed
// to touch. So this asserts the whole file, not just curfew's part of it.

func requireUCI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("no uci; run this in the OpenWrt test image")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to write /etc/config")
	}
}

// realRouterDHCP is the live router's own /etc/config/dhcp, including the
// static lease written by the shell tool this project replaces and the DHCP
// options a previous bug destroyed.
const realRouterDHCP = `
config dnsmasq
	option port '54'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	list dhcp_option '6,192.168.1.1'
	list dhcp_option '42,192.168.1.1'

config host
	option mac 'F8:25:51:09:38:38'
	option ip '192.168.1.10'
	option name 'parental_printer'
`

type shellRunner struct{ t *testing.T }

func (s shellRunner) Run(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func writeDHCP(t *testing.T, content string) {
	t.Helper()
	if err := os.MkdirAll("/etc/config", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/config/dhcp", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove("/etc/config/dhcp") })
}

func uciShow(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", "uci show dhcp").CombinedOutput()
	if err != nil {
		t.Fatalf("uci show dhcp: %s %v", out, err)
	}
	return string(out)
}

func TestPinningARealRouterConfigPreservesEverythingElse(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	r := shellRunner{t}

	current, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	// BASELINE: the household's entry and its options are there to begin
	// with, or the survival assertions below would prove nothing.
	if len(current) != 1 || current[0].Name != "parental_printer" {
		t.Fatalf("baseline: want the printer entry, got %+v", current)
	}

	plan := Reconcile(current, []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"},
		{MAC: "f0:d7:aa:da:66:35", Name: "tia phone", IP: "192.168.1.182"},
	})
	if _, err := Apply(r, plan); err != nil && !strings.Contains(err.Error(), "dnsmasq") {
		// A reload failure is expected in a container with no procd, and is
		// not what this test is about.
		t.Fatalf("Apply: %v", err)
	}

	file, err := os.ReadFile("/etc/config/dhcp")
	if err != nil {
		t.Fatal(err)
	}
	got := string(file)

	// The household's own static lease, untouched, in full.
	for _, must := range []string{"F8:25:51:09:38:38", "192.168.1.10", "parental_printer"} {
		if !strings.Contains(got, must) {
			t.Errorf("the household's own static lease lost %q:\n%s", must, got)
		}
	}
	// The DHCP options a previous bug wiped out. Nothing in this change has
	// any business touching them, which is exactly why they are asserted.
	for _, must := range []string{"6,192.168.1.1", "42,192.168.1.1"} {
		if !strings.Contains(got, must) {
			t.Errorf("a DHCP option unrelated to this change was destroyed (%q):\n%s", must, got)
		}
	}
	// And the unrelated dnsmasq settings.
	for _, must := range []string{"option port '54'", "readethers", "leasetime '12h'"} {
		if !strings.Contains(got, must) {
			t.Errorf("unrelated dhcp config was destroyed (%q):\n%s", must, got)
		}
	}
	// curfew's own entries are really there, so this is not passing because
	// nothing was written.
	if !strings.Contains(got, "curfew_14e01d6a9c6c") || !strings.Contains(got, "192.168.1.123") {
		t.Errorf("curfew's own static lease was not written:\n%s", got)
	}
}

// Idempotency proved through the REAL round trip rather than by a double that
// reproduces what the commands would have done.
func TestASecondReconcileAgainstRealUCIPlansNothing(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	r := shellRunner{t}

	devices := []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"},
		{MAC: "f0:d7:aa:da:66:35", Name: "tia phone", IP: "192.168.1.182"},
	}
	first, _ := Read(r)
	plan := Reconcile(first, devices)
	if len(plan.Commands) == 0 {
		t.Fatal("baseline: the first pass should have something to do")
	}
	_, _ = Apply(r, plan)

	// Re-read what uci ACTUALLY holds and plan again.
	second, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	again := Reconcile(second, devices)
	if len(again.Commands) != 0 {
		t.Errorf("re-running rewrote the config; it must converge:\n%v\nstate was:\n%s",
			again.Commands, uciShow(t))
	}
	if len(again.Pinned) != 2 {
		t.Errorf("the second pass lost track of the pinned addresses: %+v", again.Pinned)
	}
}

// Deregistering must remove curfew's entry and NOTHING else, through real uci.
func TestRemovingADeviceThroughRealUCIKeepsTheForeignEntry(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	r := shellRunner{t}

	devices := []Device{{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"}}
	first, _ := Read(r)
	_, _ = Apply(r, Reconcile(first, devices))

	// Now deregister everything.
	second, _ := Read(r)
	_, _ = Apply(r, Reconcile(second, nil))

	after, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].Name != "parental_printer" {
		t.Errorf("want only the household's own entry left, got %+v\n%s", after, uciShow(t))
	}
	file, _ := os.ReadFile("/etc/config/dhcp")
	if !strings.Contains(string(file), "42,192.168.1.1") {
		t.Errorf("removing a device destroyed an unrelated DHCP option:\n%s", file)
	}
}

// A foreign entry pinning a registered MAC: curfew must write nothing and must
// not end up with two static leases for one device, which dnsmasq would treat
// as a broken config.
func TestCurfewNeverCreatesASecondLeaseForAForeignPinnedMAC(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	r := shellRunner{t}

	current, _ := Read(r)
	// Register the printer, observed somewhere else entirely.
	plan := Reconcile(current, []Device{
		{MAC: "f8:25:51:09:38:38", Name: "printer", IP: "192.168.1.200"}})
	_, _ = Apply(r, plan)

	after, _ := Read(r)
	count := 0
	for _, h := range after {
		if h.MAC == "f8:25:51:09:38:38" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("want exactly one static lease for that MAC, got %d:\n%s", count, uciShow(t))
	}
	if len(plan.Conflicts) != 1 {
		t.Errorf("the clash must be reported: %+v", plan.Conflicts)
	}
}

// twoForeignHosts has the printer PLUS another household entry, so adoption
// has to pick the right one out of an index-addressed list.
const twoForeignHosts = `
config dnsmasq
	option port '54'

config dhcp 'lan'
	option interface 'lan'
	list dhcp_option '6,192.168.1.1'
	list dhcp_option '42,192.168.1.1'

config host
	option mac 'AA:AA:AA:AA:AA:AA'
	option ip '192.168.1.11'
	option name 'their-nas'

config host
	option mac 'F8:25:51:09:38:38'
	option ip '192.168.1.10'
	option name 'parental_printer'

config host
	option mac 'BB:BB:BB:BB:BB:BB'
	option ip '192.168.1.12'
	option name 'their-camera'
`

// Adoption through REAL uci. The control is the pair of entries curfew was NOT
// told about: they must come out byte for byte the same, at the same
// addresses. An index mistake here would delete one of them silently, which is
// exactly the class of bug that got through the previous stage's gate.
func TestAdoptingOneEntryThroughRealUCILeavesTheOthersExactlyAsTheyWere(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, twoForeignHosts)
	r := shellRunner{t}

	current, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	// BASELINE: three foreign entries, none owned by curfew.
	if len(current) != 3 {
		t.Fatalf("baseline: want 3 host entries, got %+v", current)
	}
	for _, h := range current {
		if h.Owned() {
			t.Fatalf("baseline: nothing should be curfew's yet, got %+v", h)
		}
	}

	a := PlanAdoption(current, map[string]string{"f8:25:51:09:38:38": "printer"})
	if len(a.Entries) != 1 {
		t.Fatalf("want exactly the printer adopted, got %+v", a.Entries)
	}
	if _, err := Apply(r, Plan{Commands: a.Commands}); err != nil &&
		!strings.Contains(err.Error(), "dnsmasq") {
		t.Fatalf("Apply: %v", err)
	}

	after, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 3 {
		t.Fatalf("want still 3 host entries, got %d:\n%s", len(after), uciShow(t))
	}

	byMAC := map[string]Host{}
	for _, h := range after {
		byMAC[h.MAC] = h
	}

	// The printer is now curfew's, at the SAME address.
	printer, ok := byMAC["f8:25:51:09:38:38"]
	if !ok {
		t.Fatalf("the printer's lease vanished entirely:\n%s", uciShow(t))
	}
	if !printer.Owned() {
		t.Errorf("the printer was not adopted: %+v", printer)
	}
	if printer.IP != "192.168.1.10" {
		t.Errorf("adoption moved the printer to %q", printer.IP)
	}
	if printer.Name != "printer" {
		t.Errorf("name = %q, want the registered name", printer.Name)
	}

	// THE CONTROL: the two entries curfew was not told about, untouched.
	for mac, want := range map[string]Host{
		"aa:aa:aa:aa:aa:aa": {MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.11", Name: "their-nas"},
		"bb:bb:bb:bb:bb:bb": {MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.12", Name: "their-camera"},
	} {
		got, ok := byMAC[mac]
		if !ok {
			t.Errorf("adoption DELETED the household's own entry for %s:\n%s", mac, uciShow(t))
			continue
		}
		if got.IP != want.IP || got.Name != want.Name {
			t.Errorf("adoption altered the household's own entry: got %+v want ip %s name %s",
				got, want.IP, want.Name)
		}
		if got.Owned() {
			t.Errorf("curfew claimed ownership of an entry it was not given: %+v", got)
		}
	}

	// And the DHCP options, which have nothing to do with any of this.
	file, _ := os.ReadFile("/etc/config/dhcp")
	for _, must := range []string{"6,192.168.1.1", "42,192.168.1.1"} {
		if !strings.Contains(string(file), must) {
			t.Errorf("adoption destroyed an unrelated DHCP option (%q):\n%s", must, file)
		}
	}
}

// After adoption a normal reconcile must be a no-op: the entry is curfew's
// now, at the address it already had, so there is nothing left to do.
func TestAfterAdoptionAReconcilePlansNothing(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, twoForeignHosts)
	r := shellRunner{t}

	current, _ := Read(r)
	a := PlanAdoption(current, map[string]string{"f8:25:51:09:38:38": "printer"})
	_, _ = Apply(r, Plan{Commands: a.Commands})

	after, _ := Read(r)
	plan := Reconcile(after, []Device{{MAC: "f8:25:51:09:38:38", Name: "printer", IP: "192.168.1.10"}})
	if len(plan.Commands) != 0 {
		t.Errorf("reconcile still wants to change things after adoption:\n%v", plan.Commands)
	}
	// And the permanent conflict report is gone, which is the point.
	if len(plan.Conflicts) != 0 {
		t.Errorf("the entry is still reported as a foreign conflict: %+v", plan.Conflicts)
	}
}

// Adopting TWO entries out of four, through real uci.
//
// This is the test that would actually break if the deletes ran in ascending
// index order, because uci renumbers @host[N] downward as sections are removed
// (measured: deleting @host[0] moves the old @host[1] to @host[0]). With one
// adoption the ordering is unobservable, which is why this case exists.
func TestAdoptingTwoEntriesDeletesExactlyThoseTwo(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, `
config dhcp 'lan'
	option interface 'lan'

config host
	option mac 'AA:AA:AA:AA:AA:AA'
	option ip '192.168.1.11'
	option name 'their-nas'

config host
	option mac 'F8:25:51:09:38:38'
	option ip '192.168.1.10'
	option name 'parental_printer'

config host
	option mac 'BB:BB:BB:BB:BB:BB'
	option ip '192.168.1.12'
	option name 'their-camera'

config host
	option mac '14:E0:1D:6A:9C:6C'
	option ip '192.168.1.123'
	option name 'eli-old'
`)
	r := shellRunner{t}
	current, _ := Read(r)
	if len(current) != 4 {
		t.Fatalf("baseline: want 4 entries, got %d", len(current))
	}

	a := PlanAdoption(current, map[string]string{
		"f8:25:51:09:38:38": "printer",
		"14:e0:1d:6a:9c:6c": "eli phone",
	})
	if len(a.Entries) != 2 {
		t.Fatalf("want two adoptions, got %+v", a.Entries)
	}
	if _, err := Apply(r, Plan{Commands: a.Commands}); err != nil &&
		!strings.Contains(err.Error(), "dnsmasq") {
		t.Fatalf("Apply: %v", err)
	}

	after, _ := Read(r)
	byMAC := map[string]Host{}
	for _, h := range after {
		byMAC[h.MAC] = h
	}
	if len(after) != 4 {
		t.Errorf("want 4 entries still, got %d:\n%s", len(after), uciShow(t))
	}
	// The two adopted, now curfew's, at their original addresses.
	for mac, ip := range map[string]string{
		"f8:25:51:09:38:38": "192.168.1.10",
		"14:e0:1d:6a:9c:6c": "192.168.1.123",
	} {
		h, ok := byMAC[mac]
		if !ok {
			t.Errorf("%s lost its lease entirely:\n%s", mac, uciShow(t))
			continue
		}
		if !h.Owned() || h.IP != ip {
			t.Errorf("%s: got %+v, want owned by curfew at %s", mac, h, ip)
		}
	}
	// THE CONTROL: the two the household owns, untouched and still foreign.
	for mac, want := range map[string]string{
		"aa:aa:aa:aa:aa:aa": "their-nas",
		"bb:bb:bb:bb:bb:bb": "their-camera",
	} {
		h, ok := byMAC[mac]
		if !ok {
			t.Errorf("adoption DELETED the household's entry for %s:\n%s", mac, uciShow(t))
			continue
		}
		if h.Name != want || h.Owned() {
			t.Errorf("%s: got %+v, want an untouched foreign entry named %q", mac, h, want)
		}
	}
}
