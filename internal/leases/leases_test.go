package leases

import (
	"strings"
	"testing"
)

// realRouterUCI is the `uci show dhcp` output read off the live GL.iNet Flint 2
// this system runs on, trimmed to the parts that matter. The single host entry
// is the one the SHELL TOOL THIS PROJECT REPLACES wrote (config/local/device_ips
// records it), and it is the control for every assertion in this file: curfew
// did not create it in this form, so it must come out the other side untouched.
//
// Note the MAC is UPPERCASE, exactly as the router stores it.
const realRouterUCI = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].leasefile='/tmp/dhcp.leases'
dhcp.@dnsmasq[0].readethers='1'
dhcp.@dnsmasq[0].port='54'
dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.lan.start='100'
dhcp.lan.limit='150'
dhcp.lan.leasetime='12h'
dhcp.lan.dhcp_option='6,192.168.1.1'
dhcp.wan=dhcp
dhcp.wan.ignore='1'
dhcp.odhcpd=odhcpd
dhcp.odhcpd.leasefile='/tmp/odhcpd.leases'
dhcp.@host[0]=host
dhcp.@host[0].mac='F8:25:51:09:38:38'
dhcp.@host[0].ip='192.168.1.10'
dhcp.@host[0].name='parental_printer'
`

func TestParseFindsHostEntriesAndNothingElse(t *testing.T) {
	hosts := Parse(realRouterUCI)
	if len(hosts) != 1 {
		t.Fatalf("want exactly 1 host entry from the real router, got %d: %+v", len(hosts), hosts)
	}
	h := hosts[0]
	if h.Section != "@host[0]" {
		t.Errorf("section = %q, want @host[0]", h.Section)
	}
	// Lowercased on the way in. The router stores it uppercase, and a
	// case-sensitive comparison later would fail to see this MAC as already
	// pinned, so curfew would write a SECOND static lease for one device.
	if h.MAC != "f8:25:51:09:38:38" {
		t.Errorf("mac = %q, want it normalised to lowercase", h.MAC)
	}
	if h.IP != "192.168.1.10" || h.Name != "parental_printer" {
		t.Errorf("got %+v", h)
	}
	if h.Owned() {
		t.Error("the printer entry was written by the shell tool, not by curfew; " +
			"treating it as owned would let curfew delete it")
	}
	// The control: dnsmasq, lan and odhcpd sections are not host entries and
	// must not be mistaken for any. Without this, a parser that keyed on
	// "has a .mac option" or similar would happily invent entries.
	for _, h := range hosts {
		if strings.Contains(h.Section, "dnsmasq") || h.Section == "lan" || h.Section == "odhcpd" {
			t.Errorf("a non-host section was parsed as a host entry: %+v", h)
		}
	}
}

// THE test for this package. The previous stage's gate went green while
// `uci delete dhcp.lan.dhcp_option` destroyed every DHCP option the household
// had, because nothing asserted on configuration the code was not supposed to
// touch. This asserts exactly that.
func TestAForeignEntryIsNeverTouched(t *testing.T) {
	current := Parse(realRouterUCI)
	plan := Reconcile(current, []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"},
		{MAC: "f0:d7:aa:da:66:35", Name: "tia phone", IP: "192.168.1.182"},
	})

	joined := strings.Join(plan.Commands, "\n")
	if joined == "" {
		t.Fatal("nothing was planned at all, so this test would pass vacuously")
	}
	// Nothing may address the foreign section, by any spelling.
	for _, forbidden := range []string{"@host[0]", "@host", "parental_printer", "192.168.1.10"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("the plan touches the household's own entry (%q):\n%s", forbidden, joined)
		}
	}
	// And nothing may delete a host section curfew does not own.
	for _, cmd := range plan.Commands {
		if strings.Contains(cmd, "delete") && !strings.Contains(cmd, SectionPrefix) {
			t.Errorf("a delete escaped curfew's own sections: %q", cmd)
		}
	}
}

// The conflict case the brief asks to decide: a foreign entry pins a MAC
// curfew also wants to pin. curfew must yield, say so, and still make use of
// the address.
func TestAForeignPinOfARegisteredMACIsYieldedToAndReported(t *testing.T) {
	current := Parse(realRouterUCI)
	plan := Reconcile(current, []Device{
		// The printer, now registered, and observed at a DIFFERENT address
		// from the one the foreign entry pins.
		{MAC: "f8:25:51:09:38:38", Name: "printer", IP: "192.168.1.200"},
	})

	if len(plan.Conflicts) != 1 {
		t.Fatalf("want the clash reported, got %+v", plan.Conflicts)
	}
	c := plan.Conflicts[0]
	if c.MAC != "f8:25:51:09:38:38" || c.Section != "@host[0]" || c.IP != "192.168.1.10" {
		t.Errorf("the conflict must name the entry and its address, got %+v", c)
	}
	if len(plan.Commands) != 0 {
		t.Errorf("curfew must write NO competing entry for a MAC somebody else pins:\n%v", plan.Commands)
	}
	// The foreign entry's address is still a fact about where the device is,
	// and the whole point of this package is knowing that. Refusing to read it
	// would make the DNS refinement worse for no gain.
	if got := plan.Pinned["f8:25:51:09:38:38"]; got != "192.168.1.10" {
		t.Errorf("pinned address = %q, want the FOREIGN entry's 192.168.1.10 "+
			"(not the observed .200, which the router will not hand out)", got)
	}
}

func TestARegisteredDeviceIsPinnedWithAnOwnershipMarker(t *testing.T) {
	plan := Reconcile(nil, []Device{{MAC: "14:E0:1D:6A:9C:6C", Name: "eli phone", IP: "192.168.1.123"}})
	joined := strings.Join(plan.Commands, "\n")

	want := []string{
		"uci set dhcp.curfew_14e01d6a9c6c=host",
		"uci set dhcp.curfew_14e01d6a9c6c.mac='14:e0:1d:6a:9c:6c'",
		"uci set dhcp.curfew_14e01d6a9c6c.ip='192.168.1.123'",
		"uci set dhcp.curfew_14e01d6a9c6c.curfew=1",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
	if got := plan.Pinned["14:e0:1d:6a:9c:6c"]; got != "192.168.1.123" {
		t.Errorf("pinned = %q, want 192.168.1.123", got)
	}
}

// Re-running against the state the previous run produced must do NOTHING.
// The real round trip through uci is asserted in the acceptance test; this
// pins the decision logic on its own.
func TestReconcileIsANoOpWhenTheRouterAlreadyAgrees(t *testing.T) {
	devices := []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"},
		{MAC: "f0:d7:aa:da:66:35", Name: "tia phone", IP: "192.168.1.182"},
	}
	already := []Host{
		{Section: "@host[0]", MAC: "f8:25:51:09:38:38", IP: "192.168.1.10", Name: "parental_printer"},
		{Section: "curfew_14e01d6a9c6c", MAC: "14:e0:1d:6a:9c:6c", IP: "192.168.1.123", Name: "eli phone"},
		{Section: "curfew_f0d7aada6635", MAC: "f0:d7:aa:da:66:35", IP: "192.168.1.182", Name: "tia phone"},
	}
	plan := Reconcile(already, devices)
	if len(plan.Commands) != 0 {
		t.Errorf("a converged router must produce no commands, got:\n%v", plan.Commands)
	}
	// It must still report where everything is, or the caller would think the
	// devices had no addresses.
	if len(plan.Pinned) != 2 {
		t.Errorf("want both devices reported as pinned, got %+v", plan.Pinned)
	}
}

// A changed address must be rewritten. Without this, a no-op check that was
// slightly too eager would freeze every device at its first-ever address.
func TestAChangedAddressIsRewritten(t *testing.T) {
	already := []Host{{Section: "curfew_14e01d6a9c6c", MAC: "14:e0:1d:6a:9c:6c",
		IP: "192.168.1.123", Name: "eli phone"}}
	plan := Reconcile(already, []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.150"}})
	if !strings.Contains(strings.Join(plan.Commands, "\n"), "ip='192.168.1.150'") {
		t.Errorf("the new address was not written:\n%v", plan.Commands)
	}
	// A rename alone must also be picked up, or the file drifts from the page.
	plan = Reconcile(already, []Device{
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli's phone", IP: "192.168.1.123"}})
	if !strings.Contains(strings.Join(plan.Commands, "\n"), "name='eli'\\''s phone'") {
		t.Errorf("a rename was not written, or was not quoted safely:\n%v", plan.Commands)
	}
}

func TestADeregisteredDeviceLosesItsPin(t *testing.T) {
	already := []Host{
		{Section: "@host[0]", MAC: "f8:25:51:09:38:38", IP: "192.168.1.10", Name: "parental_printer"},
		{Section: "curfew_14e01d6a9c6c", MAC: "14:e0:1d:6a:9c:6c", IP: "192.168.1.123", Name: "eli phone"},
	}
	plan := Reconcile(already, nil)
	joined := strings.Join(plan.Commands, "\n")
	if !strings.Contains(joined, "uci -q delete dhcp.curfew_14e01d6a9c6c") {
		t.Errorf("a deregistered device kept its reserved address:\n%s", joined)
	}
	// The control, again: the foreign entry survives a deletion pass.
	if strings.Contains(joined, "@host[0]") {
		t.Errorf("the household's own entry was deleted too:\n%s", joined)
	}
}

// `uci -q delete` exits NON-ZERO when the thing is not set (measured in the
// OpenWrt image, for both a missing option and a missing section), which would
// abort a command chain half-done. Every delete must carry its own guard.
func TestEveryDeleteIsGuardedAgainstUciExitingNonZero(t *testing.T) {
	already := []Host{{Section: "curfew_dead", MAC: "aa:bb:cc:dd:ee:ff", IP: "1.2.3.4"}}
	plan := Reconcile(already, []Device{{MAC: "14:e0:1d:6a:9c:6c", IP: "192.168.1.123"}})

	found := false
	for _, cmd := range plan.Commands {
		if !strings.Contains(cmd, "delete") {
			continue
		}
		found = true
		if !strings.HasSuffix(cmd, "|| true") {
			t.Errorf("an unguarded delete will abort the run half-done: %q", cmd)
		}
	}
	if !found {
		t.Fatal("no delete was planned, so this test proves nothing")
	}
}

// A device nothing knows an address for must be REPORTED, not invented for.
// This is not hypothetical: on the live router one of eli's three devices
// (04:92:26:1e:6b:55) holds only a 169.254 link-local address, so it has no
// usable IPv4 at all.
func TestADeviceWithNoKnownAddressIsReportedRatherThanInvented(t *testing.T) {
	plan := Reconcile(nil, []Device{
		{MAC: "04:92:26:1e:6b:55", Name: "eli laptop (ethernet)"},
		{MAC: "14:e0:1d:6a:9c:6c", Name: "eli phone", IP: "192.168.1.123"},
	})
	if len(plan.Unaddressed) != 1 || plan.Unaddressed[0] != "04:92:26:1e:6b:55" {
		t.Errorf("the device with no address must be named, got %+v", plan.Unaddressed)
	}
	if _, ok := plan.Pinned["04:92:26:1e:6b:55"]; ok {
		t.Error("an address was invented for a device that has none")
	}
	joined := strings.Join(plan.Commands, "\n")
	if strings.Contains(joined, "04:92:26:1e:6b:55") {
		t.Errorf("a device with no address was pinned anyway:\n%s", joined)
	}
	// The control: the device that DOES have an address is still pinned, so
	// this is not just "it gave up".
	if !strings.Contains(joined, "curfew_14e01d6a9c6c") {
		t.Errorf("the addressable device was not pinned:\n%s", joined)
	}
}

func TestApplyDoesNothingWhenThereIsNothingToDo(t *testing.T) {
	r := &recordingRunner{}
	changed, err := Apply(r, Plan{})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("an empty plan reported a change")
	}
	// The important half: dnsmasq must NOT be reloaded. A reload every tick
	// would restart the household's DHCP service every minute.
	if len(r.ran) != 0 {
		t.Errorf("an empty plan still ran commands: %v", r.ran)
	}
}

func TestApplyCommitsAndReloadsOnlyAfterAllCommandsSucceed(t *testing.T) {
	r := &recordingRunner{}
	if _, err := Apply(r, Plan{Commands: []string{"uci set dhcp.curfew_x=host"}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, "uci commit dhcp") {
		t.Errorf("nothing was committed, so the change dies at the next reboot:\n%s", joined)
	}
	if !strings.Contains(joined, "/etc/init.d/dnsmasq reload") {
		t.Errorf("dnsmasq was never told, so the pin does not take effect:\n%s", joined)
	}
	// Order matters: commit before reload, or dnsmasq re-reads the old file.
	if strings.Index(joined, "uci commit dhcp") > strings.Index(joined, "dnsmasq reload") {
		t.Errorf("dnsmasq was reloaded before the commit:\n%s", joined)
	}
}

// A failure part-way through must not leave half a set of static leases
// committed, because a half-written DHCP config is a household where some
// devices cannot get an address.
func TestApplyRevertsWhenACommandFails(t *testing.T) {
	r := &recordingRunner{failOn: "curfew_second"}
	_, err := Apply(r, Plan{Commands: []string{
		"uci set dhcp.curfew_first=host",
		"uci set dhcp.curfew_second=host",
	}})
	if err == nil {
		t.Fatal("want an error")
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, "uci revert dhcp") {
		t.Errorf("a half-built change was left uncommitted but not reverted:\n%s", joined)
	}
	if strings.Contains(joined, "uci commit dhcp") {
		t.Errorf("a failed run committed anyway:\n%s", joined)
	}
}

// recordingRunner records what it was asked and can be told to fail. It is
// deliberately dumb: it knows nothing about uci, so it cannot agree with a
// broken implementation the way a double reproducing production logic would.
type recordingRunner struct {
	ran    []string
	failOn string
}

func (r *recordingRunner) Run(cmd string) (string, error) {
	r.ran = append(r.ran, cmd)
	if r.failOn != "" && strings.Contains(cmd, r.failOn) {
		return "", errShellFailed
	}
	return "", nil
}

var errShellFailed = &shellError{}

type shellError struct{}

func (e *shellError) Error() string { return "command failed" }

// Adoption takes over the entry the shell tool this project replaces wrote,
// keeping the device exactly where it is.
func TestAdoptionTakesOverAForeignEntryWithoutMovingTheDevice(t *testing.T) {
	current := Parse(realRouterUCI)
	a := PlanAdoption(current, map[string]string{"f8:25:51:09:38:38": "printer"})

	if len(a.Entries) != 1 {
		t.Fatalf("want the printer offered for adoption, got %+v", a.Entries)
	}
	e := a.Entries[0]
	if e.IP != "192.168.1.10" {
		t.Errorf("adoption must keep the device where it is, got ip %q", e.IP)
	}
	if e.OldName != "parental_printer" || e.NewName != "printer" {
		t.Errorf("the rename must be visible before it happens, got %+v", e)
	}

	joined := strings.Join(a.Commands, "\n")
	if !strings.Contains(joined, "uci -q delete dhcp.@host[0]") {
		t.Errorf("the foreign entry is never removed, so the MAC would have two leases:\n%s", joined)
	}
	if !strings.Contains(joined, "uci set dhcp.curfew_f8255109383 8.ip='192.168.1.10'") &&
		!strings.Contains(joined, "uci set dhcp.curfew_f82551093838.ip='192.168.1.10'") {
		t.Errorf("curfew's own entry was not written with the same address:\n%s", joined)
	}
	// The delete has to come FIRST: uci resolves @host[N] against the staged
	// config counting every host section, so creating ours first could shift
	// the index and delete somebody else's entry.
	if strings.Index(joined, "delete dhcp.@host[0]") > strings.Index(joined, "uci set dhcp.curfew_") {
		t.Errorf("the delete must be staged before any new host section:\n%s", joined)
	}
}

// THE control for adoption: an entry for a device curfew does not know about
// is not ours to take, and must be left completely alone.
func TestAdoptionIgnoresAForeignEntryForAnUnregisteredDevice(t *testing.T) {
	current := Parse(realRouterUCI)
	// Nothing registered at all.
	a := PlanAdoption(current, map[string]string{})
	if len(a.Entries) != 0 || len(a.Commands) != 0 {
		t.Errorf("an entry for an unregistered device was adopted: %+v %v", a.Entries, a.Commands)
	}

	// And with a DIFFERENT device registered, the printer entry still stands.
	a = PlanAdoption(current, map[string]string{"14:e0:1d:6a:9c:6c": "eli phone"})
	if len(a.Entries) != 0 {
		t.Errorf("adopted an entry whose MAC is not the registered one: %+v", a.Entries)
	}
}

// Several anonymous entries, only some registered. Deleting by index is where
// this goes wrong quietly: uci renumbers @host[N] as sections are removed, so
// an ascending delete takes out the wrong entries.
func TestAdoptionDeletesAnonymousEntriesInDescendingIndexOrder(t *testing.T) {
	current := []Host{
		{Section: "@host[0]", MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.11", Name: "theirs-a"},
		{Section: "@host[1]", MAC: "f8:25:51:09:38:38", IP: "192.168.1.10", Name: "parental_printer"},
		{Section: "@host[2]", MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.12", Name: "theirs-b"},
		{Section: "@host[3]", MAC: "14:e0:1d:6a:9c:6c", IP: "192.168.1.123", Name: "eli"},
	}
	a := PlanAdoption(current, map[string]string{
		"f8:25:51:09:38:38": "printer",
		"14:e0:1d:6a:9c:6c": "eli phone",
	})

	var deleteOrder []int
	for _, cmd := range a.Commands {
		if !strings.Contains(cmd, "delete") {
			continue
		}
		deleteOrder = append(deleteOrder, anonIndex(strings.TrimSuffix(
			strings.TrimPrefix(cmd, "uci -q delete dhcp."), " || true")))
	}
	if len(deleteOrder) != 2 {
		t.Fatalf("want two deletes, got %v from %v", deleteOrder, a.Commands)
	}
	if deleteOrder[0] < deleteOrder[1] {
		t.Errorf("deletes must run highest index first, got %v", deleteOrder)
	}
	// And the two entries curfew knows nothing about must not be mentioned.
	joined := strings.Join(a.Commands, "\n")
	for _, forbidden := range []string{"@host[0]", "@host[2]", "aa:aa", "bb:bb"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("adoption touched an unregistered device's entry (%q):\n%s", forbidden, joined)
		}
	}
}

// An entry curfew already owns is not "adopted" again, or every run would
// churn the config.
func TestAdoptionSkipsEntriesCurfewAlreadyOwns(t *testing.T) {
	current := []Host{
		{Section: "curfew_14e01d6a9c6c", MAC: "14:e0:1d:6a:9c:6c", IP: "192.168.1.123", Name: "eli phone"},
	}
	a := PlanAdoption(current, map[string]string{"14:e0:1d:6a:9c:6c": "eli phone"})
	if len(a.Entries) != 0 || len(a.Commands) != 0 {
		t.Errorf("re-adopted an entry curfew already owns: %+v", a)
	}
}
