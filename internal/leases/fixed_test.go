package leases

import (
	"strings"
	"testing"
	"time"
)

// Tests for sticky pins and the FIXED ADDRESS. The incident behind them: shyrka
// (84:47:09:84:8e:b2) was pinned at the address it was observed at, the pin
// was deleted the first tick shyrka had no lease in /tmp/dhcp.leases, and the
// next tick curfew pinned wherever it came back (192.168.1.226). Its service
// bound to 192.168.1.150 could not start. See
// work/specs/proposed/fixed-address-per-device.md and docs/adr/0012.

const (
	shyrkaMAC     = "84:47:09:84:8e:b2"
	shyrkaSection = "curfew_844709848eb2"
	printerMAC    = "f8:25:51:09:38:38"
)

func owned(mac, ip string) Host { return Host{Section: SectionFor(mac), MAC: mac, IP: ip} }

func joined(p Plan) string { return strings.Join(p.Commands, "\n") }

// THE INCIDENT, as a regression test. A registered device with no lease this
// tick keeps the pin curfew already owns, and nothing is written.
func TestAnOfflineDeviceKeepsItsPin(t *testing.T) {
	plan := Reconcile(
		[]Host{owned(shyrkaMAC, "192.168.1.150")},
		[]Device{{MAC: shyrkaMAC, Name: "shyrka"}}, // no IP: not in the lease file
	)
	if len(plan.Commands) != 0 {
		t.Fatalf("an offline device lost its pin, which is how shyrka lost .150:\n%s", joined(plan))
	}
	if got := plan.Pinned[shyrkaMAC]; got != "192.168.1.150" {
		t.Errorf("the kept pin is still a pin and must be reported as one, got %q", got)
	}
	if len(plan.Unaddressed) != 0 {
		t.Errorf("a device with a pin is not unaddressed: %v", plan.Unaddressed)
	}
}

// A router reboot empties /tmp/dhcp.leases, so EVERY device is briefly absent.
// Measured on the live router: 28 registered devices with no lease and none of
// them pinned, because every pin had been swept.
func TestARouterRebootThatEmptiesTheLeaseFileChangesNothing(t *testing.T) {
	current := []Host{
		owned(shyrkaMAC, "192.168.1.150"),
		owned("14:e0:1d:6a:9c:6c", "192.168.1.123"),
		owned(printerMAC, "192.168.1.10"),
	}
	plan := Reconcile(current, []Device{
		{MAC: shyrkaMAC}, {MAC: "14:e0:1d:6a:9c:6c"}, {MAC: printerMAC},
	})
	if len(plan.Commands) != 0 {
		t.Fatalf("an empty lease file rewrote the dhcp config:\n%s", joined(plan))
	}
	if len(plan.Pinned) != 3 {
		t.Errorf("want all three pins kept and reported, got %v", plan.Pinned)
	}
}

func TestAFixedAddressIsPinnedOverTheObservedOne(t *testing.T) {
	plan := Reconcile(
		[]Host{owned(shyrkaMAC, "192.168.1.226")},
		[]Device{{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"}},
	)
	j := joined(plan)
	if !strings.Contains(j, "uci set dhcp."+shyrkaSection+".ip='192.168.1.150'") {
		t.Errorf("the fixed address was not pinned:\n%s", j)
	}
	if strings.Contains(j, ".name=") {
		t.Errorf("a name was written into the dhcp config:\n%s", j)
	}
	if plan.Pinned[shyrkaMAC] != "192.168.1.150" {
		t.Errorf("Pinned must report the fixed address, got %q", plan.Pinned[shyrkaMAC])
	}
}

func TestAFixedAddressIsPinnedForADeviceThatIsOffline(t *testing.T) {
	plan := Reconcile(nil, []Device{{MAC: shyrkaMAC, Fixed: "192.168.1.150"}})
	if !strings.Contains(joined(plan), "ip='192.168.1.150'") {
		t.Errorf("a fixed address must not depend on the device being online:\n%s", joined(plan))
	}
	if len(plan.Unaddressed) != 0 {
		t.Errorf("a device with a fixed address is not unaddressed: %v", plan.Unaddressed)
	}
}

func TestAConvergedFixedAddressEmitsNothing(t *testing.T) {
	plan := Reconcile(
		[]Host{owned(shyrkaMAC, "192.168.1.150")},
		[]Device{{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"}},
	)
	if len(plan.Commands) != 0 {
		t.Errorf("a converged fixed address restarted dnsmasq anyway:\n%s", joined(plan))
	}
}

// Clearing never moves a device: with no fixed address the pin follows what
// the device actually holds, and with no observation it stays where it is.
func TestClearingAFixedAddressDoesNotMoveTheDevice(t *testing.T) {
	current := []Host{owned(shyrkaMAC, "192.168.1.150")}
	if p := Reconcile(current, []Device{{MAC: shyrkaMAC, IP: "192.168.1.150"}}); len(p.Commands) != 0 {
		t.Errorf("clearing rewrote a pin the device already sits on:\n%s", joined(p))
	}
	if p := Reconcile(current, []Device{{MAC: shyrkaMAC}}); len(p.Commands) != 0 {
		t.Errorf("clearing on an offline device rewrote its pin:\n%s", joined(p))
	}
}

// A foreign entry already reserving the address: two dhcp-host lines for one
// address make dnsmasq refuse to start (measured, dnsmasq 2.91), so this is a
// refusal, never a write. The device falls back to the pin it already has.
func TestAFixedAddressHeldByAForeignEntryIsRefused(t *testing.T) {
	current := []Host{
		{Section: "@host[0]", MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.150", Name: "their-nas"},
		owned(shyrkaMAC, "192.168.1.226"),
	}
	plan := Reconcile(current, []Device{{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"}})
	if strings.Contains(joined(plan), "192.168.1.150") {
		t.Fatalf("a duplicate reservation was written; dnsmasq would not start:\n%s", joined(plan))
	}
	if len(plan.Refused) != 1 || plan.Refused[0].MAC != shyrkaMAC || plan.Refused[0].IP != "192.168.1.150" {
		t.Fatalf("the refusal must be reported, got %+v", plan.Refused)
	}
	if !strings.Contains(plan.Refused[0].Reason, "@host[0]") {
		t.Errorf("the refusal should name the entry holding it: %q", plan.Refused[0].Reason)
	}
	if plan.Pinned[shyrkaMAC] != "192.168.1.226" {
		t.Errorf("the device should keep the pin it has, got %q", plan.Pinned[shyrkaMAC])
	}
}

// Decided (spec decision 2): a fixed address never displaces another device's
// pin, even one that is offline, because that would silently move it.
func TestAFixedAddressHeldByAnotherDevicesPinIsRefusedNotDisplaced(t *testing.T) {
	other := "14:e0:1d:6a:9c:6c"
	current := []Host{owned(other, "192.168.1.150")}
	plan := Reconcile(current, []Device{
		{MAC: other}, // offline, but its pin is still its pin
		{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"},
	})
	if strings.Contains(joined(plan), "dhcp.curfew_14e01d6a9c6c") {
		t.Errorf("another device's pin was touched:\n%s", joined(plan))
	}
	if strings.Contains(joined(plan), "ip='192.168.1.150'") {
		t.Errorf("a duplicate reservation was written:\n%s", joined(plan))
	}
	if len(plan.Refused) != 1 || !strings.Contains(plan.Refused[0].Reason, other) {
		t.Errorf("want one refusal naming %s, got %+v", other, plan.Refused)
	}
	// It still gets pinned somewhere: at what it holds.
	if plan.Pinned[shyrkaMAC] != "192.168.1.226" {
		t.Errorf("want a fallback to the observed address, got %q", plan.Pinned[shyrkaMAC])
	}
}

// No arbitrary winner when two devices are given the same fixed address.
func TestTwoDevicesGivenTheSameFixedAddressAreBothRefused(t *testing.T) {
	plan := Reconcile(nil, []Device{
		{MAC: shyrkaMAC, Fixed: "192.168.1.150"},
		{MAC: printerMAC, Fixed: "192.168.1.150"},
	})
	if strings.Contains(joined(plan), "192.168.1.150") {
		t.Errorf("one of two clashing fixed addresses was written:\n%s", joined(plan))
	}
	if len(plan.Refused) != 2 {
		t.Errorf("want both refused, got %+v", plan.Refused)
	}
}

// The squatter: another device holds the address in the lease file. The fixed
// owner is pinned (dnsmasq never hands a reservation to another MAC), and the
// squatter is NOT also pinned there.
func TestAnObservedAddressEqualToAnotherDevicesFixedAddressIsNotPinned(t *testing.T) {
	squatter := "14:e0:1d:6a:9c:6c"
	plan := Reconcile(nil, []Device{
		{MAC: shyrkaMAC, Fixed: "192.168.1.150"},
		{MAC: squatter, IP: "192.168.1.150"},
	})
	if strings.Contains(joined(plan), "dhcp.curfew_14e01d6a9c6c") {
		t.Errorf("the squatter was pinned at the fixed address:\n%s", joined(plan))
	}
	if plan.Pinned[shyrkaMAC] != "192.168.1.150" {
		t.Errorf("the fixed owner should be pinned, got %v", plan.Pinned)
	}
	if _, ok := plan.Pinned[squatter]; ok {
		t.Errorf("the squatter must not be reported as pinned there: %v", plan.Pinned)
	}
}

// The ownership promise, unchanged: a foreign entry for the same MAC is
// yielded to and reported, even when a fixed address was asked for.
func TestAForeignEntryForAFixedAddressMACIsYieldedTo(t *testing.T) {
	current := []Host{{Section: "@host[0]", MAC: shyrkaMAC, IP: "192.168.1.99", Name: "hand-made"}}
	plan := Reconcile(current, []Device{{MAC: shyrkaMAC, Fixed: "192.168.1.150"}})
	if len(plan.Commands) != 0 {
		t.Errorf("curfew competed with a foreign entry for the same MAC:\n%s", joined(plan))
	}
	if len(plan.Conflicts) != 1 {
		t.Errorf("the clash must be reported: %+v", plan.Conflicts)
	}
}

// ---- the LAN, read from uci rather than assumed ----

const liveNetworkLAN = `network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.1.1/24'
network.lan.ip6assign='60'
`

func liveLAN(t *testing.T) LAN {
	t.Helper()
	lan, err := ParseLAN(liveNetworkLAN, realRouterUCI)
	if err != nil {
		t.Fatal(err)
	}
	return lan
}

func TestParseLANReadsTheLiveRoutersCIDRForm(t *testing.T) {
	lan := liveLAN(t)
	if lan.Router.String() != "192.168.1.1" || lan.Prefix.String() != "192.168.1.0/24" {
		t.Errorf("got router %s prefix %s", lan.Router, lan.Prefix)
	}
	if lan.PoolStart.String() != "192.168.1.100" || lan.PoolEnd.String() != "192.168.1.249" {
		t.Errorf("pool: got %s-%s, want .100-.249", lan.PoolStart, lan.PoolEnd)
	}
	if lan.LeaseTime != 12*time.Hour {
		t.Errorf("lease time: got %s", lan.LeaseTime)
	}
}

func TestParseLANReadsTheNetmaskForm(t *testing.T) {
	lan, err := ParseLAN("network.lan.ipaddr='10.0.0.1'\nnetwork.lan.netmask='255.255.0.0'\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if lan.Prefix.String() != "10.0.0.0/16" {
		t.Errorf("got %s", lan.Prefix)
	}
	// OpenWrt's defaults when dhcp.lan says nothing.
	if lan.PoolStart.String() != "10.0.0.100" || lan.PoolEnd.String() != "10.0.0.249" || lan.LeaseTime != 12*time.Hour {
		t.Errorf("defaults: %s-%s %s", lan.PoolStart, lan.PoolEnd, lan.LeaseTime)
	}
}

func TestParseLANRefusesWhenThereIsNoAddress(t *testing.T) {
	if _, err := ParseLAN("network.lan=interface\n", ""); err == nil {
		t.Error("a LAN with no address was accepted; nothing could be validated against it")
	}
}

func TestCheckAddressRefusesWhatCannotBeAHost(t *testing.T) {
	lan := liveLAN(t)
	for ip, why := range map[string]string{
		"192.168.1.0":   "the network address",
		"192.168.1.255": "the broadcast address",
		"192.168.1.1":   "the router",
		"192.168.2.150": "outside",
		"10.0.0.1":      "outside",
		"banana":        "not an IPv4 address",
		"fd00::150":     "not an IPv4 address",
	} {
		err := lan.CheckAddress(ip)
		if err == nil {
			t.Errorf("%s was accepted", ip)
			continue
		}
		if !strings.Contains(err.Error(), why) {
			t.Errorf("%s: want a reason mentioning %q, got %v", ip, why, err)
		}
	}
	for _, ok := range []string{"192.168.1.150", "192.168.1.10", "192.168.1.254"} {
		if err := lan.CheckAddress(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
}

func TestScreenFixedClearsAnInvalidAddressAndReportsIt(t *testing.T) {
	lan := liveLAN(t)
	devices, refused := ScreenFixed(lan, nil, []Device{
		{MAC: shyrkaMAC, Fixed: "192.168.1.150"},
		{MAC: printerMAC, Fixed: "192.168.1.1"},
	})
	if devices[0].Fixed != "192.168.1.150" || devices[1].Fixed != "" {
		t.Errorf("want only the invalid one cleared: %+v", devices)
	}
	if len(refused) != 1 || refused[0].MAC != printerMAC {
		t.Errorf("want the router's own address refused: %+v", refused)
	}
	// With no readable LAN NOTHING fixed is trusted, and every one is reported.
	devices, refused = ScreenFixed(LAN{}, errBoom, []Device{{MAC: shyrkaMAC, Fixed: "192.168.1.150"}})
	if devices[0].Fixed != "" || len(refused) != 1 {
		t.Errorf("an unvalidated fixed address was let through: %+v %+v", devices, refused)
	}
}

type boom struct{}

func (boom) Error() string { return "boom" }

var errBoom = boom{}

// ---- the lease file and the full check run before any write ----

const liveLeases = `1792813109 84:47:09:84:8e:b2 192.168.1.226 shyrka *
1792813000 14:e0:1d:6a:9c:6c 192.168.1.123 eli-phone 01:14:e0:1d:6a:9c:6c
1792813200 aa:bb:cc:dd:ee:ff 192.168.1.160 * *
`

func TestParseLeaseFile(t *testing.T) {
	got := ParseLeaseFile(liveLeases)
	if len(got) != 3 {
		t.Fatalf("want 3 leases, got %+v", got)
	}
	if got[0].MAC != shyrkaMAC || got[0].IP != "192.168.1.226" || got[0].Expires.Unix() != 1792813109 {
		t.Errorf("first lease: %+v", got[0])
	}
}

func survey(t *testing.T) Survey {
	t.Helper()
	return Survey{
		LAN:    liveLAN(t),
		Hosts:  append(Parse(realRouterUCI), owned("14:e0:1d:6a:9c:6c", "192.168.1.123")),
		Leases: ParseLeaseFile(liveLeases),
		Now:    time.Unix(1792780000, 0),
	}
}

func hasLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestCheckFixedForShyrka(t *testing.T) {
	c := survey(t).CheckFixed(shyrkaMAC, "192.168.1.150", nil)
	if len(c.Errors) != 0 {
		t.Fatalf("shyrka at .150 should be allowed: %v", c.Errors)
	}
	if !hasLine(c.Warnings, "inside the DHCP pool") {
		t.Errorf("an in-pool address must be said out loud: %v", c.Warnings)
	}
	if !hasLine(c.Warnings, "192.168.1.226") || !hasLine(c.Warnings, "next DHCP renewal") {
		t.Errorf("want the will-move note naming the current address: %v", c.Warnings)
	}
}

func TestCheckFixedRefusesAnAddressAnyHostEntryUses(t *testing.T) {
	s := survey(t)
	// The printer's FOREIGN entry.
	c := s.CheckFixed(shyrkaMAC, "192.168.1.10", nil)
	if len(c.Errors) != 1 || !strings.Contains(c.Errors[0], "@host[0]") {
		t.Errorf("want a refusal naming the foreign entry, got %v", c.Errors)
	}
	// Another device's OWNED pin.
	c = s.CheckFixed(shyrkaMAC, "192.168.1.123", nil)
	if len(c.Errors) != 1 || !strings.Contains(c.Errors[0], "14:e0:1d:6a:9c:6c") {
		t.Errorf("want a refusal naming the other device, got %v", c.Errors)
	}
	// This device's OWN pin is not a clash.
	c = s.CheckFixed("14:e0:1d:6a:9c:6c", "192.168.1.123", nil)
	if len(c.Errors) != 0 {
		t.Errorf("a device's own pin counted as a duplicate: %v", c.Errors)
	}
}

func TestCheckFixedRefusesAnotherDevicesFixedAddress(t *testing.T) {
	c := survey(t).CheckFixed(shyrkaMAC, "192.168.1.150", map[string]string{printerMAC: "192.168.1.150"})
	if len(c.Errors) != 1 || !strings.Contains(c.Errors[0], printerMAC) {
		t.Errorf("want a refusal naming %s, got %v", printerMAC, c.Errors)
	}
}

func TestCheckFixedRefusesAnInvalidAddress(t *testing.T) {
	c := survey(t).CheckFixed(shyrkaMAC, "192.168.1.255", nil)
	if len(c.Errors) != 1 {
		t.Errorf("the broadcast address was not refused: %v", c.Errors)
	}
}

// Another MAC holds it right now: allowed, but the move cannot complete until
// that lease is gone, and that must not be silent.
func TestCheckFixedWarnsWhenAnotherMACHoldsTheAddress(t *testing.T) {
	c := survey(t).CheckFixed(shyrkaMAC, "192.168.1.160", nil)
	if len(c.Errors) != 0 {
		t.Fatalf("unexpected refusal: %v", c.Errors)
	}
	if !hasLine(c.Warnings, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("want a warning naming the current holder: %v", c.Warnings)
	}
}

func TestCheckFixedOutsideThePoolSaysNothingAboutThePool(t *testing.T) {
	c := survey(t).CheckFixed(printerMAC, "192.168.1.20", nil)
	if hasLine(c.Warnings, "pool") {
		t.Errorf("an out-of-pool address was reported as in the pool: %v", c.Warnings)
	}
}

// ---- the whole pass, against a recording runner ----

type scriptedRunner struct {
	out map[string]string
	ran []string
}

func (s *scriptedRunner) Run(cmd string) (string, error) {
	s.ran = append(s.ran, cmd)
	for prefix, out := range s.out {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	if strings.HasPrefix(cmd, "pgrep dnsmasq") {
		return "yes\n", nil
	}
	return "", nil
}

func TestPassPinsAFixedAddressAndReportsAnInvalidOne(t *testing.T) {
	r := &scriptedRunner{out: map[string]string{
		"uci show network.lan": liveNetworkLAN,
		"uci show dhcp":        realRouterUCI,
	}}
	plan, err := Pass(r, []Device{
		{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"},
		{MAC: "14:e0:1d:6a:9c:6c", Fixed: "192.168.1.255"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(joined(plan), "ip='192.168.1.150'") {
		t.Errorf("shyrka's fixed address was not pinned:\n%s", joined(plan))
	}
	if strings.Contains(joined(plan), "192.168.1.255") {
		t.Errorf("an invalid fixed address was written:\n%s", joined(plan))
	}
	if len(plan.Refused) != 1 {
		t.Errorf("the invalid address must be reported: %+v", plan.Refused)
	}
	if !strings.Contains(strings.Join(r.ran, "\n"), "uci commit dhcp") {
		t.Errorf("the plan was not applied: %v", r.ran)
	}
}
