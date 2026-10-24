//go:build linux

package leases

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Acceptance tests for the FIXED ADDRESS against real uci and a real dnsmasq,
// in the OpenWrt image (docker/acceptance.sh). They skip elsewhere.

const liveNetworkConfig = `
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1/24'
	option ip6assign '60'
`

func writeNetwork(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile("/etc/config/network", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove("/etc/config/network") })
}

// printerSection is the household's own entry, as text, so "untouched" can be
// asserted byte for byte rather than field by field.
func printerSection(t *testing.T) string {
	t.Helper()
	file, err := os.ReadFile("/etc/config/dhcp")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)config host\n\toption mac 'F8:25:51:09:38:38'.*?(\n\n|$)`).Find(file)
	if m == nil {
		t.Fatalf("the household's printer entry is missing:\n%s", file)
	}
	// Trimmed, because what FOLLOWS the section (a blank line before curfew's
	// own section, or the end of the file) is not part of it.
	return strings.TrimSpace(string(m))
}

// pass runs what the daemon runs, minus Apply's dnsmasq liveness gate (this
// image has no procd, so there is no service to be alive; see applyCommands).
func pass(t *testing.T, devices []Device) Plan {
	t.Helper()
	r := shellRunner{t}
	lan, lanErr := ReadLAN(r)
	screened, refused := ScreenFixed(lan, lanErr, devices)
	current, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	plan := Reconcile(current, screened)
	plan.Refused = append(refused, plan.Refused...)
	applyCommands(t, plan)
	return plan
}

func TestAFixedAddressLandsInTheRealDHCPConfigAndNothingElseMoves(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	writeNetwork(t, liveNetworkConfig)
	before := printerSection(t)

	plan := pass(t, []Device{{MAC: shyrkaMAC, Name: "shyrka", IP: "192.168.1.226", Fixed: "192.168.1.150"}})
	if len(plan.Refused) != 0 {
		t.Fatalf("unexpected refusal: %+v", plan.Refused)
	}

	file, _ := os.ReadFile("/etc/config/dhcp")
	got := string(file)
	section := regexp.MustCompile(`(?s)config host '` + shyrkaSection + `'.*?(\n\n|$)`).FindString(got)
	if section == "" {
		t.Fatalf("no curfew-owned section for shyrka:\n%s", got)
	}
	for _, must := range []string{"option mac '84:47:09:84:8e:b2'", "option ip '192.168.1.150'", "option curfew '1'"} {
		if !strings.Contains(section, must) {
			t.Errorf("shyrka's section lacks %q:\n%s", must, section)
		}
	}
	if strings.Contains(section, "option name") {
		t.Errorf("a name was written; dnsmasq refuses to start on a bad one:\n%s", section)
	}
	if after := printerSection(t); after != before {
		t.Errorf("the household's own entry changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	for _, must := range []string{"6,192.168.1.1", "42,192.168.1.1", "option port '54'"} {
		if !strings.Contains(got, must) {
			t.Errorf("unrelated dhcp config was destroyed (%q)", must)
		}
	}

	// dnsmasq accepts the result (the init script's dhcp-host rendering).
	dnsmasqAccepts(t)

	// And a second pass is a no-op, so the daemon does not reload every tick.
	current, _ := Read(shellRunner{t})
	if again := Reconcile(current, []Device{{MAC: shyrkaMAC, IP: "192.168.1.226", Fixed: "192.168.1.150"}}); len(again.Commands) != 0 {
		t.Errorf("a converged fixed address is rewritten every pass:\n%v", again.Commands)
	}
}

// The printer's foreign entry holds 192.168.1.10. Asking for it is refused by
// the pre-write check AND by the reconciler, and the file is not touched at
// all: a duplicate dhcp-host address stops dnsmasq starting (measured, below).
func TestADuplicateFixedAddressIsRefusedAndTheFileIsUntouched(t *testing.T) {
	requireUCI(t)
	writeDHCP(t, realRouterDHCP)
	writeNetwork(t, liveNetworkConfig)
	r := shellRunner{t}
	before, _ := os.ReadFile("/etc/config/dhcp")

	s, err := ReadSurvey(r, filepath.Join(t.TempDir(), "no-leases-yet"))
	if err != nil {
		t.Fatal(err)
	}
	c := s.CheckFixed(shyrkaMAC, "192.168.1.10", nil)
	if len(c.Errors) != 1 || !strings.Contains(c.Errors[0], "@host[0]") {
		t.Errorf("the check run before any write did not refuse it: %+v", c)
	}

	plan := pass(t, []Device{{MAC: shyrkaMAC, Name: "shyrka", Fixed: "192.168.1.10"}})
	if len(plan.Refused) != 1 {
		t.Errorf("the reconciler did not refuse it: %+v", plan.Refused)
	}
	after, _ := os.ReadFile("/etc/config/dhcp")
	if string(after) != string(before) {
		t.Errorf("a refused fixed address still changed the file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The measurement behind the uniqueness rule: dnsmasq does not skip a second
// dhcp-host line for an address, it refuses to start.
func TestDnsmasqRefusesToStartOnADuplicateReservation(t *testing.T) {
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("no dnsmasq; run this in the test image")
	}
	conf := filepath.Join(t.TempDir(), "dup.conf")
	os.WriteFile(conf, []byte("dhcp-host=aa:aa:aa:aa:aa:01,192.168.1.150\n"+
		"dhcp-host=aa:aa:aa:aa:aa:02,192.168.1.150\n"), 0o644)
	out, err := exec.Command("dnsmasq", "--test", "-C", conf).CombinedOutput()
	if err == nil {
		t.Errorf("dnsmasq accepted two reservations for one address; the uniqueness "+
			"rule's rationale no longer holds and docs/adr/0012 should be revisited: %s", out)
	}
	t.Logf("dnsmasq on a duplicate reservation: %s", strings.TrimSpace(string(out)))
}

func dnsmasqAccepts(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		return
	}
	conf := filepath.Join(t.TempDir(), "dnsmasq.conf")
	os.WriteFile(conf, []byte(renderHosts(t)), 0o644)
	if out, err := exec.Command("dnsmasq", "--test", "-C", conf).CombinedOutput(); err != nil {
		t.Errorf("dnsmasq refuses the config curfew caused:\n%s\n%s", out, renderHosts(t))
	}
}

// renderHosts turns what uci holds into dhcp-host lines, as OpenWrt's dnsmasq
// init script does.
func renderHosts(t *testing.T) string {
	t.Helper()
	hosts, err := Read(shellRunner{t})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString("dhcp-host=" + h.MAC + "," + h.IP)
		if h.Name != "" {
			b.WriteString("," + h.Name)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---- a real DHCP exchange ----

const (
	dhcpNS     = "curfewdhcp"
	dhcpBridge = "br-dhcp-t"
	dhcpRouter = "10.98.1.1"
	clientMAC  = "02:00:5e:10:00:42"
)

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %s %v", cmd, out, err)
	}
	return string(out)
}

// This busybox has no pkill, so signals go through pgrep. The first character
// is bracketed so the pattern cannot match the `sh -c` running it, whose own
// command line contains the pattern text (it did, and killed itself).
const (
	clientProc  = "[u]dhcpc -i dhcp1"
	dnsmasqProc = "[d]nsmasq -k -C /tmp/curfew-dhcp-test"
)

func signal(sig, proc string) string {
	return fmt.Sprintf("pgrep -f '%s' | xargs -r kill -%s", proc, sig)
}

func running(proc string) bool {
	out, _ := exec.Command("sh", "-c", "pgrep -f '"+proc+"'").Output()
	return len(strings.TrimSpace(string(out))) > 0
}

func dhcpTeardown() {
	exec.Command("sh", "-c", signal("TERM", clientProc)+" ; "+signal("TERM", dnsmasqProc)+" ; "+
		"ip netns delete "+dhcpNS+" ; ip link delete "+dhcpBridge+" ; true").Run()
}

// startDnsmasq runs a real dnsmasq on the test bridge with the dhcp-host lines
// uci holds, the way OpenWrt's init script renders them, and reports whether
// it is still running a moment later: dnsmasq exits rather than skipping a
// line it rejects, so being alive is the assertion that matters.
func startDnsmasq(t *testing.T, conf, leasefile string) {
	t.Helper()
	body := fmt.Sprintf("port=0\ninterface=%s\nbind-interfaces\ndhcp-authoritative\n"+
		"dhcp-range=10.98.1.100,10.98.1.249,12h\ndhcp-leasefile=%s\n%s", dhcpBridge, leasefile, renderHosts(t))
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Stop the previous instance and WAIT for it, or the new one cannot bind
	// and the liveness check below would be looking at the old process.
	sh(t, signal("TERM", dnsmasqProc)+" ; true")
	for i := 0; running(dnsmasqProc); i++ {
		if i > 50 {
			t.Fatal("the previous dnsmasq would not stop")
		}
		time.Sleep(100 * time.Millisecond)
	}
	sh(t, fmt.Sprintf("dnsmasq -k -C %s >%s.log 2>&1 </dev/null &", conf, conf))
	time.Sleep(1500 * time.Millisecond)
	if !running(dnsmasqProc) {
		log, _ := os.ReadFile(conf + ".log")
		t.Fatalf("dnsmasq is NOT running on the config curfew caused, so nothing could get an address:\n%s\n%s", log, body)
	}
}

// waitBound waits until the client script has logged a new address.
func waitBound(t *testing.T, logPath string, after int) (string, int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for i := after; i < len(lines); i++ {
			f := strings.Fields(lines[i])
			if len(f) == 2 && (f[0] == "bound" || f[0] == "renew") {
				return f[1], i + 1
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	data, _ := os.ReadFile(logPath)
	t.Fatalf("the client never got an address:\n%s", data)
	return "", 0
}

// waitFor reports whether the client logged binding to ip after line `after`.
func waitFor(logPath string, after int, ip string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for i := after; i < len(lines); i++ {
			f := strings.Fields(lines[i])
			if len(f) == 2 && (f[0] == "bound" || f[0] == "renew") && f[1] == ip {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// The end-to-end claim: a device holding a dynamic lease is given a fixed
// address, curfew writes it, dnsmasq keeps running, and when the device RENEWS
// (not reboots) it is moved onto the fixed address. "It moves on its next
// renewal" is what curfew tells a user, so it is measured here, not assumed.
func TestARealClientMovesToItsFixedAddressOnRenewal(t *testing.T) {
	requireUCI(t)
	for _, tool := range []string{"dnsmasq", "udhcpc", "nsenter"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s; run this in the test image", tool)
		}
	}
	if _, err := exec.Command("sh", "-c", "ip netns list").CombinedOutput(); err != nil {
		t.Skip("no netns support")
	}
	dhcpTeardown()
	t.Cleanup(dhcpTeardown)

	// A LAN that is NOT 192.168.1.0/24, so nothing here can pass by a
	// hardcoded subnet.
	writeNetwork(t, "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.98.1.1'\n\toption netmask '255.255.255.0'\n")
	writeDHCP(t, "config dhcp 'lan'\n\toption interface 'lan'\n\toption start '100'\n\toption limit '150'\n\toption leasetime '12h'\n")

	sh(t, "mkdir -p /var/run/netns && ip netns add "+dhcpNS)
	sh(t, "ip link add "+dhcpBridge+" type bridge && ip addr add "+dhcpRouter+"/24 dev "+dhcpBridge+" && ip link set "+dhcpBridge+" up")
	sh(t, "ip link add dhcp0 type veth peer name dhcp1 && ip link set dhcp0 master "+dhcpBridge+" && ip link set dhcp0 up")
	sh(t, "ip link set dhcp1 netns "+dhcpNS)
	in := "nsenter --net=/var/run/netns/" + dhcpNS + " "
	sh(t, in+"ip link set dhcp1 address "+clientMAC+" && "+in+"ip link set dhcp1 up")

	dir := t.TempDir()
	script := filepath.Join(dir, "script")
	clientLog := filepath.Join(dir, "client.log")
	os.WriteFile(script, []byte("#!/bin/sh\necho \"$1 $ip\" >> "+clientLog+"\n"), 0o755)
	conf := "/tmp/curfew-dhcp-test.conf"
	leasefile := filepath.Join(dir, "dhcp.leases")
	t.Cleanup(func() { os.Remove(conf); os.Remove(conf + ".log") })

	// 1. No reservation: the client gets whatever dnsmasq picks.
	startDnsmasq(t, conf, leasefile)
	sh(t, in+"udhcpc -i dhcp1 -f -s "+script+" -t 10 -T 1 >"+dir+"/udhcpc.out 2>&1 </dev/null &")
	first, seen := waitBound(t, clientLog, 0)
	fixed := "10.98.1.150"
	if first == fixed {
		fixed = "10.98.1.151"
	}
	t.Logf("dynamic lease: %s; fixed address chosen: %s", first, fixed)

	// 2. The check run before any write sees the REAL lease and says the
	//    device will move on renewal.
	s, err := ReadSurvey(shellRunner{t}, leasefile)
	if err != nil {
		t.Fatal(err)
	}
	c := s.CheckFixed(clientMAC, fixed, nil)
	if len(c.Errors) != 0 {
		t.Fatalf("unexpected refusal: %v", c.Errors)
	}
	if !strings.Contains(strings.Join(c.Warnings, "\n"), first) {
		t.Errorf("the check should say the device is at %s until it renews: %v", first, c.Warnings)
	}

	// 3. curfew pins it, dnsmasq restarts on the result and stays up.
	plan := pass(t, []Device{{MAC: clientMAC, IP: first, Fixed: fixed}})
	if len(plan.Refused) != 0 {
		t.Fatalf("unexpected refusal: %+v", plan.Refused)
	}
	startDnsmasq(t, conf, leasefile)

	// 4. A RENEWAL (SIGUSR1), not a reboot. dnsmasq must refuse the old
	//    address and the client must end up on the fixed one.
	sh(t, signal("USR1", clientProc))
	if !waitFor(clientLog, seen, fixed, 30*time.Second) {
		data, _ := os.ReadFile(clientLog)
		out, _ := os.ReadFile(dir + "/udhcpc.out")
		t.Fatalf("after renewing, the client never reached its fixed address %s:\n%s\n%s", fixed, data, out)
	}
	leases, _ := os.ReadFile(leasefile)
	if !strings.Contains(string(leases), clientMAC+" "+fixed) {
		t.Errorf("dnsmasq's lease file does not show the move:\n%s", leases)
	}
	data, _ := os.ReadFile(clientLog)
	t.Logf("client events across the move:\n%s", data)
}
