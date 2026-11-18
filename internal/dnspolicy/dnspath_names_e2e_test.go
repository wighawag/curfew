//go:build linux

package dnspolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnstest"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// The household's own case, end to end, as the daemon runs it: "workstation
// igc" at its fixed address 192.168.1.122 carries *.lan.telemaque.ska.sh, and
// one Manager.Tick against REAL uci, a REAL dnsmasq on 54 and a REAL AdGuard
// on 53 must make both resolvers answer it, A only. Then the REAL
// legacy/scripts/panic-off.sh hands port 53 back to dnsmasq, and the name must
// still resolve, while the public-record failure it fixes (rebind protection
// dropping an upstream private answer) is shown to be real on the same
// resolver. This is the harness version of the owner's live-router checklist.
//
// What is played: procd, which this image does not run. `/etc/init.d/dnsmasq`
// is answered by rendering the DNS options from the uci file exactly as the
// init script does and restarting a real dnsmasq on the configured port.
//
// Mutation-checked 2026-11-18: with the local-only `server` entry not written,
// this fails on dnsmasq at 54 and at 53 with AAAA 2606:4700::66, the upstream
// sentinel, i.e. the AAAA question was forwarded.

const e2eDHCP = `
config dnsmasq
	option port '54'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	list server '/corp.example/10.0.0.1'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	list dhcp_option '6,192.168.1.1'

config host
	option mac 'F8:25:51:09:38:38'
	option ip '192.168.1.10'
`

const igcMAC = "38:05:25:3a:b0:70"

type e2eRouter struct {
	t    *testing.T
	res  *dnstest.Resolver
	conf string
}

func (r *e2eRouter) Run(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "/etc/init.d/dnsmasq"):
		r.restart()
		return "", nil
	case strings.HasPrefix(cmd, "pgrep dnsmasq"):
		if r.res != nil {
			return "yes\n", nil
		}
		return "no\n", nil
	case strings.Contains(cmd, "uci show network.lan"):
		return "network.lan=interface\nnetwork.lan.ipaddr='192.168.1.1/24'\n", nil
	case strings.Contains(cmd, "ip -6 neigh"), strings.HasPrefix(cmd, "logread"):
		return "", nil
	}
	out, err := exec.Command("sh", "-c", cmd).Output()
	return string(out), err
}

// restart plays procd: dnsmasq on whatever port uci now says (53 when unset).
func (r *e2eRouter) restart() {
	r.res.Stop()
	r.res = nil
	port := 53
	if out, _ := exec.Command("sh", "-c", "uci -q get dhcp.@dnsmasq[0].port").Output(); strings.TrimSpace(string(out)) == "54" {
		port = 54
	}
	show, _ := exec.Command("sh", "-c", "uci show dhcp").Output()
	res, err := dnstest.StartResolver(port, r.conf, dnstest.DnsmasqDNSOptions(string(show)))
	if err != nil {
		r.t.Logf("dnsmasq did not start: %v", err)
		return
	}
	r.res = res
}

func panicOffScript(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"legacy/scripts/panic-off.sh", "../../legacy/scripts/panic-off.sh"} {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skip("legacy/scripts/panic-off.sh not found")
	return ""
}

func expectLocal(t *testing.T, where, server string) {
	t.Helper()
	a, err := dnstest.Query(server, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	if len(a.A) != 1 || a.A[0] != "192.168.1.122" {
		t.Errorf("%s: A breakoutbunny.lan.telemaque.ska.sh: want 192.168.1.122, got %s", where, a)
	}
	a, err = dnstest.Query(server, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatalf("%s: %v", where, err)
	}
	if !a.NoData() || a.Sentinel() {
		t.Errorf("%s: AAAA: want NOERROR, no address, nothing forwarded; got %s", where, a)
	}
}

func TestTheHouseholdsLocalNameResolvesFromBothResolversAndAfterPanicOff(t *testing.T) {
	for _, tool := range []string{"uci", "dnsmasq", "flock", "mkfifo"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s; run this in the OpenWrt test image", tool)
		}
	}
	api := startAdGuardForNames(t) // AdGuard on 53, sentinel upstream on 5454
	script := panicOffScript(t)

	prevDHCP, prevErr := os.ReadFile("/etc/config/dhcp")
	if err := os.WriteFile("/etc/config/dhcp", []byte(e2eDHCP), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll("/tmp/.uci")
	t.Cleanup(func() {
		if prevErr == nil {
			_ = os.WriteFile("/etc/config/dhcp", prevDHCP, 0o644)
		} else {
			_ = os.Remove("/etc/config/dhcp")
		}
	})
	router := &e2eRouter{t: t, conf: filepath.Join(t.TempDir(), "dnsmasq.conf")}
	router.restart()
	if router.res == nil {
		t.Fatal("dnsmasq does not start on the household's own config")
	}
	t.Cleanup(func() { router.res.Stop() })

	// A hand-made rewrite that must survive everything below.
	if err := api.AddRewrite("router.home.arpa", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	leaseFile := filepath.Join(dir, "dhcp.leases")
	if err := os.WriteFile(leaseFile, []byte("1786220000 "+igcMAC+" 192.168.1.122 telemaque *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := &registry.Registry{Devices: []registry.Device{{MAC: igcMAC, Name: "workstation igc",
		IP: "192.168.1.122", DNSNames: []string{"*.lan.telemaque.ska.sh"}}}}
	ledger := filepath.Join(dir, "dns-records.json")
	m := NewManager(Config{
		Registry: memRegistry{reg}, Schedule: memSchedule{&schedule.Profiles{}},
		Runner: router, API: api, Rewrites: api,
		ListURL: "http://127.0.0.1:1/unused", LANInterface: "br-lan",
		LeasePath: leaseFile, LedgerPath: ledger, Location: time.UTC,
	})

	// Baseline: before the daemon runs, the name is only the upstream's.
	if a, _ := dnstest.Query("127.0.0.1:53", "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Fatalf("baseline: AdGuard should forward the name before curfew writes anything, got %s", a)
	}

	_ = m.Tick() // the restrictions half has nothing to do and may complain; names are what matter
	if router.res == nil {
		t.Fatal("dnsmasq is not running after the daemon's pass")
	}
	expectLocal(t, "AdGuard on 53", "127.0.0.1:53")
	expectLocal(t, "dnsmasq on 54", router.res.Addr())

	// panic-off, the real script: AdGuard stopped, dnsmasq back to 53.
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), "NFT=true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("panic-off.sh: %v\n%s", err, out)
	}
	for i := 0; i < 50; i++ {
		if out, _ := exec.Command("sh", "-c", "pgrep AdGuardHome").Output(); len(out) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if port, _ := exec.Command("sh", "-c", "uci -q get dhcp.@dnsmasq[0].port").Output(); strings.TrimSpace(string(port)) != "53" {
		t.Fatalf("panic-off did not move dnsmasq back to 53: %q", port)
	}
	router.restart() // what procd does for the script's `/etc/init.d/dnsmasq restart`
	if router.res == nil || router.res.Port != 53 {
		t.Fatal("dnsmasq is not serving on 53 after panic-off")
	}
	expectLocal(t, "dnsmasq on 53 after panic-off", "127.0.0.1:53")
	// And the failure the local record replaces is real on this resolver.
	if a, _ := dnstest.Query("127.0.0.1:53", dnstest.PrivateName, dnsmessage.TypeA); len(a.A) != 0 {
		t.Errorf("baseline: rebind protection should drop an upstream private answer, got %s", a)
	}

	// The name is removed while AdGuard is down: dnsmasq stops answering it
	// (the dnsmasq half needs no AdGuard), and nothing curfew did not write
	// is touched.
	reg.Devices[0].DNSNames = nil
	_ = m.Tick()
	if router.res == nil {
		t.Fatal("dnsmasq is not running after removing the name")
	}
	if a, _ := dnstest.Query("127.0.0.1:53", "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Errorf("after removal dnsmasq should forward the name again, got %s", a)
	}
	if srv, _ := exec.Command("sh", "-c", "uci -q get dhcp.@dnsmasq[0].server").Output(); strings.TrimSpace(string(srv)) != "/corp.example/10.0.0.1" {
		t.Errorf("the household's server entry changed: %q", srv)
	}
	l, _ := dnsledger.Load(ledger)
	if len(l.Dnsmasq) != 0 {
		t.Errorf("the dnsmasq half of the ledger still owns removed entries: %+v", l.Dnsmasq)
	}
	// AdGuard was down, so its rewrite is still recorded as curfew's, to be
	// removed when it is back: nothing is orphaned.
	if len(l.AdGuard) != 1 {
		t.Errorf("the AdGuard rewrite must stay recorded while AdGuard is unreachable: %+v", l.AdGuard)
	}
}
