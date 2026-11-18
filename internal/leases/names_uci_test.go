//go:build linux

package leases

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnstest"
)

// Local DNS names against REAL uci and a REAL dnsmasq, in the OpenWrt image.
//
// The pass runs for real through Pass and Apply. The image has no procd, so
// `/etc/init.d/dnsmasq reload|restart` is played by routerDnsmasq below: it
// renders the DNS options from the uci file exactly as the init script does
// and restarts a real dnsmasq on them. Everything a client then sees is a real
// answer from that dnsmasq, with an upstream that answers every name under
// test with a sentinel, so a forwarded question cannot pass for a local one.

func requireDnsmasq(t *testing.T) {
	t.Helper()
	requireUCI(t)
	for _, tool := range []string{"dnsmasq", "flock", "mkfifo"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s; run this in the OpenWrt test image", tool)
		}
	}
}

// A router-shaped dhcp config: rebind protection, the household's local
// domain, dnsmasq on 54, plus somebody else's host entry and list entries
// that must come out byte-for-byte unchanged.
const namesDHCP = `
config dnsmasq
	option port '54'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	list server '/corp.example/10.0.0.1'
	list address '/handmade.example/192.168.1.77'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'

config host
	option mac 'F8:25:51:09:38:38'
	option ip '192.168.1.10'
	option name 'parental_printer'
`

const namesNetwork = `network.lan=interface
network.lan.ipaddr='192.168.1.1/24'
`

// routerDnsmasq is the runner: the real shell, except the init script, which
// it replaces with "render uci, restart a real dnsmasq on the DNS port".
type routerDnsmasq struct {
	t    *testing.T
	port int
	conf string
	res  *dnstest.Resolver
}

func (r *routerDnsmasq) Run(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "/etc/init.d/dnsmasq"):
		r.restart()
		return "", nil
	case strings.HasPrefix(cmd, "uci show network.lan"):
		return namesNetwork, nil
	case strings.HasPrefix(cmd, "logread"):
		return "", nil
	case strings.HasPrefix(cmd, "pgrep dnsmasq"):
		if r.res != nil {
			return "yes\n", nil
		}
		return "no\n", nil
	}
	out, err := exec.Command("sh", "-c", cmd).Output()
	return string(out), err
}

func (r *routerDnsmasq) restart() {
	r.res.Stop()
	r.res = nil
	show, _ := exec.Command("sh", "-c", "uci show dhcp").Output()
	res, err := dnstest.StartResolver(r.port, r.conf, dnstest.DnsmasqDNSOptions(string(show)))
	if err != nil {
		r.t.Logf("dnsmasq did not start: %v", err)
		return
	}
	r.res = res
}

func setUpNames(t *testing.T) (*routerDnsmasq, string) {
	t.Helper()
	requireDnsmasq(t)
	writeDHCP(t, namesDHCP)
	_ = os.RemoveAll("/tmp/.uci")
	_ = os.RemoveAll(StageDir)
	stop, err := dnstest.StartUpstream("lan.telemaque.ska.sh", "nas.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	r := &routerDnsmasq{t: t, port: 5454 + 100, conf: filepath.Join(t.TempDir(), "dnsmasq.conf")}
	r.restart()
	if r.res == nil {
		t.Fatal("dnsmasq does not even start on the household's own config")
	}
	t.Cleanup(func() { r.res.Stop(); stop() })
	return r, filepath.Join(t.TempDir(), "dns-records.json")
}

func ask(t *testing.T, r *routerDnsmasq, name string, typ dnsmessage.Type) dnstest.Answer {
	t.Helper()
	a, err := dnstest.Query(r.res.Addr(), name, typ)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// foreignLines is everything in the dhcp config curfew does not own: the
// household's host entry line by line, and each of its own list values (the
// list LINES legitimately gain curfew's values, so the values are compared).
func foreignLines(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("sh", "-c", "uci show dhcp | grep '@host'").Output()
	addr, _ := exec.Command("sh", "-c", "uci -q get dhcp.@dnsmasq[0].address").Output()
	srv, _ := exec.Command("sh", "-c", "uci -q get dhcp.@dnsmasq[0].server").Output()
	var keep []string
	for _, v := range strings.Fields(string(addr) + " " + string(srv)) {
		if strings.Contains(v, "corp.example") || strings.Contains(v, "handmade.example") {
			keep = append(keep, v)
		}
	}
	return string(out) + strings.Join(keep, "\n")
}

func TestDnsmasqAnswersALocalNameAOnlyAndNeverForwardsTheRest(t *testing.T) {
	r, ledger := setUpNames(t)
	before := foreignLines(t)

	// Baseline: before curfew writes anything, the name is the upstream's.
	if a := ask(t, r, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Fatalf("baseline: the upstream should answer before any local record exists, got %s", a)
	}

	devices := []Device{{MAC: igcMAC, Name: "workstation igc", Fixed: "192.168.1.122",
		DNSNames: []string{"*.lan.telemaque.ska.sh"}}}
	if _, err := Pass(r, devices, PassOptions{LedgerPath: ledger}); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if r.res == nil {
		t.Fatal("dnsmasq is not running after the pass")
	}

	if a := ask(t, r, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); len(a.A) != 1 || a.A[0] != "192.168.1.122" {
		t.Errorf("A: want 192.168.1.122, got %s", a)
	}
	if a := ask(t, r, "a.b.lan.telemaque.ska.sh", dnsmessage.TypeA); len(a.A) != 1 || a.A[0] != "192.168.1.122" {
		t.Errorf("A two levels down: want 192.168.1.122, got %s", a)
	}
	// Mutation-checked 2026-11-18: with the `server` entry not written, this
	// fails with AAAA 2606:4700::66 (the sentinel) and HTTPS REFUSED by the
	// upstream, i.e. both forwarded, which is the finding's measurement.
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnstest.TypeHTTPS} {
		if a := ask(t, r, "breakoutbunny.lan.telemaque.ska.sh", typ); !a.NoData() || a.Sentinel() {
			t.Errorf("%s: want NOERROR with no answer and nothing forwarded, got %s", typ, a)
		}
	}
	// The *. meaning: the apex is NOT ours, so it is still the upstream's.
	if a := ask(t, r, "lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Errorf("the apex of a *. name must not be answered locally, got %s", a)
	}
	if got := foreignLines(t); got != before {
		t.Errorf("entries curfew does not own changed:\nbefore:\n%s\nafter:\n%s", before, got)
	}

	// A second pass changes nothing and does not reload.
	plan, err := Pass(r, devices, PassOptions{LedgerPath: ledger})
	if err != nil || len(plan.Commands) != 0 {
		t.Errorf("a converged pass emitted %v (%v)", plan.Commands, err)
	}

	// Removing the name removes exactly curfew's entries.
	devices[0].DNSNames = nil
	if _, err := Pass(r, devices, PassOptions{LedgerPath: ledger}); err != nil {
		t.Fatal(err)
	}
	if a := ask(t, r, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Errorf("after removal the upstream should answer again, got %s", a)
	}
	if got := foreignLines(t); got != before {
		t.Errorf("removal touched entries curfew does not own:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	l, _ := dnsledger.Load(ledger)
	if len(l.Dnsmasq) != 0 {
		t.Errorf("the ledger still owns removed entries: %+v", l.Dnsmasq)
	}
}

// The bug this fixes, reproduced: rebind protection drops a PUBLIC answer
// that points at a private address, and does not touch a LOCAL one.
func TestRebindProtectionDropsTheUpstreamPrivateAnswerButNotTheLocalOne(t *testing.T) {
	r, ledger := setUpNames(t)
	if a := ask(t, r, dnstest.PrivateName, dnsmessage.TypeA); len(a.A) != 0 {
		t.Fatalf("baseline: rebind protection should drop an upstream private answer, got %s", a)
	}
	devices := []Device{{MAC: igcMAC, Name: "workstation igc", Fixed: "192.168.1.122",
		DNSNames: []string{dnstest.PrivateName}}}
	if _, err := Pass(r, devices, PassOptions{LedgerPath: ledger}); err != nil {
		t.Fatal(err)
	}
	if a := ask(t, r, dnstest.PrivateName, dnsmessage.TypeA); len(a.A) != 1 || a.A[0] != "192.168.1.122" {
		t.Errorf("the local answer must pass rebind protection, got %s", a)
	}
}

// A change dnsmasq refuses must be rolled back, leaving it running and
// answering on the household's previous config.
func TestARecordDnsmasqRefusesIsRolledBackAndDnsmasqKeepsAnswering(t *testing.T) {
	r, _ := setUpNames(t)
	_, err := Apply(r, Plan{Commands: []string{
		"uci add_list dhcp.@dnsmasq[0].address='/broken.example/not-an-address'",
	}})
	if err == nil {
		t.Fatal("a record dnsmasq refuses must be an error")
	}
	if r.res == nil {
		t.Fatal("dnsmasq is not running after the rollback")
	}
	out, _ := exec.Command("sh", "-c", "uci show dhcp").Output()
	if strings.Contains(string(out), "not-an-address") {
		t.Errorf("the bad record survived the rollback:\n%s", out)
	}
	if a := ask(t, r, "example.com", dnsmessage.TypeA); len(a.A) != 1 {
		t.Errorf("dnsmasq is running but not answering after the rollback: %s", a)
	}
}
