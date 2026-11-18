//go:build linux

package dnspolicy

import (
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnstest"
	"github.com/wighawag/curfew/internal/leases"
)

// Local DNS names against a REAL AdGuard, asserted on real answers. The
// upstream answers every name under test with a sentinel, so "AAAA gets no
// address" cannot be satisfied by a question that was forwarded.

func startAdGuardForNames(t *testing.T) *adguard.Client {
	t.Helper()
	requireAdGuard(t)
	startAdGuard(t)
	// Swap startAdGuard's fixture for the sentinel upstream on the same port.
	_, _ = sh("killall dnsmasq 2>/dev/null")
	stop, err := dnstest.StartUpstream("lan.telemaque.ska.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return adguard.NewClient(aghAPI, "parent", aghPwd)
}

func askAdGuard(t *testing.T, name string, typ dnsmessage.Type) dnstest.Answer {
	t.Helper()
	a, err := dnstest.Query("127.0.0.1:53", name, typ)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAdGuardAnswersALocalNameAOnlyAndRemovesOnlyItsOwnRewrite(t *testing.T) {
	api := startAdGuardForNames(t)
	if err := api.AddRewrite("router.home.arpa", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	if a := askAdGuard(t, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Fatalf("baseline: the upstream should answer before curfew writes anything, got %s", a)
	}

	path := filepath.Join(t.TempDir(), "dns-records.json")
	save := func(rs []dnsledger.Rewrite) error {
		return dnsledger.Save(path, &dnsledger.Ledger{AdGuard: rs})
	}
	targets := []leases.NameTarget{{MAC: "38:05:25:3a:b0:70", Name: "*.lan.telemaque.ska.sh", IP: "192.168.1.122"}}
	rep, err := ReconcileRewrites(api, targets, &dnsledger.Ledger{}, save)
	if err != nil {
		t.Fatal(err)
	}
	if err := save(rep.Final); err != nil {
		t.Fatal(err)
	}

	if a := askAdGuard(t, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); len(a.A) != 1 || a.A[0] != "192.168.1.122" {
		t.Errorf("A: want 192.168.1.122, got %s", a)
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnstest.TypeHTTPS} {
		if a := askAdGuard(t, "breakoutbunny.lan.telemaque.ska.sh", typ); !a.NoData() || a.Sentinel() {
			t.Errorf("%s: want NOERROR with no answer and nothing forwarded, got %s", typ, a)
		}
	}
	if a := askAdGuard(t, "lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Errorf("the apex of a *. name must not be answered by AdGuard, got %s", a)
	}

	// A second pass writes nothing.
	l, _ := dnsledger.Load(path)
	rep, err = ReconcileRewrites(api, targets, l, save)
	if err != nil || rep.Changed() {
		t.Errorf("a converged pass wrote: %+v %v", rep, err)
	}

	// Removing the name removes exactly curfew's rewrite.
	l, _ = dnsledger.Load(path)
	if _, err := ReconcileRewrites(api, nil, l, save); err != nil {
		t.Fatal(err)
	}
	if a := askAdGuard(t, "breakoutbunny.lan.telemaque.ska.sh", dnsmessage.TypeA); !a.Sentinel() {
		t.Errorf("after removal the upstream should answer again, got %s", a)
	}
	list, err := api.Rewrites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Domain != "router.home.arpa" || list[0].Answer != "192.168.1.1" {
		t.Errorf("the household's rewrite must be all that is left: %+v", list)
	}
}
