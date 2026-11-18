package dnspolicy

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/leases"
)

// The AdGuard half of local DNS names against a fake API that behaves like
// the measured v0.107.78: add accepts duplicates, delete removes every
// identical copy, update replaces one.

type fakeRewrites struct {
	list        []adguard.RewriteObject
	calls       []string
	rewritesOff bool
	filterOff   bool
	clients     []adguard.ClientObject
	failAdd     bool
	// onWrite is called before every write, to observe the ledger.
	onWrite func()
}

func (f *fakeRewrites) Rewrites() ([]adguard.RewriteObject, error) {
	return append([]adguard.RewriteObject(nil), f.list...), nil
}
func (f *fakeRewrites) write(c string) {
	if f.onWrite != nil {
		f.onWrite()
	}
	f.calls = append(f.calls, c)
}
func (f *fakeRewrites) AddRewrite(d, a string) error {
	f.write("add " + d + " " + a)
	if f.failAdd {
		return errors.New("HTTP 500")
	}
	f.list = append(f.list, adguard.RewriteObject{Domain: d, Answer: a})
	return nil
}
func (f *fakeRewrites) DeleteRewrite(d, a string) error {
	f.write("delete " + d + " " + a)
	var kept []adguard.RewriteObject
	for _, o := range f.list {
		if !(o.Domain == d && o.Answer == a) {
			kept = append(kept, o)
		}
	}
	f.list = kept
	return nil
}
func (f *fakeRewrites) UpdateRewrite(d, old, a string) error {
	f.write("update " + d + " " + old + " " + a)
	for i, o := range f.list {
		if o.Domain == d && o.Answer == old {
			f.list[i].Answer = a
			return nil
		}
	}
	return errors.New("no such rewrite")
}
func (f *fakeRewrites) RewritesEnabled() (bool, error)  { return !f.rewritesOff, nil }
func (f *fakeRewrites) FilteringEnabled() (bool, error) { return !f.filterOff, nil }
func (f *fakeRewrites) Clients() ([]adguard.ClientObject, error) {
	return f.clients, nil
}

func ro(d, a string) adguard.RewriteObject { return adguard.RewriteObject{Domain: d, Answer: a} }

var igcTarget = leases.NameTarget{MAC: "38:05:25:3a:b0:70", Name: "*.lan.telemaque.ska.sh", IP: "192.168.1.122"}

func run(t *testing.T, f *fakeRewrites, targets []leases.NameTarget, l *dnsledger.Ledger) (RewriteReport, []dnsledger.Rewrite) {
	t.Helper()
	var saved []dnsledger.Rewrite
	rep, err := ReconcileRewrites(f, targets, l, func(rs []dnsledger.Rewrite) error { saved = rs; return nil })
	if err != nil {
		t.Fatal(err)
	}
	return rep, saved
}

func TestANewNameIsAddedAndOwned(t *testing.T) {
	f := &fakeRewrites{}
	rep, _ := run(t, f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{})
	if strings.Join(f.calls, "|") != "add *.lan.telemaque.ska.sh 192.168.1.122" {
		t.Errorf("calls: %v", f.calls)
	}
	if len(rep.Final) != 1 || rep.Final[0] != rw("*.lan.telemaque.ska.sh", "192.168.1.122") {
		t.Errorf("final ledger: %+v", rep.Final)
	}
}

func TestABareNameIsThePairOfRewrites(t *testing.T) {
	f := &fakeRewrites{}
	run(t, f, []leases.NameTarget{{MAC: "m", Name: "nas.home.arpa", IP: "192.168.1.150"}}, &dnsledger.Ledger{})
	got := strings.Join(f.calls, "|")
	if got != "add nas.home.arpa 192.168.1.150|add *.nas.home.arpa 192.168.1.150" {
		t.Errorf("calls: %s", got)
	}
}

func TestAConvergedStateWritesNothing(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{ro("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	l := &dnsledger.Ledger{AdGuard: []dnsledger.Rewrite{rw("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	rep, _ := run(t, f, []leases.NameTarget{igcTarget}, l)
	if len(f.calls) != 0 || rep.Changed() {
		t.Errorf("a converged state wrote: %v", f.calls)
	}
}

func TestAMovedAddressIsUpdatedInPlace(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{ro("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	l := &dnsledger.Ledger{AdGuard: []dnsledger.Rewrite{rw("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	moved := igcTarget
	moved.IP = "192.168.1.123"
	rep, wa := run(t, f, []leases.NameTarget{moved}, l)
	if strings.Join(f.calls, "|") != "update *.lan.telemaque.ska.sh 192.168.1.122 192.168.1.123" {
		t.Errorf("a move must be one in-place update: %v", f.calls)
	}
	if len(rep.Final) != 1 || rep.Final[0].Answer != "192.168.1.123" {
		t.Errorf("final: %+v", rep.Final)
	}
	if len(wa) != 2 {
		t.Errorf("write-ahead must own old and new until the update lands: %+v", wa)
	}
}

func TestARemovedNameDeletesOnlyCurfewsRewrite(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{
		ro("*.lan.telemaque.ska.sh", "192.168.1.122"), ro("router.home.arpa", "192.168.1.1"),
	}}
	l := &dnsledger.Ledger{AdGuard: []dnsledger.Rewrite{rw("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	rep, _ := run(t, f, nil, l)
	if strings.Join(f.calls, "|") != "delete *.lan.telemaque.ska.sh 192.168.1.122" {
		t.Errorf("calls: %v", f.calls)
	}
	if len(f.list) != 1 || f.list[0].Domain != "router.home.arpa" {
		t.Errorf("the household's rewrite must survive: %+v", f.list)
	}
	if len(rep.Final) != 0 {
		t.Errorf("nothing is owned afterwards: %+v", rep.Final)
	}
}

func TestAForeignRewriteForTheSameDomainIsYieldedTo(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{ro("*.lan.telemaque.ska.sh", "192.168.1.99")}}
	rep, _ := run(t, f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{})
	if len(f.calls) != 0 {
		t.Errorf("curfew wrote next to a household rewrite: %v", f.calls)
	}
	if len(rep.Yielded) != 1 || !strings.Contains(rep.Yielded[0], "192.168.1.99") {
		t.Errorf("want it reported: %+v", rep.Yielded)
	}
}

func TestAnIdenticalForeignRewriteIsNotClaimed(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{ro("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	rep, _ := run(t, f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{})
	if len(f.calls) != 0 || len(rep.Final) != 0 || len(rep.Unclaimed) != 1 {
		t.Errorf("an identical household rewrite was touched or claimed: calls=%v %+v", f.calls, rep)
	}
	// So removing the name later leaves it alone.
	run(t, f, nil, &dnsledger.Ledger{})
	if len(f.list) != 1 {
		t.Errorf("the household's rewrite was deleted: %+v", f.list)
	}
}

// One delete removes every identical copy (measured), so with a household
// duplicate of curfew's rewrite, curfew deletes nothing.
func TestADuplicatedRewriteIsNotDeleted(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{
		ro("*.lan.telemaque.ska.sh", "192.168.1.122"), ro("*.lan.telemaque.ska.sh", "192.168.1.122"),
	}}
	l := &dnsledger.Ledger{AdGuard: []dnsledger.Rewrite{rw("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	rep, _ := run(t, f, nil, l)
	if len(f.calls) != 0 || len(rep.Kept) != 1 {
		t.Errorf("deleted a duplicate: %v %+v", f.calls, rep)
	}
}

func TestTheLedgerIsWrittenBeforeAdGuardIs(t *testing.T) {
	var saved []dnsledger.Rewrite
	f := &fakeRewrites{}
	f.onWrite = func() {
		if len(saved) == 0 {
			t.Error("AdGuard was written before the ledger recorded the rewrite")
		}
	}
	_, err := ReconcileRewrites(f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{},
		func(rs []dnsledger.Rewrite) error { saved = rs; return nil })
	if err != nil {
		t.Fatal(err)
	}
	// And a ledger that cannot be written stops the pass before AdGuard.
	f2 := &fakeRewrites{}
	_, err = ReconcileRewrites(f2, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{},
		func([]dnsledger.Rewrite) error { return errors.New("disk full") })
	if err == nil || len(f2.calls) != 0 {
		t.Errorf("wrote without a ledger: %v %v", err, f2.calls)
	}
}

func TestAFailedAddIsNotLeftClaimed(t *testing.T) {
	f := &fakeRewrites{failAdd: true}
	rep, err := ReconcileRewrites(f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{},
		func([]dnsledger.Rewrite) error { return nil })
	if err == nil {
		t.Fatal("a failed add must be reported")
	}
	if len(rep.Final) != 0 {
		t.Errorf("a rewrite that was never created is still claimed: %+v", rep.Final)
	}
}

func TestWhoGetsNoRewritesIsReported(t *testing.T) {
	f := &fakeRewrites{rewritesOff: true, filterOff: true, clients: []adguard.ClientObject{
		{Name: "Dad laptop", UseGlobalSettings: false, FilteringEnabled: false},
		{Name: "Mum phone", UseGlobalSettings: true, FilteringEnabled: false},
		{Name: "curfew-eli", UseGlobalSettings: false, FilteringEnabled: false},
	}}
	rep, _ := run(t, f, []leases.NameTarget{igcTarget}, &dnsledger.Ledger{})
	j := strings.Join(rep.Bypass, "\n")
	for _, want := range []string{"rewrites are switched off", "filtering is off", `"Dad laptop"`} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in:\n%s", want, j)
		}
	}
	if strings.Contains(j, "Mum phone") || strings.Contains(j, "curfew-eli") {
		t.Errorf("reported a client that does get rewrites:\n%s", j)
	}
	// With no names at all, there is nothing to warn about.
	rep, _ = run(t, &fakeRewrites{rewritesOff: true}, nil, &dnsledger.Ledger{})
	if len(rep.Bypass) != 0 {
		t.Errorf("warned with no local names: %v", rep.Bypass)
	}
}

// Reviewer P1: when the DHCP pass planned nothing (it could not read the dhcp
// config), the AdGuard half must not delete curfew's rewrites.
func TestNoRewriteIsTouchedWhenTheDHCPPassPlannedNothing(t *testing.T) {
	f := &fakeRewrites{list: []adguard.RewriteObject{ro("*.lan.telemaque.ska.sh", "192.168.1.122")}}
	ledger := filepath.Join(t.TempDir(), "dns-records.json")
	if err := dnsledger.Save(ledger, &dnsledger.Ledger{AdGuard: []dnsledger.Rewrite{rw("*.lan.telemaque.ska.sh", "192.168.1.122")}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Rewrites: f, LedgerPath: ledger})
	m.reconcileRewrites(leases.Plan{NamesSkipped: "the dhcp config could not be read"})
	if len(f.calls) != 0 {
		t.Errorf("rewrites were changed with ownership unknown: %v", f.calls)
	}
}
