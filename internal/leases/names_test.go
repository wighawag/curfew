package leases

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/dnsledger"
	"github.com/wighawag/curfew/internal/dnsnames"
)

// The dnsmasq half of local DNS names: what PlanNames emits, what it refuses
// to touch, and that Pass records ownership BEFORE it writes.

const igcMAC = "38:05:25:3a:b0:70"

var routerCtx = dnsnames.Context{Known: true, LocalDomains: []string{"lan"}}

func igc(names ...string) Device {
	return Device{MAC: igcMAC, Name: "workstation igc", Fixed: "192.168.1.122", DNSNames: names}
}

var pinnedIGC = map[string]string{igcMAC: "192.168.1.122"}

func ledgerOf(es ...dnsledger.DnsmasqEntry) *dnsledger.Ledger { return &dnsledger.Ledger{Dnsmasq: es} }

func addr(v string) dnsledger.DnsmasqEntry {
	return dnsledger.DnsmasqEntry{List: ListAddress, Value: v}
}
func srv(v string) dnsledger.DnsmasqEntry { return dnsledger.DnsmasqEntry{List: ListServer, Value: v} }

func cmds(p NamesPlan) string { return strings.Join(p.Commands, "\n") }

func TestANewNameAddsItsAddressAndLocalOnlyServerEntry(t *testing.T) {
	p := PlanNames([]Device{igc("*.lan.telemaque.ska.sh")}, pinnedIGC, routerCtx, nil, nil, ledgerOf())
	want := "uci add_list dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.122'\n" +
		"uci add_list dhcp.@dnsmasq[0].server='/*.lan.telemaque.ska.sh/'"
	if cmds(p) != want {
		t.Errorf("got:\n%s\nwant:\n%s", cmds(p), want)
	}
	if len(p.Targets) != 1 || p.Targets[0].IP != "192.168.1.122" {
		t.Errorf("targets: %+v", p.Targets)
	}
	if len(p.Final) != 2 || len(p.WriteAhead) != 2 {
		t.Errorf("both entries must be owned before and after: %+v", p)
	}
}

func TestAConvergedStateEmitsNothing(t *testing.T) {
	a, s := "/*.lan.telemaque.ska.sh/192.168.1.122", "/*.lan.telemaque.ska.sh/"
	p := PlanNames([]Device{igc("*.lan.telemaque.ska.sh")}, pinnedIGC, routerCtx,
		[]string{a}, []string{s}, ledgerOf(addr(a), srv(s)))
	if len(p.Commands) != 0 || len(p.Changed) != 0 {
		t.Errorf("a converged state emitted:\n%s", cmds(p))
	}
}

// The name follows the fixed address: the old answer goes, the new one comes,
// and the local-only entry, which does not mention the address, stays.
func TestAMovedFixedAddressRewritesOnlyTheAnswer(t *testing.T) {
	old, s := "/*.lan.telemaque.ska.sh/192.168.1.122", "/*.lan.telemaque.ska.sh/"
	d := igc("*.lan.telemaque.ska.sh")
	d.Fixed = "192.168.1.123"
	p := PlanNames([]Device{d}, map[string]string{igcMAC: "192.168.1.123"}, routerCtx,
		[]string{old}, []string{s}, ledgerOf(addr(old), srv(s)))
	want := "uci del_list dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.122'\n" +
		"uci add_list dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.123'"
	if cmds(p) != want {
		t.Errorf("got:\n%s\nwant:\n%s", cmds(p), want)
	}
	// The write-ahead ledger still owns the OLD entry until it is gone.
	if !containsEntry(p.WriteAhead, addr(old)) || containsEntry(p.Final, addr(old)) {
		t.Errorf("old entry must be kept until deleted: wa=%v final=%v", p.WriteAhead, p.Final)
	}
}

// End to end through Pass: a set-ip move is ONE plan carrying the pin change
// and the answer change.
func TestPassMovesThePinAndTheNameInOneTransaction(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "dns-records.json")
	old, s := "/*.lan.telemaque.ska.sh/192.168.1.122", "/*.lan.telemaque.ska.sh/"
	if err := dnsledger.Save(ledgerPath, ledgerOf(addr(old), srv(s))); err != nil {
		t.Fatal(err)
	}
	show := realRouterUCI +
		"dhcp.curfew_3805253ab070=host\n" +
		"dhcp.curfew_3805253ab070.mac='38:05:25:3a:b0:70'\n" +
		"dhcp.curfew_3805253ab070.ip='192.168.1.122'\n" +
		"dhcp.curfew_3805253ab070.curfew='1'\n" +
		"dhcp.@dnsmasq[0].address='" + old + "'\n" +
		"dhcp.@dnsmasq[0].server='" + s + "'\n"
	r := &scriptedRunner{out: map[string]string{"uci show network.lan": liveNetworkLAN, "uci show dhcp": show}}
	d := igc("*.lan.telemaque.ska.sh")
	d.Fixed = "192.168.1.123"
	plan, err := Pass(r, []Device{d}, PassOptions{LedgerPath: ledgerPath})
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(plan.Commands, "\n")
	for _, want := range []string{"ip='192.168.1.123'", "del_list dhcp.@dnsmasq[0].address='" + old,
		"add_list dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.123'"} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in one plan:\n%s", want, j)
		}
	}
	commits := strings.Count(strings.Join(r.ran, "\n"), " commit dhcp")
	if commits != 1 {
		t.Errorf("want exactly one commit for pins and names together, got %d", commits)
	}
	l, _ := dnsledger.Load(ledgerPath)
	if l.HasDnsmasq(addr(old)) || !l.HasDnsmasq(addr("/*.lan.telemaque.ska.sh/192.168.1.123")) {
		t.Errorf("the ledger after success must own exactly the new entries: %+v", l)
	}
}

func TestARefusedFixedAddressGetsNoName(t *testing.T) {
	p := PlanNames([]Device{igc("*.lan.telemaque.ska.sh")}, map[string]string{}, routerCtx, nil, nil, ledgerOf())
	if len(p.Commands) != 0 || len(p.Targets) != 0 {
		t.Errorf("a name was answered for an address the device does not hold:\n%s", cmds(p))
	}
	if len(p.Refused) != 1 || !strings.Contains(p.Refused[0].Reason, "not pinned") {
		t.Errorf("want a refusal saying why: %+v", p.Refused)
	}
}

func TestAnInvalidStoredNameIsRefusedAgainstTheRoutersConfig(t *testing.T) {
	p := PlanNames([]Device{igc("printer.lan", "*.lan.telemaque.ska.sh")}, pinnedIGC, routerCtx, nil, nil, ledgerOf())
	if len(p.Refused) != 1 || p.Refused[0].Name != "printer.lan" {
		t.Errorf("printer.lan must be refused by the local-domain rule: %+v", p.Refused)
	}
	if len(p.Targets) != 1 {
		t.Errorf("the valid name must still be answered: %+v", p.Targets)
	}
}

func TestAForeignEntryForTheSameDomainBlocksOnlyThatName(t *testing.T) {
	foreign := "/*.lan.telemaque.ska.sh/192.168.1.99"
	p := PlanNames([]Device{igc("*.lan.telemaque.ska.sh", "nas.home.arpa")}, pinnedIGC, routerCtx,
		[]string{foreign, "/other.example/10.0.0.1"}, nil, ledgerOf())
	if strings.Contains(cmds(p), "lan.telemaque.ska.sh") {
		t.Errorf("curfew wrote a second answer next to a foreign one:\n%s", cmds(p))
	}
	if !strings.Contains(cmds(p), "/nas.home.arpa/192.168.1.122") {
		t.Errorf("an unrelated name was blocked too:\n%s", cmds(p))
	}
	if len(p.Yielded) != 1 || p.Yielded[0].Entry != foreign {
		t.Errorf("the foreign entry must be reported: %+v", p.Yielded)
	}
	if strings.Contains(cmds(p), "del_list") {
		t.Errorf("a foreign entry was deleted:\n%s", cmds(p))
	}
}

func TestAnIdenticalForeignEntryIsNeitherDuplicatedNorClaimed(t *testing.T) {
	a, s := "/*.lan.telemaque.ska.sh/192.168.1.122", "/*.lan.telemaque.ska.sh/"
	p := PlanNames([]Device{igc("*.lan.telemaque.ska.sh")}, pinnedIGC, routerCtx, []string{a}, []string{s}, ledgerOf())
	if len(p.Commands) != 0 {
		t.Errorf("identical household entries were touched:\n%s", cmds(p))
	}
	if containsEntry(p.Final, addr(a)) || containsEntry(p.Final, srv(s)) {
		t.Errorf("curfew claimed entries it did not write: %+v", p.Final)
	}
	if len(p.Unclaimed) != 2 {
		t.Errorf("both should be reported as unclaimed: %+v", p.Unclaimed)
	}
	// And so removing the name later deletes nothing of theirs.
	p = PlanNames([]Device{igc()}, pinnedIGC, routerCtx, []string{a}, []string{s}, ledgerOf())
	if len(p.Commands) != 0 {
		t.Errorf("removing the name deleted the household's entries:\n%s", cmds(p))
	}
}

func TestOnlyEntriesInTheLedgerAndPresentAreEverDeleted(t *testing.T) {
	ours, theirs, gone := "/old.home.arpa/192.168.1.122", "/corp.example/10.0.0.1", "/gone.home.arpa/192.168.1.122"
	p := PlanNames(nil, nil, routerCtx, []string{ours, theirs}, []string{"/old.home.arpa/"},
		ledgerOf(addr(ours), srv("/old.home.arpa/"), addr(gone)))
	want := "uci del_list dhcp.@dnsmasq[0].address='/old.home.arpa/192.168.1.122'\n" +
		"uci del_list dhcp.@dnsmasq[0].server='/old.home.arpa/'"
	if cmds(p) != want {
		t.Errorf("got:\n%s\nwant:\n%s", cmds(p), want)
	}
	if len(p.Final) != 0 {
		t.Errorf("after the deletes curfew owns nothing, and the absent entry is pruned: %+v", p.Final)
	}
	if !containsEntry(p.WriteAhead, addr(gone)) {
		t.Errorf("nothing is forgotten before a successful pass: %+v", p.WriteAhead)
	}
}

func TestADuplicatedOwnedEntryIsNotDeleted(t *testing.T) {
	a := "/old.home.arpa/192.168.1.122"
	p := PlanNames(nil, nil, routerCtx, []string{a, a}, nil, ledgerOf(addr(a)))
	if strings.Contains(cmds(p), "del_list") {
		t.Errorf("deleting would remove the household's copy too:\n%s", cmds(p))
	}
	if len(p.Kept) != 1 {
		t.Errorf("want it reported: %+v", p.Kept)
	}
}

func TestDeregisteringADeviceRemovesExactlyItsEntries(t *testing.T) {
	a, s := "/*.lan.telemaque.ska.sh/192.168.1.122", "/*.lan.telemaque.ska.sh/"
	other := Device{MAC: "84:47:09:84:8e:b2", Name: "shyrka", Fixed: "192.168.1.150", DNSNames: []string{"nas.home.arpa"}}
	oa, os_ := "/nas.home.arpa/192.168.1.150", "/nas.home.arpa/"
	p := PlanNames([]Device{other}, map[string]string{"84:47:09:84:8e:b2": "192.168.1.150"}, routerCtx,
		[]string{a, oa}, []string{s, os_}, ledgerOf(addr(a), srv(s), addr(oa), srv(os_)))
	want := "uci del_list dhcp.@dnsmasq[0].address='/*.lan.telemaque.ska.sh/192.168.1.122'\n" +
		"uci del_list dhcp.@dnsmasq[0].server='/*.lan.telemaque.ska.sh/'"
	if cmds(p) != want {
		t.Errorf("got:\n%s\nwant:\n%s", cmds(p), want)
	}
}

// Write-ahead, observed from the outside: by the time the first add_list
// runs, the ledger on disk already owns the entry.
func TestPassRecordsOwnershipBeforeWriting(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "dns-records.json")
	seen := false
	r := &watchRunner{scriptedRunner: scriptedRunner{out: map[string]string{
		"uci show network.lan": liveNetworkLAN, "uci show dhcp": realRouterUCI,
	}}, onAdd: func() {
		data, _ := os.ReadFile(ledgerPath)
		seen = strings.Contains(string(data), "/*.lan.telemaque.ska.sh/192.168.1.122")
	}}
	_, err := Pass(r, []Device{igc("*.lan.telemaque.ska.sh")}, PassOptions{LedgerPath: ledgerPath})
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("an entry was written before the ledger recorded it, so a crash could orphan it")
	}
}

type watchRunner struct {
	scriptedRunner
	onAdd func()
	done  bool
}

func (w *watchRunner) Run(cmd string) (string, error) {
	if !w.done && strings.Contains(cmd, "add_list dhcp.@dnsmasq") {
		w.done = true
		w.onAdd()
	}
	return w.scriptedRunner.Run(cmd)
}

// An unreadable ledger means ownership is UNKNOWN: names are left exactly as
// they are, and the pins still go ahead.
func TestAnUnreadableLedgerManagesNoNamesButStillPins(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "dns-records.json")
	if err := os.WriteFile(ledgerPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &scriptedRunner{out: map[string]string{"uci show network.lan": liveNetworkLAN,
		"uci show dhcp": realRouterUCI + "dhcp.@dnsmasq[0].address='/old.home.arpa/192.168.1.122'\n"}}
	plan, err := Pass(r, []Device{igc("*.lan.telemaque.ska.sh"), {MAC: shyrkaMAC, IP: "192.168.1.226"}},
		PassOptions{LedgerPath: ledgerPath})
	if err != nil {
		t.Fatal(err)
	}
	if plan.NamesSkipped == "" {
		t.Error("the skip must be reported")
	}
	j := strings.Join(plan.Commands, "\n")
	if strings.Contains(j, "dnsmasq[0]") {
		t.Errorf("names were changed with ownership unknown:\n%s", j)
	}
	if !strings.Contains(j, "curfew_844709848eb2") {
		t.Errorf("the pins must still go ahead:\n%s", j)
	}
}

// The ledger lives on flash: a pass with nothing to change must not write it.
func TestAConvergedPassDoesNotRewriteTheLedger(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "dns-records.json")
	r := &scriptedRunner{out: map[string]string{"uci show network.lan": liveNetworkLAN, "uci show dhcp": realRouterUCI}}
	if _, err := Pass(r, nil, PassOptions{LedgerPath: ledgerPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
		t.Errorf("a pass with no names and nothing owned wrote the ledger: %v", err)
	}
}

// Reviewer P1: a pass that could not read the dhcp config planned nothing, and
// must say so, or the AdGuard half would read "no targets" as "remove every
// name" and delete curfew's rewrites for a tick.
func TestAnUnreadableDhcpConfigMarksNamesAsUnmanaged(t *testing.T) {
	r := &failingShowRunner{}
	plan, err := Pass(r, []Device{igc("*.lan.telemaque.ska.sh")}, PassOptions{LedgerPath: filepath.Join(t.TempDir(), "l.json")})
	if err == nil {
		t.Fatal("want the read error")
	}
	if plan.NamesSkipped == "" {
		t.Error("names must be marked unmanaged when nothing could be planned")
	}
}

type failingShowRunner struct{}

func (failingShowRunner) Run(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "uci show network.lan"):
		return liveNetworkLAN, nil
	case strings.HasPrefix(cmd, "uci show dhcp"):
		return "", errShellFailed
	}
	return "", nil
}

// A router without nslookup cannot probe, which is not evidence of a dead
// resolver, so it must not roll back every change.
func TestAMissingNslookupIsNotADeadResolver(t *testing.T) {
	r := &noNslookupRunner{}
	if _, err := Apply(r, Plan{Commands: []string{"uci set dhcp.curfew_x=host"}}); err != nil {
		t.Fatalf("a missing probe tool rolled the change back: %v", err)
	}
}

type noNslookupRunner struct{ recordingRunner }

func (n *noNslookupRunner) Run(cmd string) (string, error) {
	if strings.HasPrefix(cmd, "nslookup") {
		return "sh: nslookup: not found\n", nil
	}
	return n.recordingRunner.Run(cmd)
}
