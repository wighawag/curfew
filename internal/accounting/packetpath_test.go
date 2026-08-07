//go:build linux

package accounting

import (
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/contract"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/netnstest"
)

// Packet-path tests for accounting.
//
// Every claim this package makes is about what the KERNEL counts, so every one
// of them is settled by sending a real packet and reading a real counter. Per
// docs/adr/0004-tests-assert-on-the-packet-path.md, a counter that looks right
// is not evidence; a counter that moved when a packet arrived is.
//
// Note what these tests do NOT do: they never fake a counter. The counter is
// the thing most likely to be wrong, both because it is cumulative and because
// it lives in a table another package rebuilds underneath it.

const (
	eliMAC = "aa:bb:cc:dd:ee:01"
	dadMAC = "aa:bb:cc:dd:ee:03"
)

func newTestAccountant(t *testing.T) *Accountant {
	t.Helper()
	a, err := New(Config{LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf})
	if err != nil {
		t.Fatalf("accounting.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Teardown() })
	return a
}

func newTestEnforcer(t *testing.T) *enforce.Enforcer {
	t.Helper()
	e, err := enforce.New(enforce.Config{LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf})
	if err != nil {
		t.Fatalf("enforce.New: %v", err)
	}
	return e
}

func read(t *testing.T, a *Accountant, profile string) uint64 {
	t.Helper()
	got, err := a.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return got[profile]
}

// The baseline claim: traffic from a profile's device moves that profile's
// counter, and only that profile's.
func TestPacketPathTrafficMovesTheRightProfilesCounter(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	if _, err := a.EnsureShape(map[string][]string{
		"eli": {eliMAC}, "dad": {dadMAC},
	}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC, dadMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}

	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline: an allowed device must reach the internet, or nothing below means anything")
	}
	if read(t, a, "eli") == 0 {
		t.Error("traffic from eli's device did not move eli's counter")
	}
	if got := read(t, a, "dad"); got != 0 {
		t.Errorf("dad's counter moved to %d without dad sending anything", got)
	}
}

// The property ADR 0001 requires, and the one the hook-priority split exists
// to deliver: accounting counts only traffic that SURVIVED enforcement, so a
// blocked device's retries cannot burn its own allowance.
func TestPacketPathABlockedProfileBurnsNoBudget(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}

	// Control first: the counter DOES move when traffic gets through. Without
	// it, a counter stuck at zero for any reason would pass as success.
	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline: the device must reach the internet first")
	}
	moved := read(t, a, "eli")
	if moved == 0 {
		t.Fatal("the counter never moved even for allowed traffic, so the test below proves nothing")
	}

	// Now block it by SCHEDULE and let it retry hard.
	if err := e.ApplyDesired(enforce.Desired{
		Allowed: []string{eliMAC}, Blocked: []string{eliMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	before := read(t, a, "eli")
	for range 3 {
		if net.Reaches() {
			t.Fatal("the device must be blocked here")
		}
	}
	if after := read(t, a, "eli"); after != before {
		t.Errorf("a schedule-blocked device burned %d bytes of budget by retrying: %d -> %d",
			after-before, before, after)
	}
}

// The same claim for the OTHER drop tier. It is structural rather than a
// special case (the manual tier is above accounting too), and the brief asks
// for it to be verified with a packet and a counter read rather than assumed
// from the ordering.
func TestPacketPathAManuallyBlockedProfileBurnsNoBudget(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}, "dad": {dadMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if err := e.ApplyDesired(enforce.Desired{
		Allowed: []string{eliMAC, dadMAC}, Manual: []string{eliMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}

	net.SetClientMAC(eliMAC)
	before := read(t, a, "eli")
	for range 3 {
		if net.Reaches() {
			t.Fatal("a manually blocked device must not reach the internet")
		}
	}
	if after := read(t, a, "eli"); after != before {
		t.Errorf("a manually blocked device burned %d bytes of budget: %d -> %d",
			after-before, before, after)
	}

	// Control: accounting is alive and counting for a device that is NOT
	// blocked, so the zero above is the block and not a dead counter.
	net.SetClientMAC(dadMAC)
	if !net.Reaches() {
		t.Fatal("the unblocked device must reach the internet")
	}
	if read(t, a, "dad") == 0 {
		t.Error("accounting counted nothing at all, so the assertion above proves nothing")
	}
}

// Accounting must never influence a verdict. Asserted in BOTH directions,
// because a table that broke everything and a table that allowed everything
// would each be caught by only one of them.
func TestPacketPathAccountingChangesNoVerdict(t *testing.T) {
	net := netnstest.Require(t)
	e := newTestEnforcer(t)
	a := newTestAccountant(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	net.SetClientMAC(eliMAC)

	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !net.Reaches() {
		t.Error("an allowed device must still be allowed with accounting present")
	}
	if err := e.ApplyDesired(enforce.Desired{
		Allowed: []string{eliMAC}, Blocked: []string{eliMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if net.Reaches() {
		t.Error("accounting's accept-policy chain let a blocked device through")
	}
}

// The trap that motivated a separate table. ApplyDesired replaces the WHOLE
// enforcement table, several times a night in practice, and a counter living
// in it would have been silently zeroed each time.
func TestCountersSurviveAnEnforcementRebuild(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline")
	}
	before := read(t, a, "eli")
	if before == 0 {
		t.Fatal("nothing was counted, so survival proves nothing")
	}

	for i := range 3 {
		if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC}}); err != nil {
			t.Fatalf("rebuild %d: %v", i, err)
		}
	}
	after := read(t, a, "eli")
	if after != before {
		t.Errorf("an enforcement rebuild changed the accounting counter: %d -> %d", before, after)
	}
	// And it is still counting afterwards, rather than having survived as a
	// frozen number.
	if !net.Reaches() {
		t.Fatal("still allowed")
	}
	if read(t, a, "eli") <= after {
		t.Error("the counter stopped counting after an enforcement rebuild")
	}
}

// Rebuilding the accounting table zeroes the counters, which is unavoidable.
// What matters is that it is ANNOUNCED, via the generation, so the sampler
// knows rather than infers, and that it does not happen when nothing changed.
func TestEnsureShapeRebuildsOnlyWhenTheHouseholdChanged(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	shape := map[string][]string{"eli": {eliMAC}}
	rebuilt, err := a.EnsureShape(shape)
	if err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if !rebuilt {
		t.Fatal("the first call must build the table")
	}
	gen := a.Generation()
	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{eliMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if !net.Reaches() {
		t.Fatal("baseline")
	}
	counted := read(t, a, "eli")
	if counted == 0 {
		t.Fatal("nothing counted")
	}

	// The steady state. Rebuilding here would zero the counter on every tick,
	// so usage would never accumulate while every individual read still looked
	// perfectly plausible.
	for i := range 5 {
		rebuilt, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}})
		if err != nil {
			t.Fatalf("EnsureShape %d: %v", i, err)
		}
		if rebuilt {
			t.Fatal("an unchanged household must not rebuild accounting: the counters would reset every tick")
		}
	}
	if got := read(t, a, "eli"); got != counted {
		t.Errorf("the counter changed without a rebuild: %d -> %d", counted, got)
	}
	if a.Generation() != gen {
		t.Error("the generation moved without a rebuild")
	}

	// A real change rebuilds, and says so.
	rebuilt, err = a.EnsureShape(map[string][]string{"eli": {eliMAC}, "dad": {dadMAC}})
	if err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if !rebuilt {
		t.Fatal("adding a profile must rebuild accounting")
	}
	if a.Generation() == gen {
		t.Error("a rebuild must change the generation, or the sampler cannot know the counters were reset")
	}
	if got := read(t, a, "eli"); got != 0 {
		t.Errorf("a rebuild zeroes counters; got %d, and if this ever stops being true the sampler's reset handling is dead code", got)
	}
}

// MAC order and case must not count as a change, or a config rewrite would
// zero every counter and quietly hand back everyone's spent allowance.
func TestEnsureShapeIgnoresOrderAndCase(t *testing.T) {
	netnstest.Require(t)
	a := newTestAccountant(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC, dadMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	rebuilt, err := a.EnsureShape(map[string][]string{"eli": {"AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:01"}})
	if err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if rebuilt {
		t.Error("reordering and recasing the same MACs must not zero the counters")
	}
}

// A profile with no devices has nothing to count, and a counter nothing writes
// to would read as a permanently idle child rather than as an absent one.
func TestAProfileWithNoDevicesGetsNoCounter(t *testing.T) {
	netnstest.Require(t)
	a := newTestAccountant(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}, "ghost": {}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	got, err := a.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if _, present := got["ghost"]; present {
		t.Error("a profile with no devices must not report a counter")
	}
	if _, present := got["eli"]; !present {
		t.Error("a profile with devices must report a counter")
	}
}

// The escape hatch in the README deletes ONE table. It must still restore
// connectivity with accounting in place, or the documented recovery path is a
// lie the first time somebody needs it.
func TestPacketPathTheEscapeHatchStillWorksWithAccountingPresent(t *testing.T) {
	net := netnstest.Require(t)
	a := newTestAccountant(t)
	e := newTestEnforcer(t)
	if _, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}}); err != nil {
		t.Fatalf("EnsureShape: %v", err)
	}
	if err := e.ApplyDesired(enforce.Desired{
		Allowed: []string{eliMAC}, Manual: []string{eliMAC},
	}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	net.SetClientMAC(eliMAC)
	if net.Reaches() {
		t.Fatal("the device must start out blocked")
	}
	net.DeleteTable() // exactly what the README tells a person to run
	if !net.Reaches() {
		t.Error("the escape hatch did not restore connectivity: the accounting table is blocking something")
	}
	// And the accounting table really is still there, so the assertion above
	// is about a table that exists rather than one already gone.
	out, err := net.Run("nft list table inet " + contract.AccountingTable)
	if err != nil {
		t.Errorf("the accounting table should still be present: %s %v", out, err)
	}
}

func TestCounterNamesAreDistinctAndReadable(t *testing.T) {
	// The common case must stay greppable on a router at 2am. The household's
	// own config capitalises its profiles, so this is not a corner.
	for name, want := range map[string]string{"eli": "profile_eli", "Eli": "profile_eli"} {
		if got := CounterName(name); got != want {
			t.Errorf("CounterName(%q) = %q, want %q", name, got, want)
		}
	}
	// Two names that sanitise to the same body must not collide onto one
	// counter, or two children would silently share a budget.
	a, b := CounterName("my kid"), CounterName("my-kid")
	if a == b {
		t.Errorf("%q and %q both map to %q", "my kid", "my-kid", a)
	}
	long := CounterName(string(make([]byte, 200)))
	if len(long) > 64 {
		t.Errorf("counter name %d chars long; older kernels cap object names well below that", len(long))
	}
}

// The one ambiguity case folding leaves behind, refused loudly rather than
// allowed to become two children on one counter.
func TestTwoProfilesDifferingOnlyInCaseAreRefused(t *testing.T) {
	netnstest.Require(t)
	a := newTestAccountant(t)
	_, err := a.EnsureShape(map[string][]string{"eli": {eliMAC}, "Eli": {dadMAC}})
	if err == nil {
		t.Fatal("two profiles mapping to one counter must be refused, not silently merged")
	}
	if !strings.Contains(err.Error(), "share one budget") {
		t.Errorf("the error must say what goes wrong, got %v", err)
	}
}
