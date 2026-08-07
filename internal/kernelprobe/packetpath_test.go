//go:build linux

package kernelprobe

import (
	"testing"

	"github.com/google/nftables"

	"github.com/wighawag/curfew/internal/contract"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/netnstest"
)

const (
	allowedMAC = "aa:bb:cc:dd:ee:01"
	unknownMAC = "aa:bb:cc:dd:ee:99"
)

// The probe must measure the kernel it is actually run on, and say so.
func TestProbeMeasuresThisKernelAndCleansUpAfterItself(t *testing.T) {
	netnstest.Require(t)

	report, err := Run()
	if err != nil {
		t.Fatalf("the probe could not finish: %v", err)
	}
	if len(report.Checks) < 9 {
		t.Errorf("want every fact measured, for tickets AND for budget counters, "+
			"got only %d checks:\n%s", len(report.Checks), report)
	}
	if !report.OK() {
		t.Errorf("the kernel under test should support all of this:\n%s", report)
	}
	if report.Kernel == "" {
		t.Error("the report must name the kernel it measured, or it cannot be quoted anywhere")
	}
	// Every check must carry its numbers, since a row of bare ticks is not
	// evidence and cannot be checked by a reader.
	for _, c := range report.Checks {
		// The exceptions are the checks whose only content is "the kernel did
		// not refuse this", which has no number to report.
		switch c.What {
		case "the kernel accepts an ether_addr set with 'flags timeout'",
			"a whole-table replace carrying a live element succeeds in one transaction",
			"the kernel reclaims an expired element with no process involved",
			"the kernel accepts a named counter object":
		default:
			if c.Detail == "" {
				t.Errorf("check %q carries no measurement", c.What)
			}
		}
	}

	left, err := Present()
	if err != nil {
		t.Fatal(err)
	}
	if left {
		t.Error("the probe left its table behind; on a live router that is litter in the ruleset")
	}
}

// The probe must also measure the facts BUDGET accounting relies on, or a
// board where named counters do not work would report a clean bill of health
// while every child's budget silently read zero.
func TestProbeMeasuresTheCounterFactsBudgetsRelyOn(t *testing.T) {
	netnstest.Require(t)
	report, err := Run()
	if err != nil {
		t.Fatalf("the probe could not finish: %v", err)
	}
	for _, want := range []string{
		"the kernel accepts a named counter object",
		"a named counter reads back the value it was given",
		"a counter survives a whole-table replace of a DIFFERENT table",
	} {
		found := false
		for _, c := range report.Checks {
			if c.What == want {
				found = true
				if !c.OK {
					t.Errorf("this kernel fails %q (%s), so budget accounting cannot be trusted on it",
						c.What, c.Detail)
				}
			}
		}
		if !found {
			t.Errorf("the probe does not measure %q:\n%s", want, report)
		}
	}
}

// The probe must not disturb ACCOUNTING either, which is a second live table
// it could delete by accident. Without this the safety claim covers only half
// of what is now on a router.
func TestProbeCannotDisturbAccounting(t *testing.T) {
	netnstest.Require(t)
	conn, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	tbl := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet, Name: contract.AccountingTable,
	})
	conn.AddObj(&nftables.CounterObj{Table: tbl, Name: "profile_eli", Bytes: 987654})
	if err := conn.Flush(); err != nil {
		t.Fatalf("building a stand-in accounting table: %v", err)
	}
	t.Cleanup(func() {
		c, _ := nftables.New()
		c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: contract.AccountingTable})
		_ = c.Flush()
	})

	if _, err := Run(); err != nil {
		t.Fatalf("the probe could not finish: %v", err)
	}

	objs, err := conn.GetObjects(&nftables.Table{
		Family: nftables.TableFamilyINet, Name: contract.AccountingTable,
	})
	if err != nil {
		t.Fatalf("the accounting table is unreadable after the probe: %v", err)
	}
	var got uint64
	for _, o := range objs {
		if c, ok := o.(*nftables.CounterObj); ok && c.Name == "profile_eli" {
			got = c.Bytes
		}
	}
	if got != 987654 {
		t.Errorf("the probe disturbed a live accounting counter: got %d, want 987654", got)
	}
}

// The load-bearing safety property, asserted with packets rather than with a
// promise in a doc comment.
//
// This runs on a LIVE router, by design, so "it works in its own table" has to
// be true rather than intended. The probe creates and deletes tables, and a
// deletion aimed at the wrong name would take the whole household's policy
// with it while looking like a diagnostic.
func TestProbeCannotDisturbEnforcement(t *testing.T) {
	net := netnstest.Require(t)
	e, err := enforce.New(enforce.Config{
		LANInterface: netnstest.LANIf, WANInterface: netnstest.WANIf,
	})
	if err != nil {
		t.Fatalf("enforce.New: %v", err)
	}
	if err := e.ApplyDesired(enforce.Desired{Allowed: []string{allowedMAC}}); err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}

	// Baseline, both directions, before the probe runs.
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Fatal("baseline: the allowed device must reach the internet before the probe")
	}
	net.SetClientMAC(unknownMAC)
	if net.Reaches() {
		t.Fatal("baseline: the unknown device must be blocked before the probe")
	}

	before, err := net.Run("nft list table inet " + contract.Table)
	if err != nil {
		t.Fatalf("reading the enforcement ruleset: %v", err)
	}

	report, err := Run()
	if err != nil {
		t.Fatalf("the probe could not finish: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the probe failed, so what follows is not a fair test of it:\n%s", report)
	}

	// Still blocked, still allowed, and the ruleset byte for byte as it was.
	if net.Reaches() {
		t.Error("after the probe ran, a blocked device reached the internet")
	}
	net.SetClientMAC(allowedMAC)
	if !net.Reaches() {
		t.Error("after the probe ran, an allowed device lost the internet")
	}
	after, err := net.Run("nft list table inet " + contract.Table)
	if err != nil {
		t.Fatalf("the enforcement table is unreadable after the probe: %v", err)
	}
	if before != after {
		t.Errorf("the probe changed the enforcement ruleset.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
