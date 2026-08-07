//go:build linux

package kernelprobe

import (
	"testing"

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
	if len(report.Checks) < 6 {
		t.Errorf("want every fact measured, got only %d checks:\n%s", len(report.Checks), report)
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
		if c.Detail == "" && c.What != "the kernel accepts an ether_addr set with 'flags timeout'" &&
			c.What != "a whole-table replace carrying a live element succeeds in one transaction" &&
			c.What != "the kernel reclaims an expired element with no process involved" {
			t.Errorf("check %q carries no measurement", c.What)
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
