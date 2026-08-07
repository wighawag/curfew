package kernelprobe

import (
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/contract"
)

// The probe creates and DELETES tables. Pointing it at the enforcement table
// would turn a diagnostic that is advertised as safe on a live router into an
// outage for the whole household.
func TestTheProbeNeverNamesTheEnforcementTable(t *testing.T) {
	if TableName == contract.Table {
		t.Fatalf("the probe table is %q, which is the enforcement table", TableName)
	}
	if !strings.Contains(TableName, "probe") {
		t.Errorf("the probe table %q should be obviously a probe to anyone reading "+
			"nft list tables on a router at 2am", TableName)
	}
}

// An empty report must not read as success. Without this, a probe that
// measured nothing at all would print the reassuring line.
func TestAnEmptyReportIsNotAPass(t *testing.T) {
	var r Report
	if r.OK() {
		t.Error("a report with no checks in it must not report OK")
	}
	if !strings.Contains(r.String(), "FAILED") {
		t.Errorf("an empty report should not print reassurance, got:\n%s", r.String())
	}
}

func TestReportNamesWhatFailedAndCountsIt(t *testing.T) {
	r := Report{Kernel: "6.12.94", Checks: []Check{
		{What: "the good one", OK: true, Detail: "30s"},
		{What: "the bad one", OK: false, Detail: "28s before, 30s after"},
	}}
	if r.OK() {
		t.Error("a report with a failing check must not report OK")
	}
	if r.Failures() != 1 {
		t.Errorf("Failures() = %d, want 1", r.Failures())
	}
	out := r.String()
	for _, want := range []string{
		"6.12.94",
		"PASS  the good one (30s)",
		"FAIL  the bad one (28s before, 30s after)",
		"1 check(s) FAILED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report should contain %q, got:\n%s", want, out)
		}
	}
	// The detail is not decoration. A run that prints only ticks is not
	// evidence, and the numbers are what let a reader check the arithmetic.
	if strings.Contains(out, "PASS  the good one\n") {
		t.Error("a passing check must still carry its measurement")
	}
}

func TestAPassingReportSaysSo(t *testing.T) {
	r := Report{Checks: []Check{{What: "a thing", OK: true}}}
	if !r.OK() {
		t.Fatal("all checks passed")
	}
	if !strings.Contains(r.String(), "every fact") {
		t.Errorf("got:\n%s", r.String())
	}
}
