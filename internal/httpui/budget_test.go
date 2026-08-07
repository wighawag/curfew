package httpui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

const budgetMAC = "aa:bb:cc:dd:ee:01"

var testLimits = budget.Limits{
	Daily: budget.D(4 * time.Hour), Continuous: budget.D(2 * time.Hour),
	Gap: budget.D(10 * time.Minute), ResetGap: budget.D(30 * time.Minute),
}

// budgetPage renders the home page for a household with one budgeted profile
// in the given budget state, and with the firewall doing whatever `blocked`
// says. It uses the REAL policy core, so what the page shows is derived by the
// same code the daemon runs.
func budgetPage(t *testing.T, st budget.State, blocked bool) string {
	t.Helper()
	store := &memStore{reg: &registry.Registry{Devices: []registry.Device{{MAC: budgetMAC, Name: "phone"}}}}
	sch := &fakeSchedule{ps: &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{budgetMAC}, Budget: testLimits},
	}}}
	state := &memState{st: &blockstate.State{
		ManualBlocked: []string{},
		BudgetDay:     budget.Settings{}.Day(time.Now()),
		Budget:        map[string]budget.State{"eli": st},
	}}
	fw := &fakeFirewall{live: []string{budgetMAC}}
	if blocked {
		fw.blocked = []string{budgetMAC}
	}
	srv, _ := assemble(store, sch, state, fw, "", "", time.Local)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("home page returned %d: %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestThePageShowsWhatIsLeftOfABudget(t *testing.T) {
	body := budgetPage(t, budget.State{Usage: budget.D(90 * time.Minute)}, false)
	for _, want := range []string{"used 1h 30m today", "2h 30m of 4h0m0s left"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not say %q\n%s", want, body)
		}
	}
}

// The trap this test exists for: the page derives "should be blocked" from the
// schedule and the parent's decision. Leaving the budget out of that made
// every spent allowance render as DRIFT, so the page would cry wolf about
// exactly the thing it exists to report honestly.
func TestASpentBudgetIsNotReportedAsDrift(t *testing.T) {
	body := budgetPage(t, budget.State{Usage: budget.D(4 * time.Hour)}, true)
	if strings.Contains(body, "blocked, but nothing says it should be") {
		t.Errorf("a budget block was reported as drift\n%s", body)
	}
	if !strings.Contains(body, string(budget.ReasonDaily)) {
		t.Errorf("the page must say WHY the child is offline, want %q\n%s", budget.ReasonDaily, body)
	}
}

// The other half of the same trap: a budget that says the child should be
// blocked while the FIREWALL is letting them through IS drift, and must still
// be reported. Without this the fix above could have been "never report drift".
func TestABudgetTheFirewallIsNotEnforcingIsStillDrift(t *testing.T) {
	body := budgetPage(t, budget.State{Usage: budget.D(4 * time.Hour)}, false)
	if !strings.Contains(body, "should be blocked right now, but is not") {
		t.Errorf("a spent budget the firewall ignores must be reported as drift\n%s", body)
	}
}

func TestThePageDistinguishesTheTwoWaysABudgetBlocks(t *testing.T) {
	daily := budgetPage(t, budget.State{Usage: budget.D(4 * time.Hour)}, true)
	if !strings.Contains(daily, string(budget.ReasonDaily)) {
		t.Errorf("want the daily reason\n%s", daily)
	}
	continuous := budgetPage(t, budget.State{
		Usage:         budget.D(2 * time.Hour),
		Session:       budget.D(2 * time.Hour),
		CooldownUntil: time.Now().Add(20 * time.Minute),
	}, true)
	if !strings.Contains(continuous, string(budget.ReasonContinuous)) {
		t.Errorf("want the continuous reason\n%s", continuous)
	}
	// And it says when they get back online, because "blocked" with no end in
	// sight is what a child asks a parent about.
	if !strings.Contains(continuous, "back in") {
		t.Errorf("want the time until the allowance refills\n%s", continuous)
	}
}

func TestAProfileWithNoBudgetShowsNoBudgetLine(t *testing.T) {
	store := &memStore{reg: &registry.Registry{Devices: []registry.Device{{MAC: budgetMAC}}}}
	sch := &fakeSchedule{ps: &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "printer", Devices: []string{budgetMAC}},
	}}}
	srv, _ := assemble(store, sch, &memState{}, &fakeFirewall{live: []string{budgetMAC}}, "", "", time.Local)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(rec.Body.String(), "budget:") {
		t.Errorf("a profile with no budget must not show an allowance\n%s", rec.Body)
	}
}

func TestObservedTrafficIsRenderedForCalibration(t *testing.T) {
	// The calibration surface. Without a figure a household can see, the
	// activity threshold can only ever be the guess it ships with.
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{
		{512, "512 B"},
		{2048, "2.0 KB"},
		{3 * 1024 * 1024, "3.0 MB"},
	} {
		_, observed := budgetLines(budget.Status{
			ObservedBytes: tc.bytes, ObservedOK: true,
		}, time.Minute)
		if !strings.Contains(observed, tc.want) {
			t.Errorf("observed line for %d bytes = %q, want it to contain %q",
				tc.bytes, observed, tc.want)
		}
	}
	_, active := budgetLines(budget.Status{
		ObservedBytes: 900 * 1024, ObservedOK: true, ObservedActive: true,
	}, time.Minute)
	if !strings.Contains(active, "counted as use") {
		t.Errorf("an active interval must say so, got %q", active)
	}
	_, idle := budgetLines(budget.Status{ObservedBytes: 10, ObservedOK: true}, time.Minute)
	if !strings.Contains(idle, "idle") {
		t.Errorf("an interval below the threshold must say so, got %q", idle)
	}
	// Nothing measured yet, so nothing claimed.
	if _, none := budgetLines(budget.Status{}, time.Minute); none != "" {
		t.Errorf("with no observation the page must say nothing, got %q", none)
	}
	// Accounting off entirely: still nothing claimed, rather than "0 B".
	if _, off := budgetLines(budget.Status{ObservedOK: true}, 0); off != "" {
		t.Errorf("with accounting off the page must say nothing, got %q", off)
	}
}

func TestAnUnlimitedAllowanceIsNotRenderedAsZeroLeft(t *testing.T) {
	// A profile with a daily budget but no continuous one has an unlimited
	// stretch. Rendering that as "0m of 0s left" would read as "no time left".
	line, _ := budgetLines(budget.Status{
		Limits: budget.Limits{Daily: budget.D(4 * time.Hour)},
		Used:   time.Hour, DailyLeft: 3 * time.Hour, DailyOK: true,
	}, time.Minute)
	if strings.Contains(line, "stretch") {
		t.Errorf("an unlimited stretch must not be rendered at all, got %q", line)
	}
	if !strings.Contains(line, "3h of 4h0m0s left") {
		t.Errorf("want the daily allowance, got %q", line)
	}
}
