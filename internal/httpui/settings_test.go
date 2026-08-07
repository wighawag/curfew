package httpui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// settingsServer builds a household with one profile carrying no budget yet.
func settingsServer(t *testing.T) (*Server, *fakeSchedule) {
	t.Helper()
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
	}}
	srv, sch, _ := newProfileServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		ps, []string{"aa:bb:cc:dd:ee:01"}, nil)
	return srv, sch
}

func get(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// The split itself. The home page is what a parent opens with a child waiting,
// so the test says what must NOT be on it as well as what must.
func TestTheHomePageCarriesOnlyTheThingsNeededInTheMoment(t *testing.T) {
	srv, _ := settingsServer(t)
	body := get(t, srv, "/").Body.String()

	for _, want := range []string{
		`action="/profiles/block"`,  // turn a child off
		`action="/profiles/ticket"`, // give them time
		`href="/settings"`,          // and a way to everything else
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the home page must offer %s", want)
		}
	}
	// Configuration is a sit-down job and belongs elsewhere. Each of these on
	// the home page is something to scroll past while a child waits.
	for _, unwanted := range []string{
		`action="/profiles/window/add"`,
		`action="/profiles/window/remove"`,
		`action="/profiles/create"`,
		`action="/profiles/delete"`,
		`action="/profiles/devices"`,
		`action="/profiles/budget"`,
		`action="/settings/budget"`,
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("%s belongs on the settings page, not the home page", unwanted)
		}
	}
	assertWholePage(t, get(t, srv, "/"))
}

// And the control: everything removed from home must actually EXIST somewhere,
// or this would be a test that passes by deleting features.
func TestTheSettingsPageCarriesEverythingTheHomePageDropped(t *testing.T) {
	srv, _ := settingsServer(t)
	rec := get(t, srv, "/settings")
	assertWholePage(t, rec)
	body := rec.Body.String()
	for _, want := range []string{
		`action="/profiles/window/add"`,
		`action="/profiles/create"`,
		`action="/profiles/delete"`,
		`action="/profiles/devices"`,
		`action="/profiles/budget"`,
		`action="/settings/budget"`,
		`href="/"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the settings page must offer %s", want)
		}
	}
}

func TestABudgetCanBeSetFromTheSettingsPage(t *testing.T) {
	srv, sch := settingsServer(t)
	rec := post(t, srv.Handler(), "/profiles/budget", url.Values{
		"name": {"eli"}, "daily": {"4h"}, "continuous": {"2h"},
		"gap": {"10m"}, "reset_gap": {"30m"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("unexpected error: %s", loc)
	}
	// An edit must come back to where it was made, not throw you home.
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/settings") {
		t.Errorf("a settings edit must return to settings, got %q", loc)
	}
	got := sch.ps.Profiles[0].Budget
	want := budget.Limits{
		Daily: budget.D(4 * time.Hour), Continuous: budget.D(2 * time.Hour),
		Gap: budget.D(10 * time.Minute), ResetGap: budget.D(30 * time.Minute),
	}
	if got != want {
		t.Errorf("budget saved as %+v, want %+v", got, want)
	}
	// And the form shows it back, or a parent cannot tell what is set.
	body := get(t, srv, "/settings").Body.String()
	for _, want := range []string{`value="4h"`, `value="2h"`, `value="10m"`, `value="30m"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form should show the saved value %s", want)
		}
	}
}

func TestClearingTheBoxesMakesAProfileUnlimitedAgain(t *testing.T) {
	srv, sch := settingsServer(t)
	post(t, srv.Handler(), "/profiles/budget", url.Values{
		"name": {"eli"}, "daily": {"4h"},
	})
	if sch.ps.Profiles[0].Budget.Unlimited() {
		t.Fatal("the budget should be set before we test clearing it")
	}
	post(t, srv.Handler(), "/profiles/budget", url.Values{
		"name": {"eli"}, "daily": {""}, "continuous": {""}, "gap": {""}, "reset_gap": {""},
	})
	if !sch.ps.Profiles[0].Budget.Unlimited() {
		t.Errorf("clearing every box must mean unlimited, got %+v", sch.ps.Profiles[0].Budget)
	}
}

// The validator's refusals must reach the person typing, not the log.
func TestAnUnusableBudgetIsRefusedWithAMessage(t *testing.T) {
	for _, tc := range []struct {
		what string
		form url.Values
		says string
	}{
		{"a bare number", url.Values{"name": {"eli"}, "daily": {"240"}}, "unit"},
		{"nonsense", url.Values{"name": {"eli"}, "daily": {"soon"}}, "not a duration"},
		{"half a continuity group",
			url.Values{"name": {"eli"}, "continuous": {"2h"}}, "together"},
		{"a penalty weaker than stopping",
			url.Values{"name": {"eli"}, "continuous": {"2h"}, "gap": {"10m"}, "reset_gap": {"5m"}},
			"reset_gap"},
		{"a stretch longer than the day",
			url.Values{"name": {"eli"}, "daily": {"1h"}, "continuous": {"2h"},
				"gap": {"1m"}, "reset_gap": {"1m"}}, "never be reached"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			srv, sch := settingsServer(t)
			rec := post(t, srv.Handler(), "/profiles/budget", tc.form)
			loc := rec.Header().Get("Location")
			if !strings.Contains(loc, "error=") {
				t.Fatalf("%s must be refused, got %q", tc.what, loc)
			}
			if !strings.Contains(loc, url.QueryEscape(tc.says)) &&
				!strings.Contains(loc, strings.ReplaceAll(tc.says, " ", "+")) {
				t.Errorf("the message should mention %q, got %q", tc.says, loc)
			}
			// Nothing reaches the file. A rejected budget that saved anyway
			// would be enforced at the next tick.
			if !sch.ps.Profiles[0].Budget.Unlimited() {
				t.Errorf("a refused budget was saved anyway: %+v", sch.ps.Profiles[0].Budget)
			}
		})
	}
}

func TestTheHouseholdBudgetSettingsCanBeSet(t *testing.T) {
	srv, sch := settingsServer(t)
	rec := post(t, srv.Handler(), "/settings/budget", url.Values{
		"reset_time": {"04:30"}, "threshold_kb": {"80"},
	})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("unexpected error: %s", loc)
	}
	if sch.ps.Budget.ResetTime != "04:30" {
		t.Errorf("reset time = %q, want 04:30", sch.ps.Budget.ResetTime)
	}
	// Typed in KB, stored in bytes. Getting this conversion backwards would
	// make the threshold a thousand times too small and every idle device
	// would burn budget.
	if got := sch.ps.Budget.ActivityThresholdBytesPerMinute; got != 80*1024 {
		t.Errorf("threshold = %d bytes/min, want %d", got, 80*1024)
	}
	body := get(t, srv, "/settings").Body.String()
	if !strings.Contains(body, `value="80"`) {
		t.Error("the form should show the threshold back in the units it was typed in")
	}
	if !strings.Contains(body, `value="04:30"`) {
		t.Error("the form should show the saved reset time")
	}
}

func TestABadHouseholdSettingIsRefused(t *testing.T) {
	srv, sch := settingsServer(t)
	for _, form := range []url.Values{
		{"reset_time": {"25:00"}, "threshold_kb": {"50"}},
		{"reset_time": {"03:00"}, "threshold_kb": {"lots"}},
		{"reset_time": {"03:00"}, "threshold_kb": {"0"}},
	} {
		rec := post(t, srv.Handler(), "/settings/budget", form)
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
			t.Errorf("%v must be refused, got %q", form, loc)
		}
	}
	if sch.ps.Budget != (budget.Settings{}) {
		t.Errorf("a refused setting was saved anyway: %+v", sch.ps.Budget)
	}
}

// The threshold default is a GUESS, and the page has to say so. This is the
// single most likely thing to make the feature feel arbitrary in a house, and
// a settings page that presented the default as a settled number would be the
// quietest possible way to get that wrong.
func TestTheSettingsPageAdmitsTheThresholdDefaultIsAGuess(t *testing.T) {
	srv, _ := settingsServer(t)
	body := get(t, srv, "/settings").Body.String()
	if !strings.Contains(body, "guess rather than a") {
		t.Errorf("the page must admit the default threshold is not measured:\n%s", body)
	}
	// And it must stop saying so once a household has set its own number,
	// otherwise the warning is noise and gets ignored.
	post(t, srv.Handler(), "/settings/budget", url.Values{
		"reset_time": {"03:00"}, "threshold_kb": {"80"},
	})
	body = get(t, srv, "/settings").Body.String()
	if strings.Contains(body, "guess rather than a") {
		t.Error("once the threshold is set by hand the page must stop calling it a guess")
	}
}

// The calibration figure belongs next to the field it calibrates.
func TestTheObservedRateIsShownWhereTheThresholdIsSet(t *testing.T) {
	srv, _ := settingsServer(t)
	body := get(t, srv, "/settings").Body.String()
	if !strings.Contains(body, "KB per minute, upstream") {
		t.Error("the threshold field must state its units and direction")
	}
	if !strings.Contains(body, "1.4%") {
		t.Error("the page should say why the numbers are smaller than expected")
	}
}

func TestSettingsRejectsANonGetAndBudgetFormsRejectANonPost(t *testing.T) {
	srv, _ := settingsServer(t)
	rec := post(t, srv.Handler(), "/settings", url.Values{})
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /settings should be 405, got %d", rec.Code)
	}
	for _, path := range []string{"/profiles/budget", "/settings/budget"} {
		rec := get(t, srv, path)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s should be 405, got %d", path, rec.Code)
		}
	}
}

func TestABudgetForAProfileThatDoesNotExistIsRefused(t *testing.T) {
	srv, _ := settingsServer(t)
	rec := post(t, srv.Handler(), "/profiles/budget", url.Values{
		"name": {"ghost"}, "daily": {"4h"},
	})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("want an error for an unknown profile, got %q", loc)
	}
}

// The custom duration box on the home page. Presets cover the common taps;
// this is for "until half past", which a fixed set of buttons cannot express.
func TestACustomTicketDurationIsGrantedAndBounded(t *testing.T) {
	srv, _ := settingsServer(t)
	rec := post(t, srv.Handler(), "/profiles/ticket", url.Values{
		"name": {"eli"}, "minutes": {"47"},
	})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("a custom duration must be accepted: %s", loc)
	}
	// A ticket action belongs to the home page, so it comes back there rather
	// than dumping a parent into settings.
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("a ticket must return home, got %q", loc)
	}
	fw := srv.firewall.(*fakeFirewall)
	if got := fw.tickets["aa:bb:cc:dd:ee:01"]; got != 47*time.Minute {
		t.Errorf("granted %s, want 47m", got)
	}
}

func TestANonsenseCustomDurationIsRefusedRatherThanRounded(t *testing.T) {
	srv, _ := settingsServer(t)
	for _, v := range []string{"", "0", "-5", "half an hour", "1e3"} {
		rec := post(t, srv.Handler(), "/profiles/ticket", url.Values{
			"name": {"eli"}, "minutes": {v},
		})
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
			t.Errorf("minutes=%q must be refused, got %q", v, loc)
		}
	}
	fw := srv.firewall.(*fakeFirewall)
	if len(fw.tickets) != 0 {
		t.Errorf("no ticket should have been granted, got %v", fw.tickets)
	}
}

// The form's cap must be the number the core actually enforces, or the form
// either blocks a legal grant or promises an illegal one.
//
// Only the AGREEMENT is asserted here. Whether an over-long grant is actually
// refused belongs to internal/enforce, which tests it against a real kernel
// (TestGrantTicketRejectsDurationsThatAreNotTickets); teaching this package's
// firewall double to reject it would be the double doing the code's job, which
// is how a deleted rule stayed green here once before.
func TestTheFormCapMatchesTheCapTheCoreEnforces(t *testing.T) {
	srv, _ := settingsServer(t)
	max := int(srv.core.MaxTicket().Minutes())
	if max <= 0 {
		t.Fatalf("the core reports a cap of %d minutes, so the form has nothing to match", max)
	}
	body := get(t, srv, "/").Body.String()
	// The leading space matters: without it `data-max="720"` would satisfy
	// this assertion, and a mutation that renamed the attribute survived
	// exactly that way before the space was added.
	if !strings.Contains(body, ` max="`+strconv.Itoa(max)+`"`) {
		t.Errorf("the form should cap at %d minutes, the number the core enforces", max)
	}
}

// Both pages list the household in the same order. Two orders for the same
// set of children is how a parent edits the wrong one.
func TestBothPagesListProfilesInTheSameOrder(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{
		{Name: "tia"}, {Name: "dad"}, {Name: "eli"},
	}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	order := func(path string) []string {
		body := get(t, srv, path).Body.String()
		var seen []string
		for _, n := range []string{"tia", "dad", "eli"} {
			seen = append(seen, n)
		}
		sort.Slice(seen, func(i, j int) bool {
			return strings.Index(body, "<h2>"+seen[i]+"</h2>") < strings.Index(body, "<h2>"+seen[j]+"</h2>")
		})
		return seen
	}
	home, settings := order("/"), order("/settings")
	if !slices.Equal(home, settings) {
		t.Errorf("home lists %v but settings lists %v", home, settings)
	}
	if !slices.Equal(home, []string{"dad", "eli", "tia"}) {
		t.Errorf("want profiles sorted by name, got %v", home)
	}
}
