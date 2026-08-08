package httpui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/schedule"
)

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// recordingApplier stands in for the router. It records what it was asked for
// and nothing else: it knows no rule about categories, so it cannot agree with
// a broken implementation.
type recordingApplier struct {
	got    [][]string
	report adguard.ApplyReport
	err    error
}

func (a *recordingApplier) apply(wanted []string) (adguard.ApplyReport, error) {
	a.got = append(a.got, append([]string(nil), wanted...))
	return a.report, a.err
}

func categoryServer(t *testing.T, applier *recordingApplier) (*Server, *fakeSchedule) {
	t.Helper()
	srv, _, sch, _ := newProfileServerWithState(t, nil,
		&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}, nil, nil, nil)
	if applier != nil {
		srv.UseAdGuardCategories(applier.apply)
	}
	return srv, sch
}

// The choice is the household's, so it must be in curfew's config: that is
// what makes it survive a reinstall and travel with push and pull, which is
// the whole reason this is not done in AdGuard's own UI.
func TestSavingCategoriesStoresThemInCurfewsConfigAndAppliesThem(t *testing.T) {
	applier := &recordingApplier{report: adguard.ApplyReport{
		Changed: true, Removed: []string{"Malware"}, Downtime: 42 * time.Second}}
	srv, sch := categoryServer(t, applier)

	rec := post(t, srv.Handler(), "/settings/categories", url.Values{
		"categories": {"Gambling", "Porn", "Phishing", "Ransomware", "Scam", "Fraud", "Ads"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect, got %d: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("saving reported an error: %s", loc)
	}

	got := sch.ps.Categories()
	if len(got) != 7 || contains(got, "Malware") {
		t.Errorf("the config does not record the choice: %v", got)
	}
	if len(applier.got) != 1 || contains(applier.got[0], "Malware") {
		t.Errorf("AdGuard was not asked for the same set: %v", applier.got)
	}
	// The measured downtime is reported, because the form promised a minute
	// and a promise nobody can check is not a promise.
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "42s") {
		t.Errorf("the confirmation does not say how long DNS was down: %s", loc)
	}
}

// Absent must mean the default set, so an existing household upgrading to this
// version keeps exactly what it had.
func TestAHouseholdThatHasNeverChosenGetsTheDefaultSet(t *testing.T) {
	ps := &schedule.Profiles{}
	got := ps.Categories()
	if len(got) != len(adguard.Categories) {
		t.Fatalf("an unconfigured household should carry the default set, got %v", got)
	}
	// And choosing NOTHING is a different thing from never having chosen.
	ps.SetCategories(nil)
	if len(ps.Categories()) != 0 {
		t.Errorf("a household that removed every list was given the defaults back: %v",
			ps.Categories())
	}
}

// A failed apply must not lose the choice. The config is the household's and
// belongs to curfew whatever the router's DNS is doing.
func TestAFailedApplyStillKeepsTheSavedChoiceAndSaysWhatWentWrong(t *testing.T) {
	applier := &recordingApplier{err: errors.New("AdGuard did not come back")}
	srv, sch := categoryServer(t, applier)

	rec := post(t, srv.Handler(), "/settings/categories", url.Values{
		"categories": {"Porn"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("a failed apply was reported as success: %s", loc)
	}
	if !strings.Contains(loc, "did+not+come+back") {
		t.Errorf("the page does not carry AdGuard's own reason: %s", loc)
	}
	if got := sch.ps.Categories(); len(got) != 1 || got[0] != "Porn" {
		t.Errorf("a failed apply threw away the household's choice: %v", got)
	}
}

// Unticking everything is a legitimate choice and must reach the router as an
// empty set, not be read as "no selection, so change nothing".
func TestUntickingEveryCategoryIsAppliedRatherThanIgnored(t *testing.T) {
	applier := &recordingApplier{report: adguard.ApplyReport{Changed: true}}
	srv, sch := categoryServer(t, applier)

	post(t, srv.Handler(), "/settings/categories", url.Values{})
	if got := sch.ps.Categories(); len(got) != 0 {
		t.Errorf("an empty selection did not save as empty: %v", got)
	}
	if len(applier.got) != 1 || len(applier.got[0]) != 0 {
		t.Errorf("an empty selection was not applied: %v", applier.got)
	}
}

func TestAnUnknownCategoryIsRefusedBeforeAnythingIsSaved(t *testing.T) {
	applier := &recordingApplier{}
	srv, sch := categoryServer(t, applier)

	rec := post(t, srv.Handler(), "/settings/categories", url.Values{
		"categories": {"Porn", "Cats"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Error("an unknown category was accepted")
	}
	if sch.ps.FilterCategories != nil {
		t.Errorf("a refused save changed the config: %v", sch.ps.Categories())
	}
	if len(applier.got) != 0 {
		t.Error("a refused save restarted AdGuard")
	}
}

// With no AdGuard wired up, the section must say so rather than offer a
// control that saves and silently applies to nothing.
func TestWithoutAdGuardTheSectionSaysSoInsteadOfPretending(t *testing.T) {
	srv, _ := categoryServer(t, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	body := rec.Body.String()
	if strings.Contains(body, `action="/settings/categories"`) {
		t.Error("a control was offered that cannot do anything")
	}
	if !strings.Contains(body, "AdGuard is not configured here") {
		t.Errorf("the page does not explain why the control is missing:\n%s", body)
	}
}

// The page must warn BEFORE the tap, not explain afterwards, because the tap
// takes the whole household's DNS down.
func TestTheFormWarnsThatApplyingRestartsAdGuard(t *testing.T) {
	applier := &recordingApplier{}
	srv, _ := categoryServer(t, applier)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	form := formAction(t, rec.Body.String(), "/settings/categories")
	if !strings.Contains(form, "RESTARTS AdGuard") {
		t.Errorf("the form does not warn that DNS goes down:\n%s", form)
	}
	// Every category is offered, ticked as the household has it.
	for _, name := range adguard.Categories {
		if !strings.Contains(form, `value="`+name+`"`) {
			t.Errorf("category %q is not offered:\n%s", name, form)
		}
	}
	if strings.Count(form, "checked") != len(adguard.Categories) {
		t.Errorf("a default household should show every box ticked:\n%s", form)
	}
}

func TestCategoriesNeedAPost(t *testing.T) {
	applier := &recordingApplier{}
	srv, _ := categoryServer(t, applier)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings/categories", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", rec.Code)
	}
	if len(applier.got) != 0 {
		t.Error("a GET restarted AdGuard")
	}
}
