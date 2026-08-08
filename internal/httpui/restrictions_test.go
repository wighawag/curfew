package httpui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wighawag/curfew/internal/schedule"
)

// Tests for the settings UI that sets a website restriction on a window.
//
// They assert on what was STORED and on what the next page says, rather than
// on markup, because a substring assertion against a whole page is how
// `max="720"` came to be satisfied by `data-max="720"` in this repo.

func withLists(ps *schedule.Profiles, lists map[string][]string) *schedule.Profiles {
	ps.BlockLists = lists
	return ps
}

func TestAddingARestrictionStoresTheWindowAndWhatItBlocks(t *testing.T) {
	ps := withLists(&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}},
		map[string][]string{"no_streaming": {"twitch.tv"}})
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/restriction/add", url.Values{
		"name": {"eli"}, "start": {"08:00"}, "end": {"10:00"},
		"day":     {"mon", "tue", "wed", "thu", "fri"},
		"list":    {"no_streaming"},
		"service": {"youtube"},
	})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("adding a restriction failed: %s", loc)
	}

	p, ok := sch.ps.Find("eli")
	if !ok || len(p.Restrictions) != 1 {
		t.Fatalf("restriction not stored: %+v", sch.ps)
	}
	r := p.Restrictions[0]
	if len(r.Windows) != 1 || r.Windows[0].Start != "08:00" || r.Windows[0].End != "10:00" {
		t.Errorf("window not stored: %+v", r.Windows)
	}
	if len(r.Windows[0].Days) != 5 {
		t.Errorf("days not stored: %+v", r.Windows[0].Days)
	}
	if len(r.Lists) != 1 || r.Lists[0] != "no_streaming" {
		t.Errorf("lists not stored: %+v", r.Lists)
	}
	if len(r.Services) != 1 || r.Services[0] != "youtube" {
		t.Errorf("services not stored: %+v", r.Services)
	}
	// And the name is derived rather than asked for, so a parent never types
	// one, and it stays unique within the profile.
	if r.Name == "" {
		t.Error("a stored restriction with no name cannot be reported in a log or an error")
	}
}

// The mistake a parent will actually make: set the times, forget to tick
// anything. It must be refused, not saved as something that looks configured
// and blocks nothing.
func TestARestrictionThatBlocksNothingIsRefused(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/restriction/add", url.Values{
		"name": {"eli"}, "start": {"08:00"}, "end": {"10:00"}, "day": {"mon"},
	})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("want an error, got %s", loc)
	}
	if p, _ := sch.ps.Find("eli"); len(p.Restrictions) != 0 {
		t.Errorf("a restriction that blocks nothing was stored: %+v", p.Restrictions)
	}
}

// A restriction naming a list that does not exist would block nothing while
// reading exactly like one that works. Not reachable through the checkboxes,
// very reachable through a stale form or a crafted post.
func TestARestrictionNamingAnUnknownListIsRefused(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/restriction/add", url.Values{
		"name": {"eli"}, "start": {"08:00"}, "end": {"10:00"}, "day": {"mon"},
		"list": {"no_such_list"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Error("a restriction naming an unknown list must be refused")
	}
	if p, _ := sch.ps.Find("eli"); len(p.Restrictions) != 0 {
		t.Errorf("it was stored anyway: %+v", p.Restrictions)
	}
}

func TestRemovingARestrictionRemovesTheRightOne(t *testing.T) {
	ps := withLists(&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli",
		Restrictions: []schedule.Restriction{
			{Name: "a", Lists: []string{"l1"}, Windows: []schedule.Window{{Days: schedule.AllDays, Start: "08:00", End: "10:00"}}},
			{Name: "b", Lists: []string{"l2"}, Windows: []schedule.Window{{Days: schedule.AllDays, Start: "20:00", End: "21:00"}}},
		}}}}, map[string][]string{"l1": {"a.example"}, "l2": {"b.example"}})
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	// Remove the SECOND one. Removing the first proves nothing: an
	// implementation that always drops index 0 passes that case, and one did.
	post(t, srv.Handler(), "/profiles/restriction/remove", url.Values{
		"name": {"eli"}, "index": {"1"}})

	p, _ := sch.ps.Find("eli")
	if len(p.Restrictions) != 1 {
		t.Fatalf("want one left, got %+v", p.Restrictions)
	}
	if p.Restrictions[0].Name != "a" {
		t.Errorf("the WRONG restriction was removed: %+v", p.Restrictions)
	}

	// And an index past the end must be refused rather than panicking or
	// silently removing something.
	rec := post(t, srv.Handler(), "/profiles/restriction/remove", url.Values{
		"name": {"eli"}, "index": {"7"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Error("an out-of-range index must be an error")
	}
	if p, _ := sch.ps.Find("eli"); len(p.Restrictions) != 1 {
		t.Errorf("an out-of-range remove changed the list: %+v", p.Restrictions)
	}
}

func TestSavingABlockListStoresOneDomainPerLine(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	post(t, srv.Handler(), "/settings/blocklist", url.Values{
		"list":    {"no_streaming"},
		"domains": {"twitch.tv\niplayer.bbc.co.uk\n\n# a comment\nTWITCH.TV\n"},
	})
	got := sch.ps.BlockLists["no_streaming"]
	if len(got) != 2 {
		t.Fatalf("want 2 domains (deduplicated, comment dropped), got %v", got)
	}
	if got[0] != "twitch.tv" || got[1] != "iplayer.bbc.co.uk" {
		t.Errorf("domains not parsed: %v", got)
	}
}

// A name with a space would be rendered into AdGuard rule text and change how
// the rule parses, so it is refused at the door with a usable suggestion.
func TestABlockListNameWithASpaceIsRefused(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/settings/blocklist", url.Values{
		"list": {"no streaming"}, "domains": {"twitch.tv"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("want an error, got %s", loc)
	}
	if !strings.Contains(loc, "no_streaming") {
		t.Errorf("the error should suggest a usable name, got %s", loc)
	}
	if len(sch.ps.BlockLists) != 0 {
		t.Errorf("it was stored anyway: %v", sch.ps.BlockLists)
	}
}

func TestAnEmptyBlockListIsRefused(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/settings/blocklist", url.Values{
		"list": {"empty"}, "domains": {"   \n\n"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Error("a list with no domains must be refused")
	}
	if len(sch.ps.BlockLists) != 0 {
		t.Errorf("it was stored anyway: %v", sch.ps.BlockLists)
	}
}

// Deleting a list a restriction still uses would leave that restriction
// blocking nothing while looking untouched. It must be refused, and it must
// name who is using it so the refusal is actionable.
func TestDeletingABlockListInUseIsRefusedAndNamesTheProfile(t *testing.T) {
	ps := withLists(&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli",
		Restrictions: []schedule.Restriction{{Name: "r", Lists: []string{"no_streaming"},
			Windows: []schedule.Window{{Days: schedule.AllDays, Start: "08:00", End: "10:00"}}}}}}},
		map[string][]string{"no_streaming": {"twitch.tv"}})
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/settings/blocklist/delete", url.Values{"list": {"no_streaming"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatalf("want a refusal, got %s", loc)
	}
	if !strings.Contains(loc, "eli") {
		t.Errorf("the refusal must name who is using it, got %s", loc)
	}
	// It must also say WHAT TO DO. Letting this fall through to the schedule
	// validator produces "refusing to save an unusable schedule: restriction
	// names block list ... which is not defined", which describes a corrupt
	// file rather than the thing the parent just tried to do.
	if !strings.Contains(loc, "still+used+by") && !strings.Contains(loc, "still%20used%20by") {
		t.Errorf("the refusal should explain it is in use and what to do, got %s", loc)
	}
	if _, ok := sch.ps.BlockLists["no_streaming"]; !ok {
		t.Error("the list was deleted despite being in use")
	}
}

// The control for the one above: an unused list deletes cleanly, so the
// refusal is about being in use rather than deletion being broken.
func TestDeletingAnUnusedBlockListWorks(t *testing.T) {
	ps := withLists(&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}},
		map[string][]string{"no_streaming": {"twitch.tv"}})
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/settings/blocklist/delete", url.Values{"list": {"no_streaming"}})
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("deleting an unused list failed: %s", loc)
	}
	if _, ok := sch.ps.BlockLists["no_streaming"]; ok {
		t.Error("the list was not deleted")
	}
}

// The settings page must SAY that a restriction will not be applied when
// AdGuard is not configured, rather than offering a control that silently does
// nothing.
func TestTheSettingsPageWarnsWhenAdGuardIsNotConfigured(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	if !strings.Contains(rec.Body.String(), "never applied") {
		t.Error("the page does not warn that restrictions will not be applied")
	}

	// The control: with AdGuard wired up the warning goes away and the
	// catalogue is offered, so the warning means something.
	srv.UseAdGuardServices(func() ([]string, error) { return []string{"youtube", "roblox"}, nil })
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	body := rec.Body.String()
	if strings.Contains(body, "never applied") {
		t.Error("the warning is still shown with AdGuard configured")
	}
	form := formAction(t, body, "/profiles/restriction/add")
	for _, want := range []string{`value="youtube"`, `value="roblox"`} {
		if !strings.Contains(form, want) {
			t.Errorf("the service %s is not offered in the restriction form", want)
		}
	}
}

// An AdGuard that cannot be reached must be reported as such, because an empty
// service list is otherwise indistinguishable from an AdGuard offering none.
func TestAnUnreadableServiceCatalogueSaysSoRatherThanShowingNothing(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)
	srv.UseAdGuardServices(func() ([]string, error) { return nil, errUnreachable })

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	if !strings.Contains(rec.Body.String(), "could not be read") {
		t.Error("the page does not say why no services are offered")
	}
}

var errUnreachable = &unreachableError{}

type unreachableError struct{}

func (e *unreachableError) Error() string { return "connection refused" }

// A restriction the parent set must show on the page, with what it blocks and
// whether it is in force, so "configured" and "happening now" are told apart.
func TestTheSettingsPageShowsARestrictionAndWhetherItIsInForce(t *testing.T) {
	ps := withLists(&schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli",
		Restrictions: []schedule.Restriction{{
			Name: "no streaming", Lists: []string{"no_streaming"}, Services: []string{"youtube"},
			// Always active, so the assertion does not depend on the clock.
		}}}}}, map[string][]string{"no_streaming": {"twitch.tv"}})
	srv, _, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	body := rec.Body.String()
	for _, want := range []string{"no_streaming", "youtube", "in force now"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	// And it must say these are softer than a blocked window, or a parent will
	// trust them the same way they trust bedtime.
	if !strings.Contains(body, "get around") {
		t.Error("the page does not say a DNS restriction is a softer control")
	}
}

// A comment must not become a domain. Splitting on whitespace before stripping
// the comment turned "# a comment" into rules blocking "a" and "comment",
// which are real names nobody asked to block.
func TestACommentNeverBecomesADomain(t *testing.T) {
	got := splitDomains("twitch.tv\n# block these later: foo.example bar.example\n! and this\n")
	if len(got) != 1 || got[0] != "twitch.tv" {
		t.Errorf("a comment leaked into the domains: %v", got)
	}
	// The control: a trailing comment on a real line keeps the domain.
	got = splitDomains("twitch.tv # streaming\n")
	if len(got) != 1 || got[0] != "twitch.tv" {
		t.Errorf("a trailing comment ate the domain: %v", got)
	}
}

// Something that is not a plain domain must be refused rather than written
// into AdGuard rule text where it would silently mean something else.
func TestADomainCarryingRuleSyntaxIsRefused(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	rec := post(t, srv.Handler(), "/settings/blocklist", url.Values{
		"list": {"bad"}, "domains": {"||twitch.tv^$client=someone"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Error("a domain carrying AdGuard rule syntax must be refused")
	}
	if len(sch.ps.BlockLists) != 0 {
		t.Errorf("it was stored anyway: %v", sch.ps.BlockLists)
	}
}

// The DoH toggle is its own form on purpose: an unchecked checkbox submits
// nothing, so folding it into another form would silently turn it off whenever
// that form was saved.
func TestTheDoHToggleIsSavedAndDefaultsToOn(t *testing.T) {
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	// Default, with nothing stored, is ON.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assertWholePage(t, rec)
	form := formAction(t, rec.Body.String(), "/settings/dns")
	if !strings.Contains(form, "checked") {
		t.Error("the DoH block should be shown as on by default")
	}

	// Turning it off stores false rather than leaving it absent, so the
	// household's deliberate choice survives a push and a pull.
	post(t, srv.Handler(), "/settings/dns", url.Values{})
	if sch.ps.BlockDoHBootstrap == nil || *sch.ps.BlockDoHBootstrap {
		t.Errorf("turning it off was not stored: %v", sch.ps.BlockDoHBootstrap)
	}
	if sch.ps.DoHBootstrapBlocked() {
		t.Error("the accessor still reports it as on")
	}

	// And back on again.
	post(t, srv.Handler(), "/settings/dns", url.Values{"block_doh": {"1"}})
	if !sch.ps.DoHBootstrapBlocked() {
		t.Error("turning it back on was not stored")
	}
}

// Saving the BUDGET form must not disturb the DoH setting, which is the exact
// bug that folding the checkbox into that form would have created.
func TestSavingBudgetSettingsLeavesTheDoHSettingAlone(t *testing.T) {
	off := false
	ps := &schedule.Profiles{Profiles: []schedule.Profile{{Name: "eli"}}, BlockDoHBootstrap: &off}
	srv, sch, _ := newProfileServer(t, nil, ps, nil, nil)

	post(t, srv.Handler(), "/settings/budget", url.Values{
		"reset_time": {"03:00"}, "threshold_kb": {"50"}})

	if sch.ps.DoHBootstrapBlocked() {
		t.Error("saving the budget form turned the DoH block back on")
	}
}
