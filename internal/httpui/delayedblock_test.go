package httpui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// The whole feature from the page's side: a parent taps "in 30", the child is
// NOT cut off, and the card says when they will be.
// armed reports whether a countdown is stored for this profile, read back
// through the store the way the daemon would read it after a reboot.
func armed(t *testing.T, st *memState, profile string) bool {
	t.Helper()
	s, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	_, ok := s.PendingBlockAt(profile)
	return ok
}

func TestArmingADelayedBlockFromTheHomePageDoesNotCutTheChildOffYet(t *testing.T) {
	srv, st, _, fw := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)

	rec := post(t, srv.Handler(), "/profiles/block-in", url.Values{
		"name": {"eli"}, "minutes": {"30"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect back home, got %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("arming reported an error: %s", rec.Header().Get("Location"))
	}

	// The decision is recorded, which is what makes it survive a reboot.
	if !armed(t, st, "eli") {
		t.Error("nothing was persisted, so a reboot cancels the countdown")
	}
	// And nothing was blocked. This is the assertion that separates this
	// feature from the block button next to it.
	if len(fw.manual) != 0 {
		t.Errorf("arming a delayed block blocked the child immediately: %v", fw.manual)
	}

	// The page says so, and offers a way out.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	body := rec.Body.String()
	if !strings.Contains(body, "blocks in") {
		t.Errorf("the home page does not say a block is coming:\n%s", body)
	}
	if !strings.Contains(body, `action="/profiles/block-in/cancel"`) {
		t.Errorf("an armed countdown cannot be cancelled from the page:\n%s", body)
	}
}

// The button has to be there before it can be tapped, with the presets and a
// custom box, the same shape as the ticket row it mirrors.
func TestTheHomePageOffersTheDelayedBlockButton(t *testing.T) {
	srv, _, _ := newProfileServer(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	form := formAction(t, rec.Body.String(), "/profiles/block-in")
	if !strings.Contains(form, `name="minutes"`) {
		t.Errorf("the delayed-block form sends no duration:\n%s", form)
	}
	if !strings.Contains(form, `value="eli"`) {
		t.Errorf("the delayed-block form names no profile:\n%s", form)
	}
}

func TestCancellingFromTheHomePageDisarmsTheCountdown(t *testing.T) {
	srv, st, _, _ := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)

	post(t, srv.Handler(), "/profiles/block-in", url.Values{
		"name": {"eli"}, "minutes": {"30"}})
	if !armed(t, st, "eli") {
		t.Fatal("baseline: nothing was armed, so cancelling proves nothing")
	}
	rec := post(t, srv.Handler(), "/profiles/block-in/cancel", url.Values{"name": {"eli"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want a redirect, got %d", rec.Code)
	}
	if armed(t, st, "eli") {
		t.Error("the countdown is still armed after cancelling")
	}
}

// A duration a parent could not have meant must be refused with something they
// can read, not accepted and quietly turned into a block right now.
func TestADelayedBlockWithNoUsableDurationIsRefused(t *testing.T) {
	srv, st, _, fw := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)

	for _, bad := range []string{"", "0", "-5", "soon"} {
		rec := post(t, srv.Handler(), "/profiles/block-in", url.Values{
			"name": {"eli"}, "minutes": {bad}})
		if !strings.Contains(rec.Header().Get("Location"), "error=") {
			t.Errorf("a delay of %q was accepted silently", bad)
		}
		if armed(t, st, "eli") {
			t.Fatalf("a delay of %q armed a countdown anyway", bad)
		}
		if len(fw.manual) != 0 {
			t.Fatalf("a delay of %q blocked the child: %v", bad, fw.manual)
		}
	}
}

// The GET path must not act. A link-prefetching browser or a phone's page
// preview must not be able to arm a block.
func TestADelayedBlockNeedsAPost(t *testing.T) {
	srv, st, _, _ := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)

	for _, path := range []string{"/profiles/block-in", "/profiles/block-in/cancel"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: want 405, got %d", path, rec.Code)
		}
	}
	if armed(t, st, "eli") {
		t.Error("a GET armed a countdown")
	}
}

// A profile that is already blocked gets no countdown button, because there is
// nothing for it to do, and the core refuses it anyway.
func TestAnAlreadyBlockedProfileIsNotOfferedACountdown(t *testing.T) {
	srv, _, _, _ := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		nil, []string{"aa:bb:cc:dd:ee:01"}, []string{"eli"})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assertWholePage(t, rec)
	if strings.Contains(rec.Body.String(), `action="/profiles/block-in"`) {
		t.Error("a profile that is already blocked was offered a delayed block")
	}
}

// The countdown line is DERIVED from the clock on each render, so it cannot go
// stale, and it must round the way a person reads a clock rather than showing
// a bare timestamp.
func TestTheCountdownLineCountsDownAsTheClockMoves(t *testing.T) {
	srv, _, _, _ := newProfileServerWithState(t,
		[]registry.Device{{MAC: "aa:bb:cc:dd:ee:01", Name: "eli phone"}},
		&schedule.Profiles{Profiles: []schedule.Profile{
			{Name: "eli", Devices: []string{"aa:bb:cc:dd:ee:01"}},
		}},
		[]string{"aa:bb:cc:dd:ee:01"}, nil, nil)

	post(t, srv.Handler(), "/profiles/block-in", url.Values{
		"name": {"eli"}, "minutes": {"45"}})

	views, err := srv.profileViews(time.Now().In(srv.loc))
	if err != nil {
		t.Fatal(err)
	}
	if got := views[0].PendingBlock; !strings.Contains(got, "45m") {
		t.Errorf("the card does not say how long is left, got %q", got)
	}
	// Wind the clock forward: the same stored deadline must read differently.
	views, err = srv.profileViews(time.Now().In(srv.loc).Add(30 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := views[0].PendingBlock; !strings.Contains(got, "15m") {
		t.Errorf("the countdown did not move with the clock, got %q", got)
	}
	// And once it is due, the card must not claim it is still coming.
	views, err = srv.profileViews(time.Now().In(srv.loc).Add(50 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := views[0].PendingBlock; strings.Contains(got, "-") {
		t.Errorf("an overdue countdown renders a negative duration: %q", got)
	}
}
