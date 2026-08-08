package httpui

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/schedule"
)

// The category blocklists, as something a household chooses rather than
// something the installer decided once.
//
// This is the one control on this server that deliberately interrupts the
// house. Applying it stops AdGuard, rewrites its config and starts it again,
// which takes DNS down for the best part of a minute; every other way of
// changing a subscribed list makes AdGuard rebuild its filtering engine while
// the old one is still resident, and on a 1 GB router that is what OOM-killed
// it and cost 88 seconds of DNS unannounced. A deliberate minute beats a
// random one, but only if the page SAYS so before the tap, which is why the
// form carries the warning and the confirmation carries the measured downtime.

// CategoryApplier applies a category change to the running AdGuard. It is nil
// when the daemon has not wired one up, in which case the section renders as
// unavailable rather than as a control that saves and does nothing.
type CategoryApplier func(wanted []string) (adguard.ApplyReport, error)

// UseAdGuardCategories lets the settings page own the category blocklists.
func (s *Server) UseAdGuardCategories(apply CategoryApplier) {
	s.applyCategories = apply
}

// CategoryView is one tick box on the settings page.
type CategoryView struct {
	Name     string
	Selected bool
	// Note warns about a list whose cost is worth knowing before choosing it.
	Note string
}

// categoryNotes are measured facts about specific lists, not opinions. They
// are here because a name alone gives a parent no way to judge, and because
// both of the false positives this household actually hit came from one list
// that is also more than half the memory.
var categoryNotes = map[string]string{
	"Malware": "56 MB, over half the total. Blocks eth.limo and euc.li as false positives.",
	"Porn":    "20 MB. Blocks opensea.io as a false positive.",
}

func categoryViews(ps *schedule.Profiles) []CategoryView {
	chosen := map[string]bool{}
	for _, c := range ps.Categories() {
		if name, ok := adguard.CanonicalCategory(c); ok {
			chosen[name] = true
		}
	}
	out := make([]CategoryView, 0, len(adguard.Categories))
	for _, name := range adguard.Categories {
		out = append(out, CategoryView{
			Name: name, Selected: chosen[name], Note: categoryNotes[name],
		})
	}
	return out
}

// handleCategories saves the household's choice and applies it.
//
// The config is saved FIRST and independently of whether AdGuard could be
// restarted. The choice is the household's and belongs in curfew's config
// whatever the router's DNS is doing; an apply that fails is reported, and the
// settings page then shows the saved choice next to AdGuard's actual state, so
// a disagreement is visible rather than hidden behind a form that silently
// reverted.
func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var wanted []string
	for _, name := range r.Form["categories"] {
		c, ok := adguard.CanonicalCategory(name)
		if !ok {
			redirectSettings(w, r, fmt.Errorf("no filter category called %q", name))
			return
		}
		wanted = append(wanted, c)
	}
	sort.Strings(wanted)

	if err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		ps.SetCategories(wanted)
		return nil
	}); err != nil {
		redirectSettings(w, r, err)
		return
	}
	if s.applyCategories == nil {
		redirectSaved(w, r, "filter lists saved; AdGuard is not configured here, so nothing "+
			"was applied to it")
		return
	}

	report, err := s.applyCategories(wanted)
	if err != nil {
		s.log.Error("applying the filter lists to AdGuard", "error", err)
		redirectSettings(w, r, err)
		return
	}
	if !report.Changed {
		redirectSaved(w, r, "filter lists saved; AdGuard already had exactly these")
		return
	}
	s.log.Info("filter lists applied", "added", report.Added, "removed", report.Removed,
		"downtime", report.Downtime.Round(time.Second))
	redirectSaved(w, r, fmt.Sprintf("filter lists applied; AdGuard restarted and DNS was "+
		"down for %s", report.Downtime.Round(time.Second)))
}
