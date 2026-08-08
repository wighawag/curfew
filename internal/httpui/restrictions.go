package httpui

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/wighawag/curfew/internal/schedule"
)

// The settings UI for per-profile DNS restrictions, and for the household's
// own named domain lists that feed them.
//
// A restriction row is deliberately the SAME shape as a blocked window (days,
// a start and an end) with one addition: what to block during it. That is the
// whole difference a parent needs to hold in their head, and making the two
// forms look alike is what makes "no internet after 22:00" and "no streaming
// between 08:00 and 10:00" feel like two settings of one kind rather than two
// unrelated features.
//
// They are NOT the same kind underneath, and the page says so rather than
// hiding it. A blocked window is nftables on MAC: it fails closed, it covers
// every protocol, and a device cannot escape it. A restriction is AdGuard on
// IP: it fails OPEN, it only removes names from DNS, and a determined child
// can walk around it. A parent who believed the second was as solid as the
// first would be relying on something this project knows to be softer, and
// that is exactly the kind of quiet false confidence the whole codebase exists
// to remove.

// RestrictionView is one restriction row on the settings page.
type RestrictionView struct {
	// When describes the windows in the same words a blocked window uses.
	When []string
	// Blocks names what it removes, ready to read: the household lists first,
	// then the catalogue services.
	Blocks string
	// Active says whether it applies right now, so a parent can tell "this is
	// set up" from "this is in force".
	Active bool
}

// blockListView is one household domain list on the settings page.
type blockListView struct {
	Name string
	// Domains is the textarea content: one domain per line, which is the only
	// format that survives a round trip without inventing a separator.
	Domains string
	Count   int
	// UsedBy names the profiles whose restrictions reference this list, so
	// deleting one is an informed decision rather than a surprise.
	UsedBy []string
}

// describeRestriction renders what a restriction blocks, in a parent's words.
func describeRestriction(r schedule.Restriction) string {
	var parts []string
	if len(r.Lists) > 0 {
		parts = append(parts, strings.Join(r.Lists, ", "))
	}
	if len(r.Services) > 0 {
		parts = append(parts, strings.Join(r.Services, ", "))
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, " + ")
}

// restrictionName derives a name for a restriction added from the page.
//
// The stored model lets one named restriction carry SEVERAL windows, which a
// hand-editor can use to say "no streaming, at these three times". The page
// deliberately does not expose that: a parent thinks in rows of "between these
// hours, block this", so each row is its own restriction and the name is
// derived rather than asked for. Including the times keeps it unique, which
// matters because two restrictions in one profile may not share a name.
func restrictionName(r schedule.Restriction) string {
	what := describeRestriction(r)
	if len(r.Windows) == 0 {
		return what
	}
	w := r.Windows[0]
	return fmt.Sprintf("%s %s-%s", what, w.Start, w.End)
}

// handleRestrictionAdd adds one restriction window to a profile.
func (s *Server) handleRestrictionAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	start := r.FormValue("start")
	end := r.FormValue("end")

	var days []schedule.Day
	for _, d := range r.Form["day"] {
		parsed, err := schedule.ParseDay(d)
		if err != nil {
			redirectSettings(w, r, err)
			return
		}
		days = append(days, parsed)
	}
	lists := cleaned(r.Form["list"])
	services := cleaned(r.Form["service"])

	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		p, ok := ps.Find(name)
		if !ok {
			return fmt.Errorf("no profile called %q", name)
		}
		win := schedule.Window{Days: days, Start: start, End: end}
		if err := win.Validate(); err != nil {
			return err
		}
		restriction := schedule.Restriction{
			Lists: lists, Services: services, Windows: []schedule.Window{win},
		}
		restriction.Name = restrictionName(restriction)
		// Validated before it is appended, so a rejected restriction never
		// reaches the file and the message names the real problem. The
		// "blocks nothing" case is the one a parent will actually hit, by
		// setting times and forgetting to tick anything.
		known := map[string]bool{}
		for l := range ps.BlockLists {
			known[l] = true
		}
		if err := restriction.Validate(known); err != nil {
			return err
		}
		for _, existing := range p.Restrictions {
			if existing.Name == restriction.Name {
				return fmt.Errorf("%q already has exactly this restriction", p.Name)
			}
		}
		p.Restrictions = append(p.Restrictions, restriction)
		return nil
	})
	if err == nil {
		s.log.Info("dns restriction added", "profile", name, "start", start, "end", end,
			"lists", lists, "services", services)
	}
	redirectSettings(w, r, err)
}

// handleRestrictionRemove drops one restriction from a profile.
func (s *Server) handleRestrictionRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	idx := r.FormValue("index")
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		p, ok := ps.Find(name)
		if !ok {
			return fmt.Errorf("no profile called %q", name)
		}
		var i int
		if _, scanErr := fmt.Sscanf(idx, "%d", &i); scanErr != nil || i < 0 || i >= len(p.Restrictions) {
			return fmt.Errorf("no such restriction")
		}
		p.Restrictions = append(p.Restrictions[:i], p.Restrictions[i+1:]...)
		return nil
	})
	if err == nil {
		s.log.Info("dns restriction removed", "profile", name)
	}
	redirectSettings(w, r, err)
}

// handleBlockListSave creates or replaces one household domain list.
func (s *Server) handleBlockListSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("list"))
	domains := splitDomains(r.FormValue("domains"))

	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		if name == "" {
			return fmt.Errorf("a block list needs a name")
		}
		if strings.ContainsAny(name, " \t,") {
			// The name is referenced from a restriction and rendered into
			// AdGuard rule text, so a space or a comma would change how it
			// parses. Refused at the door rather than silently mangled.
			return fmt.Errorf("a block list name cannot contain spaces or commas: try %q",
				strings.ReplaceAll(strings.TrimSpace(name), " ", "_"))
		}
		if len(domains) == 0 {
			return fmt.Errorf("block list %q has no domains in it", name)
		}
		if ps.BlockLists == nil {
			ps.BlockLists = map[string][]string{}
		}
		ps.BlockLists[name] = domains
		return nil
	})
	if err == nil {
		s.log.Info("block list saved", "list", name, "domains", len(domains))
		redirectSaved(w, r, "block list "+name)
		return
	}
	redirectSettings(w, r, err)
}

// handleBlockListDelete removes a household domain list.
//
// It REFUSES while a restriction still references it, and names the profiles,
// rather than deleting it and leaving restrictions pointing at nothing. A
// restriction naming a list that does not exist blocks nothing while reading,
// on the page and in the file, exactly like one that works.
func (s *Server) handleBlockListDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("list"))
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		if _, ok := ps.BlockLists[name]; !ok {
			return fmt.Errorf("no block list called %q", name)
		}
		if users := listUsers(ps, name); len(users) > 0 {
			return fmt.Errorf("block list %q is still used by %s; remove those restrictions first",
				name, strings.Join(users, ", "))
		}
		delete(ps.BlockLists, name)
		if len(ps.BlockLists) == 0 {
			ps.BlockLists = nil
		}
		return nil
	})
	if err == nil {
		s.log.Info("block list deleted", "list", name)
	}
	redirectSettings(w, r, err)
}

// listUsers names the profiles whose restrictions reference a list.
func listUsers(ps *schedule.Profiles, list string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps.Profiles {
		for _, r := range p.Restrictions {
			for _, l := range r.Lists {
				if l == list && !seen[p.Name] {
					seen[p.Name] = true
					out = append(out, p.Name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// splitDomains reads the textarea: one domain per line, blanks and comments
// dropped, lowercased so the same domain typed twice is the same domain.
//
// Comments are stripped PER LINE and before anything is split on whitespace.
// Doing it the other way round turns "# a comment" into the domains "a" and
// "comment", which is a rule that blocks a real name nobody asked to block.
func splitDomains(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		if i := strings.IndexAny(line, "#!"); i >= 0 {
			line = line[:i]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
		}) {
			d := strings.ToLower(strings.TrimSpace(field))
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// cleaned trims and drops blanks from a set of checkbox values.
func cleaned(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// handleDNSSettings owns the household-wide DNS knobs. Today that is one: the
// DoH bootstrap block.
//
// It is a checkbox rather than a hand-edited field because every other setting
// on this page is editable here, and a control that exists only in a JSON file
// is a control a parent will never find. It is separated from the budget form
// because an unchecked checkbox submits NOTHING, so folding it into a form
// about something else would silently turn it off whenever that other form was
// saved.
func (s *Server) handleDNSSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	on := r.FormValue("block_doh") != ""
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		ps.BlockDoHBootstrap = &on
		return nil
	})
	if err == nil {
		s.log.Info("DoH bootstrap blocking changed", "enabled", on)
		redirectSaved(w, r, "DNS settings saved")
		return
	}
	redirectSettings(w, r, err)
}

// handleAllowedDomains saves the household's DNS exceptions.
//
// These exist because curfew's OWN default filter lists produce false
// positives: measured on the live router, opensea.io is blocked by the Porn
// list and eth.limo by the Malware list, both from blocklistproject. Without
// this a household has to choose between filtering and reaching a site it
// uses, or keep the exception in AdGuard where a reinstall loses it, which is
// the exact defect ADR 0002 recorded.
func (s *Server) handleAllowedDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	domains := splitDomains(r.FormValue("domains"))
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		ps.AllowedDomains = domains
		return nil
	})
	if err == nil {
		s.log.Info("allowed domains saved", "count", len(domains))
		redirectSaved(w, r, "always-allowed sites saved")
		return
	}
	redirectSettings(w, r, err)
}
