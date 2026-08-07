package httpui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/contract"
	"github.com/wighawag/curfew/internal/schedule"
)

// ticketDurations are the taps a parent gets on their phone. Kept short and
// few on purpose: a ticket is "a bit more time now", and anything long enough
// to need a date picker is a schedule change instead.
var ticketDurations = []time.Duration{
	15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour,
}

// ScheduleStore loads and saves profiles and their windows.
type ScheduleStore interface {
	Load() (*schedule.Profiles, error)
	Save(*schedule.Profiles) error
}

// ProfileView is one row of the home page.
type ProfileView struct {
	Name    string
	Devices []DeviceView
	Windows []string
	// Blocked is read from the FIREWALL, not computed from the clock, per
	// docs/adr/0004-tests-assert-on-the-packet-path.md. It is the truth about
	// what is happening to packets right now. True only when EVERY device is
	// blocked; see Partial.
	Blocked bool
	// Partial means some of the profile's devices are blocked and some are
	// not. That is always drift: a half-enforced bedtime is a child online on
	// their other device.
	Partial bool
	// ShouldBeBlocked is what the schedule AND the parent's stored decision say
	// SHOULD be true, allowing for a live ticket. When it disagrees with the
	// firewall the page says so, because that gap is the entire failure this
	// project exists to make visible rather than hide.
	ShouldBeBlocked bool
	Reason          string
	// ManuallyBlocked is the parent's stored DECISION: this profile is off
	// until they say otherwise. It drives which of the two buttons is offered,
	// so it is intent rather than what the firewall is doing.
	ManuallyBlocked bool
	// ManualEnforced is whether the FIREWALL is dropping every one of this
	// profile's devices in the manual tier. It is tracked separately from
	// Blocked because a profile can be offline for the RIGHT overall answer
	// and the WRONG reason: blocked by a window that is about to end, while a
	// parent believes they blocked it indefinitely.
	ManualEnforced bool
	// TicketLeft is the KERNEL's own countdown on this profile's grant, empty
	// when there is none. Nothing here tracks a parallel clock, which is why
	// it cannot drift and why an expiring ticket needs no bookkeeping.
	TicketLeft string
	// NeedsDevices flags a profile with no devices. It is a warning rather
	// than a neutral state because a schedule with nothing to apply it to
	// enforces nothing while looking configured, which is the shape of every
	// failure this project exists to surface. Shown whether or not a window
	// happens to be active right now.
	NeedsDevices bool
	// Warning is the text for that, phrased for the case at hand.
	Warning string
	// StateLabel and StateClass are what the badge shows. Computed here rather
	// than branched in the template so the empty-profile case can state the
	// schedule's verdict ("would be blocked") instead of being flattened into
	// "allowed", which hid the fact that a window was active.
	StateLabel string
	StateClass string
	// Budget is this profile's allowance line, empty when it has none.
	Budget string
	// Observed is what the profile's devices actually sent in the last
	// accounting interval, shown for EVERY profile including unbudgeted ones.
	//
	// It is on the page because the activity threshold's default is an
	// unvalidated guess and ADR 0001 requires it to be calibrated against real
	// idle household devices. This is the calibration surface: leave a device
	// alone, read what it sends, set the threshold above it.
	Observed string
}

// Drifted reports a disagreement between the firewall and the schedule.
//
// A profile with NO devices can never drift: there is no MAC to block, so
// "should be blocked" is satisfied vacuously. Reporting drift there was a real
// bug, and an alarming one, since a freshly created profile always tripped it
// before any device had been assigned.
func (p ProfileView) Drifted() bool {
	if len(p.Devices) == 0 {
		return false
	}
	if p.ManuallyBlocked != p.ManualEnforced {
		// Right answer, wrong reason. A profile a parent blocked indefinitely,
		// which the firewall is only holding down with a bedtime window, comes
		// back online at 08:00 while the page says it is blocked until lifted.
		return true
	}
	return p.Partial || p.Blocked != p.ShouldBeBlocked
}

// profileViews joins intent (the schedule, and the parent's stored decision)
// with truth (what the firewall is doing to packets right now).
func (s *Server) profileViews(now time.Time) ([]ProfileView, error) {
	ps, err := s.schedule.Load()
	if err != nil {
		return nil, err
	}
	reg, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	fw, err := s.readFirewall()
	if err != nil {
		return nil, err
	}
	manualIntent, err := s.core.ManuallyBlocked()
	if err != nil {
		return nil, err
	}
	budgets, err := s.core.BudgetStatus()
	if err != nil {
		return nil, err
	}
	interval := s.core.AccountingInterval()
	name := map[string]string{}
	for _, d := range reg.Devices {
		name[d.MAC] = d.Name
	}

	out := make([]ProfileView, 0, len(ps.Profiles))
	for _, p := range ps.Profiles {
		v := ProfileView{Name: p.Name, ManuallyBlocked: manualIntent[p.Name]}
		for _, w := range p.Windows {
			v.Windows = append(v.Windows, w.Describe())
		}
		left, hasTicket := fw.ticketLeft(p.Devices)
		if hasTicket {
			v.TicketLeft = humanDuration(left)
		}
		windowActive := p.BlockedAt(now)
		overBudget := budgets[p.Name].Blocked
		// What SHOULD be true, as the reason set of ADR 0006 computes it: a
		// manual block on its own is enough, and a schedule or BUDGET block is
		// overridden by a live ticket. A manual block is NOT, which is the rule
		// that stops a child ticketing their way out of being grounded.
		//
		// The budget belongs in this expression for the same reason it belongs
		// in the chain's blocked set: leaving it out would make every spent
		// allowance render as DRIFT, so the page would cry wolf about the one
		// thing it exists to report honestly.
		v.ShouldBeBlocked = v.ManuallyBlocked || ((windowActive || overBudget) && !hasTicket)

		blockedCount := 0
		byReason := map[string]int{}
		for _, m := range p.Devices {
			allowed, reason := fw.verdict(m)
			v.Devices = append(v.Devices, DeviceView{MAC: m, Name: name[m], Allowed: allowed})
			byReason[reason]++
			if !allowed {
				blockedCount++
			}
		}
		sort.Slice(v.Devices, func(i, j int) bool { return v.Devices[i].MAC < v.Devices[j].MAC })
		// Blocked means EVERY device is blocked. Counting "any" would let a
		// half-enforced bedtime read as enforced, which is a child online on
		// their second device.
		v.Blocked = len(p.Devices) > 0 && blockedCount == len(p.Devices)
		v.Partial = blockedCount > 0 && blockedCount < len(p.Devices)
		// Whether the FIREWALL, not the state file, is enforcing each kind of
		// block on every one of the profile's devices.
		allManual := len(p.Devices) > 0 && byReason[contract.ReasonManual] == len(p.Devices)
		allTicketed := len(p.Devices) > 0 && byReason[contract.ReasonTicket] == len(p.Devices)
		v.ManualEnforced = allManual

		v.Budget, v.Observed = budgetLines(budgets[p.Name], interval)

		v.NeedsDevices = len(p.Devices) == 0
		switch {
		case v.NeedsDevices && len(p.Windows) > 0:
			v.Warning = fmt.Sprintf("no devices assigned, so these %d window(s) block nothing",
				len(p.Windows))
		case v.NeedsDevices:
			v.Warning = "no devices assigned, and no windows yet"
		}

		switch {
		case len(p.Devices) == 0:
			// No reason line: the badge and the warning already say it, and a
			// third phrasing of the same fact is noise.
			v.Reason = ""
		case v.Partial:
			v.Reason = fmt.Sprintf("only %d of %d devices are blocked", blockedCount, len(p.Devices))
		// The disagreements come FIRST. They are what the badge shows when a
		// profile has drifted, so a descriptive line reaching the badge ahead of
		// them would replace the warning with a reassurance.
		case v.ManuallyBlocked && !v.ManualEnforced:
			v.Reason = "you blocked this, but the firewall is not enforcing that block"
		case !v.ManuallyBlocked && v.ManualEnforced:
			v.Reason = "the firewall is blocking this by hand, but no decision here says so"
		case v.Blocked && !v.ShouldBeBlocked:
			v.Reason = "blocked, but nothing says it should be"
		case !v.Blocked && v.ShouldBeBlocked:
			v.Reason = "should be blocked right now, but is not"
		// The rest read alongside the badge, which already names the state, so
		// each says something the badge does not.
		case allManual && windowActive:
			v.Reason = "and inside a blocked window, so unblocking leaves them blocked"
		case allManual:
			v.Reason = "until you unblock them"
		case v.Blocked && overBudget:
			// Named before the generic window case, because "inside a blocked
			// window" is a plainly wrong explanation for a child who is offline
			// because they used up their afternoon. Both reasons are reported
			// when both are live: ADR 0006 chose a reason SET precisely so a
			// page can say "bedtime, and over budget" rather than pick one.
			v.Reason = string(budgets[p.Name].Reason)
			if left := budgets[p.Name].CooldownLeft; left > 0 {
				v.Reason += ", back in " + humanDuration(left)
			}
			if windowActive {
				v.Reason = "inside a blocked window, and " + v.Reason
			}
		case allTicketed && windowActive:
			v.Reason = "then the window takes over again"
		case allTicketed:
			v.Reason = "nothing else is blocking them right now"
		case v.Blocked && windowActive:
			v.Reason = "inside a blocked window"
		case len(p.Windows) == 0:
			v.Reason = "no schedule"
		default:
			v.Reason = "outside every window"
		}
		// The badge. An empty profile reports what the schedule WOULD do, since
		// saying "allowed" there concealed an active window.
		switch {
		case v.Drifted():
			v.StateClass, v.StateLabel = "drift", v.Reason
		case v.NeedsDevices && v.ShouldBeBlocked:
			v.StateClass, v.StateLabel = "idle", "no devices, would be blocked"
		case v.NeedsDevices:
			v.StateClass, v.StateLabel = "idle", "no devices, would be allowed"
		case v.Blocked && overBudget && !allManual:
			v.StateClass, v.StateLabel = "off", string(budgets[p.Name].Reason)
		case v.Blocked && allManual:
			v.StateClass, v.StateLabel = "off", "blocked by you"
		case v.Blocked:
			v.StateClass, v.StateLabel = "off", "blocked"
		case allTicketed:
			v.StateClass, v.StateLabel = "on", "ticket: "+v.TicketLeft+" left"
		default:
			v.StateClass, v.StateLabel = "on", "allowed"
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	views, err := s.profileViews(time.Now().In(s.loc))
	if err != nil {
		s.log.Error("rendering home", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	unassigned, err := s.unassignedDevices()
	if err != nil {
		s.log.Error("rendering home", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := homeData{
		Profiles:   views,
		Unassigned: unassigned,
		Now:        time.Now().In(s.loc).Format("Mon 15:04 MST"),
		Zone:       s.loc.String(),
		Error:      r.URL.Query().Get("error"),
		AllDays:    schedule.AllDays,
		Tickets:    ticketChoices(),
	}
	s.render(w, homeTemplate, data, "home")
}

// unassignedDevices are registered devices in no profile. They are always
// allowed, and naming them here stops "why is this child not blocked?" being
// a mystery when the answer is that their device is in no profile.
func (s *Server) unassignedDevices() ([]DeviceView, error) {
	reg, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	ps, err := s.schedule.Load()
	if err != nil {
		return nil, err
	}
	inProfile := map[string]bool{}
	for _, p := range ps.Profiles {
		for _, m := range p.Devices {
			inProfile[m] = true
		}
	}
	var out []DeviceView
	for _, d := range reg.Devices {
		if !inProfile[d.MAC] {
			out = append(out, DeviceView{MAC: d.MAC, Name: d.Name})
		}
	}
	return out, nil
}

func redirectHome(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Redirect(w, r, "/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// mutateSchedule loads, applies fn, validates and saves. Every schedule change
// goes through here so none of them can skip validation and leave a schedule
// nobody can predict.
func (s *Server) mutateSchedule(fn func(*schedule.Profiles) error) error {
	ps, err := s.schedule.Load()
	if err != nil {
		return err
	}
	if err := fn(ps); err != nil {
		return err
	}
	if err := s.schedule.Save(ps); err != nil {
		return err
	}
	// Apply it NOW. Waiting for the next tick leaves the page honestly but
	// alarmingly reporting "should be blocked right now, but is not" for up to
	// a minute after you press the button.
	if err := s.core.Reconcile(); err != nil {
		return fmt.Errorf("saved, but the firewall was NOT updated: %w", err)
	}
	return nil
}

// handleProfileBlock turns a profile off until a parent turns it back on.
func (s *Server) handleProfileBlock(w http.ResponseWriter, r *http.Request) {
	name, ok := s.postedProfile(w, r)
	if !ok {
		return
	}
	redirectHome(w, r, s.core.Block(name))
}

// handleProfileUnblock lifts that decision, and only that decision. A profile
// inside its bedtime window stays blocked, because the schedule reason is
// still live (ADR 0006).
func (s *Server) handleProfileUnblock(w http.ResponseWriter, r *http.Request) {
	name, ok := s.postedProfile(w, r)
	if !ok {
		return
	}
	redirectHome(w, r, s.core.Unblock(name))
}

// handleProfileTicket grants a time-limited pass.
//
// It is one call that grants exactly one thing. Giving a manually blocked
// child time is deliberately TWO taps here, unblock and then ticket, and the
// core refuses the fused version: fusing them would mean a parent who wanted
// thirty minutes silently cancelled an indefinite block as well.
func (s *Server) handleProfileTicket(w http.ResponseWriter, r *http.Request) {
	name, ok := s.postedProfile(w, r)
	if !ok {
		return
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(r.FormValue("minutes")))
	if err != nil || minutes <= 0 {
		redirectHome(w, r, fmt.Errorf("a ticket needs a duration in whole minutes, got %q",
			r.FormValue("minutes")))
		return
	}
	redirectHome(w, r, s.core.GrantTicket(name, time.Duration(minutes)*time.Minute))
}

// postedProfile enforces POST and pulls the profile name out of the form.
func (s *Server) postedProfile(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return "", false
	}
	return r.FormValue("name"), true
}

func (s *Server) handleProfileCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		if name == "" {
			return fmt.Errorf("a profile needs a name")
		}
		if _, exists := ps.Find(name); exists {
			return fmt.Errorf("a profile called %q already exists", name)
		}
		ps.Profiles = append(ps.Profiles, schedule.Profile{
			Name: name, Devices: []string{}, Windows: []schedule.Window{},
		})
		return nil
	})
	if err == nil {
		s.log.Info("profile created", "name", name)
	}
	redirectHome(w, r, err)
}

func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
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
	// Lift any manual block FIRST, while the profile still exists. Otherwise
	// the persisted decision outlives the thing it was about, and a profile
	// later recreated under the same name would come back mysteriously
	// blocked by a parent who does not remember doing it.
	if err := s.core.Unblock(name); err != nil {
		redirectHome(w, r, err)
		return
	}
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		for i := range ps.Profiles {
			if ps.Profiles[i].Name == name {
				ps.Profiles = append(ps.Profiles[:i], ps.Profiles[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no profile called %q", name)
	})
	if err == nil {
		// Deleting a profile releases its devices, so the next reconcile lifts
		// their block. That is the intended reading of "this group no longer
		// has a schedule", and it happens within a tick rather than silently.
		s.log.Info("profile deleted", "name", name)
	}
	redirectHome(w, r, err)
}

// handleProfileDevices sets a profile's device membership from the checkboxes.
func (s *Server) handleProfileDevices(w http.ResponseWriter, r *http.Request) {
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
	macs := r.Form["mac"]
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		p, ok := ps.Find(name)
		if !ok {
			return fmt.Errorf("no profile called %q", name)
		}
		clean := make([]string, 0, len(macs))
		for _, m := range macs {
			clean = append(clean, strings.ToLower(strings.TrimSpace(m)))
		}
		sort.Strings(clean)
		p.Devices = clean
		return nil
	})
	if err == nil {
		s.log.Info("profile membership changed", "name", name, "devices", len(macs))
	}
	redirectHome(w, r, err)
}

func (s *Server) handleWindowAdd(w http.ResponseWriter, r *http.Request) {
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
			redirectHome(w, r, err)
			return
		}
		days = append(days, parsed)
	}
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		p, ok := ps.Find(name)
		if !ok {
			return fmt.Errorf("no profile called %q", name)
		}
		win := schedule.Window{Days: days, Start: start, End: end}
		// Validate before appending, so a rejected window never reaches the
		// file and the error names the actual problem.
		if err := win.Validate(); err != nil {
			return err
		}
		p.Windows = append(p.Windows, win)
		return nil
	})
	if err == nil {
		s.log.Info("window added", "profile", name, "start", start, "end", end, "days", len(days))
	}
	redirectHome(w, r, err)
}

func (s *Server) handleWindowRemove(w http.ResponseWriter, r *http.Request) {
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
		if _, scanErr := fmt.Sscanf(idx, "%d", &i); scanErr != nil || i < 0 || i >= len(p.Windows) {
			return fmt.Errorf("no such window")
		}
		p.Windows = append(p.Windows[:i], p.Windows[i+1:]...)
		return nil
	})
	if err == nil {
		s.log.Info("window removed", "profile", name)
	}
	redirectHome(w, r, err)
}

type homeData struct {
	Profiles   []ProfileView
	Unassigned []DeviceView
	Now        string
	Zone       string
	Error      string
	AllDays    []schedule.Day
	Tickets    []ticketChoice
}

// ticketChoice is one duration button.
type ticketChoice struct {
	Minutes int
	Label   string
}

func ticketChoices() []ticketChoice {
	out := make([]ticketChoice, 0, len(ticketDurations))
	for _, d := range ticketDurations {
		out = append(out, ticketChoice{Minutes: int(d.Minutes()), Label: humanDuration(d)})
	}
	return out
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>curfew</title>
<style>
 body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; max-width: 44rem; }
 h1 { font-size: 1.3rem; margin-bottom: .2rem; }
 h2 { font-size: 1.05rem; margin: 0; }
 .now { color: #666; font-size: .85rem; margin-bottom: 1.2rem; }
 .profile { border: 1px solid #ddd; border-radius: .5rem; padding: .8rem; margin-bottom: 1rem; }
 .head { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
 .state { font-weight: 600; padding: .1rem .5rem; border-radius: .3rem; font-size: .85rem; }
 .off { background: #fdecea; color: #b00020; }
 .on  { background: #e7f6ec; color: #0a7d28; }
 .drift { background: #fff4e5; color: #8a5300; border: 1px solid #f0c48a; }
 .idle { background: #eef2f7; color: #33506e; border: 1px solid #c9d6e4; }
 .warnline { background: #fff4e5; color: #8a5300; border: 1px solid #f0c48a;
             border-radius: .3rem; padding: .35rem .5rem; margin-top: .5rem; font-size: .85rem; }
 .muted { color: #666; font-size: .85rem; }
 ul { margin: .5rem 0; padding-left: 1.1rem; }
 li { font-size: .9rem; margin-bottom: .2rem; }
 code { font-family: ui-monospace, monospace; font-size: .85rem; }
 form { margin: 0; }
 .row { display: flex; gap: .3rem; flex-wrap: wrap; align-items: center; margin-top: .4rem; }
 input[type=time], input[type=text] { padding: .35rem; font-size: .9rem; }
 button { padding: .35rem .6rem; font-size: .85rem; }
 .danger { color: #b00020; }
 .actions { display: flex; gap: .4rem; flex-wrap: wrap; align-items: center;
            margin-top: .6rem; padding-top: .6rem; border-top: 1px dashed #e2e2e2; }
 .actions form { display: inline; }
 .block { padding: .45rem .8rem; font-weight: 600; color: #b00020; border: 1px solid #f0b6bd;
          background: #fdecea; border-radius: .3rem; }
 .unblock { padding: .45rem .8rem; font-weight: 600; color: #0a7d28; border: 1px solid #a9dcb9;
            background: #e7f6ec; border-radius: .3rem; }
 .tickets { display: flex; gap: .3rem; flex-wrap: wrap; align-items: center; margin-top: .5rem; }
 .tickets button { padding: .45rem .7rem; }
 .days label { font-size: .8rem; margin-right: .4rem; white-space: nowrap; }
 .err { background: #fdecea; color: #b00020; padding: .6rem; margin-bottom: 1rem; }
 details { margin-top: .6rem; }
 summary { font-size: .85rem; cursor: pointer; color: #333; }
</style>
</head>
<body>
<h1>curfew</h1>
<div class="now">{{.Now}} ({{.Zone}}) &middot; <a href="/devices/">all devices</a></div>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

{{range $p := .Profiles}}
<div class="profile">
  <div class="head">
    <h2>{{.Name}}</h2>
    <span class="state {{.StateClass}}">{{.StateLabel}}</span>
    <span class="muted">{{if not .Drifted}}{{.Reason}}{{end}}</span>
  </div>
  {{if .NeedsDevices}}<div class="warnline">{{.Warning}}</div>{{end}}
  {{if .Budget}}<div class="muted">budget: {{.Budget}}</div>{{end}}
  {{if .Observed}}<div class="muted">{{.Observed}}</div>{{end}}

  <div class="actions">
    {{if .ManuallyBlocked}}
      <form method="POST" action="/profiles/unblock">
        <input type="hidden" name="name" value="{{.Name}}">
        <button type="submit" class="unblock">unblock {{.Name}}</button>
      </form>
      <span class="muted">off until you lift it. Lifting it leaves any bedtime window in force.</span>
    {{else}}
      <form method="POST" action="/profiles/block">
        <input type="hidden" name="name" value="{{.Name}}">
        <button type="submit" class="block">block {{.Name}}</button>
      </form>
      <span class="muted">off until you say otherwise. Cancels any ticket.</span>
    {{end}}
  </div>

  {{if .ManuallyBlocked}}
  <div class="muted" style="margin-top:.5rem">Unblock first to give {{.Name}} time:
    a ticket cannot lift a block you imposed.</div>
  {{else}}
  <div class="tickets">
    <span class="muted">give time:</span>
    {{range $.Tickets}}
    <form method="POST" action="/profiles/ticket">
      <input type="hidden" name="name" value="{{$p.Name}}">
      <input type="hidden" name="minutes" value="{{.Minutes}}">
      <button type="submit">{{.Label}}</button>
    </form>
    {{end}}
    {{if $p.TicketLeft}}<span class="muted">{{$p.TicketLeft}} left; tapping again adds a fresh ticket</span>{{end}}
  </div>
  {{end}}

  <ul>
  {{range $i, $w := .Windows}}
    <li>{{$w}}
      <form method="POST" action="/profiles/window/remove" style="display:inline">
        <input type="hidden" name="name" value="{{$p.Name}}">
        <input type="hidden" name="index" value="{{$i}}">
        <button type="submit" class="danger">remove</button>
      </form>
    </li>
  {{else}}
    <li class="muted">no blocked windows: always allowed</li>
  {{end}}
  </ul>

  <details>
    <summary>add a blocked window</summary>
    <form method="POST" action="/profiles/window/add">
      <input type="hidden" name="name" value="{{.Name}}">
      <div class="row days">
        {{range $.AllDays}}<label><input type="checkbox" name="day" value="{{.}}" checked>{{.}}</label>{{end}}
      </div>
      <div class="row">
        from <input type="time" name="start" value="22:00" required>
        to <input type="time" name="end" value="08:00" required>
        <button type="submit">add</button>
      </div>
      <div class="muted">An end earlier than the start runs overnight, and belongs to the day it starts on.</div>
    </form>
  </details>

  <details>
    <summary>devices in this profile ({{len .Devices}})</summary>
    <form method="POST" action="/profiles/devices">
      <input type="hidden" name="name" value="{{.Name}}">
      {{range .Devices}}
      <div><label><input type="checkbox" name="mac" value="{{.MAC}}" checked>
        {{if .Name}}{{.Name}}{{else}}<span class="muted">unnamed</span>{{end}}
        <code>{{.MAC}}</code></label></div>
      {{end}}
      {{range $.Unassigned}}
      <div><label><input type="checkbox" name="mac" value="{{.MAC}}">
        {{if .Name}}{{.Name}}{{else}}<span class="muted">unnamed</span>{{end}}
        <code>{{.MAC}}</code> <span class="muted">(in no profile)</span></label></div>
      {{end}}
      <div class="row"><button type="submit">save membership</button></div>
    </form>
  </details>

  <details>
    <summary class="danger">delete this profile</summary>
    <form method="POST" action="/profiles/delete"
          onsubmit="return confirm('Delete {{.Name}}? Its devices go back to being always allowed.')">
      <input type="hidden" name="name" value="{{.Name}}">
      <div class="row"><button type="submit" class="danger">delete {{.Name}}</button></div>
    </form>
  </details>
</div>
{{else}}
<p class="muted">No profiles yet. A device in no profile is always allowed.</p>
{{end}}

<div class="profile">
  <h2 style="font-size:.95rem">New profile</h2>
  <form method="POST" action="/profiles/create">
    <div class="row">
      <input type="text" name="name" placeholder="eli" required autocapitalize="none" autocomplete="off">
      <button type="submit">create</button>
    </div>
  </form>
</div>

{{if .Unassigned}}
<p class="muted">{{len .Unassigned}} registered device(s) are in no profile, so they are always allowed.</p>
{{end}}
<p class="muted">Blocked/allowed is read from the firewall itself. If it ever disagrees with
the schedule, this page says so rather than showing you what it hoped.</p>
<p class="muted">A block you impose outranks a ticket, so a ticket cannot undo it, and
blocking cancels any ticket already running. To end a ticket early, block and then unblock.
Tickets are held by the kernel and are gone after a reboot; a block you impose is not.</p>
</body>
</html>
`))
