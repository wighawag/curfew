package httpui

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/budget"
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
	// Timing answers the two questions a parent has with a child in front of
	// them: when does this end, and when does the next one start. Empty when
	// there is no answer, which is honest: a manual block ends when a parent
	// says so, and a profile with no windows has no next block.
	Timing string
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

		v.Timing = timingLine(p, budgets[p.Name], v.ManuallyBlocked, windowActive, now)
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
		Profiles:         views,
		UnassignedCount:  len(unassigned),
		Now:              time.Now().In(s.loc).Format("Mon 15:04 MST"),
		Zone:             s.loc.String(),
		Error:            r.URL.Query().Get("error"),
		Tickets:          ticketChoices(),
		MaxTicketMinutes: int(s.core.MaxTicket().Minutes()),
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
	redirectSettings(w, r, err)
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
		redirectSettings(w, r, err)
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
	redirectSettings(w, r, err)
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
	redirectSettings(w, r, err)
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
			redirectSettings(w, r, err)
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
	redirectSettings(w, r, err)
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
	redirectSettings(w, r, err)
}

type homeData struct {
	Profiles []ProfileView
	Now      string
	Zone     string
	Error    string
	Tickets  []ticketChoice
	// MaxTicketMinutes bounds the custom-duration box, so the commonest way to
	// get the error is prevented by the form rather than explained after the
	// fact. The core enforces the same cap regardless; this is a courtesy, not
	// the control.
	MaxTicketMinutes int
	// Unassigned devices belong to no profile and are therefore always
	// allowed. Only the COUNT is shown here, as a one-line warning, because
	// "why is this child not blocked?" is a home-page question even though
	// fixing it is a settings-page job.
	UnassignedCount int
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

// timingLine says when the current block lifts, or when the next one lands.
//
// It exists because a window list is not an answer. "22:00 to 08:00, every
// day" makes a parent do the arithmetic at the moment they least want to, and
// a cooldown had no visible end at all: the page said "nothing else is blocking
// them right now" while a budget cooldown was very much still running, which
// is precisely the reassuring half-truth this project exists to remove.
//
// Everything here is DERIVED from the clock on each render, so nothing can go
// stale and nothing is scheduled.
func timingLine(p schedule.Profile, b budget.Status, manuallyBlocked, windowActive bool,
	now time.Time) string {

	if manuallyBlocked {
		// No time to give, and inventing one would be a lie: it lifts when a
		// parent lifts it.
		return "blocked until you unblock it"
	}
	// A live cooldown is reported even when a ticket is currently overriding
	// it, because it is what the child falls back to when the ticket lapses.
	if b.CooldownLeft > 0 {
		return fmt.Sprintf("stretch used up; next allowed at %s (in %s)",
			now.Add(b.CooldownLeft).Format("15:04"), humanDuration(b.CooldownLeft))
	}
	if b.Blocked && b.Reason == budget.ReasonDaily {
		return "daily allowance spent; back when the day resets"
	}
	when, willBlock, ok := p.NextChange(now)
	if !ok {
		return ""
	}
	at := when.Format("15:04")
	// The weekday appears only when the moment is genuinely far off. Keying
	// on "a different calendar day" instead reads "blocked until Tue 08:00"
	// for an ordinary overnight bedtime, which is noise eight hours before it
	// happens; but a weekday-only window seen on a Saturday really does need
	// to say Monday.
	if when.Sub(now) > 18*time.Hour {
		at = when.Format("Mon 15:04")
	}
	if windowActive && !willBlock {
		return fmt.Sprintf("blocked until %s", at)
	}
	if !windowActive && willBlock {
		return fmt.Sprintf("next blocked at %s", at)
	}
	return ""
}
