package httpui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/schedule"
)

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
	// ShouldBeBlocked is what the schedule says SHOULD be true. When the two
	// disagree the page says so, because that gap is the entire failure this
	// project exists to make visible rather than hide.
	ShouldBeBlocked bool
	Reason          string
	// NeedsDevices flags a profile with no devices. It is a warning rather
	// than a neutral state because a schedule with nothing to apply it to
	// enforces nothing while looking configured, which is the shape of every
	// failure this project exists to surface. Shown whether or not a window
	// happens to be active right now.
	NeedsDevices bool
	// Warning is the text for that, phrased for the case at hand.
	Warning string
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
	return p.Partial || p.Blocked != p.ShouldBeBlocked
}

// profileViews joins the schedule (intent) with the firewall (truth).
func (s *Server) profileViews(now time.Time) ([]ProfileView, error) {
	ps, err := s.schedule.Load()
	if err != nil {
		return nil, err
	}
	reg, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	blockedNow, err := s.firewall.Blocked()
	if err != nil {
		return nil, err
	}
	allowedNow, err := s.firewall.Allowlist()
	if err != nil {
		return nil, err
	}
	isBlocked := map[string]bool{}
	for _, m := range blockedNow {
		isBlocked[m] = true
	}
	isAllowed := map[string]bool{}
	for _, m := range allowedNow {
		isAllowed[m] = true
	}
	name := map[string]string{}
	for _, d := range reg.Devices {
		name[d.MAC] = d.Name
	}

	out := make([]ProfileView, 0, len(ps.Profiles))
	for _, p := range ps.Profiles {
		v := ProfileView{Name: p.Name, ShouldBeBlocked: p.BlockedAt(now)}
		for _, w := range p.Windows {
			v.Windows = append(v.Windows, w.Describe())
		}
		blockedCount := 0
		for _, m := range p.Devices {
			v.Devices = append(v.Devices, DeviceView{
				MAC: m, Name: name[m], Allowed: isAllowed[m] && !isBlocked[m],
			})
			if isBlocked[m] {
				blockedCount++
			}
		}
		sort.Slice(v.Devices, func(i, j int) bool { return v.Devices[i].MAC < v.Devices[j].MAC })
		// Blocked means EVERY device is blocked. Counting "any" would let a
		// half-enforced bedtime read as enforced, which is a child online on
		// their second device.
		v.Blocked = len(p.Devices) > 0 && blockedCount == len(p.Devices)
		v.Partial = blockedCount > 0 && blockedCount < len(p.Devices)

		v.NeedsDevices = len(p.Devices) == 0
		switch {
		case v.NeedsDevices && len(p.Windows) > 0:
			v.Warning = fmt.Sprintf("no devices assigned, so these %d window(s) block nothing",
				len(p.Windows))
		case v.NeedsDevices:
			v.Warning = "no devices assigned, and no windows yet"
		}

		switch {
		case len(p.Devices) == 0 && v.ShouldBeBlocked:
			v.Reason = "not blocked: there are no devices in this profile"
		case len(p.Devices) == 0:
			v.Reason = "not blocked: there are no devices in this profile"
		case v.Partial:
			v.Reason = fmt.Sprintf("only %d of %d devices are blocked", blockedCount, len(p.Devices))
		case v.Blocked && v.ShouldBeBlocked:
			v.Reason = "inside a blocked window"
		case v.Blocked && !v.ShouldBeBlocked:
			v.Reason = "blocked, but no window says it should be"
		case !v.Blocked && v.ShouldBeBlocked:
			v.Reason = "should be blocked right now, but is not"
		case len(p.Windows) == 0:
			v.Reason = "no schedule"
		default:
			v.Reason = "outside every window"
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
	if err := s.reconcile(); err != nil {
		return fmt.Errorf("saved, but the firewall was NOT updated: %w", err)
	}
	return nil
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
    {{if .Drifted}}
      <span class="state drift">{{.Reason}}</span>
    {{else if .Blocked}}
      <span class="state off">blocked</span>
    {{else}}
      <span class="state on">allowed</span>
    {{end}}
    <span class="muted">{{if not .Drifted}}{{.Reason}}{{end}}</span>
  </div>
  {{if .NeedsDevices}}<div class="warnline">{{.Warning}}</div>{{end}}

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
</body>
</html>
`))
