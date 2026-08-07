package httpui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/schedule"
)

// The settings page owns everything that CONFIGURES the household: schedules,
// profile membership, budgets, and the two household budget knobs.
//
// It is a separate page from the home one because the two are used at
// different moments and by different urgency. The home page is what a parent
// opens on their phone to answer "is this child online, and can I give them
// twenty minutes?", and every extra control on it is something to scroll past
// while a child waits. Configuration is a sit-down job done rarely. Mixing
// them made the common case the harder one.
//
// Everything here redirects back HERE rather than home, so an edit leaves you
// where you were editing.

// budgetFields are the four per-profile limits as a form would carry them.
// Strings rather than durations, so a rejected value can be shown back to the
// person who typed it instead of being silently reset to zero.
type budgetFields struct {
	Daily      string
	Continuous string
	Gap        string
	ResetGap   string
}

// SettingsProfile is one profile's row on the settings page.
type SettingsProfile struct {
	Name    string
	Devices []DeviceView
	Windows []string
	Budget  budgetFields
	// Observed is what this profile's devices actually sent in the last
	// accounting interval. It sits on THIS page, next to the threshold field,
	// because that is the only place the number is actionable: it exists so
	// the activity threshold can be calibrated against real devices rather
	// than left at the guess it ships with.
	Observed string
}

type settingsData struct {
	Profiles   []SettingsProfile
	Unassigned []DeviceView
	Now        string
	Zone       string
	Error      string
	Saved      string
	AllDays    []schedule.Day
	// ResetTime and Threshold are the household knobs.
	ResetTime string
	// ThresholdKB is the activity threshold in KIBIBYTES per minute, because
	// nobody wants to type 51200. The stored value stays in bytes.
	ThresholdKB string
	// ThresholdIsDefault drives the warning. The default is an UNVALIDATED
	// GUESS (ADR 0001 requires calibration against real idle devices), and a
	// page that presented it as a settled number would be the single most
	// likely thing to make this feature feel arbitrary in a house.
	ThresholdIsDefault bool
	// AccountingOff is true when no accountant is wired up, in which case no
	// observed figure exists and saying nothing beats showing zeros.
	AccountingOff bool
}

func (s *Server) settingsProfiles() ([]SettingsProfile, error) {
	ps, err := s.schedule.Load()
	if err != nil {
		return nil, err
	}
	reg, err := s.store.Load()
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
	out := make([]SettingsProfile, 0, len(ps.Profiles))
	for _, p := range ps.Profiles {
		v := SettingsProfile{Name: p.Name, Budget: budgetFields{
			Daily:      p.Budget.Daily.Form(),
			Continuous: p.Budget.Continuous.Form(),
			Gap:        p.Budget.Gap.Form(),
			ResetGap:   p.Budget.ResetGap.Form(),
		}}
		for _, w := range p.Windows {
			v.Windows = append(v.Windows, w.Describe())
		}
		for _, m := range p.Devices {
			v.Devices = append(v.Devices, DeviceView{MAC: m, Name: name[m]})
		}
		_, v.Observed = budgetLines(budgets[p.Name], interval)
		out = append(out, v)
	}
	// Sorted by name, the same as the home page. Two pages listing the same
	// household in two different orders is a small thing that makes a parent
	// check twice that they are editing the right child.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profiles, err := s.settingsProfiles()
	if err != nil {
		s.log.Error("rendering settings", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	unassigned, err := s.unassignedDevices()
	if err != nil {
		s.log.Error("rendering settings", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	ps, err := s.schedule.Load()
	if err != nil {
		s.log.Error("rendering settings", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	interval := s.core.AccountingInterval()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.render(w, settingsTemplate, settingsData{
		Profiles:           profiles,
		Unassigned:         unassigned,
		Now:                time.Now().In(s.loc).Format("Mon 15:04 MST"),
		Zone:               s.loc.String(),
		Error:              r.URL.Query().Get("error"),
		Saved:              r.URL.Query().Get("saved"),
		AllDays:            schedule.AllDays,
		ResetTime:          ps.Budget.ResetTime,
		ThresholdKB:        strconv.FormatUint(ps.Budget.Threshold()/1024, 10),
		ThresholdIsDefault: ps.Budget.ActivityThresholdBytesPerMinute == 0,
		AccountingOff:      interval == 0,
	}, "settings")
}

// handleProfileBudget sets one profile's four limits.
//
// All four are submitted together, and clearing a box clears that limit, so
// the form can express "unlimited" as well as any combination the validator
// allows. Submitting them one at a time would make the group rule
// (continuous, gap and reset_gap are all or none) impossible to satisfy
// without passing through an invalid state.
func (s *Server) handleProfileBudget(w http.ResponseWriter, r *http.Request) {
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
	var limits budget.Limits
	for _, f := range []struct {
		field string
		into  *budget.Duration
	}{
		{"daily", &limits.Daily},
		{"continuous", &limits.Continuous},
		{"gap", &limits.Gap},
		{"reset_gap", &limits.ResetGap},
	} {
		v, err := budget.ParseDuration(r.FormValue(f.field))
		if err != nil {
			redirectSettings(w, r, fmt.Errorf("%s: %w", f.field, err))
			return
		}
		*f.into = v
	}
	// Validated BEFORE it reaches the file, so a set of limits that would be
	// inert or perverse is refused with a message naming the field rather than
	// saved and discovered at the next daemon start.
	if err := limits.Validate(); err != nil {
		redirectSettings(w, r, err)
		return
	}
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		p, ok := ps.Find(name)
		if !ok {
			return fmt.Errorf("no profile called %q", name)
		}
		p.Budget = limits
		return nil
	})
	if err == nil {
		s.log.Info("budget changed", "profile", name, "daily", limits.Daily.String(),
			"continuous", limits.Continuous.String())
		redirectSaved(w, r, "budget for "+name+" saved")
		return
	}
	redirectSettings(w, r, err)
}

// handleBudgetSettings sets the two HOUSEHOLD knobs: when the day rolls over,
// and how much traffic counts as use.
func (s *Server) handleBudgetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	reset := strings.TrimSpace(r.FormValue("reset_time"))
	kb := strings.TrimSpace(r.FormValue("threshold_kb"))

	var threshold uint64
	if kb != "" {
		n, err := strconv.ParseUint(kb, 10, 64)
		if err != nil || n == 0 {
			redirectSettings(w, r, fmt.Errorf(
				"the activity threshold must be a whole number of KB per minute, got %q", kb))
			return
		}
		threshold = n * 1024
	}
	settings := budget.Settings{ResetTime: reset, ActivityThresholdBytesPerMinute: threshold}
	if err := settings.Validate(); err != nil {
		redirectSettings(w, r, err)
		return
	}
	err := s.mutateSchedule(func(ps *schedule.Profiles) error {
		ps.Budget = settings
		return nil
	})
	if err == nil {
		s.log.Info("household budget settings changed",
			"reset_time", settings.ResetTime, "threshold_bytes_per_minute", threshold)
		redirectSaved(w, r, "household budget settings saved")
		return
	}
	redirectSettings(w, r, err)
}

var settingsTemplate = template.Must(template.New("settings").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>curfew settings</title>
<style>
` + sharedCSS + `
 .field { display: flex; gap: .4rem; align-items: center; margin-top: .35rem; flex-wrap: wrap; }
 .field label { font-size: .85rem; min-width: 9rem; }
 .field input[type=text] { width: 6rem; }
 .ok { background: #e7f6ec; color: #0a7d28; padding: .6rem; margin-bottom: 1rem;
       border-radius: .3rem; font-size: .9rem; }
 .guess { background: #fff4e5; color: #8a5300; border: 1px solid #f0c48a;
          border-radius: .3rem; padding: .5rem .6rem; margin-top: .5rem; font-size: .85rem; }
</style>
</head>
<body>
<h1>settings</h1>
<div class="now">{{.Now}} ({{.Zone}}) &middot; <a href="/">home</a> &middot;
  <a href="/devices/">all devices</a></div>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Saved}}<div class="ok">{{.Saved}}</div>{{end}}

{{range $p := .Profiles}}
<div class="profile">
  <div class="head"><h2>{{.Name}}</h2></div>

  <details>
    <summary>daily budget</summary>
    <form method="POST" action="/profiles/budget">
      <input type="hidden" name="name" value="{{.Name}}">
      <div class="field">
        <label for="d-{{.Name}}">total per day</label>
        <input id="d-{{.Name}}" type="text" name="daily" value="{{.Budget.Daily}}"
               placeholder="4h" autocapitalize="none" autocomplete="off">
        <span class="muted">blank means unlimited</span>
      </div>
      <div class="field">
        <label for="c-{{.Name}}">one stretch</label>
        <input id="c-{{.Name}}" type="text" name="continuous" value="{{.Budget.Continuous}}"
               placeholder="2h" autocapitalize="none" autocomplete="off">
      </div>
      <div class="field">
        <label for="g-{{.Name}}">a stretch ends after</label>
        <input id="g-{{.Name}}" type="text" name="gap" value="{{.Budget.Gap}}"
               placeholder="10m" autocapitalize="none" autocomplete="off">
        <span class="muted">of not using it</span>
      </div>
      <div class="field">
        <label for="r-{{.Name}}">then wait</label>
        <input id="r-{{.Name}}" type="text" name="reset_gap" value="{{.Budget.ResetGap}}"
               placeholder="30m" autocapitalize="none" autocomplete="off">
        <span class="muted">before using budget again</span>
      </div>
      <div class="muted">Write durations with a unit: 4h, 90m, 2h30m. The last three go
        together: set all of them or none. The wait must not be shorter than the stretch
        gap, or being cut off would be cheaper than stopping.</div>
      {{if .Observed}}<div class="muted">{{.Observed}}</div>{{end}}
      <div class="row"><button type="submit">save budget</button></div>
    </form>
  </details>

  <details>
    <summary>blocked windows ({{len .Windows}})</summary>
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

<div class="profile">
  <h2 style="font-size:.95rem">Budget settings for the whole house</h2>
  <form method="POST" action="/settings/budget">
    <div class="field">
      <label for="reset">the day starts at</label>
      <input id="reset" type="time" name="reset_time" value="{{if .ResetTime}}{{.ResetTime}}{{else}}03:00{{end}}">
      <span class="muted">not midnight: children are awake at midnight</span>
    </div>
    <div class="field">
      <label for="thr">counts as use above</label>
      <input id="thr" type="text" name="threshold_kb" value="{{.ThresholdKB}}"
             inputmode="numeric" autocomplete="off">
      <span class="muted">KB per minute, upstream</span>
    </div>
    {{if .ThresholdIsDefault}}
    <div class="guess">This threshold is the DEFAULT, and it is a guess rather than a
      measurement. Leave the budgets off for an evening, watch the figures under each
      profile above, and set this above what your idle devices send and below what they
      send in use.</div>
    {{end}}
    {{if .AccountingOff}}
    <div class="guess">Accounting is not running, so no figures are being measured.</div>
    {{end}}
    <div class="muted">Only UPSTREAM traffic is counted, because the download direction
      cannot be attributed to a device at this point in the network. Upstream is roughly
      1.4% of what is downloaded, so the numbers are smaller than you expect.</div>
    <div class="row"><button type="submit">save</button></div>
  </form>
</div>
</body>
</html>
`))
