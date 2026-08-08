package httpui

import (
	"html/template"
	"net/http"
)

// The two pages this system serves, and the split between them.
//
// The HOME page answers two questions, one-handed, on a phone, while a child
// waits: is this child online, and can I give them twenty minutes? It is
// deliberately small, because every additional control on it is something to
// scroll past at the moment it is least welcome.
//
// The SETTINGS page (internal/httpui/settings.go) owns everything that
// CONFIGURES the household: schedules, membership, budgets, and the two
// household budget knobs. That is a sit-down job done rarely, and mixing it
// into the home page made the common case the harder one.
//
// They share their stylesheet so the second page cannot drift into looking
// like a different application.

// sharedCSS is used by both pages.
const sharedCSS = `
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
 .row { display: flex; gap: .3rem; flex-wrap: wrap; align-items: center; margin-top: .4rem; }
 input[type=time], input[type=text], input[type=number] { padding: .35rem; font-size: .9rem; }
 button { padding: .35rem .6rem; font-size: .85rem; }
 .danger { color: #b00020; }
 .block { padding: .45rem .8rem; font-weight: 600; color: #b00020; border: 1px solid #f0b6bd;
          background: #fdecea; border-radius: .3rem; }
 .unblock { padding: .45rem .8rem; font-weight: 600; color: #0a7d28; border: 1px solid #a9dcb9;
            background: #e7f6ec; border-radius: .3rem; }
 .tickets { display: flex; gap: .3rem; flex-wrap: wrap; align-items: center; margin-top: .6rem; }
 .tickets button { padding: .45rem .7rem; }
 .tickets form { display: inline; }
 .days label { font-size: .8rem; margin-right: .4rem; white-space: nowrap; }
 .err { background: #fdecea; color: #b00020; padding: .6rem; margin-bottom: 1rem; }
 details { margin-top: .6rem; }
 summary { font-size: .85rem; cursor: pointer; color: #333; }
`

// redirectTo sends the browser somewhere after a POST, carrying any error in
// the query string so the destination page can show it.
//
// Every mutating handler redirects rather than rendering, so a refresh cannot
// repeat a block, a ticket or a delete. Which page it lands on is the
// handler's choice: an action taken on the home page comes back home, and an
// edit made in settings comes back to settings, so neither loses your place.
func redirectTo(w http.ResponseWriter, r *http.Request, path string, err error) {
	if err != nil {
		http.Redirect(w, r, path+"?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func redirectHome(w http.ResponseWriter, r *http.Request, err error) {
	redirectTo(w, r, "/", err)
}

func redirectSettings(w http.ResponseWriter, r *http.Request, err error) {
	redirectTo(w, r, "/settings", err)
}

// redirectSaved confirms a settings edit landed.
//
// Configuration changes need this and the home page's actions do not: blocking
// a profile visibly changes its badge, whereas saving a budget of "4h" leaves
// a page that looks exactly as it did whether or not the save worked.
func redirectSaved(w http.ResponseWriter, r *http.Request, what string) {
	http.Redirect(w, r, "/settings?saved="+template.URLQueryEscaper(what), http.StatusSeeOther)
}

// homeTemplate is deliberately SMALL: one row per profile, with the state and
// the two actions that matter in reach, and a link to everything else.
var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>curfew</title>
<style>
` + sharedCSS + `
 .rowp { border: 1px solid #ddd; border-radius: .5rem; padding: .7rem .8rem; margin-bottom: .7rem; }
 .rowp .head { justify-content: space-between; }
 .sub { color: #666; font-size: .85rem; margin-top: .25rem; }
 .custom { display: inline-flex; gap: .25rem; align-items: center; }
 .custom input { width: 4.4rem; }
</style>
</head>
<body>
<h1>curfew</h1>
<div class="now">{{.Now}} ({{.Zone}}) &middot; <a href="/settings">settings</a> &middot;
  <a href="/devices/">all devices</a></div>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

{{range $p := .Profiles}}
<div class="rowp">
  <div class="head">
    <h2>{{.Name}}</h2>
    <span class="state {{.StateClass}}">{{.StateLabel}}</span>
  </div>
  {{if not .Drifted}}{{if .Reason}}<div class="sub">{{.Reason}}</div>{{end}}{{end}}
  {{if .NeedsDevices}}<div class="warnline">{{.Warning}}</div>{{end}}
  {{if .Budget}}<div class="sub">{{.Budget}}</div>{{end}}

  <div class="tickets">
    {{if .ManuallyBlocked}}
      <form method="POST" action="/profiles/unblock">
        <input type="hidden" name="name" value="{{.Name}}">
        <button type="submit" class="unblock">unblock</button>
      </form>
      <span class="muted">off until you lift it; a ticket cannot lift it</span>
    {{else}}
      <form method="POST" action="/profiles/block">
        <input type="hidden" name="name" value="{{.Name}}">
        <button type="submit" class="block">block</button>
      </form>
      {{range $.Tickets}}
      <form method="POST" action="/profiles/ticket">
        <input type="hidden" name="name" value="{{$p.Name}}">
        <input type="hidden" name="minutes" value="{{.Minutes}}">
        <button type="submit">{{.Label}}</button>
      </form>
      {{end}}
      <form method="POST" action="/profiles/ticket" class="custom">
        <input type="hidden" name="name" value="{{$p.Name}}">
        <input type="number" name="minutes" min="1" max="{{$.MaxTicketMinutes}}"
               placeholder="min" aria-label="minutes of internet for {{$p.Name}}" required>
        <button type="submit">give</button>
      </form>
    {{end}}
  </div>
  {{if .Timing}}<div class="sub">{{.Timing}}</div>{{end}}
  {{if .TicketLeft}}<div class="sub">ticket: {{.TicketLeft}} left; tapping again adds a fresh one</div>{{end}}
</div>
{{else}}
<p class="muted">No profiles yet. Create one in <a href="/settings">settings</a>.
A device in no profile is always allowed.</p>
{{end}}

{{if .UnassignedCount}}
<p class="muted">{{.UnassignedCount}} registered device(s) are in no profile, so they are
always allowed. Assign them in <a href="/settings">settings</a>.</p>
{{end}}
<p class="muted">Blocked/allowed is read from the firewall itself. If it ever disagrees
with the schedule, this page says so rather than showing you what it hoped.</p>
</body>
</html>
`))
