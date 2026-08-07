// Package httpui serves the device page and its JSON API.
//
// The page reports, per device, what the FIREWALL currently allows rather than
// what the registry file claims. Where the two disagree the firewall is right
// (docs/adr/0004-tests-assert-on-the-packet-path.md), and showing the
// disagreement instead of hiding it is deliberate: a green dot that came from
// reading back our own config file is exactly the reassurance that let the
// original system report success while enforcing nothing.
package httpui

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/wighawag/curfew/internal/registry"
)

// Firewall is the READ surface this package needs: what the kernel is doing
// right now, one method per tier of the ordering contract. Narrow on purpose,
// so the UI can be tested without root, netlink or a kernel.
//
// There is deliberately no Apply here. Every write goes through Core, because
// a handler that applies a partial view of the desired state wipes the tiers
// it did not know about: this interface used to carry Apply(macs), and adding
// a device therefore cleared every schedule block until the next reconcile
// tick, up to a minute later.
type Firewall interface {
	Allowlist() ([]string, error)
	// Blocked is what the firewall is dropping by schedule or budget.
	Blocked() ([]string, error)
	// ManualBlocked is what it is dropping because a parent said so. A status
	// derived without this reads a manually blocked profile as allowed, which
	// docs/adr/0006 names as the trap in splitting the block into two sets.
	ManualBlocked() ([]string, error)
	// Tickets maps a MAC to the time the KERNEL says its grant has left.
	Tickets() (map[string]time.Duration, error)
}

// Core is the policy layer: everything that CHANGES what the firewall is asked
// to do. Keeping it behind an interface is what stops this package importing
// the enforcement code, which the laptop binary must never reach (see
// separation_test.go).
type Core interface {
	// Reconcile makes the firewall match the desired state.
	Reconcile() error
	// Block turns a profile off until a parent turns it back on.
	Block(profile string) error
	// Unblock lifts that decision, and nothing else.
	Unblock(profile string) error
	// GrantTicket gives a profile access for d.
	GrantTicket(profile string, d time.Duration) error
	// ManuallyBlocked reports the parent's INTENT, against which what the
	// firewall is doing can be compared.
	ManuallyBlocked() (map[string]bool, error)
}

// Store loads and saves the device registry.
type Store interface {
	Load() (*registry.Registry, error)
	Save(*registry.Registry) error
}

// Server is the HTTP surface.
type Server struct {
	store    Store
	schedule ScheduleStore
	firewall Firewall
	core     Core
	log      *slog.Logger
	user     string
	password string
	// loc is the zone schedules are evaluated in. It is explicit rather than
	// implicit, because the system default on OpenWrt is UTC and a household
	// bedtime evaluated in UTC is silently an hour out half the year.
	loc *time.Location
}

// New builds the server. An empty user or password disables authentication,
// which the daemon warns about loudly at startup: this page grants network
// access, and it is reachable by the very devices it is keeping off the
// internet, since blocking applies to forwarded traffic and not to the router.
//
// That reachability is why the password is half of the defence against a child
// freeing themselves, and why the other half is that a manual block outranks a
// ticket in the chain (ADR 0006). Neither half is sufficient alone.
func New(store Store, sched ScheduleStore, firewall Firewall, core Core, log *slog.Logger,
	user, password string, loc *time.Location) *Server {
	if loc == nil {
		loc = time.Local
	}
	return &Server{store: store, schedule: sched, firewall: firewall, core: core, log: log,
		user: user, password: password, loc: loc}
}

// DeviceView is one row of the page and of the API.
type DeviceView struct {
	MAC string `json:"mac"`
	// Name is optional and may be empty.
	Name string `json:"name,omitempty"`
	// Allowed is read from the firewall, not from the registry.
	Allowed bool `json:"allowed"`
	// Unregistered marks a MAC the firewall allows that the registry does not
	// know about. It should never appear; if it does, something wrote to the
	// ruleset behind our back and that is worth seeing.
	Unregistered bool `json:"unregistered,omitempty"`
}

func (s *Server) authOK(r *http.Request) bool {
	if s.user == "" || s.password == "" {
		return true
	}
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Constant-time on both, and compared independently so neither length
	// leaks through an early return.
	userOK := subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(p), []byte(s.password)) == 1
	return userOK && passOK
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/devices/", s.handleDevicesPage)
	mux.HandleFunc("/profiles/create", s.handleProfileCreate)
	mux.HandleFunc("/profiles/delete", s.handleProfileDelete)
	mux.HandleFunc("/profiles/devices", s.handleProfileDevices)
	mux.HandleFunc("/profiles/window/add", s.handleWindowAdd)
	mux.HandleFunc("/profiles/window/remove", s.handleWindowRemove)
	mux.HandleFunc("/profiles/block", s.handleProfileBlock)
	mux.HandleFunc("/profiles/unblock", s.handleProfileUnblock)
	mux.HandleFunc("/profiles/ticket", s.handleProfileTicket)
	mux.HandleFunc("/devices", s.handleAddDevice)
	mux.HandleFunc("/devices/rename", s.handleRenameDevice)
	mux.HandleFunc("/devices/remove", s.handleRemoveDevice)
	mux.HandleFunc("/api/devices", s.handleAPIDevices)
	return s.withAuth(s.withNoStore(mux))
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authOK(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="curfew", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withNoStore stops a phone browser caching a page whose whole purpose is to
// show current state.
func (s *Server) withNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// render executes a template into a BUFFER before writing a byte of response.
//
// This is not tidiness. html/template writes as it goes, so a template error
// halfway through leaves a 200 with a truncated page: the browser shows
// something plausible with the rest of the form silently missing, and any test
// asserting on status or on a string near the top passes. That is exactly how
// a real bug shipped here. Buffering turns the same failure into a 500 and a
// log line, which is the difference between a lie and an error.
func (s *Server) render(w http.ResponseWriter, t *template.Template, data any, what string) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		s.log.Error("rendering "+what, "error", err)
		http.Error(w, "failed to render the page", http.StatusInternalServerError)
		return
	}
	if _, err := buf.WriteTo(w); err != nil {
		s.log.Error("writing "+what, "error", err)
	}
}

// view joins the registry (names) with the firewall (truth).
//
// Allowed is the verdict the whole chain would reach, not membership of the
// allowlist. A device that is registered but inside its bedtime, or blocked by
// a parent, is not allowed out, and a page saying otherwise because it read
// only one set is the exact defect ADR 0006 warns about when the block splits
// into two sets.
func (s *Server) view() ([]DeviceView, error) {
	reg, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	fw, err := s.readFirewall()
	if err != nil {
		return nil, err
	}
	live, err := s.firewall.Allowlist()
	if err != nil {
		return nil, err
	}

	out := make([]DeviceView, 0, len(reg.Devices))
	seen := make(map[string]bool, len(reg.Devices))
	for _, d := range reg.Devices {
		seen[d.MAC] = true
		allowed, _ := fw.verdict(d.MAC)
		out = append(out, DeviceView{MAC: d.MAC, Name: d.Name, Allowed: allowed})
	}
	for _, m := range live {
		if !seen[m] {
			allowed, _ := fw.verdict(m)
			out = append(out, DeviceView{MAC: m, Allowed: allowed, Unregistered: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

func (s *Server) handleAPIDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices, err := s.view()
	if err != nil {
		s.log.Error("listing devices", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"devices": devices}); err != nil {
		s.log.Error("encoding devices", "error", err)
	}
}

// handleDevicesPage serves the device list at /devices/.
func (s *Server) handleDevicesPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/devices/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices, err := s.view()
	if err != nil {
		s.log.Error("rendering index", "error", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := pageData{Devices: devices, Error: r.URL.Query().Get("error")}
	s.render(w, indexTemplate, data, "devices")
}

// handleAddDevice registers a device and reconciles the firewall.
//
// The registry is saved BEFORE the firewall is applied, and an apply failure
// is reported rather than swallowed. Saving first means a crash between the
// two leaves a device registered but not yet enforced, which the next
// reconcile fixes; the reverse order would leave the firewall allowing a
// device no file records, which nothing would ever correct.
//
// It reconciles the WHOLE desired state rather than pushing the new allowlist
// on its own. Pushing one tier is what this used to do, and it silently
// emptied every block set for as long as it took the next tick to arrive.
func (s *Server) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := r.FormValue("mac")
	name := r.FormValue("name")

	if _, err := registry.NormaliseMAC(mac); err != nil {
		http.Redirect(w, r, "/devices/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}

	reg, err := s.store.Load()
	if err != nil {
		s.log.Error("loading registry", "error", err)
		http.Error(w, "failed to read the registry", http.StatusInternalServerError)
		return
	}
	if err := reg.Add(mac, name); err != nil {
		http.Redirect(w, r, "/devices/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.store.Save(reg); err != nil {
		s.log.Error("saving registry", "error", err)
		http.Error(w, "failed to save the registry", http.StatusInternalServerError)
		return
	}
	if err := s.core.Reconcile(); err != nil {
		// Loudly, and with a non-2xx status. The device is registered but not
		// enforced, and saying so is the entire point of this project.
		s.log.Error("applying ruleset", "error", err)
		http.Error(w, fmt.Sprintf("device saved but the firewall was NOT updated: %v", err),
			http.StatusInternalServerError)
		return
	}
	s.log.Info("device registered", "mac", mac, "name", name)
	http.Redirect(w, r, "/devices/", http.StatusSeeOther)
}

// handleRenameDevice changes a device's name.
//
// It does NOT touch the firewall, and that is deliberate rather than an
// omission: the allowlist is keyed on MAC, so a name is pure metadata and
// renaming cannot change who has internet. Reconciling here would put the
// ruleset at risk for an operation that has no business affecting it.
func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := r.FormValue("mac")
	name := r.FormValue("name")

	reg, err := s.store.Load()
	if err != nil {
		s.log.Error("loading registry", "error", err)
		http.Error(w, "failed to read the registry", http.StatusInternalServerError)
		return
	}
	if err := reg.Rename(mac, name); err != nil {
		// Includes the not-registered case, which must not silently insert.
		http.Redirect(w, r, "/devices/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.store.Save(reg); err != nil {
		s.log.Error("saving registry", "error", err)
		http.Error(w, "failed to save the registry", http.StatusInternalServerError)
		return
	}
	s.log.Info("device renamed", "mac", mac, "name", name)
	http.Redirect(w, r, "/devices/", http.StatusSeeOther)
}

// handleRemoveDevice deregisters a device and revokes its access.
//
// Unlike rename, this DOES reconcile the firewall: removing a device from the
// allowlist is the whole point, and leaving the ruleset untouched would mean
// the page said "removed" while the device kept its internet, which is the
// exact lie this project exists to remove.
func (s *Server) handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := r.FormValue("mac")

	reg, err := s.store.Load()
	if err != nil {
		s.log.Error("loading registry", "error", err)
		http.Error(w, "failed to read the registry", http.StatusInternalServerError)
		return
	}
	if err := reg.Remove(mac); err != nil {
		http.Redirect(w, r, "/devices/?error="+template.URLQueryEscaper(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.store.Save(reg); err != nil {
		s.log.Error("saving registry", "error", err)
		http.Error(w, "failed to save the registry", http.StatusInternalServerError)
		return
	}
	if err := s.core.Reconcile(); err != nil {
		s.log.Error("applying ruleset", "error", err)
		http.Error(w, fmt.Sprintf("device removed from the list but the firewall was NOT updated, "+
			"so it may still have access: %v", err), http.StatusInternalServerError)
		return
	}
	s.log.Info("device removed", "mac", mac)
	http.Redirect(w, r, "/devices/", http.StatusSeeOther)
}

type pageData struct {
	Devices []DeviceView
	Error   string
}

var indexTemplate = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>curfew devices</title>
<style>
 body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; max-width: 40rem; }
 h1 { font-size: 1.3rem; }
 table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }
 th, td { text-align: left; padding: .5rem .4rem; border-bottom: 1px solid #ddd; font-size: .95rem; }
 code { font-family: ui-monospace, monospace; }
 .yes { color: #0a7d28; font-weight: 600; }
 .no  { color: #b00020; font-weight: 600; }
 .warn { background: #fff4e5; }
 form { display: grid; gap: .6rem; }
 form.rename { display: flex; gap: .3rem; margin: 0; }
 form.rename input { padding: .4rem; font-size: .9rem; }
 form.rename button { padding: .4rem .6rem; font-size: .85rem; }
 form.remove { margin: 0; }
 button.danger { padding: .4rem .6rem; font-size: .85rem; color: #b00020; }
 input { padding: .6rem; font-size: 1rem; width: 100%; box-sizing: border-box; }
 button { padding: .7rem; font-size: 1rem; }
 .err { background: #fdecea; color: #b00020; padding: .6rem; margin-bottom: 1rem; }
 .muted { color: #666; font-size: .85rem; }
</style>
</head>
<body>
<p><a href="/">&larr; profiles</a></p>
<h1>Devices allowed on the internet</h1>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<table>
<tr><th>Name</th><th>MAC</th><th>Allowed</th><th></th></tr>
{{range .Devices}}
<tr{{if .Unregistered}} class="warn"{{end}}>
  <td>
    {{if .Unregistered}}
      <span class="muted">not in the registry</span>
    {{else}}
      <form method="POST" action="/devices/rename" class="rename">
        <input type="hidden" name="mac" value="{{.MAC}}">
        <input name="name" value="{{.Name}}" placeholder="unnamed" aria-label="name for {{.MAC}}"
               autocapitalize="none" autocomplete="off">
        <button type="submit">Save</button>
      </form>
    {{end}}
  </td>
  <td><code>{{.MAC}}</code></td>
  <td>{{if .Allowed}}<span class="yes">yes</span>{{else}}<span class="no">no</span>{{end}}</td>
  <td>{{if not .Unregistered}}
    <form method="POST" action="/devices/remove" class="remove"
          onsubmit="return confirm('Remove {{if .Name}}{{.Name}}{{else}}{{.MAC}}{{end}} and cut off its internet?')">
      <input type="hidden" name="mac" value="{{.MAC}}">
      <button type="submit" class="danger">Remove</button>
    </form>
  {{end}}</td>
</tr>
{{else}}
<tr><td colspan="4" class="muted">No devices registered. Nothing can reach the internet.</td></tr>
{{end}}
</table>
<h2 style="font-size:1.05rem">Add a device</h2>
<form method="POST" action="/devices">
  <input name="mac" placeholder="aa:bb:cc:dd:ee:01" required autocapitalize="none" autocomplete="off">
  <input name="name" placeholder="name (optional)" autocomplete="off">
  <button type="submit">Allow this device</button>
</form>
<p class="muted">Edit a name and press Save. Names are labels only: the allowlist
works on MAC addresses, so renaming never changes who has internet.</p>
<p class="muted">The Allowed column is read from the firewall itself, not from the
saved list, so if the two ever disagree you will see it here.</p>
</body>
</html>
`))
