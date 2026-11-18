package httpui

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/wighawag/curfew/internal/dnsnames"
)

// UseNameContext lets the devices page add a local DNS name, checked with the
// router's own view (its local domain and its NTP servers) by the same rules
// `curfew push` runs (internal/dnsnames). Left unset, the page refuses to add
// a name it cannot fully check, and still allows removing one.
func (s *Server) UseNameContext(ctx func() (dnsnames.Context, error)) {
	s.nameContext = ctx
}

// handleDNSName adds or removes one local DNS name on a device.
//
// Like a fixed address it never touches the firewall: a name is DNS
// metadata, and it cannot change who has internet. The daemon's next pass
// writes the records, under the same liveness check and rollback as a pin.
func (s *Server) handleDNSName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	fail := func(msg string) {
		http.Redirect(w, r, "/devices/?error="+template.URLQueryEscaper(msg), http.StatusSeeOther)
	}
	name := strings.TrimSpace(r.FormValue("name"))
	reg, err := s.store.Load()
	if err != nil {
		s.log.Error("loading registry", "error", err)
		http.Error(w, "failed to read the registry", http.StatusInternalServerError)
		return
	}
	canonical, err := reg.Resolve(r.FormValue("mac"))
	if err != nil {
		fail(err.Error())
		return
	}

	var notice []string
	switch r.FormValue("action") {
	case "remove":
		if err := reg.RemoveDNSName(canonical, name); err != nil {
			fail(err.Error())
			return
		}
		notice = append(notice, "Local DNS name "+dnsnames.Canonical(name)+
			" removed; the router removes exactly the records curfew made for it within a minute.")
	case "add":
		if s.nameContext == nil {
			fail("cannot check that name against the router's own config here, so it was not saved")
			return
		}
		ctx, err := s.nameContext()
		if err != nil {
			s.log.Error("reading the router's config for local names", "error", err)
			fail("cannot read the router's config (" + err.Error() + "), so the name was not saved")
			return
		}
		warnings, err := reg.AddDNSName(canonical, name)
		if err != nil {
			fail("Not saved: " + err.Error())
			return
		}
		parsed, _ := dnsnames.Parse(name)
		var devices []dnsnames.Device
		var ip string
		for _, d := range reg.Devices {
			label := d.MAC
			if d.Name != "" {
				label = d.Name + " (" + d.MAC + ")"
			}
			devices = append(devices, dnsnames.Device{MAC: d.MAC, Label: label, Fixed: d.IP, Names: d.DNSNames})
			if d.MAC == canonical {
				ip = d.IP
			}
		}
		for _, res := range dnsnames.Check(devices, ctx) {
			if res.MAC == canonical && res.Name == parsed.String() && len(res.Errors) > 0 {
				fail("Not saved: " + strings.Join(res.Errors, "; "))
				return
			}
		}
		notice = append(notice, "Local DNS name "+parsed.String()+" -> "+ip+
			" saved; the router answers it within a minute (IPv4 only).")
		notice = append(notice, warnings...)
	default:
		fail("unknown action")
		return
	}
	if err := s.store.Save(reg); err != nil {
		s.log.Error("saving registry", "error", err)
		http.Error(w, "failed to save the registry", http.StatusInternalServerError)
		return
	}
	s.log.Info("local DNS names changed", "mac", canonical, "action", r.FormValue("action"), "name", name)
	http.Redirect(w, r, "/devices/?notice="+template.URLQueryEscaper(strings.Join(notice, " ")),
		http.StatusSeeOther)
}
