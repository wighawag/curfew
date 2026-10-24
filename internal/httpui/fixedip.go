package httpui

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/wighawag/curfew/internal/leases"
)

// UseAddresses lets the devices page set a device's FIXED ADDRESS, checked
// against the router's own view (its LAN, its host entries, its lease file)
// with leases.Survey.CheckFixed: the same check `curfew push` runs, so the
// page and the CLI cannot disagree about what is allowed. Left unset, the page
// refuses to set an address it cannot check, and still allows clearing one.
func (s *Server) UseAddresses(survey func() (leases.Survey, error)) {
	s.addresses = survey
}

// handleSetIP sets or clears a device's fixed address.
//
// It does NOT touch the firewall: an address is DHCP metadata and cannot
// change who has internet. The daemon's next pass writes the static lease,
// which is also where the dnsmasq liveness check and rollback live.
func (s *Server) handleSetIP(w http.ResponseWriter, r *http.Request) {
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
	mac := r.FormValue("mac")
	ip := strings.TrimSpace(r.FormValue("ip"))
	clear := r.FormValue("clear") != "" || ip == ""

	reg, err := s.store.Load()
	if err != nil {
		s.log.Error("loading registry", "error", err)
		http.Error(w, "failed to read the registry", http.StatusInternalServerError)
		return
	}
	canonical, err := reg.Resolve(mac)
	if err != nil {
		// Includes the not-registered case, which must not silently insert.
		fail(err.Error())
		return
	}

	var notice []string
	if clear {
		ip = ""
		notice = append(notice, "Fixed address cleared. The device keeps the address it has now.")
	} else {
		if s.addresses == nil {
			fail("cannot check that address against the router's DHCP config here, so it was not saved")
			return
		}
		survey, err := s.addresses()
		if err != nil {
			s.log.Error("reading the router's DHCP view", "error", err)
			fail("cannot read the router's DHCP config (" + err.Error() + "), so the address was not saved")
			return
		}
		others := map[string]string{}
		for _, d := range reg.Devices {
			if d.MAC != canonical && d.IP != "" {
				others[d.MAC] = d.IP
			}
		}
		check := survey.CheckFixed(canonical, ip, others)
		if len(check.Errors) > 0 {
			fail("Not saved: " + strings.Join(check.Errors, "; "))
			return
		}
		notice = append(notice, "Fixed address "+ip+" saved; the router pins it within a minute.")
		notice = append(notice, check.Warnings...)
	}
	if err := reg.SetIP(canonical, ip); err != nil {
		fail(err.Error())
		return
	}
	if err := s.store.Save(reg); err != nil {
		s.log.Error("saving registry", "error", err)
		http.Error(w, "failed to save the registry", http.StatusInternalServerError)
		return
	}
	s.log.Info("fixed address changed", "mac", canonical, "ip", ip)
	http.Redirect(w, r, "/devices/?notice="+template.URLQueryEscaper(strings.Join(notice, " ")),
		http.StatusSeeOther)
}

// pinnedAddresses is MAC to the address curfew's own host entry pins, when the
// router's view can be read. It is shown next to the fixed address because a
// device with none is still pinned, and that is what the household sees.
func (s *Server) pinnedAddresses() map[string]string {
	out := map[string]string{}
	if s.addresses == nil {
		return out
	}
	survey, err := s.addresses()
	if err != nil {
		return out
	}
	for _, h := range survey.Hosts {
		if h.Owned() {
			out[h.MAC] = h.IP
		}
	}
	return out
}
