// Package dnsnames is the meaning of a device's local DNS names and the ONE
// set of rules that decides which are allowed.
//
// A local DNS name is a name the router answers itself, with the device's
// fixed address, from both of its resolvers (AdGuard and dnsmasq). What a name
// covers is fixed by docs/adr/0013, and it is chosen by what BOTH resolvers
// can render faithfully (measured, see
// work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md):
//
//   - "x" covers x and every name below it;
//   - "*.x" covers every name strictly below x, and not x itself.
//
// There is deliberately no exact-name-only form: dnsmasq cannot answer exactly
// one name and also keep AAAA from being forwarded upstream.
//
// The rules (Check) run in four places, so they live here and nowhere else:
// `curfew add-dns-name` (with only what the device file knows), `curfew push`
// and the router's devices page (with the router's own uci), and every daemon
// pass (defence in depth against a hand-edited file). This package is pure: it
// reads nothing and imports nothing of curfew's, so both binaries can use it.
package dnsnames

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Canonical is the spelling a name is stored and compared in: trimmed,
// lowercased, one trailing dot dropped. It does not validate; a name that does
// not parse keeps its canonical spelling so it can still be shown and refused.
func Canonical(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

// CanonicalSet canonicalises a list of names, drops empties and duplicates and
// sorts it, so two spellings or two orders of the same set compare equal.
func CanonicalSet(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		c := Canonical(n)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Name is a parsed, valid local DNS name.
type Name struct {
	// Base is the domain the name hangs off: "lan.telemaque.ska.sh" for both
	// "lan.telemaque.ska.sh" and "*.lan.telemaque.ska.sh".
	Base string
	// Wildcard is true for the "*.x" form: names strictly below Base.
	Wildcard bool
}

// String is the canonical spelling.
func (n Name) String() string {
	if n.Wildcard {
		return "*." + n.Base
	}
	return n.Base
}

// Parse checks the SYNTAX of a name and returns it parsed. A valid name is an
// optional single leading "*.", then a hostname of at least two labels, each
// 1 to 63 of [a-z0-9-] not starting or ending with a hyphen, 253 characters at
// most. ASCII only: an internationalised name is written in its xn-- form.
func Parse(s string) (Name, error) {
	c := Canonical(s)
	if c == "" {
		return Name{}, fmt.Errorf("an empty name is not a DNS name")
	}
	n := Name{Base: c}
	if strings.HasPrefix(c, "*.") {
		n.Wildcard, n.Base = true, c[2:]
	}
	if strings.Contains(n.Base, "*") {
		return Name{}, fmt.Errorf("%q: '*' is only allowed once, as a leading '*.' meaning "+
			"\"every name below\"", s)
	}
	if _, err := netip.ParseAddr(n.Base); err == nil {
		return Name{}, fmt.Errorf("%q is an address, not a name", s)
	}
	if len(n.Base) > 253 {
		return Name{}, fmt.Errorf("%q is longer than the 253 characters a DNS name may have", s)
	}
	labels := strings.Split(n.Base, ".")
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return Name{}, fmt.Errorf("%q is not a valid DNS name: %v", s, err)
		}
	}
	if len(labels) < 2 {
		if n.Wildcard {
			return Name{}, fmt.Errorf("%q would answer for every name in the top-level domain "+
				"%q; a local name needs at least two labels below the '*.'", s, n.Base)
		}
		return Name{}, fmt.Errorf("%q has a single label; a local name needs at least two "+
			"(for example nas.home.arpa), so it cannot shadow a top-level domain or a bare "+
			"hostname the router already answers", s)
	}
	return n, nil
}

func checkLabel(l string) error {
	switch {
	case l == "":
		return fmt.Errorf("it has an empty label")
	case len(l) > 63:
		return fmt.Errorf("the label %q is longer than 63 characters", l)
	case l[0] == '-' || l[len(l)-1] == '-':
		return fmt.Errorf("the label %q starts or ends with a hyphen", l)
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			if r > 127 {
				return fmt.Errorf("%q is not ASCII; write an internationalised name in its xn-- form", l)
			}
			return fmt.Errorf("the label %q has %q, and only letters, digits and '-' are allowed", l, r)
		}
	}
	return nil
}

// under reports whether host is d or a name below d.
func under(host, d string) bool {
	return host == d || strings.HasSuffix(host, "."+d)
}

// strictlyUnder reports whether host is a name below d, not d itself.
func strictlyUnder(host, d string) bool { return host != d && under(host, d) }

// Covers reports whether the name answers for host (a canonical hostname).
func (n Name) Covers(host string) bool {
	host = Canonical(host)
	if n.Wildcard {
		return strictlyUnder(host, n.Base)
	}
	return under(host, n.Base)
}

// Overlaps reports whether some hostname is covered by both names.
func Overlaps(a, b Name) bool {
	switch {
	case !a.Wildcard && !b.Wildcard:
		return under(a.Base, b.Base) || under(b.Base, a.Base)
	case a.Wildcard && b.Wildcard:
		return under(a.Base, b.Base) || under(b.Base, a.Base)
	case a.Wildcard: // *.x against y
		return strictlyUnder(b.Base, a.Base) || under(a.Base, b.Base)
	default:
		return Overlaps(b, a)
	}
}

// specialUse are domains the network relies on resolving the normal way, and
// a local record anywhere under them breaks something real. home.arpa is the
// one exception carved out below: RFC 8375 reserves it for exactly this use.
var specialUse = []struct{ domain, why string }{
	{"localhost", "it is this machine on every device"},
	{"local", "it is mDNS, which printers, AirPlay and casting rely on"},
	{"invalid", "it is reserved to never resolve"},
	{"onion", "it is reserved for Tor"},
	{"arpa", "reverse lookups live there (home.arpa, the one local-use part of it, is allowed)"},
}

// Context is what the ROUTER knows that the device file does not. The zero
// value means "not known", and then only the file-level rules apply.
type Context struct {
	// Known is set when the context was actually read from a router.
	Known bool
	// LocalDomains are domains dnsmasq answers from its own DHCP leases
	// (`option local '/lan/'` and `option domain 'lan'`): DHCP clients
	// register their hostnames there.
	LocalDomains []string
	// RouterHostnames are names the router itself resolves to work: today
	// its NTP servers (a wrong clock moves every schedule). AdGuard's
	// upstream and bootstrap hostnames are NOT read yet (deferred: the live
	// router's upstreams are IP addresses, so nothing would match); a caller
	// that knows them can add them here. A local name covering one would
	// hand the router a wrong answer.
	RouterHostnames []string
}

// Device is what the rules need to know about one registered device.
type Device struct {
	MAC string
	// Label names the device in messages, usually "name (mac)".
	Label string
	// Fixed is its fixed address, empty when it has none.
	Fixed string
	// Names are its local DNS names, as stored.
	Names []string
}

// Result is the verdict on one name of one device. Errors refuse it; Warnings
// must be shown to whoever set it, never swallowed.
type Result struct {
	MAC      string
	Name     string
	Errors   []string
	Warnings []string
}

// Check applies every rule to every name of every device.
func Check(devices []Device, ctx Context) []Result {
	type entry struct {
		dev  int
		raw  string
		name Name
		ok   bool
	}
	var all []entry
	for i, d := range devices {
		for _, raw := range CanonicalSet(d.Names) {
			n, err := Parse(raw)
			all = append(all, entry{dev: i, raw: raw, name: n, ok: err == nil})
		}
	}

	var out []Result
	for _, e := range all {
		d := devices[e.dev]
		r := Result{MAC: d.MAC, Name: e.raw}
		if !e.ok {
			_, err := Parse(e.raw)
			r.Errors = append(r.Errors, err.Error())
			out = append(out, r)
			continue
		}
		if strings.TrimSpace(d.Fixed) == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("%s has no fixed address, so %s would point at "+
				"an address that can change. Give it one with 'curfew set-ip' first", d.Label, e.raw))
		}
		r.Errors = append(r.Errors, ruleErrors(e.name)...)
		if ctx.Known {
			r.Errors = append(r.Errors, contextErrors(e.name, ctx)...)
		}
		for _, o := range all {
			if o.raw == e.raw && o.dev == e.dev || !o.ok || !Overlaps(e.name, o.name) {
				continue
			}
			if o.dev != e.dev {
				r.Errors = append(r.Errors, fmt.Sprintf("%s overlaps %s, which %s already has; the "+
					"router would hold two answers for the same names", e.raw, o.raw, devices[o.dev].Label))
				continue
			}
			// Same device: names form a tree, so overlap means one contains
			// the other. Refuse the one that adds nothing.
			if contains(o.name, e.name) {
				r.Errors = append(r.Errors, fmt.Sprintf("%s is already covered by %s on the same device",
					e.raw, o.raw))
			}
		}
		if len(strings.Split(e.name.Base, ".")) == 2 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s answers for every name in %s on your LAN, "+
				"not just one machine's; make sure that is what you mean", e.raw, e.name.Base))
		}
		out = append(out, r)
	}
	return out
}

// contains reports whether every hostname b covers is covered by a.
func contains(a, b Name) bool {
	switch {
	case !a.Wildcard:
		return under(b.Base, a.Base)
	case b.Wildcard:
		return under(b.Base, a.Base)
	default:
		return strictlyUnder(b.Base, a.Base)
	}
}

func ruleErrors(n Name) []string {
	var errs []string
	for _, s := range specialUse {
		if s.domain == "arpa" && (n.Base == "home.arpa" || strings.HasSuffix(n.Base, ".home.arpa")) {
			continue
		}
		// A name cannot cover a special-use domain from ABOVE (that would be
		// a single label, refused by Parse), so being under one is the case.
		if under(n.Base, s.domain) {
			errs = append(errs, fmt.Sprintf("%s is under .%s, and %s", n, s.domain, s.why))
		}
	}
	return errs
}

func contextErrors(n Name, ctx Context) []string {
	var errs []string
	for _, d := range ctx.LocalDomains {
		d = Canonical(strings.Trim(d, "/"))
		if d == "" {
			continue
		}
		if Overlaps(n, Name{Base: d}) {
			errs = append(errs, fmt.Sprintf("%s overlaps the router's own local domain .%s, where "+
				"DHCP clients register their hostnames and dnsmasq answers them itself", n, d))
		}
	}
	for _, h := range ctx.RouterHostnames {
		h = Canonical(h)
		if h == "" {
			continue
		}
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		if n.Covers(h) {
			errs = append(errs, fmt.Sprintf("%s would also answer for %s, which the router itself "+
				"resolves to work (its clock or its upstream DNS)", n, h))
		}
	}
	return errs
}
