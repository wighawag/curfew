package dnsnames

import (
	"strings"
)

// How a name is rendered on each resolver (docs/adr/0013), and how the
// router's own uci is read. Kept next to the meaning of a name so the meaning
// and its two renderings cannot drift apart.

// DnsmasqDomain is the domain part of the dnsmasq entries for the name:
// "x" for x-and-below, "*.x" for strictly-below (dnsmasq 2.86+ wildcard).
func (n Name) DnsmasqDomain() string { return n.String() }

// DnsmasqAddress is the `list address` value that answers the name's A
// queries with ip.
func (n Name) DnsmasqAddress(ip string) string { return "/" + n.DnsmasqDomain() + "/" + ip }

// DnsmasqServer is the `list server` value that makes the name LOCAL-ONLY:
// without it dnsmasq forwards AAAA and every other type upstream (measured),
// with it they get NOERROR and no answer.
func (n Name) DnsmasqServer() string { return "/" + n.DnsmasqDomain() + "/" }

// AdGuardDomains are the rewrite domains that cover exactly what the name
// covers: AdGuard's own "x" is exactly x (measured), so x-and-below needs the
// pair x and *.x.
func (n Name) AdGuardDomains() []string {
	if n.Wildcard {
		return []string{"*." + n.Base}
	}
	return []string{n.Base, "*." + n.Base}
}

// DomainsOf returns the domains a dnsmasq `address` or `server` value names:
// "/a/b/1.2.3.4" names a and b. A value that is not of that shape names none.
func DomainsOf(value string) []string {
	if !strings.HasPrefix(value, "/") {
		return nil
	}
	parts := strings.Split(value[1:], "/")
	if len(parts) < 2 {
		return nil
	}
	var out []string
	for _, p := range parts[:len(parts)-1] {
		if p = Canonical(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// UCIValues splits the value side of a `uci show` line into its list items:
// `'a' 'b c'` is [a, "b c"], and uci's `'\”` escape is undone.
func UCIValues(v string) []string {
	var out []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case !in && c == '\'':
			in = true
			cur.Reset()
		case in && c == '\'':
			// `'\''` closes, emits a literal quote and reopens.
			if strings.HasPrefix(v[i:], `'\''`) {
				cur.WriteByte('\'')
				i += 3
				continue
			}
			in = false
			out = append(out, cur.String())
		case in:
			cur.WriteByte(c)
		}
	}
	return out
}

// uciOption returns the list items of `<key>=...` in `uci show` output.
func uciOption(show, key string) []string {
	for _, line := range strings.Split(show, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return UCIValues(v)
		}
	}
	return nil
}

// firstDnsmasq is how `uci show dhcp` names the first dnsmasq section:
// "dhcp.@dnsmasq[0]" when it is anonymous (as on the live router), or
// "dhcp.<name>" when it has a name. curfew writes through @dnsmasq[0], which
// is that same section either way, so it must read it under either name.
func firstDnsmasq(show string) string {
	for _, line := range strings.Split(show, "\n") {
		if k, ok := strings.CutSuffix(strings.TrimSpace(line), "=dnsmasq"); ok && strings.HasPrefix(k, "dhcp.") {
			return k
		}
	}
	return "dhcp.@dnsmasq[0]"
}

// DnsmasqLists reads the `address` and `server` lists of the first dnsmasq
// instance from `uci show dhcp`. curfew only ever writes to that instance.
func DnsmasqLists(dhcpShow string) (address, server []string) {
	sec := firstDnsmasq(dhcpShow)
	return uciOption(dhcpShow, sec+".address"), uciOption(dhcpShow, sec+".server")
}

// ContextFromUCI builds the router context from `uci show dhcp` and
// `uci show system` (either may be empty when it could not be read).
func ContextFromUCI(dhcpShow, systemShow string) Context {
	ctx := Context{Known: true}
	sec := firstDnsmasq(dhcpShow)
	for _, key := range []string{sec + ".local", sec + ".domain"} {
		for _, v := range uciOption(dhcpShow, key) {
			if d := Canonical(strings.Trim(v, "/")); d != "" {
				ctx.LocalDomains = append(ctx.LocalDomains, d)
			}
		}
	}
	ctx.RouterHostnames = append(ctx.RouterHostnames, uciOption(systemShow, "system.ntp.server")...)
	return ctx
}
