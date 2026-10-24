package leases

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Fixed addresses: an IPv4 address the household chose for a device, which
// curfew pins as that device's static DHCP lease.
//
// The checks live here, in ONE pure function (Survey.CheckFixed), and run in
// three places: `curfew push` before it writes the device list, the router's
// devices page before it saves, and every daemon pass (ScreenFixed plus
// Reconcile's refusals) as defence in depth against a hand-edited file. Three
// callers with one rule is what stops the page and the CLI disagreeing about
// what is allowed. See docs/adr/0012.

// DefaultLeaseFile is where OpenWrt's dnsmasq keeps its leases.
const DefaultLeaseFile = "/tmp/dhcp.leases"

// LAN is what the router's own config says the LAN is. It is read from uci
// rather than assumed, so nothing here depends on 192.168.1.0/24.
type LAN struct {
	// Router is the router's own address on the LAN.
	Router netip.Addr
	// Prefix is the LAN subnet, masked (192.168.1.0/24).
	Prefix netip.Prefix
	// PoolStart and PoolEnd bound dnsmasq's dynamic range.
	PoolStart, PoolEnd netip.Addr
	// LeaseTime is dhcp.lan.leasetime; zero means infinite.
	LeaseTime time.Duration
}

// uciOptions collects `<prefix>.<option>='value'` lines from `uci show`
// output. A list option keeps its FIRST value, which for network.lan.ipaddr is
// the primary address.
func uciOptions(show, prefix string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(show, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix+".") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, prefix+"."), "=")
		if !ok || strings.Contains(key, ".") {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "'") {
			if end := strings.Index(value[1:], "'"); end >= 0 {
				value = value[1 : end+1]
			}
		}
		out[key] = strings.Trim(value, "'\"")
	}
	return out
}

// ParseLAN reads `uci show network.lan` and `uci show dhcp` (or just its
// dhcp.lan part). The address may be CIDR (`192.168.1.1/24`, as on the live
// router) or an address plus `netmask`. Pool and lease time fall back to
// OpenWrt's own defaults (start 100, limit 150, 12h) when dhcp.lan is silent.
func ParseLAN(networkShow, dhcpShow string) (LAN, error) {
	net := uciOptions(networkShow, "network.lan")
	raw := net["ipaddr"]
	if raw == "" {
		return LAN{}, errors.New("network.lan has no ipaddr, so the LAN cannot be known")
	}
	var lan LAN
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() {
			return LAN{}, fmt.Errorf("network.lan.ipaddr %q is not an IPv4 address with a prefix", raw)
		}
		lan.Router, lan.Prefix = p.Addr(), p.Masked()
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil || !a.Is4() {
			return LAN{}, fmt.Errorf("network.lan.ipaddr %q is not an IPv4 address", raw)
		}
		bits, err := maskBits(net["netmask"])
		if err != nil {
			return LAN{}, err
		}
		lan.Router, lan.Prefix = a, netip.PrefixFrom(a, bits).Masked()
	}

	dhcp := uciOptions(dhcpShow, "dhcp.lan")
	start, limit := 100, 150
	if v, err := strconv.Atoi(dhcp["start"]); err == nil && v > 0 {
		start = v
	}
	if v, err := strconv.Atoi(dhcp["limit"]); err == nil && v > 0 {
		limit = v
	}
	base := lan.Prefix.Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	last := n | (1<<(32-lan.Prefix.Bits()) - 1)
	from, to := n+uint32(start), n+uint32(start+limit-1)
	if to >= last {
		to = last - 1
	}
	lan.PoolStart, lan.PoolEnd = u32addr(from), u32addr(to)

	lan.LeaseTime = 12 * time.Hour
	if lt := dhcp["leasetime"]; lt != "" {
		d, err := parseLeaseTime(lt)
		if err != nil {
			return LAN{}, err
		}
		lan.LeaseTime = d
	}
	return lan, nil
}

func u32addr(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func maskBits(mask string) (int, error) {
	if mask == "" {
		return 0, errors.New("network.lan.ipaddr has no prefix and network.lan has no netmask, " +
			"so the LAN subnet cannot be known")
	}
	a, err := netip.ParseAddr(mask)
	if err != nil || !a.Is4() {
		return 0, fmt.Errorf("network.lan.netmask %q is not a netmask", mask)
	}
	b := a.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := 0
	for n&0x80000000 != 0 {
		bits++
		n <<= 1
	}
	if n != 0 {
		return 0, fmt.Errorf("network.lan.netmask %q is not a contiguous netmask", mask)
	}
	return bits, nil
}

// parseLeaseTime reads OpenWrt's leasetime: "12h", "30m", "2d", "3600" or
// "infinite".
func parseLeaseTime(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "infinite" {
		return 0, nil
	}
	unit := time.Second
	switch {
	case strings.HasSuffix(s, "w"):
		unit, s = 7*24*time.Hour, strings.TrimSuffix(s, "w")
	case strings.HasSuffix(s, "d"):
		unit, s = 24*time.Hour, strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "h"):
		unit, s = time.Hour, strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "m"):
		unit, s = time.Minute, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "s"):
		s = strings.TrimSuffix(s, "s")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("dhcp.lan.leasetime %q is not a lease time", s)
	}
	return time.Duration(n) * unit, nil
}

// ReadLAN reads the LAN definition off the router.
func ReadLAN(r Runner) (LAN, error) {
	net, err := r.Run("uci show network.lan")
	if err != nil {
		return LAN{}, fmt.Errorf("reading network.lan: %w", err)
	}
	dhcp, _ := r.Run("uci -q show dhcp.lan || true")
	return ParseLAN(net, dhcp)
}

// CheckAddress refuses what cannot be a host's address on this LAN.
func (l LAN) CheckAddress(ip string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err == nil {
		a = a.Unmap()
	}
	if err != nil || !a.Is4() {
		return fmt.Errorf("%q is not an IPv4 address", ip)
	}
	if !l.Prefix.Contains(a) {
		return fmt.Errorf("%s is outside the LAN %s", a, l.Prefix)
	}
	if a == l.Prefix.Addr() {
		return fmt.Errorf("%s is the network address of %s", a, l.Prefix)
	}
	if a == l.broadcast() {
		return fmt.Errorf("%s is the broadcast address of %s", a, l.Prefix)
	}
	if a == l.Router {
		return fmt.Errorf("%s is the router's own address", a)
	}
	return nil
}

func (l LAN) broadcast() netip.Addr {
	b := l.Prefix.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return u32addr(n | (1<<(32-l.Prefix.Bits()) - 1))
}

// InPool reports whether ip falls inside dnsmasq's dynamic range.
func (l LAN) InPool(ip netip.Addr) bool {
	return l.PoolStart.IsValid() && ip.Compare(l.PoolStart) >= 0 && ip.Compare(l.PoolEnd) <= 0
}

// Lease is one line of dnsmasq's lease file.
type Lease struct {
	MAC     string
	IP      string
	Expires time.Time // zero for an infinite lease
}

// ParseLeaseFile reads /tmp/dhcp.leases: `<expiry> <mac> <ip> <hostname> <client-id>`.
func ParseLeaseFile(s string) []Lease {
	var out []Lease
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		secs, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		l := Lease{MAC: normaliseMAC(f[1]), IP: f[2]}
		if secs > 0 {
			l.Expires = time.Unix(secs, 0)
		}
		out = append(out, l)
	}
	return out
}

// Survey is the router's view, everything CheckFixed needs.
type Survey struct {
	LAN    LAN
	Hosts  []Host
	Leases []Lease
	Now    time.Time
}

// ReadSurvey reads the LAN, the host entries and the lease file off the router.
func ReadSurvey(r Runner, leasePath string) (Survey, error) {
	lan, err := ReadLAN(r)
	if err != nil {
		return Survey{}, err
	}
	hosts, err := Read(r)
	if err != nil {
		return Survey{}, err
	}
	out, err := r.Run(fmt.Sprintf("cat %s 2>/dev/null || true", leasePath))
	if err != nil {
		return Survey{}, fmt.Errorf("reading DHCP leases from %s: %w", leasePath, err)
	}
	return Survey{LAN: lan, Hosts: hosts, Leases: ParseLeaseFile(out), Now: time.Now()}, nil
}

// Check is the outcome of checking one fixed address. Errors refuse it;
// Warnings must be shown to the person setting it, never swallowed.
type Check struct {
	Errors   []string
	Warnings []string
}

// CheckFixed checks giving mac the fixed address ip, against the router's view
// and the fixed addresses of the OTHER devices (otherFixed: MAC to address).
func (s Survey) CheckFixed(mac, ip string, otherFixed map[string]string) Check {
	var c Check
	mac = normaliseMAC(mac)
	if err := s.LAN.CheckAddress(ip); err != nil {
		c.Errors = append(c.Errors, err.Error())
		return c
	}
	addr, _ := netip.ParseAddr(strings.TrimSpace(ip))
	addr = addr.Unmap()
	ip = addr.String()

	for _, h := range s.Hosts {
		switch {
		case h.MAC == mac && !h.Owned():
			c.Errors = append(c.Errors, fmt.Sprintf("a host entry curfew does not own (dhcp.%s) "+
				"already pins %s at %s; curfew yields to it, so a fixed address would never take "+
				"effect. Hand it over with 'curfew adopt-leases' first", h.Section, mac, h.IP))
		case h.MAC != mac && h.IP == ip && h.Owned():
			c.Errors = append(c.Errors, fmt.Sprintf("%s is already pinned by curfew for %s; give "+
				"that device another fixed address first, or remove it", ip, h.MAC))
		case h.MAC != mac && h.IP == ip:
			who := h.MAC
			if h.Name != "" {
				who += ", " + h.Name
			}
			c.Errors = append(c.Errors, fmt.Sprintf("%s is already reserved by the host entry "+
				"dhcp.%s (%s); two reservations for one address stop dnsmasq starting", ip, h.Section, who))
		}
	}
	others := make([]string, 0, len(otherFixed))
	for m := range otherFixed {
		others = append(others, m)
	}
	sort.Strings(others)
	for _, m := range others {
		if normaliseMAC(m) != mac && strings.TrimSpace(otherFixed[m]) == ip {
			c.Errors = append(c.Errors, fmt.Sprintf("%s is already the fixed address of %s", ip, m))
		}
	}
	if len(c.Errors) > 0 {
		return c
	}

	var mine *Lease
	for i, l := range s.Leases {
		if l.MAC == mac {
			mine = &s.Leases[i]
			continue
		}
		if l.IP == ip && (l.Expires.IsZero() || l.Expires.After(s.Now)) {
			until := "with no expiry"
			if !l.Expires.IsZero() {
				until = "until " + l.Expires.Local().Format("Mon 15:04") +
					" (in " + roughly(l.Expires.Sub(s.Now)) + ")"
			}
			c.Warnings = append(c.Warnings, fmt.Sprintf("%s is currently leased to %s %s. It keeps "+
				"it until then, or until it renews and is given another address, so %s cannot "+
				"move there before that", ip, l.MAC, until, mac))
		}
	}
	if s.LAN.InPool(addr) {
		c.Warnings = append(c.Warnings, fmt.Sprintf("%s is inside the DHCP pool (%s to %s). That "+
			"is allowed: dnsmasq honours a static lease inside its own pool and will not hand "+
			"the address to anything else", ip, s.LAN.PoolStart, s.LAN.PoolEnd))
	}
	switch {
	case mine == nil:
		c.Warnings = append(c.Warnings, fmt.Sprintf("%s has no lease right now, so it gets %s "+
			"the next time it asks for an address", mac, ip))
	case mine.IP != ip:
		when := "on its next DHCP renewal"
		if s.LAN.LeaseTime > 0 && !mine.Expires.IsZero() {
			renew := mine.Expires.Add(-s.LAN.LeaseTime / 2)
			if renew.After(s.Now) {
				when += fmt.Sprintf(", around %s (in %s)", renew.Local().Format("Mon 15:04"),
					roughly(renew.Sub(s.Now)))
			} else {
				when += ", which is due now"
			}
		}
		c.Warnings = append(c.Warnings, fmt.Sprintf("%s currently holds %s and moves to %s %s. "+
			"To move it sooner, renew on the device (for example 'networkctl renew <interface>' "+
			"or 'dhcpcd -n <interface>'), or reconnect its Wi-Fi or cable", mac, mine.IP, ip, when))
	}
	return c
}

func roughly(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%02dm", h, m)
}

// ScreenFixed clears every fixed address that is not valid on this LAN, and
// reports each one. With no readable LAN NOTHING fixed is trusted: an
// unvalidated address could be the router's own or outside the subnet.
func ScreenFixed(lan LAN, lanErr error, devices []Device) ([]Device, []Refusal) {
	out := append([]Device(nil), devices...)
	var refused []Refusal
	for i := range out {
		ip := strings.TrimSpace(out[i].Fixed)
		if ip == "" {
			continue
		}
		mac := normaliseMAC(out[i].MAC)
		if lanErr != nil {
			refused = append(refused, Refusal{MAC: mac, IP: ip, Reason: "the LAN definition " +
				"could not be read (" + lanErr.Error() + "), so no fixed address can be checked"})
			out[i].Fixed = ""
			continue
		}
		if err := lan.CheckAddress(ip); err != nil {
			refused = append(refused, Refusal{MAC: mac, IP: ip, Reason: err.Error()})
			out[i].Fixed = ""
			continue
		}
		a, _ := netip.ParseAddr(ip)
		out[i].Fixed = a.Unmap().String()
	}
	return out, refused
}

// Pass is one pinning pass, as the daemon runs it: read the LAN and the host
// entries, screen the fixed addresses, reconcile, apply. It returns the plan
// even when applying fails, so the caller can still report what was refused.
func Pass(r Runner, devices []Device) (Plan, error) {
	lan, lanErr := ReadLAN(r)
	screened, refused := ScreenFixed(lan, lanErr, devices)
	current, err := Read(r)
	if err != nil {
		return Plan{Pinned: map[string]string{}, Refused: refused}, err
	}
	plan := Reconcile(current, screened)
	plan.Refused = append(refused, plan.Refused...)
	_, err = Apply(r, plan)
	return plan, err
}

// PassAndLog runs Pass and says what happened. It is shared by the DNS layer
// and by the daemon's own loop when AdGuard is off, because a fixed address is
// a DHCP promise and must hold whether or not AdGuard exists.
//
// Every failure is WARNED about and nothing stops the caller: the whole layer
// is fail-open, and a lease that could not be written must not take the
// firewall or the rest of the pass down with it.
func PassAndLog(r Runner, log *slog.Logger, devices []Device) Plan {
	plan, err := Pass(r, devices)
	switch {
	case err != nil:
		log.Warn("could not pin static DHCP leases; the addresses already handed out "+
			"are still used", "error", err)
	case len(plan.Commands) > 0:
		log.Info("static DHCP leases updated", "commands", len(plan.Commands))
	}
	for _, c := range plan.Conflicts {
		log.Warn("a static lease curfew does not own already pins this device",
			"mac", c.MAC, "section", "dhcp."+c.Section, "ip", c.IP,
			"what_curfew_did", "left it alone and used its address")
	}
	for _, f := range plan.Refused {
		log.Warn("an address was NOT pinned", "mac", f.MAC, "ip", f.IP, "why", f.Reason,
			"what_curfew_did", "wrote nothing for that address; the device keeps the pin it has, if any")
	}
	return plan
}
