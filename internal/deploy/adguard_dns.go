package deploy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
)

// Making AdGuard actually own DNS, which is the half that was missing.
//
// An AdGuard that is running is not an AdGuard that is filtering. Measured on
// the live router: dnsmasq held port 53, so AdGuard fatally exited with
// "listen tcp 0.0.0.0:53: bind: address already in use" on every start, and
// procd eventually gave up. The household resolved happily through dnsmasq the
// whole time, with no filtering at all and nothing saying so.
//
// Worse, the failure is INVISIBLE to a naive check. AdGuard serves its web API
// about two seconds after starting and only attempts the DNS bind about
// FORTY-THREE seconds later, once it has loaded its blocklists. Anything that
// verified the admin API immediately, as this code first did, passed against a
// process that was already doomed. So verification here waits for DNS itself,
// and asks who actually holds port 53.

// dnsmasqPort reports the port dnsmasq is CONFIGURED to use, and whether that
// could be established at all.
//
// "uci could not answer" is not "dnsmasq is on 53". An earlier version
// conflated them and tried to reconfigure a dnsmasq that was not there. Where
// uci is silent, the decision is made from what is actually LISTENING on port
// 53 instead, which is evidence rather than inference.
func dnsmasqPort(r Runner) (port string, known bool, err error) {
	out, err := r.Run("uci get dhcp.@dnsmasq[0].port 2>/dev/null || true")
	if err != nil {
		return "", false, err
	}
	if p := strings.TrimSpace(out); p != "" {
		return p, true, nil
	}
	return "", false, nil
}

// dnsmasqIsInTheWay reports whether dnsmasq needs moving off port 53.
//
// Two independent pieces of evidence, and either is enough. It is LISTENING on
// 53 right now, which is the state that stops AdGuard binding; or uci says 53,
// which is the state that would take the port back at the next restart even if
// AdGuard has it today.
func dnsmasqIsInTheWay(r Runner) (bool, error) {
	holder, err := portFiftyThreeHolder(r)
	if err != nil {
		return false, err
	}
	if strings.Contains(holder, "dnsmasq") {
		return true, nil
	}
	port, known, err := dnsmasqPort(r)
	if err != nil {
		return false, err
	}
	return known && port == "53", nil
}

// portFiftyThreeHolder reports which process is listening on port 53, so a
// conflict is named rather than inferred.
func portFiftyThreeHolder(r Runner) (string, error) {
	out, err := r.Run("netstat -tulnp 2>/dev/null | grep -E '[^0-9]53 ' | head -1")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) == 0 {
		return "", nil
	}
	last := fields[len(fields)-1]
	if i := strings.Index(last, "/"); i >= 0 {
		return last[i+1:], nil
	}
	return last, nil
}

// dhcpOptions reads the LAN's DHCP options as a list.
func dhcpOptions(r Runner) ([]string, error) {
	out, err := r.Run("uci -q get dhcp.lan.dhcp_option 2>/dev/null || true")
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.TrimSpace(out)), nil
}

// withDNSOption replaces the DNS option (number 6) and KEEPS every other one.
//
// This exists because deleting the whole list was destroying configuration
// that has nothing to do with DNS. `uci delete dhcp.lan.dhcp_option` removes
// ALL options, so a household with an NTP server (option 42), a domain
// (option 15) or anything else lost it silently the moment curfew took port
// 53. The legacy script did the same, which is not a defence.
func withDNSOption(existing []string, routerIP string) []string {
	out := make([]string, 0, len(existing)+1)
	for _, opt := range existing {
		if strings.HasPrefix(opt, "6,") {
			continue
		}
		out = append(out, opt)
	}
	if routerIP != "" {
		out = append(out, "6,"+routerIP)
	}
	return out
}

// setDHCPOptions writes the option list back, replacing whatever is there.
func setDHCPOptions(r Runner, options []string) error {
	if _, err := r.Run("uci -q delete dhcp.lan.dhcp_option || true"); err != nil {
		return err
	}
	for _, opt := range options {
		if _, err := r.Run(fmt.Sprintf("uci add_list dhcp.lan.dhcp_option='%s'", opt)); err != nil {
			return fmt.Errorf("setting DHCP option %q: %w", opt, err)
		}
	}
	return nil
}

// moveDnsmasqTo54 frees port 53 for AdGuard and points DHCP at the router for
// DNS, which is the arrangement ADR 0002 describes. dnsmasq keeps DHCP.
//
// It returns the DHCP options as they were, so a rollback can put them back
// exactly rather than approximately.
func moveDnsmasqTo54(r Runner, routerIP string) ([]string, error) {
	before, err := dhcpOptions(r)
	if err != nil {
		return nil, err
	}
	if _, err := r.Run("uci set dhcp.@dnsmasq[0].port=54"); err != nil {
		return before, fmt.Errorf("moving dnsmasq to port 54: %w", err)
	}
	if err := setDHCPOptions(r, withDNSOption(before, routerIP)); err != nil {
		return before, err
	}
	for _, cmd := range []string{"uci commit dhcp", "/etc/init.d/dnsmasq restart"} {
		if _, err := r.Run(cmd); err != nil {
			return before, fmt.Errorf("moving dnsmasq to port 54 (%s): %w", cmd, err)
		}
	}
	return before, nil
}

// restoreDnsmasqTo53 is the ROLLBACK, and it is why taking port 53 is safe to
// attempt at all.
//
// If AdGuard cannot serve DNS after dnsmasq has stepped aside, the household
// has no resolver at all, which is a real outage rather than a degraded
// feature. So every failure path after the move calls this, and the house ends
// up where it started: dnsmasq answering, nothing filtered, and its DHCP
// options exactly as they were.
func restoreDnsmasqTo53(r Runner, options []string) error {
	if _, err := r.Run("uci set dhcp.@dnsmasq[0].port=53"); err != nil {
		return fmt.Errorf("restoring dnsmasq to port 53: %w", err)
	}
	if err := setDHCPOptions(r, options); err != nil {
		return err
	}
	for _, cmd := range []string{"uci commit dhcp", "/etc/init.d/dnsmasq restart"} {
		if _, err := r.Run(cmd); err != nil {
			return fmt.Errorf("restoring dnsmasq to port 53 (%s): %w", cmd, err)
		}
	}
	return nil
}

// ensureServiceEnabled makes AdGuard start at boot.
//
// Found missing on the live router: the init script existed but there was no
// rc.d symlink, so a power cut would have left the household with no AdGuard
// and nothing to notice. Restarting a service that cannot come back on its own
// is only half an install.
func ensureServiceEnabled(r Runner) (bool, error) {
	out, err := r.Run("ls /etc/rc.d/*adguardhome* 2>/dev/null | head -1")
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) != "" {
		return false, nil
	}
	if _, err := r.Run("[ -x /etc/init.d/adguardhome ] && /etc/init.d/adguardhome enable 2>/dev/null; true"); err != nil {
		return false, err
	}
	return true, nil
}

// adGuardServesDNS reports whether AdGuard itself now holds port 53.
//
// Asking WHO holds the port matters as much as whether the port answers:
// dnsmasq answering on 53 looks identical to AdGuard answering on 53 from the
// outside, and that is exactly the state this router was in while appearing
// fine.
func adGuardServesDNS(r Runner) (bool, error) {
	holder, err := portFiftyThreeHolder(r)
	if err != nil {
		return false, err
	}
	return strings.Contains(holder, "AdGuard"), nil
}

// resolvesThrough asks the router to resolve a name, proving DNS actually
// works rather than merely that something is bound to the port.
func resolvesThrough(addr, name string, timeout time.Duration) error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(addr, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, name)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%s resolved to nothing", name)
	}
	return nil
}

// waitForAdGuardDNS waits for AdGuard to take over port 53, or explains why it
// never did.
//
// The patience is not arbitrary. AdGuard loads its blocklists before binding,
// which took 43 seconds on the real router, so anything checking sooner is
// checking nothing. If AdGuard dies instead, its own fatal line is pulled out
// of the log and reported, because "it did not come up" is useless next to
// "address already in use".
func waitForAdGuardDNS(r Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := adGuardServesDNS(r)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	holder, _ := portFiftyThreeHolder(r)
	fatal, _ := r.Run("logread 2>/dev/null | grep -i adguard | grep -i fatal | tail -1")
	msg := fmt.Sprintf("AdGuard did not take over DNS on port 53 within %s", timeout)
	if holder != "" {
		msg += fmt.Sprintf("; port 53 is held by %s", holder)
	}
	if f := strings.TrimSpace(fatal); f != "" {
		msg += fmt.Sprintf("\n       AdGuard said: %s", f)
	}
	return fmt.Errorf("%s", msg)
}

// adGuardRunning reports whether the process exists at all.
//
// Needed because "not serving DNS" has two very different causes: AdGuard is
// still starting, which deserves patience, or AdGuard is not running, which
// deserves a start. Waiting two minutes for a process that does not exist is
// how the previous version wasted the whole timeout and then reported failure.
func adGuardRunning(r Runner) (bool, error) {
	out, err := r.Run("pgrep AdGuardHome >/dev/null 2>&1 && echo yes || echo no")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}

// takeOverDNS makes AdGuard running AND the household's resolver, and puts
// everything back if it cannot.
//
// forceRestart is set when the config was just edited, because AdGuard will
// not pick up a new admin account without one.
//
// The ORDER here is load-bearing and was wrong at first. Verifying the admin
// API before freeing port 53 is doomed on a router where dnsmasq holds it:
// AdGuard starts, serves its API for about forty-three seconds, then exits
// when the DNS bind fails. So the port is freed and AdGuard is brought up
// FIRST, and only then is anything verified.
func takeOverDNS(r Runner, opt AdGuardOptions, report *AdGuardReport, forceRestart bool) error {
	timeout := opt.DNSTimeout
	if timeout <= 0 {
		timeout = DefaultDNSTimeout
	}

	running, err := adGuardRunning(r)
	if err != nil {
		return err
	}
	if !forceRestart && running {
		serving, err := adGuardServesDNS(r)
		if err != nil {
			return err
		}
		if serving {
			report.ServingDNS = true
			return nil
		}
		// Running but not on port 53 yet. It may still be loading blocklists,
		// which took 43 seconds on the real router, so give it that chance
		// before concluding anything and moving a working resolver aside.
		if holder, err := portFiftyThreeHolder(r); err != nil {
			return err
		} else if holder == "" {
			if err := waitForAdGuardDNS(r, timeout); err == nil {
				report.ServingDNS = true
				return nil
			}
		}
	}

	holder, err := portFiftyThreeHolder(r)
	if err != nil {
		return err
	}
	if holder != "" && !strings.Contains(holder, "AdGuard") && !strings.Contains(holder, "dnsmasq") {
		return fmt.Errorf("port 53 is held by %q, which is neither AdGuard nor dnsmasq, "+
			"so curfew will not touch it. Free port 53 and re-run", holder)
	}

	// Free the port. dnsmasq keeps DHCP and moves to 54, per ADR 0002. This is
	// checked against its CONFIGURED port as well as what is listening, since
	// a dnsmasq that is merely stopped would otherwise grab 53 back at the
	// next restart and knock AdGuard out again.
	// Only move a dnsmasq that is actually in the way. On a router with no
	// dnsmasq, or one already on another port, there is nothing to move.
	inTheWay, err := dnsmasqIsInTheWay(r)
	if err != nil {
		return err
	}
	if inTheWay {
		report.MovedDnsmasq = true
		before, err := moveDnsmasqTo54(r, opt.RouterIP)
		report.dhcpOptionsBefore = before
		if err != nil {
			return rollback(r, report, err)
		}
	}

	if _, err := r.Run(restartAdGuard()); err != nil {
		return rollback(r, report, fmt.Errorf("starting AdGuard: %w", err))
	}
	report.StartedAdGuard = !running
	if err := waitForAdGuardDNS(r, timeout); err != nil {
		return rollback(r, report, err)
	}
	if opt.RouterIP != "" {
		if err := resolvesThrough(opt.RouterIP, "example.com", 15*time.Second); err != nil {
			return rollback(r, report,
				fmt.Errorf("AdGuard holds port 53 but cannot resolve a name: %w", err))
		}
	}
	report.ServingDNS = true
	return nil
}

// rollback restores dnsmasq to port 53 so the household keeps a resolver, and
// reports both what went wrong and what was undone.
func rollback(r Runner, report *AdGuardReport, cause error) error {
	if !report.MovedDnsmasq {
		return cause
	}
	if err := restoreDnsmasqTo53(r, report.dhcpOptionsBefore); err != nil {
		return fmt.Errorf("%w.\n       WORSE: rolling dnsmasq back to port 53 also failed: %v.\n"+
			"       The household may have NO working DNS. Fix by hand: "+
			"uci set dhcp.@dnsmasq[0].port=53; uci commit dhcp; /etc/init.d/dnsmasq restart",
			cause, err)
	}
	report.RolledBack = true
	return fmt.Errorf("%w.\n       dnsmasq has been put back on port 53, so DNS still works, "+
		"but nothing is being filtered", cause)
}

// dnsSummary describes the DNS half for a person.
func (r AdGuardReport) dnsSummary() string {
	switch {
	case r.RolledBack:
		return "AdGuard is NOT filtering: dnsmasq was put back on port 53"
	case r.ServingDNS && r.MovedDnsmasq:
		return fmt.Sprintf("AdGuard now owns DNS on port 53 (dnsmasq moved to 54, still doing DHCP), "+
			"admin page on port %d", adguard.DefaultPort)
	case r.ServingDNS:
		return "AdGuard is serving DNS on port 53"
	default:
		return "AdGuard is NOT serving DNS"
	}
}
