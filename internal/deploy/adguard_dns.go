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

// dnsmasqPort reads the port dnsmasq is configured to use.
func dnsmasqPort(r Runner) (string, error) {
	out, err := r.Run("uci get dhcp.@dnsmasq[0].port 2>/dev/null || echo 53")
	if err != nil {
		return "", err
	}
	port := strings.TrimSpace(out)
	if port == "" {
		// An unset port means dnsmasq's default, which is 53.
		port = "53"
	}
	return port, nil
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

// moveDnsmasqTo54 frees port 53 for AdGuard and points DHCP at the router for
// DNS, which is the arrangement ADR 0002 describes. dnsmasq keeps DHCP.
func moveDnsmasqTo54(r Runner, routerIP string) error {
	for _, cmd := range []string{
		"uci set dhcp.@dnsmasq[0].port=54",
		"uci -q delete dhcp.lan.dhcp_option",
		fmt.Sprintf("uci add_list dhcp.lan.dhcp_option='6,%s'", routerIP),
		"uci commit dhcp",
		"/etc/init.d/dnsmasq restart",
	} {
		if _, err := r.Run(cmd); err != nil {
			return fmt.Errorf("moving dnsmasq to port 54 (%s): %w", cmd, err)
		}
	}
	return nil
}

// restoreDnsmasqTo53 is the ROLLBACK, and it is why taking port 53 is safe to
// attempt at all.
//
// If AdGuard cannot serve DNS after dnsmasq has stepped aside, the household
// has no resolver at all, which is a real outage rather than a degraded
// feature. So every failure path after the move calls this, and the house ends
// up where it started: dnsmasq answering, nothing filtered.
func restoreDnsmasqTo53(r Runner) error {
	for _, cmd := range []string{
		"uci set dhcp.@dnsmasq[0].port=53",
		"uci -q delete dhcp.lan.dhcp_option",
		"uci commit dhcp",
		"/etc/init.d/dnsmasq restart",
	} {
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

// takeOverDNS makes AdGuard the household's resolver, and puts everything back
// if it cannot.
func takeOverDNS(r Runner, opt AdGuardOptions, report *AdGuardReport) error {
	timeout := opt.DNSTimeout
	if timeout <= 0 {
		timeout = DefaultDNSTimeout
	}

	serving, err := adGuardServesDNS(r)
	if err != nil {
		return err
	}
	if serving {
		report.ServingDNS = true
		return nil
	}

	holder, err := portFiftyThreeHolder(r)
	if err != nil {
		return err
	}
	// Nothing is holding port 53 yet. AdGuard may simply still be starting: it
	// loads its blocklists before binding, which took 43 seconds on the real
	// router. Concluding "conflict" here and moving dnsmasq would be acting on
	// a race rather than on a fact.
	if holder == "" {
		if err := waitForAdGuardDNS(r, timeout); err == nil {
			report.ServingDNS = true
			return nil
		}
		if holder, err = portFiftyThreeHolder(r); err != nil {
			return err
		}
	}

	port, err := dnsmasqPort(r)
	if err != nil {
		return err
	}
	if port != "53" && holder != "" && !strings.Contains(holder, "dnsmasq") {
		return fmt.Errorf("port 53 is held by %q, which is neither AdGuard nor dnsmasq, "+
			"so curfew will not touch it. Free port 53 and re-run", holder)
	}

	if port == "53" {
		report.MovedDnsmasq = true
		if err := moveDnsmasqTo54(r, opt.RouterIP); err != nil {
			return err
		}
	}
	if _, err := r.Run(restartAdGuard()); err != nil {
		return rollback(r, report, fmt.Errorf("restarting AdGuard: %w", err))
	}
	if err := waitForAdGuardDNS(r, timeout); err != nil {
		return rollback(r, report, err)
	}
	// Bound is not the same as working. Ask it to resolve something.
	if opt.RouterIP != "" {
		if err := resolvesThrough(opt.RouterIP, "example.com", 10*time.Second); err != nil {
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
	if err := restoreDnsmasqTo53(r); err != nil {
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
