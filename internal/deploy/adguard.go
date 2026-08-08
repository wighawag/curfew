package deploy

import (
	"fmt"
	"strings"
	"time"

	"github.com/wighawag/curfew/internal/adguard"
)

// AdGuard setup, over ssh, in two modes that are deliberately kept apart:
// INSTALL when the router has none, and ADOPT when it already does.
//
// Adoption exists because plenty of people install AdGuard themselves, and
// replacing their configuration to "manage" it would destroy the exceptions
// and lists they built up. So adoption changes exactly one thing, and only
// when it is missing: an admin account.
//
// That one thing is not a nicety. Measured on v0.107.78, an AdGuard with
// `users: []` serves its entire REST API unauthenticated: a plain
// POST /control/protection {"enabled":false} returns 200 OK and turns off all
// filtering for the household. legacy/scripts/setup-adguard.sh ships exactly
// that, so any router set up with it is one HTTP request away from having no
// DNS filtering, and the request can come from the device being filtered.

// AdGuardOptions configures the AdGuard half of an install.
type AdGuardOptions struct {
	// Enabled is false when the operator passed -no-adguard.
	Enabled bool
	// User and Password are the admin account. Password is REQUIRED when
	// Enabled, because the whole point is that the API stops being open.
	User     string
	Password string
	// RouterIP is the address the admin page will be reached on, used for the
	// API and for what gets printed at the end.
	RouterIP string
	// DNSTimeout bounds how long to wait for AdGuard to take over port 53.
	// Zero means DefaultDNSTimeout. It is a field rather than a constant
	// because AdGuard loads its blocklists before binding (43 seconds on the
	// real router), so the honest wait is long enough to make a test that
	// exercises the failure path unbearable at full length.
	DNSTimeout time.Duration
}

// DefaultDNSTimeout is how long AdGuard gets to take over port 53. Generous on
// purpose: measured on the live router, it served its admin API two seconds
// after starting and only attempted the DNS bind 43 seconds later.
const DefaultDNSTimeout = 2 * time.Minute

// AdGuardReport says what happened, in terms a person can check.
type AdGuardReport struct {
	// Skipped is set when -no-adguard was passed or AdGuard was left alone.
	Skipped bool
	Reason  string
	// Installed is true when curfew put AdGuard there; Adopted when it found
	// one already running.
	Installed bool
	Adopted   bool
	// SecuredNow is true when this run closed an open API.
	SecuredNow bool
	// AlreadySecured is true when an admin account was already configured, in
	// which case curfew changed nothing about authentication.
	AlreadySecured bool
	// Version is what the running AdGuard reports, read back rather than
	// assumed.
	Version string
	// Verified records that an unauthenticated request was REFUSED and an
	// authenticated one accepted, both measured after the change.
	Verified bool
	// ServingDNS records that AdGuard actually holds port 53 and resolves.
	// Kept separate from Verified because the two were measured to disagree:
	// AdGuard serves its admin API about two seconds after starting and only
	// attempts the DNS bind about forty-three seconds later, so a run can pass
	// every authentication check and still be filtering nothing.
	ServingDNS bool
	// MovedDnsmasq records that dnsmasq was moved to port 54 to free 53.
	MovedDnsmasq bool
	// RolledBack records that the attempt failed and dnsmasq was put back, so
	// the household still has a resolver and nothing is filtered.
	RolledBack bool
	// EnabledService records that AdGuard had no boot-time symlink and now
	// does.
	EnabledService bool
	// StartedAdGuard records that AdGuard was not running at all and was
	// started. A crash-looped AdGuard that procd has given up on presents
	// exactly like a stopped one, and both must be recoverable.
	StartedAdGuard bool
}

// Summary renders the report for a terminal.
func (r AdGuardReport) Summary() string {
	if r.Skipped {
		return "AdGuard: skipped (" + r.Reason + ")"
	}
	var head string
	switch {
	case r.Installed:
		head = fmt.Sprintf("AdGuard: installed %s, API authenticated", r.Version)
	case r.SecuredNow:
		head = fmt.Sprintf("AdGuard: adopted %s and CLOSED ITS OPEN API "+
			"(it was answering every request on the LAN without a password)", r.Version)
	case r.AlreadySecured:
		head = fmt.Sprintf("AdGuard: adopted %s, which already had an admin account", r.Version)
	default:
		head = "AdGuard: nothing to do"
	}
	extra := []string{r.dnsSummary()}
	if r.EnabledService {
		extra = append(extra, "enabled it to start at boot")
	}
	return head + "\n         " + strings.Join(extra, "\n         ")
}

// adGuardPresent reports whether the binary is on the router at all.
func adGuardPresent(r Runner) (bool, error) {
	out, err := r.Run(fmt.Sprintf("[ -x %s ] && echo yes || echo no", adguard.BinaryPath))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}

// SetupAdGuard makes AdGuard present and authenticated, or explains why it did
// not.
//
// It NEVER rewrites an existing configuration. The only edit it will make to a
// config it did not create is inserting an admin account into an empty users
// list, and internal/adguard.EnsureUser refuses to do even that when an
// account already exists.
func SetupAdGuard(r Runner, opt AdGuardOptions) (AdGuardReport, error) {
	if !opt.Enabled {
		return AdGuardReport{Skipped: true, Reason: "-no-adguard was passed"}, nil
	}
	if strings.TrimSpace(opt.Password) == "" {
		return AdGuardReport{}, fmt.Errorf(
			"an AdGuard admin password is required: without one AdGuard serves its whole API " +
				"to any device on the LAN, including the ones being filtered. " +
				"Pass -adguard-password, or -password to set both, or -no-adguard to skip AdGuard")
	}
	if opt.User == "" {
		opt.User = adguard.DefaultUser
	}

	present, err := adGuardPresent(r)
	if err != nil {
		return AdGuardReport{}, err
	}
	if !present {
		return installAdGuard(r, opt)
	}
	return adoptAdGuard(r, opt)
}

// adoptAdGuard takes over an AdGuard that is already on the router.
func adoptAdGuard(r Runner, opt AdGuardOptions) (AdGuardReport, error) {
	report := AdGuardReport{Adopted: true}

	config, err := r.Run("cat " + adguard.ConfigPath + " 2>/dev/null || true")
	if err != nil {
		return report, err
	}
	if strings.TrimSpace(config) == "" {
		return report, fmt.Errorf("AdGuard is installed but %s is empty or unreadable, "+
			"so curfew will not guess at it. Finish AdGuard's own setup first", adguard.ConfigPath)
	}

	configChanged := false
	switch adguard.InspectUsers([]byte(config)) {
	case adguard.UsersPresent:
		report.AlreadySecured = true
	case adguard.UsersUnknown:
		return report, fmt.Errorf("cannot find a top-level 'users:' key in %s, so curfew will "+
			"not edit it. Set a password in AdGuard's own UI and re-run", adguard.ConfigPath)
	default:
		hash, err := adguard.HashPassword(opt.Password)
		if err != nil {
			return report, err
		}
		edited, changed, err := adguard.EnsureUser([]byte(config), opt.User, hash)
		if err != nil {
			return report, err
		}
		if !changed {
			return report, fmt.Errorf("the AdGuard config was not changed, so its API is still open")
		}
		// Keep a copy of what was there before. This edit is the one place
		// curfew writes to a file AdGuard owns, and a backup costs nothing
		// against the cost of getting it wrong on a live router.
		if _, err := r.Run(fmt.Sprintf("cp %s %s.curfew-backup", adguard.ConfigPath, adguard.ConfigPath)); err != nil {
			return report, fmt.Errorf("backing up the AdGuard config: %w", err)
		}
		if err := uploadString(r, string(edited), adguard.ConfigPath, "AdGuard config"); err != nil {
			return report, err
		}
		configChanged = true
		report.SecuredNow = true
	}

	// Make it survive a reboot. Found missing on the live router: the init
	// script was there but had no rc.d symlink, so a power cut would have left
	// the household with no AdGuard at all.
	enabled, err := ensureServiceEnabled(r)
	if err != nil {
		return report, err
	}
	report.EnabledService = enabled

	// Get it RUNNING and owning DNS first. Verifying the admin API before
	// port 53 is free is doomed on a router where dnsmasq holds it: AdGuard
	// serves its API for about 43 seconds and then exits on the failed bind,
	// so the check would pass and the process would die. This also covers an
	// AdGuard that is simply stopped, which is what a crash loop procd has
	// given up on looks like.
	if err := takeOverDNS(r, opt, &report, configChanged); err != nil {
		return report, err
	}

	// Only now verify against the RUNNING server. A config with a user in it
	// that AdGuard has not reloaded is still an open API, and what a child on
	// the LAN meets is the server, not the file.
	if err := verifyAdGuard(r, opt, &report); err != nil {
		return report, err
	}
	return report, nil
}

// verifyAdGuard proves that an unauthenticated request is REFUSED and an
// authenticated one is accepted.
//
// Both halves are required. Checking only that our password works would pass
// against a completely open server, because an open AdGuard accepts
// credentials and cheerfully ignores them; checking only the refusal would
// pass against one that is simply broken.
//
// The check runs from HERE over the network rather than by shelling a fetcher
// on the router. That is not a preference: the OpenWrt image's wget is
// uclient-fetch, which fails these requests outright ("Operation not
// permitted") and does not replay a body after a 401, both recorded traps in
// this repo. It is also the more faithful test, since it is the same request a
// browser or a child's phone would make.
//
// When AdGuard cannot be reached from here at all, this REFUSES to report
// success. An unverifiable security fix reported as done is the exact class of
// lie this project exists to remove.
func verifyAdGuard(_ Runner, opt AdGuardOptions, report *AdGuardReport) error {
	addr := opt.RouterIP
	if addr == "" {
		addr = "127.0.0.1"
	}
	client := adguard.NewClient(fmt.Sprintf("%s:%d", addr, adguard.DefaultPort), opt.User, opt.Password)

	// Wait briefly: a restart takes a moment to bind. Bounded by a DEADLINE
	// rather than by an attempt count, because each attempt carries its own
	// HTTP timeout and the two multiply: thirty attempts of ten seconds is
	// five minutes of apparent hang, which is what this loop did at first.
	var reachable bool
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if client.Reachable() {
			reachable = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !reachable {
		return fmt.Errorf("AdGuard's admin API at %s:%d cannot be reached from here, so curfew "+
			"CANNOT confirm its API is authenticated.\n"+
			"       If AdGuard binds only to localhost on your router, check it there with:\n"+
			"         ssh <host> \"wget -qO- http://127.0.0.1:%d/control/status\"\n"+
			"       An answer containing a version means the API is still open to the LAN",
			addr, adguard.DefaultPort, adguard.DefaultPort)
	}

	secured, err := client.Secured()
	if err != nil {
		return err
	}
	if !secured {
		return fmt.Errorf("AdGuard at %s:%d is STILL answering unauthenticated requests, so any "+
			"device on the LAN can turn filtering off for the household. Its config was changed "+
			"but the running server has not picked it up; restart it and re-run",
			addr, adguard.DefaultPort)
	}
	status, err := client.Status()
	if err != nil {
		return fmt.Errorf("AdGuard refused the admin credentials after setup: %w", err)
	}
	report.Version = status.Version
	report.Verified = true
	return nil
}

// installAdGuard puts AdGuard on a router that has none.
//
// The admin account is written into the config BEFORE AdGuard is ever
// started, so the open-API window never exists at all. The legacy script wrote
// `users: []` and left it open permanently; here there is no moment, however
// brief, when a device on the LAN could turn filtering off.
func installAdGuard(r Runner, opt AdGuardOptions) (AdGuardReport, error) {
	report := AdGuardReport{Installed: true}
	hash, err := adguard.HashPassword(opt.Password)
	if err != nil {
		return report, err
	}

	arch, err := r.Run("uname -m")
	if err != nil {
		return report, err
	}
	aghArch, err := adguard.ArchFor(strings.TrimSpace(arch))
	if err != nil {
		return report, err
	}

	if _, err := r.Run("mkdir -p /opt/AdGuardHome"); err != nil {
		return report, err
	}
	// Download only when the binary is genuinely absent. This is also what
	// makes the rest of this function exercisable in the test image, which
	// ships AdGuard already.
	dl := fmt.Sprintf(
		"[ -x %s ] || (wget -q -O /tmp/agh.tar.gz "+
			"https://static.adguard.com/adguardhome/release/AdGuardHome_linux_%s.tar.gz && "+
			"tar -xzf /tmp/agh.tar.gz -C /opt && rm -f /tmp/agh.tar.gz)",
		adguard.BinaryPath, aghArch)
	if _, err := r.Run(dl); err != nil {
		return report, fmt.Errorf("downloading AdGuard for %s: %w", aghArch, err)
	}
	if ok, err := adGuardPresent(r); err != nil {
		return report, err
	} else if !ok {
		return report, fmt.Errorf("AdGuard is still not present at %s after the download step",
			adguard.BinaryPath)
	}

	conf := adguard.InitialConfig(adguard.ConfigParams{
		User: opt.User, PasswordHash: hash, RouterIP: opt.RouterIP,
	})
	if err := uploadString(r, conf, adguard.ConfigPath, "AdGuard config"); err != nil {
		return report, err
	}
	if _, err := r.Run("chmod 600 " + adguard.ConfigPath); err != nil {
		return report, err
	}
	if err := uploadString(r, adguard.InitScript(), "/etc/init.d/adguardhome", "AdGuard init script"); err != nil {
		return report, err
	}
	if _, err := r.Run("chmod +x /etc/init.d/adguardhome"); err != nil {
		return report, err
	}

	// dnsmasq moving to port 54 is NOT done here. takeOverDNS below owns it,
	// because it is the step that can leave the household with no resolver at
	// all and it therefore needs the rollback.
	if _, err := r.Run(restartAdGuard()); err != nil {
		return report, err
	}

	enabled, err := ensureServiceEnabled(r)
	if err != nil {
		return report, err
	}
	report.EnabledService = enabled
	if err := takeOverDNS(r, opt, &report, true); err != nil {
		return report, err
	}
	if err := verifyAdGuard(r, opt, &report); err != nil {
		return report, err
	}
	return report, nil
}

// restartAdGuard restarts AdGuard whichever way this router runs it.
//
// The procd service is preferred, and it is what exists when curfew or the
// legacy script installed AdGuard. An AdGuard somebody installed by hand may
// have no service at all, and an earlier version of this command then killed
// AdGuard and never started it again: adoption took the household's DNS down
// while reporting that it had secured it. Verifying against the running
// server rather than the config file is what caught that.
//
// nohup does NOT exist in OpenWrt's busybox (measured: "sh: nohup: not
// found"), so detaching uses setsid where available and a plain background
// subshell otherwise. All three descriptors are redirected either way, because
// a child holding the ssh session's stdout open hangs the command.
func restartAdGuard() string {
	run := fmt.Sprintf("%s -c %s -w /opt/AdGuardHome --no-check-update",
		adguard.BinaryPath, adguard.ConfigPath)
	return fmt.Sprintf(`if [ -x /etc/init.d/adguardhome ]; then
  /etc/init.d/adguardhome restart
else
  killall AdGuardHome 2>/dev/null
  sleep 1
  if command -v setsid >/dev/null 2>&1; then L=setsid; else L=; fi
  ( $L %s >/dev/null 2>&1 </dev/null & )
fi
true`, run)
}
