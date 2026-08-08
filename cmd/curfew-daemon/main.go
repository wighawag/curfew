// Command curfew-daemon runs ON THE ROUTER. It owns the nftables ruleset
// and serves the device page.
//
// This is deliberately a SEPARATE binary from the laptop-side `curfew`
// tool, and the separation is a safety property rather than tidiness: the
// laptop tool cannot import this package's enforcement code, so running the
// wrong command on a laptop cannot rewrite that laptop's firewall.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	// The IANA database, embedded in the binary. OpenWrt ships no
	// /usr/share/zoneinfo, so without this Go cannot resolve a zone name at
	// all and time.Local silently becomes UTC. A parental control system
	// computing bedtime an hour out, and saying nothing, is exactly the class
	// of quiet wrongness this project exists to remove. Costs ~450 KB.
	_ "time/tzdata"

	"github.com/wighawag/curfew/internal/accounting"
	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/dnspolicy"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/httpui"
	"github.com/wighawag/curfew/internal/kernelprobe"
	"github.com/wighawag/curfew/internal/policy"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
	"github.com/wighawag/curfew/internal/shellrun"
)

// version is stamped at release time via -ldflags "-X main.version=<tag>".
// Without it the goreleaser ldflag is a silent no-op and there is no way to
// ask a router which build it is running, which is the first question worth
// asking when something is wrong on a box you reach over the network.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

type options struct {
	registryPath string
	profilesPath string
	statePath    string
	lan          string
	wan          string
	listen       string
	user         string
	password     string
	reconcile    time.Duration
	timezone     string
	// AdGuard credentials, for the per-profile DNS restrictions. Absent means
	// the whole DNS refinement is off, which degrades nothing else: schedules,
	// budgets, manual blocks and tickets are nftables on MAC and do not consult
	// AdGuard at all.
	adguardURL      string
	adguardUser     string
	adguardPassword string
	// listenIP is the address AdGuard will fetch curfew's filter list from. It
	// must be one the ROUTER can reach, since AdGuard does the fetching.
	routerIP string
}

// envOr lets every flag also come from the environment, which is how the
// service file passes configuration and how tests isolate state.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run(args []string, stderr *os.File) int {
	var opt options
	fs := flag.NewFlagSet("curfew-daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opt.registryPath, "registry", envOr("CURFEW_REGISTRY", "/etc/config/curfew/devices.json"),
		"path to the device registry")
	fs.StringVar(&opt.profilesPath, "profiles", envOr("CURFEW_PROFILES", "/etc/config/curfew/profiles.json"),
		"path to the profiles and schedules")
	fs.StringVar(&opt.statePath, "state", envOr("CURFEW_STATE", blockstate.DefaultPath),
		"path to the persisted block state (manual blocks, which must survive a reboot)")
	fs.StringVar(&opt.lan, "lan", envOr("CURFEW_LAN", "br-lan"), "LAN interface")
	fs.StringVar(&opt.wan, "wan", envOr("CURFEW_WAN", ""),
		"WAN interface (required: guessing it is how enforcement silently matches nothing)")
	fs.StringVar(&opt.listen, "listen", envOr("CURFEW_LISTEN", ":8080"), "HTTP listen address")
	fs.StringVar(&opt.user, "user", envOr("CURFEW_USER", "parent"), "HTTP basic auth username")
	fs.StringVar(&opt.password, "password", envOr("CURFEW_PASSWORD", ""),
		"HTTP basic auth password (empty disables authentication, with a warning)")
	fs.DurationVar(&opt.reconcile, "reconcile", time.Minute,
		"how often to re-check that the firewall still matches the registry, and "+
			"how often budget usage is accounted for")
	fs.StringVar(&opt.timezone, "timezone", envOr("CURFEW_TZ", ""),
		"IANA timezone for schedules, e.g. Europe/London (default: the system zone, which on OpenWrt is UTC)")
	fs.StringVar(&opt.adguardURL, "adguard", envOr("CURFEW_ADGUARD_URL", ""),
		"AdGuard admin API address, e.g. 127.0.0.1:3000 (empty disables per-profile DNS restrictions)")
	fs.StringVar(&opt.adguardUser, "adguard-user", envOr("CURFEW_ADGUARD_USER", "parent"),
		"AdGuard admin username")
	fs.StringVar(&opt.adguardPassword, "adguard-password", envOr("CURFEW_ADGUARD_PASSWORD", ""),
		"AdGuard admin password")
	fs.StringVar(&opt.routerIP, "router-ip", envOr("CURFEW_ROUTER_IP", "127.0.0.1"),
		"the address AdGuard should fetch curfew's filter list from")
	showVersion := fs.Bool("version", false, "print the version and exit")
	probe := fs.Bool("probe", false,
		"measure whether this KERNEL supports what tickets rely on, then exit. "+
			"Safe on a live router: it works in its own table with no chain and no hook")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	if *probe {
		return runProbe(stderr)
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("starting", "version", version)

	loc, err := resolveLocation(opt.timezone, log)
	if err != nil {
		log.Error("cannot resolve the timezone; refusing to start", "timezone", opt.timezone, "error", err)
		return 1
	}
	log.Info("schedules evaluated in", "zone", loc.String(),
		"local_time", time.Now().In(loc).Format("Mon 15:04 MST"))

	if opt.wan == "" {
		log.Error("no WAN interface configured; refusing to start",
			"hint", "pass -wan or set CURFEW_WAN (on a PPPoE line this is pppoe-wan, not eth1)")
		return 1
	}

	fw, err := enforce.New(enforce.Config{LANInterface: opt.lan, WANInterface: opt.wan})
	if err != nil {
		log.Error("cannot reach the firewall", "error", err)
		return 1
	}

	store := registry.FileStore{Path: opt.registryPath}
	sched := schedule.FileStore{Path: opt.profilesPath}
	state := blockstate.FileStore{Path: opt.statePath}
	if _, err := store.Load(); err != nil {
		log.Error("cannot read the registry", "path", opt.registryPath, "error", err)
		return 1
	}
	if _, err := sched.Load(); err != nil {
		// A schedule nobody can predict is worse than none, so refuse.
		log.Error("cannot read the schedule", "path", opt.profilesPath, "error", err)
		return 1
	}
	st, err := state.Load()
	if err != nil {
		// Carrying on with empty state would silently lift every manual block,
		// which is the exact thing persisting it exists to prevent.
		log.Error("cannot read the persisted block state", "path", opt.statePath, "error", err)
		return 1
	}
	if len(st.ManualBlocked) > 0 {
		log.Info("restoring manual blocks", "profiles", st.ManualBlocked)
	}
	if len(st.Budget) > 0 {
		log.Info("restoring budget usage", "day", st.BudgetDay, "profiles", len(st.Budget))
	}

	acct, err := accounting.New(accounting.Config{LANInterface: opt.lan, WANInterface: opt.wan})
	if err != nil {
		log.Error("cannot set up budget accounting", "error", err)
		return 1
	}

	profiles, err := sched.Load()
	if err != nil {
		log.Error("cannot read the schedule", "path", opt.profilesPath, "error", err)
		return 1
	}
	threshold := profiles.Budget.Threshold()
	core := policy.New(store, sched, state, fw, loc, log).
		WithAccounting(acct, opt.reconcile, threshold)
	if threshold == budget.DefaultActivityThreshold &&
		profiles.Budget.ActivityThresholdBytesPerMinute == 0 {
		// Said out loud, every start, because ADR 0001 requires this number to
		// be calibrated against real idle devices and the default is not. A
		// guessed constant presented as a measured one is how a budget comes to
		// feel arbitrary in a house.
		log.Warn("the activity threshold is the UNCALIBRATED default",
			"bytes_per_minute", threshold,
			"why_it_matters", "too low and an idle phone burns the allowance overnight; too high and light use is free",
			"how_to_fix", "watch the observed rates on the home page for an evening, then set budget_settings.activity_threshold_bytes_per_minute")
	}

	// Enforce BEFORE serving. Coming up with the page available but the
	// ruleset unapplied is precisely the state that lies about being in
	// control, so a failure here is fatal rather than logged and ignored.
	//
	// This is also the boot restore: the desired state it applies includes the
	// manual blocks read back off disk, so a reboot cannot hand a grounded
	// child their internet back.
	if err := core.Tick(); err != nil {
		log.Error("cannot apply the ruleset; refusing to start", "error", err)
		return 1
	}
	log.Info("ruleset applied", "lan", opt.lan, "wan", opt.wan)

	if opt.password == "" {
		log.Warn("NO PASSWORD SET: the device page is unauthenticated",
			"why_it_matters", "blocking applies to forwarded traffic, so a device kept off the internet can still reach this page and allow itself")
	}

	// The DNS refinement: per-profile, time-windowed restrictions in AdGuard,
	// plus the static DHCP leases that give it something to key on. Set up
	// BEFORE the HTTP server, because the server has to serve the filter list
	// AdGuard will fetch.
	dns := setUpDNSRestrictions(opt, sched, store, loc, log)

	ui := httpui.New(store, sched, fw, core, log, opt.user, opt.password, loc)
	if dns != nil {
		ui.ServeFilterList(dnspolicy.FilterListPath, dns.FilterList)
		// So the settings page can offer AdGuard's own service catalogue
		// instead of a list compiled into curfew that drifts from it.
		ui.UseAdGuardServices(dns.Services)
	}
	srv := &http.Server{
		Addr:              opt.listen,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go reconcileLoop(ctx, log, core, opt.reconcile)
	if dns != nil {
		go dnsLoop(ctx, log, dns, opt.reconcile)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("serving", "addr", opt.listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Error("http server failed", "error", err)
		return 1
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "error", err)
		return 1
	}
	// The ruleset is deliberately LEFT IN PLACE on exit. Stopping the daemon
	// must not open the household's internet; removing policy is what the
	// panic path is for, and it is an explicit choice rather than a side
	// effect of a process dying.
	return 0
}

// runProbe measures the kernel and prints what it found.
//
// It deliberately does not start the daemon, read any config or touch the
// enforcement table, so it can be run on a live router at any time to answer
// "is this board still one where tickets work?". That question stops being
// answered by the test suite the moment the hardware or the firmware changes,
// because the suite runs against the kernel of whatever machine builds it.
func runProbe(stderr *os.File) int {
	report, err := kernelprobe.Run()
	if err != nil {
		// Could not complete, which is NOT the same as a fact being false, so
		// it gets its own exit code rather than being printed as a failure.
		fmt.Fprintf(stderr, "curfew-daemon -probe: %v\n", err)
		fmt.Fprintln(stderr, "the probe could not finish, so this says NOTHING about the kernel")
		return 2
	}
	fmt.Print(report.String())
	left, err := kernelprobe.Present()
	if err == nil && left {
		fmt.Fprintf(stderr, "WARNING: the probe table is still present. Remove it with: nft delete table inet %s\n",
			kernelprobe.TableName)
		return 3
	}
	if !report.OK() {
		return 1
	}
	return 0
}

// resolveLocation picks the zone schedules are evaluated in.
//
// It refuses an unknown zone rather than falling back, because falling back
// means running everyone's bedtime an hour out with nothing said. When no zone
// is configured it warns, since the system default on this platform is UTC and
// that is almost never what a household means.
func resolveLocation(name string, log *slog.Logger) (*time.Location, error) {
	if name == "" {
		now := time.Now()
		if zone, _ := now.Zone(); zone == "UTC" {
			log.Warn("NO TIMEZONE SET: schedules will be evaluated in UTC",
				"why_it_matters", "a 22:00 bedtime fires at 22:00 UTC, which is an hour out in British summer time",
				"fix", "pass -timezone Europe/London, or reinstall so the router's own zone is picked up")
		}
		return time.Local, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, err
	}
	return loc, nil
}

// reconcileLoop re-asserts the desired state onto the firewall whenever the
// two have drifted. This is the level-triggered discipline the design rests
// on: a missed moment, a crash mid-write, or something else clobbering the
// table all self-heal on the next pass, instead of leaving a state nothing
// corrects.
func reconcileLoop(ctx context.Context, log *slog.Logger, core *policy.Core, every time.Duration) {
	if every <= 0 {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Tick, not Reconcile: this is the one caller that also MEASURES.
			// The UI's own reconciles must not advance the budget, or a parent
			// tapping buttons would burn a child's afternoon.
			if err := core.Tick(); err != nil {
				log.Error("reconcile failed", "error", err)
			}
		}
	}
}

// setUpDNSRestrictions wires the per-profile DNS refinement, or explains why it
// is off and returns nil.
//
// Returning nil is a first-class outcome rather than a failure. The refinement
// is the ONLY thing that depends on AdGuard, and losing it costs a household
// "no streaming between 08:00 and 10:00" while bedtime, budgets, manual blocks
// and tickets carry on untouched, because those are nftables on MAC. Refusing
// to start over it would trade a working household for a missing feature.
//
// It is also the upgrade path. `curfew update` deliberately never rewrites
// daemon.conf, so a router installed before this feature existed has no AdGuard
// credentials in that file and will land here. Saying so plainly, with the fix,
// is the whole mitigation.
func setUpDNSRestrictions(opt options, sched schedule.FileStore, store registry.FileStore,
	loc *time.Location, log *slog.Logger) *dnspolicy.Manager {

	if opt.adguardURL == "" || opt.adguardPassword == "" {
		log.Warn("per-profile DNS restrictions are OFF: no AdGuard credentials configured",
			"what_still_works", "schedules, budgets, manual blocks, tickets and the MAC allowlist, "+
				"none of which use AdGuard",
			"what_does_not", "per-profile website and service restrictions",
			"how_to_fix", "re-run 'curfew install' from your laptop, which writes the AdGuard "+
				"settings into "+deployDaemonConf+"; 'curfew update' deliberately leaves that file alone")
		return nil
	}
	ps, err := sched.Load()
	if err == nil && !ps.AnyRestrictions() {
		// Said out loud so "AdGuard is wired up" is never confused with
		// "something is being restricted". An integration that manages nothing
		// looks identical from outside to one that is broken.
		log.Info("AdGuard is configured but no profile has any DNS restrictions, " +
			"so curfew will create no AdGuard objects")
	}

	api := adguard.NewClient(opt.adguardURL, opt.adguardUser, opt.adguardPassword)
	listURL := fmt.Sprintf("http://%s%s", net.JoinHostPort(opt.routerIP, listenPort(opt.listen)),
		dnspolicy.FilterListPath)
	log.Info("per-profile DNS restrictions are on",
		"adguard", opt.adguardURL, "filter_list", listURL)

	return dnspolicy.NewManager(dnspolicy.Config{
		Registry: store, Schedule: sched, Runner: shellrun.Local{}, API: api,
		ListURL: listURL, LANInterface: opt.lan, Location: loc, Log: log,
		// The daemon runs on the router, so it can ask the kernel whether
		// AdGuard can afford a filter-engine rebuild before causing one. It
		// could not, once, and the house lost DNS for it.
		Headroom: dnspolicy.RouterHeadroom(),
	})
}

// deployDaemonConf is where the settings file lives on the router. Stated here
// rather than imported, because the daemon must not depend on the laptop-side
// deploy package (see separation_test.go); it is only ever printed.
const deployDaemonConf = "/etc/config/curfew/daemon.conf"

// listenPort extracts the port from a listen address like ":8080".
func listenPort(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil && port != "" {
		return port
	}
	return "8080"
}

// dnsLoop re-asserts the DNS refinement on the same cadence as the firewall.
//
// It runs on a tick rather than only on action, which ADR 0010 reserved for
// AdGuard, and the reason it is safe is SCOPE rather than frequency: every
// write it makes is to an object curfew created and named, so a household
// editing its own AdGuard rules, lists or clients is never fought. See the
// package comment on internal/dnspolicy.
//
// A failure is logged and the loop continues. This is the fail-open half of
// the safety property: the refinement going quiet must never take the
// load-bearing controls down with it.
func dnsLoop(ctx context.Context, log *slog.Logger, m *dnspolicy.Manager, every time.Duration) {
	if every <= 0 {
		return
	}
	if err := m.Tick(); err != nil {
		log.Error("DNS restrictions could not be applied; the firewall is unaffected", "error", err)
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Tick(); err != nil {
				log.Error("DNS restrictions could not be applied; the firewall is unaffected",
					"error", err)
			}
		}
	}
}
