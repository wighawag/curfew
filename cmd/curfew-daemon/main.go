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

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/httpui"
	"github.com/wighawag/curfew/internal/policy"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
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
		"how often to re-check that the firewall still matches the registry")
	fs.StringVar(&opt.timezone, "timezone", envOr("CURFEW_TZ", ""),
		"IANA timezone for schedules, e.g. Europe/London (default: the system zone, which on OpenWrt is UTC)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Println(version)
		return 0
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

	core := policy.New(store, sched, state, fw, loc, log)

	// Enforce BEFORE serving. Coming up with the page available but the
	// ruleset unapplied is precisely the state that lies about being in
	// control, so a failure here is fatal rather than logged and ignored.
	//
	// This is also the boot restore: the desired state it applies includes the
	// manual blocks read back off disk, so a reboot cannot hand a grounded
	// child their internet back.
	if err := core.Reconcile(); err != nil {
		log.Error("cannot apply the ruleset; refusing to start", "error", err)
		return 1
	}
	log.Info("ruleset applied", "lan", opt.lan, "wan", opt.wan)

	if opt.password == "" {
		log.Warn("NO PASSWORD SET: the device page is unauthenticated",
			"why_it_matters", "blocking applies to forwarded traffic, so a device kept off the internet can still reach this page and allow itself")
	}

	srv := &http.Server{
		Addr:              opt.listen,
		Handler:           httpui.New(store, sched, fw, core, log, opt.user, opt.password, loc).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go reconcileLoop(ctx, log, core, opt.reconcile)

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
			if err := core.Reconcile(); err != nil {
				log.Error("reconcile failed", "error", err)
			}
		}
	}
}
