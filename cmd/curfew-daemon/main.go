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

	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/httpui"
	"github.com/wighawag/curfew/internal/registry"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

type options struct {
	registryPath string
	lan          string
	wan          string
	listen       string
	user         string
	password     string
	reconcile    time.Duration
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
	fs.StringVar(&opt.lan, "lan", envOr("CURFEW_LAN", "br-lan"), "LAN interface")
	fs.StringVar(&opt.wan, "wan", envOr("CURFEW_WAN", ""),
		"WAN interface (required: guessing it is how enforcement silently matches nothing)")
	fs.StringVar(&opt.listen, "listen", envOr("CURFEW_LISTEN", ":8080"), "HTTP listen address")
	fs.StringVar(&opt.user, "user", envOr("CURFEW_USER", "parent"), "HTTP basic auth username")
	fs.StringVar(&opt.password, "password", envOr("CURFEW_PASSWORD", ""),
		"HTTP basic auth password (empty disables authentication, with a warning)")
	fs.DurationVar(&opt.reconcile, "reconcile", time.Minute,
		"how often to re-check that the firewall still matches the registry")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

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
	reg, err := store.Load()
	if err != nil {
		log.Error("cannot read the registry", "path", opt.registryPath, "error", err)
		return 1
	}

	// Enforce BEFORE serving. Coming up with the page available but the
	// ruleset unapplied is precisely the state that lies about being in
	// control, so a failure here is fatal rather than logged and ignored.
	if err := fw.Apply(reg.MACs()); err != nil {
		log.Error("cannot apply the ruleset; refusing to start", "error", err)
		return 1
	}
	log.Info("ruleset applied", "devices", len(reg.MACs()), "lan", opt.lan, "wan", opt.wan)

	if opt.password == "" {
		log.Warn("NO PASSWORD SET: the device page is unauthenticated",
			"why_it_matters", "blocking applies to forwarded traffic, so a device kept off the internet can still reach this page and allow itself")
	}

	srv := &http.Server{
		Addr:              opt.listen,
		Handler:           httpui.New(store, fw, log, opt.user, opt.password).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go reconcileLoop(ctx, log, store, fw, opt.reconcile)

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

// reconcileLoop re-asserts the registry onto the firewall whenever the two
// have drifted. This is the level-triggered discipline the design rests on: a
// missed moment, a crash mid-write, or something else clobbering the table all
// self-heal on the next pass, instead of leaving a state nothing corrects.
func reconcileLoop(ctx context.Context, log *slog.Logger, store registry.FileStore, fw *enforce.Enforcer, every time.Duration) {
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
			if err := reconcileOnce(store, fw); err != nil {
				log.Error("reconcile failed", "error", err)
			}
		}
	}
}

// reconcileOnce applies the registry only when the firewall disagrees with it,
// so a steady state costs one read rather than a ruleset rewrite every tick.
func reconcileOnce(store registry.FileStore, fw *enforce.Enforcer) error {
	reg, err := store.Load()
	if err != nil {
		return fmt.Errorf("reading registry: %w", err)
	}
	if _, err := fw.EnsureApplied(reg.MACs()); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}
	return nil
}
