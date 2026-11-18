package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// `curfew push` refuses to send a field to a daemon that does not list it here,
// because that daemon's page would drop it on its next save. So the list is a
// promise, and each entry is asserted by running the flag for real.
func TestFeaturesListsEveryRegistryFieldThisDaemonUnderstands(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	code := run([]string{"-features"}, os.Stderr)
	os.Stdout = saved
	w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if code != 0 {
		t.Fatalf("-features exited %d", code)
	}
	got := strings.Fields(buf.String())
	for _, want := range []string{"fixed-address", "local-dns-names"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("-features does not list %q: %v", want, got)
		}
	}
}

// Shutdown waits for a pass in flight (up to the grace) so a DHCP
// transaction is not cut between its commit and its reload.
func TestShutdownWaitsForAPassInFlight(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { time.Sleep(300 * time.Millisecond); wg.Done() }()
	start := time.Now()
	if !waitFor(&wg, 5*time.Second) {
		t.Fatal("a pass that finished in 300ms was reported as still running")
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Error("shutdown did not wait for the pass")
	}
	var stuck sync.WaitGroup
	stuck.Add(1)
	if waitFor(&stuck, 100*time.Millisecond) {
		t.Error("a pass that never finishes must not be reported finished")
	}
	stuck.Done()
}

// The order matters and the wait is never skipped: the pass in flight is
// waited for first, and an HTTP shutdown that fails cannot skip that wait.
func TestShutdownWaitsForThePassBeforeClosingHTTPEvenWhenHTTPFails(t *testing.T) {
	var order []string
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	code := shutdown(
		func() bool { order = append(order, "wait"); return true },
		func() error { order = append(order, "http"); return errors.New("timed out") },
		log, 0)
	if strings.Join(order, ",") != "wait,http" {
		t.Errorf("want the pass waited for before HTTP closes, got %v", order)
	}
	if code != 1 {
		t.Errorf("a failed HTTP shutdown must still report failure, got %d", code)
	}
}
