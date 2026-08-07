package blockstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMissingFileIsEmptyStateSoAFirstRunNeedsNoBootstrap(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err != nil {
		t.Fatalf("a missing state file must not be an error: %v", err)
	}
	if len(s.ManualBlocked) != 0 {
		t.Errorf("want empty state, got %+v", s)
	}
}

// A file that exists but cannot be parsed must NOT read as "nobody is
// blocked". That would lift every manual block at the quietest possible
// moment, which is the failure this file exists to prevent.
func TestACorruptFileIsAnErrorRatherThanAnEmptyBlocklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"manual_blocked": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err == nil {
		t.Fatalf("a half-written state file must be refused, got %+v", s)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error should name the file, got %q", err)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"tia", "eli"}}); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsBlocked("eli") || !got.IsBlocked("tia") {
		t.Errorf("both profiles should come back blocked, got %+v", got)
	}
	if got.IsBlocked("dad") {
		t.Error("nobody else should be blocked")
	}
	// Sorted on the way in and out, so the file does not churn on every write
	// and a diff means something changed.
	if got.ManualBlocked[0] != "eli" {
		t.Errorf("want a stable order, got %v", got.ManualBlocked)
	}
}

func TestSaveCreatesTheDirectoryAndLeavesNoTempFileBehind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "curfew")
	path := filepath.Join(dir, "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"eli"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("an atomic write must leave exactly the state file, got %v", names)
	}
}

// Each operation touches exactly the reason it owns, which is the whole point
// of the reason set in ADR 0006.
func TestUnblockRemovesOnlyThatProfile(t *testing.T) {
	s := &State{}
	if !s.Block("eli") {
		t.Error("blocking a fresh profile must report a change")
	}
	if s.Block("eli") {
		t.Error("blocking twice must report no change, so nothing is rewritten")
	}
	s.Block("tia")
	if !s.Unblock("eli") {
		t.Error("unblocking must report a change")
	}
	if s.IsBlocked("eli") {
		t.Error("eli should be free")
	}
	if !s.IsBlocked("tia") {
		t.Error("unblocking eli must not touch tia")
	}
	if s.Unblock("nobody") {
		t.Error("unblocking a profile that was not blocked must report no change")
	}
}

// The location is load-bearing, not incidental: /etc/config/ is the only
// directory OpenWrt's sysupgrade preserves (measured; see
// work/notes/findings/openwrt-etc-config-preserved-across-sysupgrade.md).
// Anywhere else and a firmware upgrade silently frees every grounded child.
func TestTheDefaultPathIsWhereASysupgradePreservesIt(t *testing.T) {
	const keep = "/etc/config/"
	if !strings.HasPrefix(DefaultPath, keep) {
		t.Errorf("DefaultPath = %q, but only %s survives a sysupgrade", DefaultPath, keep)
	}
}

// The suite must never write to the real location. A test that quietly edited
// /etc/config/curfew/state.json would be editing a live router's state on a
// developer machine, and would also pass for the wrong reason.
func TestTheSuiteNeverTouchesTheRealStateFile(t *testing.T) {
	before, beforeErr := os.Stat(DefaultPath)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, &State{ManualBlocked: []string{"eli"}}); err != nil {
		t.Fatal(err)
	}
	after, afterErr := os.Stat(DefaultPath)
	if (beforeErr == nil) != (afterErr == nil) {
		t.Fatalf("%s appeared or vanished during the test", DefaultPath)
	}
	if beforeErr == nil && after.ModTime() != before.ModTime() {
		t.Errorf("%s was modified by a test", DefaultPath)
	}
}
