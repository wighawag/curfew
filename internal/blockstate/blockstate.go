// Package blockstate holds the per-profile state that must survive a reboot.
//
// This is STATE, not configuration: nobody authors it, the tool writes it, and
// it records a DECISION a parent made rather than a fact the system can
// recompute. That distinction is the reason it exists at all. A `schedule`
// block is derived from the clock on every tick and needs no persisting; a
// `budget` block is derived from a usage counter; but a manual block means
// "off until I say otherwise", and there is nothing to derive it from. If it
// is not written down, a power cut silently grants a grounded child their
// internet back, which is the headline defect of the system this replaces.
//
// It lives under /etc/config/ because that is the ONLY location OpenWrt's
// sysupgrade preserves (measured; see
// work/notes/findings/openwrt-etc-config-preserved-across-sysupgrade.md and the
// pinning test in internal/deploy). Living next to the config files does not
// make it config.
//
// Tickets are deliberately absent from this file. A ticket is a time-limited
// grant held in a kernel timeout set, and it is MEANT to die with the router:
// persisting one would resurrect a grant whose whole point was that it expires.
package blockstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// DefaultPath is where the daemon keeps this file on the router.
const DefaultPath = "/etc/config/curfew/state.json"

// State is the persisted block state.
//
// Today it carries exactly one member. The other three items on the
// authoritative list in the enforcement spec (the usage counter, the
// daily-reset day marker, and the schedule reason while it is still
// edge-driven) belong here too as the policy layer reaches them; the schedule
// reason is already derived from the clock in this implementation and so needs
// no member.
type State struct {
	// ManualBlocked names the profiles a parent has blocked until they lift
	// it. Profile NAMES rather than MACs, because a manual block acts on a
	// whole profile and must keep applying to a device added to that profile
	// afterwards.
	ManualBlocked []string `json:"manual_blocked"`
}

// IsBlocked reports whether this profile carries a manual block.
func (s *State) IsBlocked(profile string) bool {
	return slices.Contains(s.ManualBlocked, profile)
}

// Block adds the manual reason for a profile, reporting whether anything
// changed. Blocking a profile that is already blocked is a no-op rather than
// an error: the parent's intent is already recorded, and re-tapping a button
// should not fail.
func (s *State) Block(profile string) bool {
	if s.IsBlocked(profile) {
		return false
	}
	s.ManualBlocked = append(s.ManualBlocked, profile)
	sort.Strings(s.ManualBlocked)
	return true
}

// Unblock removes the manual reason for a profile, reporting whether anything
// changed.
//
// It removes exactly the one reason it owns. Every other reason a profile may
// carry is untouched, which is the whole point of the reason SET in
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md:
// lifting a manual block at 23:00 must not also cancel bedtime.
func (s *State) Unblock(profile string) bool {
	out := s.ManualBlocked[:0:0]
	for _, p := range s.ManualBlocked {
		if p != profile {
			out = append(out, p)
		}
	}
	if len(out) == len(s.ManualBlocked) {
		return false
	}
	s.ManualBlocked = out
	return true
}

// Load reads the state. A missing file is empty state, so a first run needs no
// bootstrap.
//
// A file that exists but cannot be parsed is an ERROR rather than empty state.
// Treating it as empty would silently unblock every grounded child, which is
// the failure mode this file exists to prevent, and it would do it at the
// quietest possible moment.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{ManualBlocked: []string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.ManualBlocked == nil {
		s.ManualBlocked = []string{}
	}
	clean := s.ManualBlocked[:0]
	seen := map[string]bool{}
	for _, p := range s.ManualBlocked {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		clean = append(clean, p)
	}
	s.ManualBlocked = clean
	sort.Strings(s.ManualBlocked)
	return &s, nil
}

// Save writes the state atomically, so a power cut mid-write cannot leave a
// half-written file that the next boot refuses to parse.
func Save(path string, s *State) error {
	if s.ManualBlocked == nil {
		s.ManualBlocked = []string{}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	return os.Rename(tmpName, path)
}

// FileStore adapts a state file to the small interface the policy layer needs.
type FileStore struct{ Path string }

// Load reads the state from disk.
func (f FileStore) Load() (*State, error) { return Load(f.Path) }

// Save writes the state to disk atomically.
func (f FileStore) Save(s *State) error { return Save(f.Path, s) }
