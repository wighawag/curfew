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

	"github.com/wighawag/curfew/internal/budget"
)

// DefaultPath is where the daemon keeps this file on the router.
const DefaultPath = "/etc/config/curfew/state.json"

// State is THE AUTHORITATIVE LIST of everything that must survive a reboot.
//
// This type is the single place that list is stated. The enforcement spec
// carried it in prose and required that no other document restate it, because
// three successive drafts each dropped a different member while retyping it.
// The spec is a launch snapshot that is explicitly not maintained, so the list
// now lives HERE, in the thing that cannot drift from what is actually
// written to disk, and every document points at this type instead of copying
// it. If you add a member, add it here and nowhere else.
//
// The members, and why each one cannot be derived:
//
//  1. ManualBlocked — a DECISION, with nothing to recompute it from.
//  2. BudgetDay — which budget day the counters below belong to. Without it a
//     reboot looks like a new day and hands back a spent allowance.
//  3. Budget[profile].Usage — how much of today has been used.
//  4. Budget[profile].Session — how much of the current unbroken session has
//     been used.
//  5. Budget[profile].LastActive — what the continuity gap is measured from.
//  6. Budget[profile].CooldownUntil — when a spent continuous allowance
//     refills.
//
// What is deliberately NOT here:
//
//   - The `budget` REASON. It is derived from members 3 to 6 against the
//     profile's limits on every check, never stored and never restored, so it
//     cannot latch and a stale one cannot survive.
//   - The `schedule` reason. The policy layer derives it from the clock on
//     every tick, so the member the enforcement spec reserved for it is not
//     needed at all.
//   - The previous counter reading the sampler subtracts from. It baselines a
//     kernel counter that dies with the table, so persisting it would keep a
//     number whose meaning had already gone. It lives in memory.
//   - Tickets, which are kernel timeout state and are meant to die with the
//     router.
type State struct {
	// ManualBlocked names the profiles a parent has blocked until they lift
	// it. Profile NAMES rather than MACs, because a manual block acts on a
	// whole profile and must keep applying to a device added to that profile
	// afterwards.
	ManualBlocked []string `json:"manual_blocked"`

	// BudgetDay is the budget day the counters below belong to, as
	// budget.DayFormat. It is GLOBAL because the reset time is global (ADR
	// 0009). Empty means nothing has been accounted yet.
	BudgetDay string `json:"budget_day,omitempty"`

	// Budget holds each profile's live budget counters, keyed by profile name
	// for the same reason ManualBlocked is: a device added to a profile joins
	// that profile's allowance rather than getting a fresh one.
	Budget map[string]budget.State `json:"budget,omitempty"`
}

// EffectiveDay is the budget day the counters should be read and written
// under, given what the clock currently says.
//
// It is normally just the computed day. The exception is the whole reason this
// function exists: a clock that has jumped BACKWARDS must not be allowed to
// address an earlier day, because every read under an earlier day returns zero
// state and the next write would then overwrite a spent allowance with a fresh
// one. An OpenWrt router has no RTC and boots at the epoch, so this is a
// routine event rather than a corner case.
//
// Every caller that reads or writes budget state goes through here, which is
// what makes the rule impossible to apply on one path and forget on the other.
// RollOver enforces the same direction, and having both is deliberate: this
// one keeps the READS consistent, that one keeps the WRITES safe.
func (s *State) EffectiveDay(computed string) string {
	if s.BudgetDay != "" && computed < s.BudgetDay {
		return s.BudgetDay
	}
	return computed
}

// BudgetFor returns a profile's budget state AS OF the given budget day.
//
// The rollover is applied here, as a derivation rather than an event: if the
// stored counters belong to an earlier day, this returns zero state, whether
// or not any tick has got round to writing that zero down. That is what makes
// a daemon which was down across the reset time still see the new day, and it
// is the same discipline internal/schedule uses for windows.
func (s *State) BudgetFor(profile, day string) budget.State {
	if s.BudgetDay != day {
		return budget.State{}
	}
	return s.Budget[profile]
}

// RollOver moves the budget counters to a new day, zeroing everything the
// budget owns and touching nothing else.
//
// It reports whether anything changed. Note what it CANNOT do: it has no
// access to ManualBlocked and no notion of a schedule, so a reset can never
// clear a reason it does not own. The implementation this replaces called
// unblock_profile unconditionally on rollover and silently cancelled bedtime;
// here that bug is not merely fixed but unavailable.
//
// It refuses to move BACKWARDS. A router with no RTC boots at the epoch, and
// a rollover to 1970 would hand every child a fresh allowance on every power
// cut, which is precisely the reboot-grants-internet failure this file exists
// to prevent. The cost is that a clock wrongly set into the FUTURE freezes the
// rollover until real time catches up, which is the rarer fault and the one
// that errs towards staying blocked.
func (s *State) RollOver(day string) bool {
	if s.BudgetDay == day {
		return false
	}
	if s.BudgetDay != "" && day < s.BudgetDay {
		return false
	}
	s.BudgetDay = day
	s.Budget = nil
	return true
}

// SetBudget records a profile's budget state, reporting whether it changed.
// Zero state is stored as absence, so an untouched household writes nothing.
func (s *State) SetBudget(profile string, b budget.State) bool {
	cur, had := s.Budget[profile]
	if b.Zero() {
		if !had {
			return false
		}
		delete(s.Budget, profile)
		return true
	}
	if had && cur.Usage == b.Usage && cur.Session == b.Session &&
		cur.LastActive.Equal(b.LastActive) && cur.CooldownUntil.Equal(b.CooldownUntil) {
		return false
	}
	if s.Budget == nil {
		s.Budget = map[string]budget.State{}
	}
	s.Budget[profile] = b
	return true
}

// ForgetBudget drops budget state for profiles that no longer exist, so a
// deleted profile's counters cannot come back to life under a reused name.
func (s *State) ForgetBudget(known map[string]bool) bool {
	changed := false
	for name := range s.Budget {
		if !known[name] {
			delete(s.Budget, name)
			changed = true
		}
	}
	if len(s.Budget) == 0 {
		s.Budget = nil
	}
	return changed
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
