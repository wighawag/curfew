// Package schedule is the policy layer: which profiles should be blocked, and
// when.
//
// A schedule is DESIRED STATE, not a list of events. Nothing here fires at a
// boundary; callers ask "what should be true right now?" and get an answer.
// That is deliberate and is the reason cron is gone: a missed moment cannot be
// lost, because the next tick recomputes from the clock. A router that boots
// at 22:05 is blocked within a tick, where a missed cron edge was gone for the
// night. See work/notes/findings/busybox-crond-treats-a-bad-time-field-as-a-wildcard.md
// for how badly the event model failed in practice.
package schedule

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Day is a day of the week, stored as a short lowercase name so the config is
// readable and not locale- or number-dependent.
type Day string

const (
	Mon Day = "mon"
	Tue Day = "tue"
	Wed Day = "wed"
	Thu Day = "thu"
	Fri Day = "fri"
	Sat Day = "sat"
	Sun Day = "sun"
)

// AllDays is every day, in week order starting Monday.
var AllDays = []Day{Mon, Tue, Wed, Thu, Fri, Sat, Sun}

var dayOf = map[time.Weekday]Day{
	time.Monday: Mon, time.Tuesday: Tue, time.Wednesday: Wed,
	time.Thursday: Thu, time.Friday: Fri, time.Saturday: Sat, time.Sunday: Sun,
}

// ParseDay accepts the short name, case-insensitively.
func ParseDay(s string) (Day, error) {
	d := Day(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range AllDays {
		if d == known {
			return d, nil
		}
	}
	return "", fmt.Errorf("unknown day %q (use mon, tue, wed, thu, fri, sat or sun)", s)
}

// Window is a recurring period during which a profile is blocked.
//
// Days lists the days the window STARTS on. That matters whenever End is at or
// before Start, which means the window runs past midnight: a Friday 22:00 to
// 08:00 window blocks Friday night into Saturday morning, and is therefore
// "Friday", not "Friday and Saturday". Any other reading makes a weekend
// bedtime impossible to express.
type Window struct {
	Days  []Day  `json:"days"`
	Start string `json:"start"` // "HH:MM", inclusive
	End   string `json:"end"`   // "HH:MM", exclusive
}

// minutes parses "HH:MM" into minutes since midnight.
func minutes(hhmm string) (int, error) {
	parts := strings.Split(strings.TrimSpace(hhmm), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time %q (want HH:MM)", hhmm)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour in %q (0-23)", hhmm)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute in %q (0-59)", hhmm)
	}
	return h*60 + m, nil
}

// Validate reports why a window is unusable. It is strict on purpose: the
// previous system accepted an hour of 24 and silently turned the line into
// "every hour", so an unparseable field must be refused at the door rather
// than reinterpreted.
func (w Window) Validate() error {
	if len(w.Days) == 0 {
		// Deliberately an error rather than "no days means every day". An
		// unspecified field silently meaning "everything" is precisely the
		// busybox crond behaviour that made the previous system's schedules
		// untrustworthy (see the finding on it), and `"days": []` in the file
		// would read as "never" to anyone looking. The form ticks every day by
		// default instead, so the data stays explicit.
		return errors.New("a window needs at least one day: tick the days it should apply on")
	}
	seen := map[Day]bool{}
	for _, d := range w.Days {
		if _, err := ParseDay(string(d)); err != nil {
			return err
		}
		if seen[d] {
			return fmt.Errorf("day %q listed twice", d)
		}
		seen[d] = true
	}
	s, err := minutes(w.Start)
	if err != nil {
		return err
	}
	e, err := minutes(w.End)
	if err != nil {
		return err
	}
	if s == e {
		return fmt.Errorf("start and end are both %s, which is a zero-length window; "+
			"use 00:00 to 24:00 semantics by setting end to 23:59 if you meant all day", w.Start)
	}
	return nil
}

func (w Window) hasDay(d Day) bool {
	for _, x := range w.Days {
		if x == d {
			return true
		}
	}
	return false
}

// Contains reports whether t falls inside the window, in t's own location.
//
// The start is inclusive and the end exclusive, so a 22:00 to 08:00 window
// blocks at exactly 22:00 and is clear at exactly 08:00, which is what a
// person means by "no internet from ten till eight".
func (w Window) Contains(t time.Time) bool {
	s, err := minutes(w.Start)
	if err != nil {
		return false
	}
	e, err := minutes(w.End)
	if err != nil {
		return false
	}
	now := t.Hour()*60 + t.Minute()
	today := dayOf[t.Weekday()]
	yesterday := dayOf[t.AddDate(0, 0, -1).Weekday()]

	if s < e {
		// Ordinary same-day window, e.g. lunch 12:00 to 13:00.
		return w.hasDay(today) && now >= s && now < e
	}
	// Crosses midnight. Either we are after the start on a listed day, or
	// before the end on the morning AFTER a listed day.
	return (w.hasDay(today) && now >= s) || (w.hasDay(yesterday) && now < e)
}

// Profile is a named group of devices with its own schedule.
type Profile struct {
	Name string `json:"name"`
	// Devices are MAC addresses, canonical lowercase, referencing the device
	// registry. A MAC here that is not registered simply matches nothing.
	Devices []string `json:"devices"`
	Windows []Window `json:"windows"`
}

// BlockedAt reports whether this profile should be blocked at t.
func (p Profile) BlockedAt(t time.Time) bool {
	for _, w := range p.Windows {
		if w.Contains(t) {
			return true
		}
	}
	return false
}

// Profiles is the whole schedule config.
type Profiles struct {
	Profiles []Profile `json:"profiles"`
}

// Find returns a profile by name.
func (ps *Profiles) Find(name string) (*Profile, bool) {
	for i := range ps.Profiles {
		if ps.Profiles[i].Name == name {
			return &ps.Profiles[i], true
		}
	}
	return nil, false
}

// BlockedMACs returns every MAC that should be blocked at t, deduplicated and
// sorted so the result is stable and can be compared against the firewall.
func (ps *Profiles) BlockedMACs(t time.Time) []string {
	seen := map[string]bool{}
	for _, p := range ps.Profiles {
		if !p.BlockedAt(t) {
			continue
		}
		for _, m := range p.Devices {
			seen[strings.ToLower(m)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Validate checks every profile, reporting all problems rather than the first,
// so a person fixing a config sees the whole list.
func (ps *Profiles) Validate() error {
	var problems []string
	names := map[string]bool{}
	for _, p := range ps.Profiles {
		if strings.TrimSpace(p.Name) == "" {
			problems = append(problems, "a profile has no name")
			continue
		}
		if names[p.Name] {
			problems = append(problems, fmt.Sprintf("profile %q is defined twice", p.Name))
		}
		names[p.Name] = true
		for i, w := range p.Windows {
			if err := w.Validate(); err != nil {
				problems = append(problems, fmt.Sprintf("profile %q window %d: %v", p.Name, i+1, err))
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Load reads the schedule. A missing file is an empty schedule, so a first run
// needs no bootstrap.
func Load(path string) (*Profiles, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Profiles{Profiles: []Profile{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var ps Profiles
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if ps.Profiles == nil {
		ps.Profiles = []Profile{}
	}
	for i := range ps.Profiles {
		for j, m := range ps.Profiles[i].Devices {
			ps.Profiles[i].Devices[j] = strings.ToLower(strings.TrimSpace(m))
		}
	}
	if err := ps.Validate(); err != nil {
		// Refuse rather than enforce a schedule nobody can predict.
		return nil, fmt.Errorf("%s is not usable: %w", path, err)
	}
	return &ps, nil
}

// Save writes the schedule atomically.
func Save(path string, ps *Profiles) error {
	if ps.Profiles == nil {
		ps.Profiles = []Profile{}
	}
	if err := ps.Validate(); err != nil {
		return fmt.Errorf("refusing to save an unusable schedule: %w", err)
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding schedule: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".schedule-*.tmp")
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

// FileStore adapts a schedule file to the small interface the HTTP layer
// needs, so that layer depends on two methods rather than the filesystem.
type FileStore struct{ Path string }

// Load reads the schedule from disk.
func (f FileStore) Load() (*Profiles, error) { return Load(f.Path) }

// Save writes the schedule to disk atomically.
func (f FileStore) Save(ps *Profiles) error { return Save(f.Path, ps) }

// Describe renders a window the way a person would say it.
func (w Window) Describe() string {
	d := "every day"
	switch {
	case len(w.Days) == 7:
	case sameSet(w.Days, []Day{Mon, Tue, Wed, Thu, Fri}):
		d = "weekdays"
	case sameSet(w.Days, []Day{Sat, Sun}):
		d = "weekends"
	default:
		parts := make([]string, 0, len(w.Days))
		for _, x := range AllDays {
			if w.hasDay(x) {
				parts = append(parts, string(x))
			}
		}
		d = strings.Join(parts, ", ")
	}
	overnight := ""
	if s, err1 := minutes(w.Start); err1 == nil {
		if e, err2 := minutes(w.End); err2 == nil && s >= e {
			overnight = " (overnight)"
		}
	}
	return fmt.Sprintf("%s to %s, %s%s", w.Start, w.End, d, overnight)
}

func sameSet(a, b []Day) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[Day]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// Equal reports whether two schedules are the same, order-insensitively for
// profiles but order-sensitively for a profile's windows, since a window list
// is authored and its order is what a person sees on the page.
func Equal(a, b *Profiles) bool {
	ai, bi := map[string]Profile{}, map[string]Profile{}
	if a != nil {
		for _, p := range a.Profiles {
			ai[p.Name] = p
		}
	}
	if b != nil {
		for _, p := range b.Profiles {
			bi[p.Name] = p
		}
	}
	if len(ai) != len(bi) {
		return false
	}
	for name, pa := range ai {
		pb, ok := bi[name]
		if !ok || len(pa.Windows) != len(pb.Windows) || len(pa.Devices) != len(pb.Devices) {
			return false
		}
		for i := range pa.Windows {
			if pa.Windows[i].Start != pb.Windows[i].Start || pa.Windows[i].End != pb.Windows[i].End ||
				!sameSet(pa.Windows[i].Days, pb.Windows[i].Days) {
				return false
			}
		}
		da := append([]string(nil), pa.Devices...)
		db := append([]string(nil), pb.Devices...)
		sort.Strings(da)
		sort.Strings(db)
		for i := range da {
			if da[i] != db[i] {
				return false
			}
		}
	}
	return true
}
