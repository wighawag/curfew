package schedule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// at builds a local time on a known weekday. 2026-08-03 is a Monday, so the
// offsets below read as the day they name.
func at(day time.Weekday, hhmm string) time.Time {
	base := time.Date(2026, 8, 3, 0, 0, 0, 0, time.Local) // Monday
	offset := (int(day) - int(time.Monday) + 7) % 7
	m, _ := minutes(hhmm)
	return base.AddDate(0, 0, offset).Add(time.Duration(m) * time.Minute)
}

func TestAtHelperLandsOnTheRightWeekday(t *testing.T) {
	// The helper underpins every case below, so it gets its own check rather
	// than being assumed.
	for _, d := range []time.Weekday{time.Monday, time.Wednesday, time.Saturday, time.Sunday} {
		if got := at(d, "12:00").Weekday(); got != d {
			t.Errorf("at(%v) landed on %v", d, got)
		}
	}
}

func TestSameDayWindow(t *testing.T) {
	lunch := Window{Days: []Day{Mon, Tue, Wed, Thu, Fri}, Start: "12:00", End: "13:00"}
	cases := []struct {
		when time.Time
		want bool
		why  string
	}{
		{at(time.Monday, "11:59"), false, "just before"},
		{at(time.Monday, "12:00"), true, "start is inclusive"},
		{at(time.Monday, "12:59"), true, "inside"},
		{at(time.Monday, "13:00"), false, "end is exclusive"},
		{at(time.Saturday, "12:30"), false, "not a listed day"},
	}
	for _, c := range cases {
		if got := lunch.Contains(c.when); got != c.want {
			t.Errorf("%s: %s -> %v, want %v", c.why, c.when.Format("Mon 15:04"), got, c.want)
		}
	}
}

// The case most likely to be wrong, and the one a household notices.
func TestOvernightWindowSpansMidnight(t *testing.T) {
	night := Window{Days: AllDays, Start: "22:00", End: "08:00"}
	cases := []struct {
		when time.Time
		want bool
		why  string
	}{
		{at(time.Monday, "21:59"), false, "before bedtime"},
		{at(time.Monday, "22:00"), true, "bedtime starts"},
		{at(time.Monday, "23:59"), true, "late evening"},
		{at(time.Tuesday, "00:00"), true, "just after midnight"},
		{at(time.Tuesday, "07:59"), true, "early morning"},
		{at(time.Tuesday, "08:00"), false, "morning release"},
		{at(time.Tuesday, "12:00"), false, "daytime"},
	}
	for _, c := range cases {
		if got := night.Contains(c.when); got != c.want {
			t.Errorf("%s: %s -> %v, want %v", c.why, c.when.Format("Mon 15:04"), got, c.want)
		}
	}
}

// Days name the day the window STARTS. Without that rule a weekend bedtime is
// inexpressible, so it is asserted rather than left implicit.
func TestOvernightWindowBelongsToItsStartDay(t *testing.T) {
	fridayNight := Window{Days: []Day{Fri}, Start: "22:00", End: "08:00"}
	if !fridayNight.Contains(at(time.Friday, "23:00")) {
		t.Error("Friday 23:00 should be inside a Friday-night window")
	}
	if !fridayNight.Contains(at(time.Saturday, "02:00")) {
		t.Error("Saturday 02:00 is still Friday night and should be inside")
	}
	if fridayNight.Contains(at(time.Saturday, "23:00")) {
		t.Error("Saturday 23:00 belongs to Saturday, which is not listed")
	}
	if fridayNight.Contains(at(time.Friday, "02:00")) {
		t.Error("Friday 02:00 is Thursday night, which is not listed")
	}
}

func TestMultipleWindowsCombine(t *testing.T) {
	// The stated requirement: block at night AND at lunchtime.
	p := Profile{Name: "eli", Windows: []Window{
		{Days: AllDays, Start: "22:00", End: "08:00"},
		{Days: []Day{Mon, Tue, Wed, Thu, Fri}, Start: "12:00", End: "13:00"},
	}}
	if !p.BlockedAt(at(time.Monday, "23:00")) {
		t.Error("night window should block")
	}
	if !p.BlockedAt(at(time.Monday, "12:30")) {
		t.Error("lunch window should block")
	}
	if p.BlockedAt(at(time.Monday, "15:00")) {
		t.Error("afternoon is outside both")
	}
	if p.BlockedAt(at(time.Sunday, "12:30")) {
		t.Error("lunch is weekdays only")
	}
}

func TestDifferentDaysDifferentRules(t *testing.T) {
	// "Wednesdays and Fridays differently", as asked for.
	p := Profile{Name: "tia", Windows: []Window{
		{Days: []Day{Wed, Fri}, Start: "14:00", End: "16:00"},
	}}
	if !p.BlockedAt(at(time.Wednesday, "15:00")) || !p.BlockedAt(at(time.Friday, "15:00")) {
		t.Error("Wednesday and Friday afternoons should block")
	}
	if p.BlockedAt(at(time.Thursday, "15:00")) {
		t.Error("Thursday should not")
	}
}

func TestBlockedMACsUnionsProfilesAndDeduplicates(t *testing.T) {
	ps := &Profiles{Profiles: []Profile{
		{Name: "a", Devices: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"},
			Windows: []Window{{Days: AllDays, Start: "22:00", End: "08:00"}}},
		{Name: "b", Devices: []string{"aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"},
			Windows: []Window{{Days: AllDays, Start: "22:00", End: "08:00"}}},
		{Name: "c", Devices: []string{"aa:bb:cc:00:00:09"},
			Windows: []Window{{Days: []Day{Sun}, Start: "01:00", End: "02:00"}}},
	}}
	got := ps.BlockedMACs(at(time.Monday, "23:00"))
	want := []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted, deduplicated)", got, want)
		}
	}
}

func TestNoWindowsMeansNeverBlocked(t *testing.T) {
	p := Profile{Name: "adult", Devices: []string{"aa:bb:cc:00:00:01"}}
	for _, d := range []time.Weekday{time.Monday, time.Saturday} {
		for _, h := range []string{"00:00", "12:00", "23:59"} {
			if p.BlockedAt(at(d, h)) {
				t.Fatalf("a profile with no windows must never be blocked (%v %s)", d, h)
			}
		}
	}
}

// Strictness matters here specifically: the system this replaces accepted an
// hour of 24 and silently reinterpreted it as "every hour".
func TestValidateRejectsNonsense(t *testing.T) {
	bad := []Window{
		{Days: []Day{Mon}, Start: "24:00", End: "08:00"},
		{Days: []Day{Mon}, Start: "22:00", End: "08:60"},
		{Days: []Day{Mon}, Start: "22", End: "08:00"},
		{Days: []Day{Mon}, Start: "-1:00", End: "08:00"},
		{Days: []Day{}, Start: "22:00", End: "08:00"},
		{Days: []Day{"funday"}, Start: "22:00", End: "08:00"},
		{Days: []Day{Mon, Mon}, Start: "22:00", End: "08:00"},
		{Days: []Day{Mon}, Start: "22:00", End: "22:00"},
	}
	for _, w := range bad {
		if err := w.Validate(); err == nil {
			t.Errorf("want an error for %+v", w)
		}
	}
	good := Window{Days: []Day{Mon}, Start: "22:00", End: "08:00"}
	if err := good.Validate(); err != nil {
		t.Errorf("a valid window was rejected: %v", err)
	}
}

func TestLoadRefusesAnUnusableSchedule(t *testing.T) {
	// Better to refuse than to enforce a schedule nobody can predict.
	p := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(p, []byte(`{"profiles":[{"name":"x","windows":[{"days":["mon"],"start":"25:00","end":"08:00"}]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("want an error for an invalid hour")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	ps, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Profiles) != 0 {
		t.Errorf("want empty, got %+v", ps.Profiles)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "profiles.json")
	in := &Profiles{Profiles: []Profile{{
		Name: "eli", Devices: []string{"AA:BB:CC:00:00:01"},
		Windows: []Window{{Days: []Day{Fri, Sat}, Start: "23:00", End: "09:00"}},
	}}}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Profiles) != 1 || out.Profiles[0].Devices[0] != "aa:bb:cc:00:00:01" {
		t.Fatalf("MACs should be canonicalised on load: %+v", out.Profiles)
	}
	if len(out.Profiles[0].Windows) != 1 || out.Profiles[0].Windows[0].Start != "23:00" {
		t.Fatalf("window lost: %+v", out.Profiles[0].Windows)
	}
}

func TestSaveRefusesAnInvalidSchedule(t *testing.T) {
	p := filepath.Join(t.TempDir(), "profiles.json")
	bad := &Profiles{Profiles: []Profile{{
		Name: "x", Windows: []Window{{Days: []Day{Mon}, Start: "99:00", End: "08:00"}},
	}}}
	if err := Save(p, bad); err == nil {
		t.Fatal("want an error")
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("nothing should have been written")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	ps := &Profiles{Profiles: []Profile{
		{Name: "a", Windows: []Window{{Days: []Day{Mon}, Start: "25:00", End: "08:00"}}},
		{Name: "a"},
	}}
	err := ps.Validate()
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "25:00") || !strings.Contains(err.Error(), "twice") {
		t.Errorf("both problems should be reported, got: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	cases := map[string]Window{
		"22:00 to 08:00, every day (overnight)": {Days: AllDays, Start: "22:00", End: "08:00"},
		"12:00 to 13:00, weekdays":              {Days: []Day{Mon, Tue, Wed, Thu, Fri}, Start: "12:00", End: "13:00"},
		"09:00 to 11:00, weekends":              {Days: []Day{Sat, Sun}, Start: "09:00", End: "11:00"},
		"14:00 to 16:00, wed, fri":              {Days: []Day{Wed, Fri}, Start: "14:00", End: "16:00"},
	}
	for want, w := range cases {
		if got := w.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	}
}
