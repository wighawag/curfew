package dnspolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc writes a /proc that says what the test wants it to say. The numbers
// in the callers come off the live router, including the ones from the moment
// AdGuard was killed.
func fakeProc(t *testing.T, availKB int, procs map[string]int) string {
	t.Helper()
	dir := t.TempDir()
	meminfo := "MemTotal:        1010032 kB\n" +
		"MemFree:          172524 kB\n" +
		"MemAvailable:   " + itoa(availKB) + " kB\n" +
		"Buffers:            1234 kB\n"
	if availKB < 0 {
		meminfo = "MemTotal:        1010032 kB\nMemFree:          172524 kB\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := 10000
	for name, rssKB := range procs {
		pid++
		p := filepath.Join(dir, itoa(pid))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "comm"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		status := "Name:\t" + name + "\nVmSize:\t 2244676 kB\nVmRSS:\t" + itoa(rssKB) + " kB\n"
		if err := os.WriteFile(filepath.Join(p, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A non-numeric entry, which a real /proc is full of.
	if err := os.MkdirAll(filepath.Join(dir, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func itoa(n int) string {
	if n < 0 {
		return "0"
	}
	var b []byte
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func headroomFor(t *testing.T, availKB int, procs map[string]int) string {
	t.Helper()
	return ProcHeadroom{Dir: fakeProc(t, availKB, procs), Process: "AdGuardHome"}.Short()
}

// The measured incident: AdGuard resident at 555 MB with 321 MB available, and
// a rebuild needs a second copy of the first number.
func TestARebuildIsRefusedWhenAdGuardIsBiggerThanTheMemoryLeft(t *testing.T) {
	why := headroomFor(t, 321320, map[string]int{"AdGuardHome": 568000, "dnsmasq": 2100})
	if why == "" {
		t.Fatal("the exact conditions that OOM-killed AdGuard were judged affordable")
	}
	// The message has to be actionable, not just a refusal.
	for _, want := range []string{"554 MB", "313 MB", "swap"} {
		if !strings.Contains(why, want) {
			t.Errorf("the refusal does not say %q, so nobody can act on it: %s", want, why)
		}
	}
}

// The control: a router with room must not be blocked, or the guard has just
// turned the feature off everywhere.
func TestARebuildIsAllowedWhenThereIsRoomForIt(t *testing.T) {
	if why := headroomFor(t, 700000, map[string]int{"AdGuardHome": 400000}); why != "" {
		t.Errorf("a router with room to spare was blocked: %s", why)
	}
}

// A measurement that cannot be taken is not a refusal. A guard that silently
// disabled the feature on any system it did not recognise would be worse than
// no guard at all.
func TestAnUnmeasurableRouterIsNotBlocked(t *testing.T) {
	if why := headroomFor(t, 500000, map[string]int{"dnsmasq": 2100}); why != "" {
		t.Errorf("AdGuard is not running under that name, which is not a reason to refuse: %s", why)
	}
	if why := headroomFor(t, -1, map[string]int{"AdGuardHome": 900000}); why != "" {
		t.Errorf("a kernel with no MemAvailable is not a reason to refuse: %s", why)
	}
	if why := (ProcHeadroom{Dir: "/nonexistent", Process: "AdGuardHome"}).Short(); why != "" {
		t.Errorf("an unreadable /proc is not a reason to refuse: %s", why)
	}
}

// The live router is the case this was built for, so read it when the test is
// running there and say what it decided. It asserts nothing about the answer:
// the answer depends on the household's blocklists.
func TestTheRealRouterIsMeasurable(t *testing.T) {
	h := RouterHeadroom()
	if _, err := h.available(); err != nil {
		t.Skipf("not a Linux router: %v", err)
	}
	rss, err := h.adguardRSS()
	if err != nil {
		t.Skipf("no AdGuard running here: %v", err)
	}
	t.Logf("AdGuard resident: %d MB; headroom verdict: %q", rss/(1<<20), h.Short())
}
