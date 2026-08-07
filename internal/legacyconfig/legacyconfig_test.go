package legacyconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "parental_profiles")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseProfiles(t *testing.T) {
	p := write(t, `# a comment
# another|with|pipes

ronan|0|aa:bb:cc:00:00:08,aa:bb:cc:00:00:04
eli|240|aa:bb:cc:00:00:03,AA:BB:CC:00:00:02
`)
	got, err := ParseProfiles(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 profiles, got %d: %+v", len(got), got)
	}
	if got[1].Name != "eli" || got[1].Budget != 240 || len(got[1].MACs) != 2 {
		t.Errorf("eli parsed wrong: %+v", got[1])
	}
	// Canonicalised on the way in, so the uppercase entry matches later.
	if got[1].MACs[1] != "aa:bb:cc:00:00:02" {
		t.Errorf("MAC not canonicalised: %q", got[1].MACs[1])
	}
}

// A bad entry must be reported. Silently skipping it is a device that loses
// internet after the migration with nothing saying why.
func TestParseProfilesReportsUnusableEntries(t *testing.T) {
	p := write(t, `good|0|aa:bb:cc:dd:ee:01
bad|0|not-a-mac
truncated
`)
	profiles, err := ParseProfiles(p)
	if err == nil {
		t.Fatal("want an error naming the unusable entries, got nil")
	}
	if !strings.Contains(err.Error(), "not-a-mac") || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("the error should name both problems, got: %v", err)
	}
	// The usable entries still come back, so an operator can see what WOULD be
	// imported alongside what could not be.
	if len(profiles) < 1 || profiles[0].Name != "good" {
		t.Errorf("usable profiles should still be returned, got %+v", profiles)
	}
}

func TestToRegistryNamesAndDeduplicates(t *testing.T) {
	profiles := []Profile{
		{Name: "printer", MACs: []string{"aa:bb:cc:dd:ee:01"}},
		{Name: "eli", MACs: []string{"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}},
	}
	reg := ToRegistry(profiles)
	if len(reg.Devices) != 3 {
		t.Fatalf("want 3 devices, got %+v", reg.Devices)
	}
	byMAC := map[string]string{}
	for _, d := range reg.Devices {
		byMAC[d.MAC] = d.Name
	}
	// A single-device profile keeps the bare name; a multi-device one is
	// suffixed so the entries are distinguishable on the page.
	if byMAC["aa:bb:cc:dd:ee:01"] != "printer" {
		t.Errorf("single-device profile should keep its name, got %q", byMAC["aa:bb:cc:dd:ee:01"])
	}
	if byMAC["aa:bb:cc:dd:ee:02"] != "eli-1" || byMAC["aa:bb:cc:dd:ee:03"] != "eli-2" {
		t.Errorf("multi-device profile should be suffixed, got %v", byMAC)
	}
}

// The real config has a profile listing the same MAC twice, and another where
// a MAC could appear in two profiles. The allowlist has always been the
// deduplicated union, so the import must not produce duplicates.
func TestToRegistryHandlesRepeatedMACs(t *testing.T) {
	profiles := []Profile{
		{Name: "shyrka", MACs: []string{"aa:bb:cc:00:00:06", "aa:bb:cc:00:00:06"}},
		{Name: "other", MACs: []string{"aa:bb:cc:00:00:06"}},
	}
	reg := ToRegistry(profiles)
	if len(reg.Devices) != 1 {
		t.Fatalf("a repeated MAC must be registered once, got %+v", reg.Devices)
	}
	// One real device, so it keeps the unsuffixed name rather than becoming
	// shyrka-1 because of the duplicate line.
	if reg.Devices[0].Name != "shyrka" {
		t.Errorf("want the bare profile name for a single real device, got %q", reg.Devices[0].Name)
	}
}

// The whole point of the import: the allowlist it produces must match what the
// legacy system was enforcing, or installing takes the household offline.
func TestImportPreservesTheAllowlistOfTheRealConfigShape(t *testing.T) {
	p := write(t, `# === Parents ===
ronan|0|aa:bb:cc:00:00:08,aa:bb:cc:00:00:04,aa:bb:cc:00:00:01
ritu|0|aa:bb:cc:00:00:07
printer|0|AA:BB:CC:00:00:09
shyrka|0|aa:bb:cc:00:00:06,aa:bb:cc:00:00:06
eli|240|aa:bb:cc:00:00:03,AA:BB:CC:00:00:02,AA:BB:CC:00:00:05
#ishan|240|aa:bb:cc:dd:ee:03
`)
	profiles, err := ParseProfiles(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reg := ToRegistry(profiles)
	// 3 + 1 + 1 + 1 (deduplicated) + 3 = 9. The commented-out profile must not
	// contribute, exactly as the legacy allowlist ignored it.
	if len(reg.MACs()) != 9 {
		t.Fatalf("want 9 unique MACs, got %d: %v", len(reg.MACs()), reg.MACs())
	}
	for _, m := range reg.MACs() {
		if strings.Contains(m, "aa:bb:cc:dd:ee:03") {
			t.Error("a commented-out profile must not be imported")
		}
	}
}
