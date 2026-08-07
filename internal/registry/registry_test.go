package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormaliseMACAcceptedSpellings(t *testing.T) {
	// All of these are the same device. If any spelling survives
	// uncanonicalised it can be registered twice and removed by neither.
	for _, in := range []string{
		"aa:bb:cc:dd:ee:01",
		"AA:BB:CC:DD:EE:01",
		"aa-bb-cc-dd-ee-01",
		"  aa:bb:cc:dd:ee:01  ",
	} {
		got, err := NormaliseMAC(in)
		if err != nil {
			t.Fatalf("NormaliseMAC(%q): unexpected error %v", in, err)
		}
		if got != "aa:bb:cc:dd:ee:01" {
			t.Errorf("NormaliseMAC(%q) = %q, want aa:bb:cc:dd:ee:01", in, got)
		}
	}
}

func TestNormaliseMACRejectsJunk(t *testing.T) {
	for _, in := range []string{"", "   ", "nonsense", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:zz"} {
		if _, err := NormaliseMAC(in); err == nil {
			t.Errorf("NormaliseMAC(%q): want error, got nil", in)
		}
	}
}

func TestNormaliseMACRejectsNon48Bit(t *testing.T) {
	// net.ParseMAC happily accepts 8- and 20-octet addresses. An ether_addr
	// nftables set holds 6, so anything else must be refused here rather than
	// failing later inside the firewall where the error is easy to swallow.
	if _, err := NormaliseMAC("aa:bb:cc:dd:ee:ff:00:11"); err == nil {
		t.Error("NormaliseMAC(8 octets): want error, got nil")
	}
}

func TestAddIsIdempotentAndRenames(t *testing.T) {
	r := &Registry{}
	if err := r.Add("AA:BB:CC:DD:EE:01", "phone"); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("aa-bb-cc-dd-ee-01", "eli phone"); err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 {
		t.Fatalf("want 1 device after re-adding the same MAC, got %d: %+v", len(r.Devices), r.Devices)
	}
	if r.Devices[0].Name != "eli phone" {
		t.Errorf("want the name updated to %q, got %q", "eli phone", r.Devices[0].Name)
	}
}

func TestAddAllowsAnonymousDevice(t *testing.T) {
	// The name is optional by design: a device may be allowed without one.
	r := &Registry{}
	if err := r.Add("aa:bb:cc:dd:ee:02", ""); err != nil {
		t.Fatal(err)
	}
	if got := r.MACs(); len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("want the anonymous device allowlisted, got %v", got)
	}
}

func TestAddRejectsInvalidWithoutMutating(t *testing.T) {
	r := &Registry{}
	if err := r.Add("not-a-mac", "x"); err == nil {
		t.Fatal("want error for an invalid MAC")
	}
	if len(r.Devices) != 0 {
		t.Fatalf("a rejected Add must not mutate the registry, got %+v", r.Devices)
	}
}

func TestRemove(t *testing.T) {
	r := &Registry{}
	if err := r.Add("aa:bb:cc:dd:ee:01", "a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("aa:bb:cc:dd:ee:02", "b"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("AA:BB:CC:DD:EE:01"); err != nil {
		t.Fatalf("Remove by a different spelling should work: %v", err)
	}
	if got := r.MACs(); len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("after Remove want only ...:02, got %v", got)
	}
	if err := r.Remove("aa:bb:cc:dd:ee:09"); err == nil {
		t.Error("removing an unregistered MAC must be an error, not a silent no-op")
	}
}

func TestMACsIsSorted(t *testing.T) {
	r := &Registry{}
	for _, m := range []string{"aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"} {
		if err := r.Add(m, ""); err != nil {
			t.Fatal(err)
		}
	}
	got := r.MACs()
	want := []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("MACs() = %v, want sorted %v", got, want)
		}
	}
}

func TestLoadMissingFileIsEmptyNotError(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("a missing registry must load as empty, got %v", err)
	}
	if len(r.Devices) != 0 {
		t.Fatalf("want empty, got %+v", r.Devices)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "devices.json")
	in := &Registry{}
	if err := in.Add("aa:bb:cc:dd:ee:01", "eli phone"); err != nil {
		t.Fatal(err)
	}
	if err := in.Add("aa:bb:cc:dd:ee:02", ""); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Devices) != 2 || out.Devices[0].Name != "eli phone" || out.Devices[1].Name != "" {
		t.Fatalf("round trip lost data: %+v", out.Devices)
	}
}

func TestSaveLeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	r := &Registry{}
	if err := r.Add("aa:bb:cc:dd:ee:01", "x"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("atomic save left a temp file behind: %s", e.Name())
		}
	}
}

func TestLoadRejectsGarbageMACInFile(t *testing.T) {
	// A hand-edited file must fail loudly rather than yielding a registry whose
	// entries silently match no device.
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte(`{"devices":[{"mac":"zz","name":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("want an error for an unparseable MAC in the file, got nil")
	}
}
