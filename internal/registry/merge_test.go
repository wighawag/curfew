package registry

import (
	"strings"
	"testing"
)

func reg(pairs ...string) *Registry {
	r := &Registry{Devices: []Device{}}
	for i := 0; i < len(pairs); i += 2 {
		r.Devices = append(r.Devices, Device{MAC: pairs[i], Name: pairs[i+1]})
	}
	return r
}

func names(r *Registry) map[string]string {
	m := map[string]string{}
	for _, d := range r.Devices {
		m[d.MAC] = d.Name
	}
	return m
}

const (
	m1 = "aa:bb:cc:00:00:01"
	m2 = "aa:bb:cc:00:00:02"
	m3 = "aa:bb:cc:00:00:03"
)

func TestMergeTakesEachSidesIndependentChange(t *testing.T) {
	// The common case, and the whole reason a structured merge beats text
	// markers: a rename here and an addition there are not a conflict.
	base := reg(m1, "phone")
	local := reg(m1, "eli phone")            // renamed locally
	remote := reg(m1, "phone", m2, "tablet") // added on the router
	merged, conflicts := Merge3(base, local, remote)
	if len(conflicts) != 0 {
		t.Fatalf("want a clean merge, got %+v", conflicts)
	}
	got := names(merged)
	if got[m1] != "eli phone" || got[m2] != "tablet" {
		t.Errorf("both changes should survive, got %v", got)
	}
}

func TestMergeIdenticalChangesAreNotAConflict(t *testing.T) {
	base := reg(m1, "old")
	merged, conflicts := Merge3(base, reg(m1, "new"), reg(m1, "new"))
	if len(conflicts) != 0 {
		t.Fatalf("same change on both sides is agreement, got %+v", conflicts)
	}
	if names(merged)[m1] != "new" {
		t.Errorf("got %v", names(merged))
	}
}

func TestMergeRemovalOnOneSideIsApplied(t *testing.T) {
	base := reg(m1, "phone", m2, "tablet")
	merged, conflicts := Merge3(base, reg(m1, "phone", m2, "tablet"), reg(m1, "phone"))
	if len(conflicts) != 0 {
		t.Fatalf("want clean, got %+v", conflicts)
	}
	if _, still := names(merged)[m2]; still {
		t.Error("a removal on the router should be applied locally")
	}
}

func TestMergeConflictWhenBothRename(t *testing.T) {
	base := reg(m1, "phone")
	merged, conflicts := Merge3(base, reg(m1, "eli phone"), reg(m1, "elis phone"))
	if len(conflicts) != 1 || conflicts[0].Kind != BothRenamed {
		t.Fatalf("want one BothRenamed conflict, got %+v", conflicts)
	}
	c := conflicts[0]
	if c.LocalName != "eli phone" || c.RemoteName != "elis phone" || c.BaseName != "phone" {
		t.Errorf("conflict should carry all three sides: %+v", c)
	}
	// Still usable, carrying the local value.
	if names(merged)[m1] != "eli phone" {
		t.Errorf("got %v", names(merged))
	}
}

// The dangerous one: taking the removal silently discards an edit, taking the
// rename silently restores network access. Neither may happen quietly.
func TestMergeConflictWhenOneSideRemovesAndTheOtherRenames(t *testing.T) {
	base := reg(m1, "phone")
	_, conflicts := Merge3(base, reg(), reg(m1, "eli phone"))
	if len(conflicts) != 1 || conflicts[0].Kind != RemovedAndRenamed {
		t.Fatalf("want RemovedAndRenamed, got %+v", conflicts)
	}
	if conflicts[0].InLocal || !conflicts[0].InRemote {
		t.Errorf("presence should be recorded per side: %+v", conflicts[0])
	}
}

func TestMergeRemovalOnBothSidesIsAgreement(t *testing.T) {
	base := reg(m1, "phone")
	merged, conflicts := Merge3(base, reg(), reg())
	if len(conflicts) != 0 || len(merged.Devices) != 0 {
		t.Fatalf("both removing is agreement, got %+v / %+v", conflicts, merged.Devices)
	}
}

// A missing base is treated as empty, and that must give sane answers rather
// than declaring everything a conflict.
func TestMergeWithNoBase(t *testing.T) {
	merged, conflicts := Merge3(nil,
		reg(m1, "phone", m2, "laptop"),
		reg(m1, "phone", m3, "tv"))
	if len(conflicts) != 0 {
		t.Fatalf("identical entries and distinct additions should merge, got %+v", conflicts)
	}
	got := names(merged)
	if len(got) != 3 || got[m1] != "phone" || got[m2] != "laptop" || got[m3] != "tv" {
		t.Errorf("got %v", got)
	}
}

func TestMergeWithNoBaseConflictsOnDifferingNames(t *testing.T) {
	// With no common ancestor there is no way to tell which is newer, so this
	// must be a conflict rather than a guess.
	_, conflicts := Merge3(nil, reg(m1, "laptop"), reg(m1, "tv"))
	if len(conflicts) != 1 || conflicts[0].Kind != BothAdded {
		t.Fatalf("want BothAdded, got %+v", conflicts)
	}
}

func TestEqual(t *testing.T) {
	if !Equal(reg(m1, "a", m2, "b"), reg(m2, "b", m1, "a")) {
		t.Error("order must not matter")
	}
	if Equal(reg(m1, "a"), reg(m1, "b")) {
		t.Error("a differing name is a difference")
	}
	if Equal(reg(m1, "a"), reg(m1, "a", m2, "b")) {
		t.Error("an extra device is a difference")
	}
	if !Equal(nil, reg()) {
		t.Error("nil and empty are the same thing")
	}
}

func TestRenderConflictsNamesBothSides(t *testing.T) {
	_, conflicts := Merge3(reg(m1, "phone"), reg(m1, "eli phone"), reg())
	out := RenderConflicts(conflicts)
	for _, want := range []string{m1, "eli phone", "(not present)", "--force"} {
		if !strings.Contains(out, want) {
			t.Errorf("report should mention %q:\n%s", want, out)
		}
	}
}
