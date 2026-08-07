package registry

import (
	"fmt"
	"sort"
	"strings"
)

// Three-way merge for device registries.
//
// The list is keyed by MAC, so a structured merge is both possible and far
// better than git-style text markers: a rename here and an addition there are
// not a conflict at all, and only a device genuinely changed on both sides
// needs a human. The base is the last state both sides agreed on.
//
// A MISSING base is treated as an empty registry, which gives the right
// answers without special-casing: a device present on both sides with the same
// name merges silently, one present on a single side is taken, and one present
// on both with different names is correctly reported as a conflict, because
// with no common ancestor there is no way to know which is newer.

// ConflictKind explains why a device could not be merged automatically.
type ConflictKind string

const (
	// BothRenamed means each side gave the device a different name.
	BothRenamed ConflictKind = "renamed differently on both sides"
	// RemovedAndRenamed means one side removed the device while the other
	// renamed it. This one matters: taking the removal silently discards an
	// edit, and taking the rename silently restores network access.
	RemovedAndRenamed ConflictKind = "removed on one side, renamed on the other"
	// BothAdded means the device is new to both sides, with different names.
	BothAdded ConflictKind = "added on both sides with different names"
)

// Conflict is one device that needs a human.
type Conflict struct {
	MAC  string
	Kind ConflictKind
	// Each side's name, and whether the device was present at all.
	BaseName, LocalName, RemoteName string
	InBase, InLocal, InRemote       bool
}

func index(r *Registry) map[string]Device {
	m := map[string]Device{}
	if r == nil {
		return m
	}
	for _, d := range r.Devices {
		m[d.MAC] = d
	}
	return m
}

// Merge3 merges local and remote against their common base.
//
// The returned registry holds every automatically resolved device. Conflicted
// devices are carried at their LOCAL value so the result is still a usable
// list, but the caller is expected to refuse the merge while conflicts remain
// rather than quietly applying a half-decided answer.
func Merge3(base, local, remote *Registry) (*Registry, []Conflict) {
	b, l, r := index(base), index(local), index(remote)

	macs := map[string]bool{}
	for m := range b {
		macs[m] = true
	}
	for m := range l {
		macs[m] = true
	}
	for m := range r {
		macs[m] = true
	}
	ordered := make([]string, 0, len(macs))
	for m := range macs {
		ordered = append(ordered, m)
	}
	sort.Strings(ordered)

	out := &Registry{Devices: []Device{}}
	var conflicts []Conflict

	for _, mac := range ordered {
		bd, inB := b[mac]
		ld, inL := l[mac]
		rd, inR := r[mac]

		same := func(x Device, inX bool, y Device, inY bool) bool {
			return inX == inY && x.Name == y.Name
		}

		switch {
		case same(ld, inL, rd, inR):
			// Both sides agree, including both having removed it.
			if inL {
				out.Devices = append(out.Devices, ld)
			}
		case same(ld, inL, bd, inB):
			// Only the remote moved.
			if inR {
				out.Devices = append(out.Devices, rd)
			}
		case same(rd, inR, bd, inB):
			// Only the local moved.
			if inL {
				out.Devices = append(out.Devices, ld)
			}
		default:
			c := Conflict{
				MAC: mac, InBase: inB, InLocal: inL, InRemote: inR,
				BaseName: bd.Name, LocalName: ld.Name, RemoteName: rd.Name,
			}
			switch {
			case inL != inR:
				c.Kind = RemovedAndRenamed
			case !inB:
				c.Kind = BothAdded
			default:
				c.Kind = BothRenamed
			}
			conflicts = append(conflicts, c)
			// Carry the local value so the list stays usable; the caller
			// refuses while conflicts exist.
			if inL {
				out.Devices = append(out.Devices, ld)
			}
		}
	}
	return out, conflicts
}

// Equal reports whether two registries hold the same devices with the same
// names, regardless of order.
func Equal(a, b *Registry) bool {
	ai, bi := index(a), index(b)
	if len(ai) != len(bi) {
		return false
	}
	for mac, ad := range ai {
		bd, ok := bi[mac]
		if !ok || ad.Name != bd.Name {
			return false
		}
	}
	return true
}

func describe(present bool, name string) string {
	if !present {
		return "(not present)"
	}
	if name == "" {
		return "(unnamed)"
	}
	return name
}

// RenderConflicts produces the report written for a human to act on. It is
// deliberately plain text naming each side, rather than inline markers: the
// file is a description of a decision to make, not something to edit in place
// and feed back.
func RenderConflicts(cs []Conflict) string {
	var sb strings.Builder
	sb.WriteString("curfew: device list conflicts\n")
	sb.WriteString("=============================\n\n")
	fmt.Fprintf(&sb, "%d device(s) changed on BOTH your laptop and the router since they\n", len(cs))
	sb.WriteString("last agreed, so neither side can be applied without losing an edit.\n\n")
	for _, c := range cs {
		fmt.Fprintf(&sb, "%s  (%s)\n", c.MAC, c.Kind)
		fmt.Fprintf(&sb, "    last agreed : %s\n", describe(c.InBase, c.BaseName))
		fmt.Fprintf(&sb, "    your laptop : %s\n", describe(c.InLocal, c.LocalName))
		fmt.Fprintf(&sb, "    the router  : %s\n\n", describe(c.InRemote, c.RemoteName))
	}
	sb.WriteString("To resolve, pick a side per device by editing your local list, then push;\n")
	sb.WriteString("or take one side wholesale:\n\n")
	sb.WriteString("    curfew pull <host> --force    # the router wins, discarding local edits\n")
	sb.WriteString("    curfew push <host> --force    # your laptop wins, discarding router edits\n\n")
	sb.WriteString("Everything NOT listed above merged cleanly and is already in your local list.\n")
	return sb.String()
}
