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
	// BothChangedIP means each side gave the device a different fixed address
	// (one of them may have cleared it).
	BothChangedIP ConflictKind = "fixed address changed differently on both sides"
	// RemovedAndRenamed means one side removed the device while the other
	// changed it (renamed it, or set or cleared its fixed address). This one
	// matters: taking the removal silently discards an edit, and taking the
	// edit silently restores network access.
	RemovedAndRenamed ConflictKind = "removed on one side, changed on the other"
	// BothAdded means the device is new to both sides, with different names
	// or fixed addresses.
	BothAdded ConflictKind = "added on both sides differently"
)

// Conflict is one device that needs a human.
type Conflict struct {
	MAC  string
	Kind ConflictKind
	// Each side's name and fixed address, and whether the device was present.
	BaseName, LocalName, RemoteName string
	BaseIP, LocalIP, RemoteIP       string
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

// sameDevice compares every field a person can edit. Adding a field to Device
// without adding it here would make push and pull silently discard it, which
// is the trap ADR 0009 recorded for the budget knobs.
func sameDevice(a, b Device) bool { return a.Name == b.Name && a.IP == b.IP }

// mergeField is the three-way rule for ONE field of a device present on both
// sides: agreement, or whichever side moved away from the base. ok is false
// when both moved, differently.
func mergeField(base, local, remote string) (string, bool) {
	switch {
	case local == remote:
		return local, true
	case local == base:
		return remote, true
	case remote == base:
		return local, true
	}
	return local, false
}

// Merge3 merges local and remote against their common base.
//
// A device present on both sides is merged FIELD BY FIELD, so a rename on the
// laptop and a fixed address set on the router are independent edits and both
// apply. Only the same field changed differently on both sides is a conflict.
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
		conflict := func(kind ConflictKind) {
			conflicts = append(conflicts, Conflict{
				MAC: mac, Kind: kind, InBase: inB, InLocal: inL, InRemote: inR,
				BaseName: bd.Name, LocalName: ld.Name, RemoteName: rd.Name,
				BaseIP: bd.IP, LocalIP: ld.IP, RemoteIP: rd.IP,
			})
			// Carry the local value so the list stays usable; the caller
			// refuses while conflicts exist.
			if inL {
				out.Devices = append(out.Devices, ld)
			}
		}

		switch {
		case !inL && !inR:
			// Removed on both sides, or never anywhere: agreement.
		case inL && inR && sameDevice(ld, rd):
			out.Devices = append(out.Devices, ld)
		case inL && inR && !inB:
			// New on both sides, differently. With no common ancestor there
			// is no way to know which is newer, so this is not guessed.
			conflict(BothAdded)
		case inL && inR:
			name, nameOK := mergeField(bd.Name, ld.Name, rd.Name)
			ip, ipOK := mergeField(bd.IP, ld.IP, rd.IP)
			switch {
			case !nameOK:
				conflict(BothRenamed)
			case !ipOK:
				conflict(BothChangedIP)
			default:
				out.Devices = append(out.Devices, Device{MAC: mac, Name: name, IP: ip})
			}
		default:
			// Present on exactly one side.
			present := ld
			if inR {
				present = rd
			}
			switch {
			case !inB:
				// Added on that side.
				out.Devices = append(out.Devices, present)
			case sameDevice(present, bd):
				// Removed on the other side and untouched here: the removal wins.
			default:
				conflict(RemovedAndRenamed)
			}
		}
	}
	return out, conflicts
}

// Equal reports whether two registries hold the same devices with the same
// names and fixed addresses, regardless of order. push uses this to decide
// whether the router changed since the last sync, so a field missing here is
// a field push silently overwrites.
func Equal(a, b *Registry) bool {
	ai, bi := index(a), index(b)
	if len(ai) != len(bi) {
		return false
	}
	for mac, ad := range ai {
		bd, ok := bi[mac]
		if !ok || !sameDevice(ad, bd) {
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

func describeIP(present bool, ip string) string {
	if !present {
		return "(not present)"
	}
	if ip == "" {
		return "(none)"
	}
	return ip
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
		fmt.Fprintf(&sb, "    the router  : %s\n", describe(c.InRemote, c.RemoteName))
		if c.BaseIP != c.LocalIP || c.LocalIP != c.RemoteIP {
			sb.WriteString("    fixed address:\n")
			fmt.Fprintf(&sb, "      last agreed : %s\n", describeIP(c.InBase, c.BaseIP))
			fmt.Fprintf(&sb, "      your laptop : %s\n", describeIP(c.InLocal, c.LocalIP))
			fmt.Fprintf(&sb, "      the router  : %s\n", describeIP(c.InRemote, c.RemoteIP))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("To resolve, pick a side per device by editing your local list, then push;\n")
	sb.WriteString("or take one side wholesale:\n\n")
	sb.WriteString("    curfew pull <host> --force    # the router wins, discarding local edits\n")
	sb.WriteString("    curfew push <host> --force    # your laptop wins, discarding router edits\n\n")
	sb.WriteString("Everything NOT listed above merged cleanly and is already in your local list.\n")
	return sb.String()
}
