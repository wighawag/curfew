// Package legacyconfig reads the pipe-delimited files the shell implementation
// used, so a live router can be migrated without anybody retyping MAC
// addresses.
//
// This exists for one reason: the new device registry starts EMPTY, and an
// empty allowlist means nothing in the house reaches the internet. Installing
// the daemon onto a working router without importing first would take the whole
// household offline, so the import is a safety step rather than a convenience.
package legacyconfig

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/wighawag/my-router/internal/registry"
)

// Profile is one line of the legacy parental_profiles file.
type Profile struct {
	Name   string
	Budget int
	MACs   []string
}

// ParseProfiles reads `name|budget|mac,mac,mac`, skipping blanks and comments.
//
// Malformed lines are REPORTED, not skipped. A silently ignored line here is a
// device that quietly loses internet after the migration, which is exactly the
// class of failure this rewrite exists to end.
func ParseProfiles(path string) ([]Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var profiles []Profile
	var problems []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			problems = append(problems, fmt.Sprintf("line %d: want name|budget|macs, got %q", lineNo, line))
			continue
		}
		name := strings.TrimSpace(parts[0])
		budget, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			// A non-numeric budget does not affect the allowlist, so it is
			// recorded as 0 rather than failing the whole import.
			budget = 0
		}
		var macs []string
		for _, raw := range strings.Split(parts[2], ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			canonical, err := registry.NormaliseMAC(raw)
			if err != nil {
				problems = append(problems, fmt.Sprintf("line %d (%s): %v", lineNo, name, err))
				continue
			}
			macs = append(macs, canonical)
		}
		profiles = append(profiles, Profile{Name: name, Budget: budget, MACs: macs})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(problems) > 0 {
		return profiles, fmt.Errorf("%s has %d unusable entr%s:\n  %s",
			path, len(problems), plural(len(problems)), strings.Join(problems, "\n  "))
	}
	return profiles, nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// ToRegistry flattens profiles into a device registry.
//
// The legacy format carried device names only as free-text comments, which
// cannot be mapped back to a specific MAC, so each device is named after its
// profile (suffixed when a profile has several). That is a name a human can
// recognise and correct from the page, which is better than leaving it blank.
//
// A MAC appearing in two profiles is registered ONCE. The real config has a
// profile listing the same MAC twice, and the allowlist has always been the
// deduplicated union, so preserving that is what keeps behaviour identical.
func ToRegistry(profiles []Profile) *registry.Registry {
	reg := &registry.Registry{Devices: []registry.Device{}}
	seen := map[string]bool{}
	for _, p := range profiles {
		// Deduplicate within the profile first, so the suffixes count real
		// devices rather than repeated entries.
		var unique []string
		inProfile := map[string]bool{}
		for _, m := range p.MACs {
			if inProfile[m] {
				continue
			}
			inProfile[m] = true
			unique = append(unique, m)
		}
		for i, m := range unique {
			if seen[m] {
				continue
			}
			seen[m] = true
			name := p.Name
			if len(unique) > 1 {
				name = fmt.Sprintf("%s-%d", p.Name, i+1)
			}
			// Add cannot fail here: every MAC was canonicalised at parse time.
			_ = reg.Add(m, name)
		}
	}
	return reg
}
