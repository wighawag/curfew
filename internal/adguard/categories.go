package adguard

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Which category blocklists AdGuard subscribes to, as something a household
// OWNS rather than something baked into the installer.
//
// It exists because the set was compiled in: `curfew install` wrote eight
// lists and nothing could change them afterwards, so a household that deleted
// one in AdGuard's UI got it back on the next install. That is exactly the
// defect ADR 0002 recorded for the always-allowed sites, one level up, and the
// same answer applies: the choice lives in curfew's config, travels with push
// and pull, and survives a reinstall.
//
// # Why this edits AdGuard's config file when ADR 0010 says to use the API
//
// Because the API cannot do it safely on the hardware this runs on. Removing a
// list through /control/filtering/remove_url makes AdGuard rebuild its whole
// filtering engine, holding the old one and the new one at once. Measured on
// the live router: AdGuard resident at 547 MB with 300 MB available, and a
// rebuild is what OOM-killed it on 2026-08-08 and cost the household 88
// seconds of DNS. Shrinking the rule set through the API therefore needs a
// spike larger than the memory the shrink would free, which is a deadlock.
//
// Writing the config and restarting builds the engine ONCE, cold, with no
// spike at all. It costs a deliberate minute of downtime instead of a random
// one, and the alternative on this router is an OOM kill at whatever hour
// AdGuard's own 24-hour refresh happens to land on.
//
// The edit is deliberately the smallest possible: only the `filters:` block is
// touched, every other byte of the file is preserved, and inside that block
// only entries whose URL is one curfew itself installs are added or removed. A
// list a household subscribed to by hand has a different URL and is invisible
// here, which is the same ownership boundary the client objects use.

// FilterEntry is one subscribed list as AdGuard's config records it.
type FilterEntry struct {
	Enabled bool
	URL     string
	Name    string
	ID      int64
}

// OwnedCategory reports whether this URL is one curfew's own category list,
// and which category it is. Anything else belongs to the household.
func OwnedCategory(url string) (string, bool) {
	for _, name := range Categories {
		if CategoryURL(name) == url {
			return name, true
		}
	}
	return "", false
}

// KnownCategory reports whether name is a category curfew can install.
func KnownCategory(name string) bool {
	for _, c := range Categories {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

// CanonicalCategory returns the catalogue's spelling of a category name.
func CanonicalCategory(name string) (string, bool) {
	for _, c := range Categories {
		if strings.EqualFold(c, name) {
			return c, true
		}
	}
	return "", false
}

// SetCategories rewrites a config so the category lists curfew owns are
// exactly those in wanted, and reports whether anything changed.
//
// Everything outside the `filters:` block is returned byte for byte. Inside
// it, entries curfew does not own keep their position and their text: a
// household's own list, and curfew's own managed filter list, are carried
// through untouched.
func SetCategories(config string, wanted []string) (string, bool, error) {
	want := map[string]bool{}
	for _, name := range wanted {
		c, ok := CanonicalCategory(name)
		if !ok {
			return "", false, fmt.Errorf("no category called %q; curfew knows %s",
				name, strings.Join(Categories, ", "))
		}
		want[c] = true
	}

	lines := strings.Split(config, "\n")
	start, end := filtersBlock(lines)
	if start < 0 {
		return "", false, fmt.Errorf("this AdGuard config has no top-level 'filters:' key, " +
			"so curfew will not edit it")
	}

	entries, indent, err := parseEntries(lines[start+1 : end])
	if err != nil {
		return "", false, err
	}

	var kept []FilterEntry
	have := map[string]bool{}
	maxID := int64(0)
	for _, e := range entries {
		if e.ID > maxID {
			maxID = e.ID
		}
		name, owned := OwnedCategory(e.URL)
		if !owned {
			kept = append(kept, e) // the household's own, or curfew's managed list
			continue
		}
		if want[name] {
			kept = append(kept, e)
			have[name] = true
		}
	}
	// Added at the end, with fresh ids, so an id AdGuard is already using for
	// a list's data file is never reused for different content.
	var missing []string
	for name := range want {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		maxID++
		kept = append(kept, FilterEntry{
			Enabled: true, URL: CategoryURL(name), Name: name, ID: maxID,
		})
	}

	rendered := renderEntries(kept, indent)
	if equalLines(lines[start+1:end], rendered) {
		return config, false, nil
	}
	out := append([]string{}, lines[:start+1]...)
	out = append(out, rendered...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), true, nil
}

// Categories lists the category lists a config currently subscribes to.
func ConfiguredCategories(config string) []string {
	lines := strings.Split(config, "\n")
	start, end := filtersBlock(lines)
	if start < 0 {
		return nil
	}
	entries, _, err := parseEntries(lines[start+1 : end])
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if name, owned := OwnedCategory(e.URL); owned {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// filtersBlock finds the line index of `filters:` and the index one past its
// last member. A top-level key is a line that starts in column zero, which is
// what ends the block; `filters: []` has no members at all.
func filtersBlock(lines []string) (start, end int) {
	start = -1
	for i, line := range lines {
		if strings.HasPrefix(line, "filters:") {
			start = i
			break
		}
	}
	if start < 0 {
		return -1, -1
	}
	if strings.TrimSpace(strings.TrimPrefix(lines[start], "filters:")) == "[]" {
		return start, start + 1
	}
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '-' && line[0] != '\t' {
			return start, i
		}
	}
	return start, len(lines)
}

// parseEntries reads the members of the filters block, and reports the
// indentation the file uses for them.
//
// AdGuard writes `  - enabled: true` with two spaces; the config curfew's own
// installer writes has the dash in column zero. Both are valid YAML and both
// occur in the wild, so the indentation is FOLLOWED rather than imposed: a
// rewrite that reindented the block would produce a diff a household reading
// its own config could not explain.
func parseEntries(lines []string) ([]FilterEntry, string, error) {
	var out []FilterEntry
	// An EMPTY indent is a real answer, not a missing one: the config curfew's
	// own installer writes puts the dash in column zero. Defaulting on "" would
	// reindent every fresh install's file on the first edit.
	indent, seenItem := "", false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if !seenItem {
				indent = line[:strings.Index(line, "-")]
				seenItem = true
			}
			out = append(out, FilterEntry{})
			trimmed = strings.TrimPrefix(trimmed, "- ")
		} else if len(out) == 0 {
			return nil, "", fmt.Errorf("unexpected line in the filters block: %q", line)
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, "", fmt.Errorf("unexpected line in the filters block: %q", line)
		}
		e := &out[len(out)-1]
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "enabled":
			e.Enabled = value == "true"
		case "url":
			e.URL = unquote(value)
		case "name":
			e.Name = unquote(value)
		case "id":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, "", fmt.Errorf("filter id %q is not a number", value)
			}
			e.ID = n
		default:
			// A key curfew does not know about is a key AdGuard added. It is
			// preserved by keeping the ENTRY, but curfew cannot render it, so
			// refuse rather than write a file that silently drops it.
			return nil, "", fmt.Errorf("this AdGuard's filter entries carry a field curfew "+
				"does not know (%q), so curfew will not rewrite them", strings.TrimSpace(key))
		}
	}
	if !seenItem {
		indent = "  " // an empty block: follow what AdGuard itself writes
	}
	return out, indent, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

// quoteName quotes a name the way AdGuard does when it needs to.
func quoteName(s string) string {
	if strings.ContainsAny(s, ":#{}[]&*!|>'\"%@`") || strings.TrimSpace(s) != s || s == "" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return s
}

func renderEntries(entries []FilterEntry, indent string) []string {
	var out []string
	for _, e := range entries {
		out = append(out,
			fmt.Sprintf("%s- enabled: %t", indent, e.Enabled),
			fmt.Sprintf("%s  url: %s", indent, e.URL),
			fmt.Sprintf("%s  name: %s", indent, quoteName(e.Name)),
			fmt.Sprintf("%s  id: %d", indent, e.ID),
		)
	}
	return out
}

func equalLines(a, b []string) bool {
	// Blank lines inside the block are noise for this comparison.
	strip := func(in []string) []string {
		var out []string
		for _, l := range in {
			if strings.TrimSpace(l) != "" {
				out = append(out, l)
			}
		}
		return out
	}
	x, y := strip(a), strip(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
