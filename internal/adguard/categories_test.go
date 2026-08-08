package adguard

import (
	"strings"
	"testing"
)

// liveFilters is the filters block copied verbatim off the live router on
// 2026-08-08, after AdGuard had rewritten the file itself. The indentation and
// the quoted name are AdGuard's, not curfew's, and pinning against them is the
// point: the installer's own format is NOT the format this code will meet.
const liveFilters = `filters:
  - enabled: true
    url: https://blocklistproject.github.io/Lists/adguard/gambling-ags.txt
    name: Gambling
    id: 1
  - enabled: true
    url: https://blocklistproject.github.io/Lists/adguard/porn-ags.txt
    name: Porn
    id: 2
  - enabled: true
    url: https://blocklistproject.github.io/Lists/adguard/malware-ags.txt
    name: Malware
    id: 3
  - enabled: true
    url: https://blocklistproject.github.io/Lists/adguard/ads-ags.txt
    name: Ads
    id: 8
  - enabled: true
    url: http://192.168.1.1:8080/curfew-filter.txt
    name: 'curfew (managed: do not edit)'
    id: 1786170369
`

// liveConfig wraps that block in the neighbours it really has, so the test can
// assert that everything outside it survives byte for byte.
const liveConfig = `http:
  address: 0.0.0.0:3000
dns:
  bind_hosts:
    - 192.168.1.1
  upstream_dns:
    - 1.1.1.1
` + liveFilters + `whitelist_filters: []
user_rules:
  - '@@||handwritten.example^'
dhcp:
  enabled: false
`

func TestRemovingACategoryLeavesEveryOtherByteOfTheConfigAlone(t *testing.T) {
	out, changed, err := SetCategories(liveConfig, []string{"Gambling", "Porn", "Ads"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removing the Malware list reported no change")
	}
	if strings.Contains(out, "malware-ags.txt") {
		t.Errorf("the Malware list is still subscribed:\n%s", out)
	}

	// The household's own things, and curfew's own managed list, survive.
	for _, want := range []string{
		"curfew-filter.txt",
		"name: 'curfew (managed: do not edit)'",
		"id: 1786170369",
		"'@@||handwritten.example^'",
		"bind_hosts",
		"1.1.1.1",
		"dhcp:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("removing a category destroyed %q:\n%s", want, out)
		}
	}
	// The ids of the lists that stayed must not move: AdGuard names each
	// list's cached file after its id, so renumbering would hand a list
	// somebody else's rules.
	if !strings.Contains(out, "url: https://blocklistproject.github.io/Lists/adguard/ads-ags.txt\n    name: Ads\n    id: 8") {
		t.Errorf("the surviving lists were renumbered:\n%s", out)
	}
	// And nothing outside the filters block moved.
	if !strings.HasPrefix(out, "http:\n  address: 0.0.0.0:3000\ndns:\n") {
		t.Errorf("the head of the file changed:\n%s", out)
	}
}

func TestAddingACategoryAppendsItWithAFreshID(t *testing.T) {
	out, changed, err := SetCategories(liveConfig,
		[]string{"Gambling", "Porn", "Malware", "Ads", "Phishing"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("adding a category reported no change")
	}
	if !strings.Contains(out, "phishing-ags.txt") {
		t.Errorf("the new category is not subscribed:\n%s", out)
	}
	// A fresh id, above every id in use, so it cannot collide with the cached
	// data file of a list that was removed earlier.
	if !strings.Contains(out, "id: 1786170370") {
		t.Errorf("the new list reused an id already in use:\n%s", out)
	}
	if got := ConfiguredCategories(out); len(got) != 5 {
		t.Errorf("want five categories after the add, got %v", got)
	}
}

// Nothing to do must WRITE nothing, or every pass would rewrite AdGuard's
// config and every save would cost a restart.
func TestNoChangeIsReportedAsNoChange(t *testing.T) {
	_, changed, err := SetCategories(liveConfig, []string{"Gambling", "Porn", "Malware", "Ads"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a config that already says exactly this was rewritten anyway")
	}
	// Order must not matter either.
	_, changed, err = SetCategories(liveConfig, []string{"Ads", "Malware", "Porn", "Gambling"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("listing the same categories in a different order counted as a change")
	}
}

// The installer's own format has the dash in column zero. Both shapes are
// valid YAML and both exist in the wild, so both must round trip.
func TestTheInstallersOwnFormatRoundTrips(t *testing.T) {
	cfg := InitialConfig(ConfigParams{User: "parent", PasswordHash: "x", RouterIP: "192.168.1.1"})
	if got := ConfiguredCategories(cfg); len(got) != len(Categories) {
		t.Fatalf("baseline: a fresh install should carry every category, got %v", got)
	}
	out, changed, err := SetCategories(cfg, []string{"Porn", "Ads"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("dropping six categories reported no change")
	}
	if strings.Contains(out, "malware-ags.txt") {
		t.Errorf("Malware survived:\n%s", out)
	}
	// The indentation of the block must be the file's own, not this code's.
	if !strings.Contains(out, "\n- enabled: true\n  url: https://blocklistproject") {
		t.Errorf("the block was reindented:\n%s", out)
	}
	if !strings.Contains(out, "whitelist_filters: []") {
		t.Errorf("the tail of the file was lost:\n%s", out)
	}
}

// A household that removed every category is a household with no category
// filtering, which is allowed and must not corrupt the file.
func TestEveryCategoryCanBeRemoved(t *testing.T) {
	out, changed, err := SetCategories(liveConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removing everything reported no change")
	}
	if strings.Contains(out, "blocklistproject") {
		t.Errorf("a category list survived:\n%s", out)
	}
	// curfew's own list is NOT a category and must still be there, or the
	// household's exceptions and restrictions would go with it.
	if !strings.Contains(out, "curfew-filter.txt") {
		t.Errorf("curfew's own managed list was removed as if it were a category:\n%s", out)
	}
	if _, _, err := SetCategories(out, []string{"Porn"}); err != nil {
		t.Errorf("the file this produced cannot be edited again: %v", err)
	}
}

// A config whose filter entries carry a field curfew cannot render must be
// REFUSED, not rewritten with the field silently dropped.
func TestAnUnknownFieldInAFilterEntryIsRefused(t *testing.T) {
	cfg := strings.Replace(liveConfig, "    id: 1\n", "    id: 1\n    checksum: abc123\n", 1)
	if _, _, err := SetCategories(cfg, []string{"Porn"}); err == nil {
		t.Error("a filter entry with an unknown field was rewritten anyway, dropping it")
	}
}

func TestAConfigWithNoFiltersKeyIsRefused(t *testing.T) {
	if _, _, err := SetCategories("http:\n  address: x\n", []string{"Porn"}); err == nil {
		t.Error("a config with no filters key was edited anyway")
	}
}

func TestAnUnknownCategoryIsRefusedWithTheCatalogue(t *testing.T) {
	_, _, err := SetCategories(liveConfig, []string{"Porn", "Cats"})
	if err == nil {
		t.Fatal("an unknown category was accepted, so a typo silently subscribes nothing")
	}
	if !strings.Contains(err.Error(), "Gambling") {
		t.Errorf("the refusal does not say what the choices are: %v", err)
	}
}

// The ownership boundary, stated as a test: a list a household added by hand
// is not curfew's to touch.
func TestAHouseholdsOwnListIsNotACategory(t *testing.T) {
	if _, owned := OwnedCategory("https://someoneelse.example/list.txt"); owned {
		t.Error("a stranger's list was claimed as curfew's")
	}
	if _, owned := OwnedCategory("http://192.168.1.1:8080/curfew-filter.txt"); owned {
		t.Error("curfew's own managed list was claimed as a category, so removing " +
			"every category would delete the household's exceptions with it")
	}
	if _, owned := OwnedCategory(CategoryURL("Malware")); !owned {
		t.Error("curfew does not recognise its own category list")
	}
}
