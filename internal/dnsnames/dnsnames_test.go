package dnsnames

import (
	"strings"
	"testing"
)

func TestCanonicalSetFoldsSpellingOrderAndDuplicates(t *testing.T) {
	got := CanonicalSet([]string{" *.LAN.Telemaque.ska.sh. ", "nas.home.arpa", "*.lan.telemaque.ska.sh", ""})
	want := []string{"*.lan.telemaque.ska.sh", "nas.home.arpa"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseAcceptsTheTwoFormsAndRefusesEverythingElse(t *testing.T) {
	for _, ok := range []string{
		"*.lan.telemaque.ska.sh", "lan.telemaque.ska.sh", "nas.home.arpa", "xn--bcher-kva.example",
		"a-b.example", "breakoutbunny.lan.telemaque.ska.sh.",
	} {
		if _, err := Parse(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"":                     "empty",
		"nas":                  "single label",
		"*.sh":                 "top-level domain",
		"a.*.example":          "'*' is only allowed",
		"*.*.example":          "'*' is only allowed",
		"*example.com":         "'*' is only allowed",
		"192.168.1.122":        "address",
		"under_score.example":  "only letters",
		"-bad.example":         "hyphen",
		"bad-.example":         "hyphen",
		"a..example":           "empty label",
		"bücher.example":       "xn--",
		"x." + long(64) + ".a": "longer than 63",
		long(250) + ".example": "253",
	} {
		_, err := Parse(bad)
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), why) {
			t.Errorf("%q: want a reason mentioning %q, got %v", bad, why, err)
		}
	}
}

func long(n int) string { return strings.Repeat("a", n) }

func mustParse(t *testing.T, s string) Name {
	t.Helper()
	n, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The meaning of a name, ADR 0013: x covers x and below; *.x strictly below.
func TestCoversIsTheADRMeaning(t *testing.T) {
	bare, wild := mustParse(t, "lan.example.com"), mustParse(t, "*.lan.example.com")
	for host, want := range map[string][2]bool{
		"lan.example.com":       {true, false},
		"a.lan.example.com":     {true, true},
		"a.b.lan.example.com":   {true, true},
		"example.com":           {false, false},
		"xlan.example.com":      {false, false},
		"lan.example.com.other": {false, false},
	} {
		if got := bare.Covers(host); got != want[0] {
			t.Errorf("%s covers %s = %v, want %v", bare, host, got, want[0])
		}
		if got := wild.Covers(host); got != want[1] {
			t.Errorf("%s covers %s = %v, want %v", wild, host, got, want[1])
		}
	}
}

func TestOverlapMatrix(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"x.example", "x.example", true},
		{"x.example", "*.x.example", true},
		{"x.example", "a.x.example", true},
		{"*.x.example", "a.x.example", true},
		{"*.x.example", "*.a.x.example", true},
		{"*.a.x.example", "x.example", true},
		{"*.x.example", "x.example.other", false},
		{"*.a.x.example", "b.x.example", false},
		{"a.x.example", "b.x.example", false},
		{"*.x.example", "*.y.example", false},
		{"*.a.x.example", "a.x.example", true}, // a.x covers everything below itself
	}
	for _, c := range cases {
		a, b := mustParse(t, c.a), mustParse(t, c.b)
		if got := Overlaps(a, b); got != c.want {
			t.Errorf("Overlaps(%s, %s) = %v, want %v", a, b, got, c.want)
		}
		if got := Overlaps(b, a); got != c.want {
			t.Errorf("Overlaps(%s, %s) = %v, want %v (not symmetric)", b, a, got, c.want)
		}
	}
	// The one asymmetric-looking case: *.x does not reach x itself, so it
	// overlaps a name ABOVE x only because that name covers everything below.
	if Overlaps(mustParse(t, "*.x.example"), mustParse(t, "y.x.example")) != true {
		t.Error("*.x must overlap a name strictly below x")
	}
}

func workstation(names ...string) Device {
	return Device{MAC: "38:05:25:3a:b0:70", Label: "workstation igc (38:05:25:3a:b0:70)",
		Fixed: "192.168.1.122", Names: names}
}

func only(t *testing.T, rs []Result, name string) Result {
	t.Helper()
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no result for %q in %+v", name, rs)
	return Result{}
}

func mentions(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestTheHouseholdsOwnNameIsAccepted(t *testing.T) {
	rs := Check([]Device{workstation("*.lan.telemaque.ska.sh")}, routerContext())
	r := only(t, rs, "*.lan.telemaque.ska.sh")
	if len(r.Errors) != 0 || len(r.Warnings) != 0 {
		t.Errorf("the real name was not accepted cleanly: %+v", r)
	}
}

func routerContext() Context {
	return Context{Known: true, LocalDomains: []string{"/lan/", "lan"},
		RouterHostnames: []string{"0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org", "1.1.1.1"}}
}

func TestANameNeedsAFixedAddress(t *testing.T) {
	d := workstation("*.lan.telemaque.ska.sh")
	d.Fixed = ""
	r := only(t, Check([]Device{d}, Context{}), "*.lan.telemaque.ska.sh")
	if !mentions(r.Errors, "no fixed address") || !mentions(r.Errors, "curfew set-ip") {
		t.Errorf("want a fixed-address refusal naming set-ip: %+v", r)
	}
}

func TestOverlapAcrossDevicesIsRefusedOnBothNamingTheOther(t *testing.T) {
	other := Device{MAC: "84:47:09:84:8e:b2", Label: "shyrka (84:47:09:84:8e:b2)", Fixed: "192.168.1.150",
		Names: []string{"nas.lan.telemaque.ska.sh"}}
	rs := Check([]Device{workstation("*.lan.telemaque.ska.sh"), other}, Context{})
	a := only(t, rs, "*.lan.telemaque.ska.sh")
	b := only(t, rs, "nas.lan.telemaque.ska.sh")
	if !mentions(a.Errors, "shyrka") || !mentions(b.Errors, "workstation igc") {
		t.Errorf("each side must name the other device: %+v / %+v", a, b)
	}
	// Control: disjoint names on two devices are fine.
	other.Names = []string{"nas.home.arpa"}
	rs = Check([]Device{workstation("*.lan.telemaque.ska.sh"), other}, Context{})
	for _, r := range rs {
		if len(r.Errors) != 0 {
			t.Errorf("disjoint names were refused: %+v", r)
		}
	}
}

func TestARedundantNameOnTheSameDeviceIsRefused(t *testing.T) {
	rs := Check([]Device{workstation("lan.telemaque.ska.sh", "*.lan.telemaque.ska.sh", "a.lan.telemaque.ska.sh")}, Context{})
	if r := only(t, rs, "lan.telemaque.ska.sh"); len(r.Errors) != 0 {
		t.Errorf("the covering name itself must stay valid: %+v", r)
	}
	for _, n := range []string{"*.lan.telemaque.ska.sh", "a.lan.telemaque.ska.sh"} {
		if r := only(t, rs, n); !mentions(r.Errors, "already covered by lan.telemaque.ska.sh") {
			t.Errorf("%s must be refused as redundant: %+v", n, r)
		}
	}
}

func TestTheRoutersLocalDomainIsRefusedFromEitherOption(t *testing.T) {
	for _, local := range []string{"/lan/", "lan"} {
		ctx := Context{Known: true, LocalDomains: []string{local}}
		for _, n := range []string{"printer.lan", "*.home.lan"} {
			// "printer.lan" has two labels and so is syntactically fine; it
			// is the local-domain rule that must catch it.
			r := only(t, Check([]Device{workstation(n)}, ctx), n)
			if !mentions(r.Errors, "local domain .lan") {
				t.Errorf("%s with local %q: %+v", n, local, r)
			}
		}
	}
	// Without a router context the rule cannot run, and must not guess.
	r := only(t, Check([]Device{workstation("printer.lan")}, Context{}), "printer.lan")
	if mentions(r.Errors, "local domain") {
		t.Errorf("the local-domain rule ran with no router context: %+v", r)
	}
}

func TestSpecialUseDomainsAreRefusedButHomeArpaIsAllowed(t *testing.T) {
	for _, n := range []string{"printer.local", "*.foo.localhost", "x.invalid", "x.onion", "1.168.192.in-addr.arpa"} {
		r := only(t, Check([]Device{workstation(n)}, Context{}), n)
		if len(r.Errors) == 0 {
			t.Errorf("%s accepted", n)
		}
	}
	for _, n := range []string{"nas.home.arpa", "*.studio.home.arpa"} {
		r := only(t, Check([]Device{workstation(n)}, Context{}), n)
		if len(r.Errors) != 0 {
			t.Errorf("%s refused: %+v", n, r)
		}
	}
}

func TestANameCoveringARouterHostnameIsRefused(t *testing.T) {
	for _, n := range []string{"*.pool.ntp.org", "openwrt.pool.ntp.org"} {
		r := only(t, Check([]Device{workstation(n)}, routerContext()), n)
		if !mentions(r.Errors, "the router itself") {
			t.Errorf("%s would answer for the router's NTP server and was accepted: %+v", n, r)
		}
	}
	// An upstream given as an address matches no name.
	r := only(t, Check([]Device{workstation("one.one.example")}, routerContext()), "one.one.example")
	if len(r.Errors) != 0 {
		t.Errorf("an unrelated name was refused: %+v", r)
	}
}

func TestAWholeRegistrableDomainIsWarnedNotRefused(t *testing.T) {
	for _, n := range []string{"example.com", "*.example.com"} {
		r := only(t, Check([]Device{workstation(n)}, Context{}), n)
		if len(r.Errors) != 0 || !mentions(r.Warnings, "every name in example.com") {
			t.Errorf("%s: want a warning only, got %+v", n, r)
		}
	}
	r := only(t, Check([]Device{workstation("lan.example.com")}, Context{}), "lan.example.com")
	if len(r.Warnings) != 0 {
		t.Errorf("a three-label name was warned about: %+v", r)
	}
}

func TestAnUnparseableStoredNameIsReportedNotDropped(t *testing.T) {
	r := only(t, Check([]Device{workstation("bad_name.example")}, Context{}), "bad_name.example")
	if len(r.Errors) == 0 {
		t.Errorf("a bad stored name was not refused: %+v", r)
	}
}
