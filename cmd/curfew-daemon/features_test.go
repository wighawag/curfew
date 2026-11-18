package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// `curfew push` refuses to send a field to a daemon that does not list it here,
// because that daemon's page would drop it on its next save. So the list is a
// promise, and each entry is asserted by running the flag for real.
func TestFeaturesListsEveryRegistryFieldThisDaemonUnderstands(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	code := run([]string{"-features"}, os.Stderr)
	os.Stdout = saved
	w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if code != 0 {
		t.Fatalf("-features exited %d", code)
	}
	got := strings.Fields(buf.String())
	for _, want := range []string{"fixed-address", "local-dns-names"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("-features does not list %q: %v", want, got)
		}
	}
}
