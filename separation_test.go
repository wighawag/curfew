package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The laptop binary must not be able to touch a firewall.
//
// This is the reason there are two binaries rather than one with a subcommand:
// running the wrong thing on a laptop should be incapable of rewriting that
// laptop's own network. A comment saying so would rot, so the property is
// asserted against the real import graph. If someone later imports the
// enforcement package here for convenience, this fails and explains why.
func TestLaptopBinaryCannotImportEnforcement(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, dep := range strings.Split(string(out), "\n") {
		switch strings.TrimSpace(dep) {
		case "github.com/wighawag/curfew/internal/enforce":
			t.Error("the laptop binary imports internal/enforce. It must not: " +
				"the whole point of the two-binary split is that the laptop tool " +
				"cannot rewrite a firewall. Move the logic behind the deploy layer.")
		case "github.com/google/nftables":
			t.Error("the laptop binary pulls in github.com/google/nftables. " +
				"Nothing on the laptop side should be able to talk to netfilter.")
		}
	}
}

// The daemon is the one that SHOULD have it. Without this control the test
// above would pass just as happily if the enforcement package were deleted.
func TestDaemonBinaryDoesImportEnforcement(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./cmd/curfew-daemon").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	if !strings.Contains(string(out), "github.com/wighawag/curfew/internal/enforce") {
		t.Error("the daemon does not import internal/enforce, so the check above proves nothing")
	}
}
