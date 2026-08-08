// Package shellrun runs commands on the machine it is running on.
//
// It exists so that the same logic can be driven two ways: over ssh from a
// laptop by internal/deploy, or locally by the daemon on the router. Both
// speak the same tiny Runner interface, so internal/leases and
// internal/lanhosts do not need to know which side they are on.
//
// It captures stderr and turns a non-zero exit into an error carrying that
// output, for the reason recorded on internal/deploy: the installer this
// replaces ended every remote call in 2>/dev/null and reported success
// unconditionally, which is how two of its flags stayed dead unnoticed.
package shellrun

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Local runs commands with /bin/sh on this machine.
type Local struct{}

// Run executes a command and returns its stdout.
func (Local) Run(cmd string) (string, error) {
	c := exec.Command("sh", "-c", cmd)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %w: %s", cmd, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
