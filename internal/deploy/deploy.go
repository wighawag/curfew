// Package deploy is the laptop side: putting the daemon on the router and
// moving configuration back and forth.
//
// It shells out to the system ssh and scp so it inherits the SSH setup the
// operator already has (agent, keys, ~/.ssh/config), rather than reimplementing
// any of that. What it does NOT inherit is the old installer's habit of ending
// every remote call in 2>/dev/null: every command here captures stderr and
// turns a non-zero exit into an error carrying that output. The previous
// installer reported success unconditionally, which is how two of its flags
// stayed dead without anyone noticing.
package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wighawag/curfew/internal/contract"
)

// Runner executes commands against the router. It is an interface so the
// install sequence can be tested without a router.
type Runner interface {
	// Run executes a command on the remote host, returning its stdout.
	Run(cmd string) (string, error)
	// Upload copies a local file to a remote path.
	Upload(localPath, remotePath string) error
	// Download copies a remote file to a local path.
	Download(remotePath, localPath string) error
}

// SSHRunner talks to a real router.
type SSHRunner struct {
	// Host is the ssh destination, for example root@192.168.1.1.
	Host string
	// Opts are extra ssh options.
	Opts []string
}

func (s SSHRunner) Run(cmd string) (string, error) {
	args := append([]string{}, s.Opts...)
	args = append(args, s.Host, cmd)
	c := exec.Command("ssh", args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ssh %s: %w: %s", cmd, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (s SSHRunner) scp(from, to string) error {
	// -O forces the legacy protocol: OpenWrt has no SFTP server, so without it
	// every copy fails on a modern scp.
	args := append([]string{"-O"}, s.Opts...)
	args = append(args, from, to)
	c := exec.Command("scp", args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("scp %s -> %s: %w: %s", from, to, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s SSHRunner) Upload(localPath, remotePath string) error {
	return s.scp(localPath, s.Host+":"+remotePath)
}

func (s SSHRunner) Download(remotePath, localPath string) error {
	return s.scp(s.Host+":"+remotePath, localPath)
}

// Paths on the router. Fixed rather than configurable, because a deployment
// that can land in two places is a deployment nobody can reason about.
//
// RemoteConfDir lives under /etc/config/ for a specific, measured reason: that
// is the only place a firmware upgrade preserves. OpenWrt's sysupgrade keep
// list (/lib/upgrade/keep.d/, read on the real image) contains "/etc/config/"
// and does NOT contain /usr/sbin or an arbitrary /etc/<app> directory, so a
// device list stored anywhere else is silently destroyed by the next
// sysupgrade and the household comes back with an empty allowlist. A
// subdirectory is used rather than a bare file so our data is namespaced;
// verified that uci tolerates both a subdirectory and a JSON file there and
// still reads neighbouring configs.
//
// The BINARY is deliberately not preserved: /usr/sbin is not in the keep list,
// so a sysupgrade removes it and you re-run `curfew install`, which ships a
// fresh binary and leaves the preserved device list alone.
const (
	RemoteBinary   = "/usr/sbin/curfew-daemon"
	RemoteConfDir  = "/etc/config/curfew"
	RemoteRegistry = "/etc/config/curfew/devices.json"
	RemoteInit     = "/etc/init.d/curfew"
	ServiceName    = "curfew"
	// RemoteKeepList registers our files for preservation across a firmware
	// upgrade. Without it a sysupgrade removes the daemon AND its service
	// definition, so the router comes back enforcing nothing, with every
	// device on the internet and nothing saying so. The device list survives
	// regardless (it lives under /etc/config/), which makes the gap worse
	// rather than better: the configuration says who is allowed while the
	// firewall allows everyone.
	//
	// This is the mechanism every OpenWrt package uses; dropbear keeps its
	// host keys the same way. NOTE it is convention verified by observing the
	// installed packages, not by reading the sysupgrade script, which is not
	// present in the rootfs test image. Confirm on the real router before
	// relying on it, and see the fallback in the comment on RemoteConfDir.
	RemoteKeepList = "/lib/upgrade/keep.d/curfew"
)

// GoArch maps what `uname -m` reports on the router to a GOARCH. Detecting
// this rather than assuming it matters because pushing the wrong architecture
// produces a binary that cannot exec, on a device reached over the network
// whose network is the thing being configured.
func GoArch(unameM string) (string, error) {
	switch strings.TrimSpace(unameM) {
	case "aarch64", "arm64":
		return "arm64", nil
	case "x86_64", "amd64":
		return "amd64", nil
	case "mips":
		return "mips", nil
	case "mipsel":
		return "mipsle", nil
	case "armv7l", "armv7":
		return "arm", nil
	default:
		return "", fmt.Errorf("unsupported router architecture %q", strings.TrimSpace(unameM))
	}
}

// DetectArch asks the router what it is.
func DetectArch(r Runner) (string, error) {
	out, err := r.Run("uname -m")
	if err != nil {
		return "", fmt.Errorf("detecting router architecture: %w", err)
	}
	return GoArch(out)
}

// initScript is the procd service. respawn is what replaces the resilience
// cron used to provide; it is available on OpenWrt (verified in the real
// image at /lib/functions/procd.sh).
func initScript(wan, lan, listen, user, password string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# curfew: parental control daemon. Managed by the curfew tool.
START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s \
        -registry %s \
        -lan %q \
        -wan %q \
        -listen %q
    procd_set_param env CURFEW_USER=%q CURFEW_PASSWORD=%q
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, RemoteBinary, RemoteRegistry, lan, wan, listen, user, password)
}

// InstallOptions configures a deployment.
type InstallOptions struct {
	LAN      string
	WAN      string
	Listen   string
	User     string
	Password string
	// BinaryPath is the locally built daemon to push.
	BinaryPath string
	// RegistryPath, when set and present on disk, is uploaded BEFORE the
	// service starts. This matters more than it looks: the daemon applies the
	// registry at startup, so starting with an empty one takes every device in
	// the house off the internet until something pushes a real list. Shipping
	// it as part of the install removes that window entirely.
	RegistryPath string
}

// Install puts the daemon on the router, installs the service and starts it.
//
// Ordering matters: the binary and the service definition land BEFORE anything
// is started, and the registry is only created if absent, so re-running an
// install never discards the device list.
func Install(r Runner, opt InstallOptions) error {
	if opt.WAN == "" {
		return fmt.Errorf("WAN interface is required")
	}
	if opt.BinaryPath == "" {
		return fmt.Errorf("no daemon binary to install")
	}
	if _, err := os.Stat(opt.BinaryPath); err != nil {
		return fmt.Errorf("daemon binary: %w", err)
	}

	if _, err := r.Run("mkdir -p " + RemoteConfDir); err != nil {
		return err
	}
	// Upload to a temp path then move, so a half-copied binary is never the
	// thing procd tries to exec.
	tmpRemote := RemoteBinary + ".new"
	if err := r.Upload(opt.BinaryPath, tmpRemote); err != nil {
		return err
	}
	if _, err := r.Run(fmt.Sprintf("chmod +x %s && mv %s %s", tmpRemote, tmpRemote, RemoteBinary)); err != nil {
		return err
	}

	local, err := os.CreateTemp("", "curfew-init-*")
	if err != nil {
		return fmt.Errorf("creating temp init script: %w", err)
	}
	defer os.Remove(local.Name())
	if _, err := local.WriteString(initScript(opt.WAN, opt.LAN, opt.Listen, opt.User, opt.Password)); err != nil {
		local.Close()
		return fmt.Errorf("writing temp init script: %w", err)
	}
	if err := local.Close(); err != nil {
		return fmt.Errorf("closing temp init script: %w", err)
	}
	if err := r.Upload(local.Name(), RemoteInit); err != nil {
		return err
	}
	if _, err := r.Run("chmod +x " + RemoteInit); err != nil {
		return err
	}

	// Ship the device list before anything starts, when there is one.
	if opt.RegistryPath != "" {
		if _, statErr := os.Stat(opt.RegistryPath); statErr == nil {
			if err := r.Upload(opt.RegistryPath, RemoteRegistry); err != nil {
				return err
			}
		}
	}
	// Otherwise ensure one exists, without ever clobbering a list already on
	// the router.
	if _, err := r.Run(fmt.Sprintf("[ -f %s ] || printf '%%s\\n' '{\"devices\":[]}' > %s",
		RemoteRegistry, RemoteRegistry)); err != nil {
		return err
	}

	// Register for preservation across a firmware upgrade, before starting.
	keep, err := os.CreateTemp("", "curfew-keep-*")
	if err != nil {
		return fmt.Errorf("creating temp keep list: %w", err)
	}
	defer os.Remove(keep.Name())
	if _, err := fmt.Fprintf(keep, "%s\n%s\n", RemoteBinary, RemoteInit); err != nil {
		keep.Close()
		return fmt.Errorf("writing temp keep list: %w", err)
	}
	if err := keep.Close(); err != nil {
		return fmt.Errorf("closing temp keep list: %w", err)
	}
	if _, err := r.Run("mkdir -p /lib/upgrade/keep.d"); err != nil {
		return err
	}
	if err := r.Upload(keep.Name(), RemoteKeepList); err != nil {
		return err
	}

	if _, err := r.Run(RemoteInit + " enable"); err != nil {
		return err
	}
	if _, err := r.Run(RemoteInit + " restart"); err != nil {
		return err
	}
	return nil
}

// Verify reads the allowlist back OUT OF THE FIREWALL on the router and
// reports how many MACs it is actually enforcing.
//
// This is the whole discipline of this project applied to deployment: an
// install that reports success because every command exited 0 is exactly the
// lie being removed. The only evidence that the daemon is enforcing is the
// kernel's own set.
func Verify(r Runner) (int, error) {
	out, err := r.Run(fmt.Sprintf("nft list set inet %s %s 2>&1 || true", contract.Table, contract.AllowedSet))
	if err != nil {
		return 0, err
	}
	if strings.Contains(out, "No such file") || strings.Contains(out, "does not exist") {
		return 0, fmt.Errorf("the %s table is not present: the daemon is not enforcing.\n%s", contract.Table, strings.TrimSpace(out))
	}
	i := strings.Index(out, "elements = {")
	if i < 0 {
		// The set exists but holds nothing. Legitimate for an empty registry,
		// and worth reporting as zero rather than as an error.
		return 0, nil
	}
	rest := out[i+len("elements = {"):]
	if j := strings.Index(rest, "}"); j >= 0 {
		rest = rest[:j]
	}
	count := 0
	for _, part := range strings.Split(rest, ",") {
		if strings.TrimSpace(part) != "" {
			count++
		}
	}
	return count, nil
}

// Push copies the local registry to the router and reloads the service.
func Push(r Runner, localPath string) error {
	if _, err := os.Stat(localPath); err != nil {
		return fmt.Errorf("local registry: %w", err)
	}
	if _, err := r.Run("mkdir -p " + RemoteConfDir); err != nil {
		return err
	}
	if err := r.Upload(localPath, RemoteRegistry); err != nil {
		return err
	}
	// Reload so the change takes effect now rather than at the next reconcile.
	if _, err := r.Run(RemoteInit + " restart"); err != nil {
		return err
	}
	return nil
}

// Pull copies the router's registry to a local path, creating the parent
// directory if needed.
func Pull(r Runner, localPath string) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("creating local directory: %w", err)
	}
	return r.Download(RemoteRegistry, localPath)
}
