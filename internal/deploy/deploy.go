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

	"github.com/wighawag/curfew/internal/blockstate"
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
	RemoteProfiles = "/etc/config/curfew/profiles.json"
	// RemoteState is the persisted block state: which profiles a parent has
	// blocked until they say otherwise. It is STATE rather than config, and it
	// lives here anyway for the same measured reason as everything else in
	// this directory. If a reboot or an upgrade lost it, a grounded child would
	// come back online with nothing saying so.
	//
	// Neither push nor pull touches it. It is the router's own state, and
	// copying a laptop's idea of who is grounded over the top of it would
	// silently undo a decision made on the phone five minutes earlier.
	//
	// Taken from the daemon's own default rather than written out again here.
	// Two literals for one path is how the table name once desynchronised (see
	// the comment on internal/contract), and the failure would be quiet: the
	// service would be told to keep state in a file nothing else reads.
	RemoteState = blockstate.DefaultPath
	RemoteInit  = "/etc/init.d/curfew"
	ServiceName = "curfew"
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
	// RemoteDaemonConf holds the daemon's settings as DATA rather than baked
	// into the generated init script. That is what lets `update` replace the
	// binary and the service template without being told the WAN interface and
	// the password all over again, and without silently changing them.
	RemoteDaemonConf = "/etc/config/curfew/daemon.conf"
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

// DetectTimezone reads the router's own configured zone name.
//
// It matters because OpenWrt ships no zoneinfo database, so the daemon's
// process default is UTC. A household that set Europe/London in LuCI would
// otherwise get bedtimes an hour out for half the year, with nothing saying
// so. An empty result is not an error: it means the router has no zone set
// either, and the daemon warns about that at startup.
func DetectTimezone(r Runner) (string, error) {
	out, err := r.Run("uci -q get system.@system[0].zonename 2>/dev/null || true")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
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
func initScript() string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# curfew: parental control daemon. Managed by the curfew tool.
START=99
USE_PROCD=1

CONF=%s

start_service() {
    if [ ! -f "$CONF" ]; then
        echo "curfew: missing $CONF; run 'curfew install' from your laptop" >&2
        return 1
    fi
    . "$CONF"
    procd_open_instance
    procd_set_param command %s \
        -registry %s \
        -profiles %s \
        -state %s \
        -lan "$CURFEW_LAN" \
        -wan "$CURFEW_WAN" \
        -listen "$CURFEW_LISTEN" \
        -timezone "$CURFEW_TZ"
    procd_set_param env CURFEW_USER="$CURFEW_USER" CURFEW_PASSWORD="$CURFEW_PASSWORD"
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, RemoteDaemonConf, RemoteBinary, RemoteRegistry, RemoteProfiles, RemoteState)
}

// shellQuote renders a value safe to `.` into a POSIX shell. Passwords can
// contain anything, and a naive quote would either break the file or let a
// value execute.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// daemonConf renders the settings file the init script sources.
func daemonConf(lan, wan, listen, user, password, timezone string) string {
	return fmt.Sprintf(`# curfew daemon settings. Written by 'curfew install'.
# 'curfew update' deliberately leaves this file alone.
CURFEW_LAN=%s
CURFEW_WAN=%s
CURFEW_LISTEN=%s
CURFEW_USER=%s
CURFEW_PASSWORD=%s
CURFEW_TZ=%s
`, shellQuote(lan), shellQuote(wan), shellQuote(listen), shellQuote(user),
		shellQuote(password), shellQuote(timezone))
}

// uploadString writes content to a remote path, via a temp local file.
func uploadString(r Runner, content, remotePath, what string) error {
	local, err := os.CreateTemp("", "curfew-*")
	if err != nil {
		return fmt.Errorf("creating temp %s: %w", what, err)
	}
	defer os.Remove(local.Name())
	if _, err := local.WriteString(content); err != nil {
		local.Close()
		return fmt.Errorf("writing temp %s: %w", what, err)
	}
	if err := local.Close(); err != nil {
		return fmt.Errorf("closing temp %s: %w", what, err)
	}
	return r.Upload(local.Name(), remotePath)
}

// pushBinary uploads the daemon and proves it actually executes on this
// router. Shared by install and update, because the wrong-architecture trap
// is identical for both.
func pushBinary(r Runner, binaryPath string) error {
	if binaryPath == "" {
		return fmt.Errorf("no daemon binary to install")
	}
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("daemon binary: %w", err)
	}
	// Upload to a temp path then move, so a half-copied binary is never the
	// thing procd tries to exec.
	tmpRemote := RemoteBinary + ".new"
	if err := r.Upload(binaryPath, tmpRemote); err != nil {
		return err
	}
	if _, err := r.Run(fmt.Sprintf("chmod +x %s && mv %s %s", tmpRemote, tmpRemote, RemoteBinary)); err != nil {
		return err
	}
	// A wrong-architecture push otherwise "succeeds" all the way through
	// enable and start, and shows up only as procd respawning a binary that
	// cannot exec, which is invisible from the laptop.
	if _, err := r.Run(RemoteBinary + " -version"); err != nil {
		return fmt.Errorf("the installed binary does not run on this router "+
			"(wrong architecture?): %w", err)
	}
	return nil
}

// InstallOptions configures a deployment.
type InstallOptions struct {
	LAN      string
	WAN      string
	Listen   string
	User     string
	Password string
	// Timezone is the IANA zone schedules are evaluated in.
	Timezone string
	// BinaryPath is the locally built daemon to push.
	BinaryPath string
	// RegistryPath is the local device list, shipped only when the router has
	// none, so a first install never starts with an empty allowlist.
	RegistryPath string
	// ProfilesPath is the local schedule, shipped on the same terms.
	ProfilesPath string
}

// Install puts the daemon on the router, writes its settings and service
// definition, and starts it.
func Install(r Runner, opt InstallOptions) error {
	if opt.WAN == "" {
		return fmt.Errorf("WAN interface is required")
	}
	if _, err := r.Run("mkdir -p " + RemoteConfDir); err != nil {
		return err
	}
	if err := pushBinary(r, opt.BinaryPath); err != nil {
		return err
	}

	// Settings as DATA, separate from the service definition that reads them.
	// This is what lets `update` replace the binary and the service template
	// later without being told the WAN interface and the password again.
	conf := daemonConf(opt.LAN, opt.WAN, opt.Listen, opt.User, opt.Password, opt.Timezone)
	if err := uploadString(r, conf, RemoteDaemonConf, "settings"); err != nil {
		return err
	}
	// The password is in there, so it must not be world-readable.
	if _, err := r.Run("chmod 600 " + RemoteDaemonConf); err != nil {
		return err
	}

	if err := uploadString(r, initScript(), RemoteInit, "init script"); err != nil {
		return err
	}
	if _, err := r.Run("chmod +x " + RemoteInit); err != nil {
		return err
	}

	// Ship the local device list ONLY when the router has none.
	//
	// The point is to avoid ever starting with an empty allowlist, which would
	// take the whole household off the internet. It is NOT to make the router
	// match the laptop: devices can be added and renamed on the router's own
	// page, and an install run later must not silently discard those edits.
	// Making the router match the laptop is what `push` is for.
	remoteHas, err := r.Run(fmt.Sprintf("[ -s %s ] && echo yes || echo no", RemoteRegistry))
	if err != nil {
		return err
	}
	if strings.TrimSpace(remoteHas) != "yes" && opt.RegistryPath != "" {
		if _, statErr := os.Stat(opt.RegistryPath); statErr == nil {
			if err := r.Upload(opt.RegistryPath, RemoteRegistry); err != nil {
				return err
			}
		}
	}
	if _, err := r.Run(fmt.Sprintf("[ -f %s ] || printf '%%s\\n' '{\"devices\":[]}' > %s",
		RemoteRegistry, RemoteRegistry)); err != nil {
		return err
	}

	// Same rule for the schedule: seed it only if the router has none, so an
	// install never discards profiles created on the router's own page.
	remoteSched, err := r.Run(fmt.Sprintf("[ -s %s ] && echo yes || echo no", RemoteProfiles))
	if err != nil {
		return err
	}
	if strings.TrimSpace(remoteSched) != "yes" && opt.ProfilesPath != "" {
		if _, statErr := os.Stat(opt.ProfilesPath); statErr == nil {
			if err := r.Upload(opt.ProfilesPath, RemoteProfiles); err != nil {
				return err
			}
		}
	}
	if _, err := r.Run(fmt.Sprintf("[ -f %s ] || printf '%%s\\n' '{\"profiles\":[]}' > %s",
		RemoteProfiles, RemoteProfiles)); err != nil {
		return err
	}

	// Register for preservation across a firmware upgrade. /usr/sbin and
	// /etc/init.d are NOT in OpenWrt's keep list, so without this a sysupgrade
	// leaves a device list saying who is allowed and no daemon enforcing it.
	if _, err := r.Run("mkdir -p /lib/upgrade/keep.d"); err != nil {
		return err
	}
	if err := uploadString(r, RemoteBinary+"\n"+RemoteInit+"\n", RemoteKeepList, "keep list"); err != nil {
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

// Update replaces the daemon binary and the service definition, and nothing
// else.
//
// It does not ask for the WAN interface or the password again, because those
// live in RemoteDaemonConf as data rather than baked into the generated init
// script. It deliberately leaves that file AND the device list alone, so
// updating the binary can never change who is allowed on the network or
// silently discard edits made on the router's own page.
func Update(r Runner, binaryPath string) error {
	has, err := r.Run(fmt.Sprintf("[ -f %s ] && echo yes || echo no", RemoteDaemonConf))
	if err != nil {
		return err
	}
	if strings.TrimSpace(has) != "yes" {
		return fmt.Errorf("no settings found at %s on the router.\n"+
			"       This router was set up by an older version, or never installed. "+
			"Run 'curfew install' once to write them", RemoteDaemonConf)
	}
	if err := pushBinary(r, binaryPath); err != nil {
		return err
	}
	// The init script is a static template now, so replacing it is safe: it
	// carries no settings of its own.
	if err := uploadString(r, initScript(), RemoteInit, "init script"); err != nil {
		return err
	}
	if _, err := r.Run("chmod +x " + RemoteInit); err != nil {
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

// FetchFile reads a remote file into localPath, reporting whether it existed
// at all so "the router has none yet" is distinguishable from "the download
// failed", which would otherwise be treated as empty and quietly wipe data.
func FetchFile(r Runner, remotePath, localPath string) (bool, error) {
	out, err := r.Run(fmt.Sprintf("[ -s %s ] && echo yes || echo no", remotePath))
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) != "yes" {
		return false, nil
	}
	if err := r.Download(remotePath, localPath); err != nil {
		return false, err
	}
	return true, nil
}

// PushFile copies a local file to a remote path.
func PushFile(r Runner, localPath, remotePath string) error {
	if _, err := os.Stat(localPath); err != nil {
		return fmt.Errorf("local file: %w", err)
	}
	if _, err := r.Run("mkdir -p " + RemoteConfDir); err != nil {
		return err
	}
	return r.Upload(localPath, remotePath)
}

// Restart reloads the daemon so a pushed change takes effect now rather than
// at the next reconcile tick.
func Restart(r Runner) error {
	_, err := r.Run(RemoteInit + " restart")
	return err
}

// FetchRegistry reads the router's device list into localPath. It reports
// whether the router had one at all, so "the router has no list yet" is
// distinguishable from "the download failed", which would otherwise be treated
// as an empty list and quietly wipe devices.
func FetchRegistry(r Runner, localPath string) (bool, error) {
	out, err := r.Run(fmt.Sprintf("[ -s %s ] && echo yes || echo no", RemoteRegistry))
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) != "yes" {
		return false, nil
	}
	if err := r.Download(RemoteRegistry, localPath); err != nil {
		return false, err
	}
	return true, nil
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
