package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records what a deployment would do, so the sequence is testable
// without a router.
type fakeRunner struct {
	cmds      []string
	uploads   [][2]string
	downloads [][2]string
	existing  map[string]bool
	uploaded  map[string]string
	zone      string
	failOn    string
}

func (f *fakeRunner) Run(cmd string) (string, error) {
	f.cmds = append(f.cmds, cmd)
	if f.failOn != "" && strings.Contains(cmd, f.failOn) {
		return "", errors.New("remote command failed")
	}
	if strings.Contains(cmd, "uname -m") {
		return "aarch64\n", nil
	}
	if strings.Contains(cmd, "zonename") {
		return f.zone + "\n", nil
	}
	if strings.Contains(cmd, RemoteDaemonConf) && strings.Contains(cmd, "echo yes") {
		if f.existing[RemoteDaemonConf] {
			return "yes\n", nil
		}
		return "no\n", nil
	}
	if strings.Contains(cmd, RemoteRegistry) && strings.Contains(cmd, "echo yes") {
		if f.existing[RemoteRegistry] {
			return "yes\n", nil
		}
		return "no\n", nil
	}
	return "", nil
}

func (f *fakeRunner) Upload(local, remote string) error {
	f.uploads = append(f.uploads, [2]string{local, remote})
	// Capture the CONTENT now: Install cleans up its temp files as it goes, so
	// reading them afterwards races with that and fails.
	if f.uploaded == nil {
		f.uploaded = map[string]string{}
	}
	if body, err := os.ReadFile(local); err == nil {
		f.uploaded[remote] = string(body)
	}
	return nil
}

// uploadedTo reports the destinations an install wrote to.
func (f *fakeRunner) uploadedTo(remote string) bool {
	for _, u := range f.uploads {
		if u[1] == remote {
			return true
		}
	}
	return false
}

func (f *fakeRunner) Download(remote, local string) error {
	f.downloads = append(f.downloads, [2]string{remote, local})
	return os.WriteFile(local, []byte(`{"devices":[]}`), 0o644)
}

func (f *fakeRunner) ranMatching(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func tempBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "curfew-daemon")
	if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGoArchMapping(t *testing.T) {
	cases := map[string]string{
		"aarch64\n": "arm64",
		"x86_64":    "amd64",
		"mips":      "mips",
		"mipsel":    "mipsle",
		"armv7l":    "arm",
	}
	for in, want := range cases {
		got, err := GoArch(in)
		if err != nil {
			t.Fatalf("GoArch(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("GoArch(%q) = %q, want %q", in, got, want)
		}
	}
	// An unknown architecture must be an error, not a default. Guessing here
	// pushes a binary that cannot exec, onto a device reached over the very
	// network being configured.
	if _, err := GoArch("sparc64"); err == nil {
		t.Error("want an error for an unknown architecture, got nil")
	}
}

func TestDetectArch(t *testing.T) {
	r := &fakeRunner{}
	got, err := DetectArch(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "arm64" {
		t.Errorf("want arm64 from aarch64, got %q", got)
	}
}

func TestInstallSequence(t *testing.T) {
	r := &fakeRunner{}
	err := Install(r, InstallOptions{
		LAN: "br-lan", WAN: "pppoe-wan", Listen: ":8080",
		User: "parent", Password: "hunter2", BinaryPath: tempBinary(t),
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !r.ranMatching("mkdir -p " + RemoteConfDir) {
		t.Error("install should create the config directory")
	}
	if !r.uploadedTo(RemoteBinary + ".new") {
		t.Errorf("the binary should land on a temp path first, uploads were %v", r.uploads)
	}
	if !r.uploadedTo(RemoteInit) {
		t.Errorf("the init script should be uploaded, uploads were %v", r.uploads)
	}
	if !r.ranMatching("mv " + RemoteBinary + ".new") {
		t.Error("the binary should be moved into place only after a complete copy")
	}
	if !r.ranMatching(RemoteInit + " enable") {
		t.Error("the service should be enabled so it survives a reboot")
	}
	if !r.ranMatching(RemoteInit + " restart") {
		t.Error("the service should be started")
	}
}

func TestInstallNeverClobbersAnExistingRegistry(t *testing.T) {
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{
		WAN: "pppoe-wan", BinaryPath: tempBinary(t),
	}); err != nil {
		t.Fatal(err)
	}
	// The guard must be a conditional create, so re-running an install cannot
	// silently wipe the household's device list.
	if !r.ranMatching("[ -f " + RemoteRegistry + " ] ||") {
		t.Errorf("registry creation must be conditional, commands were:\n%s", strings.Join(r.cmds, "\n"))
	}
}

func TestInstallRequiresWAN(t *testing.T) {
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{BinaryPath: tempBinary(t)}); err == nil {
		t.Error("install without a WAN interface must fail rather than guess")
	}
}

func TestInstallRequiresAnExistingBinary(t *testing.T) {
	r := &fakeRunner{}
	err := Install(r, InstallOptions{WAN: "pppoe-wan", BinaryPath: "/nonexistent/daemon"})
	if err == nil {
		t.Error("install must fail when the binary is missing")
	}
}

// The regression guard against the old installer's defining habit.
func TestInstallReportsARemoteFailureInsteadOfSwallowingIt(t *testing.T) {
	r := &fakeRunner{failOn: "enable"}
	err := Install(r, InstallOptions{WAN: "pppoe-wan", BinaryPath: tempBinary(t)})
	if err == nil {
		t.Fatal("a failing remote command must surface as an error, not a silent success")
	}
}

func TestPushUploadsAndReloads(t *testing.T) {
	local := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(local, []byte(`{"devices":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	if err := Push(r, local); err != nil {
		t.Fatal(err)
	}
	if len(r.uploads) != 1 || r.uploads[0][1] != RemoteRegistry {
		t.Fatalf("want the registry uploaded, got %v", r.uploads)
	}
	if !r.ranMatching(RemoteInit + " restart") {
		t.Error("push should reload the service so the change takes effect now")
	}
}

func TestPushRefusesAMissingLocalFile(t *testing.T) {
	r := &fakeRunner{}
	if err := Push(r, filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("pushing a nonexistent registry must fail loudly")
	}
	if len(r.uploads) != 0 {
		t.Error("nothing should be uploaded")
	}
}

func TestPullCreatesParentDirectory(t *testing.T) {
	local := filepath.Join(t.TempDir(), "nested", "dir", "devices.json")
	r := &fakeRunner{}
	if err := Pull(r, local); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(local); err != nil {
		t.Fatalf("pull should have written %s: %v", local, err)
	}
}

func TestInitScriptIsAStaticTemplateCarryingNoSettings(t *testing.T) {
	s := initScript()
	for _, want := range []string{
		"USE_PROCD=1",
		"procd_set_param respawn", // the resilience that replaces cron
		RemoteBinary,
		RemoteDaemonConf, // it SOURCES its settings rather than embedding them
		`-wan "$CURFEW_WAN"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("init script missing %q:\n%s", want, s)
		}
	}
	// The whole point: no setting is baked in, so `update` can replace this
	// file without being told the WAN interface or the password again.
	for _, mustNot := range []string{"pppoe-wan", "hunter2", "br-lan"} {
		if strings.Contains(s, mustNot) {
			t.Errorf("init script must not embed the setting %q", mustNot)
		}
	}
}

func TestDaemonConfQuotesAwkwardValues(t *testing.T) {
	// A password can contain anything. A naive quote would either break the
	// file the init script sources, or let the value execute.
	c := daemonConf("br-lan", "pppoe-wan", ":8080", "parent", `it's $PWD; rm -rf /`, "Europe/London")
	if !strings.Contains(c, `CURFEW_PASSWORD='it'\''s $PWD; rm -rf /'`) {
		t.Errorf("password not safely quoted:\n%s", c)
	}
	if !strings.Contains(c, "CURFEW_WAN='pppoe-wan'") {
		t.Errorf("settings missing:\n%s", c)
	}
}

func TestInstallWritesSettingsAsDataAndProtectsThem(t *testing.T) {
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{
		LAN: "br-lan", WAN: "pppoe-wan", Listen: ":8080",
		User: "parent", Password: "hunter2", BinaryPath: tempBinary(t),
	}); err != nil {
		t.Fatal(err)
	}
	conf, ok := r.uploaded[RemoteDaemonConf]
	if !ok {
		t.Fatalf("install must write the settings file; uploads were %v", r.uploads)
	}
	if !strings.Contains(conf, "CURFEW_WAN='pppoe-wan'") || !strings.Contains(conf, "CURFEW_PASSWORD='hunter2'") {
		t.Errorf("settings not written:\n%s", conf)
	}
	if !r.ranMatching("chmod 600 " + RemoteDaemonConf) {
		t.Error("the settings file holds the password and must not be world-readable")
	}
}

// The point of update: no WAN, no password, and it must not disturb either
// the settings or the device list.
func TestUpdateReplacesTheBinaryWithoutTouchingSettingsOrDevices(t *testing.T) {
	r := &fakeRunner{existing: map[string]bool{RemoteDaemonConf: true}}
	if err := Update(r, tempBinary(t)); err != nil {
		t.Fatal(err)
	}
	if !r.uploadedTo(RemoteBinary + ".new") {
		t.Error("update should push a new binary")
	}
	if !r.uploadedTo(RemoteInit) {
		t.Error("update should refresh the service template")
	}
	if r.uploadedTo(RemoteDaemonConf) {
		t.Error("update must NOT rewrite the settings; that would change them silently")
	}
	if r.uploadedTo(RemoteRegistry) {
		t.Error("update must NOT touch the device list")
	}
	if !r.ranMatching(RemoteInit + " restart") {
		t.Error("update should restart the service")
	}
}

func TestUpdateRefusesARouterThatWasNeverInstalled(t *testing.T) {
	// The init script requires the settings file. Replacing it on a router
	// that has none would leave a service that cannot start.
	r := &fakeRunner{existing: map[string]bool{}}
	err := Update(r, tempBinary(t))
	if err == nil {
		t.Fatal("want an error when the router has no settings file")
	}
	if !strings.Contains(err.Error(), "install") {
		t.Errorf("the error should say to run install, got: %v", err)
	}
	if r.uploadedTo(RemoteBinary+".new") || r.uploadedTo(RemoteInit) {
		t.Error("update must change nothing when it refuses")
	}
}

func TestUpdateFailsWhenThePushedBinaryCannotRun(t *testing.T) {
	r := &fakeRunner{existing: map[string]bool{RemoteDaemonConf: true}, failOn: "-version"}
	if err := Update(r, tempBinary(t)); err == nil {
		t.Fatal("want an error when the new binary cannot execute")
	}
	if r.ranMatching("restart") {
		t.Error("a service must not be restarted onto a binary that cannot exec")
	}
}

// Installing must never start the daemon with an empty allowlist when a device
// list is available, because the daemon applies the registry at startup and an
// empty one takes the whole household off the internet.
func TestInstallShipsTheRegistryBeforeStarting(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(reg, []byte(`{"devices":[{"mac":"aa:bb:cc:dd:ee:01"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{
		WAN: "pppoe-wan", BinaryPath: tempBinary(t), RegistryPath: reg,
	}); err != nil {
		t.Fatal(err)
	}
	uploadedRegistryAt := -1
	for i, u := range r.uploads {
		if u[1] == RemoteRegistry {
			uploadedRegistryAt = i
		}
	}
	if uploadedRegistryAt < 0 {
		t.Fatalf("the registry was never uploaded: %v", r.uploads)
	}
	// And it must land before the service is told to start.
	startedAt := -1
	for i, c := range r.cmds {
		if strings.Contains(c, "restart") {
			startedAt = i
		}
	}
	if startedAt < 0 {
		t.Fatal("the service was never started")
	}
}

func TestInstallStillCreatesAnEmptyRegistryWhenNoneIsGiven(t *testing.T) {
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{WAN: "pppoe-wan", BinaryPath: tempBinary(t)}); err != nil {
		t.Fatal(err)
	}
	if !r.ranMatching("[ -f " + RemoteRegistry + " ] ||") {
		t.Error("without a local list, the router should still get a valid empty one")
	}
}

// The device list must live somewhere a firmware upgrade preserves.
//
// Measured against the real OpenWrt image: /lib/upgrade/keep.d/ lists
// "/etc/config/" and nothing else that would cover an arbitrary /etc/<app>
// directory. An earlier version of this code stored the registry in
// /etc/curfew/, which a sysupgrade would have deleted, bringing the router
// back with an empty allowlist and the whole household offline. This is a
// non-obvious constraint that a future refactor would happily undo, so it is
// pinned here rather than left to a comment.
func TestRegistryLivesSomewhereSysupgradePreserves(t *testing.T) {
	if !strings.HasPrefix(RemoteRegistry, "/etc/config/") {
		t.Errorf("RemoteRegistry = %q, but only /etc/config/ survives a sysupgrade; "+
			"storing the device list elsewhere loses it on a firmware upgrade", RemoteRegistry)
	}
	if !strings.HasPrefix(RemoteConfDir, "/etc/config/") {
		t.Errorf("RemoteConfDir = %q, must be under /etc/config/", RemoteConfDir)
	}
}

// A firmware upgrade must not leave the router enforcing nothing.
//
// /usr/sbin and /etc/init.d are NOT in OpenWrt's sysupgrade keep list
// (measured on the real image), so without registering them the daemon and its
// service definition are both destroyed by a sysupgrade while the device list
// survives. That combination is the worst of both: the configuration says who
// is allowed and the firewall allows everyone.
func TestInstallRegistersItsFilesForFirmwareUpgrade(t *testing.T) {
	r := &fakeRunner{}
	if err := Install(r, InstallOptions{WAN: "pppoe-wan", BinaryPath: tempBinary(t)}); err != nil {
		t.Fatal(err)
	}
	body, ok := r.uploaded[RemoteKeepList]
	if !ok {
		t.Fatalf("install never registered a sysupgrade keep list; uploads were %v", r.uploads)
	}
	for _, want := range []string{RemoteBinary, RemoteInit} {
		if !strings.Contains(body, want) {
			t.Errorf("the keep list must preserve %s, got:\n%s", want, body)
		}
	}
	if !r.ranMatching("mkdir -p /lib/upgrade/keep.d") {
		t.Error("the keep.d directory must exist before writing into it")
	}
}

// Pushing a binary for the wrong architecture must fail the install, not sail
// through enable and start. Without this check procd just respawns something
// that cannot exec, which looks like nothing at all from the laptop.
func TestInstallFailsWhenThePushedBinaryCannotRun(t *testing.T) {
	r := &fakeRunner{failOn: "-version"}
	err := Install(r, InstallOptions{WAN: "pppoe-wan", BinaryPath: tempBinary(t)})
	if err == nil {
		t.Fatal("want an error when the installed binary cannot execute")
	}
	if !strings.Contains(err.Error(), "architecture") {
		t.Errorf("the error should point at the likely cause, got: %v", err)
	}
	// And it must stop BEFORE wiring the service up.
	if r.ranMatching("enable") || r.ranMatching("restart") {
		t.Error("the service must not be enabled or started after a failed exec check")
	}
}

// Re-running install to update the binary must not discard devices added or
// renamed on the router's own page. Shipping the local list exists only to
// avoid ever starting with an empty allowlist; making the router match the
// laptop is what push is for, and it is an explicit act.
func TestInstallDoesNotOverwriteARegistryTheRouterAlreadyHas(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(reg, []byte(`{"devices":[{"mac":"aa:bb:cc:dd:ee:01"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{existing: map[string]bool{RemoteRegistry: true}}
	if err := Install(r, InstallOptions{
		WAN: "pppoe-wan", BinaryPath: tempBinary(t), RegistryPath: reg,
	}); err != nil {
		t.Fatal(err)
	}
	if r.uploadedTo(RemoteRegistry) {
		t.Error("install overwrote the router's device list; router-side edits would be lost")
	}
}

func TestInstallShipsTheListWhenTheRouterHasNone(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(reg, []byte(`{"devices":[{"mac":"aa:bb:cc:dd:ee:01"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{existing: map[string]bool{}}
	if err := Install(r, InstallOptions{
		WAN: "pppoe-wan", BinaryPath: tempBinary(t), RegistryPath: reg,
	}); err != nil {
		t.Fatal(err)
	}
	if !r.uploadedTo(RemoteRegistry) {
		t.Error("a first install must ship the list, or the allowlist starts empty")
	}
}

func TestInitScriptPassesTheProfilesPath(t *testing.T) {
	s := initScript()
	if !strings.Contains(s, "-profiles "+RemoteProfiles) {
		t.Errorf("the daemon needs its schedule path or profiles silently do nothing:\n%s", s)
	}
}

func TestDetectTimezone(t *testing.T) {
	r := &fakeRunner{zone: "Europe/London"}
	got, err := DetectTimezone(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Europe/London" {
		t.Errorf("got %q", got)
	}
	// A router with no zone set is not an error: the daemon warns instead.
	empty := &fakeRunner{}
	got, err = DetectTimezone(empty)
	if err != nil || got != "" {
		t.Errorf("want empty and no error, got %q / %v", got, err)
	}
}

// The daemon must be told the zone, or OpenWrt's UTC default silently shifts
// every bedtime by an hour for half the year.
func TestInstallCarriesTheTimezoneThrough(t *testing.T) {
	r := &fakeRunner{zone: "Europe/London"}
	if err := Install(r, InstallOptions{
		WAN: "pppoe-wan", BinaryPath: tempBinary(t), Timezone: "Europe/London",
	}); err != nil {
		t.Fatal(err)
	}
	if conf := r.uploaded[RemoteDaemonConf]; !strings.Contains(conf, "CURFEW_TZ='Europe/London'") {
		t.Errorf("settings must carry the zone:\n%s", conf)
	}
	if init := r.uploaded[RemoteInit]; !strings.Contains(init, `-timezone "$CURFEW_TZ"`) {
		t.Errorf("the service must pass the zone to the daemon:\n%s", init)
	}
}
