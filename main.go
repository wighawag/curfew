// Command curfew runs ON YOUR LAPTOP. It installs the router daemon and
// moves configuration to and from the router. It does three things: install,
// push, pull.
//
// It deliberately cannot enforce anything. The enforcement code lives only in
// the curfew-daemon binary, and this package does not import it, so running
// the wrong command here can never rewrite your laptop's own firewall. That
// separation is the reason there are two binaries rather than one with a flag.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wighawag/curfew/internal/deploy"
	"github.com/wighawag/curfew/internal/legacyconfig"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

const usage = `curfew - manage the parental control router from your laptop

Usage:
  curfew import [flags]           build a device list from the legacy config
  curfew install <host> [flags]   first-time setup: daemon, settings, service
  curfew update <host> [flags]    update the daemon binary, keeping its settings
  curfew push <host> [flags]      send your local device list to the router
  curfew pull <host> [flags]      merge the router's device list into yours
  curfew version

The host is an ssh destination, for example root@192.168.1.1.
Your existing ssh configuration, keys and agent are used as-is.
`

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if isVersionArg(args) {
		fmt.Println(resolveVersion())
		return 0
	}

	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "import":
		err = cmdImport(rest)
	case "install":
		err = cmdInstall(rest)
	case "update":
		err = cmdUpdate(rest)
	case "push":
		err = cmdPush(rest)
	case "pull":
		err = cmdPull(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "curfew: %v\n", err)
		return 1
	}
	return 0
}

// hostAndFlags pulls the leading host argument off, then parses the rest, so
// both `install <host> -flag` and `install -flag <host>` work.
func hostAndFlags(fs *flag.FlagSet, args []string) (string, error) {
	var host string
	var flagArgs []string
	for _, a := range args {
		if host == "" && !strings.HasPrefix(a, "-") {
			host = a
			continue
		}
		flagArgs = append(flagArgs, a)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("no host given (for example root@192.168.1.1)")
	}
	return host, nil
}

func defaultRegistryPath() string {
	return filepath.Join("config", "local", "devices.json")
}

// basePath is where the last state the laptop and the router agreed on is
// recorded. It is what makes "has the other side changed since we last
// synced?" answerable at all, and therefore what lets push and pull refuse
// instead of overwriting.
func basePath(registryPath string) string {
	return filepath.Join(filepath.Dir(registryPath), ".devices.base.json")
}

// profilesPath sits next to the device list, mirroring the router's layout.
func profilesPath(registryPath string) string {
	return filepath.Join(filepath.Dir(registryPath), "profiles.json")
}

func profilesBasePath(registryPath string) string {
	return filepath.Join(filepath.Dir(registryPath), ".profiles.base.json")
}

// syncProfiles moves the schedule in one direction, with the same
// last-agreed guard the device list uses.
//
// Schedules are compared and taken WHOLE rather than merged entry by entry.
// A structured merge of windows is a real piece of work and would mostly
// invent decisions nobody asked for; refusing and naming the two sides is
// honest, and the file is small enough to reconcile by hand.
func syncProfiles(runner deploy.Runner, regPath string, pull, force bool) (string, error) {
	local, err := schedule.Load(profilesPath(regPath))
	if err != nil {
		return "", err
	}
	base, err := schedule.Load(profilesBasePath(regPath))
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "curfew-profiles-*.json")
	if err != nil {
		return "", err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	present, err := deploy.FetchFile(runner, deploy.RemoteProfiles, tmp.Name())
	if err != nil {
		return "", err
	}
	remote := &schedule.Profiles{Profiles: []schedule.Profile{}}
	if present {
		if remote, err = schedule.Load(tmp.Name()); err != nil {
			return "", fmt.Errorf("the router's schedule is unusable: %w", err)
		}
	}

	localChanged := !schedule.Equal(local, base)
	remoteChanged := !schedule.Equal(remote, base)

	switch {
	case schedule.Equal(local, remote):
		if err := schedule.Save(profilesBasePath(regPath), remote); err != nil {
			return "", err
		}
		return "schedule already in step", nil
	case pull:
		if localChanged && remoteChanged && !force {
			return "", fmt.Errorf("the schedule changed on BOTH sides since the last sync.\n" +
				"       Schedules are taken whole, not merged, so pick one:\n" +
				"         curfew pull <host> --force   # the router's schedule wins\n" +
				"         curfew push <host> --force   # your local schedule wins")
		}
		if !remoteChanged && !force {
			return "schedule unchanged on the router", nil
		}
		if err := schedule.Save(profilesPath(regPath), remote); err != nil {
			return "", err
		}
		if err := schedule.Save(profilesBasePath(regPath), remote); err != nil {
			return "", err
		}
		return fmt.Sprintf("pulled %d profile(s)", len(remote.Profiles)), nil
	default: // push
		if remoteChanged && !force {
			return "", fmt.Errorf("the router's schedule changed since your last sync, so pushing " +
				"would discard it.\n       Run 'curfew pull' first, or push --force to overwrite it")
		}
		if err := deploy.PushFile(runner, profilesPath(regPath), deploy.RemoteProfiles); err != nil {
			return "", err
		}
		if err := schedule.Save(profilesBasePath(regPath), local); err != nil {
			return "", err
		}
		return fmt.Sprintf("pushed %d profile(s)", len(local.Profiles)), nil
	}
}

func conflictPath(registryPath string) string {
	return filepath.Join(filepath.Dir(registryPath), "devices.conflict.txt")
}

// fetchRemote reads the router's list. A router with no list yet is an empty
// registry, which is correct: nothing has been agreed, so everything local
// looks like an addition.
func fetchRemote(runner deploy.Runner) (*registry.Registry, error) {
	tmp, err := os.CreateTemp("", "curfew-remote-*.json")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	present, err := deploy.FetchRegistry(runner, tmp.Name())
	if err != nil {
		return nil, err
	}
	if !present {
		return &registry.Registry{Devices: []registry.Device{}}, nil
	}
	return registry.Load(tmp.Name())
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	lan := fs.String("lan", "br-lan", "LAN interface on the router")
	wan := fs.String("wan", "", "WAN interface on the router (required; on PPPoE this is pppoe-wan)")
	listen := fs.String("listen", ":8080", "address the device page listens on")
	user := fs.String("user", "parent", "username for the device page")
	password := fs.String("password", "", "password for the device page (strongly recommended)")
	binary := fs.String("binary", "", "prebuilt daemon binary to install (default: build one)")
	regPath := fs.String("registry", defaultRegistryPath(),
		"device list to ship with the install, so the allowlist is never empty at startup")

	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	if *wan == "" {
		return fmt.Errorf("-wan is required: guessing it is how enforcement silently matches nothing.\n" +
			"       On this router's PPPoE line it is pppoe-wan, not eth1. Check with: ssh <host> ifstatus wan")
	}
	if *password == "" {
		fmt.Fprintln(os.Stderr, "curfew: warning: no -password given, so the device page will be unauthenticated.")
		fmt.Fprintln(os.Stderr, "           A device kept off the internet can still reach that page and allow itself.")
	}

	runner := deploy.SSHRunner{Host: host}

	arch, err := deploy.DetectArch(runner)
	if err != nil {
		return err
	}
	fmt.Printf("router architecture: %s\n", arch)

	binPath := *binary
	if binPath == "" {
		binPath, err = buildDaemon(arch)
		if err != nil {
			return err
		}
		defer os.Remove(binPath)
		fmt.Printf("built the daemon for %s\n", arch)
	}

	if _, err := os.Stat(*regPath); err != nil {
		fmt.Fprintf(os.Stderr, "curfew: warning: no device list at %s.\n", *regPath)
		fmt.Fprintln(os.Stderr, "           The router will start with an EMPTY allowlist, which means")
		fmt.Fprintln(os.Stderr, "           nothing on your LAN reaches the internet. Run 'curfew import' first")
		fmt.Fprintln(os.Stderr, "           if you are migrating from the shell scripts.")
	}

	if err := deploy.Install(runner, deploy.InstallOptions{
		LAN: *lan, WAN: *wan, Listen: *listen,
		User: *user, Password: *password, BinaryPath: binPath,
		RegistryPath: *regPath, ProfilesPath: profilesPath(*regPath),
	}); err != nil {
		return err
	}
	// Verify against the kernel rather than trusting that the commands
	// succeeded. An install that says "done" without checking is the failure
	// this whole project is about.
	count, err := deploy.Verify(runner)
	if err != nil {
		return fmt.Errorf("installed, but verification FAILED: %w", err)
	}
	fmt.Printf("installed and started on %s\n", host)
	fmt.Printf("the firewall is enforcing an allowlist of %d device(s)\n", count)
	if count == 0 {
		fmt.Fprintln(os.Stderr, "\nWARNING: the allowlist is EMPTY, so nothing on the LAN can reach the internet.")
		fmt.Fprintln(os.Stderr, "         Run 'curfew import' then 'curfew push <host>', or add devices on the page.")
		fmt.Fprintf(os.Stderr, "         To undo everything right now: ssh %s 'nft delete table inet curfew'\n", host)
	}
	fmt.Printf("device page: http://<router>%s\n", *listen)
	return nil
}

// buildDaemon cross-compiles the router binary with the local Go toolchain.
// CGO is off so the result is static and depends on nothing in the router's
// userland.
// buildDaemon cross-compiles the router binary from the CURRENT WORKING TREE.
//
// This is the point worth knowing: install and update do not need a release or
// a tag. They build whatever source you are sitting on and push that, so a
// change can be tried on the real router while it is still being argued about.
// Tagging is only for distributing the LAPTOP binary to other machines.
func buildDaemon(goarch string) (string, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", fmt.Errorf("no Go toolchain found to build the daemon; " +
			"install Go, or pass -binary with a prebuilt daemon")
	}
	if _, err := os.Stat(filepath.Join("cmd", "curfew-daemon")); err != nil {
		return "", fmt.Errorf("no ./cmd/curfew-daemon here, so there is nothing to build.\n" +
			"       Run this from a curfew checkout to deploy your working tree, " +
			"or pass -binary with a prebuilt daemon")
	}
	out := filepath.Join(os.TempDir(), fmt.Sprintf("curfew-daemon-%s", goarch))
	cmd := exec.Command("go", "build",
		"-ldflags", "-X main.version="+devVersion(),
		"-o", out, "./cmd/curfew-daemon")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building the daemon for %s: %w\n%s", goarch, err, output)
	}
	return out, nil
}

// devVersion labels a working-tree build so `curfew-daemon -version` on the
// router says which commit is running, and whether it had uncommitted changes.
// Without it every iteration reports "dev" and you cannot tell what you are
// looking at, which matters most precisely when you are iterating.
func devVersion() string {
	rev, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "dev"
	}
	v := "dev+" + strings.TrimSpace(string(rev))
	if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil &&
		len(strings.TrimSpace(string(out))) > 0 {
		v += "-dirty"
	}
	return v
}

// cmdImport converts the legacy pipe-delimited profiles into a device
// registry. It is a separate, explicit step rather than something install does
// silently, because it is the operator's chance to look at the list before it
// becomes the allowlist that decides who has internet.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	from := fs.String("profiles", filepath.Join("config", "local", "parental_profiles"),
		"legacy parental_profiles file to read")
	out := fs.String("out", defaultRegistryPath(), "device list to write")
	force := fs.Bool("force", false, "overwrite the device list if it already exists")
	if err := fs.Parse(args); err != nil {
		return err
	}

	profiles, parseErr := legacyconfig.ParseProfiles(*from)
	if parseErr != nil {
		// Report and stop. A partial import is an allowlist missing devices,
		// which is silent loss of internet for whoever owns them.
		return fmt.Errorf("%w\n\nNothing was written. Fix those entries, or re-run with the file corrected", parseErr)
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to overwrite it", *out)
	}

	reg := legacyconfig.ToRegistry(profiles)
	if len(reg.Devices) == 0 {
		return fmt.Errorf("%s produced no devices; refusing to write an empty allowlist", *from)
	}
	if err := registry.Save(*out, reg); err != nil {
		return err
	}
	fmt.Printf("imported %d devices from %d profiles into %s\n", len(reg.Devices), len(profiles), *out)
	for _, d := range reg.Devices {
		fmt.Printf("  %s  %s\n", d.MAC, d.Name)
	}
	fmt.Println("\nCheck this list: it becomes the allowlist, and anything missing loses internet.")
	return nil
}

// cmdUpdate replaces the daemon binary without re-specifying how the router is
// configured. The settings live on the router as data, so asking for them
// again would only create a chance to change them by accident.
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	binary := fs.String("binary", "", "prebuilt daemon binary to install (default: build one)")
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	runner := deploy.SSHRunner{Host: host}

	arch, err := deploy.DetectArch(runner)
	if err != nil {
		return err
	}
	binPath := *binary
	if binPath == "" {
		binPath, err = buildDaemon(arch)
		if err != nil {
			return err
		}
		defer os.Remove(binPath)
	}

	if err := deploy.Update(runner, binPath); err != nil {
		return err
	}
	count, err := deploy.Verify(runner)
	if err != nil {
		return fmt.Errorf("updated, but verification FAILED: %w", err)
	}
	fmt.Printf("updated %s (%s)\n", host, arch)
	fmt.Printf("the firewall is enforcing an allowlist of %d device(s)\n", count)
	return nil
}

func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	path := fs.String("registry", defaultRegistryPath(), "local device list to send")
	force := fs.Bool("force", false, "overwrite the router even if it has changed since the last sync")
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	runner := deploy.SSHRunner{Host: host}

	local, err := registry.Load(*path)
	if err != nil {
		return err
	}
	remote, err := fetchRemote(runner)
	if err != nil {
		return err
	}
	base, err := registry.Load(basePath(*path))
	if err != nil {
		return err
	}

	// Refuse rather than overwrite. Devices can be added, renamed and removed
	// on the router's own page, and silently discarding that is exactly the
	// kind of quiet data loss this project is trying to stop doing.
	if !*force && !registry.Equal(remote, base) {
		return fmt.Errorf("the router's device list has changed since your last sync, "+
			"so pushing would discard those changes.\n"+
			"       Run 'curfew pull %s' to merge them in first, or "+
			"'curfew push %s --force' to overwrite the router anyway", host, host)
	}

	if err := deploy.Push(runner, *path); err != nil {
		return err
	}
	if err := registry.Save(basePath(*path), local); err != nil {
		return err
	}
	_ = os.Remove(conflictPath(*path))
	fmt.Printf("pushed %d device(s) to %s\n", len(local.Devices), host)

	msg, err := syncProfiles(runner, *path, false, *force)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", msg)
	return deploy.Restart(runner)
}

func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	path := fs.String("registry", defaultRegistryPath(), "where to write the device list")
	force := fs.Bool("force", false, "take the router's list wholesale, discarding local changes")
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	runner := deploy.SSHRunner{Host: host}

	remote, err := fetchRemote(runner)
	if err != nil {
		return err
	}
	if *force {
		if err := registry.Save(*path, remote); err != nil {
			return err
		}
		if err := registry.Save(basePath(*path), remote); err != nil {
			return err
		}
		_ = os.Remove(conflictPath(*path))
		fmt.Printf("pulled %d device(s) from %s, discarding local changes\n", len(remote.Devices), host)
		msg, err := syncProfiles(runner, *path, true, true)
		if err != nil {
			return err
		}
		fmt.Println(msg)
		return nil
	}

	local, err := registry.Load(*path)
	if err != nil {
		return err
	}
	base, err := registry.Load(basePath(*path))
	if err != nil {
		return err
	}

	merged, conflicts := registry.Merge3(base, local, remote)
	if len(conflicts) > 0 {
		report := registry.RenderConflicts(conflicts)
		cp := conflictPath(*path)
		if writeErr := os.WriteFile(cp, []byte(report), 0o600); writeErr != nil {
			return fmt.Errorf("writing the conflict report: %w", writeErr)
		}
		fmt.Fprint(os.Stderr, report)
		return fmt.Errorf("%d device(s) conflict; nothing was changed. Details in %s", len(conflicts), cp)
	}

	if err := registry.Save(*path, merged); err != nil {
		return err
	}
	// The base becomes what the ROUTER holds, not the merged result: the
	// router does not have the merge yet, so that is still the last agreed
	// point. A push straight after this then succeeds.
	if err := registry.Save(basePath(*path), remote); err != nil {
		return err
	}
	_ = os.Remove(conflictPath(*path))

	if registry.Equal(merged, local) {
		fmt.Printf("already up to date with %s (%d device(s))\n", host, len(merged.Devices))
	} else {
		fmt.Printf("merged %s into %s (%d device(s))\n", host, *path, len(merged.Devices))
	}
	if !registry.Equal(merged, remote) {
		fmt.Printf("your list now differs from the router; run 'curfew push %s' to send it\n", host)
	}

	// The schedule lives in its own file and must be synced too, or a profile
	// created on the router is invisible on the laptop and a later push wipes
	// it. That gap shipped once.
	msg, err := syncProfiles(runner, *path, true, false)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
