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
	"strconv"
	"strings"

	"github.com/wighawag/curfew/internal/adguard"
	"github.com/wighawag/curfew/internal/deploy"
	"github.com/wighawag/curfew/internal/leases"
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
  curfew probe <host>             check the router's KERNEL still supports tickets
  curfew adopt-leases <host>      take over static DHCP leases written by something else
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
	case "probe":
		err = cmdProbe(rest)
	case "adopt-leases":
		err = cmdAdoptLeases(rest)
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
	password := fs.String("password", "",
		"password for BOTH the device page and AdGuard's admin page (strongly recommended)")
	curfewPassword := fs.String("curfew-password", "",
		"password for the device page only, overriding -password")
	adguardPassword := fs.String("adguard-password", "",
		"password for AdGuard's admin page and API only, overriding -password. "+
			"On a router that already has AdGuard with a login, pass the EXISTING one")
	adguardUser := fs.String("adguard-user", adguard.DefaultUser, "username for AdGuard's admin page")
	noAdGuard := fs.Bool("no-adguard", false,
		"do not install or touch AdGuard Home at all")
	binary := fs.String("binary", "", "prebuilt daemon binary to install (default: build one)")
	tz := fs.String("timezone", "", "IANA timezone for schedules (default: the router's own zonename)")
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
	// One -password sets both, and either can be overridden. Two systems on
	// this router grant internet access, and shipping either of them without
	// a password means the device being filtered can free itself.
	curfewPass := firstNonEmpty(*curfewPassword, *password)
	adguardPass := firstNonEmpty(*adguardPassword, *password)
	if curfewPass == "" {
		fmt.Fprintln(os.Stderr, "curfew: warning: no -password given, so the device page will be unauthenticated.")
		fmt.Fprintln(os.Stderr, "           A device kept off the internet can still reach that page and allow itself.")
	}
	if !*noAdGuard && adguardPass == "" {
		return fmt.Errorf("no password for AdGuard.\n" +
			"       An AdGuard with no admin account serves its whole API to every device on the LAN:\n" +
			"       one request turns off filtering for the house, and it can come from the child's own phone.\n" +
			"       Pass -password to set both, -adguard-password for AdGuard alone, or -no-adguard to skip it")
	}

	runner := deploy.SSHRunner{Host: host}

	arch, err := deploy.DetectArch(runner)
	if err != nil {
		return err
	}
	fmt.Printf("router architecture: %s\n", arch)

	zone := *tz
	if zone == "" {
		if zone, err = deploy.DetectTimezone(runner); err != nil {
			return err
		}
	}
	if zone == "" {
		fmt.Fprintln(os.Stderr, "my-router: warning: the router has no timezone set, so schedules will")
		fmt.Fprintln(os.Stderr, "           run in UTC. A 22:00 bedtime then fires at 23:00 British summer")
		fmt.Fprintln(os.Stderr, "           time. Set it in LuCI, or pass -timezone Europe/London.")
	} else {
		fmt.Printf("schedules will use the router's timezone: %s\n", zone)
	}

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

	// The daemon gets AdGuard's credentials even though AdGuard is set up
	// below, because daemon.conf is written once here and never again: update
	// deliberately leaves it alone. The daemon retries every tick, so a
	// credential written before AdGuard exists costs one failed pass, not a
	// broken install. With -no-adguard they are left empty, which turns the
	// DNS refinement off and nothing else.
	routerIP := hostAddress(host)
	aghURL := ""
	if !*noAdGuard {
		aghURL = fmt.Sprintf("127.0.0.1:%d", adguard.DefaultPort)
	}
	if err := deploy.Install(runner, deploy.InstallOptions{
		LAN: *lan, WAN: *wan, Listen: *listen,
		User: *user, Password: curfewPass, Timezone: zone, BinaryPath: binPath,
		RegistryPath: *regPath, ProfilesPath: profilesPath(*regPath),
		AdGuardURL: aghURL, AdGuardUser: *adguardUser, AdGuardPassword: adguardPass,
		RouterIP: routerIP,
	}); err != nil {
		return err
	}
	// AdGuard AFTER the daemon, deliberately. The daemon is what enforces the
	// allowlist and the schedules; if AdGuard setup fails, the household still
	// ends up with working parental control and a clear message about the DNS
	// half, rather than neither.
	agh, aghErr := deploy.SetupAdGuard(runner, deploy.AdGuardOptions{
		Enabled: !*noAdGuard, User: *adguardUser, Password: adguardPass, RouterIP: routerIP,
	})
	if aghErr != nil {
		fmt.Fprintf(os.Stderr, "\ncurfew: AdGuard setup FAILED: %v\n", aghErr)
		fmt.Fprintln(os.Stderr, "        Everything else is installed and enforcing. Re-run once that is fixed,")
		fmt.Fprintln(os.Stderr, "        or pass -no-adguard to leave AdGuard alone.")
	} else {
		fmt.Println(agh.Summary())
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

// cmdProbe asks the ROUTER's own daemon binary to measure its kernel.
//
// The measurement has to happen on the router, because the thing in question
// is that kernel's behaviour, and this laptop's kernel says nothing about it.
// So this is a thin driver: it runs the already-installed daemon with -probe
// and relays what it says. Nothing about enforcement is touched, by design of
// the probe rather than by care taken here.
//
// Worth running after a firmware upgrade, on a new board, or whenever a ticket
// behaves oddly, because the test suite measures the kernel of whatever
// machine built it and cannot speak for this one.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	runner := deploy.SSHRunner{Host: host}
	out, runErr := runner.Run(deploy.RemoteBinary + " -probe")
	fmt.Print(out)
	if runErr != nil {
		if strings.Contains(runErr.Error(), "flag provided but not defined") {
			return fmt.Errorf("the daemon on %s is too old to know -probe. Run 'curfew update %s' first",
				host, host)
		}
		return fmt.Errorf("the probe reported a problem on %s: %w", host, runErr)
	}
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

// firstNonEmpty returns the first value that is set, which is how a specific
// flag overrides the shared one.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// hostAddress strips any user@ prefix and port from an ssh host, leaving the
// address AdGuard should bind to and be reached on.
func hostAddress(host string) string {
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i+1:], "]") {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			host = host[:i]
		}
	}
	return strings.Trim(host, "[]")
}

// cmdAdoptLeases hands curfew a static DHCP lease that something else wrote.
//
// This is deliberately a SEPARATE, opt-in command rather than something the
// daemon does on a tick. curfew's whole leases design rests on the promise
// that it only ever touches host entries it created, and "curfew deletes
// entries it did not create" must never become automatic behaviour. So the
// reconciler always YIELDS to a foreign entry, and only this command, run by a
// person who has seen exactly what it will do, can transfer ownership.
//
// The motivating case is the entry the shell tool this project replaces wrote
// for the printer. Left alone it makes the daemon report a conflict on every
// pass for ever, and leaves one device pinned by a mechanism curfew does not
// own.
func cmdAdoptLeases(args []string) error {
	fs := flag.NewFlagSet("adopt-leases", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "actually make the change (without this, it only shows the plan)")
	regPath := fs.String("registry", defaultRegistryPath(), "device list to match MACs against")

	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	runner := deploy.SSHRunner{Host: host}

	reg, err := registry.Load(*regPath)
	if err != nil {
		return err
	}
	names := make(map[string]string, len(reg.Devices))
	for _, d := range reg.Devices {
		names[strings.ToLower(d.MAC)] = d.Name
	}

	current, err := leases.Read(runner)
	if err != nil {
		return err
	}
	plan := leases.PlanAdoption(current, names)
	if len(plan.Entries) == 0 {
		fmt.Println("Nothing to adopt: every static lease on this router is either curfew's")
		fmt.Println("already, or belongs to a device curfew does not know about.")
		return nil
	}

	fmt.Printf("These static DHCP leases were written by something other than curfew,\n")
	fmt.Printf("and their MAC is a device in your list:\n\n")
	for _, e := range plan.Entries {
		fmt.Printf("  dhcp.%s\n", e.Section)
		fmt.Printf("      mac  %s\n", e.MAC)
		fmt.Printf("      ip   %s   (kept exactly as it is: the device does not move)\n", e.IP)
		if e.OldName != e.NewName {
			fmt.Printf("      name %s  ->  %s\n", e.OldName, e.NewName)
		} else {
			fmt.Printf("      name %s\n", e.OldName)
		}
		fmt.Println()
	}
	fmt.Printf("curfew would delete each entry above and write its own (dhcp.%s...) in the\n",
		leases.SectionPrefix)
	fmt.Printf("same commit, so dnsmasq never sees two leases for one MAC. Every other host\n")
	fmt.Printf("entry on the router is left alone.\n\n")

	if !*yes {
		fmt.Println("Nothing has been changed. Re-run with -yes to do it.")
		return nil
	}

	changed, err := leases.Apply(runner, leases.Plan{Commands: plan.Commands})
	if err != nil {
		return fmt.Errorf("adopting leases: %w\n"+
			"       The change was staged and reverted, so the router is as it was.\n"+
			"       Check with: ssh %s 'uci show dhcp | grep host'", err, host)
	}
	if !changed {
		return fmt.Errorf("nothing was applied, which should not happen with %d entries to adopt",
			len(plan.Entries))
	}

	// Read it back off the router rather than trusting that the commands
	// exited zero. An adopt that says "done" without checking is the lie this
	// project exists to remove.
	after, err := leases.Read(runner)
	if err != nil {
		return fmt.Errorf("adopted, but reading the result back FAILED: %w", err)
	}
	owned := map[string]leases.Host{}
	for _, h := range after {
		if h.Owned() {
			owned[h.MAC] = h
		}
	}
	for _, e := range plan.Entries {
		got, ok := owned[e.MAC]
		if !ok {
			return fmt.Errorf("%s is NOT pinned by curfew after adoption; check the router by hand:\n"+
				"       ssh %s 'uci show dhcp | grep host'", e.MAC, host)
		}
		if got.IP != e.IP {
			return fmt.Errorf("%s was adopted at %s but should be at %s; the device may have moved",
				e.MAC, got.IP, e.IP)
		}
	}
	fmt.Printf("adopted %d lease(s), verified on the router\n", len(plan.Entries))
	fmt.Println("Remove the matching line from config/local/device_ips: the shell tool that")
	fmt.Println("wrote it is retired, and curfew owns that entry now.")
	return nil
}
