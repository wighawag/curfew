// Command my-router runs ON YOUR LAPTOP. It installs the router daemon and
// moves configuration to and from the router. It does three things: install,
// push, pull.
//
// It deliberately cannot enforce anything. The enforcement code lives only in
// the my-router-daemon binary, and this package does not import it, so running
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

	"github.com/wighawag/my-router/internal/deploy"
	"github.com/wighawag/my-router/internal/legacyconfig"
	"github.com/wighawag/my-router/internal/registry"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

const usage = `my-router - manage the parental control router from your laptop

Usage:
  my-router import [flags]           build a device list from the legacy config
  my-router install <host> [flags]   install or update the daemon on the router
  my-router push <host> [flags]      send your local device list to the router
  my-router pull <host> [flags]      fetch the router's device list
  my-router version

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
		fmt.Fprintf(os.Stderr, "my-router: %v\n", err)
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
		fmt.Fprintln(os.Stderr, "my-router: warning: no -password given, so the device page will be unauthenticated.")
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
		fmt.Fprintf(os.Stderr, "my-router: warning: no device list at %s.\n", *regPath)
		fmt.Fprintln(os.Stderr, "           The router will start with an EMPTY allowlist, which means")
		fmt.Fprintln(os.Stderr, "           nothing on your LAN reaches the internet. Run 'my-router import' first")
		fmt.Fprintln(os.Stderr, "           if you are migrating from the shell scripts.")
	}

	if err := deploy.Install(runner, deploy.InstallOptions{
		LAN: *lan, WAN: *wan, Listen: *listen,
		User: *user, Password: *password, BinaryPath: binPath,
		RegistryPath: *regPath,
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
		fmt.Fprintln(os.Stderr, "         Run 'my-router import' then 'my-router push <host>', or add devices on the page.")
		fmt.Fprintf(os.Stderr, "         To undo everything right now: ssh %s 'nft delete table inet parental_control'\n", host)
	}
	fmt.Printf("device page: http://<router>%s\n", *listen)
	return nil
}

// buildDaemon cross-compiles the router binary with the local Go toolchain.
// CGO is off so the result is static and depends on nothing in the router's
// userland.
func buildDaemon(goarch string) (string, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", fmt.Errorf("no Go toolchain found to build the daemon; " +
			"install Go, or pass -binary with a prebuilt daemon")
	}
	out := filepath.Join(os.TempDir(), fmt.Sprintf("my-router-daemon-%s", goarch))
	cmd := exec.Command("go", "build", "-o", out, "./cmd/my-router-daemon")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building the daemon for %s: %w\n%s", goarch, err, output)
	}
	return out, nil
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

func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	path := fs.String("registry", defaultRegistryPath(), "local device list to send")
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	if err := deploy.Push(deploy.SSHRunner{Host: host}, *path); err != nil {
		return err
	}
	fmt.Printf("pushed %s to %s\n", *path, host)
	return nil
}

func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	path := fs.String("registry", defaultRegistryPath(), "where to write the device list")
	host, err := hostAndFlags(fs, args)
	if err != nil {
		return err
	}
	if err := deploy.Pull(deploy.SSHRunner{Host: host}, *path); err != nil {
		return err
	}
	fmt.Printf("pulled %s from %s\n", *path, host)
	return nil
}
