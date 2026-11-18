package main

import (
	"fmt"
	"strings"

	"github.com/wighawag/curfew/internal/dnsnames"
	"github.com/wighawag/curfew/internal/registry"
)

// `curfew add-dns-name` / `curfew remove-dns-name`: give a registered device a
// LOCAL DNS NAME the router answers itself, or take one away.
//
// Like set-ip they edit the LOCAL device file only and take no host: the
// router is changed by `curfew push`, which checks the names against the
// router's own config first. What a name covers is docs/adr/0013's rule: "x"
// is x and every name below it, "*.x" is every name strictly below x.

type dnsNameArgs struct {
	ref, name, registry string
}

func parseDNSNameArgs(cmd string, args []string) (dnsNameArgs, error) {
	a := dnsNameArgs{registry: defaultRegistryPath()}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-registry" || arg == "--registry":
			if i+1 >= len(args) {
				return a, fmt.Errorf("%s needs a path", arg)
			}
			i++
			a.registry = args[i]
		case strings.HasPrefix(arg, "-registry=") || strings.HasPrefix(arg, "--registry="):
			a.registry = arg[strings.Index(arg, "=")+1:]
		case strings.HasPrefix(arg, "-") && arg != "-":
			return a, fmt.Errorf("unknown flag %s", arg)
		default:
			pos = append(pos, arg)
		}
	}
	if len(pos) != 2 {
		return a, fmt.Errorf("give a device and one DNS name\n"+
			"usage: curfew %s <mac|name> <dns-name>   (quote a '*', for example '*.lan.example.com')", cmd)
	}
	a.ref, a.name = pos[0], pos[1]
	return a, nil
}

func cmdAddDNSName(args []string) error {
	a, err := parseDNSNameArgs("add-dns-name", args)
	if err != nil {
		return err
	}
	msg, err := addDNSName(a.registry, a.ref, a.name)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func cmdRemoveDNSName(args []string) error {
	a, err := parseDNSNameArgs("remove-dns-name", args)
	if err != nil {
		return err
	}
	msg, err := removeDNSName(a.registry, a.ref, a.name)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func addDNSName(path, ref, name string) (string, error) {
	reg, err := registry.Load(path)
	if err != nil {
		return "", err
	}
	mac, err := reg.Resolve(ref)
	if err != nil {
		return "", err
	}
	warnings, err := reg.AddDNSName(mac, name)
	if err != nil {
		return "", err
	}
	if err := registry.Save(path, reg); err != nil {
		return "", err
	}
	var ip string
	for _, d := range reg.Devices {
		if d.MAC == mac {
			ip = d.IP
		}
	}
	parsed, _ := dnsnames.Parse(name) // AddDNSName accepted it, so it parses
	stored := parsed.String()
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: local DNS name %s -> %s set in %s.\n", describeDevice(reg, mac), stored, ip, path)
	fmt.Fprintf(&sb, "%s\n", coverage(stored))
	for _, w := range warnings {
		fmt.Fprintf(&sb, "warning: %s\n", w)
	}
	sb.WriteString("On your LAN the router's answer wins over any public record for the same name, " +
		"and it answers A only: there is no IPv6 address for it.\n")
	sb.WriteString("Run 'curfew push <host>' to apply it; push checks it against the router's own " +
		"config first and writes nothing if it clashes.")
	return sb.String(), nil
}

// coverage says in words what a stored name answers for.
func coverage(name string) string {
	if base, ok := strings.CutPrefix(name, "*."); ok {
		return fmt.Sprintf("It answers every name below %s (such as www.%s), but not %s itself.", base, base, base)
	}
	return fmt.Sprintf("It answers %s and every name below it.", name)
}

func removeDNSName(path, ref, name string) (string, error) {
	reg, err := registry.Load(path)
	if err != nil {
		return "", err
	}
	mac, err := reg.Resolve(ref)
	if err != nil {
		return "", err
	}
	if err := reg.RemoveDNSName(mac, name); err != nil {
		return "", err
	}
	if err := registry.Save(path, reg); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: local DNS name %s removed from %s.\n"+
		"Run 'curfew push <host>' to apply it; the router then removes exactly the records curfew "+
		"made for it.", describeDevice(reg, mac), dnsnames.Canonical(name), path), nil
}

// DNSNamesFeature is what a daemon that understands local DNS names reports
// in `curfew-daemon -features`.
const DNSNamesFeature = "local-dns-names"

func anyDNSNames(r *registry.Registry) bool {
	if r == nil {
		return false
	}
	for _, d := range r.Devices {
		if len(d.DNSNames) > 0 {
			return true
		}
	}
	return false
}

// requireDNSNamesSupport refuses to send local DNS names to a daemon that does
// not know the field: its page would drop them on its next save, and the next
// pull would read that as the household deleting them. Same reasoning, and
// same fix, as fixed addresses.
func requireDNSNamesSupport(supported bool, local *registry.Registry, host string) error {
	if supported || !anyDNSNames(local) {
		return nil
	}
	return fmt.Errorf("your device list sets local DNS names, but the daemon on %s is too old "+
		"to know about them and would drop them.\n"+
		"       Run 'curfew update %s' first, then push again", host, host)
}

// readNameContext reads what the router knows that the device file does not:
// its local domain and NTP servers, and the dnsmasq address/server lists.
func readNameContext(r interface{ Run(string) (string, error) }) (ctx dnsnames.Context, address, server []string, err error) {
	dhcp, err := r.Run("uci show dhcp")
	if err != nil {
		return ctx, nil, nil, fmt.Errorf("reading the router's dhcp config: %w", err)
	}
	system, _ := r.Run("uci -q show system || true")
	address, server = dnsnames.DnsmasqLists(dhcp)
	return dnsnames.ContextFromUCI(dhcp, system), address, server, nil
}

func namesDevices(r *registry.Registry) []dnsnames.Device {
	var out []dnsnames.Device
	if r == nil {
		return out
	}
	for _, d := range r.Devices {
		out = append(out, dnsnames.Device{MAC: d.MAC, Label: describeDevice(r, d.MAC), Fixed: d.IP, Names: d.DNSNames})
	}
	return out
}

// checkPushNames runs every rule, with the router's context, on every local
// DNS name in the list being pushed. errs refuse the push; notes are printed:
// warnings, a line per device whose names this push changes, and a report of
// dnsmasq entries for the same domain that are not what curfew would write
// (the daemon leaves those alone, so dnsmasq will not answer that name).
func checkPushNames(ctx dnsnames.Context, address, server []string, local, remote *registry.Registry) (errs, notes []string) {
	results := dnsnames.Check(namesDevices(local), ctx)
	byMAC := map[string][]dnsnames.Result{}
	for _, r := range results {
		byMAC[r.MAC] = append(byMAC[r.MAC], r)
	}
	remoteKey := map[string]string{}
	if remote != nil {
		for _, d := range remote.Devices {
			remoteKey[d.MAC] = strings.Join(d.DNSNames, " ") + "@" + d.IP
		}
	}
	existing := append(append([]string(nil), address...), server...)
	for _, d := range local.Devices {
		if len(d.DNSNames) == 0 {
			continue
		}
		who := describeDevice(local, d.MAC)
		var bad bool
		for _, r := range byMAC[d.MAC] {
			for _, e := range r.Errors {
				errs = append(errs, fmt.Sprintf("%s: %s", who, e))
				bad = true
			}
		}
		if bad {
			continue
		}
		changed := remoteKey[d.MAC] != strings.Join(d.DNSNames, " ")+"@"+d.IP
		for _, r := range byMAC[d.MAC] {
			n, _ := dnsnames.Parse(r.Name)
			if changed {
				notes = append(notes, fmt.Sprintf("%s: %s -> %s, answered by the router within a minute",
					who, n, d.IP))
			}
			for _, w := range r.Warnings {
				notes = append(notes, "    warning: "+w)
			}
			ours := map[string]bool{n.DnsmasqAddress(d.IP): true, n.DnsmasqServer(): true}
			for _, v := range existing {
				if ours[v] {
					continue
				}
				for _, dom := range dnsnames.DomainsOf(v) {
					if dom == n.DnsmasqDomain() {
						notes = append(notes, fmt.Sprintf("    note: the router's dnsmasq already has "+
							"%q for %s. If curfew wrote it (for example before a set-ip move) the router "+
							"replaces it; if somebody else did, curfew leaves it alone and dnsmasq will not "+
							"answer %s for this device", v, dom, n))
					}
				}
			}
		}
	}
	return errs, notes
}
