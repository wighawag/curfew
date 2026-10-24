package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wighawag/curfew/internal/deploy"
	"github.com/wighawag/curfew/internal/leases"
	"github.com/wighawag/curfew/internal/registry"
)

// `curfew set-ip`: give a registered device a FIXED ADDRESS, or clear it.
//
// It edits the LOCAL device file only and takes no host, like nothing else in
// the command table: the router is changed by `curfew push`, which checks the
// address against the router's own DHCP config before writing anything. Only
// the router knows its subnet, its pool and who else holds an address, so
// that is where the real checks are; this command catches what it can offline
// (the spelling, and an address another device in the file already has).
// See docs/adr/0012.

type setIPArgs struct {
	ref, ip, registry string
	clear             bool
}

// parseSetIPArgs accepts flags on either side of the positional arguments, so
// `set-ip shyrka --clear` and `set-ip --clear shyrka` both work.
func parseSetIPArgs(args []string) (setIPArgs, error) {
	a := setIPArgs{registry: defaultRegistryPath()}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-clear" || arg == "--clear":
			a.clear = true
		case arg == "-registry" || arg == "--registry":
			if i+1 >= len(args) {
				return a, fmt.Errorf("%s needs a path", arg)
			}
			i++
			a.registry = args[i]
		case strings.HasPrefix(arg, "-registry=") || strings.HasPrefix(arg, "--registry="):
			a.registry = arg[strings.Index(arg, "=")+1:]
		case strings.HasPrefix(arg, "-"):
			return a, fmt.Errorf("unknown flag %s", arg)
		default:
			pos = append(pos, arg)
		}
	}
	const how = "usage: curfew set-ip <mac|name> <ip>   or   curfew set-ip <mac|name> --clear"
	switch {
	case len(pos) == 0:
		return a, fmt.Errorf("no device given\n%s", how)
	case a.clear && len(pos) != 1:
		return a, fmt.Errorf("--clear takes a device and no address\n%s", how)
	case !a.clear && len(pos) != 2:
		return a, fmt.Errorf("give a device and one address\n%s", how)
	}
	a.ref = pos[0]
	if !a.clear {
		a.ip = pos[1]
	}
	return a, nil
}

func cmdSetIP(args []string) error {
	a, err := parseSetIPArgs(args)
	if err != nil {
		return err
	}
	msg, err := setIP(a.registry, a.ref, a.ip, a.clear)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

// setIP edits the device file at path and says what happens next.
func setIP(path, ref, ip string, clear bool) (string, error) {
	reg, err := registry.Load(path)
	if err != nil {
		return "", err
	}
	mac, err := reg.Resolve(ref)
	if err != nil {
		return "", err
	}
	if clear {
		ip = ""
	}
	if err := reg.SetIP(mac, ip); err != nil {
		return "", err
	}
	if err := registry.Save(path, reg); err != nil {
		return "", err
	}
	who := describeDevice(reg, mac)
	if clear {
		return fmt.Sprintf("%s: fixed address cleared in %s.\n"+
			"Run 'curfew push <host>' to apply it. The device keeps the address it has now.", who, path), nil
	}
	for _, d := range reg.Devices {
		if d.MAC == mac {
			ip = d.IP
		}
	}
	return fmt.Sprintf("%s: fixed address %s set in %s.\n"+
		"Run 'curfew push <host>' to apply it; push checks it against the router's DHCP "+
		"config first and writes nothing if it clashes.", who, ip, path), nil
}

func describeDevice(reg *registry.Registry, mac string) string {
	for _, d := range reg.Devices {
		if d.MAC == mac && d.Name != "" {
			return fmt.Sprintf("%s (%s)", d.Name, mac)
		}
	}
	return mac
}

func anyFixed(r *registry.Registry) bool {
	for _, d := range r.Devices {
		if d.IP != "" {
			return true
		}
	}
	return false
}

// requireFixedAddressSupport refuses a push that carries a fixed address to a
// daemon that does not know the field. That daemon's own page would drop it on
// its next save, and the next pull would read the drop as the household
// clearing it: a silent loss through the very merge meant to prevent one.
func requireFixedAddressSupport(supported bool, local *registry.Registry, host string) error {
	if supported || !anyFixed(local) {
		return nil
	}
	return fmt.Errorf("your device list sets a fixed address, but the daemon on %s is too old "+
		"to know about fixed addresses and would drop them.\n"+
		"       Run 'curfew update %s' first, then push again", host, host)
}

// daemonSupports asks the router's daemon whether it understands a feature.
// An older daemon has no -features flag and fails, which reads as "no".
func daemonSupports(r deploy.Runner, feature string) bool {
	out, err := r.Run(deploy.RemoteBinary + " -features 2>/dev/null")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == feature {
			return true
		}
	}
	return false
}

// checkPushAddresses runs the router-side checks on every fixed address in the
// list being pushed. errs refuse the push; notes are printed for each device
// whose fixed address this push CHANGES, because those are the devices about
// to move and the household needs to know when and how.
func checkPushAddresses(s leases.Survey, local, remote *registry.Registry) (errs, notes []string) {
	remoteIP := map[string]string{}
	inRemote := map[string]bool{}
	if remote != nil {
		for _, d := range remote.Devices {
			remoteIP[d.MAC] = d.IP
			inRemote[d.MAC] = true
		}
	}
	devices := append([]registry.Device(nil), local.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].MAC < devices[j].MAC })
	for _, d := range devices {
		who := describeDevice(local, d.MAC)
		changed := d.IP != remoteIP[d.MAC]
		if d.IP == "" {
			if changed && inRemote[d.MAC] {
				notes = append(notes, fmt.Sprintf("%s: fixed address cleared; it keeps the address it has now", who))
			}
			continue
		}
		others := map[string]string{}
		for _, o := range local.Devices {
			if o.MAC != d.MAC && o.IP != "" {
				others[o.MAC] = o.IP
			}
		}
		c := s.CheckFixed(d.MAC, d.IP, others)
		for _, e := range c.Errors {
			errs = append(errs, fmt.Sprintf("%s: %s", who, e))
		}
		if len(c.Errors) == 0 && changed {
			notes = append(notes, fmt.Sprintf("%s: fixed address %s", who, d.IP))
			for _, w := range c.Warnings {
				notes = append(notes, "    "+w)
			}
		}
	}
	return errs, notes
}
