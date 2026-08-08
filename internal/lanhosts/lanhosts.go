// Package lanhosts answers "what addresses does this MAC currently have?" by
// reading what the router already knows.
//
// It exists because AdGuard identifies a client by IP and curfew identifies a
// device by MAC (docs/adr/0010), so something has to join the two. Everything
// here is OBSERVATION, and it is deliberately kept away from the load-bearing
// controls: whether a child is online at all, their schedule, their budget and
// any manual block are nftables on MAC and never consult a line of this
// package. Only the domain refinement uses it. A missing or wrong answer here
// means "no streaming" might not apply while bedtime and budget still do.
//
// # The two address families get DIFFERENT rules, and the asymmetry is the point
//
// A stale IPv4 address is DANGEROUS. DHCP reissues addresses, so an address
// that belonged to one child an hour ago can belong to another now, and a rule
// keyed to it would restrict the WRONG CHILD. That is worse than no rule at
// all. So IPv4 is taken ONLY from the DHCP lease file, which is the router's
// own record of what it handed out, and never from the ARP table, which is
// full of addresses nothing is authoritative about.
//
// A stale IPv6 address is nearly harmless. A SLAAC address carries 64 bits of
// interface identifier, and a temporary one is random, so it will essentially
// never be reissued to a different device. That is what makes it safe to take
// IPv6 from the neighbour table, which is the only place these addresses
// appear at all.
//
// # Why the neighbour table, and why that also prunes
//
// Measured on the live router: the addresses AdGuard actually sees are SLAAC
// privacy addresses (fd96:17c2:5378:0:b0fe:9959:ad68:8107 and the like).
// odhcpd's own leases and /tmp/hosts contain something else entirely, the
// DHCPv6-assigned addresses (fd96:17c2:5378::641), which made ZERO queries.
// So odhcpd is not a usable source for this and `ip -6 neigh` is.
//
// Privacy addresses rotate, so any list of them needs pruning or it grows
// without bound. The pruning here is structural rather than a policy with a
// timer: the answer is exactly what the neighbour table says RIGHT NOW, with
// no accumulated history. An address a device is actively using cannot age out
// of that table while it is in use, because the router is replying to it.
package lanhosts

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// MaxIPv6PerDevice bounds how many IPv6 addresses one device contributes.
//
// A device with privacy extensions holds a couple at a time (three was the
// most seen on the live router), so this is slack rather than a limit anyone
// should meet. It exists so that a device misbehaving, or an unusually long
// neighbour table, cannot grow an AdGuard client object without bound. Being
// over it is REPORTED rather than silently truncated.
const MaxIPv6PerDevice = 16

// Addresses is what is known about one MAC.
type Addresses struct {
	// IPv4 is the address the DHCP server records having handed out. Empty
	// when there is no lease, which is a real and reportable state rather than
	// an error.
	IPv4 string
	// IPv6 is every address the neighbour table currently maps to this MAC.
	IPv6 []string
	// TooManyIPv6 is set when the device presented more addresses than
	// MaxIPv6PerDevice and the list was truncated.
	TooManyIPv6 bool
}

// Runner executes commands where the router can answer them.
type Runner interface {
	Run(cmd string) (string, error)
}

// ParseLeases reads dnsmasq's lease file.
//
// Format is `<expiry> <mac> <ip> <hostname> <clientid>`. Only the MAC and the
// address are taken; the hostname is the device's own claim about itself and
// is not something to trust or store.
func ParseLeases(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mac := strings.ToLower(fields[1])
		ip := fields[2]
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			continue
		}
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		out[mac] = ip
	}
	return out
}

// ParseNeigh reads `ip -6 neigh show dev <lan>` into MAC to addresses.
//
// Entries with no lladdr are skipped. They are real (the live router carries
// several in FAILED state) and they map to nothing, so including them would
// invent a client identity out of an address whose owner is unknown, which is
// exactly the wrong-device risk this package is shaped to avoid.
func ParseNeigh(content string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() != nil {
			continue // not an IPv6 address
		}
		if ip.IsMulticast() {
			continue
		}
		var mac string
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				mac = strings.ToLower(fields[i+1])
				break
			}
		}
		if mac == "" {
			continue
		}
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		out[mac] = append(out[mac], fields[0])
	}
	for mac := range out {
		sort.Strings(out[mac])
	}
	return out
}

// Observe reads the router's current view of the LAN.
//
// leasePath and lanInterface are passed in rather than assumed so the same
// code runs against a test fixture and against the router.
func Observe(r Runner, leasePath, lanInterface string) (map[string]Addresses, error) {
	// `cat || true`: a router that has handed out no leases yet has no file,
	// and that is an empty LAN rather than a failure.
	leaseOut, err := r.Run(fmt.Sprintf("cat %s 2>/dev/null || true", leasePath))
	if err != nil {
		return nil, fmt.Errorf("reading DHCP leases from %s: %w", leasePath, err)
	}
	neighOut, err := r.Run(fmt.Sprintf("ip -6 neigh show dev %s 2>/dev/null || true", lanInterface))
	if err != nil {
		return nil, fmt.Errorf("reading the IPv6 neighbour table on %s: %w", lanInterface, err)
	}
	return Join(ParseLeases(leaseOut), ParseNeigh(neighOut)), nil
}

// Join merges the two observations into one view per MAC.
func Join(v4 map[string]string, v6 map[string][]string) map[string]Addresses {
	out := map[string]Addresses{}
	for mac, ip := range v4 {
		a := out[mac]
		a.IPv4 = ip
		out[mac] = a
	}
	for mac, ips := range v6 {
		a := out[mac]
		if len(ips) > MaxIPv6PerDevice {
			a.TooManyIPv6 = true
			ips = ips[:MaxIPv6PerDevice]
		}
		a.IPv6 = ips
		out[mac] = a
	}
	return out
}
