package lanhosts

import (
	"fmt"
	"net"
	"strings"
)

// A SIGHTING is a different question from the rest of this package, asked for
// a different purpose, and the difference is what makes its looser rules safe.
//
// Observe answers "what addresses does this MAC have?", and its answer keys a
// DNS restriction to a client. A wrong answer there restricts the WRONG CHILD,
// which is why IPv4 comes only from the lease file and never from the ARP
// table, and why the hostname is thrown away as an untrustworthy claim.
//
// ObserveSightings answers "which MACs has this router seen at all?", and its
// answer is shown to a HUMAN who is deciding whether to enrol one of them.
// Nothing derived here keys any policy to any address. That inverts both
// trade-offs:
//
//   - The ARP/neighbour table IS used, because a device with a static address
//     or a lapsed lease has no lease line, and that device is precisely the one
//     an admin most needs to see. A stale address next to it is a cosmetic
//     wrong, not a misapplied rule.
//   - The claimed hostname IS carried, because it is the only thing on the row
//     that lets a person recognise their own phone. It stays a CLAIM: it is
//     displayed at the moment of enrolment and never stored, so nothing in this
//     system ever depends on a device's account of itself.
//
// If either of those ever starts feeding something that decides who reaches
// the internet, this reasoning stops holding and the strict rules above apply
// instead.

// Sighting is what the router currently knows about one MAC it has seen.
type Sighting struct {
	// MAC is the canonical lowercase colon-separated address.
	MAC string
	// IPv4 is the leased address where there is one, else whatever the
	// neighbour table last recorded. DISPLAY ONLY.
	IPv4 string
	// Hostname is the name the device claimed for itself over DHCP. It is a
	// hint for a human and is never stored. Empty when the device offered
	// none.
	Hostname string
	// Leased distinguishes "the router handed this device an address" from
	// "the router has merely overheard this address", which is the difference
	// between a device that completed DHCP and one that did not.
	Leased bool
}

// ParseLeaseSightings reads dnsmasq's lease file, keeping the hostname that
// ParseLeases deliberately discards.
//
// Format is `<expiry> <mac> <ip> <hostname> <clientid>`.
func ParseLeaseSightings(content string) map[string]Sighting {
	out := map[string]Sighting{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mac := strings.ToLower(fields[1])
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		ip := net.ParseIP(fields[2])
		if ip == nil || ip.To4() == nil {
			continue
		}
		s := Sighting{MAC: mac, IPv4: fields[2], Leased: true}
		if len(fields) > 3 {
			// dnsmasq writes "*" for a client that named itself nothing.
			// Passing that through would put a device called "*" in front of
			// a parent, so it is normalised here rather than in a template.
			if h := fields[3]; h != "*" {
				s.Hostname = h
			}
		}
		out[mac] = s
	}
	return out
}

// ParseNeighSightings reads `ip neigh show dev <lan>` for MAC PRESENCE.
//
// Both address families are accepted, because the question is which MACs
// exist rather than which addresses they hold; an IPv6-only neighbour is a
// device worth listing and simply has no IPv4 address to show. Entries with no
// lladdr are skipped: they are real (a FAILED entry has none) and they name no
// device.
func ParseNeighSightings(content string) map[string]Sighting {
	out := map[string]Sighting{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.IsMulticast() {
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
		s := out[mac]
		s.MAC = mac
		if ip.To4() != nil && s.IPv4 == "" {
			s.IPv4 = fields[0]
		}
		out[mac] = s
	}
	return out
}

// ObserveSightings reads every MAC the router currently knows about.
//
// It NEVER returns an error for a source it could not read. This list exists
// so a human can see a device that is not working; degrading it to an error
// page would remove the one screen that explains the problem, at the exact
// moment it is needed. A caller that wants to know a source failed should
// notice an empty result, which is honest, rather than be handed a failure it
// can only log.
func ObserveSightings(r Runner, leasePath, lanInterface string) (map[string]Sighting, error) {
	out := map[string]Sighting{}

	// The neighbour table first, so a lease can overwrite an overheard
	// address with the one the router actually handed out.
	if neigh, err := r.Run(fmt.Sprintf("ip neigh show dev %s 2>/dev/null || true", lanInterface)); err == nil {
		for mac, s := range ParseNeighSightings(neigh) {
			out[mac] = s
		}
	}
	if leaseOut, err := r.Run(fmt.Sprintf("cat %s 2>/dev/null || true", leasePath)); err == nil {
		for mac, s := range ParseLeaseSightings(leaseOut) {
			if s.IPv4 == "" {
				s.IPv4 = out[mac].IPv4
			}
			out[mac] = s
		}
	}
	return out, nil
}
