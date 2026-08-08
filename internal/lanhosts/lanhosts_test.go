package lanhosts

import (
	"fmt"
	"strings"
	"testing"
)

// Real output from the live router, so the parsers are pinned against what
// they will actually meet rather than against something invented to suit them.
const realNeigh = `fe80::e903:ea9f:d236:2379 lladdr c0:3d:03:d4:ad:6b used 0/0/0 probes 1 STALE
fd96:17c2:5378:0:3d6f:27cd:ce7b:79f7 lladdr c0:3d:03:d4:ad:6b used 0/0/0 probes 1 STALE
fd96:17c2:5378:0:75fc:3167:87c6:8b1e lladdr 04:92:26:1e:6b:55 used 0/0/0 probes 1 STALE
fd96:17c2:5378:0:3c6b:8d73:e05b:a403  used 0/0/0 probes 3 FAILED
fd96:17c2:5378:0:ccf2:6046:70d5:e30b lladdr 04:92:26:1e:6b:55 used 0/0/0 probes 1 STALE
fd96:17c2:5378:0:df0c:d02b:894a:72f lladdr 14:e0:1d:6a:9c:6c used 0/0/0 probes 1 STALE
fd96:17c2:5378:0:41b7:ded0:bee5:3977  used 0/0/0 probes 3 FAILED
fd96:17c2:5378:0:888c:8a4a:c98c:1de0 lladdr 14:e0:1d:6a:9c:6c used 0/0/0 probes 1 STALE
`

// Real lease lines, in dnsmasq's own format.
const realLeases = `1786220000 14:e0:1d:6a:9c:6c 192.168.1.123 * 01:14:e0:1d:6a:9c:6c
1786220001 f0:d7:aa:da:66:35 192.168.1.182 * 01:f0:d7:aa:da:66:35
1786220002 f8:25:51:09:38:38 192.168.1.10 parental_printer *
`

func TestLeasesGiveTheIPv4Address(t *testing.T) {
	got := ParseLeases(realLeases)
	if got["14:e0:1d:6a:9c:6c"] != "192.168.1.123" {
		t.Errorf("eli phone = %q, want 192.168.1.123", got["14:e0:1d:6a:9c:6c"])
	}
	if len(got) != 3 {
		t.Errorf("want 3 leases, got %d: %+v", len(got), got)
	}
}

// Junk must be skipped rather than turned into an address, because a garbage
// entry that reached AdGuard would be a rule keyed to nothing, or worse to
// somebody else.
func TestLeaseGarbageIsSkipped(t *testing.T) {
	got := ParseLeases("not a lease\n123 notamac 192.168.1.5 x\n456 14:e0:1d:6a:9c:6c notanip x\n\n")
	if len(got) != 0 {
		t.Errorf("garbage produced addresses: %+v", got)
	}
}

func TestNeighGivesEveryIPv6AddressPerMAC(t *testing.T) {
	got := ParseNeigh(realNeigh)
	// Two privacy addresses for one device is the ordinary case on this LAN.
	eli := got["14:e0:1d:6a:9c:6c"]
	if len(eli) != 2 {
		t.Errorf("want both of eli's phone addresses, got %v", eli)
	}
	// A link-local address counts too: a client can query the router's
	// link-local DNS address and would then present one.
	desi := got["c0:3d:03:d4:ad:6b"]
	if len(desi) != 2 {
		t.Errorf("want the link-local and the ULA, got %v", desi)
	}
}

// The entries with no lladdr are real on this router and map to NOBODY.
// Attaching them to a device would be inventing an identity.
func TestNeighEntriesWithNoMACAreSkipped(t *testing.T) {
	got := ParseNeigh(realNeigh)
	for mac, addrs := range got {
		for _, a := range addrs {
			if a == "fd96:17c2:5378:0:3c6b:8d73:e05b:a403" || a == "fd96:17c2:5378:0:41b7:ded0:bee5:3977" {
				t.Errorf("an address with no lladdr was attributed to %s", mac)
			}
		}
	}
}

// The safety property, asserted directly: IPv4 comes from the LEASE FILE and
// never from the neighbour table. A stale ARP entry is exactly how a rule ends
// up applying to the wrong child.
func TestIPv4IsNeverTakenFromTheNeighbourTable(t *testing.T) {
	// An ARP-shaped line for a MAC with NO lease. If IPv4 ever came from
	// neighbour data, this would produce an address.
	v4 := ParseLeases("")
	v6 := ParseNeigh("192.168.1.99 lladdr aa:bb:cc:dd:ee:ff used 0/0/0 probes 1 STALE\n")
	joined := Join(v4, v6)
	if a, ok := joined["aa:bb:cc:dd:ee:ff"]; ok && a.IPv4 != "" {
		t.Errorf("an IPv4 address was taken from neighbour data: %+v", a)
	}
	// And the control: an IPv4 line must not become an IPv6 id either.
	if a := joined["aa:bb:cc:dd:ee:ff"]; len(a.IPv6) != 0 {
		t.Errorf("an IPv4 address was recorded as an IPv6 id: %+v", a)
	}
}

func TestJoinPutsBothFamiliesTogether(t *testing.T) {
	joined := Join(ParseLeases(realLeases), ParseNeigh(realNeigh))
	eli := joined["14:e0:1d:6a:9c:6c"]
	if eli.IPv4 != "192.168.1.123" {
		t.Errorf("IPv4 = %q", eli.IPv4)
	}
	if len(eli.IPv6) != 2 {
		t.Errorf("IPv6 = %v", eli.IPv6)
	}
	// A device with IPv6 but NO lease is the measured real case
	// (04:92:26:1e:6b:55 holds only a link-local IPv4 on the live router). It
	// must still contribute its IPv6, or the refinement silently misses a
	// device that is very much online.
	laptop := joined["04:92:26:1e:6b:55"]
	if laptop.IPv4 != "" {
		t.Errorf("want no IPv4 for the device with no lease, got %q", laptop.IPv4)
	}
	if len(laptop.IPv6) != 2 {
		t.Errorf("a device with no IPv4 lease still has IPv6 addresses, got %v", laptop.IPv6)
	}
}

// An unbounded id list is how a rotating privacy address grows an AdGuard
// object for ever. Truncation must be reported rather than silent.
func TestTooManyIPv6AddressesIsCappedAndReported(t *testing.T) {
	var b strings.Builder
	for i := range MaxIPv6PerDevice + 5 {
		fmt.Fprintf(&b, "fd00::%x lladdr aa:bb:cc:dd:ee:01 used 0/0/0 probes 1 STALE\n", i+1)
	}
	joined := Join(nil, ParseNeigh(b.String()))
	got := joined["aa:bb:cc:dd:ee:01"]
	if len(got.IPv6) > MaxIPv6PerDevice {
		t.Errorf("the list was not capped: %d addresses", len(got.IPv6))
	}
	if !got.TooManyIPv6 {
		t.Error("truncation must be reported, or a device silently loses coverage")
	}
}

// The router answering nothing must read as "nothing known", not as an error
// and not as a wrong answer.
func TestAnEmptyRouterIsAnEmptyView(t *testing.T) {
	r := stubRunner{}
	got, err := Observe(r, "/tmp/dhcp.leases", "br-lan")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("want nothing known, got %+v", got)
	}
}

func TestObserveReadsBothSources(t *testing.T) {
	r := stubRunner{leases: realLeases, neigh: realNeigh}
	got, err := Observe(r, "/tmp/dhcp.leases", "br-lan")
	if err != nil {
		t.Fatal(err)
	}
	if got["14:e0:1d:6a:9c:6c"].IPv4 == "" || len(got["14:e0:1d:6a:9c:6c"].IPv6) == 0 {
		t.Errorf("both sources should have been read, got %+v", got["14:e0:1d:6a:9c:6c"])
	}
}

// stubRunner replays router output. It is deliberately dumb: it matches on the
// command text and returns a canned string, encoding no behaviour of its own.
type stubRunner struct{ leases, neigh string }

func (s stubRunner) Run(cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "dhcp.leases"):
		return s.leases, nil
	case strings.Contains(cmd, "neigh"):
		return s.neigh, nil
	}
	return "", nil
}
