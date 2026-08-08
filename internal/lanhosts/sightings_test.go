package lanhosts

import (
	"errors"
	"strings"
	"testing"
)

func TestParseLeaseSightingsKeepsTheHostnameAndAddress(t *testing.T) {
	got := ParseLeaseSightings("1785993502 aa:bb:cc:dd:ee:01 192.168.1.42 elis-phone 01:aa:bb\n")
	s, ok := got["aa:bb:cc:dd:ee:01"]
	if !ok {
		t.Fatalf("lease not seen: %+v", got)
	}
	if s.IPv4 != "192.168.1.42" {
		t.Errorf("address: want 192.168.1.42, got %q", s.IPv4)
	}
	if s.Hostname != "elis-phone" {
		t.Errorf("hostname: want elis-phone, got %q", s.Hostname)
	}
}

// dnsmasq writes "*" for a client that offered no hostname. Carrying that
// through to a page would show a parent a device called "*", which is worse
// than showing nothing, so it is normalised away at the parser rather than
// worked around in a template.
func TestParseLeaseSightingsTreatsStarAsNoHostname(t *testing.T) {
	got := ParseLeaseSightings("1785993502 aa:bb:cc:dd:ee:02 192.168.1.43 * 01:aa\n")
	if h := got["aa:bb:cc:dd:ee:02"].Hostname; h != "" {
		t.Errorf("want no hostname for '*', got %q", h)
	}
}

func TestParseLeaseSightingsSkipsRubbish(t *testing.T) {
	got := ParseLeaseSightings(strings.Join([]string{
		"",
		"garbage",
		"1785993502 not-a-mac 192.168.1.44 host id",
		"1785993502 aa:bb:cc:dd:ee:03 not-an-ip host id",
		"1785993502 aa:bb:cc:dd:ee:04 192.168.1.45 host id",
	}, "\n"))
	if len(got) != 1 {
		t.Fatalf("want only the one good line, got %+v", got)
	}
	if _, ok := got["aa:bb:cc:dd:ee:04"]; !ok {
		t.Errorf("the good line was dropped: %+v", got)
	}
}

// A device with a static address, or one whose lease has lapsed, is exactly
// the device an admin most needs to see. It has no lease line, so the
// neighbour table is the only place it appears at all.
func TestParseNeighSightingsFindsMACsWithNoLease(t *testing.T) {
	got := ParseNeighSightings(strings.Join([]string{
		"192.168.1.50 lladdr aa:bb:cc:dd:ee:05 REACHABLE",
		"fd96:17c2:5378:0:b0fe:9959:ad68:8107 lladdr aa:bb:cc:dd:ee:06 STALE",
		"192.168.1.51  FAILED",
		"192.168.1.52 lladdr not-a-mac REACHABLE",
	}, "\n"))
	if len(got) != 2 {
		t.Fatalf("want the two entries carrying a usable lladdr, got %+v", got)
	}
	if got["aa:bb:cc:dd:ee:05"].IPv4 != "192.168.1.50" {
		t.Errorf("v4 neighbour address not carried: %+v", got["aa:bb:cc:dd:ee:05"])
	}
	// An IPv6-only neighbour is still a MAC worth listing, but it has no IPv4
	// address to show and must not invent one.
	if a := got["aa:bb:cc:dd:ee:06"].IPv4; a != "" {
		t.Errorf("an IPv6 neighbour must not produce an IPv4 address, got %q", a)
	}
}

func TestObserveSightingsPrefersTheLeaseOverTheNeighbourTable(t *testing.T) {
	r := fakeRunner{
		leases: "1785993502 aa:bb:cc:dd:ee:07 192.168.1.60 laptop id\n",
		neigh:  "192.168.1.99 lladdr aa:bb:cc:dd:ee:07 STALE\n",
	}
	got, err := ObserveSightings(&r, "/tmp/dhcp.leases", "br-lan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := got["aa:bb:cc:dd:ee:07"]
	// The lease is the router's own record of what it handed out; the
	// neighbour entry is whatever was overheard, and may be stale.
	if s.IPv4 != "192.168.1.60" {
		t.Errorf("want the leased address to win, got %q", s.IPv4)
	}
	if s.Hostname != "laptop" {
		t.Errorf("hostname lost: %+v", s)
	}
}

// Nothing here decides whether anybody has internet, so an unreadable router
// is an empty list and not an error. A page that 500s because the neighbour
// table could not be read would be a worse outcome than one that shows
// nothing.
func TestObserveSightingsFailsSoft(t *testing.T) {
	got, err := ObserveSightings(&fakeRunner{err: errors.New("no such command")}, "/tmp/x", "br-lan")
	if err != nil {
		t.Fatalf("want a soft failure, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want an empty list, got %+v", got)
	}
}

func TestObserveSightingsSurvivesOneSourceFailing(t *testing.T) {
	got, err := ObserveSightings(&fakeRunner{
		leases:   "1785993502 aa:bb:cc:dd:ee:08 192.168.1.61 tv id\n",
		neighErr: true,
	}, "/tmp/dhcp.leases", "br-lan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["aa:bb:cc:dd:ee:08"]; !ok {
		t.Fatalf("a failing neighbour table must not lose the leases: %+v", got)
	}
}

type fakeRunner struct {
	leases   string
	neigh    string
	err      error
	neighErr bool
}

func (f *fakeRunner) Run(cmd string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if strings.Contains(cmd, "neigh") {
		if f.neighErr {
			return "", errors.New("ip: not found")
		}
		return f.neigh, nil
	}
	return f.leases, nil
}
