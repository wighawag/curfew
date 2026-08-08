package httpui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wighawag/curfew/internal/lanhosts"
	"github.com/wighawag/curfew/internal/registry"
)

// The PENDING list closes the gap between what the router knows and what a
// person has to type.
//
// Registering a device used to mean reading a MAC address off another screen
// and typing it into a box. The router already holds every address on the LAN,
// so that was work a person did for a machine, and it had a failure mode worth
// naming: a mistyped address registers a device that does not exist,
// enforcement silently applies to nobody, and the page cheerfully lists it as
// allowed. This is the same class of lie the whole project exists to remove,
// arriving through the keyboard instead of through a state file.
//
// Everything here is OBSERVATION and none of it is load-bearing. It decides
// nothing about who reaches the internet; it only shortens the path between an
// admin and a decision they were going to make anyway. So every failure in it
// degrades to an empty list, never to an error: the one moment this page is
// needed is the moment something is not working, and a 500 then would remove
// the only screen that explains why.

// PendingDevice is one device the router has seen and the registry does not
// know about.
type PendingDevice struct {
	MAC string
	// Hostname is the name the device claimed for ITSELF over DHCP. It is
	// shown because it is the only thing on the row a person can recognise,
	// and it is never stored: what gets saved is the name the admin types.
	Hostname string
	// IPv4 is display only. It is not what any policy is keyed to, which is
	// why it may come from the neighbour table here when the identity bridge
	// refuses that source (see internal/lanhosts).
	IPv4 string
	// Randomised marks a locally administered address. Evidence rather than
	// proof; see registry.LocallyAdministered for why it is worth saying and
	// why nothing decides anything by it.
	Randomised bool
	// Leased distinguishes a device the router gave an address to from one it
	// merely overheard. A device with no lease is often a device whose
	// enrolment or DHCP is exactly what is broken.
	Leased bool
}

// UseLANSightings lets the device page list what the router has seen.
//
// Left unset, the pending section is ABSENT rather than empty. That is the
// honest rendering: "curfew is not looking" and "curfew looked and found
// nothing" are different states, and an empty table would claim the second
// while meaning the first.
func (s *Server) UseLANSightings(observe func() (map[string]lanhosts.Sighting, error)) {
	s.sightings = observe
}

// pendingDevices subtracts the registry from what the router has seen.
func (s *Server) pendingDevices() []PendingDevice {
	if s.sightings == nil {
		return nil
	}
	seen, err := s.sightings()
	if err != nil {
		// Warned, not returned. See the package note above: this list is a
		// convenience and must never be able to break the page it sits on.
		s.log.Warn("could not read what the router has seen on the LAN; "+
			"the pending-device list will be empty", "error", err)
		return nil
	}
	reg, err := s.store.Load()
	if err != nil {
		s.log.Warn("could not read the device registry for the pending list", "error", err)
		return nil
	}
	known := make(map[string]bool, len(reg.Devices))
	for _, d := range reg.Devices {
		known[d.MAC] = true
	}

	out := make([]PendingDevice, 0, len(seen))
	for mac, sighting := range seen {
		canonical, err := registry.NormaliseMAC(mac)
		if err != nil || known[canonical] {
			continue
		}
		out = append(out, PendingDevice{
			MAC:        canonical,
			Hostname:   sighting.Hostname,
			IPv4:       sighting.IPv4,
			Randomised: registry.LocallyAdministered(canonical),
			Leased:     sighting.Leased,
		})
	}
	// Named devices first, because a row a person can recognise is the row
	// they are looking for; then by address, which is stable across reloads.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Hostname == "") != (out[j].Hostname == "") {
			return out[i].Hostname != ""
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// profileChoice is one option in the enrolment form's profile select.
type profileChoice struct {
	Value string
	Label string
}

// noProfileChoice is the sentinel for "register it, govern it by nothing".
const noProfileChoice = "none"

// profilePrefix namespaces real profile names inside the select's values.
//
// Without it a household with a profile called "none" could not express the
// difference between that profile and no profile at all. Prefixing every real
// name makes the collision impossible by construction rather than by hoping
// nobody picks that word.
const profilePrefix = "p:"

func (s *Server) profileChoices() []profileChoice {
	ps, err := s.schedule.Load()
	if err != nil {
		s.log.Warn("could not read profiles for the enrolment form", "error", err)
		return nil
	}
	out := make([]profileChoice, 0, len(ps.Profiles))
	for _, p := range ps.Profiles {
		out = append(out, profileChoice{Value: profilePrefix + p.Name, Label: p.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// parseProfileChoice reads the form's profile field.
//
// An ABSENT field means no profile, which keeps the endpoint's original
// contract intact for anything that posts a bare MAC. An unreadable value is
// REFUSED rather than treated as no-profile, because "no profile" is the
// permissive answer: a device in no profile is an ungoverned device with
// permanently unrestricted access (docs/adr/0003), so guessing it from an
// input nobody understood would hand out more internet than anyone asked for.
func parseProfileChoice(v string) (name string, err error) {
	switch {
	case strings.TrimSpace(v) == "", v == noProfileChoice:
		return "", nil
	case strings.HasPrefix(v, profilePrefix):
		return strings.TrimPrefix(v, profilePrefix), nil
	default:
		return "", fmt.Errorf("could not read which profile to use from %q", v)
	}
}
