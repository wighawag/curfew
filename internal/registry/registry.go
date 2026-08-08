// Package registry is the device registry: the named MAC addresses that are
// allowed on the network. It is the single source of truth for the allowlist.
//
// Storage is JSON the tool owns and rewrites losslessly, per
// docs/adr/0008-configuration-is-tool-owned-structured-files-split-by-concern.md,
// and devices are named first-class entities rather than bare MACs with the
// name in a comment, per docs/adr/0003-devices-are-named-and-profiles-group-them.md.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Device is one named MAC address. Name is optional: a device may be
// registered and allowed with no name at all.
type Device struct {
	MAC  string `json:"mac"`
	Name string `json:"name,omitempty"`
}

// Registry is the whole device file.
type Registry struct {
	Devices []Device `json:"devices"`
}

// ErrNotFound is returned by Remove for a MAC that is not registered.
var ErrNotFound = errors.New("device not registered")

// NormaliseMAC parses a MAC in any accepted spelling and returns the canonical
// lowercase colon-separated form. Canonicalising on the way IN is what stops
// the same device being registered twice under two spellings, which would then
// be impossible to remove by either.
func NormaliseMAC(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", errors.New("empty MAC address")
	}
	hw, err := net.ParseMAC(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid MAC address %q: %w", s, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC address %q: want 6 octets, got %d", s, len(hw))
	}
	return hw.String(), nil
}

// LocallyAdministered reports whether a MAC was made up by the device rather
// than assigned from a vendor OUI.
//
// It is EVIDENCE, not proof, and the difference matters wherever this is
// shown. A phone using a private Wi-Fi address sets this bit, so on a
// household LAN it almost always means "randomised"; but a hand-set address,
// a virtual machine's bridge and a container all set it too. So it is worth
// saying out loud next to a device an admin is about to enrol, and it is not
// worth deciding anything by.
//
// Why it is worth saying at all: per
// work/notes/findings/wifi-mac-randomisation-is-per-network-and-persistent.md
// a randomised address is stable per network until its owner erases the
// device, resets its network settings or forgets the network. So an enrolment
// against one of these addresses works for months and then, one day, does
// not. An admin who was told at enrolment time is looking at a device that
// needs approving again; one who was not is looking at a stranger.
//
// An unparseable address is reported false: nothing is known about it, and
// claiming a property of an address that does not exist would be worse than
// saying nothing.
func LocallyAdministered(mac string) bool {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}

// Add registers a device. The MAC is canonicalised first. Adding a MAC that is
// already registered updates its name rather than creating a duplicate, so the
// operation is idempotent and the file can never hold the same MAC twice.
func (r *Registry) Add(mac, name string) error {
	canonical, err := NormaliseMAC(mac)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	for i := range r.Devices {
		if r.Devices[i].MAC == canonical {
			r.Devices[i].Name = name
			return nil
		}
	}
	r.Devices = append(r.Devices, Device{MAC: canonical, Name: name})
	return nil
}

// Rename changes a registered device's name. Unlike Add it is STRICT: renaming
// a MAC that is not registered is an error rather than a quiet insert.
// Otherwise a rename racing a removal would silently resurrect the device, and
// resurrecting an entry in an allowlist means handing back internet access
// nobody asked to restore.
func (r *Registry) Rename(mac, name string) error {
	canonical, err := NormaliseMAC(mac)
	if err != nil {
		return err
	}
	for i := range r.Devices {
		if r.Devices[i].MAC == canonical {
			r.Devices[i].Name = strings.TrimSpace(name)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, canonical)
}

// Remove deregisters a device, which also removes it from the allowlist.
func (r *Registry) Remove(mac string) error {
	canonical, err := NormaliseMAC(mac)
	if err != nil {
		return err
	}
	for i := range r.Devices {
		if r.Devices[i].MAC == canonical {
			r.Devices = append(r.Devices[:i], r.Devices[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, canonical)
}

// MACs returns the canonical allowlist, sorted so the output is stable. A
// stable order matters because this feeds both the ruleset and the UI, and an
// unstable one would make every reconcile look like a change.
func (r *Registry) MACs() []string {
	out := make([]string, 0, len(r.Devices))
	for _, d := range r.Devices {
		out = append(out, d.MAC)
	}
	sort.Strings(out)
	return out
}

// Load reads a registry. A missing file is not an error: it is an empty
// registry, so a first run needs no bootstrap step.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Registry{Devices: []Device{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var r Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if r.Devices == nil {
		r.Devices = []Device{}
	}
	// Canonicalise on load too, so a hand-edited file cannot smuggle in a
	// spelling that then fails to match anything.
	for i := range r.Devices {
		canonical, err := NormaliseMAC(r.Devices[i].MAC)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: device %d: %w", path, i, err)
		}
		r.Devices[i].MAC = canonical
	}
	return &r, nil
}

// Save writes the registry atomically: a temp file in the same directory, then
// a rename. A half-written registry would be a half-populated allowlist, which
// is a household with some devices silently offline.
func Save(path string, r *Registry) error {
	if r.Devices == nil {
		r.Devices = []Device{}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding registry: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// FileStore adapts a registry file to the interface the HTTP layer needs, so
// that layer depends on two small methods rather than on the filesystem.
type FileStore struct{ Path string }

// Load reads the registry from disk.
func (f FileStore) Load() (*Registry, error) { return Load(f.Path) }

// Save writes the registry to disk atomically.
func (f FileStore) Save(r *Registry) error { return Save(f.Path, r) }
