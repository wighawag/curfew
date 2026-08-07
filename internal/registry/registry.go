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
