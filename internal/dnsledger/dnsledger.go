// Package dnsledger is curfew's record of the DNS records it has written for
// local DNS names, and therefore of which ones it owns.
//
// Neither kind of record can carry an ownership marker (measured): an AdGuard
// rewrite is exactly {domain, answer, enabled}, and an entry in dnsmasq's
// `address` or `server` uci list is a bare string. So ownership is this file,
// per docs/adr/0014. The rules every user of it follows:
//
//   - change or delete a record only when it is in the ledger AND present;
//   - never claim a foreign record, not even one identical to what curfew
//     wants (deleting it later would destroy the household's own record);
//   - WRITE AHEAD: record before creating, forget only after deleting, so
//     after a crash or a rollback the ledger is a superset of what exists,
//     never a subset.
//
// It is router state, not configuration: never pushed or pulled, and kept in
// /etc/config so it survives a sysupgrade with the rest of curfew's files.
package dnsledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// DefaultPath is where the daemon keeps the ledger on the router.
const DefaultPath = "/etc/config/curfew/dns-records.json"

// DnsmasqEntry is one value curfew wrote into dhcp.@dnsmasq[0].
type DnsmasqEntry struct {
	// List is "address" or "server".
	List  string `json:"list"`
	Value string `json:"value"`
}

// Rewrite is one AdGuard DNS rewrite curfew created.
type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// Ledger is the whole file.
type Ledger struct {
	Dnsmasq []DnsmasqEntry `json:"dnsmasq"`
	AdGuard []Rewrite      `json:"adguard"`
}

// Load reads the ledger. A missing file is an empty ledger: curfew owns
// nothing yet, which is the safe reading.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Ledger{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the DNS record ledger %s: %w", path, err)
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		// Not "empty": an unreadable ledger means ownership is UNKNOWN, and
		// guessing either way is wrong. The caller writes nothing.
		return nil, fmt.Errorf("parsing the DNS record ledger %s: %w", path, err)
	}
	return &l, nil
}

// Save writes the ledger atomically, sorted so it diffs cleanly.
func Save(path string, l *Ledger) error {
	sort.Slice(l.Dnsmasq, func(i, j int) bool {
		if l.Dnsmasq[i].List != l.Dnsmasq[j].List {
			return l.Dnsmasq[i].List < l.Dnsmasq[j].List
		}
		return l.Dnsmasq[i].Value < l.Dnsmasq[j].Value
	})
	sort.Slice(l.AdGuard, func(i, j int) bool {
		if l.AdGuard[i].Domain != l.AdGuard[j].Domain {
			return l.AdGuard[i].Domain < l.AdGuard[j].Domain
		}
		return l.AdGuard[i].Answer < l.AdGuard[j].Answer
	})
	if l.Dnsmasq == nil {
		l.Dnsmasq = []DnsmasqEntry{}
	}
	if l.AdGuard == nil {
		l.AdGuard = []Rewrite{}
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dns-records-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// HasDnsmasq reports whether curfew recorded writing e.
func (l *Ledger) HasDnsmasq(e DnsmasqEntry) bool {
	for _, x := range l.Dnsmasq {
		if x == e {
			return true
		}
	}
	return false
}

// HasRewrite reports whether curfew recorded creating r.
func (l *Ledger) HasRewrite(r Rewrite) bool {
	for _, x := range l.AdGuard {
		if x == r {
			return true
		}
	}
	return false
}
