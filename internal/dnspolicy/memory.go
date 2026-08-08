package dnspolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Headroom answers one question, asked before curfew makes AdGuard rebuild its
// filtering engine: can this router afford it right now?
//
// It exists because the answer was NO on the live router and curfew asked
// anyway. On 2026-08-08 a filter-list change took AdGuard from its resting
// size to 876 MB on a 1010 MB box with no swap, the kernel killed it, and the
// household had no DNS for 88 seconds. A rebuild holds the old engine and the
// new one at the same time, so its cost is roughly a second copy of what
// AdGuard already has resident, and that is a number the router can be asked
// for BEFORE the write rather than discovered by being killed.
//
// This is the fail-open half of the package's contract, applied to itself: a
// DNS refinement that cannot be applied safely is reported and skipped, never
// taken out of the household's resolver.
type Headroom interface {
	// Short returns "" when a rebuild is affordable, or a sentence a person
	// can act on when it is not.
	Short() string
}

// ProcHeadroom measures the real router through /proc.
//
// Dir is the proc mount, so a test can point it at a fixture directory.
type ProcHeadroom struct {
	Dir string
	// Process is the comm name AdGuard runs under.
	Process string
}

// RouterHeadroom is the live one.
func RouterHeadroom() ProcHeadroom { return ProcHeadroom{Dir: "/proc", Process: "AdGuardHome"} }

// Short implements Headroom.
//
// It refuses when the memory the kernel says is available is less than what
// AdGuard is holding, because that is the size of the second copy a rebuild
// makes. The comparison is deliberately crude and deliberately conservative:
// the failure it prevents is the household losing its resolver, and the cost
// of being wrong in the other direction is only that a restriction lands late.
//
// A measurement that cannot be taken is NOT a refusal. If /proc says nothing
// useful, or AdGuard is not running under the expected name, this returns ""
// and the write goes ahead, because a guard that silently disabled the feature
// on any router it did not recognise would be worse than no guard.
func (p ProcHeadroom) Short() string {
	avail, err := p.available()
	if err != nil || avail == 0 {
		return ""
	}
	rss, err := p.adguardRSS()
	if err != nil || rss == 0 {
		return ""
	}
	if avail >= rss {
		return ""
	}
	return fmt.Sprintf(
		"AdGuard is holding %d MB and only %d MB is available, so rebuilding its "+
			"filtering engine would need memory this router does not have. Curfew did "+
			"NOT touch AdGuard's filter lists, because on 2026-08-08 that rebuild got "+
			"AdGuard OOM-killed and the whole house lost DNS for 88 seconds. Fix it by "+
			"giving the router swap (zram) or by removing a large blocklist; until then "+
			"a DNS restriction change is picked up on AdGuard's own update interval "+
			"instead of at once",
		rss/(1<<20), avail/(1<<20))
}

// available is MemAvailable, the kernel's own estimate of what can be handed
// out without swapping, in bytes.
func (p ProcHeadroom) available() (uint64, error) {
	data, err := os.ReadFile(filepath.Join(p.Dir, "meminfo"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("cannot read MemAvailable from %q", line)
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("no MemAvailable in %s/meminfo", p.Dir)
}

// adguardRSS is what AdGuard currently has resident, in bytes.
func (p ProcHeadroom) adguardRSS() (uint64, error) {
	entries, err := os.ReadDir(p.Dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(p.Dir, e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != p.Process {
			continue
		}
		status, err := os.ReadFile(filepath.Join(p.Dir, e.Name(), "status"))
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "VmRSS:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("cannot read VmRSS from %q", line)
			}
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	return 0, fmt.Errorf("no process named %s under %s", p.Process, p.Dir)
}
