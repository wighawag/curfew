package adguard

import (
	"fmt"
	"strings"
	"time"
)

// Applying a category change to a RUNNING AdGuard: write the config, restart,
// and prove it came back, or put the old config back.
//
// The rollback is the reason this is not three lines of shell. Writing a
// config AdGuard refuses leaves the household with no resolver at all, and
// that failure is silent from the router's point of view: procd respawns the
// service, it exits again, and nothing on any page says why the internet
// stopped working. This is the same lesson internal/leases learned the
// expensive way with dnsmasq, applied before it is learned again.

// Runner executes a command on the router.
type Runner interface {
	Run(cmd string) (string, error)
}

// Prober answers the only question that matters after a restart: is this
// AdGuard actually serving DNS again? It is an interface so the acceptance
// test can watch a real resolver while the unit tests stay hermetic.
type Prober interface {
	Serving() bool
}

// DefaultRestartTimeout is how long AdGuard gets to serve DNS again after a
// restart. Generous for the same measured reason the installer's is: it loads
// its blocklists before binding port 53, which took 43 seconds on the live
// router with 102 MB of lists.
const DefaultRestartTimeout = 120 * time.Second

// backupSuffix marks the copy taken before an edit. It is a fixed name rather
// than a timestamped one: a household finding this file should be able to tell
// at a glance that it is curfew's and that there is exactly one.
//
// It is deliberately NOT the ".curfew-backup" that internal/deploy writes when
// it closes an adopted AdGuard's open API. That one is a once-ever copy of the
// config as it was before curfew touched anything, and a routine category
// change overwriting it would quietly destroy the only record of that state.
const backupSuffix = ".curfew-prev"

// ApplyReport says what an apply did, in terms a person can check.
type ApplyReport struct {
	Changed bool
	// Added and Removed are the categories that came and went.
	Added, Removed []string
	// RolledBack is set when AdGuard did not come back and the previous config
	// was restored. The error explains why.
	RolledBack bool
	// Downtime is roughly how long DNS was unavailable, measured rather than
	// estimated, because the settings page promises "about a minute" and that
	// promise should be checkable.
	Downtime time.Duration
}

// ApplyCategories makes AdGuard subscribe to exactly the categories in wanted.
//
// It is called on ACTION, from the settings page, never from a tick. A restart
// takes the household's DNS down for the best part of a minute, and a
// background loop that could do that on its own schedule would be a worse
// thing than the problem it solves. See ADR 0010: AdGuard is reconciled on
// action; only curfew's own objects are reconciled continuously.
func ApplyCategories(r Runner, probe Prober, configPath string, wanted []string,
	restartTimeout time.Duration) (ApplyReport, error) {

	report := ApplyReport{}
	current, err := r.Run("cat " + configPath)
	if err != nil {
		return report, fmt.Errorf("reading %s: %w", configPath, err)
	}
	before := ConfiguredCategories(current)
	updated, changed, err := SetCategories(current, wanted)
	if err != nil {
		return report, err
	}
	if !changed {
		return report, nil
	}
	report.Changed = true
	report.Added, report.Removed = diffCategories(before, ConfiguredCategories(updated))

	// The backup FIRST, and verified, because everything after this point can
	// fail and the rollback is only as good as this copy.
	if _, err := r.Run(fmt.Sprintf("cp %s %s%s", configPath, configPath, backupSuffix)); err != nil {
		return report, fmt.Errorf("backing up %s: %w", configPath, err)
	}
	if out, err := r.Run(fmt.Sprintf("cmp -s %s %s%s && echo same", configPath, configPath,
		backupSuffix)); err != nil || strings.TrimSpace(out) != "same" {
		return report, fmt.Errorf("the backup of %s does not match the original, so curfew "+
			"will not edit it", configPath)
	}

	// Stopped before the write, so AdGuard cannot rewrite the file underneath
	// the edit, and so the engine is built ONCE from the new config rather
	// than rebuilt on top of the old one. Avoiding that rebuild is the whole
	// reason this path exists; see categories.go.
	started := time.Now()
	if _, err := r.Run("/etc/init.d/adguardhome stop"); err != nil {
		return report, fmt.Errorf("stopping AdGuard: %w", err)
	}
	if err := writeFile(r, configPath, updated); err != nil {
		// Nothing was changed yet, but AdGuard is down, so it must come back.
		_, _ = r.Run("/etc/init.d/adguardhome start")
		return report, fmt.Errorf("writing %s: %w", configPath, err)
	}
	if _, err := r.Run("/etc/init.d/adguardhome start"); err != nil {
		return report, fmt.Errorf("starting AdGuard: %w", err)
	}

	if waitServing(probe, restartTimeout) {
		report.Downtime = time.Since(started)
		return report, nil
	}

	// It did not come back. Put the household's resolver back exactly as it
	// was, and say so loudly rather than leaving a page that claims success.
	report.RolledBack = true
	_, _ = r.Run("/etc/init.d/adguardhome stop")
	if _, err := r.Run(fmt.Sprintf("cp %s%s %s", configPath, backupSuffix, configPath)); err != nil {
		return report, fmt.Errorf("AdGuard did not come back after the change, AND the "+
			"previous config could not be restored: %w\n"+
			"       Fix this by hand NOW: cp %s%s %s && /etc/init.d/adguardhome restart",
			err, configPath, backupSuffix, configPath)
	}
	if _, err := r.Run("/etc/init.d/adguardhome start"); err != nil {
		return report, fmt.Errorf("AdGuard did not come back after the change, and restarting "+
			"it with the restored config also failed: %w", err)
	}
	report.Downtime = time.Since(started)
	if !waitServing(probe, restartTimeout) {
		return report, fmt.Errorf("AdGuard did not come back after the change, the previous " +
			"config was restored, and it is STILL not answering DNS. The household has no " +
			"resolver: check /etc/init.d/adguardhome status and logread")
	}
	return report, fmt.Errorf("AdGuard did not come back within %s after the change, so the "+
		"previous config was restored and it is serving again. Nothing was changed",
		restartTimeout)
}

// waitServing polls until DNS answers again, or the deadline passes.
//
// It polls the RESOLVER, not the admin API. Measured in the DNS-path tests:
// AdGuard serves its API about two seconds after starting and binds :53 up to
// forty-three seconds later on a real router, so waiting for the API would
// declare success while the house still had no DNS.
func waitServing(probe Prober, timeout time.Duration) bool {
	if probe == nil {
		return true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if probe.Serving() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// writeFile puts content at path through the runner, using a here-document so
// the content never has to survive shell quoting.
func writeFile(r Runner, path, content string) error {
	const marker = "CURFEW_ADGUARD_EOF"
	if strings.Contains(content, "\n"+marker) {
		return fmt.Errorf("the config contains this function's own delimiter")
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	_, err := r.Run(fmt.Sprintf("cat > %s <<'%s'\n%s%s\n", path, marker, content, marker))
	return err
}

func diffCategories(before, after []string) (added, removed []string) {
	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}
	for _, c := range after {
		if !has(before, c) {
			added = append(added, c)
		}
	}
	for _, c := range before {
		if !has(after, c) {
			removed = append(removed, c)
		}
	}
	return added, removed
}
