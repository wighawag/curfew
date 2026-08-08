package adguard

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// scriptRunner is a router that really holds a file and really has a service
// that is either up or down. It reproduces none of the decision logic under
// test: it does not know what a category is, and it cannot tell a good config
// from a bad one except through the rule the test gives it.
type scriptRunner struct {
	files   map[string]string
	running bool
	cmds    []string
	// requires makes the service fail to come up unless the config contains
	// this string, which is how a real AdGuard rejecting a config presents
	// itself: procd starts it, it exits, and nothing serves DNS.
	requires string
	failOn   string
	err      error
}

func newRunner(config string) *scriptRunner {
	return &scriptRunner{
		files:   map[string]string{ConfigPath: config},
		running: true,
	}
}

func (s *scriptRunner) Run(cmd string) (string, error) {
	s.cmds = append(s.cmds, cmd)
	if s.failOn != "" && strings.Contains(cmd, s.failOn) {
		return "", s.err
	}
	switch {
	case strings.HasPrefix(cmd, "cat > "):
		path := strings.Fields(strings.TrimPrefix(cmd, "cat > "))[0]
		_, body, _ := strings.Cut(cmd, "\n")
		body = strings.TrimSuffix(body, "CURFEW_ADGUARD_EOF\n")
		s.files[path] = body
		return "", nil
	case strings.HasPrefix(cmd, "cat "):
		path := strings.TrimSpace(strings.TrimPrefix(cmd, "cat "))
		body, ok := s.files[path]
		if !ok {
			return "", errors.New("no such file")
		}
		return body, nil
	case strings.HasPrefix(cmd, "cp "):
		f := strings.Fields(cmd)
		s.files[f[2]] = s.files[f[1]]
		return "", nil
	case strings.HasPrefix(cmd, "cmp -s "):
		f := strings.Fields(cmd)
		if s.files[f[2]] == s.files[f[3]] {
			return "same\n", nil
		}
		return "", nil
	case strings.Contains(cmd, "adguardhome stop"):
		s.running = false
		return "", nil
	case strings.Contains(cmd, "adguardhome start"):
		s.running = s.requires == "" || strings.Contains(s.files[ConfigPath], s.requires)
		return "", nil
	}
	return "", nil
}

// Serving reports what the fake service is doing, which is what the real
// prober asks of a real resolver.
func (s *scriptRunner) Serving() bool { return s.running }

func apply(t *testing.T, r *scriptRunner, wanted ...string) (ApplyReport, error) {
	t.Helper()
	return ApplyCategories(r, r, ConfigPath, wanted, 50*time.Millisecond)
}

func TestApplyingACategoryChangeRestartsAdGuardAndLeavesItServing(t *testing.T) {
	r := newRunner(liveConfig)
	report, err := apply(t, r, "Gambling", "Porn", "Ads")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed || len(report.Removed) != 1 || report.Removed[0] != "Malware" {
		t.Errorf("the report does not say what happened: %+v", report)
	}
	if strings.Contains(r.files[ConfigPath], "malware-ags.txt") {
		t.Error("the config still subscribes to the removed list")
	}
	if !r.Serving() {
		t.Error("AdGuard was left down")
	}
	// Stopped BEFORE the write and started after: that ordering is what makes
	// the engine build once, cold, instead of being rebuilt on top of itself.
	order := strings.Join(r.cmds, "\n")
	stop := strings.Index(order, "adguardhome stop")
	write := strings.Index(order, "cat > ")
	start := strings.Index(order, "adguardhome start")
	if !(stop < write && write < start) {
		t.Errorf("wrong order (stop=%d write=%d start=%d):\n%s", stop, write, start, order)
	}
	// A backup exists, and it is the config as it was.
	if got := r.files[ConfigPath+backupSuffix]; !strings.Contains(got, "malware-ags.txt") {
		t.Error("no usable backup was taken before the edit")
	}
}

// The rollback, which is the whole reason this is not three lines of shell.
func TestAConfigAdGuardRefusesIsRolledBackAndTheHouseholdKeepsItsDNS(t *testing.T) {
	r := newRunner(liveConfig)
	r.requires = "porn-ags" // it dies unless that list is present, whatever the reason
	report, err := apply(t, r, "Gambling", "Ads")
	if err == nil {
		t.Fatal("AdGuard failed to come back and the caller was told everything was fine")
	}
	if !report.RolledBack {
		t.Errorf("the report does not say it rolled back: %+v", report)
	}
	if !strings.Contains(r.files[ConfigPath], "porn-ags.txt") {
		t.Errorf("the previous config was not restored:\n%s", r.files[ConfigPath])
	}
	if !r.Serving() {
		t.Error("the household was left with no resolver")
	}
	if !strings.Contains(err.Error(), "Nothing was changed") {
		t.Errorf("the error does not say the change was abandoned: %v", err)
	}
}

// Failing to restore is the worst case there is, and it must be unmistakable
// and carry the command a person can run.
func TestAFailedRollbackSaysExactlyWhatToTypeToFixIt(t *testing.T) {
	r := newRunner(liveConfig)
	r.requires = "porn-ags"
	r.failOn = "cp " + ConfigPath + backupSuffix
	r.err = errors.New("read-only file system")
	_, err := apply(t, r, "Gambling", "Ads")
	if err == nil {
		t.Fatal("a failed rollback was reported as success")
	}
	if !strings.Contains(err.Error(), "cp "+ConfigPath+backupSuffix) {
		t.Errorf("the error does not carry the manual fix: %v", err)
	}
}

// Nothing to do must touch nothing at all: no backup, no write, and above all
// no restart. A save that changes nothing must not cost the house its DNS.
func TestNoChangeMeansNoRestart(t *testing.T) {
	r := newRunner(liveConfig)
	report, err := apply(t, r, "Ads", "Gambling", "Malware", "Porn")
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed {
		t.Error("an identical set of categories was reported as a change")
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "stop") || strings.Contains(c, "start") || strings.HasPrefix(c, "cat > ") {
			t.Errorf("a no-op save touched the router: %v", r.cmds)
			break
		}
	}
}

// A refused edit must never reach the file, and must never stop the service.
func TestARefusedEditNeverTouchesTheRunningService(t *testing.T) {
	r := newRunner(liveConfig)
	if _, err := apply(t, r, "Cats"); err == nil {
		t.Fatal("an unknown category was applied")
	}
	if !r.Serving() {
		t.Error("a refused edit stopped AdGuard")
	}
	if r.files[ConfigPath] != liveConfig {
		t.Error("a refused edit changed the config anyway")
	}
}

// The config is written through a here-document, so a name or URL containing
// shell metacharacters cannot become a command.
func TestTheConfigIsWrittenWithoutGoingThroughShellQuoting(t *testing.T) {
	r := newRunner(strings.Replace(liveConfig,
		"name: 'curfew (managed: do not edit)'",
		"name: '$(touch /tmp/pwned) `id` \"quoted\"'", 1))
	if _, err := apply(t, r, "Gambling", "Porn", "Ads"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.files[ConfigPath], "$(touch /tmp/pwned)") {
		t.Errorf("the awkward name did not survive the write:\n%s", r.files[ConfigPath])
	}
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "cat > ") && !strings.Contains(c, "<<'CURFEW_ADGUARD_EOF'") {
			t.Error("the config was written without a quoted here-document")
		}
	}
}
