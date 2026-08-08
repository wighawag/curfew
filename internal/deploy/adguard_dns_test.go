package deploy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests for the step that can take a household's DNS away.
//
// Moving dnsmasq off port 53 is the only operation curfew performs that can
// leave a LAN with no resolver at all, so the rollback is the thing under test
// here rather than the happy path. The doubles are dumb: they replay router
// output and record commands, and know nothing about AdGuard.

// scriptedRunner answers commands from a table and records what it was asked.
type scriptedRunner struct {
	answers map[string]string
	fail    map[string]error
	ran     []string
}

func (s *scriptedRunner) Run(cmd string) (string, error) {
	s.ran = append(s.ran, cmd)
	for pattern, err := range s.fail {
		if strings.Contains(cmd, pattern) {
			return "", err
		}
	}
	for pattern, out := range s.answers {
		if strings.Contains(cmd, pattern) {
			return out, nil
		}
	}
	return "", nil
}

func (s *scriptedRunner) Upload(string, string) error   { return nil }
func (s *scriptedRunner) Download(string, string) error { return nil }

func (s *scriptedRunner) didRun(sub string) bool {
	for _, c := range s.ran {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// The live router's exact state: dnsmasq on 53, so AdGuard cannot bind.
func newConflictedRouter() *scriptedRunner {
	return &scriptedRunner{answers: map[string]string{
		"uci get dhcp.@dnsmasq[0].port": "53\n",
		"netstat":                       "tcp 0 0 192.168.1.1:53 0.0.0.0:* LISTEN 3872/dnsmasq\n",
	}}
}

func TestAConflictOnPortFiftyThreeIsDetected(t *testing.T) {
	r := newConflictedRouter()
	holder, err := portFiftyThreeHolder(r)
	if err != nil {
		t.Fatal(err)
	}
	if holder != "dnsmasq" {
		t.Errorf("holder = %q, want dnsmasq", holder)
	}
	serving, err := adGuardServesDNS(r)
	if err != nil {
		t.Fatal(err)
	}
	if serving {
		t.Error("dnsmasq holding port 53 must NOT read as AdGuard serving DNS")
	}
}

// The exact failure from the live router, as a test: AdGuard never takes over
// port 53, so dnsmasq must be put back and the household keeps a resolver.
func TestWhenAdGuardCannotTakePortFiftyThreeDnsmasqIsPutBack(t *testing.T) {
	r := newConflictedRouter()
	r.answers["logread"] = "[fatal] starting dns server: listen tcp 0.0.0.0:53: bind: address already in use\n"

	var report AdGuardReport
	err := takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1", DNSTimeout: 50 * time.Millisecond}, &report, false)
	if err == nil {
		t.Fatal("AdGuard never took port 53, so this must fail rather than report success")
	}
	if !report.MovedDnsmasq {
		t.Error("the report should record that dnsmasq was moved")
	}
	if !report.RolledBack {
		t.Error("the report must record the rollback")
	}
	if report.ServingDNS {
		t.Error("ServingDNS must be false when AdGuard never bound port 53")
	}
	// The household must have a resolver again.
	if !r.didRun("uci set dhcp.@dnsmasq[0].port=53") {
		t.Errorf("dnsmasq was not put back on port 53; the LAN would have NO DNS.\nran: %v", r.ran)
	}
	if !r.didRun("/etc/init.d/dnsmasq restart") {
		t.Error("dnsmasq was not restarted after the rollback")
	}
	// And the message must carry AdGuard's own reason, or the operator is left
	// guessing at exactly the moment they need to know.
	if !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("the error should quote AdGuard's fatal line, got: %v", err)
	}
	if !strings.Contains(err.Error(), "still works") {
		t.Errorf("the error should say DNS still works, got: %v", err)
	}
}

// A rollback that ITSELF fails is the worst case, and it must say so loudly
// with the manual fix, rather than being swallowed by the original error.
func TestAFailedRollbackSaysTheHouseholdMayHaveNoDNS(t *testing.T) {
	r := newConflictedRouter()
	r.fail = map[string]error{"uci set dhcp.@dnsmasq[0].port=53": errors.New("uci is broken")}

	var report AdGuardReport
	err := takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1", DNSTimeout: 50 * time.Millisecond}, &report, false)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "NO working DNS") {
		t.Errorf("a failed rollback must be unmistakable, got: %v", err)
	}
	// BOTH failures must survive into the message. Reporting only the original
	// cause would hide the fact that the recovery itself did not happen, which
	// is the difference between "not filtering" and "no internet".
	if !strings.Contains(err.Error(), "uci is broken") {
		t.Errorf("the rollback's own failure must be reported, got: %v", err)
	}
	if !strings.Contains(err.Error(), "uci set dhcp.@dnsmasq[0].port=53") {
		t.Errorf("the message must carry the manual fix, got: %v", err)
	}
}

// When AdGuard already owns port 53, nothing should be touched at all.
func TestWhenAdGuardAlreadyServesDNSNothingIsChanged(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{
		"pgrep AdGuardHome": "yes\n",
		"netstat":           "udp 0 0 0.0.0.0:53 0.0.0.0:* 5466/AdGuardHome\n",
	}}
	var report AdGuardReport
	if err := takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1", DNSTimeout: 50 * time.Millisecond}, &report, false); err != nil {
		t.Fatalf("takeOverDNS: %v", err)
	}
	if !report.ServingDNS {
		t.Error("AdGuard already holds port 53, so ServingDNS must be true")
	}
	if report.MovedDnsmasq {
		t.Error("nothing needed moving")
	}
	if r.didRun("uci set") {
		t.Errorf("an already-working setup was reconfigured anyway:\n%v", r.ran)
	}
}

// Something that is neither AdGuard nor dnsmasq holding port 53 is a refusal,
// not a fight. Stopping somebody else's resolver to install ours is not a
// decision this tool gets to make silently.
func TestAThirdPartyOnPortFiftyThreeIsRefused(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{
		"uci get dhcp.@dnsmasq[0].port": "54\n",
		"netstat":                       "udp 0 0 0.0.0.0:53 0.0.0.0:* 999/unbound\n",
	}}
	var report AdGuardReport
	err := takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1", DNSTimeout: 50 * time.Millisecond}, &report, false)
	if err == nil {
		t.Fatal("a third-party resolver on port 53 must be refused")
	}
	if !strings.Contains(err.Error(), "unbound") {
		t.Errorf("the error should name what is holding the port, got: %v", err)
	}
	if r.didRun("uci set") {
		t.Error("nothing should have been reconfigured")
	}
	// Refusing means refusing BEFORE acting. Restarting somebody's AdGuard and
	// then waiting out the timeout would disrupt a working router to reach the
	// same answer.
	// Checked against the restart COMMANDS rather than the binary name, since
	// a liveness probe legitimately mentions the process.
	if r.didRun("killall AdGuardHome") || r.didRun("init.d/adguardhome restart") {
		t.Errorf("AdGuard was restarted despite the refusal:\n%v", r.ran)
	}
}

// The boot-time gap found on the live router: an init script with no rc.d
// symlink, so AdGuard never comes back after a power cut.
func TestAnUnenabledServiceIsEnabled(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{"ls /etc/rc.d": "\n"}}
	enabled, err := ensureServiceEnabled(r)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Error("a service with no boot symlink must be enabled")
	}
	if !r.didRun("/etc/init.d/adguardhome enable") {
		t.Errorf("enable was never run:\n%v", r.ran)
	}

	already := &scriptedRunner{answers: map[string]string{
		"ls /etc/rc.d": "/etc/rc.d/S99adguardhome\n",
	}}
	enabled, err = ensureServiceEnabled(already)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Error("an already-enabled service must not be reported as newly enabled")
	}
	if already.didRun("enable") {
		t.Error("an already-enabled service must not be re-enabled")
	}
}

func TestDnsmasqIsOnlyMovedOnEvidence(t *testing.T) {
	// Listening on 53 right now: in the way.
	listening := &scriptedRunner{answers: map[string]string{
		"uci get": "\n",
		"netstat": "udp 0 0 192.168.1.1:53 0.0.0.0:* 3872/dnsmasq\n",
	}}
	if got, err := dnsmasqIsInTheWay(listening); err != nil || !got {
		t.Errorf("a dnsmasq listening on 53 is in the way; got %v err=%v", got, err)
	}
	// Configured for 53 but not currently listening: still in the way, because
	// it would take the port back at the next restart.
	configured := &scriptedRunner{answers: map[string]string{
		"uci get": "53\n", "netstat": "\n",
	}}
	if got, err := dnsmasqIsInTheWay(configured); err != nil || !got {
		t.Errorf("a dnsmasq configured for 53 is in the way; got %v err=%v", got, err)
	}
	// Running on another port, with uci silent: NOT in the way. This is the
	// case an earlier heuristic got wrong, reconfiguring a dnsmasq that was
	// deliberately somewhere else.
	elsewhere := &scriptedRunner{answers: map[string]string{
		"uci get": "\n", "netstat": "\n",
	}}
	if got, err := dnsmasqIsInTheWay(elsewhere); err != nil || got {
		t.Errorf("a dnsmasq that is not on 53 must be left alone; got %v err=%v", got, err)
	}
	// AdGuard already holding 53, uci silent: nothing to move.
	adguard := &scriptedRunner{answers: map[string]string{
		"uci get": "\n", "netstat": "udp 0 0 0.0.0.0:53 0.0.0.0:* 5466/AdGuardHome\n",
	}}
	if got, err := dnsmasqIsInTheWay(adguard); err != nil || got {
		t.Errorf("AdGuard already has the port; nothing to move. got %v err=%v", got, err)
	}
}

// The summary must never describe a non-filtering AdGuard as if it were
// working. This is the sentence a person reads and believes.
func TestTheSummaryNeverClaimsFilteringThatIsNotHappening(t *testing.T) {
	rolled := AdGuardReport{Adopted: true, SecuredNow: true, Version: "v0.107.78",
		MovedDnsmasq: true, RolledBack: true}
	if !strings.Contains(rolled.Summary(), "NOT filtering") {
		t.Errorf("a rolled-back run must say it is not filtering:\n%s", rolled.Summary())
	}
	notServing := AdGuardReport{Adopted: true, AlreadySecured: true, Version: "v0.107.78"}
	if !strings.Contains(notServing.Summary(), "NOT serving DNS") {
		t.Errorf("an AdGuard that is not on port 53 must say so:\n%s", notServing.Summary())
	}
	working := AdGuardReport{Adopted: true, SecuredNow: true, Version: "v0.107.78",
		ServingDNS: true, MovedDnsmasq: true}
	if !strings.Contains(working.Summary(), "owns DNS on port 53") {
		t.Errorf("a working run should say so:\n%s", working.Summary())
	}
}

// The exact state the live router was in when this was found, and the one the
// previous version could not recover from: AdGuard STOPPED (which is what a
// crash loop procd has given up on looks like), dnsmasq holding port 53, and
// the config already carrying an admin account so nothing prompts a restart.
//
// The old ordering verified the admin API first, found nothing listening, and
// gave up before it ever freed the port or started anything.
func TestAStoppedAdGuardBehindDnsmasqIsStartedNotGivenUpOn(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{
		"pgrep AdGuardHome":             "no\n",
		"uci get dhcp.@dnsmasq[0].port": "53\n",
		"netstat":                       "tcp 0 0 192.168.1.1:53 0.0.0.0:* LISTEN 3872/dnsmasq\n",
	}}
	var report AdGuardReport
	// It still fails here, because this dumb double never reports AdGuard
	// taking the port. What matters is WHAT IT TRIED before failing.
	err := takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1",
		DNSTimeout: 50 * time.Millisecond}, &report, false)
	if err == nil {
		t.Fatal("the double never lets AdGuard take port 53, so this must fail")
	}
	if !r.didRun("uci set dhcp.@dnsmasq[0].port=54") {
		t.Errorf("port 53 was never freed for AdGuard:\n%v", r.ran)
	}
	if !r.didRun("adguardhome") && !r.didRun("AdGuardHome -c") {
		t.Errorf("AdGuard was never started:\n%v", r.ran)
	}
	// And having failed, the household must still have a resolver.
	if !r.didRun("uci set dhcp.@dnsmasq[0].port=53") {
		t.Errorf("dnsmasq was not put back, so the LAN would have NO DNS:\n%v", r.ran)
	}
}

// A stopped AdGuard with the port already free must simply be started, without
// touching dnsmasq at all.
func TestAStoppedAdGuardWithAFreePortIsJustStarted(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{
		"pgrep AdGuardHome":             "no\n",
		"uci get dhcp.@dnsmasq[0].port": "54\n",
		"netstat":                       "\n",
	}}
	var report AdGuardReport
	_ = takeOverDNS(r, AdGuardOptions{RouterIP: "192.168.1.1",
		DNSTimeout: 50 * time.Millisecond}, &report, false)
	if r.didRun("uci set") {
		t.Errorf("dnsmasq was reconfigured despite port 53 being free:\n%v", r.ran)
	}
	if !r.didRun("adguardhome") && !r.didRun("AdGuardHome -c") {
		t.Errorf("AdGuard was never started:\n%v", r.ran)
	}
}

// Sequencing test for adoption itself, not just for its parts.
//
// Without this, removing the DNS takeover from adoption entirely still passed
// every test in this file, because they all drive takeOverDNS directly. The
// packet-path tests would have caught it, but only in the container, and a
// wiring mistake deserves to fail in seconds.
func TestAdoptionFreesPortFiftyThreeBeforeVerifyingAnything(t *testing.T) {
	r := &scriptedRunner{answers: map[string]string{
		"cat /opt/AdGuardHome/adguardhome.yaml": "http:\n  address: 0.0.0.0:3000\n" +
			"users:\n- name: someone\n  password: $2a$10$x\ndns:\n  port: 53\n",
		"pgrep AdGuardHome":             "no\n",
		"uci get dhcp.@dnsmasq[0].port": "53\n",
		"netstat":                       "tcp 0 0 192.168.1.1:53 0.0.0.0:* LISTEN 3872/dnsmasq\n",
		"ls /etc/rc.d":                  "\n",
	}}
	// Fails, because nothing real is listening for the verification step. The
	// assertions are about the ORDER of what it attempted.
	_, err := adoptAdGuard(r, AdGuardOptions{
		Enabled: true, User: "someone", Password: "theirs",
		RouterIP: "127.0.0.1", DNSTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want a failure: nothing is actually serving in this test")
	}
	if !r.didRun("uci set dhcp.@dnsmasq[0].port=54") {
		t.Errorf("adoption never tried to free port 53 for AdGuard:\n%v", r.ran)
	}
	if !r.didRun("/etc/init.d/adguardhome enable") {
		t.Errorf("adoption left AdGuard unable to start at boot:\n%v", r.ran)
	}
	if !r.didRun("uci set dhcp.@dnsmasq[0].port=53") {
		t.Errorf("adoption failed without restoring DNS for the household:\n%v", r.ran)
	}
}
