// Package dhcplock serialises every curfew write to OpenWrt's dhcp config.
//
// Two curfew writers stage and commit `dhcp`: the daemon's pin transaction
// (internal/leases.Apply, every tick) and the install-time DNS takeover
// (internal/deploy, moving dnsmasq to port 54 and rolling it back to 53).
// Nothing used to stop them interleaving, and the bad interleaving is an
// outage, not a glitch: if the takeover commits port=54 between the daemon's
// backup of /etc/config/dhcp and its rollback, the rollback restores dnsmasq
// to 53 while AdGuard holds 53. And uci's staging area is shared between
// processes (measured: one process's `uci commit dhcp` committed another's
// staged change), so either can commit the other's half-built change.
//
// The lock is one file, Path, held with flock(2). It is taken THROUGH the
// Runner, as a shell command on the router, because one of the writers runs
// on a laptop over ssh and must hold the lock across several separate remote
// commands. OpenWrt's busybox flock has no -w and no way to hold a lock past
// the command it runs, so a small background holder process owns it: it
// takes the lock, says so through a FIFO, and then sleeps for at most MaxHold.
// Releasing kills it. If the caller dies (an ssh connection dropping, a
// daemon crashing) the holder still expires after MaxHold, so a lost caller
// can never wedge every later pass.
//
// Measured in the test image (work/notes/findings/uci-staging-is-shared-and-flock-serialises-curfew-dhcp-writes.md):
// flock(1), OpenWrt's lock(1) and a Go flock(2) on the same file all exclude
// each other, so a future in-process holder would interoperate with this one.
package dhcplock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Path is the lock file every curfew writer of the dhcp config takes.
const Path = "/var/lock/curfew-dhcp"

// MaxHold bounds how long a holder can keep the lock if its caller vanishes.
// Every holder releases far sooner: a pin transaction including a rollback is
// a few seconds, a dnsmasq move a few more.
const MaxHold = 120 * time.Second

// ErrBusy is returned when another curfew writer held the lock for the whole
// wait. It is an ordinary outcome, not a fault: the caller tries again later.
var ErrBusy = errors.New("another curfew process is changing the DHCP config right now")

// Runner executes a shell command on the router.
type Runner interface {
	Run(cmd string) (string, error)
}

// Release gives the lock back. It is safe to call more than once.
type Release func()

// Acquire takes the lock, waiting up to wait (rounded up to whole seconds,
// because busybox sleep has no fractions) for another holder to finish.
func Acquire(r Runner, wait time.Duration) (Release, error) {
	return acquireAt(r, Path, wait, MaxHold)
}

func acquireAt(r Runner, path string, wait, maxHold time.Duration) (Release, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	pidFile := fmt.Sprintf("%s.%s.pid", path, token)
	fifo := fmt.Sprintf("%s.%s.fifo", path, token)
	waitSecs := int((wait + time.Second - 1) / time.Second)
	holdSecs := int((maxHold + time.Second - 1) / time.Second)
	dir := path[:strings.LastIndex(path, "/")]

	// The holder: try every second for waitSecs, then either record its pid
	// and become a bounded sleep (fd 9 stays open across the exec, so the lock
	// is held exactly as long as that sleep lives), or report busy. Either way
	// it writes ONE line into the FIFO, which is what the foreground waits on.
	holder := fmt.Sprintf(`command -v flock >/dev/null || { echo noflock > %[2]s; exit 0; }; `+
		`i=0; until flock -n 9; do i=$((i+1)); if [ "$i" -gt %[1]d ]; then echo busy > %[2]s; exit 0; fi; sleep 1; done; `+
		`echo $$ > %[3]s; echo held > %[2]s; exec sleep %[4]d`,
		waitSecs, fifo, pidFile, holdSecs)
	// OpenWrt's busybox has no `timeout`, so a watchdog writes "timeout" into
	// the FIFO if the holder never answers (it could not even start). Without
	// it the read below would block for ever and wedge the caller. It is
	// killed as soon as the read returns, and takes its sleep with it, so a
	// pass leaves no stray process behind.
	script := fmt.Sprintf(`mkdir -p %[1]s && rm -f %[2]s && mkfifo %[2]s && `+
		`{ sh -c '%[3]s' 9>>%[4]s </dev/null >/dev/null 2>&1 & } && `+
		`{ sh -c 'sleep %[5]d & s=$!; trap "kill $s; exit 0" TERM; wait $s; [ -p %[2]s ] && echo timeout > %[2]s' </dev/null >/dev/null 2>&1 & w=$!; } && `+
		`read l < %[2]s; kill $w 2>/dev/null; rm -f %[2]s; echo "lock:$l"`,
		dir, fifo, holder, path, waitSecs+10)

	out, err := r.Run(script)
	if err != nil {
		return nil, fmt.Errorf("taking the DHCP config lock %s: %w", path, err)
	}
	switch strings.TrimSpace(out) {
	case "lock:held":
	case "lock:busy":
		return nil, ErrBusy
	case "lock:noflock":
		return nil, fmt.Errorf("taking the DHCP config lock %s: the router has no flock command, "+
			"so curfew cannot serialise its DHCP writes and writes nothing", path)
	default:
		// Not "busy": something stopped the holder from reporting at all, so
		// whether the lock is held is unknown. Release defensively and refuse,
		// rather than write a config nothing serialises.
		releaseAt(r, pidFile)
		return nil, fmt.Errorf("taking the DHCP config lock %s: no answer from the lock holder "+
			"(got %q); is flock available on the router?", path, strings.TrimSpace(out))
	}
	done := false
	return func() {
		if done {
			return
		}
		done = true
		releaseAt(r, pidFile)
	}, nil
}

// releaseAt kills the holder recorded in pidFile. It checks the pid still
// belongs to a sleep before killing it, so a holder that already expired
// cannot cost an unrelated process that reused its pid.
func releaseAt(r Runner, pidFile string) {
	_, _ = r.Run(fmt.Sprintf(`p=$(cat %s 2>/dev/null) && grep -q sleep /proc/$p/cmdline 2>/dev/null && kill $p; rm -f %s; true`,
		pidFile, pidFile))
}

func newToken() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("making a lock token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
