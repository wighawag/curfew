package dhcplock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/shellrun"
)

// These run the REAL lock: a real shell, real flock(1), a real FIFO and a real
// flock(2) from Go as the independent observer. A fake runner would only
// prove that the script text looks like a lock.

func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"flock", "mkfifo"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s here; run this in the test image", tool)
		}
	}
}

func lockPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "curfew-dhcp")
}

// heldByAnyone asks the kernel directly, from Go, whether the file is locked.
func heldByAnyone(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

func TestALockIsHeldUntilReleasedAndExcludesASecondWriter(t *testing.T) {
	requireTools(t)
	path := lockPath(t)
	r := shellrun.Local{}

	// Baseline: nobody holds it, so the observer is not just always saying yes.
	if heldByAnyone(t, path) {
		t.Fatal("the lock file is held before anything took it")
	}
	release, err := acquireAt(r, path, 0, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !heldByAnyone(t, path) {
		t.Fatal("Acquire returned but the kernel says nobody holds the lock")
	}
	if _, err := acquireAt(r, path, 0, 30*time.Second); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second writer got in while the lock was held: %v", err)
	}
	release()
	deadline := time.Now().Add(3 * time.Second)
	for heldByAnyone(t, path) {
		if time.Now().After(deadline) {
			t.Fatal("the lock was still held after release")
		}
		time.Sleep(50 * time.Millisecond)
	}
	again, err := acquireAt(r, path, 0, 30*time.Second)
	if err != nil {
		t.Fatalf("the lock could not be taken again after release: %v", err)
	}
	again()
	release() // a second release is harmless
}

func TestAWaitingWriterGetsTheLockOnceItIsReleased(t *testing.T) {
	requireTools(t)
	path := lockPath(t)
	r := shellrun.Local{}
	first, err := acquireAt(r, path, 0, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		first()
	}()
	start := time.Now()
	second, err := acquireAt(r, path, 5*time.Second, 30*time.Second)
	if err != nil {
		t.Fatalf("a writer willing to wait 5s did not get a lock released after 1.5s: %v", err)
	}
	defer second()
	if time.Since(start) < time.Second {
		t.Errorf("the second writer got the lock after %s, before the first released it", time.Since(start))
	}
}

// A caller that vanishes (ssh dropped, daemon killed) must not wedge every
// later writer: the holder expires on its own.
func TestALockWhoseCallerVanishedExpires(t *testing.T) {
	requireTools(t)
	path := lockPath(t)
	r := shellrun.Local{}
	if _, err := acquireAt(r, path, 0, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// Never released.
	if !heldByAnyone(t, path) {
		t.Fatal("not held right after acquiring")
	}
	deadline := time.Now().Add(6 * time.Second)
	for heldByAnyone(t, path) {
		if time.Now().After(deadline) {
			t.Fatal("an abandoned lock never expired, so it would block every later pass")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A runner that answers nothing (no flock on the router, a broken shell)
// must be a refusal, never a write nothing serialises.
func TestNoAnswerFromTheHolderIsAnErrorNotALock(t *testing.T) {
	_, err := acquireAt(silentRunner{}, "/tmp/curfew-dhcp-never", 0, time.Second)
	if err == nil || errors.Is(err, ErrBusy) {
		t.Fatalf("an unanswered lock attempt must be an error, got %v", err)
	}
}

type silentRunner struct{}

func (silentRunner) Run(string) (string, error) { return "", nil }
