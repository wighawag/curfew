---
title: Serialise every curfew write to the DHCP config with one lock, measured first
slug: serialise-dhcp-commits-with-one-lock
spec: local-dns-names-for-a-device
blockedBy: []
covers: [21, 22]
---

## What to build

The daemon's pin transaction (`leases.Apply`: backup `/etc/config/dhcp`, stage, `uci commit dhcp`, reload, liveness check, rollback from the backup) and the install-time DNS takeover (`moveDnsmasqTo54` and `restoreDnsmasqTo53` in the deploy package) both stage and commit `dhcp` with nothing serialising them. If the takeover commits `port=54` between the daemon's backup and its rollback, the rollback restores dnsmasq to 53 while AdGuard holds 53. uci's staging area may also be shared between processes, so one writer's commit can sweep up the other's half-staged change. Fix it before local DNS names add more writes through the same path (design-notes Decision 7).

1. MEASURE in the test image and record the answers as a finding: does process B's `uci commit dhcp` commit changes process A staged but did not commit; does uci lock the file during commit; do OpenWrt's `lock` command and a Go `flock()` on the same file exclude each other.
2. One lock file, `/var/lock/curfew-dhcp`. The daemon's DHCP transaction TRY-locks it and holds it from the backup through any rollback; when busy it skips the pass, logs that it did, and retries on the next tick. The takeover holds it (waiting, with a timeout and a clear message) only around moving dnsmasq to 54 and around restoring it to 53, never across AdGuard's bind wait.
3. If step 1 shows the staging area is shared, the daemon also stages in a private savedir (`uci -P`) so its changes cannot be swept up by anything outside the lock.

## Acceptance criteria

- [x] A finding under `work/notes/findings/` records the three measurements with a `source:`.
- [x] A real race in the image: a daemon pass held open between its backup and a forced rollback while the takeover's move runs; afterwards `/etc/config/dhcp` has `port=54`, everything the daemon wrote that was not rolled back, and dnsmasq is running. The test fails with the lock removed.
- [x] The daemon skipping a pass on a busy lock is a logged, non-fatal outcome with a unit test.
- [x] `moveDnsmasqTo54` and `restoreDnsmasqTo53` leave every `address` and `server` list entry in `dhcp.@dnsmasq[0]` byte-for-byte unchanged (real uci test).
- [x] Tests use the container's own uci and temp lock paths where possible; nothing touches a live router.

## Blocked by

- None. Can start immediately.

## Prompt

Goal: make every curfew write to OpenWrt's `dhcp` config mutually exclusive, so the daemon's pin transaction and the install-time DNS takeover cannot interleave. Read `docs/spikes/local-dns-names/design-notes.md` (Decision 7), ADR 0010 ("A running AdGuard is not a filtering AdGuard"), ADR 0012, and `internal/leases` (Apply, rollbackDHCP) plus `internal/deploy/adguard_dns.go` (takeOverDNS, moveDnsmasqTo54, restoreDnsmasqTo53, rollback). The takeover runs from the laptop over ssh through a `Runner`, so its side of the lock is a shell command on the router (`lock` is OpenWrt's locking utility; check it exists in the image); the daemon side runs on the router and may use the same command or a Go flock, but only once step 1 proves they interoperate. Measure before designing on it (ADR 0004 spirit: assert on the real thing). Tests run in the real OpenWrt image via `docker/acceptance.sh`; add any new acceptance binary there. Done = the finding, the lock in both writers, the race test failing without the lock and passing with it, and verify green.

## Decisions (made while building, 2026-11-18)

- **The lock is held by a background `flock(1)` holder, not by OpenWrt's `lock(1)` and not by an in-process Go flock.** The takeover runs on the laptop and must hold the lock across several separate ssh commands, so the holder has to live on the router. `lock(1)` would do that but never expires: a caller that dies before `lock -u` wedges every later pass until reboot (measured). BusyBox `flock` has no `-w` and no way to outlive its child, so `internal/dhcplock` starts a holder that takes the lock, reports through a FIFO, and becomes a `sleep` of at most `MaxHold` (120s). Release kills it after checking the pid is still a sleep. One implementation serves the daemon (local shell) and the laptop (ssh) alike.
- **The daemon waits up to 10s (`leases.ApplyLockWait`) rather than a pure try-lock**, then skips the pass with a distinct "skipped, next pass tries again" warning. A takeover's stage-commit-restart is a few seconds, so a short wait usually avoids losing a tick at all; a busy lock still never stalls the daemon for long.
- **The takeover waits up to 60s and, if it cannot get the lock, changes nothing and does not roll back.** `takeOverDNS` used to roll back on any `moveDnsmasqTo54` error; with no move made, that rollback would have rewritten the DHCP options from nothing. A lock failure is a distinct error type for exactly that reason.
- **The daemon stages in a private save path (`leases.StageDir`, `uci -t`) and clears it first**, because the default staging area is shared (measured). `uci -P` was measured to commit nothing and is not used.
- Evidence: `work/notes/findings/uci-staging-is-shared-and-flock-serialises-curfew-dhcp-writes.md`; race test `internal/deploy/dhcplock_race_test.go` (passes with the lock, and its control fails with the takeover's lock removed).
- The verify gate's image could not be rebuilt today (the build container had no network: `wget` exit 4), so acceptance ran the same binaries in the existing `localhost/docker_test` image (built 2026-10-23, after the last Dockerfile change). A pre-existing dnspolicy flake was seen twice and recorded as an update to `work/notes/observations/one-unreproduced-dnspolicy-acceptance-failure-before-v0-9-3.md`.
