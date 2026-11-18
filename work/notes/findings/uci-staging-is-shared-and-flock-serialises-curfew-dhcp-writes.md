---
title: uci's staging area is shared between processes, uci -P commits nothing, and flock(1), lock(1) and Go flock(2) all exclude each other
slug: uci-staging-is-shared-and-flock-serialises-curfew-dhcp-writes
source: 'measured 2026-11-18 in the test image (openwrt/rootfs x86-64-25.12.4, BusyBox v1.37.0); script and full output in docs/spikes/serialise-dhcp-commits-with-one-lock/ (measure.sh, goflock.go, measured-2026-11-18.txt). Tool availability also read off the live router (OpenWrt 25.12.5) the same day: /bin/lock, /usr/bin/flock (busybox) and /usr/bin/mkfifo present, no timeout, no usleep.'
---

# uci staging, uci commit, and file locks on OpenWrt 25.12

Ground truth behind `internal/dhcplock` and `leases.StageDir`.

## uci

- **The default staging area (`/tmp/.uci`) is shared between processes.** Process A ran `uci set dhcp.lan.curfewa=1` and exited without committing; process B ran `uci set dhcp.lan.curfewb=1; uci commit dhcp`. Both options were committed. So anybody's commit commits everybody's staged changes. The live router had a `/tmp/.uci/dhcp` file present at the time.
- **`uci -t <dir>` (private save path) is invisible to everyone else**: a plain `uci commit dhcp` did not commit a change staged with `-t`, and a plain `uci get` did not see it, while `uci -t <dir> get` did.
- **But committing with `-t` ALSO commits what others staged in the default area** (a default-staged option was committed by `uci -t <dir> commit dhcp`). A private save path protects your staged changes from others, not others' from you.
- **`uci -P <dir>` must not be used for writes**: after `uci -P <dir> set …` the change sat in `<dir>/dhcp`, and `uci -P <dir> commit dhcp` exited 0 and committed NOTHING (neither its own change nor a default-staged one).
- **uci serialises concurrent commits itself**: two writers, each with its own `-t` save path, each set-and-committed 60 distinct options in parallel; all 120 options were in the file afterwards. Evidence that the commit is atomic per call, not proof.

## Locks

- OpenWrt 25.12 has `flock` as a BusyBox applet: `flock [-sxun] FD | { FILE [-c] PROG ARGS }`, so **no `-w` timeout**, and it holds a lock only while its child runs. There is **no `timeout` and no `usleep`**, and `sleep` takes whole seconds only (`sleep 0.3` is "invalid number").
- **flock(1), OpenWrt's `lock(1)` and a Go `syscall.Flock(LOCK_EX|LOCK_NB)` on the same file all exclude each other**, in every direction tried.
- **`lock(1)` leaves a background holder process after its caller exits** (`lock /var/lock/x` returned, and `ps` still showed `lock /var/lock/x` holding it until `lock -u`). A caller that dies before `lock -u` leaves the lock held until reboot.
- **A Go flock is released when its process dies** (killed holder, next try acquired).
- `/var/lock` exists on the router (procd creates it at boot) but not in the container, so code must `mkdir -p` it.
