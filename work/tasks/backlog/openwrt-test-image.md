---
title: Run the test suite on a real OpenWrt image
slug: openwrt-test-image
spec: openwrt-packet-path-test-harness
blockedBy: []
covers: [4, 5, 8]
---

## What to build

Replace the Alpine test container with a real OpenWrt userland, so `uci`, `logger`, `nft`, busybox applet behaviour and `uhttpd` are the real things rather than mocks or stand-ins; give the container the capabilities the suite will need; and delete the mocks the real image makes redundant.

This is the whole vertical path for this task: the image builds, the container has what it needs, the suite runs on it, and the mocks are gone. The image swap and the mock deletion are deliberately ONE task. Splitting them would leave an intermediate state where the `uci` and `logger` shims shadow the real tools on the real image, which defeats the entire point of the swap.

This task owns the whole container definition, Dockerfile AND compose file. That boundary matters: the follow-on harness task needs `ip netns add`, which requires `CAP_SYS_ADMIN`, so leaving capabilities to that task would make this task's own acceptance unmeetable.

Constrained by `docs/adr/0005-test-environment-is-a-real-openwrt-image.md`, which records why the environment is a real image rather than a lookalike, and the accepted cost of deleting the mocks.

The recipe below is measured, not inferred. Each item was found by hitting the failure.

**Base image:** `openwrt/rootfs:x86-64-25.12.4`. The architecture difference from the aarch64 router is irrelevant for nftables semantics, shell behaviour and HTTP.

**Packages:** `apk add bash ip-full coreutils-nl coreutils-cksum nsenter`. Every one of these has a measured failure behind it; do not add others speculatively.

- `iproute2` is called **`ip-full`** on OpenWrt, and busybox `ip` is not sufficient (no `link add`, no `netns`).
- `bash` is required because bats is a bash program and OpenWrt ships only ash.
- `coreutils-nl` is required because bats calls `nl`, which busybox lacks. Without it bats reports `Executed 0 instead of expected N tests` while appearing to run.
- `coreutils-cksum` is required by the AdGuard tests, which derive filter IDs with `cksum`.
- `nsenter` is needed by the follow-on harness task.

Nothing else needs installing for the harness: the base image already has `/usr/sbin/uhttpd` (to serve a page) and busybox `wget` (to fetch one), which is what the follow-on task's topology uses.

**Capabilities and sysctl, in `docker/docker-compose.yml`, on BOTH the `test` and `shell` services:** add `SYS_ADMIN` and `NET_RAW` to the existing `cap_add`, and add `sysctls: net.ipv4.ip_forward=1`. `--privileged` is NOT required. `podman compose` has been confirmed to honour the `sysctls:` key. `SYS_ADMIN` is what makes `ip netns add` work (measured: with `NET_ADMIN` alone it fails on the bind-mount with a permission error), and the sysctl is what makes the topology forward at all.

**bats is NOT packaged for OpenWrt.** Fetch `bats-core` **v1.11.0** from its GitHub release tarball during the image build, extract to a fixed path, and symlink `bin/bats` onto `PATH` so the existing compose command (`bats test/`) keeps working unchanged. Do NOT run bats' own `install.sh`: it fails with `install: command not found`, because OpenWrt has no coreutils `install`. Pin the version and prefer a checksum, so an upstream change cannot break the gate with no commit in this repo. Fetching at build time is deliberate: committing several dozen third-party files into this repo is a worse review burden than a pinned download.

**`mkdir -p /var/run` in the image.** On OpenWrt `/var/run` symlinks to `/tmp/run`, which procd creates at boot, so it does not exist in a container. Without it `ip netns add` fails, which the follow-on task depends on.

**Delete, because the real image supersedes them:** the `uci` and `logger` shim scripts in the Dockerfile; `docker/mock-iptables.sh` (the FILE, not just its `COPY` line); the two iptables-backend test cases; the iptables branches inside the shared test helpers; and the inline iptables branch in the profiles test file that reads the mock's state file. Also delete the commented-out QEMU "real OpenWrt testing" service in the compose file, which is obsolete once the base image IS OpenWrt.

Removing the iptables mock is a CHOICE, not a forced consequence, and worth understanding before doing it: the mock is plain POSIX shell and would survive the image swap fine. It goes because the iptables backend is dead code that a later spec deletes, and keeping a mock alive for a backend nobody runs is not worth the weight. The accepted cost is that the iptables code path in the profile script loses its only coverage until that later spec lands.

**Do NOT delete the shared test helpers wholesale.** That file also holds `reset_mocks`, `assert_mac_blocked` and `assert_mac_not_blocked`, which are load-bearing. Only the iptables branches go. It additionally holds two dead `assert_websites_*` helpers whose set name has never matched the real `blocked_sites_<profile>_<rule>` naming, which are safe to remove.

## Acceptance criteria

- [ ] The gate passes: `podman compose -f docker/docker-compose.yml run --build --rm test`
- [ ] **Exactly the two iptables-backend cases are removed, and no other test's result changes.** Stated relatively on purpose: the suite is 104 today so the expected outcome is 102 passing, but a sibling backlog task may legitimately remove other tests first, and an absolute count would bounce this task for someone else's landing
- [ ] No `uci`, `logger` or iptables mock remains in the image or the repo, and `docker/mock-iptables.sh` is deleted as a file
- [ ] `uci`, `logger`, `nft` and `/usr/sbin/uhttpd` resolve to the real OpenWrt binaries inside the container
- [ ] `bats --version` reports the pinned 1.11.0, and bare `bats test/` still works as the compose command invokes it
- [ ] The bats tarball is fetched at a pinned version and verified against a recorded checksum, since this fetch gates every future build
- [ ] `ip netns add` succeeds inside the container, proving both the `/var/run` fix and the added `SYS_ADMIN` capability, and `nsenter` is present
- [ ] `cat /proc/sys/net/ipv4/ip_forward` reads `1` inside the container, proving the compose sysctl took effect
- [ ] The shared test helpers keep `reset_mocks`, `assert_mac_blocked` and `assert_mac_not_blocked` working for the tests that use them

## Blocked by

- None, can start immediately.

## Prompt

> Replace the Alpine-based test container in this OpenWrt parental-control repo with a real OpenWrt userland, and delete the mocks it makes redundant.
>
> Context: this repo controls a home router. Its test suite has been running on Alpine with mocked `uci` and `logger`, which produced confidently wrong conclusions more than once (a claim about nftables JSON support and a claim about package availability were both settled only by testing a real image). Moving to `openwrt/rootfs` removes that class of error. Read `work/notes/findings/rootless-container-netns-nftables-requirements.md` first: it carries the verified recipe and the failures behind each item.
>
> Everything you need is in the What-to-build section above, and every item there was established empirically rather than assumed. The exact numbers matter: the suite is 104 tests, you remove 2 iptables-backend cases, and the result must be 102 passing with nothing else broken. If you see a different number, something else broke and you should find out what rather than adjusting the expectation.
>
> Two things that were predicted to break and do NOT, recorded so you do not go hunting. Dropping `bind-tools` is safe, but be precise about why, because the obvious reason is wrong: the website-blocking tests override the resolver with a mock, yet the profiles tests do NOT and still reach the default resolver path. They survive because busybox on OpenWrt provides `nslookup` and because they assert rule presence rather than resolved contents. Do not remove busybox's resolver on the strength of "it is mocked". Second, replacing the no-op `uci` shim with the real `uci` does not break the blocklists tests, even though they reach `uci commit dhcp` and an init-script restart, because inside the ephemeral container those either succeed harmlessly or fail quietly.
>
> Where to look: the container definition and the mock shims live in the docker directory; the test helpers and the iptables-specific cases live in the test directory. `docs/architecture.md` explains how the layers fit together.
>
> Do NOT change any script under `scripts/`, any behaviour, or the compose file's capabilities. Capabilities and the netns harness belong to the follow-on task; this one only swaps the environment and proves the existing suite still passes on it.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does it still match the code and the relevant ADRs? If the suite is no longer 104 tests, or the mocks have already moved, do NOT build on the stale premise: route the task to needs-attention with the discrepancy as the reason.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record. The bats fetch mechanism (pinned tarball versus vendored tree) is exactly such a choice: if you deviate from the pinned-fetch decision above, write the why. An un-recorded in-scope decision is a review finding, not a silent default.
