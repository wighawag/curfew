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

Nothing else needs installing for the harness: the base image already has `/usr/sbin/uhttpd` (to serve a page) and `/usr/bin/wget` (to fetch one), which is what the follow-on task's topology uses. Note `wget` here is **uclient-fetch**, not busybox wget and not GNU wget; it supports `-q`, `-O <file>` and `--timeout=N | -T N`, which is all the harness needs. There is no `timeout` applet on this image (`coreutils-timeout` is packaged if one is ever wanted), so the fetch client's own `-T` is the way to bound a probe.

**Existing Dockerfile stanzas:** keep the repo `COPY`, `WORKDIR`, the `chmod +x` of the scripts, and the mock-state directory creation. Drop the `ln -sf /usr/sbin/nft /usr/bin/nft` line: the OpenWrt image's `PATH` already covers `/usr/sbin`, so it is redundant. Bare `apk add` works on this image without a preceding `apk update`, so no index refresh is required, though adding one is harmless.

**Capabilities and sysctl, in `docker/docker-compose.yml`, on BOTH the `test` and `shell` services:** add `SYS_ADMIN` and `NET_RAW` to the existing `cap_add`, and add `sysctls: net.ipv4.ip_forward=1`. `--privileged` is NOT required. `podman compose` has been confirmed to honour the `sysctls:` key. `SYS_ADMIN` is what makes `ip netns add` work (measured: with `NET_ADMIN` alone it fails on the bind-mount with a permission error), and the sysctl is what makes the topology forward at all.

**bats is NOT packaged for OpenWrt.** Fetch it during the image build, from this exact URL, and verify this exact digest:

```
https://github.com/bats-core/bats-core/archive/refs/tags/v1.11.0.tar.gz
sha256  aeff09fdc8b0c88b3087c99de00cf549356d7a2f6a69e3fcec5e0e861d2f9063   (172044 bytes)
```

That digest was measured, and confirmed stable across two independent fetches. Use it as a literal in the Dockerfile and fail the build on mismatch. Do NOT download-then-hash-whatever-arrived: that satisfies the wording while defeating the purpose, which is that an upstream change cannot alter the gate without a commit in this repo.

Extract to a fixed path and symlink the entry point so the compose command's bare `bats test/` keeps working, for example extract to `/opt/bats-core` with `--strip-components=1` and symlink `/opt/bats-core/bin/bats` to `/usr/bin/bats`. Do NOT run bats' own `install.sh`: it fails with `install: command not found`, because OpenWrt has no coreutils `install`. Fetching at build time rather than committing the tree is deliberate: several dozen vendored third-party files are a worse review burden than a pinned, digest-checked download.

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
- [ ] A new `test/environment.bats` proves the environment claims THROUGH THE GATE rather than by a manual side-channel run: `ip netns add` succeeds (proving both the `/var/run` fix and the `SYS_ADMIN` capability), `/proc/sys/net/ipv4/ip_forward` reads `1` (proving the compose sysctl), `bats --version` is 1.11.0, and `uci`, `logger`, `nft`, `uhttpd`, `nsenter` and `cksum` all resolve. These are additive tests, which is why the count bar above is stated relatively
- [ ] Residual `mock` NAMING (the `MOCK_LOG_DIR` variable, `/tmp/mock-state`, header comments mentioning mocks) is explicitly OUT of scope: the criterion above is about mock implementations, not about renaming things
- [ ] The shared test helpers keep `reset_mocks`, `assert_mac_blocked` and `assert_mac_not_blocked` working for the tests that use them

## Blocked by

- None, can start immediately.

## Prompt

> Replace the Alpine-based test container in this OpenWrt parental-control repo with a real OpenWrt userland, and delete the mocks it makes redundant.
>
> Context: this repo controls a home router. Its test suite has been running on Alpine with mocked `uci` and `logger`, which produced confidently wrong conclusions more than once (a claim about nftables JSON support and a claim about package availability were both settled only by testing a real image). Moving to `openwrt/rootfs` removes that class of error. Read `work/notes/findings/rootless-container-netns-nftables-requirements.md` first: it carries the verified recipe and the failures behind each item.
>
> Everything you need is in the What-to-build section above, and every item there was established empirically rather than assumed. State your outcome RELATIVELY, not as an absolute count: you remove exactly the two iptables-backend cases, you add the environment test file described above, and no other test's result may change. As a sanity anchor the suite is 104 tests at the time of writing, so the likely outcome is 102 plus your new environment tests, but a sibling backlog task may legitimately remove other tests before you land, and that is not a regression.
>
> Two things that were predicted to break and do NOT, recorded so you do not go hunting. Dropping `bind-tools` is safe, but be precise about why, because the obvious reason is wrong: the website-blocking tests override the resolver with a mock, yet the profiles tests do NOT and still reach the default resolver path. They survive because busybox on OpenWrt provides `nslookup` and because they assert rule presence rather than resolved contents. Do not remove busybox's resolver on the strength of "it is mocked". Second, replacing the no-op `uci` shim with the real `uci` does not break the blocklists tests, even though they reach `uci commit dhcp` and an init-script restart, because inside the ephemeral container those either succeed harmlessly or fail quietly.
>
> Where to look: the container definition and the mock shims live in the docker directory; the test helpers and the iptables-specific cases live in the test directory. `docs/architecture.md` explains how the layers fit together.
>
> Scope fence: do NOT change any script under `scripts/` and do not change any product behaviour. You DO own the whole container definition, both `docker/Dockerfile` and `docker/docker-compose.yml`, including the capabilities and the sysctl described above. Only the netns harness itself belongs to the follow-on task.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does it still match the code and the relevant ADRs? Drift that matters here is the mocks having already moved, the two iptables cases being gone, or the base image having changed. A DIFFERENT TEST COUNT IS NOT DRIFT, because a sibling task removes tests independently. If you find real drift, route to needs-attention with the discrepancy rather than building on a stale premise.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record. The bats fetch mechanism (pinned tarball versus vendored tree) is exactly such a choice: if you deviate from the pinned-fetch decision above, write the why. An un-recorded in-scope decision is a review finding, not a silent default.
