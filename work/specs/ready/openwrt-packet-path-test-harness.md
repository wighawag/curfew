---
title: OpenWrt packet-path test harness
slug: openwrt-packet-path-test-harness
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this spec settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

The test suite cannot see whether the firewall works.

All 104 tests assert set membership or rule presence. None of them ever sends a packet. That blind spot is not theoretical: replaying the production boot order showed `parental-profiles.sh block eli` reporting success, writing `blocked` to its state file, logging "Profile blocked", and leaving the child with working internet. The suite stayed green throughout, because the sets it inspects looked exactly as expected.

The environment compounds it. Tests run on Alpine with mocked `uci` and `logger`, so OpenWrt-specific behaviour is guessed rather than observed, and a busybox stand-in substitutes for uhttpd. During the investigation this produced two confidently wrong conclusions that a real image disproved in seconds.

Until a test can say "a packet from this MAC did or did not reach the internet", every claim this project makes about enforcement is unverified.

## Solution

A test environment that runs on real OpenWrt and asserts on the packet path.

The base image becomes `openwrt/rootfs`, so `uci`, `logger`, `nft`, busybox applet behaviour and uhttpd are the real things rather than mocks. On top of it, a network-namespace harness builds an actual topology: a client namespace with a chosen MAC on a `br-lan` bridge, the container as the router, and an `internet` namespace behind an interface named `pppoe-wan` serving HTTP. A test then asks the only question that matters: did the packet get through?

This spec delivers the testbed and the assertions that can be made with it TODAY, against unmodified scripts. It deliberately does not change any enforcement behaviour. Its value is that it makes the enforcement work verifiable, and it can land and go green on its own.

## User Stories

1. As a maintainer, I want tests that send real packets through a real bridge with a chosen source MAC, so that a rule which looks correct but sits after a terminal `accept` fails the suite instead of passing it.
2. As a maintainer, I want the baseline reachability asserted before any firewall rule exists, so that a topology which silently never forwards cannot masquerade as a working firewall.
3. As a maintainer, I want the harness to fail loudly when a required tool is missing, so that a run cannot produce a confident false result (this bit the investigation: `nft` was absent from `PATH`, every call was swallowed by the scripts' own `2>/dev/null`, and a probe reported a bug that did not exist).
4. As a maintainer, I want the tests to run against a real OpenWrt userland, so that `uci`, `logger`, busybox applet differences and the real `nft` build stop being guesses.
5. As a maintainer, I want the existing suite to keep passing on the new image, so that switching environments does not quietly drop coverage. Measured bar: 102 of 104 unchanged, plus one deliberate removal, and nothing else broken.
6. As a maintainer, I want a reusable harness API rather than topology setup copied into each test file, so that the enforcement work can write packet-path assertions without rebuilding the plumbing.
7. As a maintainer, I want the unknown-device allowlist proven at the packet level, so that the one part of the system currently believed to work is actually confirmed to work. This also discharges the enforcement spec's story about a visitor's device staying blocked, which asserts the same claim and needs no second assertion there.
8. As a maintainer, I want the mocks that the real image replaces to be deleted rather than left shadowing it, so that a test cannot accidentally assert against a mock on an image that has the real tool.

### Autonomy notes (the two gate axes)

Both flags are omitted, and this time the claim rests on a measurement rather than an argument: the existing suite has been RUN on the target image and the result is recorded below (102 of 104, with both exceptions understood and owned). The harness primitives were separately proven on the same image. Earlier drafts of this spec asserted resolution on the strength of a six-test smoke run, which was a smaller thing than the claim; that gap is what the measured run closes.

This spec changes no enforcement behaviour, so it carries none of the state-model questions that gate `enforcement-contract-and-packet-path-tests`.

## Implementation Decisions

**The container recipe, verified on `openwrt/rootfs:x86-64-25.12.4`.** A 6-test smoke suite passed covering real `nft`, an `ether_addr` timeout set, real `uci` and `logger`, netns plus veth plus bridge via `nsenter`, the sysctl, and the presence of the real `uhttpd` binary. Each item below was established by hitting the failure, not by assumption:

- `apk add bash ip-full jq coreutils-nl coreutils-cksum nsenter`. OpenWrt names differ: `iproute2` is **`ip-full`**. `bash` is required because bats is a bash program and OpenWrt ships only ash.
- **`bats` is NOT packaged for OpenWrt** (`apk search bats` returns nothing against 11269 available packages). Fetch `bats-core` **v1.11.0** from its GitHub release tarball during the image build, extract it to a fixed path, and symlink `bin/bats` onto `PATH` so the existing compose command (`bats test/`) keeps working unchanged. Do NOT run its `install.sh`: it fails with `install: command not found`, because OpenWrt has no coreutils `install`. Pin the version explicitly and prefer a checksum: an unpinned "latest release" makes the gate breakable by an upstream change with no commit in this repo. Fetching at build time rather than committing the tree is the deliberate choice, since vendoring several dozen third-party files into this repo is a worse review burden than a pinned download.
- **`coreutils-nl` is required.** bats calls `nl`, which busybox does not provide. Without it bats reports `Executed 0 instead of expected N tests` while appearing to run, which is its own silent-false-result failure.
- **`coreutils-cksum` is required** by `test/setup-adguard.bats`, which uses `cksum` to derive filter IDs. Without it those assertions fail with `cksum: command not found`. Found by running the suite, not by inspection.
- **`mkdir -p /var/run` before any `ip netns` call.** On OpenWrt `/var/run` symlinks to `/tmp/run`, which procd creates at boot, so it does not exist in a container and `ip netns add` fails.
- **`nsenter --net=/var/run/netns/<ns>`, never `ip netns exec`**, which fails with `mount of /sys failed: Operation not permitted` on this image exactly as it does on Alpine.
- Capabilities `NET_ADMIN`, `SYS_ADMIN`, `NET_RAW`, plus **`--sysctl net.ipv4.ip_forward=1` at container start**. `--privileged` is not required. The sysctl is load-bearing: setting it from inside the container fails on a read-only `/proc/sys`, and without it nothing forwards, so every probe reads unreachable including the baseline. Story 2 exists precisely to catch that.
- Do not combine `--network host` with the sysctl; the runtime refuses to set a host-namespace sysctl.

**The topology.** `br-lan` bridge in the container's own namespace holding the router address; a `client` namespace attached by veth, whose MAC is settable per test; an `internet` namespace behind a veth named `pppoe-wan`, serving a known page over HTTP.

**The harness MUST set `PARENTAL_WAN_IF=pppoe-wan` and `PARENTAL_LAN_IF=br-lan`.** Naming the veth `pppoe-wan` is not sufficient on its own and it is worth being precise about why, because an earlier draft of this spec got it wrong: no script matches that literal name. Both `setup-firewall.sh` and `parental-profiles.sh` resolve the WAN interface from `PARENTAL_WAN_IF`, falling back to `uci get network.wan.device` and then to a literal `eth1`, and the existing suite pins `PARENTAL_WAN_IF=eth1`. Without the lever the generated rules match `oifname "eth1"` against a veth called `pppoe-wan` and no packet-path assertion can pass. These two levers belong in the harness's documented env set alongside `PARENTAL_CONFIG`, `PARENTAL_STATE_DIR`, `NFT` and `SLEEP`.

Both scripts also override that lever from `ifstatus wan` when it returns a non-empty `l3_device`. On the target image `ifstatus` exists but ubus is not running, so it returns nothing and the override does not fire; this was confirmed by the measured suite run, where the interface-pinned tests passed. Worth knowing rather than discovering later.

**The harness API**, as `test/test_helper/netns.bash`: `netns_setup`, `netns_client_mac <mac>`, `netns_probe` returning reachable/unreachable, `netns_teardown`. Plus a preflight that hard-fails when `nft`, `ip` or `nsenter` is missing, and an explicit `PATH` covering `/usr/sbin`.

**Mocks that the real image replaces are deleted, not left in place:** the `uci` and `logger` shims in the Dockerfile, and `docker/mock-iptables.sh` together with its `COPY` line. The iptables-backend test cases go with that mock; this is forced rather than chosen, because the mock is an Alpine-specific shim that cannot survive the image swap. The iptables code itself stays for now and is removed by the enforcement spec, which restructures that abstraction anyway.

The mock-assertion helpers in `test/test_helper/mocks.bash` are a different matter and must NOT be deleted wholesale: that file holds `reset_mocks`, `assert_mac_blocked` and `assert_mac_not_blocked`. Only their iptables branches go. It also holds two dead `assert_websites_*` helpers whose set name has never matched the real one, which are safe to remove. Note the file is loaded by three of the six bats files, not all six, and the `assert_mac_*` helpers are used only by `test/parental-profiles.bats`. That same file carries a SECOND, inline iptables branch reading the mock's state file, which is outside `mocks.bash` and must go with the rest.

**Removing the iptables mock is a choice, not a forced consequence**, and the honest framing matters because the earlier draft overstated it. `docker/mock-iptables.sh` is plain POSIX shell using only busybox-safe tools, so it would survive the image swap perfectly well. It is being removed because the iptables backend is dead code that the enforcement spec deletes, and keeping a mock alive for a backend nobody runs is not worth the image weight. The cost is real and should be accepted knowingly: it removes the only coverage of a code path that stays in the repo until the enforcement spec lands, and that spec is currently gated on open questions.

**File-by-file intent**, recorded to seed the tasking:

| File | Change |
|---|---|
| `docker/Dockerfile` | base image to `openwrt/rootfs:x86-64-25.12.4`; the apk list and pinned bats fetch above; `mkdir -p /var/run`; delete the `uci` and `logger` shims and the `COPY` of the iptables mock |
| `docker/mock-iptables.sh` | delete the file itself, not just its `COPY` line |
| `docker/docker-compose.yml` | add `SYS_ADMIN` and `NET_RAW` to `cap_add` and a `sysctls: net.ipv4.ip_forward=1` entry, on **both** the `test` and `shell` services |
| `test/test_helper/netns.bash` | new: the harness API and preflight |
| `test/test_helper/mocks.bash` | remove the iptables branches and the two dead `assert_websites_*` helpers; keep everything else |
| `test/parental-profiles.bats` | remove the iptables-backend cases and the inline iptables branch |
| `test/harness.bats` | new: the four assertions below |
| docs | README ("81 tests" and the Alpine description are both falsified by this spec), `docs/architecture.md` (its testing paragraph credits the enforcement spec with adding this harness), and `CONTEXT.md` (its Conventions paragraph says the gate is Alpine with `NET_ADMIN` only and attributes the change to the enforcement spec). All three are stale the moment this lands and no other spec owns them |

**The gate is the acceptance evidence.** The recipe was proven with `podman run` command-line flags, but the gate is `podman compose -f docker/docker-compose.yml run --build --rm test` (see `dorfl.json`). Those are not the same path: the caps and the sysctl must be carried by the compose file, and the compose `sysctls:` key has NOT been verified through `podman compose`. Acceptance is the real gate command going green, never a hand-rolled `podman run`. If the compose route cannot carry the sysctl, the fallback is to change `dorfl.json` to invoke the container directly, and whoever discovers that owns the change.

## Testing Decisions

The seam is the packet path, at the highest level available: a real client namespace with a chosen source MAC reaching a real HTTP server through the router's forward path. Assert reachable/unreachable, never ruleset text, because ruleset text is exactly what looked correct while the system enforced nothing.

Assertions this spec delivers, all satisfiable against unmodified scripts (verified by tracing the rules `apply` actually installs: an allowlisted MAC hits the accept, an unknown MAC hits the terminal drop, and return traffic matches neither rule so it falls through the accept policy):

1. Baseline: with no firewall rules, the client reaches the internet.
2. An unknown MAC (in no profile) is UNREACHABLE once the allowlist is applied.
3. An allowlisted MAC is REACHABLE once the allowlist is applied.
4. Harness preflight: with a required tool removed from `PATH`, the harness FAILS rather than reporting a pass.

Assertion 2 is deliberately the one enforcement claim currently believed true. If it fails, the harness is wrong; if it passes, the harness is trustworthy enough to carry the enforcement work's assertions.

**The blast radius of the image swap is MEASURED, not estimated.** The existing suite was run on `openwrt/rootfs:x86-64-25.12.4` with the packages above (minus `coreutils-cksum`) and no mocks at all:

```
ok:     102
not ok: 2
  not ok 49 block works with iptables backend     <- deliberately removed by this spec
  not ok 71 filter IDs are unique integers        <- cksum: command not found
```

So the acceptance bar for story 5 is precise: **102 of 104 pass unchanged**, the `cksum` failure is closed by adding `coreutils-cksum`, and the iptables-backend case is a deliberate removal rather than a regression. Restated: no test may break other than the one this spec removes on purpose.

Two predictions that did NOT hold, recorded so they are not re-litigated. Dropping `bind-tools` is safe, because `test/website-blocking.bats` overrides `NSLOOKUP` with a mock. And replacing the no-op `uci` shim with the real `uci` does not break `test/blocklists.bats`, even though `blocklists.sh update` reaches `uci set`/`uci commit dhcp` and an `/etc/init.d/dnsmasq restart`: on the target image those either succeed harmlessly inside the ephemeral container or fail quietly, and nothing hangs. This was the single largest predicted risk and it is empirically absent.

The env-override pattern to follow (`PARENTAL_CONFIG`, `PARENTAL_STATE_DIR`, `NFT`, `SLEEP`) is established in the bats `setup()` functions, not in `test_helper/mocks.bash`.

## Out of Scope

- **Any change to enforcement behaviour.** No chain restructure, no persistence, no budget or ticket changes. Those belong to `enforcement-contract-and-packet-path-tests`, which is ordered after this spec and which supplies the assertions that require them.
- Removing the iptables code path from the scripts (the enforcement spec owns it; only the mock and its tests go here).
- The Go tool, the status page, guest access, and anything touching AdGuard or DNS.

## Tasking note

The enforcement spec's tasks depend on `test/test_helper/netns.bash` existing. `taskedAfter` orders the SPECS, not the builds, so whoever tasks the enforcement spec must put `blockedBy` on its emitted tasks pointing at the task that delivers the harness API here. Without that, enforcement tasks can be emitted with `blockedBy: []` and claimed against a harness that does not yet exist.

## Further Notes

This spec was split out of `enforcement-contract-and-packet-path-tests` after three review rounds found that spec repeatedly blocked on unresolved state-model decisions while the harness half was fully resolved and independently valuable. Separating them means the testbed can land and go green now, rather than waiting behind decisions it does not depend on.

The gate stays green throughout this work: this spec adds passing tests and changes no behaviour. That is a deliberate contrast with the enforcement spec, whose tests are written to fail first.
