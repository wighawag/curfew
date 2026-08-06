---
title: OpenWrt packet-path test harness
slug: openwrt-packet-path-test-harness
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks.

> Tasked. The technical detail that was here has moved into the tasks (`openwrt-test-image`, `netns-packet-path-harness`, `refresh-test-environment-docs`); the durable rationale moved to `docs/adr/0004-tests-assert-on-the-packet-path.md` and `docs/adr/0005-test-environment-is-a-real-openwrt-image.md`; the verified environment recipe lives in `work/notes/findings/rootless-container-netns-nftables-requirements.md`.

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

Both flags omitted, and the claim rested on a measurement rather than an argument: the existing suite was RUN on the target image before tasking, giving 102 of 104 with both exceptions understood. Earlier drafts asserted resolution on the strength of a six-test smoke run, which was a smaller thing than the claim; the measured run closed that gap.

This spec changes no enforcement behaviour, so it carried none of the state-model questions that gate `enforcement-contract-and-packet-path-tests`.

## Out of Scope

- **Any change to enforcement behaviour.** No chain restructure, no persistence, no budget or ticket changes. Those belong to `enforcement-contract-and-packet-path-tests`, which is ordered after this spec and which supplies the assertions that require them.
- Removing the iptables code path from the scripts (the enforcement spec owns it; only the mock and its tests go here).
- The Go tool, the status page, guest access, and anything touching AdGuard or DNS.

## Further Notes

This spec was split out of `enforcement-contract-and-packet-path-tests` after three review rounds found that spec repeatedly blocked on unresolved state-model decisions while the harness half was fully resolved and independently valuable. Separating them means the testbed can land and go green now, rather than waiting behind decisions it does not depend on.

The gate stays green throughout this work: this spec adds passing tests and changes no behaviour. That is a deliberate contrast with the enforcement spec, whose tests are written to fail first.

**Tasking note for whoever tasks the enforcement spec:** its tasks depend on the harness API delivered here. `taskedAfter` orders the SPECS, not the builds, so put `blockedBy: [netns-packet-path-harness]` on the enforcement tasks that need it. Without that they can be emitted `blockedBy: []` and claimed against a harness that does not yet exist.
