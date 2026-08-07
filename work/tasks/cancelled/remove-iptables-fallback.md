---
title: Remove the iptables fallback backend
slug: remove-iptables-fallback
blockedBy: []
covers: []
---

## CANCELLED: absorbed into the enforcement spec

Not dropped as unwanted, but folded into `work/specs/ready/enforcement-contract-and-packet-path-tests.md`, which already owned half of it and restructures the same code.

Why it could not stand alone:

- The enforcement spec's base-image swap to `openwrt/rootfs` FORCES removal of the iptables mock, because that mock is an Alpine-specific shim in the Dockerfile. So the mock and the iptables tests were double-owned from the moment that spec was written.
- The enforcement spec restructures the very abstraction this task deletes (`nft_init`, the block/unblock dispatch, ticket handling). Carrying a dead iptables branch through that restructure means paying for it at every step, then deleting it anyway.
- Whatever survived that would then die a second time when the Go tool absorbs the shell scripts.

The work is now split across two specs, following a later split of the enforcement spec:

- `openwrt-packet-path-test-harness` removes the iptables MOCK and its test cases, forced by the base-image swap.
- `enforcement-contract-and-packet-path-tests` removes the iptables CODE, the backend dispatch, the `none` backend, the `backend` subcommand and the `status` backend line, and carries the fail-loud requirement as a user story plus a packet-path assertion.

Both durable insights were carried over: the evidence that the backend is genuinely dead, and the fail-loud requirement. One gap found in review and since closed: `docs/architecture.md` describes the abstraction being deleted and is now named in the enforcement spec's doc sweep. This file is kept only so the decision is traceable and the task is not re-proposed.

## What it would have built

Delete the iptables backend from the firewall abstraction, leaving nftables as the only implementation.

The scripts currently auto-detect a backend and carry a parallel iptables implementation of every operation (block, unblock, is-blocked, list-blocked) alongside the nftables one. It exists for backward compatibility with older OpenWrt, but the target router runs OpenWrt 25.12, which ships nftables only. The fallback is therefore never exercised in production, and it is dead weight that doubles the surface every firewall change has to be reasoned about.

Keep the *abstraction* if it is still earning its place, but it is probably simpler to call nftables directly once there is only one backend. Use judgement: the goal is less code and fewer untested paths, not preserving an indirection for its own sake.

The test suite currently runs some cases against a mock iptables via `PARENTAL_FIREWALL=iptables`. Those tests go with the backend, along with the mock in the container image. Take care not to delete the nftables coverage by accident: the two are interleaved in the same files.

## Acceptance criteria

- [ ] No iptables code path remains in any script, and no script consults an `iptables` binary
- [ ] The backend-detection logic and the `PARENTAL_FIREWALL=iptables` escape hatch are gone, or reduced to a clear error if someone sets it
- [ ] The public `backend` subcommand and the "Firewall backend" line in `status` are removed or reduced to a constant, and their tests go with them. These are nft-side surfaces existing ONLY to describe the abstraction, so they are in scope for deletion; this is the intended exception to the coverage criterion below
- [ ] iptables-specific tests and the mock iptables in the container image are removed
- [ ] No reduction in **enforcement** coverage: every test asserting what the firewall actually does still passes. Tests asserting backend *detection* or *reporting* are expected to go
- [ ] A missing or broken `nft` still fails LOUDLY. Today the `none` backend logs a warning; with it gone, do not let a missing `nft` become a silent no-op that still writes `blocked` to the state file (this repo's defining bug class is enforcement that lies)
- [ ] Any documentation claiming an iptables fallback is corrected (the README advertises "nftables: uses OpenWrt's native firewall (auto-detected, iptables fallback)")

## Blocked by

- None, but it is worth sequencing this AFTER the enforcement work lands, because that work restructures the same chain-building code and doing both at once makes the diff hard to review.

## Prompt

> Remove the iptables fallback backend from the curfew parental control scripts, leaving nftables as the sole firewall implementation.
>
> Context: this repo controls a home router running OpenWrt 25.12, which ships nftables only. The iptables path was kept for backward compatibility with older OpenWrt versions and the repo owner has decided it should go. It is never exercised on the target hardware, and it doubles the code that must be reasoned about for any firewall change.
>
> Where to look: the firewall abstraction lives in the profile-management script, which detects a backend and dispatches block/unblock/is-blocked/list-blocked to either an nftables or an iptables implementation. The container image used for tests also ships a mock iptables, and some test cases run the suite twice by setting the backend explicitly.
>
> Seams to test at: the existing test suite. Every ENFORCEMENT assertion must still pass; tests that assert backend detection or the backend-reporting line are expected to go with the abstraction. Be careful where you cut: the iptables-only cases sit in contiguous blocks, but backend branching also lives inside shared test helpers, which is where an over-eager deletion silently removes nftables coverage.
>
> Read `docs/architecture.md` for how the layers fit together before starting. Done means: no iptables code path, no mock, no iptables tests, corrected documentation, and a green gate.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does it still match the code, the relevant ADRs, and any work that landed since? This task in particular expects to run AFTER the enforcement work, which restructures the same chain-building code and removes the backgrounded ticket expiry. If that landed differently than assumed here, do NOT build on the stale premise: route the task to needs-attention with the discrepancy as the reason. Building on a stale task produces wrong-but-compiling work.
>
> RECORD non-obvious in-scope decisions you make while building, durably and linked from the done record. The fail-loud-versus-fail-silent choice for a missing `nft` is exactly such a decision: if it meets the ADR bar (hard to reverse, surprising without context, a real trade-off) write it as an ADR in `docs/adr/`; otherwise note it at the choice site and in the done record. An un-recorded in-scope decision is a review finding, not a silent default.
