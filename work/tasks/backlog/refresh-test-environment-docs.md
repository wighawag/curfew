---
title: Refresh the docs that describe the test environment
slug: refresh-test-environment-docs
spec: openwrt-packet-path-test-harness
blockedBy: [openwrt-test-image, netns-packet-path-harness]
covers: []
---

## What to build

Correct the three documents that describe the test environment, all of which become wrong the moment the OpenWrt image swap and the packet-path harness land, and none of which any other spec owns.

**The README** claims the suite is 81 tests in TWO places (the prose description and the project-structure tree) when it is 104 today, and describes the environment as Alpine. Both statements are falsified by this work, and both occurrences of the count need fixing rather than just the first one you find. While in there, note the README also carries other stale claims that belong to a different spec's sweep, so do not widen this task into them: leave the `parental_websites` references and the iptables-fallback feature line alone.

**`docs/architecture.md`** says in its testing section that the enforcement spec adds a network-namespace harness. That attribution was true before the spec was split and is now wrong: the harness ships from `openwrt-packet-path-test-harness`, and the enforcement spec consumes it. Fix the attribution and the description of what the suite now asserts.

**`CONTEXT.md`** says in its Conventions section that the gate runs an Alpine image with `NET_ADMIN` only, and that the enforcement spec is what changes this. Both halves become wrong. It should describe what the gate actually is once these tasks land: a real OpenWrt image with `NET_ADMIN`, `SYS_ADMIN`, `NET_RAW` and `net.ipv4.ip_forward=1`, and it should keep the warning about why the sysctl matters, because that warning is the reason the baseline assertion exists.

While in `CONTEXT.md`, also link the glossary terms **packet path** and **enforcement vs state** to `docs/adr/0004-tests-assert-on-the-packet-path.md`, which now carries their rationale. The file already links other terms to their ADRs (budget to 0001, device to 0003) and these two were left dangling when 0004 was written.

Keep the tense discipline these documents already use: `CONTEXT.md` marks unbuilt things explicitly, and that convention must survive this edit rather than being flattened into present tense everywhere.

## Acceptance criteria

- [ ] The README states the correct test count and describes the OpenWrt-based environment
- [ ] `docs/architecture.md` attributes the harness to the spec that actually ships it, and describes packet-path assertions as present rather than planned
- [ ] `CONTEXT.md` describes the real gate, keeps the explanation of why the ip_forward sysctl is load-bearing, and preserves its existing not-yet-implemented markers on terms that are still unbuilt
- [ ] No claim is introduced that is not true of the code at the time this lands: verify each statement against the container definition, the compose file and the actual test count rather than against these instructions
- [ ] Both README occurrences of the stale test count are corrected, not just the prose one
- [ ] `CONTEXT.md`'s `packet path` and `enforcement vs state` terms link to ADR 0004
- [ ] Out of scope and deliberately untouched: the README's `parental_websites` and iptables-fallback claims, which the enforcement spec's doc sweep owns

## Blocked by

- `openwrt-test-image` and `netns-packet-path-harness` — this task describes the end state those two produce, so it must land after both or it will document something that does not exist yet.

## Prompt

> Correct three documents in this OpenWrt parental-control repo that describe the test environment, after the test image swap and the packet-path harness have landed.
>
> Context: this repo's documentation has drifted before in ways that actively misled builders, so the standard here is that every statement you write must be verified against the code at the moment you write it, not against these instructions. Check the actual test count by counting test declarations, check the container definition for the real base image and packages, and check the compose file for the real capabilities. If any of them differs from what this task assumes, trust the code and say so.
>
> The three documents and what is wrong with each are in the What-to-build section. The subtlety worth care: `CONTEXT.md` is the project glossary and it deliberately marks unbuilt concepts as not yet implemented. Several terms in it describe things that still do not exist even after this work. Do not flatten those markers into present tense while fixing the environment description; the file's tense discipline is load-bearing, because agents read it as the source of truth for what exists.
>
> Keep the scope tight. Another spec owns a broader stale-documentation sweep covering the README's references to a config file no script reads and to an iptables fallback. Leave those alone so the two sweeps do not collide.
>
> FIRST, check this task against current reality: if the blocking tasks landed differently than described, document what actually shipped rather than what was planned.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record. Judgement calls here are real even though this is a docs task: which not-yet-implemented markers to keep, and how much of the sysctl warning to carry into the glossary versus leave in the ADR. If you make one, say so rather than leaving a reviewer to reverse-engineer it.
