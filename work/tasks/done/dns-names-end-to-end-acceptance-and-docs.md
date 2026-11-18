---
title: Prove local DNS names end to end, including after a simulated panic-off, and document them
slug: dns-names-end-to-end-acceptance-and-docs
spec: local-dns-names-for-a-device
blockedBy: [adguard-rewrites-for-dns-names, dns-names-on-the-devices-page]
covers: [4, 5, 8, 14, 22, 26]
---

## What to build

One acceptance scenario in the real image that runs what the household will run: a registry with "workstation igc" at 192.168.1.122 carrying `*.lan.telemaque.ska.sh`, the daemon's passes against real uci, real dnsmasq on 54 and real AdGuard on 53, and a sentinel upstream that answers every name (A 93.184.216.66, AAAA 2606:4700::66) plus `rebind.example` with a private address.

Asserted: from AdGuard on 53 and dnsmasq on 54, `breakoutbunny.lan.telemaque.ska.sh` A is 192.168.1.122, AAAA is NOERROR with no answer and no sentinel. Then a simulated `panic-off` (AdGuard stopped, dnsmasq moved back to 53 by `restoreDnsmasqTo53`): the same answers from 53, and the baseline that an upstream private answer (`rebind.example`) IS dropped there. Then the name is removed and both resolvers stop answering it, with the hand-made records still present.

Docs: README command table and the "what push does" paragraph; CONTEXT.md terms **local DNS name** and **DNS record ledger**; the owner's live-router checklist from the spec (the `dig` commands) in the setup guide.

## Acceptance criteria

- [x] The scenario above passes in `docker/acceptance.sh`, and fails if the `server=/x/` line is not written (mutation check, recorded in the test comment).
- [x] README, CONTEXT.md and the setup guide updated; no em dashes.
- [x] Nothing touches a live router.

## Blocked by

- adguard-rewrites-for-dns-names
- dns-names-on-the-devices-page

## Prompt

Goal: the end-to-end proof the owner's live acceptance mirrors, and the docs. Read `docs/spikes/local-dns-names/design-notes.md` (Testing Decisions, the owner's live checklist), ADR 0013, ADR 0014, the finding `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md`, and `docs/spikes/local-dns-names/measure.sh` (the sentinel upstream technique). Reuse the existing real-AdGuard and real-dnsmasq test helpers rather than adding a third copy. Done = scenario green in verify, docs updated.

## Decisions (made while building, 2026-11-18)

- **The simulated panic-off runs the REAL `legacy/scripts/panic-off.sh`** (with `NFT=true`), rather than `restoreDnsmasqTo53`, because the script is what actually runs on the router; the harness then plays procd for its `/etc/init.d/dnsmasq restart`. The test also asserts the script really left `port='53'`.
- **The scenario drives one real `Manager.Tick`** (DHCP pass with pins and names in one transaction, then the AdGuard rewrites), against real uci, a real dnsmasq on 54 (then 53) and a real AdGuard on 53. It ends by removing the name while AdGuard is down: dnsmasq stops answering it, and the AdGuard rewrite stays recorded in the ledger so nothing is orphaned.
- Mutation check recorded in the test comment: without the `server` entry it fails on 54 and on 53 with the AAAA sentinel.
- **The live-router checklist went into the README's new "Local DNS names" section**, not `docs/setup-guide.md`, which still describes the legacy shell install.
- **A pre-existing dnspolicy flake was diagnosed and fixed in the harness**: AdGuard applies client and list changes asynchronously after the API call returns, so `mustResolve` / `mustBlock` now assert the verdict appears within 3s. Evidence and the rejected first hypothesis are in the update to `work/notes/observations/one-unreproduced-dnspolicy-acceptance-failure-before-v0-9-3.md`.
- The lock's watchdog no longer leaves a stray `sleep` behind (seen while debugging the above).

## Review fixes (2026-11-18, before commit)

A subagent review found two P1s, both fixed with tests: a pass that could not read the dhcp config now marks names as unmanaged, so the AdGuard half no longer deletes curfew's rewrites for a tick; and the install-time rollback to port 53 now runs even when the DHCP config lock cannot be taken, since restoring the resolver must never be refused. Also fixed: the write-ahead ledger is saved only on a difference, a router without `nslookup` is not read as a dead resolver, a named dnsmasq section is read correctly, and push's note about an existing entry no longer claims curfew did not write it. The rest is recorded in `work/notes/observations/local-dns-names-review-deferrals.md`.
