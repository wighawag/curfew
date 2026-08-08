---
title: Force DNS through the router, so a DNS restriction cannot be walked around
slug: force-dns-through-the-router
humanOnly: true
needsAnswers: true
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks.

<!-- open-questions -->
<!--
  TRANSIENT BLOCK — stripped by the apply rung on full resolution.
-->

## Open questions

1. **Redirect or drop?** For plain DNS leaving the LAN, curfew can either DNAT it to the router (invisible: a device hardcoded to `8.8.8.8` silently gets AdGuard's answers) or drop it (simpler, no nat chain, but a device with only a hardcoded resolver then has NO DNS and reads as "the internet is broken"). Redirect is the better experience and the larger change. **Decide before tasking.**
2. **Whole LAN, or only profiles with restrictions?** Whole-LAN is simpler and cannot be walked around by moving a device between profiles, but it also applies to the parents' own devices and would break a work laptop that needs a corporate resolver or a VPN's DNS. Per-profile is narrower and matches where curfew's DNS policy already applies, but leaves an ungoverned device able to use any resolver. **Decide before tasking.**
3. **Is DoQ / QUIC in scope?** Blocking `udp/443` outright is a blunt instrument that also removes HTTP/3 for the whole household. Blocking `udp/853` (DNS-over-QUIC) is cheap and narrow. Are both wanted, or only 853?
4. **Does an exemption list need to exist from day one?** A games console, a smart TV or a work laptop with a hardcoded resolver may legitimately need to bypass. If yes, that is a per-device flag in the registry and a corresponding nftables `accept` above the redirect.

<!-- /open-questions -->

## Problem Statement

A parent sets "no streaming for eli between 08:00 and 10:00". Eli opens Firefox, turns on "Secure DNS" with a custom provider, and the restriction stops applying — silently, with nothing on the curfew page or in AdGuard indicating anything has changed. The same is true for a phone with Android Private DNS set to a hostname, and for anyone who types `8.8.8.8` into their network settings.

This is the single most likely way for the per-profile DNS restrictions shipped in `docs/adr/0011-...` to be *built and useless*. Everything in that ADR assumes the child's device asks this router. Nothing today makes it.

The cheap half is already done: curfew blocks the well-known DoH endpoint hostnames for restricted profiles (`internal/dnspolicy/doh.go`), which defeats every client that resolves its endpoint by name, and AdGuard blocks Firefox's canary itself. What remains is everything that needs no DNS lookup at all: a hardcoded plaintext resolver, DoT, DoQ, and a DoH endpoint given as a literal IP address.

## Solution

curfew's nftables ruleset gains rules that make the router the only reachable resolver for the devices it governs:

- **Plain DNS** (`udp/53`, `tcp/53`) leaving the LAN is redirected to the router, or dropped (question 1). A device hardcoded to a public resolver transparently gets AdGuard's answers.
- **DoT** (`tcp/853`) and **DoQ** (`udp/853`) leaving the LAN are dropped, so a client falls back to plain DNS, which is then redirected.
- **DoH to a literal IP** is NOT closed, and the documentation says so plainly rather than implying the hole is shut.

This is enforcement, so it lives with the rest of the enforcement contract, is packet-path tested per `docs/adr/0004-tests-assert-on-the-packet-path.md`, and gets a tested rollback.

## User Stories

1. As a parent, I want a child's device that has been pointed at a public DNS server to still be filtered, so that a restriction I set actually holds.
2. As a parent, I want a child who turns on Android Private DNS to lose that bypass, so the phone goes back through the household resolver.
3. As a parent, I want to be told which bypasses are still possible, so I do not believe the system is doing more than it is.
4. As a parent, I want my own devices to keep working exactly as they do now, including a work laptop on a VPN, so that closing a child's bypass does not cost me my job.
5. As a household member, I want DNS to keep working if this feature misbehaves, so that a wrong rule does not take the internet away from everyone.
6. As the person deploying this, I want to see it fail on the packet path in a test before I trust it on the family's router, because ruleset text that looks correct while packets flow is exactly what this project exists to distrust.
7. As the person deploying this, I want a single documented command that removes the rules, so a bad night is one ssh away from fixed.
8. As a maintainer, I want AdGuard's own upstream queries to be provably unaffected, so that forcing clients through the router cannot accidentally cut the router off from the internet.

### Autonomy notes

- **`humanOnly: true`** — this is fail-closed enforcement that can take DNS away from a live household, and two of the open questions are product decisions rather than technical ones. A human must drive the tasking.
- **`needsAnswers: true`** — questions 1 and 2 change the shape of the implementation (nat chain or not; whole-LAN or per-profile), so tasking before they are answered would cut the wrong tasks.

## Implementation Decisions

Decisions taken at launch; the open questions above are deliberately NOT pre-empted here.

- **The rules live in curfew's own table**, not in fw4, exactly as every other enforcement rule does. If redirect is chosen, that means a `nat` `prerouting` chain in the same `inet curfew` table. `ApplyDesired` replaces the whole table on every apply, so the new chain is rebuilt with the rest and needs no separate lifecycle.
- **Ordering matters and must be explicit.** The DNS rules act on destination port and address, and must not disturb `contract.Tiers`, whose ORDER IS THE POLICY. A redirect at prerouting happens before the forward chain, so a blocked device's DNS is redirected and then dropped by the forward chain anyway; that is correct and should be asserted rather than assumed.
- **The router's own upstream DNS must be untouched.** AdGuard forwards to `1.1.1.1:53` and `8.8.8.8:53` from the router itself, which is output/postrouting rather than forward, so a forward or prerouting rule should not see it. **This is the single most dangerous assumption in the change and must be MEASURED, not reasoned**: getting it wrong takes DNS away from the entire household including the router.
- **Exemptions, if any (question 4), belong in the device registry** rather than as a separate list, since ADR 0003 already makes the device the place a per-device fact lives.
- The DoH endpoint hostname list already shipped in `internal/dnspolicy/doh.go` stays where it is; this spec does not move or duplicate it.

## Testing Decisions

Every claim here is a packet-path claim and gets a packet-path test, following `internal/enforce/packetpath_test.go` and the netns harness.

- **Baseline first, always.** A client resolves through a public resolver before the rules exist. Without it, a topology fault reads as a perfect block.
- **The positive claim:** a query from a LAN client to `8.8.8.8:53` is answered by the ROUTER's resolver (redirect) or fails (drop). Under redirect, the distinguishing assertion is that the answer carries the fixture upstream's address rather than the real one, which proves interception rather than mere reachability. That is the DNS-path equivalent of the offline-fixture argument in `internal/deploy/adguard_packetpath_test.go`: against a real resolver a working redirect and a broken one can return the same answer.
- **The control that matters most:** the router's own upstream DNS still works, asserted by AdGuard successfully resolving a fixture name while the rules are in force.
- **A second control:** non-DNS traffic (port 80/443 TCP) from the same client is unaffected, so the rules are not a general outage wearing a DNS costume.
- **DoT:** a `tcp/853` connection from a LAN client to an external address fails, while the same client's plain DNS still works.
- **Mutation-test the ordering:** deliberately place the DNS rules after a terminal accept and confirm the tests fail, since an unreachable rule is the classic way this looks right and does nothing.
- **Rollback:** `nft delete table inet curfew` must restore normal DNS, asserted on the packet path, so the documented escape hatch stays complete.

## Out of Scope

- **DoH to a hardcoded IP literal, and VPNs.** Not closable without either an IP blocklist (which goes stale and hits shared CDN ranges, breaking unrelated sites) or TLS interception with a CA installed on the child's device. Both are rejected; the limitation is documented instead.
- **Blocking DoH provider IP ranges.** Same reasoning: whack-a-mole with real collateral.
- **Changing AdGuard's own upstreams to DoH or DoT.** That is a privacy improvement for the household rather than a bypass control, it is the household's setting rather than curfew's, and it is captured separately in `work/notes/ideas/`.
- **MAC spoofing.** A child copying a sibling's registered MAC is a different problem and is not addressed by anything here.

## Further Notes

Measured on the live router while writing this, and worth knowing before implementing: AdGuard's configured upstreams are `1.1.1.1` and `8.8.8.8` over **plain port 53**, load-balanced, and the query log confirms both are used in practice. So today the household's DNS is already visible to the ISP; forcing clients through the router does not change that one way or the other, but anyone touching this area should not assume the upstream leg is encrypted.

Also measured: AdGuard blocks Firefox's `use-application-dns.net` canary itself, with no rule from anyone, so the automatic-DoH case is already largely handled before this spec does anything.
