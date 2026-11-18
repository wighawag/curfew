---
title: Local DNS names for a device, answered by the router itself
slug: local-dns-names-for-a-device
humanOnly: true
promptGuidance.testFirst: true
---

> Launch snapshot: records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked: they move into tasks/ADRs and this spec settles to its durable framing of Problem / Solution / User Stories / Out of Scope.)

## Decisions taken with the owner (2026-11-18)

The five launch questions were answered "agreed" to every recommendation:

1. The field is `dns_names`; the commands are `curfew add-dns-name` and `curfew remove-dns-name`.
2. A bare `x` covers x and every name below it; `*.x` covers only names below x; there is no exact-name-only form (Decision 2).
3. Names of two devices may not overlap at all (Decision 3).
4. AdGuard clients that get no rewrites are reported, never changed (Decision 5).
5. The unserialised `uci commit dhcp` between the install-time takeover and the daemon is fixed in this spec, measured first, as its own task landing before the names code (Decision 7).

## Problem Statement

telemaque (the device "workstation igc", MAC `38:05:25:3a:b0:70`, fixed address `192.168.1.122`) serves the children's game studios at names under `*.lan.telemaque.ska.sh`. Today those names resolve only through a public Cloudflare record (`*.lan.telemaque.ska.sh A 192.168.1.122`, DNS-only, no AAAA). So the household's own LAN depends on the internet and on Cloudflare to find a machine in the same room.

It also stops working at exactly the moment it is most needed. `panic-off` hands port 53 back to dnsmasq, and dnsmasq runs with `rebind_protection=1`, which drops a public answer that points at a private address. Measured on the test image: an upstream answer of `192.168.1.122` comes back from dnsmasq as NOERROR with no address. After a panic-off, the studios vanish.

The quick fix is a dnsmasq `rebind_domain` for that name. It works, but it is a hand edit to `/etc/config/dhcp` that nothing owns, which is the split ownership ADR 0007 blames for every bug this project has had, and it still depends on Cloudflare.

## Solution

A device in the registry can carry **local DNS names**. `curfew push` sends them, and the router answers them itself, with the device's fixed address, from both of its resolvers:

- **AdGuard**, through its REST API, as DNS rewrites curfew creates and owns (ADR 0010), so the names resolve while AdGuard holds port 53;
- **dnsmasq**, as `address` and local-only `server` entries in `dhcp.@dnsmasq[0]`, so they still resolve after `panic-off`, and whenever AdGuard is skipped (`-no-adguard`). A local answer is not subject to rebind protection (measured), so no `rebind_domain` is needed.

Both answer A only. An AAAA (or HTTPS, or any other type) question for one of these names gets no address and is never forwarded upstream, on both paths (measured).

The names follow the device: a device's names point at its fixed address, a device with names must have one, and changing it with `set-ip` moves the names on the next pass. Removing a name, or the device, removes exactly the records curfew created and nothing else. The public Cloudflare record stays: a browser using its own DNS-over-HTTPS never asks the router.

First real use (by the owner, after the gate is green): `curfew update root@192.168.1.1`, then `curfew add-dns-name "workstation igc" '*.lan.telemaque.ska.sh'`, then `curfew push root@192.168.1.1`.

## User Stories

1. As a household admin, I want to give a device a local DNS name such as `*.lan.telemaque.ska.sh`, so that the router answers it for every device on the LAN without asking the internet.
2. As a household admin, I want to add and remove one name at a time from my laptop (`curfew add-dns-name <mac|name> <dns-name>`, `curfew remove-dns-name <mac|name> <dns-name>`), naming the device by its registry name or MAC exactly as `set-ip` does, so that I never hand-edit `devices.json`.
3. As a household admin, I want `curfew push` to apply the names, so that one command I already use makes them live.
4. As a household admin, I want the names to keep resolving after `panic-off` hands port 53 back to dnsmasq, so that the escape hatch does not also hide the studios.
5. As a household admin on a router installed with `-no-adguard`, I want the names to resolve from dnsmasq alone, so that local names do not depend on AdGuard.
6. As a household admin, I want the names to answer with the device's fixed address, and to move with it when I run `set-ip` and push, so that I never maintain the address in two places.
7. As a household admin, I want adding a name to a device with no fixed address refused, and clearing the fixed address of a device that still has names refused, both saying what to run instead, so that a name can never point at an address that might change underneath it.
8. As a household admin, I want an AAAA question for one of these names to get no address from either resolver, and never to be forwarded to an upstream resolver, so that a device never reaches some other machine over IPv6 by the same name.
9. As a household admin, I want a name that is not a valid DNS name, or uses `*` anywhere but one leading `*.`, refused before anything is written, so that a typo cannot reach dnsmasq.
10. As a household admin, I want a name that another device already covers refused, naming that device, so that the router never holds two answers for one name.
11. As a household admin, I want a name under the router's own local domain (`lan` here) refused, so that a curfew record cannot shadow the hostnames DHCP clients register there.
12. As a household admin, I want names the network obviously depends on refused (special-use domains such as `localhost`, `local` and `arpa`, a whole top-level domain, and any name the router itself resolves to keep time or reach its upstream), with the rule explained in the refusal, so that I cannot break the house by accident.
13. As a household admin, I want to be told, without being refused, when a name covers a whole registrable domain (`example.com`, `*.example.com`), so that I notice if I meant something narrower.
14. As a household admin, I want a name that also has a public record to be accepted, with the note that the local answer wins on the LAN, so that I can keep the Cloudflare record for devices that bypass the router.
15. As a household admin, I want a rewrite or dnsmasq entry that curfew did not create, for the same name, to be left alone and reported rather than replaced, so that a hand-made record is never destroyed and never silently fought.
16. As a household admin, I want removing a name, or removing the device, to remove exactly the AdGuard rewrites and dnsmasq entries curfew created for it, and nothing else, so that cleaning up is safe.
17. As a household admin, I want a name added on my laptop and a rename made on the router's page to merge silently on `pull`, so that two unrelated edits are not a conflict.
18. As a household admin, I want the names changed differently on both sides to be a reported conflict that lists both, so that neither edit is lost.
19. As a household admin, I want `push` to refuse when the router's names changed since the last sync, exactly as it does for device names and fixed addresses, so that a router-side edit is never silently overwritten.
20. As a household admin, I want `push` to refuse to send names to a daemon too old to understand them, saying to run `curfew update` first, so that the old daemon's page cannot drop them on its next save and make the next `pull` read that as me deleting them.
21. As a household admin, I want a dnsmasq reload that carries new name records to be checked and rolled back on failure, exactly like a pin, so that a bad record can never leave the house without DHCP, or without DNS when dnsmasq is the resolver.
22. As a household admin, I want the records to survive the install-time move of dnsmasq to port 54 and the rollback to 53 untouched, so that the DNS takeover and local names cannot undo each other.
23. As a household admin on the router's devices page, I want to see each device's names and add or remove them there, with exactly the same checks and messages as the CLI, so that the page and the laptop cannot disagree about what is allowed.
24. As a household admin, I want the daemon to say when AdGuard cannot answer the names for some clients (rewrites switched off, filtering off globally, or a client with filtering off), so that "it works from my laptop" is not mistaken for "it works everywhere".
25. As a household admin, I want a pass with nothing to change to write nothing and reload nothing, so that DHCP is not restarted every minute.
26. As a parent, I want local names to change nothing about schedules, budgets, blocks, tickets or DNS restrictions, so that naming a machine is never a way around a control.

### Autonomy notes

- **`humanOnly: true`.** The owner asked to check the spec before it is tasked, and it changes what the household's resolvers answer. A human drives the tasking.
- **`needsAnswers`:** cleared; the five launch questions were answered (Decisions taken with the owner).

Implementation and testing detail moved to the tasks (`work/tasks/*/` with `spec: local-dns-names-for-a-device`), the durable rationale to ADR 0013 and ADR 0014, and the full launch-time decisions to `docs/spikes/local-dns-names/design-notes.md`.

## Out of Scope

- Pushing to the live router, running `curfew update`, or editing live uci or AdGuard. Only the owner does that, after the verify gate is green.
- AAAA records, and fixed IPv6 addresses. A follow-up if a device's ULA is ever pinned.
- An exact-name-only form (Decision 2).
- CNAMEs, TXT, SRV or any other record type, and names pointing anywhere but the device's own fixed address.
- Reverse (PTR) records for the names.
- Pushing or pulling the AdGuard config itself, or any AdGuard setting curfew does not own (Decision 5).
- Removing the public Cloudflare record. It stays, for DoH clients (Further Notes).
- A Go `panic-off` command. When it is built (ADR 0007) it must leave these entries alone, since they are connectivity rather than policy, exactly as `legacy/scripts/panic-off.sh` already does (it touches `port`, `dhcp_option` and `confdir`, never `address` or `server`).

## Further Notes

- **Relation to `work/specs/proposed/force-dns-through-the-router.md`.** They are complementary and independent; neither blocks the other. That spec makes the router the only reachable plain-DNS resolver, which would extend local names to devices with a hardcoded resolver such as `8.8.8.8` (redirected to the router, they would get the local answer). It deliberately leaves DoH to a literal IP open, and no spec closes browser DoH to a hostname for an unrestricted device (curfew's DoH bootstrap block applies only to restricted profiles). A browser using its own DoH never asks the router, so it sees only the public record: that is why the Cloudflare record is kept, and why it must stay A-only with no AAAA. If that spec's redirect lands, its tests should include one local name, to prove a redirected query is answered locally rather than by upstream.
- **The public record publishes the private address and the name pattern.** That is already true today and this spec does not change it; it is noted so nobody assumes the local names are secret.
- **Clients bypassing AdGuard's rewrites** (Decision 5) still get the right A answer from the public record while it exists, and no AAAA from it, so in practice they work; what they lose is independence from the internet.
- **The `-p 54` check** works on the live router because dnsmasq listens on `192.168.1.1:54` (read from `netstat`) and `localservice='1'` admits the LAN.
- **Likely task cut** (for `to-task`, not binding): (a) registry field, canonicalisation, merge and `Equal`, CLI and old-daemon refusal; (b) validator; (c) dnsmasq rendering and reconcile inside the pins' transaction, with the ledger and the resolver liveness check; (d) AdGuard rewrite reconcile and the bypass report; (e) devices page; (f) the shared `dhcp` lock and the takeover-survival test; (g) acceptance in the image, docs, CONTEXT and README.
- Evidence: `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md`, produced by `docs/spikes/local-dns-names/measure.sh` (full output in `measured-2026-11-18.txt` beside it).
