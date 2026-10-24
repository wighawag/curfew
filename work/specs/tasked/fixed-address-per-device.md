---
title: Let a household choose a device's IPv4 address, and stop pins vanishing when a device is offline
slug: fixed-address-per-device
promptGuidance.testFirst: true
---

> Launch snapshot: records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked.)

Built directly from this spec (no tasks were cut) and released in curfew v0.13.0, commit 257185d. Durable decisions: `docs/adr/0012-a-pin-outlives-its-device-being-away-and-a-household-can-choose-the-address.md`.

## Decisions (answered by the owner, 2026-10-23)

1. **Identity bridge during a move:** the lease-attested union. Recorded as ADR 0012.
2. **A requested fixed address already held by another device's pin:** refused, naming the holder. Never displaced.
3. **The printer:** restored to `192.168.1.10` as part of the first real use.


## Problem Statement

A household member needs a machine at a known address. shyrka (eno1 `84:47:09:84:8e:b2`) runs a llama.cpp server bound to the literal `192.168.1.150`, and every peer's `models.json` and every anonctl exemption names `192.168.1.150:8080` (anonctl rejects hostnames). After a reboot shyrka came up at `192.168.1.226`, the server could not bind, and inference went down for the whole household.

There is no way to tell curfew "this MAC must be 192.168.1.150". And there is no way to do it by hand either, because curfew pins every registered device itself, and a hand-made reservation for a registered MAC is yielded to as a conflict and reported every minute for ever.

### Diagnosis of the incident (read from the live router, 2026-10-23 19:07 local, router up 7h11)

- **There was never a reservation for .150 that curfew would have kept.** Every `config host` section on the router is a `curfew_*` section (18 of them); there is no foreign entry at all. The assumed "router reservation" in my-boxes was never in force as configuration.
- **shyrka is registered** in `/etc/config/curfew/devices.json` (`"name": "shyrka"`, no address field, because none exists), so curfew pins it. It is pinned today as `dhcp.curfew_844709848eb2.ip='192.168.1.226'`, which is simply what it observed. Its lease is `192.168.1.226`; nothing holds `.150`.
- **The mechanism is a defect in `leases.Reconcile`, reproduced in a unit test.** The address passed to `Reconcile` is only the one in `/tmp/dhcp.leases` this tick. A registered device with no current lease is put in `Unaddressed`, so its owned section is not "wanted", and the stale-entry sweep deletes it. One tick later the device is back at whatever dnsmasq gave it and curfew pins that instead:
  - tick with shyrka pinned at .150 but no lease: `uci -q delete dhcp.curfew_844709848eb2 || true`
  - next tick, shyrka at .226: `uci set dhcp.curfew_844709848eb2.ip='192.168.1.226'` (and the rest of the section).
- **The router reboots wipe `/tmp/dhcp.leases`**, and a lease also leaves that file when it expires or the client releases it. So every pin of every device that is not currently holding a lease is deleted. The daemon's own log confirms the scale: **28 registered devices are reported "with no DHCP lease" on every tick, and none of them has a pin.** The pins that exist are only the devices online right now. A "pinned lease" today is a mirror of the lease file, not configuration.
- **shyrka is not the only victim.** The printer `f8:25:51:09:38:38` was pinned at `192.168.1.10` by the legacy shell tool (ADR 0011 records it), was adopted with `curfew adopt-leases`, and is now `dhcp.curfew_f82551093838.ip='192.168.1.129'`. Adoption made it curfew's, and the sweep then dropped it like any other.
- The exact moment shyrka's .150 pin was dropped is not recoverable: `logread` is a ring buffer cleared by the router's reboot, and shyrka came up at .226 before that reboot. Whether it was a DHCP release on shyrka's shutdown or a lease expiry, the effect is the same sweep.

So the answer to "why was .150 lost" is: **curfew pinned .150 because it observed it, then deleted that pin the first time shyrka was briefly absent from the lease file, then pinned .226 because that is what it observed next.** ADR 0011's premise, "IPv4 comes from configuration curfew owns", has not been true in practice.

## Solution

Two changes, shipped together because the first is useless without the second.

1. **A fixed address**: an optional, user-chosen IPv4 address on a registered device. When set, curfew pins exactly that address, validates it before any uci write, and reports when the device will actually move. Set from the laptop with `curfew set-ip`, carried by `push`/`pull`, and settable on the router's devices page.
2. **Owned pins are sticky**: a curfew-owned host section is deleted only when its device is deregistered, never because the device has no lease this tick. An offline device keeps its address, which is what a "pinned lease" was always meant to mean.

First real use (only on an explicit go-ahead): `curfew update`, then `curfew set-ip shyrka 192.168.1.150` and `curfew set-ip <printer> 192.168.1.10`, then `curfew push`.

## User Stories

1. As a household admin, I want to say "84:47:09:84:8e:b2 must be 192.168.1.150", so that a service bound to that literal address survives reboots of either machine.
2. As a household admin, I want to name the device by its registry name or its MAC (`curfew set-ip shyrka 192.168.1.150`), so that I do not have to look the MAC up.
3. As a household admin, I want `curfew set-ip shyrka --clear` to remove the fixed address without moving the device, so that clearing is never itself an outage.
4. As a household admin, I want a fixed address outside the LAN subnet, equal to the network or broadcast address, or equal to the router's own address, to be refused before anything is written, so that a typo cannot break DHCP.
5. As a household admin, I want a fixed address already used by ANY host entry (curfew's or a foreign one) or by another device's fixed address to be refused, naming who holds it, so that dnsmasq never sees two reservations for one address.
6. As a household admin, I want to be warned (not silently proceed) when another MAC currently holds the address in the lease file, including when that lease expires, so that I know the move cannot complete until then and how to make it sooner.
7. As a household admin, I want to be told when the address is inside the DHCP pool, so that I know it is allowed (dnsmasq honours it) and why it is mentioned.
8. As a household admin, I want to be told that the device only moves on its next DHCP renewal, roughly when that is, and how to force it, so that I am not left wondering why nothing happened.
9. As a household admin, I want a device that is switched off, or a router that has just rebooted, to keep every pin curfew owns, so that devices come back at the same address.
10. As a household admin, I want a fixed address changed on my laptop and a rename made on the router page to merge silently on `pull`, so that two unrelated edits are not a conflict.
11. As a household admin, I want a fixed address changed differently on both sides to be a reported conflict that names both values, so that neither edit is lost.
12. As a household admin, I want `push` to refuse when the router's fixed addresses changed since the last sync, exactly as it already does for names, so that a router-side change is never silently overwritten.
13. As a household admin, I want `push` to refuse against a daemon too old to know about fixed addresses, so that the old daemon's page cannot drop the field on its next save and make the next `pull` look like I cleared it.
14. As a household admin on the router's page, I want to see each device's fixed address (or "none", plus the address it is pinned at) and to set or clear it there, with exactly the same validation and the same warnings, so that the page and the CLI cannot disagree about what is allowed.
15. As a parent, I want a child's DNS restriction to keep applying while their device moves from its old address to a new fixed one, so that changing an address is not a way to escape a restriction.
16. As a parent, I want a restriction never to land on a device other than the one it was meant for during that move, so that the "wrong child" failure ADR 0011 guards against cannot be reintroduced.
17. As a household admin, I want foreign host entries to remain untouched and a foreign entry for a MAC that also has a fixed address to be yielded to and reported as a conflict, with `curfew adopt-leases` remaining the only way to take it over, so that the ownership promise of ADR 0011 still holds.
18. As a household admin, I want a pass with nothing to change to write nothing and reload nothing, so that DHCP is not restarted every minute.
19. As a household admin, I want a fixed address that fails validation on the router (for example a hand-edited `devices.json`) to be skipped and reported by the daemon rather than written, so that defence in depth does not depend on the laptop having checked.

### Autonomy notes

- **`humanOnly`:** not set. The tasking is straightforward once the open questions are answered.
- **`needsAnswers`:** cleared; the three open questions were answered (see Decisions).

## Implementation Decisions

### Data model

- `registry.Device` gains `ip` (`json:"ip,omitempty"`), the **fixed address**. Absent means "curfew pins whatever the device holds", exactly as today. It lives in the device registry because it is a property of one device, travels with push/pull for free, and needs no new file (ADR 0008). Rejected: a separate `leases.json` keyed by MAC, because it would need its own sync and merge path, and a device's address belongs to the device exactly as its name does.
- The registry's mutation API gains a strict `SetIP(mac, ip)` (empty clears), strict like `Rename`: setting an address on an unregistered MAC is an error rather than a quiet insert, for the same resurrection reason. Load canonicalises the address (`netip.ParseAddr`, IPv4 only, `Unmap`), so two spellings cannot compare unequal.
- Name resolution for `<mac|name>`: an exact MAC match first, else a unique case-insensitive name match; an ambiguous name is refused, listing the candidate MACs.

### Reconcile: what address a device is pinned at

The precedence per registered device is **fixed > observed > existing owned pin > unaddressed**:

- **fixed** set and valid: pin it.
- otherwise **observed** in the lease file: pin it (today's behaviour, ADR 0011's "pin what it already holds"; also what makes `--clear` never move a device).
- otherwise an **existing owned section**: keep it unchanged. This is the fix for the incident. The device is NOT reported as unaddressed; it is pinned.
- otherwise **unaddressed**, as today.

Deletion of an owned section happens only when its MAC is no longer registered.

Reconcile also refuses, rather than emits, anything that would make two host entries carry one address: a fixed address that collides is skipped and reported (`Plan.Refused`), and an **observed** address that equals another device's fixed address (the squatter, story 6) is not pinned for the squatter. dnsmasq's behaviour on a duplicate `dhcp-host` address is to be measured in the container before relying on Apply's rollback for it: a refusal that recurs every tick would otherwise become a dnsmasq restart and rollback every minute.

The NO `name` rule, the `curfew` marker, the per-MAC section name and the Apply liveness check plus rollback are all unchanged.

**Fixed addresses do not depend on AdGuard** (found while building: lease pinning only ran inside the AdGuard layer). With AdGuard off the daemon runs the same pinning pass on its own loop, taking no new pin from an observed address because nothing would use one. **A swap needs two pushes:** moving A off X and giving X to B in one push is refused, because A's pin still holds X when B is checked.

### Validation (one pure function, three callers)

A single pure validator in the leases package takes the requested fixed addresses, the parsed host entries, the LAN definition and the lease file, and returns hard errors and warnings. The same function is called by `push` (laptop, reading the router over ssh before anything is written), by the page's handler (router, before saving the registry), and by Reconcile (every tick, as defence in depth).

- **LAN** comes from `uci show network.lan`, never hardcoded: `ipaddr` in CIDR form (`192.168.1.1/24`, as on the live router) or `ipaddr` plus `netmask`. The router's own address is that `ipaddr`. The pool comes from `dhcp.lan.start`/`limit` (live: `.100` to `.249`), and the lease time from `dhcp.lan.leasetime` (live: `12h`).
- **Hard errors:** not a valid IPv4; outside the LAN subnet; the network or broadcast address; the router's own address; equal to the `ip` of ANY host entry other than this MAC's own section, owned or foreign; equal to another device's fixed address.
- **Warnings:** another MAC holds the address in `/tmp/dhcp.leases` (with that lease's expiry; the move completes when it expires or that device renews elsewhere); the address is inside the DHCP pool (allowed, dnsmasq honours it); this device currently holds a different address and will move on its next renewal, roughly at T1 (half the lease time), and can be forced by renewing on the device (`networkctl renew <if>`, `dhcpcd -n <if>`, or reconnecting Wi-Fi/cable).

### The identity bridge while a device moves (amends ADR 0011)

Changing a fixed address opens a window in which the device still holds its old lease. ADR 0011 currently sends AdGuard only the pinned address, so for that whole window (up to T1) the device's IPv4 queries would be unrestricted, and as soon as the old address is reissued it could become the wrong child's.

Decided rule, recorded as **ADR 0012, amending 0011**: an IPv4 address is attributed to a device's AdGuard client if and only if

- (a) the lease file shows THIS MAC holding it, or
- (b) it is this device's pin AND the lease file shows no OTHER MAC holding it.

So during a move the client carries both the old leased address and the new pin; when the device renews, the old address leaves the lease file and leaves the client on the next pass; and an address someone else holds is never attributed to the pinned owner (the squatter). A dnsmasq reservation is never handed to another MAC, which is why (b) is safe while the pinned device is offline.

The residual risk, stated plainly in the ADR: between the device's renewal freeing the old address and curfew's next pass (one tick), dnsmasq could reissue that exact address to another device, whose queries would be attributed to the moving device's profile for under a minute. With sticky pins, the only devices that still get dynamic addresses are unregistered ones (dropped by nftables anyway) and newly registered ones not yet pinned, so the exposure is narrow; it is also strictly smaller than today, where every pin follows the lease file and the same race exists on every address change. The pin-only alternative (rejected, decision 1) removes this race at the cost of the move window failing open.

This keeps 0011's asymmetry: IPv4 still never comes from ARP or the neighbour table, and the lease file is the DHCP server's own record of who holds what.

### Surfaces

- **CLI:** `curfew set-ip <mac|name> <ip>` and `curfew set-ip <mac|name> --clear`, editing the local device file only (`-registry` flag, same default as push/pull), validating what it can offline (syntax, uniqueness among local fixed addresses) and saying that `curfew push <host>` applies it. The name fits the command table: lowercase verb-noun with a hyphen like `adopt-leases`, and it is the first command that edits the local file, so it runs on the laptop and takes no host.
- **push:** before writing, reads `uci show network.lan`, `uci show dhcp` and the lease file over ssh, runs the validator, refuses on any hard error, and prints the warnings and the "moves on next renewal" note per changed device. Refuses against a daemon that does not report fixed-address support.
- **pull/push sync:** `Merge3` and `Equal` compare the device per FIELD (name and ip), so a rename on one side and an address on the other both apply; a field changed differently on both sides is a conflict whose report names both values (new kind, "fixed address changed differently on both sides"). `push`'s "router changed since last sync" check uses the same `Equal`, which is what closes story 12.
- **Router page:** the devices page shows the fixed address per device (or "none" with the address it is currently pinned at) and a set/clear form. The handler validates with the router's own uci and lease data through the same validator and shows the warnings after saving.
- **Docs:** the README command table gains `curfew set-ip`; the "pinned lease" paragraph is corrected (pins are sticky). CONTEXT.md: "pinned lease" is updated (sticky; its address comes from the fixed address when set, else what the device held when first pinned), and a new term **fixed address** is added (the user-chosen IPv4 address on a registered device, which curfew pins and validates). ADR 0012 records the sticky-pin decision and the move-window rule.

## Testing Decisions

Test-first (`promptGuidance.testFirst`). Tests assert external behaviour: the uci commands a plan emits, the registry a merge produces, what reaches AdGuard, and what lands in a real `/etc/config/dhcp`.

- **Reconcile unit tests:** an offline registered device with an owned pin keeps it and emits nothing (the incident, as a regression test); a deregistered device's pin is still removed; a fixed address is pinned over an observed one; clearing a fixed address keeps the device where it currently is; a fixed address equal to a foreign entry's or another device's address is refused and reported, never emitted; the squatter's observed address is not pinned when it equals another device's fixed address; a foreign entry for a fixed-address MAC is yielded to and reported; a converged state emits no commands; no command ever sets `name`.
- **Validator unit tests:** subnet from both `ipaddr` CIDR and `ipaddr`+`netmask`; network, broadcast and router addresses refused; duplicates across owned, foreign and fixed refused; in-pool warning; held-by-another-MAC warning with expiry; the will-move warning.
- **Identity bridge unit tests (in dnspolicy, next to the existing "observed-but-unpinned IPv4 never reaches AdGuard" test):** during a move both the old leased and the new pinned address are attributed; after renewal only the new one; an address the lease file shows another MAC holding is never attributed to the pinned owner.
- **Merge unit tests:** ip changed on one side and untouched on the other merges; a rename on one side and an ip on the other merges; ip changed differently on both sides is a conflict that names both values; `Equal` sees an ip-only difference.
- **Acceptance test in the real OpenWrt container** (`docker/acceptance.sh`, real uci and dnsmasq): a fixed address lands in `/etc/config/dhcp` as `config host 'curfew_<mac>'` with the address and the `curfew` marker and no `name`; dnsmasq is running afterwards; a pre-existing foreign host entry is byte-for-byte unchanged; a duplicate address is refused and nothing is committed. Also measured there, and recorded as a finding: what dnsmasq does with two `dhcp-host` lines for one address, and that a client holding an old lease is NAKed onto its new fixed address on renewal (via a DHCP client in a netns), so the "moves on next renewal" message is measured rather than assumed.
- **Isolation:** tests use temp registry files and the container's own uci; nothing touches `~/.config` or a live router.

## Out of Scope

- Pushing to the live router, running `curfew update`, or editing live uci. Only on the owner's explicit go-ahead, after the verify gate is green.
- Fixed IPv6 addresses. IPv6 identity stays as ADR 0011 decided (followed, not pinned).
- Writing a sanitised hostname into the host entry. Still deliberately not done (see the comment on Reconcile).
- Re-pinning the 28 currently unpinned devices to any particular address. With sticky pins they are pinned at whatever they next hold and then keep it.
- Stopping Apply from retrying a rolled-back plan every tick. Worth its own observation if the duplicate-address measurement shows it matters.

## Further Notes

- The old daemon drops unknown JSON fields when its page saves the registry, which is why `push` must refuse against it (story 13) and why the order on the live router is `curfew update` first, then `curfew push`.
- my-boxes' `hosts/shyrka/default.nix` comment says .150 "depends on a DHCP reservation on the OpenWrt router". After this lands that becomes true, and the comment should name curfew as the owner.
