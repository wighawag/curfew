---
title: Announce the enrolment page through the captive-portal API, so a device opens it by itself
slug: announce-enrolment-through-the-captive-portal-api
needsAnswers: true
taskedAfter: [device-enrolment-page-with-a-pairing-code]
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks.

<!-- open-questions -->
<!--
  TRANSIENT BLOCK — stripped by the apply rung on full resolution.
  While the spec has unresolved questions blocking autonomous tasking:
    1. Set `needsAnswers: true` in the frontmatter above.
    2. List the questions under the `## Open questions` heading below.
    3. Clear the flag (and let apply strip this block) once they are answered.
  Delete the whole fenced block — markers and all — if the spec launches fully resolved.
-->

## Open questions

1. **Which of this household's devices actually honour DHCP option 114?** The whole feature is advisory, so its value is an empirical question about the phones and laptops in this house, not about the standard. This must be measured before the work is sized: hand out the option, join with each device, and observe whether the sheet appears. If the answer is "almost none", this spec should be dropped in favour of just telling people the address.
2. **Does an unauthenticated JSON endpoint that answers per-requester count as disclosure?** It tells the requester whether their own device is registered. That is the same disclosure the enrolment page already makes to the same requester, but it is worth deciding once rather than twice.
3. **Does handing the option to EVERY device cause any harm to a registered one?** The intended answer is no: a registered device fetches the API, is told it is not captive, and carries on. But an OS that reacts badly to a captive-portal API on a network that works is a household-wide regression, so it needs observing rather than assuming.
4. **Does curfew own the dnsmasq option, and how?** Writing option 114 means curfew editing the household's `dhcp` uci config. There is precedent (`internal/leases` writes host sections it owns and names) but this is a different KIND of edit: a global option on a config section curfew did not create. What is the ownership marker, and what happens if the household set option 114 themselves?
5. Does the IPv6 route-advertisement half (the RA option) matter here, or is DHCPv4 enough given every device on this LAN gets a v4 lease?

<!-- /open-questions -->

## Problem Statement

Once the enrolment page exists, a device with no internet still has to be TOLD to open it. Someone has to know the address, be present, and say it out loud. That fails exactly when it is most needed: a visitor whose host is in another room, a child's new phone at 7am, an appliance nobody is watching.

The familiar fix is the "Sign in to network" sheet that appears by itself on joining a hotel or cafe network. Historically that is produced by intercepting and lying to the device's connectivity probe, which means rewriting packets: a new nftables table in a new hook, a DNS hijack, and a failure mode that silently breaks HTTP for the whole household if the match is too wide.

There is a standards-based alternative that produces the same sheet with no packet rewriting at all, and it should be tried first.

## Solution

The DHCP server hands every client a captive-portal API URL as part of its lease (RFC 8910, DHCP option 114). A device that supports it fetches that URL and gets a small JSON document (RFC 8908) that says whether it is captive and, if so, where the user-facing page is.

curfew answers that endpoint per requester, resolving the requesting address to a MAC the same way everything else in this system does:

- an **unregistered** device is told it is captive, and pointed at the enrolment page from the sibling spec;
- a **registered** device is told it is not captive, and its OS says nothing at all.

No DNAT, no DNS interception, no certificate errors, no third nftables table, and nothing that can break a working device's HTTP. The cost is that it is advisory: a device that does not implement RFC 8910 simply ignores the option and behaves exactly as it does today, which is the current experience rather than a worse one.

That fail-soft property is why this is worth doing before the interception route, and why the interception route stays an idea rather than a spec (`work/notes/ideas/intercept-connectivity-probes-to-force-the-enrolment-page.md`).

## User Stories

1. As the owner of a new device, I want my phone to open the enrolment page by itself when I join, so that I do not need to be told an address.
2. As a visitor, I want the same, so that I can ask for access without first asking how to ask for access.
3. As a member of the household with a registered device, I want nothing to happen at all when I join, so that the feature is invisible to everyone it does not concern.
4. As a parent, I want the announcement to point only at a page that GRANTS NOTHING, so that making enrolment easier to find does not make it easier to obtain.
5. As an admin, I want a device whose OS ignores the announcement to be no worse off than today, so that the feature cannot regress anyone.
6. As an admin, I want to turn the announcement off, so that if it misbehaves on some device the recovery is a setting rather than a rebuild.
7. As an admin, I want curfew's edit to the DHCP configuration to be recognisable as curfew's, so that it can be removed cleanly and cannot be confused with something the household wrote.
8. As an admin, I want the endpoint to disclose nothing about devices other than the requester, so that it is not a way to enumerate the household.

### Autonomy notes

`needsAnswers: true`: question 1 is a measurement that decides whether the feature is worth building at all, and question 4 is an ownership decision about editing a config section curfew did not create. Neither can be settled by the tasker.

`humanOnly` is deliberately NOT set: once those questions are answered, the work itself (one handler, one config edit, tests) is ordinary and agent-buildable.

## Implementation Decisions

- **The API document is generated, never stored.** It is a function of "is this requester's MAC in the registry", asked at request time, so it cannot go stale.
- **The requester's MAC is resolved, never accepted.** Same rule as everywhere else in this system: an address in a request is an observation the router makes, not a claim the client gets to state.
- **`no-store` on the response.** A cached "you are captive" served to a device that has since been approved would leave a nagging sheet with nothing behind it.
- **The option is written into uci with an ownership marker**, following the precedent set by `internal/leases`: curfew edits only what it can prove it wrote, and yields to a value the household set itself rather than overwriting it.
- **Off is a supported state and must be reachable without a rebuild**, since this touches the DHCP path that every device on the LAN depends on.

## Testing Decisions

- The endpoint is driven over a real HTTP server against a lease fixture: registered requester gets not-captive, unregistered gets captive plus the portal URL, unresolvable requester gets a refusal rather than a guess.
- The JSON is asserted for shape, not just for a substring, since it is consumed by an OS that will silently ignore anything malformed.
- The uci edit is tested the way `internal/leases` is: against the real OpenWrt image, asserting that a pre-existing option the household set is not clobbered and that curfew's own is removable.
- Whether the sheet actually appears is NOT unit-testable and must not be faked. It is the live-router measurement in question 1, and its result belongs in `work/notes/findings/`.

## Out of Scope

- Probe interception and DNS hijacking. Deliberately excluded; the whole point of this spec is to try the non-invasive route first. See the idea note.
- Granting anything. This announces where to ask; it does not change who is allowed out, and it must never gain the ability to.
- The enrolment page itself, which is `work/specs/proposed/device-enrolment-page-with-a-pairing-code.md` and is a prerequisite (`taskedAfter`), since announcing a page that does not exist is worse than announcing nothing.
