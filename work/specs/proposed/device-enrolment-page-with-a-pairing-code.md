---
title: An unregistered device gets a page that tells it what to do, and a code an admin can match
slug: device-enrolment-page-with-a-pairing-code
humanOnly: true
needsAnswers: true
taskedAfter: []
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

1. **Does the enrolment page stay behind the password, or become the second unauthenticated route?** It has to be reachable by a device that has no internet and no credentials, which argues for open. But every other route on this server is closed precisely because a blocked device can reach it (`internal/httpui` doc comment), and `ServeFilterList` is documented as "one route outside the password, and only one". Opening a second one needs a decision recorded the same way: what it discloses, and why that is acceptable. The page as specified discloses only the requester's own pairing code and generic instructions, and never another device's existence.
2. **Does the pairing code prove enough?** It proves the holder can see the screen of the device asking to be enrolled. A child can screenshot it and send it to a parent claiming it is the printer. Is "the admin must physically look at the device" a rule the household will actually keep, or does the confirm screen need to carry more (hostname, when it joined, whether the address is randomised) and rely on the admin reading it?
3. **What happens to a device that is registered but currently blocked and loads this page?** It must NOT be offered enrolment (it is already enrolled) and it must not be told "you are blocked by bedtime" in a way that teaches a child which lever to pull. The honest minimum is probably "this device is known; it has no internet right now", with nothing actionable.
4. **Is a memorable hostname worth the dnsmasq/AdGuard entry?** `setup.lan` resolving to the router is two lines of config but adds a name curfew owns in a resolver curfew shares with the household, and ADR 0010 is emphatic about not owning objects we did not create.
5. **Rate limiting.** The page mints a short-lived code per requesting MAC. A device refreshing in a loop should not be able to fill a code table or churn the admin list. What is the cap, and is a fixed-size table with oldest-eviction enough?

<!-- /open-questions -->

## Problem Statement

A device that is not in the device registry joins the household Wi-Fi, gets an address, and has no internet. Nothing tells it why. From the owner's side the network is simply broken, and the only recovery is knowing that a page exists at an IP address nobody has memorised. A visitor cannot self-diagnose, a new phone looks like a hardware fault, and a family member whose device rotated its Wi-Fi address (see `work/notes/findings/wifi-mac-randomisation-is-per-network-and-persistent.md`) silently drops off the network with no signal to anyone.

Meanwhile the admin, looking at the pending-device list on the settings side, sees a row of unfamiliar hex. When two unknown phones join in the same evening there is nothing on the screen that says which row is which person.

Both halves are the same missing piece: a channel between the device that wants in and the adult who decides.

## Solution

The unregistered device loads a page (told to, or dragged there by a later mechanism) that says, in plain language: this network only allows known devices, ask whoever runs it to approve this one, and show them **code 4821**. Nothing on that page grants anything, and nothing on it identifies any other device.

The admin, on the password-protected pending-device list, sees the same code next to the row for that device, alongside its hostname, its address, and whether the address looks randomised. They pick a name and a profile and approve it. The child's device is now enrolled, in a profile, with a bedtime.

The asymmetry is the point. The device can only ASK, and the only thing it can do to help is display a number. Every grant happens on the authenticated surface. A device can never enrol itself, which is the property the whole MAC allowlist exists to protect, and which any self-service flow would give away.

## User Stories

1. As the owner of a device with no internet, I want a page that tells me what is wrong and what to do about it, so that I do not assume the network is broken.
2. As the owner of that device, I want a short code on screen, so that I can tell the person who runs the network which device is mine without reading out twelve hex digits.
3. As an admin approving a device, I want the code shown next to the row in my pending list, so that I approve the right device when several unknown ones are present.
4. As an admin, I want to see the device's DHCP hostname and address next to the code, so that I have a second signal when the code cannot be read out (an appliance with no screen).
5. As an admin, I want the code to expire, so that a screenshot taken last month cannot be used to get a device approved today.
6. As an admin, I want to be told when a device's address looks randomised, so that I understand why an approved device may need approving again after a factory reset.
7. As the owner of a device, I want to be told how to stop my address changing on this one network, so that I do not have to be approved twice.
8. As a parent, I want the enrolment page never to grant access on its own, so that a child cannot walk their own device onto the network.
9. As a parent, I want the enrolment page to disclose nothing about other devices, so that it does not become a map of the household.
10. As a device owner, I want to reach the page by a name rather than an IP address, so that it can be told to me over the phone.
11. As an admin, I want a device that is already registered to get an honest, non-actionable message rather than an enrolment offer, so that a blocked child is not handed a re-enrolment path.
12. As an admin, I want approving from this flow to go through the same code path as approving from the pending list, so that the two cannot drift on what "approved" means.

### Autonomy notes

`humanOnly: true`: this spec opens a network surface reachable by devices that are deliberately being kept off the internet, and question 1 is a trust-boundary decision. A human must drive the tasking.

`needsAnswers: true`: the questions above are judgement calls the spec cannot make for the household, and two of them (1 and 3) change what gets built rather than just how.

## Implementation Decisions

- **The code is minted server-side and bound to the OBSERVED MAC**, resolved from the requester's address the same way the DNS bridge resolves it. The code is the key; the MAC is never accepted from the request. This closes the shape the first sketch of this feature had, where a URL carried `?mac=` and the handler trusted it, making the URL a forgeable instruction to allowlist an arbitrary address.
- **Codes live in memory with a short TTL** (minutes). They are runtime state that is MEANT to die with the router, like tickets, so they never touch `/etc/config`. A device that reloads the page inside the TTL gets the SAME code, or the number on the screen would stop matching the number the admin is reading.
- **Approval reuses the enrolment path built for the pending list**: register the device with a name, add it to a profile, reconcile. No second implementation of "approve", and in particular no path that registers a device into no profile, which would create an ungoverned device with permanently unrestricted access.
- **The page is static, local, and tiny.** It is loaded precisely when the device has no internet, so no CDN, no external font, no favicon fetch. Same constraint the status page carries.
- A QR code is explicitly NOT part of this. It was the original sketch, and a pairing code does the same job (bind the screen in front of you to the row on the admin's phone) with no encoder dependency and no MAC in any URL. If a QR is wanted later it is a rendering change over the same nonce.

## Testing Decisions

- Drive the page over a real HTTP server, as `internal/httpui` already does, asserting: an unregistered requester gets a code; the same requester gets the same code twice; a registered requester gets the non-actionable message and no code; an expired code is gone.
- Assert that no route in this flow mutates the registry. The enrolment page must be provably read-only: a test that POSTs at it and asserts nothing changed is the one that stops a future refactor turning it into a grant surface.
- Address-to-MAC resolution is tested against a fixture, matching the existing pattern of passing the lease path and interface in rather than assuming them.
- If the page becomes unauthenticated, a test must assert that EVERY other route still demands the password, mirroring the existing filter-list exemption test.

## Out of Scope

- Auto-navigation. The device is TOLD where to go here; being dragged there is `work/specs/proposed/announce-enrolment-through-the-captive-portal-api.md` and, only if that proves insufficient, `work/notes/ideas/intercept-connectivity-probes-to-force-the-enrolment-page.md`.
- Guest passes. A time-limited grant to an UNREGISTERED device is a different feature with a different tier in the chain, and it carries a bedtime-bypass hazard this flow deliberately avoids by never granting anything. See `work/notes/ideas/rich-status-page-guest-access-and-config-ownership.md`.
- Making enrolment survive a MAC rotation. That is `work/notes/ideas/per-device-psk-makes-identity-survive-mac-rotation.md`, and if it is adopted this page becomes the exception path rather than the routine one.
