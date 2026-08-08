---
title: Show devices the router has seen but does not know, and enrol one into a profile in a single action
slug: pending-device-list-and-guided-enrolment
blockedBy: []
covers: []
---

## What to build

The device page can currently only be told about a device: you type a MAC by hand, from memory or from another screen. The router already knows every address on the LAN, so this is work a person does that the machine could do for them, and doing it by hand is how a device ends up registered under a typo and enforcement silently does nothing for it.

Build the other half: a list of devices the router has SEEN on the LAN and the registry does not know about, and an enrolment action that registers one and puts it in a profile in one step.

End to end:

- Read the LAN sightings the router already has: the DHCP lease file (MAC, address, and the hostname the device claims) and the neighbour table (MACs with no lease, which is exactly the case a device with a static address or an expired lease falls into). Union them by MAC.
- Subtract every MAC in the device registry. What is left is the pending list.
- Show it on the device page: the claimed hostname, the address, the MAC, and a flag when the address is **locally administered**, which on a phone means a randomised private Wi-Fi address (`work/notes/findings/wifi-mac-randomisation-is-per-network-and-persistent.md`).
- Enrolling from that list takes a name and a **profile**, registers the device, adds it to that profile, and reconciles the firewall in one action.
- Assigning a profile must be possible but not silently skippable in a way that hides the consequence: a registered device in no profile is an **ungoverned device** with permanently unrestricted access (`docs/adr/0003`), so choosing "no profile" must be an explicit, labelled choice on the form rather than what happens when the field is left alone.

Two things this must NOT do:

- It must not TRUST the hostname. It is the device's own claim about itself, shown to a human as a hint at the moment of enrolment and never stored. `internal/lanhosts` deliberately drops it for that reason, and the reason survives: the only new thing here is that a human is looking at it and can disbelieve it.
- It must not use a sighting-derived address for anything but display. The IPv4-from-leases-only rule in `internal/lanhosts` exists because a stale address would key a DNS restriction to the WRONG CHILD. Nothing on this page keys policy to an address, so an ARP-derived address is safe HERE and must not leak back into that path.

The whole feature must degrade to exactly today's behaviour when the router cannot be read (no lease file, no neighbour table, no runner wired up): an empty pending list and the manual add form, never an error page. Nothing here is load-bearing for whether anybody has internet.

## Acceptance criteria

- [x] Devices in the lease file that are not in the registry appear in the pending list, with their claimed hostname and address.
- [x] A device present only in the neighbour table (no lease) also appears, so a device with a static address is not invisible.
- [x] A registered device never appears in the pending list, whatever the router has seen.
- [x] A locally administered (randomised) address is flagged as such in the list; a globally unique one is not.
- [x] Enrolling from the pending list registers the device AND adds it to the chosen profile AND reconciles, and the device disappears from the pending list afterwards.
- [x] Enrolling with no profile chosen is possible only as an explicit choice, and the form says what that means (allowed always, no schedule, no budget). Enforced in the FORM (a `required` select with no valid pre-selection); on the wire an absent field still means no profile, see Decisions.
- [x] Enrolling into a profile that does not exist is refused with a message, and registers nothing.
- [x] A reconcile failure after enrolment is reported loudly with a non-2xx status, matching the existing add-device handler: registered-but-not-enforced is a state the page must never hide.
- [x] With no observer wired up, the page renders with an empty pending list and no error. It renders with the section ABSENT rather than empty, which is a stronger form of the same criterion; see Decisions.
- [x] An unreadable lease file or neighbour table yields an empty pending list and a logged warning, not a 500.
- [x] Tests cover the new behaviour, in the style of the existing `internal/httpui` tests (real policy layer, kernel replaced by a double) and the existing parser tests (fixture strings, no live router).
- [x] Sighting parsing is tested against fixture text rather than by shelling out, so no test touches the real `/tmp` lease file or the host's neighbour table.

## Blocked by

- None; can start immediately.

## Prompt

> Build a pending-device list and a one-step enrolment action for curfew's device page.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does it still match the code, the ADRs it cites, and the modules it names? If a premise is stale, surface it rather than building on it.
>
> Domain vocabulary you need is in `CONTEXT.md`: **device registry** (the named MACs allowed on the network, the source of the MAC allowlist), **profile** (the named family member that owns a schedule and a budget), **ungoverned device** (a registered device in no profile, allowed always and restricted by nothing), and **the identity bridge** (the join between MAC and IP, whose rules you must not weaken).
>
> Where to look: `internal/registry` owns the device file and MAC canonicalisation; `internal/lanhosts` already parses the DHCP lease file and the IPv6 neighbour table and documents WHY it treats the two address families differently; `internal/httpui` serves the device page, the settings page and the profile handlers, and is tested with the real policy layer behind a fake kernel; `internal/shellrun` is the Runner that lets the same parsing code run over ssh from a laptop or locally on the router.
>
> The seams to test at: the sighting parser (fixture text in, structured sightings out), and the HTTP handlers over a real `httptest` server with the existing doubles. Do not shell out in a test, and do not read the host's real lease file or neighbour table.
>
> Constraints that are not negotiable. The hostname is the device's own claim and is displayed but never stored. An address derived from the neighbour table is display-only and must not reach anything that keys policy to an IP. Registering a device without choosing a profile creates an ungoverned device with unrestricted access, so the form must make that an explicit choice with its consequence written on it, never a default that happens when someone tabs past. The whole feature fails soft: an unreadable router yields an empty list, never an error, because nothing here decides whether anybody has internet.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record: where sighting parsing lives and why it is or is not part of `internal/lanhosts`; what "locally administered" is called in the code and in the UI, given it is evidence rather than proof of randomisation; and how the observer is wired so the page works with it absent.

## Decisions

Each of these is written durably at the choice site; they are summarised here so a reviewer does not have to go looking.

**Sighting parsing lives IN `internal/lanhosts`, in its own file, with a doc comment that states the inversion.** The alternative was a new package, to protect that package's very deliberate rules: IPv4 only ever from the lease file, hostname always discarded. Both rules exist because a wrong answer there keys a DNS restriction to the WRONG CHILD. A sighting inverts both (it DOES read the neighbour table, and it DOES carry the hostname), and that is safe only because nothing derived from it keys any policy to any address. Splitting it out would have duplicated the lease-line and neighbour-line formats, which is a live drift risk in a file format neither we nor OpenWrt controls. Co-locating them, with the reasoning written between them, keeps one parser per format and puts the two contradictory rule sets where a reader will meet both.

**"Locally administered" is the name in the code (`registry.LocallyAdministered`) and "randomised" is the word in the UI.** The code name is what the bit factually means; the UI word is what it means in this house. The doc comment says plainly that it is evidence and not proof, and names the other things that set it (a hand-set address, a VM bridge, a container). Nothing decides anything by it. Grounded in `work/notes/findings/wifi-mac-randomisation-is-per-network-and-persistent.md`, where Android's own documentation confirms randomisation sets exactly this bit.

**The observer is an optional function on the server (`UseLANSightings`), and absent renders the section ABSENT rather than empty.** "curfew is not looking" and "curfew looked and found nothing" are different states, and an empty table would claim the second while meaning the first: this project's recurring bug in miniature. It is wired unconditionally in the daemon, independent of AdGuard, because the lease file and the neighbour table exist whether or not AdGuard does.

**Enrolment writes the PROFILE before the REGISTRY, which is the opposite of the obvious order.** Two writes to two files can be interrupted between them, and the two orders fail in opposite directions. Registry first leaves a device registered and in no profile: an ungoverned device with permanently unrestricted access, strictly more internet than anyone asked for. Profile first leaves a profile naming a MAC that is not in the registry, so the MAC never reaches `allowed_macs` and the device gets nothing at all. Fail closed on the control. The rationale is written on the handler.

**Profile select values are namespaced (`p:<name>`, plus the bare sentinel `none`).** Using profile names as select values directly would make a household profile called `none` indistinguishable from no profile at all. The prefix makes the collision impossible by construction rather than by hoping nobody picks that word, and a test pins it.

**An absent `profile` form field still means no profile; an UNREADABLE one is refused.** The `/devices` endpoint keeps its original contract, so everything that posts a bare MAC behaves as before, and the explicit-choice property is carried by the form. The asymmetry is deliberate: "no profile" is the permissive answer, so it is never GUESSED from an input nobody understood, and registering with no profile is logged as such. The standing visible consequence already exists on the home page, which counts registered devices belonging to no profile.

## What is NOT in this

A "first seen" column, deliberately. It needs persistence the router does not have (the lease file records an expiry, not a first sighting), and inventing it from daemon uptime would produce a number that resets on restart and reads as fact. Left out rather than approximated.
