---
title: Intercept OS connectivity probes so an unenrolled device is dragged to the enrolment page
slug: intercept-connectivity-probes-to-force-the-enrolment-page
---

Make an unregistered device pop the operating system's "Sign in to network" sheet the moment it joins, by answering its captive-portal probe wrongly and redirecting its plaintext HTTP to curfew's enrolment page.

Held as an idea rather than a spec **on purpose, and conditionally**: it should only be built if the standards-based announcement in `work/specs/proposed/announce-enrolment-through-the-captive-portal-api.md` is measured on this household's real devices and found not to fire reliably enough. It is strictly more invasive for the same outcome, so it needs evidence before it earns its complexity.

## Why anything is needed

An unregistered device today has a working Wi-Fi association, a DHCP lease, a reachable router web server, and no internet, with nothing telling it why. The `forward`-hook drop is LAN-to-WAN only, so the device can reach curfew's page but is never sent there. The experience is "the Wi-Fi is broken", and the recovery is knowing to type an IP address.

## The mechanism

Every desktop and mobile OS fetches a known plaintext HTTP URL immediately after joining a network and decides "captive" if the answer is not the expected one:

- Apple: `captive.apple.com/hotspot-detect.html`, expecting a body containing `Success`.
- Android: `connectivitycheck.gstatic.com/generate_204`, expecting HTTP 204.
- Windows: `www.msftconnecttest.com/connecttest.txt`.

Answering those wrongly is what makes the sheet appear. Doing it selectively needs a **`nat prerouting`** hook that matches on the source MAC not being in `allowed_macs`, and for that traffic redirects DNS to a resolver that answers a wildcard, and TCP/80 to curfew's own listener, which serves a redirect to the enrolment page.

That is a genuinely new thing in this system. Everything curfew does today is one `filter`-priority table plus a counters-only table; this adds a THIRD table in a different hook family that rewrites packets rather than accepting or dropping them.

## Why it is held back

- **A new failure mode with a blast radius.** A prerouting redirect that matches too widely breaks HTTP for the whole household silently: pages resolve, connect, and return the wrong site. That is worse than the bug class this project exists to remove, because it looks like the internet being flaky rather than like curfew being wrong.
- **It needs its own packet-path tests, in both directions.** ADR 0004 is not satisfied by "the redirect rule exists". The tests that matter are: an unregistered MAC's TCP/80 arrives at curfew's listener; and a REGISTERED MAC's TCP/80 reaches the real destination untouched. The second is the regression that would otherwise take out every HTTP service in the house.
- **`ether saddr` in `nat prerouting` is an assumption, not a fact.** Whether a source MAC match works in that hook on the Flint 2's bridged LAN has to be MEASURED before any design rests on it. If it does not, the selectivity has to come from somewhere else (an IP set kept in step with the leases, which is a whole second consistency problem).
- **HTTPS is a hard ceiling anyway.** A user whose first action is opening an `https://` URL gets a certificate error, not a portal, so this improves the probe path only. Anyone who dismisses the sheet still has to be told an address.
- **It overlaps with `opennds`.** The OpenWrt package does all of this already, and is rejected for a specific reason rather than NIH: it brings its own idea of who is allowed out, which collides head-on with `contract.Tiers` being the single ordering authority. Two components both deciding what a device may reach is exactly the enforcement-versus-state confusion in the glossary.

## What would make it worth building

Evidence from the standards path: if option 114 plus an RFC 8908 API is deployed and a real iPhone, a real Android phone and a laptop are observed NOT popping the sheet, then the probe interception is the remaining lever and its cost is justified. If they do pop it, this note should be deleted rather than kept as a someday-maybe.

## If it is built

- One table, one chain, one hook, matching as narrowly as it can (unregistered source MAC, LAN interface, TCP/80 and DNS only), and nothing else in it.
- The redirect target must be curfew's own listener rather than a separate service, so there is one place that knows what an unenrolled device should be told.
- It must be independently switchable off, and the off path must be the default, because the first time it misfires the household needs a way back that is not a git bisect.
- The DNS half needs care: hijacking DNS for unregistered devices interacts with AdGuard, which is the household's resolver, and getting that wrong takes out name resolution for everyone.
