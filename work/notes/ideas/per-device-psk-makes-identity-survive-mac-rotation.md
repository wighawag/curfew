---
title: Per-device PSK makes a device's identity survive MAC rotation
slug: per-device-psk-makes-identity-survive-mac-rotation
---

Identify a device by **the Wi-Fi key it authenticated with** rather than by the MAC address it presents, so that a phone rotating its private Wi-Fi address stays the same child with the same bedtime instead of becoming an unknown device with no internet.

This is held as an idea rather than a spec because the mechanism has an unverified premise (below) and because adopting it would change what enrolment MEANS, which is an ADR-shaped decision that should be taken before anything is built on top of the MAC-only enrolment path.

## The problem it solves

curfew's whole control surface keys on MAC: `allowed_macs`, `blocked_macs`, `manual_blocked_macs`, `ticket_macs`, profile membership, pinned leases. A MAC is a device's claim about itself, and modern phones deliberately vary that claim per network.

Per `work/notes/findings/wifi-mac-randomisation-is-per-network-and-persistent.md` this is survivable: on a WPA2/WPA3 SSID the randomised address is stable until the owner erases the phone, resets its network settings, forgets the network (Apple), or toggles the setting. So MAC enrolment works, and the cost is a re-enrolment every time one of those happens, plus the confusing interval in between where a family member's phone is simply off the internet with no explanation.

It is also the standing bypass in the threat model: a child who forgets and rejoins the network, or flips Android's developer-options non-persistent switch, arrives as a device curfew has never seen. Today that means "no internet", which is the safe failure. But every enrolment convenience added on top erodes it, and a self-service enrolment flow would hand it to them outright.

## The mechanism

hostapd supports many passphrases on one SSID through `wpa_psk_file`: each line is a MAC (or `00:00:00:00:00:00` for "any device") plus a passphrase, and lines can carry a `keyid=` attribute and/or a `vlanid=`. The station's `keyid` is then attributable after association. Two ways to use it, of very different weight:

**Light: keep the MAC-set architecture, add PSK-driven re-enrolment.** Nothing about `contract.Tiers`, the chain, or the packet-path tests changes. The daemon subscribes to hostapd association events (ubus on OpenWrt), reads the connecting station's `keyid`, and updates the device registry so that the MAC currently associated with key `eli-phone` is the MAC in Eli's profile, replacing whatever address that key previously used. Enrolment becomes a one-time act (give the device Eli's key) that survives every rotation afterwards. A key belongs to exactly one device, so "device" stops being a MAC and becomes a key with a current address.

**Heavy: map each key to a VLAN and enforce per interface.** Structurally cleaner, and invalidates a large amount of MAC-keyed work including most of the packet-path suite. Almost certainly not worth it for a household.

The light variant is the interesting one.

## What it would buy

- A device that rotates its address is re-enrolled automatically, still inside its profile, still inside its bedtime. No parent action, no mysterious loss of internet.
- Enrolling a new device stops needing an admin surface at all in the common case: hand over the key.
- A visitor gets a guest key instead of a guest pass keyed to an address, which sidesteps the "guest tier outranks a bedtime block" bypass that `work/notes/ideas/rich-status-page-guest-access-and-config-ownership.md` flags, because the visitor's identity no longer depends on being unregistered.
- Revoking a device becomes meaningful: delete the key, and it cannot come back under a new address.

## What it costs, and what it does not fix

- OpenWrt's default `wpad-basic-mbedtls` is unlikely to carry the multi-PSK paths; this probably needs `wpad-full` or `wpad-openssl`. Flash and RAM on a GL-MT6000 are not the constraint, but the swap is a real install-path change and could drop the radio during the upgrade.
- The daemon grows a dependency on hostapd's event surface, which is a live-router integration with no equivalent in the container test environment. How to test it at all is an open question, and this repo does not accept "tested by mocking the thing that matters" (ADR 0004, ADR 0005).
- A registry whose contents are rewritten by radio events is a registry curfew no longer solely owns, which sits awkwardly against ADR 0008's tool-owned config. The auto-enrolment probably has to be a separate observed mapping (key to current MAC) that the desired-state computation joins against, rather than an in-place mutation of `devices.json`.
- **It does not stop key sharing.** A child who learns a sibling's or a parent's key inherits that identity, which is easier than reading the ARP table and spoofing. Per-device keys must genuinely be per device, and a shared "family" key would quietly reintroduce everything this fixes.
- It does nothing for wired devices, which keep their real MAC anyway and need none of this.

## Open questions, in the order they block progress

1. **Does OpenWrt's hostapd actually expose the per-station `keyid` on this hardware?** The whole light variant rests on it. It needs measuring on the live router (`hostapd_cli all_sta` on a station that associated with a keyed PSK line), not reasoning from upstream documentation. If `keyid` is not attributable, the fallback is `vlanid`, which drags in the heavy variant.
2. Which hostapd/wpad package the Flint 2 build actually needs, and whether swapping it can be done without a reboot or a dropped radio.
3. Where the key-to-device mapping lives, and whether it counts as configuration curfew owns (and therefore push/pull material and a secret, since it holds passphrases) or as observed state like the neighbour table.
4. What happens when two stations associate with the same key at once. Refuse, allow both, or treat the key as a small group?
5. Whether this supersedes the MAC allowlist or layers on it. Almost certainly layers: the allowlist stays the enforcement floor, and PSK identity only decides which MACs go in it.

## Relationship to the enrolment work

The pending-device list (`work/tasks/`) and the enrolment page (`work/specs/proposed/device-enrolment-page-with-a-pairing-code.md`) are useful whether or not this lands: wired devices, appliances, and anything that cannot render a page still need a manual path, and this idea's own auto-enrolment needs a first-time act to bind a key to a person. But if this is adopted, the enrolment surfaces become the exception path rather than the routine one, which should temper how much is invested in polishing them.
