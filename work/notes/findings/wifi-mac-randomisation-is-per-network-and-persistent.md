---
title: Wi-Fi MAC randomisation is per-network and persistent, not continuously rotating
slug: wifi-mac-randomisation-is-per-network-and-persistent
source: 'Apple support article HT/102509 "Use private Wi-Fi addresses on Apple devices", published 2025-12-05, retrieved 2026-08-08; and source.android.com "MAC randomization behavior" (/docs/core/connect/wifi-mac-randomization-behavior), last updated 2026-07-13, retrieved 2026-08-08. Vendor documentation, not measured on this household''s devices: the RE-randomisation triggers below are the vendors'' claims and have not been reproduced here.'
---

curfew's MAC allowlist assumes a MAC is a durable enough handle on a device to hang a bedtime off. Modern phones randomise their Wi-Fi MAC by default, which sounds like it destroys that assumption. It does not, and the exact shape of what it does matters for any enrolment flow, so the vendor behaviour is written down here rather than guessed at.

## The short version

On a WPA2/WPA3-protected home SSID, both iOS and Android default to a random address that is **per-network and stable**, not one that rotates. An address enrolled into the allowlist keeps working for months or years. It changes only on specific, nameable events, and every one of those events is something a person did to the device. So the design requirement is not "make MACs permanent"; it is "make re-enrolment cheap, and make it obvious when a device needs it".

Android's own documentation says this outright, naming the use case: persistent addresses exist so that networks "can help remember a device and let you bypass the login screen as expected, or enable parental controls".

## Android (Android 10 and later)

- Randomisation is **on by default** since Android 10, with a per-network toggle in the network details screen. Turning it off makes the device use its factory MAC.
- The randomised address is built by setting the **locally administered bit to 1** and the **unicast bit to 0**, and randomising the other 46 bits. That is the detection rule: `first_octet & 0x02 != 0` means locally administered, which for a phone on a household LAN almost always means randomised.
- The default type is **persistent randomisation**: the address is derived from the network profile's parameters (SSID, security type, or FQDN for Passpoint), and **remains the same until a factory reset**. It explicitly does **not** re-randomise when you forget and re-add the network, because it is derived from the profile parameters rather than stored.
- **Non-persistent randomisation** exists from Android 12 but applies in only two cases: a network-suggestion app asks for it via `WifiNetworkSuggestion.Builder#setMacRandomizationSetting`, or the network is an **open** network that has never hit a captive portal AND the `config_wifiAllowEnhancedMacRandomizationOnOpenSsids` overlay is on (it is off by default). Neither applies to a WPA2/WPA3 household SSID.
- When non-persistent IS in force, the address is re-rolled at the start of a new connection if the DHCP lease has expired and more than 4 hours have passed since the last disconnect, or if the current address is more than 24 hours old.
- Android 11+ has a developer-options switch, "Wi-Fi non-persistent MAC randomization", that forces non-persistent mode for every network. A child who finds it can defeat allowlist enrolment; it is behind developer options, which is itself a deliberate unlock.

## Apple (iOS 14 and later, macOS Sequoia 15 and later)

- Every network gets a different private address by default.
- From iOS 18 / iPadOS 18 / macOS Sequoia 15 / watchOS 11 / visionOS 2 the setting is three-way per network: **Off** (use the hardware MAC), **Fixed**, **Rotating**.
  - **Fixed is the default when joining a new network that uses WPA2 or stronger security**, and a Fixed address does not rotate "regardless of the network's security or length of time since you last joined the network".
  - **Rotating is the default for weak or open security**, and changes address every 2 weeks.
- The address is discarded, and a new one used on next join, when: the device is erased (all content and settings) or its network settings are reset; or the network is **forgotten** (from iOS 18, unless it was forgotten again within 24 hours; before iOS 18 the grace window was 2 weeks).
- **Before iOS 18 there was an additional expiry: a network not joined for 6 weeks got a new private address on the next join.** A device that stayed at a grandparent's for the summer would come home as a stranger. Fixed removes this.
- Apple notes that a router configured to notify on a new device joining will fire that notification the first time a device joins with a private address, which is exactly the enrolment prompt an admin surface wants.

## What this means for curfew

1. **Enrolling a randomised MAC is fine.** It is not a workaround, it is the supported path, and the vendors designed persistence specifically so that MAC-keyed features like parental controls keep working.
2. **The re-enrolment triggers are all human actions on the device**, not background rotation: factory reset, erase, reset network settings, forget-the-network (Apple), toggling the setting, or (pre-iOS 18) a six-week absence. A device that quietly stops working therefore has a cause a person can be asked about.
3. **Detecting a randomised address is cheap and worth surfacing.** The locally-administered bit is a reliable "this enrolment may not survive a reinstall" flag, and it is the difference between an admin reading a new unknown MAC as "Eli's phone came back" versus "a stranger is on my network". It is not proof: a hand-set MAC or a VM bridge also sets that bit.
4. **The advice to give a device owner is per-network, not global.** Both platforms expose the toggle inside the details of that one Wi-Fi network, so "turn private address off for this network" costs two taps and does not weaken the owner's privacy anywhere else.
5. **A determined child can still rotate.** Forget-and-rejoin on iOS, or developer options on Android, produces a new address on demand. This is the same limit the threat model already accepts for MAC spoofing, and it is the reason any self-service enrolment flow must not let a device enrol itself. It is also the strongest argument for identifying a device by the PSK it authenticated with rather than the address it presents (see `work/notes/ideas/per-device-psk-makes-identity-survive-mac-rotation.md`).
