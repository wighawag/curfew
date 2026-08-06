# Devices are named first-class entities; profiles group them by name

**Status:** accepted

The configuration model splits in two: a **device registry** naming each MAC address individually, and a **profile file** that groups device *names* into profiles. A device may be registered and allowed on the network **without belonging to any profile**, in which case it has full access, subject only to network-wide policy such as AdGuard filtering. Today the single `parental_profiles` file does both jobs, which forces every device to belong to a profile even when the profile is a fiction that exists purely to allowlist one MAC: six of the current entries (`printer`, `blink_a`, `media`, `blinky_mini_1`, `shyrka`, `desi`) are each a "profile" of one device carrying a budget field that means nothing for a printer. Putting a budget next to a device that can never have one is the smell that motivated the split.

## Considered Options

- **Split device registry from profile grouping (chosen).** Naming is where it belongs (on the device), grouping is a separate concern, and "allowed but ungoverned" becomes expressible instead of being faked with a one-device profile.
- **Keep the single file as the source of truth for both (rejected; the status quo).** Genuinely elegant as a single source of truth, and it is why the MAC allowlist has never drifted from profile membership. But it conflates identity, grouping and policy, and it makes device names impossible to express except as comments.

## Consequences

- Device names stop being comments and become data. This is what lets a status page say "Eli's phone is online" rather than showing three raw MAC addresses, and it removes the round-trip problem where any UI that rewrote the config would destroy the hand-written comments that currently carry those names.
- The MAC allowlist is derived from the **device registry**, not from profile membership. The allowlist therefore keeps working for ungoverned devices.
- Profiles reference devices by name, so a MAC can be corrected in one place when a device changes hardware.
- A migration is required: the existing single-device zero-budget **appliance** profiles collapse into plain registered devices, and the real profiles keep only their grouping. The migration must distinguish an appliance from a PERSON: a parent with one device and no budget (`ritu`) looks identical to a printer by shape, but dissolving their profile would destroy a human's identity in the system and the place any future rule for them would attach. Collapse appliances; keep people as profiles even when ungoverned.
- Budget, schedule and website rules attach to profiles, never to devices directly, so an ungoverned device is by construction unrestricted.
- This decision changes the config schema, so it should land together with, or after, the config-ownership work rather than being done twice.
