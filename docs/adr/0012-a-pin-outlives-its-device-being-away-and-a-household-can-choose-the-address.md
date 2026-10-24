# A pin outlives its device being away, a household can choose the address, and IPv4 identity follows the lease during a move

**Status:** accepted. Amends `docs/adr/0011-curfew-pins-ipv4-leases-and-follows-ipv6-to-identify-a-device-to-adguard.md`.

ADR 0011 made the IPv4 half of a device's identity "configuration curfew owns rather than something it has to observe". It was not true in practice, and a household needed a thing 0011 did not offer: an address of its own choosing. This records three decisions: pins are sticky, a device may carry a user-chosen **fixed address**, and while a device moves between addresses AdGuard attributes IPv4 by what the DHCP server says each MAC holds.

## What went wrong, measured on the live router

shyrka (`84:47:09:84:8e:b2`) runs an LLM server bound to the literal `192.168.1.150`, and every peer and every anonctl exemption names that address. After a reboot it came up at `192.168.1.226` and the service could not bind. Read off the router on 2026-10-23:

- There was no host entry curfew did not own: all 18 `config host` sections were `curfew_*`. The "router reservation" the household believed in was never in force as configuration.
- shyrka was registered and pinned as `dhcp.curfew_844709848eb2.ip='192.168.1.226'`, which is simply what curfew observed.
- The printer, adopted from the legacy shell tool at `192.168.1.10` with `curfew adopt-leases`, was pinned at `192.168.1.129`.
- The daemon logged **28 registered devices with no DHCP lease on every tick, and none of them had a pin.**

The mechanism was a sweep in `leases.Reconcile`. The address it pinned came only from `/tmp/dhcp.leases`, and a registered device with no lease that pass was treated as having nothing to pin, so its owned section was deleted as stale. A router reboot empties that file (it is tmpfs), and a lease also leaves it on expiry or release, so every pin of every device not online at that moment was swept, and the device was re-pinned wherever it next came back. A "pinned lease" was a mirror of the lease file.

## Decisions

- **A pin is removed only when its device is deregistered.** A registered device with no lease keeps the pin curfew owns for it, unchanged. The address a device is pinned at is, in order: its fixed address; else what it holds now; else the pin it already has; else nothing (reported as unaddressed).
- **A device may carry a fixed address** (`ip` on the device in `devices.json`, set with `curfew set-ip` or on the devices page, carried by push and pull, merged field by field). It lives on the device because it is a property of one device exactly as its name is, and putting it there needs no new file and no new sync path (ADR 0008). A separate leases file keyed by MAC was rejected for needing both.
- **No address is ever reserved twice.** Measured with dnsmasq 2.91 in the test image: two `dhcp-host` lines for one address are not a skipped entry, they are `duplicate dhcp-host IP address` and dnsmasq refuses to start, so the household loses DHCP. A fixed address is therefore checked before any uci write (valid IPv4 inside the LAN read from `uci show network.lan`, not the network, broadcast or router address, not used by any host entry owned or foreign, not another device's fixed address), and the reconciler refuses rather than emits any clash. A fixed address never displaces another device's pin, even an offline one's, because that would silently move the other device on its next renewal. Two devices given one fixed address are both refused rather than one winning by MAC order.
- **Fixed addresses do not depend on AdGuard.** They are a DHCP promise, so with AdGuard off the daemon still runs a pinning pass; it takes no new pin from an observed address, because nothing would use one.
- **Ownership is unchanged.** curfew still owns only `curfew_<mac>` sections, still writes no `name`, still yields to a foreign entry for the same MAC (a fixed address for such a MAC is refused until the entry is handed over with `curfew adopt-leases`), and Apply still verifies dnsmasq and rolls back.

## IPv4 identity during a move (amends 0011)

0011 sent AdGuard only the pinned IPv4 address and a test asserted that an observed one never reached it. That is unsafe in the other direction once addresses can be changed on purpose: a device given a new fixed address keeps its old lease until it renews (up to half the lease time, six hours here), so its restriction would not apply to its queries for that whole window, and changing an address would become a way to escape a restriction.

**The rule is now: an IPv4 address is attributed to a device's AdGuard client if and only if the lease file says THIS MAC holds it, or it is this device's pin and the lease file shows no OTHER MAC holding it.**

- During a move the client carries both the old leased address and the new pin, so the child stays restricted throughout.
- When the device renews, the old address leaves the lease file and leaves the client on the next pass.
- An address another MAC holds (a lease that predates a pin, a squatter on a freshly chosen fixed address) is never credited to the pinned owner.
- Case (b) is safe while the pinned device is offline because dnsmasq never hands a reserved address to another MAC.
- IPv4 still never comes from ARP or the neighbour table. The lease file is the DHCP server's own record of who holds what, and it cannot name two MACs for one address.

## Considered Options

- **Lease-attested union (chosen),** as above.
- **Pin only (rejected).** Keeps 0011's rule exactly and has no wrong-device race at all, but the moving device's IPv4 queries are unrestricted until it renews. Rejected because the window is hours, not seconds, and it is opened by the very action a parent takes.
- **Switch only once the device is seen at the new address (rejected).** It is a subset of the union with the same residual race on the old address and a longer unrestricted gap on the new one.
- **Let a fixed address displace another device's pin (rejected).** Convenient, but it silently moves a second device, which is the class of surprise this ADR exists to remove.

## Consequences

- **The residual risk, stated plainly.** Between a device renewing onto its new address and curfew's next pass (one tick, a minute by default), dnsmasq could hand the just-freed old address to another device, whose queries would be attributed to the moving device's profile for under a minute. With sticky pins the only devices that still get dynamic addresses are unregistered ones (dropped by nftables anyway) and newly registered ones not yet pinned, so the exposure is narrow; it is also smaller than before this ADR, when every pin followed the lease file and the same race existed on every address change. Like everything else in the refinement it never affects bedtime, budgets or manual blocks, which are nftables on MAC.
- **Pins now accumulate for registered devices,** including ones that have not been seen in months. The pool here is 150 addresses for about 50 registered devices, so this is not a constraint today; deregistering a device is what frees its address.
- **The move is measured, not assumed.** The acceptance suite runs a real dnsmasq and a real DHCP client in a network namespace, gives the client a fixed address while it holds a dynamic lease, renews (SIGUSR1, not a reboot), and asserts it lands on the fixed address. That is what `push` and the page tell a household: the device moves on its next renewal, or straight away if it reconnects.
- **`push` refuses to send a fixed address to a daemon that does not report the feature** (`curfew-daemon -features`), because an older daemon's page would drop the field on its next save and the next `pull` would read the drop as the household clearing it. So the order on a router is `curfew update`, then `curfew push`.
- **A swap needs two pushes.** Moving device A off address X and giving X to device B in one push is refused, because A's pin still holds X when B's is checked. It converges once A has moved.
