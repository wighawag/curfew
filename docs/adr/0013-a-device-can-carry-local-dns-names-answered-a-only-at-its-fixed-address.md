# A device can carry local DNS names, which the router answers A-only at its fixed address, and a bare name covers its subdomains

**Status:** accepted (decided with the owner on 2026-11-18; spec `work/specs/tasked/local-dns-names-for-a-device.md`)

A household needed names for a machine on its own LAN (`*.lan.telemaque.ska.sh` for the workstation serving the children's game studios) that did not depend on a public record, and that kept working after `panic-off`, where dnsmasq's rebind protection drops a public answer pointing at a private address (measured). So a device in `devices.json` carries `dns_names`, a set the household edits with `curfew add-dns-name` / `remove-dns-name` or on the devices page, and the router answers each name with that device's **fixed address** from both resolvers: AdGuard (DNS rewrites) and dnsmasq (`address` plus local-only `server` entries). It lives on the device, like the fixed address (ADR 0012), because it is a property of one device and so travels with push and pull and merges field by field with no new file (ADR 0008).

## The meaning of a name is chosen by what BOTH resolvers can render

Measured on dnsmasq 2.91 and AdGuard v0.107.78 (`work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md`):

- **`x` means x and every name below it.** Rendered as the AdGuard pair `x` + `*.x`, and as dnsmasq `address=/x/<ip>` + `server=/x/`.
- **`*.x` means every name strictly below x, and not x.** Rendered as AdGuard `*.x`, and dnsmasq `address=/*.x/<ip>` + `server=/*.x/` (the wildcard works in 2.91).
- **There is no exact-name-only form**, and that is the surprising part. AdGuard's own meaning of a bare `x` is exactly `x`, but dnsmasq cannot match it: `host-record=x,<ip>` forwards AAAA upstream, and the local-only `server=/x/` that would stop that covers every subdomain of x and so silently breaks their public resolution. A meaning only one side can render would make the two resolvers answer differently, which shows up only after `panic-off`, the moment nobody is checking.

## A only, and AAAA must neither answer nor fall through

The device's LAN IPv6 is a router-assigned ULA whose stability is not established (ADR 0011 follows IPv6 rather than pinning it), so an AAAA would be an address that can go stale and send clients to the wrong host by name. So the names answer A only, and every other type (AAAA, HTTPS) gets NOERROR with no answer and is NOT forwarded: forwarding would let a public AAAA, or any upstream answer, win over IPv6. Measured: an AdGuard A-only rewrite already does this; a dnsmasq `address` line alone does NOT (it forwards AAAA), which is why every name also gets the local-only `server=/<domain>/` line. curfew never writes AdGuard's special answers `A`/`AAAA`, which mean "use upstream for that type".

## The name follows the fixed address, and requires one

Names point at the device's fixed address, never at an observed or merely pinned one: a name is something other machines depend on literally, like a fixed address, and a pin a household never chose can be first-observed at any address. So adding a name to a device with no fixed address is refused, clearing the fixed address of a device with names is refused, and changing it with `set-ip` moves the names on the next pass (in the same DHCP transaction as the pin).

## Considered Options

- **Exact `x` and wildcard `*.x`, AdGuard's meaning (rejected):** not renderable on dnsmasq, above.
- **Only `*.x` (rejected):** renderable, but needlessly forbids the common "this name and its subdomains" case.
- **A `rebind_domain` for the public record (rejected):** works after `panic-off`, but it is a hand edit nothing owns and it still depends on the internet and Cloudflare; a local answer is not subject to rebind protection at all (measured).
- **Answer AAAA with the device's current ULA (rejected):** see above; revisit if a device's IPv6 is ever pinned.

## Consequences

- Names of different devices may not overlap, and a name may not sit under the router's local domain, a special-use domain the network depends on, a whole TLD, or a hostname the router itself resolves (NTP, upstreams). The spec lists the rule and why each part exists.
- The public record can and should stay: a browser using its own DNS-over-HTTPS never asks the router. On the LAN the local answer wins (measured on both).
- An AdGuard client with filtering off, or filtering or rewrites off globally, gets no rewrites (measured) and asks upstream; this is reported, never changed, since those are the household's settings.
- `push` refuses names to a daemon that does not report `local-dns-names`, as for fixed addresses.
