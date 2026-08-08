# curfew pins the IPv4 lease and FOLLOWS IPv6, to identify a device to AdGuard

**Status:** accepted

`docs/adr/0010-curfew-drives-adguard-through-its-api-and-owns-only-its-own-objects.md`
settled that AdGuard identifies a client by IP, that a MAC-keyed client is
accepted and never matches, and that curfew would therefore bridge the two
identities by assigning static DHCP leases. It said nothing about IPv6, and on
this router that omission would have made the whole feature a no-op for more
than half the household's DNS traffic. This records how a device is identified
to AdGuard, which uci entries curfew owns, how a time window is applied, and
what happens when a device cannot be identified at all.

## IPv6 is not optional here, and it was measured before it was designed

Measured on the live router, from AdGuard's own query log (30,000 most recent
entries):

| Client address family | Distinct clients | Share of queries |
|---|---|---|
| IPv4 | 22 | roughly half |
| IPv6 (ULA, SLAAC privacy addresses) | 25 | roughly half |

The single busiest client after the author's laptop is an IPv6 address, and a
child's device (`f0:d7:aa:da:66:35`, tia's phone) is among the IPv6 queriers.
The router runs `dhcpv6='server'`, `ra='server'`, `ra_slaac='1'`, and AdGuard
binds `:::53`, so it answers over IPv6 and sees an IPv6 source address. **A
per-client rule keyed only to an IPv4 lease is silently inert for those
queries.** That is confirmed rather than argued: deleting the IPv6 half of the
client's ids makes the end-to-end test report `twitch.tv` RESOLVED from the
child's IPv6 address while still BLOCKED from their IPv4 one.

## Considered Options

- **Pin IPv4, follow IPv6 (chosen).** The IPv4 address is fixed by a static
  lease curfew writes; IPv6 addresses are read from the router's neighbour
  table and added alongside on the same AdGuard client. Measured to work, with
  controls: a client carrying one IPv4 and several IPv6 ids matches on all of
  them, and per-client `blocked_services` applies to a client identified purely
  by IPv6.
- **Stop the router advertising itself as a DNS server over IPv6 (rejected).**
  odhcpd supports it (`dns_service`, confirmed present in the binary on the
  router), it costs nothing functionally because a query sent over IPv4 returns
  AAAA records perfectly well, and it would reduce identity to one stable
  address per device. It was rejected because it makes the feature work by
  removing IPv6 rather than by supporting it: the moment `wan6` comes up and
  the ISP delegates a prefix, IPv6 becomes real transport for this household,
  and a design that depends on IPv6 DNS being off is a design that has to be
  redone. It is recorded because it is genuinely attractive and someone will
  propose it again.
- **Turn SLAAC off and let DHCPv6 assign every address (rejected).** This would
  make IPv6 as pinnable as IPv4: odhcpd assigns from `hostid`, so curfew could
  own both families through configuration. It is rejected because **Android
  does not implement DHCPv6 at all**, and most of the phones in this household
  are Android, so they would get no IPv6 address whatsoever. Buying tidy
  identity by breaking IPv6 for the children's own devices is the wrong trade.
- **Read the IPv6 addresses from odhcpd instead of the neighbour table
  (rejected on measurement).** It looks like the natural source and it is the
  wrong one. odhcpd's leases and `/tmp/hosts` carry the DHCPv6-assigned
  addresses (`fd96:17c2:5378::641`); the addresses AdGuard actually sees are
  SLAAC privacy addresses (`fd96:17c2:5378:0:b0fe:9959:ad68:8107`). The DHCPv6
  addresses made **zero** queries in the entire log. `ip -6 neigh` is the only
  source that has the addresses that matter.

## The two families get different staleness rules, and that is the safety property

**A stale IPv4 is dangerous; a stale IPv6 privacy address is nearly harmless.**
DHCP reissues IPv4 addresses, so an address that belonged to one child an hour
ago can belong to another now, and a rule keyed to it would restrict the WRONG
CHILD, which is worse than no rule at all. A SLAAC privacy address carries 64
random bits of interface identifier and will essentially never be reissued to a
different device.

So the rule is asymmetric by construction, not by policy:

- **IPv4 comes only from the DHCP lease file and the static lease curfew
  writes.** Never from ARP. `internal/dnspolicy` takes IPv4 exclusively from
  the pinned map and a test asserts that an observed-but-unpinned IPv4 address
  never reaches AdGuard.
- **IPv6 comes from the neighbour table**, and the answer is exactly what that
  table says now, with no accumulated history. That is also the pruning: a
  privacy address rotates daily, and an address a device is actively using
  cannot age out of the table while it is in use, because the router is
  replying to it. A cap (`MaxIPv6PerDevice`) bounds the object size and
  truncation is reported rather than silent.

**What is NOT covered, stated plainly.** Between a device forming a new
temporary IPv6 address and curfew's next pass (one reconcile tick, a minute by
default), queries from that new address are unrestricted. Link-local queries to
a router address curfew does not know about are not covered. Any device whose
address does not appear in the neighbour table at all is not covered. All of
these fail OPEN on the refinement only: bedtime, budget and manual blocks are
nftables on MAC, are family-agnostic because the table is `inet`, and never
consult any of this.

## Which uci entries curfew owns

**curfew owns exactly the `dhcp` host sections whose uci section name begins
`curfew_`, and nothing else.** The name is derived from the MAC
(`dhcp.curfew_14e01d6a9c6c`), so a device always maps to the same section and
convergence is idempotent; a `curfew '1'` option is written into each one so
that ownership is legible in `/etc/config/dhcp` too. Named sections are used
rather than anonymous ones because an anonymous section is addressed by index,
and an index moves when anything before it is deleted.

**A foreign entry is never adopted automatically, and can be adopted
deliberately.** The reconciler always yields; only `curfew adopt-leases`, run
by a person who has seen the plan, transfers ownership. That split is the
safety property: "curfew deletes host entries it did not create" must never
become automatic behaviour, because the whole design rests on the opposite
promise.

*(Amended after first writing, which recorded that the existing
`dhcp.@host[0]` printer entry would never be adopted at all. That was too
conservative and had a standing cost: the reconciler reported the same
conflict on every pass for ever, and one device stayed pinned by a mechanism
curfew does not own, which is the split ownership ADR 0007 blames for every bug
in the investigation. The entry is curfew's own ancestry, written by the shell
tool this project replaces and still recorded in `config/local/device_ips`, so
handing it over is a migration rather than a seizure. What has NOT changed is
the rule that makes this safe: adoption is opt-in, per-entry, shown before it
happens, and offered only for a MAC that is a registered device.)*

Adoption keeps the device's address EXACTLY as it was, so nothing on the LAN
moves, and stages the delete and the replacement in ONE uci transaction:
write-then-delete would leave a moment with two static leases for one MAC,
which dnsmasq treats as a broken config, and delete-then-write would risk the
device losing its reservation if the write failed. Deletes are emitted FIRST
and in DESCENDING index order, both of which were measured to be necessary: a
named host section does occupy an `@host[N]` slot, and deleting `@host[0]`
renumbers the rest downward, so an ascending delete removes the wrong entries.
A real-uci test adopts two entries out of four and asserts the other two come
out untouched; reversing the sort order makes it fail.

**A foreign entry that pins a MAC curfew also wants to pin is yielded to.**
curfew writes no competing entry (two static leases for one MAC is a broken
dnsmasq config), removes nothing, reports the clash, and USES the foreign
entry's address, because a foreign pin is still a pin and refusing to read it
would only make the refinement worse.

## The pinned address is the one the device already holds

Confirmed against the real lease data rather than assumed: all of the household's
registered devices currently sit inside the DHCP pool (192.168.1.100 to
192.168.1.249). A reserved block outside the pool would therefore move every
device, and with a 12 hour lease the household would spend up to half a day
half-migrated with no way to tell which half a given device was in. Pinning what
a device already has converges instantly and disturbs nothing; dnsmasq honours a
static lease inside its own pool. The printer at .10 sits outside the pool and
is precisely the entry curfew does not touch, so it argues for nothing here.

## A device with no known address is reported, never invented for

One of eli's three devices (`04:92:26:1e:6b:55`) currently holds only a
169.254 link-local IPv4 address, so there is nothing to pin. Allocating one
from a reserved range would produce a rule keyed to an address the device does
not have and cannot be told about until its next DHCP renewal: a rule that
matches nothing while looking, in AdGuard's UI and in curfew's own reports,
exactly like one that works. So such a device is skipped and named in the log,
and a profile in that state is reported as `unresolved` (no device addressable)
or `partially resolved` (restricted on one device and not another).

## A window boundary is applied by the daemon's tick, and that does not contradict ADR 0010

ADR 0010 decided AdGuard is reconciled **on action, not on a tick**, because
its config persists and a human edits it, so a continuous reconciler would
revert a change made in AdGuard's own UI. Time-windowed rules need something to
happen at a boundary, so the tension has to be resolved.

**It is resolved by SCOPE, not by frequency.** The reconciler only ever reads,
writes or deletes objects curfew itself created: clients named `curfew-*` and
the single filter list curfew serves. Every write goes through a guard that
refuses an unowned name, so a household's own client, list, exception or rule
cannot be touched. That is the same boundary that already works between
curfew's nftables table and fw4, and it is what makes running every minute safe
where a whole-config reconciler would not be. Nothing is written unless the
desired state differs from what AdGuard holds, so a household that changes
nothing sees no writes at all. Disagreement outside curfew's own objects is
still only ever REPORTED.

## Custom domain lists reach AdGuard as one subscribed list curfew serves

curfew-daemon serves a single filter list over its existing HTTP server and
registers it once with `add_url`. `user_rules` stays entirely the human's.

Measured on v0.107.78 before committing to it, because the alternative was
writing into `user_rules` with sentinels:

- a fetched list **does** honour the `$client=` modifier;
- `add_url` fetches immediately and the rule took effect in **4ms**;
- `POST /control/filtering/refresh` re-fetched on **every one of five
  consecutive calls**, with no rate limiting: the call takes 70-90ms and the
  rule change lands 1-4ms later, in **both** directions;
- without an explicit refresh AdGuard's own update interval is **24 hours**, so
  the refresh is what makes a boundary prompt rather than eventual.

The `user_rules` alternative was also measured and does work: comment lines
survive a `set_rules` round trip and AdGuard's own rewrite of the yaml, and a
hand-written rule outside a sentinel block survives. It is rejected anyway,
because sharing one list between a program and a person means every curfew
write has to reason about text it did not author, and a subscribed list has no
such problem.

The rules in that list reference the AdGuard client by **name**
(`||twitch.tv^$client=curfew-eli`), not by address. So the list content changes
only when policy changes, and a phone rotating its IPv6 address updates the
client object without triggering a list re-fetch. Catalogue services go on the
client object's `blocked_services` instead, since the catalogue is not
expressible as filter rules.

## Consequences

- **The daemon needs AdGuard credentials, and that means a re-install.**
  `daemon.conf` gains `CURFEW_ADGUARD_URL`, `CURFEW_ADGUARD_USER`,
  `CURFEW_ADGUARD_PASSWORD` and `CURFEW_ROUTER_IP`. `curfew update`
  deliberately never rewrites that file, so it instead DETECTS the missing key
  and says that the feature will stay off and that a re-run of `curfew install`
  turns it on. A daemon with no credentials logs that the refinement is off,
  names what still works, and starts normally.
- **One HTTP route is served without authentication**, the filter list, because
  AdGuard fetches it with no credentials and has nowhere to put any. It is as
  narrow as it can be: the content is profile names and blocked domains, and
  the device addresses are not in it, because the rules key on the client name.
  A test asserts that this is the only unauthenticated route.
- **The lease writer runs on the router, in the daemon**, not only from a
  laptop. Devices are registered from the router's own page, and a lease pinned
  only by a laptop-side push would leave such a device with no address and a
  restriction that silently did not apply.
- **Everything in this layer is fail-open and reported.** A failure to read the
  DHCP config, write a lease, or reach AdGuard is warned about and the pass
  continues; none of it can stop the firewall reconciling. That is the
  asymmetry ADR 0010 states: fail open on the refinement, fail closed on the
  control.
- **The easy half of the DoH bypass is closed; the rest is not.** curfew blocks
  the well-known DoH and DoT endpoint HOSTNAMES for every profile that has
  restrictions configured, which defeats any client that resolves its endpoint
  by name, and that is how every browser and OS setting exposes it. The rules
  are deliberately NOT window-gated, because a child sets an endpoint once and
  it persists, so allowing the lookup outside the window would defeat the next
  one. It is on by default (`block_doh_bootstrap`, a pointer so that absent
  means on) and applies to nobody else, so parents and ungoverned devices keep
  DoH. Measured while building it: **AdGuard already blocks Firefox's
  `use-application-dns.net` canary itself**, with no rule from anyone, so
  curfew's entry for it is belt-and-braces rather than the load-bearing part.
  This list will go stale and is a speed bump, not a control.
- **Still bypassable, and documented as such:** a DoH endpoint given as a
  literal IP address, a hardcoded plaintext resolver such as `8.8.8.8`, DoT on
  port 853, and any VPN. Those need enforcement rules in nftables and are
  specified in `work/specs/proposed/force-dns-through-the-router.md`. A child
  who takes any of those routes escapes every restriction in this ADR while
  remaining subject to every nftables control.
- **MAC spoofing is not addressed.** A child copying a sibling's registered MAC
  defeats the allowlist and would inherit that sibling's restrictions. MAC
  randomisation is a different matter and is already handled: a rotated MAC is
  an unknown MAC, matches no tier, and is dropped.
- `schedule.Profiles` gains `block_lists` and each profile gains
  `dns_restrictions`. Both take part in `schedule.Equal`, so a push or pull
  cannot silently discard them, which is the trap ADR 0009 recorded for the
  budget knobs.
