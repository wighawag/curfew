# curfew owns the AdGuard rewrites and dnsmasq entries it wrote, by a ledger, because neither can carry a marker

**Status:** accepted (decided with the owner on 2026-11-18; spec `work/specs/tasked/local-dns-names-for-a-device.md`). Extends `docs/adr/0010-curfew-drives-adguard-through-its-api-and-owns-only-its-own-objects.md` and `docs/adr/0011-curfew-pins-ipv4-leases-and-follows-ipv6-to-identify-a-device-to-adguard.md`.

Until now every object curfew owns has been owned by a marker a person can read: its own nftables table, `curfew-<profile>` AdGuard clients, the one filter list at curfew's own URL, `curfew_<mac>` host sections with a `curfew '1'` option. Local DNS names (ADR 0013) need two new kinds of object, and **neither can carry a marker**, measured: an AdGuard rewrite is exactly `{domain, answer, enabled}` with no name or comment, and an entry in the `address` or `server` list of `dhcp.@dnsmasq[0]` is a bare string. So ownership of those is recorded instead: a router-local ledger the daemon owns, `/etc/config/curfew/dns-records.json`, listing every rewrite and every list entry curfew has written.

## The rules that keep the ADR 0010 promise without a marker

- **curfew changes or deletes an object only when it is in the ledger AND present.** Anything else is foreign, whatever its content.
- **A foreign object for the same name is yielded to and reported**, never replaced and never joined by a second answer: the pins' rule from ADR 0011.
- **A foreign object identical to what curfew wants is left alone and NOT claimed.** Claiming it would let curfew delete the household's own record later, and on AdGuard one `delete {domain, answer}` removes every identical copy at once (measured: two identical rewrites, one delete, both gone). For the same reason curfew deletes nothing while the list holds two identical copies. The name still resolves, which is what the household wanted.
- **Write-ahead**: an entry is recorded before the object is created and dropped only after it is gone, so after a crash or a rolled-back dnsmasq reload the ledger is a superset of what exists, never a subset. A superset is harmless (deleting an absent entry is a no-op, and entries neither present nor desired are pruned); a subset would orphan a record nobody could clean up.
- **The ledger is router state, not configuration**: it is not pushed or pulled, it survives a sysupgrade with the rest of `/etc/config`, and a person never edits it. The device registry stays the only thing a household edits.

## Considered Options

- **Ledger (chosen),** as above.
- **Own the names through curfew's own filter list, as `$dnsrewrite` rules (rejected).** The list is already a marked, owned object, so no ledger would be needed, and the answers were measured to be identical. Rejected because every list change re-fetches the list, which rebuilds AdGuard's filter engine and is gated by the memory headroom check, so a name could be deferred indefinitely on a tight router; a rewrite write touches no list (measured). It would also keep the names off AdGuard's "DNS rewrites" page, where a household looks for them.
- **Own a whole dnsmasq conf file in the confdir (rejected).** No ledger needed on that side, but the default confdir is tmpfs, so the names would exist after a reboot only once the daemon had run, and never if it is down: the `panic-off` path would depend on curfew being alive. uci entries persist with the DHCP config.
- **Treat any entry matching the desired state as curfew's (rejected).** Stateless, but it claims identical household records and cannot tell a stale curfew entry (an old address after a move) from a hand-made one, so it either leaks or deletes what it does not own.

## Consequences

- If the ledger is lost, curfew stops deleting those entries (it can no longer prove they are its own) and reports them as foreign; nothing it does not own is ever at risk. Recreating ownership is a deliberate act, like `curfew adopt-leases`, and is not built.
- Uninstalling or downgrading the daemon leaves the records in place, still answering at the last address. A future uninstall should remove exactly the ledger's entries; a future Go `panic-off` must leave them, since they are connectivity, not policy.
