---
title: The router's dnsmasq answers a device's local DNS names, in the same transaction as its pin
slug: dnsmasq-records-for-dns-names-in-the-pin-transaction
spec: local-dns-names-for-a-device
blockedBy: [serialise-dhcp-commits-with-one-lock, dns-names-field-validator-and-cli]
covers: [4, 5, 6, 8, 15, 16, 21, 25, 26]
---

## What to build

The daemon's pin pass also converges `dhcp.@dnsmasq[0]`'s `address` and `server` lists to the registry's local DNS names, rendered per ADR 0013 (`x` -> `/x/<ip>` + `/x/`; `*.x` -> `/*.x/<ip>` + `/*.x/`). It runs in the SAME uci transaction as the pins (one backup, commit, reload, liveness check, rollback, under the lock from `serialise-dhcp-commits-with-one-lock`), in both the DNS layer and `leaseLoop` (AdGuard off). A device's names are rendered only when its fixed address was actually pinned this pass, so a `set-ip` move rewrites the pin and the address value together, and a refused fixed address gets no names. Each name is also re-checked by the validator with the router's own context (defence in depth); a refused name is reported and not written.

Ownership is ADR 0014's ledger, `/etc/config/curfew/dns-records.json` (path configurable for tests): only entries in the ledger AND present are ever changed or deleted; a foreign entry for the same domain is yielded to and reported; an identical foreign entry is left and not claimed; write-ahead (record before create, drop after delete; prune after a successful pass). uci list edits use `uci add_list` / `uci del_list` with exact values.

Liveness: after a reload that changed anything, the existing "dnsmasq is running" check, plus, when dnsmasq is the resolver (configured port 53 or unset), an answer on 127.0.0.1:53 by the same "any answer counts" probe the daemon uses (`localResolver.Serving`). Either failure rolls back exactly as for a bad pin.

## Acceptance criteria

- [x] Unit tests: the render table; a converged state emits nothing; a fixed-address move emits the pin change and the address value change in one plan; a refused fixed address renders no names; a foreign same-domain entry blocks only that name; an identical foreign entry is not claimed; only ledger-and-present entries are deleted; write-ahead ordering of the ledger; deregistering a device removes exactly its entries.
- [x] Real uci + real dnsmasq in the image: entries land, dnsmasq (started on the init-script rendering of the lists, values passed verbatim) stays up; from it, a covered name's A is the fixed address and AAAA/HTTPS are NOERROR with no answers and no upstream sentinel (fixture upstream as in `docs/spikes/local-dns-names/measure.sh`); the apex of a `*.x` name is not answered locally; foreign host sections and list entries are byte-for-byte unchanged.
- [x] A change that makes dnsmasq refuse its config, or stop answering on 53 when it is the resolver, is rolled back and dnsmasq is running and answering afterwards.
- [x] Ledger and registry are temp files in tests; nothing touches `/etc/config/curfew` outside the container or a live router.

## Blocked by

- serialise-dhcp-commits-with-one-lock
- dns-names-field-validator-and-cli

## Prompt

Goal: make dnsmasq on the router answer each device's local DNS names, A only and never forwarding other types, so the names resolve after `panic-off` and with `-no-adguard`. Read `docs/spikes/local-dns-names/design-notes.md` (Decisions 2, 4, 6, 7), ADR 0013, ADR 0014, ADR 0012, and the finding `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md` (why the `server=/x/` line is mandatory: an `address` line alone forwards AAAA). The pins live in `internal/leases` (Reconcile, Pass, Apply, rollbackDHCP, PassAndLog) and the daemon wiring is in `cmd/curfew-daemon` (leaseLoop) and `internal/dnspolicy/manager.go`. Keep Reconcile pure and testable; the ledger is a small owned JSON file written atomically like the registry. Existing real-uci tests (`internal/leases/*_uci_test.go`) show how to start dnsmasq in the image without procd. Done = tests above, verify green.

## Decisions (made while building, 2026-11-18)

- **The ledger is its own small package, `internal/dnsledger`** (`/etc/config/curfew/dns-records.json`, daemon flag `-dns-ledger` / `CURFEW_DNS_LEDGER`), shared by the dnsmasq half here and the AdGuard half next. An UNREADABLE ledger is not treated as empty: ownership is then unknown, so the pass manages no names at all (adds nothing, deletes nothing) and still pins. If the write-ahead save fails, the name changes wait and the pins go ahead.
- **`leases.Pass` takes `PassOptions{LedgerPath}`**; an empty path means names are unmanaged. The plan's name commands are appended to the pin commands, so there is exactly one commit and one reload (asserted).
- **The resolver liveness check uses busybox `nslookup` through the Runner**, because `Apply` also runs over ssh (`adopt-leases`), and asks for `curfew-probe.<option local>` (or `localhost` when there is none), a name dnsmasq answers itself. Measured: an answer prints `Server:`; nothing listening and a dead upstream both print "no servers could be reached", and a dead upstream takes 5s, which is why `.invalid` (forwarded upstream by a router dnsmasq) would have mistaken a WAN outage for a dead resolver. It runs only when dnsmasq's configured port is 53 or unset.
- **A value present twice in a list (one curfew's, one not) is never deleted**, because `uci del_list` cannot remove just one copy; it is reported, mirroring the AdGuard duplicate rule.
- **A foreign entry for the same domain yields the WHOLE name** (neither its `address` nor its `server` entry is written), and curfew's own earlier entries for that name are removed, so dnsmasq never holds two answers.
- **Test support lives in `internal/dnstest`** (a DNS client that separates NODATA from forwarded answers, the sentinel upstream, the init-script rendering of the DNS options), for reuse by the end-to-end task. `go mod tidy` therefore promoted `golang.org/x/net` (and the already-direct `golang.org/x/crypto`) to direct requirements.
- Mutation check: with the `server` entry not written, the real-dnsmasq test fails with the AAAA sentinel, as the finding predicted.
