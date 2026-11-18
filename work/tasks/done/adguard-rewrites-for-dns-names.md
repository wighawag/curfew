---
title: AdGuard answers a device's local DNS names with rewrites curfew owns, and says which clients it cannot answer
slug: adguard-rewrites-for-dns-names
spec: local-dns-names-for-a-device
blockedBy: [dnsmasq-records-for-dns-names-in-the-pin-transaction]
covers: [6, 8, 15, 16, 24, 26]
---

## What to build

In `dnspolicy.Manager.Tick`, after the DHCP pass, reconcile AdGuard's DNS rewrites to the names the DHCP pass actually rendered (same fixed address, same refusals): `x` -> rewrites `x` and `*.x`; `*.x` -> `*.x`; answer = the fixed address; never the special answers `A` or `AAAA`. Through the REST API (`GET /control/rewrite/list`, `POST add`, `POST delete`, `PUT update` for an address move), scope-guarded by the ADR 0014 ledger (shared file with the dnsmasq half, separate section): only ledger-and-present rewrites are changed; a foreign rewrite for the same domain is yielded to and reported; an identical foreign one is not claimed; no delete while two identical copies exist; write-ahead ledger.

Each pass also reads `/control/rewrite/settings`, the global filtering state and the clients, and reports (never changes) when rewrites are off, filtering is off globally, or named non-curfew clients have filtering off, since those clients get no rewrites (measured). With no AdGuard credentials the half is skipped and the ledger's AdGuard entries are left, reported once.

## Acceptance criteria

- [x] Unit tests with a fake API: add, move via update, delete; converged = no writes; foreign same-domain yielded; identical foreign not claimed; duplicate blocks delete; ledger write-ahead; the bypass report for each of the three cases.
- [x] Against the real AdGuard in the image with a sentinel upstream: after a pass, a covered name's A is the fixed address, AAAA and HTTPS are NOERROR with no answer and no sentinel; after the name is removed, the name falls through to the sentinel; a hand-made rewrite created before the test is still present and unchanged.
- [x] Everything fails open and is logged: an AdGuard error never stops the pass or the firewall.

## Blocked by

- dnsmasq-records-for-dns-names-in-the-pin-transaction

## Prompt

Goal: make AdGuard answer local DNS names while it holds port 53, owning only the rewrites curfew created. Read `docs/spikes/local-dns-names/design-notes.md` (Decisions 2, 4, 5, 6), ADR 0010, ADR 0011 ("scope, not frequency"), ADR 0013, ADR 0014, and the finding `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md` (object shape, duplicate and delete semantics, `PUT` update, who gets no rewrites). The AdGuard client is `internal/adguard` (objects.go shows the owned-object guard style), the reconcile is `internal/dnspolicy` (Reconcile, Manager.Tick), and the real-AdGuard tests are `internal/dnspolicy/dnspath_test.go`. The ledger and the set of rendered names come from the task `dnsmasq-records-for-dns-names-in-the-pin-transaction`. Done = tests above, verify green.

## Decisions (made while building, 2026-11-18)

- **The rewrite API is a separate interface (`dnspolicy.RewriteAPI`) on the Manager** (`Config.Rewrites`), so the existing restrictions `API` and its fakes are untouched; the daemon passes the same `adguard.Client` for both.
- **The ledger after a pass is READ BACK from AdGuard** (`write-ahead ∩ what AdGuard lists afterwards`) rather than assumed from which calls returned 200, so a half-failed pass neither orphans a rewrite nor keeps a claim on one that does not exist. If the read-back fails, the write-ahead superset is kept.
- **The AdGuard client refuses the special answers `A`/`AAAA` and an empty answer** for add and update, since AdGuard reads them as "ask upstream" (measured); ownership itself is guarded by the reconcile against the ledger, because a rewrite has no field to mark it.
- **A device moving address is a `PUT /control/rewrite/update` of curfew's own rewrite**, only when exactly one copy exists; otherwise add and delete as usual.
- **The "who gets no rewrites" report runs only when there are local names**, and covers rewrites off globally, filtering off globally, and non-curfew clients with their own settings and filtering off (a client with `use_global_settings` follows the global switch, which is reported separately).
- **When the DHCP pass could not read the ledger, AdGuard is left exactly as it is** too, for the same "ownership unknown" reason. With no AdGuard credentials the daemon logs once at startup if the ledger still lists rewrites it can no longer manage.
