---
title: push checks local DNS names against the router, and refuses a daemon too old to know them
slug: push-checks-and-old-daemon-refusal-for-dns-names
spec: local-dns-names-for-a-device
blockedBy: [dns-names-field-validator-and-cli]
covers: [3, 11, 12, 19, 20]
---

## What to build

`curfew-daemon -features` gains `local-dns-names`. `curfew push` refuses, before writing anything, to send a registry with any `dns_names` to a daemon that does not list it ("run `curfew update <host>` first"), with the same reasoning and shape as `requireFixedAddressSupport`. When any side has names, push reads the router context over ssh (`uci show dhcp` for `local`/`domain` and any foreign `address`/`server` entries, `uci show system` for `ntp.server`), runs the validator from `dns-names-field-validator-and-cli` with that context, refuses on any hard error listing them, and otherwise prints the warnings and one note per device whose names this push changes ("`*.lan.telemaque.ska.sh` -> 192.168.1.122, answered by the router within a minute"). A foreign `address`/`server` entry for the same domain is reported (the daemon will yield to it), not refused. The "router changed since last sync" refusal already uses `registry.Equal`, which now covers names.

## Acceptance criteria

- [x] `-features` prints `local-dns-names` (test in the daemon package).
- [x] Unit tests: push with names to an old daemon refuses; names refused by router context refuse the push and nothing is written; warnings and change notes are printed; a router-side names change since the last sync refuses without `--force`.
- [x] The router-context reader parses real `uci show dhcp` / `uci show system` output (fixtures copied from the image), including `local='/lan/'`, `domain='lan'` and a `list server` / `list address`.
- [x] No test reaches a real router; runners are fakes or the container.

## Blocked by

- dns-names-field-validator-and-cli

## Prompt

Goal: make `curfew push` the safe way to send local DNS names to the router. Read `docs/spikes/local-dns-names/design-notes.md` (Decisions 3 and 8), ADR 0013, and how push already handles fixed addresses in `main.go` / `setip.go` (`requireFixedAddressSupport`, `daemonSupports`, `checkPushAddresses`, `leases.ReadSurvey`). The validator and the `dns_names` field come from the task `dns-names-field-validator-and-cli` (in `work/tasks/done/`). Keep the router-context reader somewhere the daemon can reuse it for its own defence-in-depth check. Done = the tests above and verify green.

## Decisions (made while building, 2026-11-18)

- **The router-context reader is pure text parsing in `internal/dnsnames`** (`ContextFromUCI`, `DnsmasqLists`, `UCIValues`), fed by two `uci show` commands. The laptop runs them over ssh, and the daemon and the page can run the same commands locally and call the same functions.
- **A dnsmasq entry for the same domain that is not byte-for-byte what curfew would write is REPORTED by push, not refused.** Push cannot see the daemon's ledger, so it cannot tell a stale curfew entry from a hand-made one; the daemon, which can, decides. An entry identical to curfew's rendering is treated as curfew's and not reported.
- **`uci show system` failing is not fatal** (`uci -q show system || true`): with no NTP servers known, that rule simply has nothing to match. The test image itself has no `system.ntp` section.
- **No `cmdPush` integration test was added**: `cmdPush` builds its own `SSHRunner`, and no existing test drives it. The "router changed since the last sync" refusal is `registry.Equal`, whose names-only difference is asserted directly.
