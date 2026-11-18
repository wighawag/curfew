---
title: A device carries local DNS names, checked by one validator and edited with add-dns-name / remove-dns-name
slug: dns-names-field-validator-and-cli
spec: local-dns-names-for-a-device
blockedBy: []
covers: [1, 2, 7, 9, 10, 11, 12, 13, 14, 17, 18]
---

## What to build

The registry half and the rules, end to end from the laptop. `registry.Device` gains `dns_names` (a set, `omitempty`). Load canonicalises (trim, lowercase, one trailing dot stripped, duplicates dropped, sorted) and KEEPS a name that does not parse, as it does for a bad fixed address. Strict `AddDNSName` / `RemoveDNSName` on the registry, and `SetIP(mac, "")` refuses while the device has names.

One pure validator (design-notes Decision 3) taking the names of every device, their fixed addresses, and an optional router context (the local domains from `option local` / `option domain`, and the `system.ntp.server` hostnames, plus a hook for resolver hostnames the daemon learns from AdGuard). It returns hard errors and warnings per name. Without a router context it applies only the rules the file alone can decide. Semantics are ADR 0013's: `x` covers x and everything below; `*.x` covers strictly below.

CLI: `curfew add-dns-name <mac|name> <dns-name>` and `curfew remove-dns-name <mac|name> <dns-name>`, local file only (`-registry`), modelled on `curfew set-ip` (same flag parsing, same device resolution, same "run curfew push to apply it" ending, printing warnings). Usage text says to quote `*`. `set-ip --clear` refuses on a device with names, saying to remove them first.

Merge: `sameDevice`, `Equal` and `Merge3` compare `dns_names` as one set-valued field; a new conflict kind "local DNS names changed differently on both sides"; the conflict report lists base, laptop and router sets.

## Acceptance criteria

- [x] Validator unit tests for every hard error and warning in design-notes Decision 3, including the overlap matrix (`x`, `*.x`, `a.x`, across and within devices), local domain from `local='/lan/'` and from `domain='lan'`, an NTP hostname, `home.arpa` allowed, `*.sh` refused, a two-label name warned, IDN only as `xn--`.
- [x] Registry tests: canonical load, a bad name kept, strict add/remove on an unregistered MAC, add refused without a fixed address, clear-ip refused with names.
- [x] Merge tests: names on one side merge; names vs rename merge; names changed differently conflict naming both sets; `Equal` sees a names-only difference; spelling and order are equal after load.
- [x] CLI tests in the style of the existing set-ip tests, against temp registry files.
- [x] Tests write only temp files; the real `config/local` is untouched.

## Blocked by

- None. Can start immediately.

## Prompt

Goal: let a household give a registered device local DNS names in its local `devices.json`, with one validator that the CLI, `push`, the devices page and the daemon will all call. Read `docs/spikes/local-dns-names/design-notes.md` (Decisions 1, 2, 3, 8, 9), ADR 0013 (meaning of a name, A only, fixed address required) and ADR 0012 (the fixed-address precedent you are mirroring). Model everything on the fixed address: `registry.Device.IP`, `Registry.SetIP`, `registry/merge.go`, `setip.go` and its tests. Put the validator where both the laptop binary and the daemon can import it without breaking `separation_test.go` (the daemon must not import the laptop-side deploy package). The JSON field is `dns_names`. Done = all tests above, verify green, README command table updated with the two commands.

## Decisions (made while building, 2026-11-18)

- **The validator is its own pure package, `internal/dnsnames`**, importing nothing of curfew's, so the registry, both binaries and the page share it without touching `separation_test.go`'s boundary. It owns the meaning of a name (`Covers`, `Overlaps`) as well as the rules.
- **Within one device, overlap means one name contains the other** (names form a tree), so the contained one is refused as redundant and the containing one stays valid.
- **The two-label warning is the only warning the validator produces.** Story 14's "a public record is fine, the local answer wins" cannot be detected offline and is true of every name, so the CLI states it on every add instead of the validator warning about it.
- **`AddDNSName` returns the warnings**, and refuses an exact duplicate rather than silently keeping one copy, so a household learns the name was already there.
- The router-context rules (local domain, the router's own hostnames) are implemented and unit-tested here; reading that context from the router is the push task's.
