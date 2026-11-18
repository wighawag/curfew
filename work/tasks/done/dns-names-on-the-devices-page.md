---
title: See and edit a device's local DNS names on the router's devices page
slug: dns-names-on-the-devices-page
spec: local-dns-names-for-a-device
blockedBy: [push-checks-and-old-daemon-refusal-for-dns-names]
covers: [23]
---

## What to build

The devices page shows each device's local DNS names next to its fixed address, and an add form and a remove button per name. The handler resolves the device, runs the same validator with the router's own context (the reader from `push-checks-and-old-daemon-refusal-for-dns-names`, run locally), refuses on hard errors with the validator's message, saves the registry, and shows the warnings after saving, exactly as the fixed-address form does. Clearing a fixed address on the page is refused while the device has names, with the same message as the CLI.

## Acceptance criteria

- [x] Handler tests in the style of the fixed-address page tests: add, remove, refusal message, warnings shown, clear-ip refused with names, unregistered MAC refused.
- [x] Names written by the page survive a `pull` (they are in the same registry file and field).
- [x] Tests use temp registry files.

## Blocked by

- push-checks-and-old-daemon-refusal-for-dns-names

## Prompt

Goal: let a household manage local DNS names from the router's own page, with exactly the CLI's rules. Read `docs/spikes/local-dns-names/design-notes.md` (Decision 9) and ADR 0013. The fixed-address page work is the template: `internal/httpui/fixedip.go` and its tests. The validator and router-context reader come from the tasks `dns-names-field-validator-and-cli` and `push-checks-and-old-daemon-refusal-for-dns-names`. Done = tests above, verify green.

## Decisions (made while building, 2026-11-18)

- **One handler, `POST /devices/dns-name` with `action=add|remove`**, beside `/devices/ip`. The router context comes from `Server.UseNameContext`, which the daemon wires to its own `uci show dhcp` / `uci show system`; without it the page refuses to ADD (it cannot run every rule) and still allows REMOVE, mirroring the fixed-address form.
- **The add form is shown only on a device with a fixed address**; others say "needs a fixed address", so the refusal is visible before anyone types.
- Names saved by the page live in the same `dns_names` field of the same registry file, so `pull` carries them with no extra work (the registry round-trip and merge tests cover the field).
