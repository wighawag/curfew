---
title: google/nftables drives the kernel directly and can replace a whole ruleset atomically, carrying live timeouts
slug: google-nftables-drives-the-kernel-and-replaces-rulesets-atomically
source: 'measured 2026-08-06 with github.com/google/nftables v0.3.0, Go 1.26, CGO_ENABLED=0 static amd64 binary, run inside openwrt/rootfs:x86-64-25.12.4 with NET_ADMIN/SYS_ADMIN/NET_RAW, against the repo packet-path harness (test/test_helper/netns.bash). IMPORTANT FIDELITY LIMIT: a container shares the HOST kernel, so this exercised Linux 6.12.96 (Debian amd64), NOT the router aarch64 OpenWrt 25.12.5 kernel. Netlink is a kernel interface, so unlike the shell tests this gap is not obviously irrelevant and needs one confirmation on the real router.'
---

## The library drives the kernel, with `nft` never invoked

A static Go binary built the entire `parental_control` table (four `ether_addr` sets, a policy chain, a base `forward` hook at priority -10 narrowing LAN to WAN, and a jump) in a single netlink transaction. `nft` was then used only to LOOK, and saw a complete, correct table.

The ruleset enforces on real packets, asserted through the harness with a baseline first: an allowlisted client reached the internet, an unknown MAC was dropped by a rule Go wrote, and the allowlisted client reached it again.

## `ether_addr` timeout sets work, and the REMAINING time is readable

```
element aa:bb:cc:dd:ee:01 timeout=30s expires=29.988s
...4s later...
element aa:bb:cc:dd:ee:01 timeout=30s expires=25.98s
```

`GetSetElements` returns `Expires` as a live countdown, so a UI can render the kernel's own number rather than tracking a parallel one.

## A whole-table replace can carry live elements with their deadlines

This is the load-bearing result. Reading back live elements, then queueing `delete table` plus a full rebuild plus the carried elements in ONE batch, works:

```
carrying aa:bb:cc:dd:ee:01 with 25.98s remaining
OK: whole ruleset replaced in one transaction, live tickets carried
element aa:bb:cc:dd:ee:01 timeout=25.98s expires=25.956s
client STILL reachable: only the carried ticket allows it
```

The client was schedule-blocked and reachable ONLY via the ticket, so a lost carry-over would have shown up as a dropped packet. It did not. A configuration change (a new manual block) landed in the same transaction.

Two details worth knowing:

- The `delete table` may only be queued if the table already exists, or the batch fails with `ENOENT` (`conn.Receive: netlink receive: no such file or directory`). Check existence first, then delete and rebuild in the same batch.
- The carried element's `Timeout` becomes the REMAINING time (25.98s), not the original 30s. The absolute deadline is preserved correctly, but the originally granted duration is lost, so anything wanting to display "a 30 minute ticket" must store that separately.

## A Go ruleset is textually different from the shell one, and identical in behaviour

`nft` renders the library's `ether saddr` match as a raw payload expression:

```
@ll,48,48 @manual_blocked drop
```

Semantically identical (offset 48 bits, length 48 bits, being bytes 6 to 11 of the link-layer header), and it enforces correctly on packets. But any test asserting on ruleset TEXT will break across a shell-to-Go port even when behaviour is unchanged. This is independent evidence for `docs/adr/0004-tests-assert-on-the-packet-path.md`: packet-path assertions survive the port, text assertions do not, which is exactly what a language-agnostic acceptance suite needs.
