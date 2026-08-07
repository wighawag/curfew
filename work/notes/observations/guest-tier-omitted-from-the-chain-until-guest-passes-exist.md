---
title: The guest tier is omitted from the chain rather than shipped empty, which departs from the enforcement spec
slug: guest-tier-omitted-from-the-chain-until-guest-passes-exist
---

The enforcement contract spec says `guest_macs` "is created but never populated. The set and its accept rule ship as part of the ordering contract so guest access can be added later without touching the skeleton."

The manual-block and ticket work did NOT do that. `contract.Tiers` carries four tiers (manual, ticket, schedule/budget, allowlist) and no guest tier, with a comment saying where it goes when it is built.

The reason, recorded because it is a deliberate departure and not an oversight:

- Guest passes were explicitly out of scope for that change, so nothing would ever put an element in the set.
- An accept rule matching a permanently empty set sits in the middle of a chain whose ORDER is the policy, and no packet-path test can cover it, because covering it would mean populating the set, which is the feature. Under `docs/adr/0004-tests-assert-on-the-packet-path.md` that is an unexercised enforcement rule, which is the shape of thing this project keeps finding broken.
- The "without touching the skeleton" benefit is smaller than it looks now that the order is DATA. Adding the tier is one line in `contract.Tiers` plus a reader in the two places that walk it, and both of those places FAIL LOUDLY on a tier they do not know about rather than silently skipping it, so the addition cannot be half-done.

What a builder of guest passes should know: add the tier between `TicketSet` and `BlockedSet`, and the compiler and tests will then demand the two readers (`enforce.Desired.forSet` and `httpui.readFirewall`) and, per ADR 0004, a packet-path test for the new accept.
