# A block carries a SET of reasons, and a manual block outranks a ticket

**Status:** accepted

A profile's block is a **set** of concurrent reasons (`schedule`, `budget`, `manual`), and the block lifts only when the set empties; each operation adds or removes exactly the reason it owns. A **manual** block, meaning an indefinite one a parent imposes until they lift it, **outranks a ticket**; every other reason is overridden by a ticket. This replaces the earlier informal model in which a block was a single value, which was measured to hand a child the rest of the night: with a scalar plus precedence, `manual` overwrites `schedule`, and lifting the manual block lifts everything, so a parent who imposes and then lifts a block at 23:00 silently cancels bedtime.

## Considered Options

- **A set of reasons (chosen).** The only model measured to survive the case above. It is also what lets a status page say "bedtime, and over budget" instead of picking one, and it makes the daily budget reset structurally incapable of clearing a reason it does not own.
- **A scalar with a precedence order (rejected).** Simpler, and indistinguishable from the set on every scenario that does not involve `manual`: both survive a bedtime block crossing its budget, the midnight reset, and a ticket that lets the budget cross mid-block. It fails only, but reliably, when two reasons are concurrently live and the higher-ranked one is cleared first. Recorded because the rejection is non-obvious and someone will propose the scalar again on the grounds that it is simpler.

## Consequences

- **The chain needs TWO block sets, and this is forced rather than stylistic.** A ticket must override a bedtime window and a manual block must outrank a ticket, and one set cannot satisfy both because a set has one position in the chain. So `manual_blocked_macs` sits above the ticket accept and `blocked_macs` (schedule and budget) sits below it. The full ordering is: manual block, ticket, guest, schedule/budget block, website blocking, allowlist, drop.
- **A ticket is an override that lapses, not a mutation.** It adds MACs to a kernel-timeout set and changes nothing else, so on expiry the profile falls back to whatever reasons are live at that moment, with no bookkeeping. Blocking cancels any live ticket, so a later unblock cannot resurrect one; and unblocking before ticketing is a deliberate two-step gesture the frontend performs, never a fused operation.
- **This reverses the precedence recorded earlier**, where a ticket outranked everything. That earlier order made an indefinite parental block unenforceable, because the ticket page is served by the router and remains reachable by the very device being blocked, which was confirmed by measurement: a blocked client loaded the page and issued itself a ticket. The password on that page and this precedence are two independent halves of the same fix, and neither alone is sufficient.
- **Status must still be derived from the firewall**, per `docs/adr/0004-tests-assert-on-the-packet-path.md`. Splitting into two sets means any existing derivation that mapped set membership to a status has to gain a `manual_blocked_macs` case, or a manually blocked profile reads as allowed.
- The policy layer inherits this as a decision rather than a question: `schedule` and `budget` are facts it computes, `manual` is a decision it stores, and all three are members of the same set.
