# A budget minute counts actual use, gated by a traffic threshold

**Status:** accepted

A daily time budget counts minutes in which a profile's devices **actually used** the internet, not minutes of wall-clock time, and not minutes of merely being connected. Because a modern phone chatters constantly in the background (push notifications, sync, presence keepalives), "used" cannot mean "any packet at all" or an idle phone in a pocket would burn a child's whole allowance overnight, so a minute counts only when traffic in that minute exceeds a **threshold** above background noise. This is what a parent means by "four hours", and the current implementation means nothing of the sort: `budget-check` increments unconditionally every minute from midnight, so `eli|240` in practice means "blocked at 04:00", regardless of whether any device was even switched on.

## Considered Options

- **Actual use above a threshold (chosen).** Matches the parent's mental model. Costs per-profile traffic accounting and a threshold that must be calibrated against real idle devices rather than guessed.
- **Wall-clock elapsed (rejected; the accidental status quo).** Free to compute and already implemented, but it measures the passage of time rather than usage, which is not a budget in any sense a parent would recognise.
- **Presence-based, counting a minute when a device is connected (rejected).** A two-line change using the ARP table, but a connected-and-idle tablet on a shelf burns the allowance, which reproduces the same complaint in a subtler form.

## Consequences

- Budget accounting needs per-profile traffic counters. The intended shape is nftables named counters in a dedicated accounting chain containing counter rules only, so accounting can never influence a verdict. Two ordering constraints follow from the semantics and must be honoured by whatever hook placement is chosen: accounting must count only traffic that **survives** enforcement (otherwise a blocked device's retries burn the allowance, contradicting the consequence below), and it must not alter any verdict. No hook priority is fixed here deliberately: this ADR settles the semantics, and the exploration spec picks the mechanism.
- The threshold is a tuning parameter with no correct a-priori value. It must be calibrated empirically against real idle household devices, and it should be configurable rather than compiled in, because the right number will differ per device generation.
- The budget can no longer be computed from state files alone; it becomes a function of the firewall's counters. This is consistent with the wider principle that enforcement is ground truth and state files are commentary.
- A blocked or sleeping child no longer burns budget, which is the intended behaviour but also means a budget can now carry over unspent within a day in a way the old behaviour hid.
- The exact measurement mechanism and threshold remain to be spiked; this ADR fixes the semantics, not the implementation.
