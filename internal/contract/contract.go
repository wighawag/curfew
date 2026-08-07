// Package contract holds the names and ordering of the nftables objects that
// make up the enforcement contract.
//
// It exists because TWO packages need these names and only one of them is
// allowed to touch a firewall. internal/enforce builds the ruleset with
// netlink; internal/deploy reads it back over ssh to verify an install
// actually enforces. The laptop binary must not import internal/enforce (see
// separation_test.go), so the names cannot live there, and duplicating them
// caused a real bug: the verification hardcoded a table name that a rename
// would silently desynchronise, turning "installed correctly" into "the table
// is not present" with nothing wrong.
//
// This package deliberately has NO dependencies. Anything that needs a
// netlink library does not belong here.
package contract

// Table is the dedicated nftables table, kept separate from OpenWrt's fw4 so
// the two never mix.
const Table = "curfew"

// Sets and chains within the table.
const (
	// ManualBlockedSet holds MACs a parent has blocked until they say
	// otherwise. It is matched FIRST, above the ticket accept, so a child
	// cannot ticket their way out of being grounded.
	ManualBlockedSet = "manual_blocked_macs"
	// TicketSet holds MACs with a live time-limited grant. Its elements carry
	// KERNEL timeouts and vanish on their own, which is why a ticket needs no
	// background process and no bookkeeping on expiry.
	TicketSet = "ticket_macs"
	// BlockedSet holds MACs currently blocked by a schedule window or an
	// exhausted budget. It is matched ABOVE AllowedSet, so being registered
	// does not save you from your bedtime, and BELOW TicketSet, so a ticket
	// overrides it.
	BlockedSet = "blocked_macs"
	// AllowedSet holds every registered MAC.
	AllowedSet = "allowed_macs"
	// PolicyChain holds the ordering contract.
	PolicyChain = "policy"
	// BaseChain is the hooked chain that narrows to LAN-to-WAN before jumping
	// to PolicyChain.
	BaseChain = "forward"
)

// Reason names why a tier acts, using the vocabulary of
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md.
// A profile's block carries a SET of these and lifts only when the set empties.
const (
	ReasonManual   = "manual"
	ReasonTicket   = "ticket"
	ReasonSchedule = "schedule"
	// ReasonAllowlist is not a block reason; it names the tier that lets a
	// registered device out.
	ReasonAllowlist = "allowlist"
)

// Tier is one rung of the ordering contract: a set, and what happens to a
// packet whose source MAC is in it.
type Tier struct {
	// Set is the nftables set this tier matches on.
	Set string
	// Accept is the verdict: true accepts the packet, false drops it.
	Accept bool
	// Reason names the tier in the domain's own vocabulary, so a UI can say
	// WHY a device is in the state it is in without keeping its own copy of
	// the ordering.
	Reason string
	// KernelTimeout marks a set whose elements expire on their own. Such a
	// set holds LIVE RUNTIME STATE rather than desired state: it is never
	// computed from config, it is read back off the kernel and carried across
	// a rebuild with its remaining deadline intact.
	KernelTimeout bool
}

// Tiers IS the policy. The order of this slice is the order the rules are
// matched in, and it is fixed by
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md:
// manual block, ticket, schedule/budget block, allowlist, then a terminal drop
// that internal/enforce appends after the last tier.
//
// It is DATA rather than a sequence of statements because two places depend on
// it and they must not be able to drift: internal/enforce builds the chain by
// walking this slice, and internal/httpui decides what a device's state
// actually is by walking the same slice in the same order. Reordering it here
// changes both, which is what makes the packet-path tests a check on the UI's
// story too.
//
// guest_macs is deliberately ABSENT rather than present-and-empty. It belongs
// between the ticket accept and the block per ADR 0006, and it is not built:
// shipping an accept rule for a set that nothing ever populates would put an
// unexercised accept in the middle of the chain that no packet-path test
// covers. Add it here, with its packet-path test, when guest passes are built.
var Tiers = []Tier{
	{Set: ManualBlockedSet, Accept: false, Reason: ReasonManual},
	{Set: TicketSet, Accept: true, Reason: ReasonTicket, KernelTimeout: true},
	{Set: BlockedSet, Accept: false, Reason: ReasonSchedule},
	{Set: AllowedSet, Accept: true, Reason: ReasonAllowlist},
}

// HookPriority runs this table ahead of fw4 without mixing into it.
const HookPriority = -10

// Budget accounting lives in its OWN table, and that separation is forced
// rather than tidy.
//
// internal/enforce replaces the WHOLE enforcement table on every apply, and an
// apply happens on every drift: every schedule boundary, every device edit,
// every block. A counter living in that table is therefore destroyed several
// times a night. Measured, not reasoned: a named counter created in the curfew
// table read {bytes:4242} before an apply and was GONE afterwards (0 objects
// present), while the same counter in a separate table read identically before
// and after. Budget accounting would have been quietly wrong rather than
// visibly broken, which is the failure mode this project exists to remove.
//
// Tickets survive that same replace only because they are explicitly read back
// and re-emitted. Counters could have been carried the same way; a separate
// table is chosen instead because it is what ADR 0001's hook-priority split
// already points at, and because it needs no carry-over step that a future
// change can forget. See docs/adr/0009-the-budget-continuity-model.md.
const (
	// AccountingTable holds counters ONLY. Nothing in it can affect a packet.
	AccountingTable = "curfew_accounting"
	// AccountingChain is hooked at AccountingPriority and contains counter
	// rules with no verdict.
	AccountingChain = "accounting"
)

// AccountingPriority runs accounting AFTER enforcement, which is what makes
// accounting count only traffic that SURVIVED enforcement. Without that a
// blocked device's retries would burn the child's allowance, contradicting
// ADR 0001. Measured on the packet path: with enforcement at -10 and
// accounting at 0, a schedule-blocked device's retries moved the counter by
// exactly 0 bytes, and so did a manually blocked device's.
const AccountingPriority = 0
