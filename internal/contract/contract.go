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
	// AllowedSet holds every registered MAC.
	AllowedSet = "allowed_macs"
	// PolicyChain holds the ordering contract.
	PolicyChain = "policy"
	// BaseChain is the hooked chain that narrows to LAN-to-WAN before jumping
	// to PolicyChain.
	BaseChain = "forward"
)

// HookPriority runs this table ahead of fw4 without mixing into it.
const HookPriority = -10
