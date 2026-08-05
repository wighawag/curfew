#!/bin/bash
# ============================================================================
# mocks.bash - Test helpers for parental control script testing
#
# Uses REAL nftables (installed in Docker) for nft backend tests.
# Uses mock iptables for iptables backend tests.
# Mocks uci and logger (OpenWrt-specific).
# ============================================================================

MOCK_LOG_DIR="${MOCK_LOG_DIR:-/tmp/mock-state}"
MOCK_NFT_TABLE="${NFT_TABLE:-parental_control}"
MOCK_NFT_SET="${NFT_SET:-blocked_macs}"
MOCK_IPTABLES_STATE="${MOCK_LOG_DIR}/iptables_state"

# Reset state between tests
reset_mocks() {
    mkdir -p "$MOCK_LOG_DIR"

    # Flush real nftables table if it exists
    nft flush table inet "$MOCK_NFT_TABLE" 2>/dev/null || true
    nft delete table inet "$MOCK_NFT_TABLE" 2>/dev/null || true

    # Reset iptables mock state
    : > "$MOCK_IPTABLES_STATE" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/iptables.log" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/logger.log" 2>/dev/null || true
}

# Assert that a specific MAC is blocked
# Works with both nft (real) and iptables (mock) backends
assert_mac_blocked() {
    local mac="$1"
    if [ "${PARENTAL_FIREWALL:-nft}" = "iptables" ]; then
        grep -q "^DROP $mac$" "$MOCK_IPTABLES_STATE"
    else
        # Use real nft to check
        nft get element inet "$MOCK_NFT_TABLE" "$MOCK_NFT_SET" "{ $mac }" 2>/dev/null
    fi
}

# Assert that a specific MAC is NOT blocked
assert_mac_not_blocked() {
    local mac="$1"
    if [ "${PARENTAL_FIREWALL:-nft}" = "iptables" ]; then
        ! grep -q "^DROP $mac$" "$MOCK_IPTABLES_STATE"
    else
        # Use real nft to check - should fail
        ! nft get element inet "$MOCK_NFT_TABLE" "$MOCK_NFT_SET" "{ $mac }" 2>/dev/null
    fi
}

# Assert that a profile's website blocking is active
# Checks that the nftables set for the profile has entries
assert_websites_blocked() {
    local profile="$1"
    local set_name="blocked_sites_${profile}"
    # The set should exist and have at least one element
    nft list set inet "$MOCK_NFT_TABLE" "$set_name" 2>/dev/null | grep -q '[0-9]'
}

# Assert that a profile's website blocking is NOT active
assert_websites_not_blocked() {
    local profile="$1"
    local set_name="blocked_sites_${profile}"
    # The set should not exist or be empty
    ! nft list set inet "$MOCK_NFT_TABLE" "$set_name" 2>/dev/null | grep -q '[0-9]'
}