#!/bin/bash
# ============================================================================
# mocks.bash - Test helpers for parental control script testing
#
# The container runs a real OpenWrt userland, so uci, logger and nft are the
# real binaries and nothing here mocks them. What remains are shared
# assertions plus state reset between tests.
# ============================================================================

MOCK_LOG_DIR="${MOCK_LOG_DIR:-/tmp/mock-state}"
MOCK_NFT_TABLE="${NFT_TABLE:-parental_control}"
MOCK_NFT_SET="${NFT_SET:-blocked_macs}"

# Reset state between tests
reset_mocks() {
    mkdir -p "$MOCK_LOG_DIR"

    # Flush real nftables table if it exists
    nft flush table inet "$MOCK_NFT_TABLE" 2>/dev/null || true
    nft delete table inet "$MOCK_NFT_TABLE" 2>/dev/null || true
}

# Assert that a specific MAC is blocked
assert_mac_blocked() {
    local mac="$1"
    nft get element inet "$MOCK_NFT_TABLE" "$MOCK_NFT_SET" "{ $mac }" 2>/dev/null
}

# Assert that a specific MAC is NOT blocked
assert_mac_not_blocked() {
    local mac="$1"
    ! nft get element inet "$MOCK_NFT_TABLE" "$MOCK_NFT_SET" "{ $mac }" 2>/dev/null
}
