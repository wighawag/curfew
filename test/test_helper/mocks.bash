#!/bin/bash
# ============================================================================
# mocks.bash - Test helpers for parental control script testing
#
# Works with the mock binaries provided by the Docker test container.
# Supports both nft (nftables) and iptables mock backends.
# ============================================================================

MOCK_LOG_DIR="${MOCK_LOG_DIR:-/tmp/mock-state}"
MOCK_NFT_STATE="${MOCK_LOG_DIR}/nft_state"
MOCK_IPTABLES_STATE="${MOCK_LOG_DIR}/iptables_state"

# Reset mock state between tests
reset_mocks() {
    mkdir -p "$MOCK_LOG_DIR"
    : > "$MOCK_NFT_STATE" 2>/dev/null || true
    : > "$MOCK_IPTABLES_STATE" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/nft.log" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/iptables.log" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/logger.log" 2>/dev/null || true
}

# Assert that a specific MAC is blocked
# Uses the appropriate state file based on FIREWALL_BACKEND
assert_mac_blocked() {
    local mac="$1"
    local state_file
    if [ "${PARENTAL_FIREWALL:-nft}" = "iptables" ]; then
        state_file="$MOCK_IPTABLES_STATE"
    else
        state_file="$MOCK_NFT_STATE"
    fi
    grep -q "$mac" "$state_file"
}

# Assert that a specific MAC is NOT blocked
assert_mac_not_blocked() {
    local mac="$1"
    local state_file
    if [ "${PARENTAL_FIREWALL:-nft}" = "iptables" ]; then
        state_file="$MOCK_IPTABLES_STATE"
    else
        state_file="$MOCK_NFT_STATE"
    fi
    ! grep -q "$mac" "$state_file"
}