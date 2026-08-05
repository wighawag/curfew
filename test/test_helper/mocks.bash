#!/bin/bash
# ============================================================================
# mocks.bash - Test helpers for parental control script testing
#
# Works with the mock binaries provided by the Docker test container.
# Handles state reset between tests and provides assertions.
# ============================================================================

MOCK_LOG_DIR="${MOCK_LOG_DIR:-/tmp/mock-state}"
MOCK_IPTABLES_STATE="${MOCK_LOG_DIR}/iptables_state"

# Reset mock state between tests
reset_mocks() {
    mkdir -p "$MOCK_LOG_DIR"
    : > "$MOCK_IPTABLES_STATE" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/iptables.log" 2>/dev/null || true
    : > "${MOCK_LOG_DIR}/logger.log" 2>/dev/null || true
}

# Assert that a specific MAC is blocked (has a DROP rule)
assert_mac_blocked() {
    local mac="$1"
    grep -q "^DROP $mac$" "$MOCK_IPTABLES_STATE"
}

# Assert that a specific MAC is NOT blocked
assert_mac_not_blocked() {
    local mac="$1"
    ! grep -q "^DROP $mac$" "$MOCK_IPTABLES_STATE"
}

# Assert that an iptables command was called
assert_iptables_called() {
    local pattern="$1"
    grep -q "$pattern" "${MOCK_LOG_DIR}/iptables.log"
}

# Assert that an iptables command was NOT called
assert_iptables_not_called() {
    local pattern="$1"
    ! grep -q "$pattern" "${MOCK_LOG_DIR}/iptables.log"
}