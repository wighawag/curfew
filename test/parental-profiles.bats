#!/usr/bin/env bats
# Tests for parental-profiles.sh

load "${BATS_TEST_DIRNAME}/test_helper/mocks"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/scripts/parental-profiles.sh"

setup() {
    # Docker container provides mock iptables, uci, logger at /usr/bin/
    # We just need to set up test config and state
    export PARENTAL_CONFIG="${BATS_TMPDIR}/parental_profiles"
    export PARENTAL_STATE_DIR="${BATS_TMPDIR}/parental-state"
    export MOCK_LOG_DIR="/tmp/mock-state"
    export PARENTAL_WAN_IF="eth1"
    export PARENTAL_LAN_IF="br-lan"
    export SLEEP="true"  # Don't actually sleep in tests
    export PARENTAL_SKIP_AUTOBLOCK=1  # Don't run background auto-block in tests

    cat > "$PARENTAL_CONFIG" << 'EOF'
alice|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
bob|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
teen|0|aa:bb:cc:dd:ee:05,aa:bb:cc:dd:ee:06
EOF

    rm -rf "$PARENTAL_STATE_DIR"
    mkdir -p "$PARENTAL_STATE_DIR" "$MOCK_LOG_DIR"
    reset_mocks
}

teardown() {
    true
}

# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

@test "list shows all profiles" {
    run sh "$SCRIPT" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice"
    echo "$output" | grep -q "bob"
    echo "$output" | grep -q "teen"
}

@test "list shows budget as unlimited for 0" {
    run sh "$SCRIPT" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "teen: budget=unlimited"
}

@test "list shows budget in minutes" {
    run sh "$SCRIPT" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice: budget=120min"
    echo "$output" | grep -q "bob: budget=90min"
}

@test "list shows devices for each profile" {
    run sh "$SCRIPT" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "aa:bb:cc:dd:ee:01"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:03"
}

# ---------------------------------------------------------------------------
# Block / Unblock
# ---------------------------------------------------------------------------

@test "block_profile blocks all MACs in profile" {
    run sh "$SCRIPT" block alice
    [ "$status" -eq 0 ]
    assert_mac_blocked "aa:bb:cc:dd:ee:01"
    assert_mac_blocked "aa:bb:cc:dd:ee:02"
}

@test "block_profile only blocks MACs in that profile" {
    run sh "$SCRIPT" block alice
    [ "$status" -eq 0 ]
    assert_mac_not_blocked "aa:bb:cc:dd:ee:03"
    assert_mac_not_blocked "aa:bb:cc:dd:ee:04"
}

@test "unblock_profile removes all DROP rules for profile MACs" {
    # First block
    sh "$SCRIPT" block alice
    assert_mac_blocked "aa:bb:cc:dd:ee:01"

    # Then unblock
    run sh "$SCRIPT" unblock alice
    [ "$status" -eq 0 ]
    assert_mac_not_blocked "aa:bb:cc:dd:ee:01"
    assert_mac_not_blocked "aa:bb:cc:dd:ee:02"
}

@test "block on non-existent profile fails" {
    run sh "$SCRIPT" block nonexistent
    [ "$status" -ne 0 ]
    echo "$output" | grep -qi "not found"
}

@test "unblock on non-existent profile fails" {
    run sh "$SCRIPT" unblock nonexistent
    [ "$status" -ne 0 ]
    echo "$output" | grep -qi "not found"
}

@test "block is idempotent (blocking twice doesn't add duplicate rules)" {
    sh "$SCRIPT" block alice
    sh "$SCRIPT" block alice
    # Should only have one DROP rule per MAC
    count=$(grep -c "^DROP aa:bb:cc:dd:ee:01$" "$MOCK_LOG_DIR/iptables_state")
    [ "$count" -eq 1 ]
}

@test "unblock is idempotent (unblocking when not blocked doesn't error)" {
    run sh "$SCRIPT" unblock alice
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------

@test "ticket unblocks profile immediately" {
    # First block the profile
    sh "$SCRIPT" block alice
    assert_mac_blocked "aa:bb:cc:dd:ee:01"

    # Issue ticket
    run sh "$SCRIPT" ticket alice 30
    [ "$status" -eq 0 ]
    assert_mac_not_blocked "aa:bb:cc:dd:ee:01"
    assert_mac_not_blocked "aa:bb:cc:dd:ee:02"
}

@test "ticket records entry in tickets file" {
    sh "$SCRIPT" block alice
    sh "$SCRIPT" ticket alice 30
    [ -f "$PARENTAL_STATE_DIR/tickets" ]
    grep -q "^alice 30 " "$PARENTAL_STATE_DIR/tickets"
}

@test "ticket on non-existent profile fails" {
    run sh "$SCRIPT" ticket nonexistent 30
    [ "$status" -ne 0 ]
}

@test "ticket with invalid duration fails" {
    run sh "$SCRIPT" ticket alice 0
    [ "$status" -ne 0 ]
    run sh "$SCRIPT" ticket alice -5
    [ "$status" -ne 0 ]
    run sh "$SCRIPT" ticket alice abc
    [ "$status" -ne 0 ]
}

@test "ticket without duration fails" {
    run sh "$SCRIPT" ticket alice
    [ "$status" -ne 0 ]
}

@test "tickets command shows active tickets" {
    sh "$SCRIPT" block alice
    sh "$SCRIPT" ticket alice 30
    run sh "$SCRIPT" tickets
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice"
    echo "$output" | grep -q "30"
}

@test "tickets command shows no active tickets when empty" {
    run sh "$SCRIPT" tickets
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "no active tickets"
}

# ---------------------------------------------------------------------------
# Time budgets
# ---------------------------------------------------------------------------

@test "budget-check increments usage counter" {
    sh "$SCRIPT" budget-check alice
    used=$(cat "$PARENTAL_STATE_DIR/alice_used")
    [ "$used" -eq 1 ]
}

@test "budget-check blocks profile when budget exceeded" {
    # Bob has 90 min budget. Set used to 89, then check.
    echo "89" > "$PARENTAL_STATE_DIR/alice_used"  # wait, use bob
    echo "89" > "$PARENTAL_STATE_DIR/bob_used"
    echo "$(date +%Y-%m-%d)" > "$PARENTAL_STATE_DIR/bob_day"

    sh "$SCRIPT" budget-check bob
    # Budget is 90, used becomes 90, should be blocked
    assert_mac_blocked "aa:bb:cc:dd:ee:03"
    assert_mac_blocked "aa:bb:cc:dd:ee:04"
}

@test "budget-check does not block when under budget" {
    echo "10" > "$PARENTAL_STATE_DIR/alice_used"
    echo "$(date +%Y-%m-%d)" > "$PARENTAL_STATE_DIR/alice_day"

    sh "$SCRIPT" budget-check alice
    # Budget is 120, used becomes 11, should NOT be blocked
    assert_mac_not_blocked "aa:bb:cc:dd:ee:01"
}

@test "budget-check skips profiles with 0 budget (unlimited)" {
    sh "$SCRIPT" budget-check teen
    assert_mac_not_blocked "aa:bb:cc:dd:ee:05"
    assert_mac_not_blocked "aa:bb:cc:dd:ee:06"
}

@test "budget-check resets on new day" {
    # Set old date and some usage
    echo "100" > "$PARENTAL_STATE_DIR/alice_used"
    echo "2020-01-01" > "$PARENTAL_STATE_DIR/alice_day"

    sh "$SCRIPT" budget-check alice
    # Should have reset
    used=$(cat "$PARENTAL_STATE_DIR/alice_used")
    [ "$used" -eq 1 ]
}

@test "budget-check with no profile checks all profiles" {
    sh "$SCRIPT" budget-check
    # All profiles should have usage incremented
    [ "$(cat "$PARENTAL_STATE_DIR/alice_used")" -eq 1 ]
    [ "$(cat "$PARENTAL_STATE_DIR/bob_used")" -eq 1 ]
    # teen has 0 budget, should not have usage tracked
    [ ! -f "$PARENTAL_STATE_DIR/teen_used" ] || \
      [ "$(cat "$PARENTAL_STATE_DIR/teen_used")" = "0" ]
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@test "status shows all profiles" {
    run sh "$SCRIPT" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice"
    echo "$output" | grep -q "bob"
    echo "$output" | grep -q "teen"
}

@test "status shows blocked status after block" {
    sh "$SCRIPT" block alice
    run sh "$SCRIPT" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "blocked"
}

# ---------------------------------------------------------------------------
# CLI validation
# ---------------------------------------------------------------------------

@test "no command shows usage" {
    run sh "$SCRIPT"
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "usage"
}

@test "help flag shows usage" {
    run sh "$SCRIPT" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "usage"
}

@test "unknown command fails" {
    run sh "$SCRIPT" frobnicate
    [ "$status" -ne 0 ]
}

@test "block without profile name fails" {
    run sh "$SCRIPT" block
    [ "$status" -ne 0 ]
}

@test "reset clears usage counter" {
    echo "50" > "$PARENTAL_STATE_DIR/alice_used"
    run sh "$SCRIPT" reset alice
    [ "$status" -eq 0 ]
    [ "$(cat "$PARENTAL_STATE_DIR/alice_used")" -eq 0 ]
}