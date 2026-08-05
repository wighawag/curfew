#!/usr/bin/env bats
# Tests for website-blocking.sh

load "${BATS_TEST_DIRNAME}/test_helper/mocks"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
SCRIPT="sh $SCRIPT_DIR/scripts/website-blocking.sh"

setup() {
    export PARENTAL_FIREWALL="nft"
    export PARENTAL_CONFIG="${BATS_TMPDIR}/parental_profiles"
    export PARENTAL_WEBSITES_CONFIG="${BATS_TMPDIR}/parental_websites"
    export PARENTAL_STATE_DIR="${BATS_TMPDIR}/parental-state"
    export MOCK_LOG_DIR="/tmp/mock-state"
    export NSLOOKUP="${BATS_TMPDIR}/mock-nslookup"

    # Create mock nslookup that returns fake IPs
    cat > "$NSLOOKUP" << 'NSLOOKUP'
#!/bin/sh
# Mock nslookup - returns a fake IP for any domain
echo "Server: 127.0.0.1"
echo "Address: 127.0.0.1:53"
echo ""
echo "Non-authoritative answer:"
echo "Name: $1"
echo "Address: 10.0.0.1"
echo "Address: 10.0.0.2"
NSLOOKUP
    chmod +x "$NSLOOKUP"

    # Profile config (same as parental-profiles tests)
    cat > "$PARENTAL_CONFIG" << 'EOF'
alice|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
bob|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
teen|0|aa:bb:cc:dd:ee:05,aa:bb:cc:dd:ee:06
EOF

    # Website blocking config (with groups)
    cat > "$PARENTAL_WEBSITES_CONFIG" << 'EOF'
alice|after_school|youtube.com,www.youtube.com,tiktok.com
alice|evening|youtube.com,www.youtube.com,tiktok.com,netflix.com
bob|tiktok.com,snapchat.com
EOF

    rm -rf "$PARENTAL_STATE_DIR"
    mkdir -p "$PARENTAL_STATE_DIR" "$MOCK_LOG_DIR"
    reset_mocks
}

teardown() {
    # Clean up nftables
    nft delete table inet parental_control 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

@test "list shows all profiles with website blocking" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice"
    echo "$output" | grep -q "bob"
}

@test "list shows domains for each profile" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "youtube.com"
    echo "$output" | grep -q "tiktok.com"
    echo "$output" | grep -q "snapchat.com"
}

@test "list shows disabled status initially" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "disabled"
}

@test "status shows all profiles" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice"
    echo "$output" | grep -q "bob"
}

# ---------------------------------------------------------------------------
# Enable / Disable
# ---------------------------------------------------------------------------

@test "enable creates nftables set for profile+group" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    [ "$status" -eq 0 ]
    nft list set inet parental_control blocked_sites_alice_after_school 2>/dev/null
}

@test "enable creates nftables rules for each MAC" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    [ "$status" -eq 0 ]
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "aa:bb:cc:dd:ee:01"
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "aa:bb:cc:dd:ee:02"
}

@test "disable removes nftables rules" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"

    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable alice after_school
    [ "$status" -eq 0 ]
    ! nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"
}

@test "enable on non-existent profile fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable nonexistent
    [ "$status" -ne 0 ]
}

@test "enable on non-existent group fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice nonexistent_group
    [ "$status" -ne 0 ]
}

@test "enable writes state file" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    [ "$(cat "$PARENTAL_STATE_DIR/alice_after_school_websites")" = "enabled" ]
}

@test "disable writes state file" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable alice after_school
    [ "$(cat "$PARENTAL_STATE_DIR/alice_after_school_websites")" = "disabled" ]
}

@test "enable is idempotent (enabling twice doesn't create duplicate rules)" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    count=$(nft -a list chain inet parental_control forward 2>/dev/null | grep -c "blocked_sites_alice_after_school")
    [ "$count" -eq 2 ]
}

# ---------------------------------------------------------------------------
# Independence from internet blocking
# ---------------------------------------------------------------------------

@test "website blocking is independent of internet blocking" {
    sh "$SCRIPT_DIR/scripts/parental-profiles.sh" block alice
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/parental-profiles.sh" unblock alice
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"
}

@test "disabling internet unblock does not affect website blocking" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/parental-profiles.sh" unblock alice
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"
}

# ---------------------------------------------------------------------------
# CLI validation
# ---------------------------------------------------------------------------

@test "no command shows usage" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh"
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "usage"
}

@test "enable without profile name fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable
    [ "$status" -ne 0 ]
}

@test "disable without profile name fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable
    [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# Groups: different domain lists at different times
# ---------------------------------------------------------------------------

@test "different groups can be active simultaneously" {
    # Enable after_school group
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    # Enable evening group (different domains) at the same time
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice evening

    # Both groups should have rules
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_evening"
}

@test "disabling one group does not affect the other" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice evening

    # Disable after_school
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable alice after_school

    # evening should still be active
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_evening"
    # after_school should be gone
    ! nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_alice_after_school"
}

@test "each group has its own nftables set" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice after_school
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable alice evening

    # Both sets should exist with different names
    nft list set inet parental_control blocked_sites_alice_after_school 2>/dev/null
    nft list set inet parental_control blocked_sites_alice_evening 2>/dev/null
}

@test "backward compatible with 2-field format (no group)" {
    # bob uses 2-field format (no group) - should use 'default' group
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable bob
    [ "$status" -eq 0 ]
    nft list set inet parental_control blocked_sites_bob_default 2>/dev/null
}

@test "status shows groups" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "alice/after_school"
    echo "$output" | grep -q "alice/evening"
    echo "$output" | grep -q "bob/default"
}