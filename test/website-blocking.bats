#!/usr/bin/env bats
# Tests for website-blocking.sh (reusable block rules)

load "${BATS_TEST_DIRNAME}/test_helper/mocks"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

setup() {
    export PARENTAL_FIREWALL="nft"
    export PARENTAL_CONFIG="${BATS_TMPDIR}/parental_profiles"
    export PARENTAL_WEBSITES_CONFIG="${BATS_TMPDIR}/parental_websites"
    export BLOCK_RULES_CONFIG="${BATS_TMPDIR}/block_rules"
    export PARENTAL_STATE_DIR="${BATS_TMPDIR}/parental-state"
    export MOCK_LOG_DIR="/tmp/mock-state"
    export NSLOOKUP="${BATS_TMPDIR}/mock-nslookup"

    # Mock nslookup
    cat > "$NSLOOKUP" << 'NSLOOKUP'
#!/bin/sh
echo "Server: 127.0.0.1"
echo "Address: 127.0.0.1:53"
echo ""
echo "Non-authoritative answer:"
echo "Name: $1"
echo "Address: 10.0.0.1"
echo "Address: 10.0.0.2"
NSLOOKUP
    chmod +x "$NSLOOKUP"

    # Profiles
    cat > "$PARENTAL_CONFIG" << 'EOF'
eli|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
ishan|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
tia|90|aa:bb:cc:dd:ee:05,aa:bb:cc:dd:ee:06
EOF

    # Block rules (reusable domain lists)
    cat > "$BLOCK_RULES_CONFIG" << 'EOF'
no_streaming|youtube.com,www.youtube.com,tiktok.com,netflix.com
no_gaming|roblox.com,steam.com,epicgames.com
no_social|tiktok.com,snapchat.com,instagram.com
EOF

    # Associations (which profiles use which rules)
    cat > "$PARENTAL_WEBSITES_CONFIG" << 'EOF'
eli|no_streaming
eli|no_gaming
ishan|no_streaming
ishan|no_gaming
tia|no_streaming
EOF

    rm -rf "$PARENTAL_STATE_DIR"
    mkdir -p "$PARENTAL_STATE_DIR" "$MOCK_LOG_DIR"
    reset_mocks
}

teardown() {
    nft delete table inet parental_control 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@test "rules lists all defined block rules" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" rules
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "no_streaming"
    echo "$output" | grep -q "no_gaming"
    echo "$output" | grep -q "no_social"
}

@test "rules shows domain count per rule" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" rules
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "no_streaming: 4 domains"
}

# ---------------------------------------------------------------------------
# Associations / list / status
# ---------------------------------------------------------------------------

@test "list shows all associations" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" list
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "eli/no_streaming"
    echo "$output" | grep -q "eli/no_gaming"
    echo "$output" | grep -q "ishan/no_streaming"
    echo "$output" | grep -q "tia/no_streaming"
}

@test "list shows domains from block_rules (not duplicated)" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" list
    [ "$status" -eq 0 ]
    # Domains should appear for each association
    echo "$output" | grep -q "youtube.com"
    echo "$output" | grep -q "roblox.com"
}

@test "status shows all associations" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "eli/no_streaming"
    echo "$output" | grep -q "tia/no_streaming"
}

@test "status shows disabled initially" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" status
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "disabled"
}

# ---------------------------------------------------------------------------
# Enable / Disable
# ---------------------------------------------------------------------------

@test "enable creates nftables set for profile+rule" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    [ "$status" -eq 0 ]
    nft list set inet parental_control blocked_sites_eli_no_streaming 2>/dev/null
}

@test "enable creates rules for each MAC in profile" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    [ "$status" -eq 0 ]
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "aa:bb:cc:dd:ee:01"
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "aa:bb:cc:dd:ee:02"
}

@test "enable on non-existent rule fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli nonexistent_rule
    [ "$status" -ne 0 ]
    echo "$output" | grep -qi "not found"
}

@test "disable removes nftables rules" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_streaming"
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable eli no_streaming
    [ "$status" -eq 0 ]
    ! nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_streaming"
}

@test "enable writes state file" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    [ "$(cat "$PARENTAL_STATE_DIR/eli_no_streaming_websites")" = "enabled" ]
}

@test "disable writes state file" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable eli no_streaming
    [ "$(cat "$PARENTAL_STATE_DIR/eli_no_streaming_websites")" = "disabled" ]
}

@test "enable is idempotent" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    count=$(nft -a list chain inet parental_control forward 2>/dev/null | grep -c "blocked_sites_eli_no_streaming")
    [ "$count" -eq 2 ]
}

# ---------------------------------------------------------------------------
# Independence from internet blocking
# ---------------------------------------------------------------------------

@test "website blocking is independent of internet blocking" {
    sh "$SCRIPT_DIR/scripts/parental-profiles.sh" block eli
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    sh "$SCRIPT_DIR/scripts/parental-profiles.sh" unblock eli
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_streaming"
}

@test "disabling one rule does not affect another" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_gaming
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable eli no_streaming
    # no_gaming should still be active
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_gaming"
    ! nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_streaming"
}

@test "same rule can be active for multiple profiles simultaneously" {
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli no_streaming
    sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable ishan no_streaming
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_eli_no_streaming"
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_sites_ishan_no_streaming"
}

# ---------------------------------------------------------------------------
# CLI validation
# ---------------------------------------------------------------------------

@test "no command shows usage" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh"
    [ "$status" -eq 0 ]
    echo "$output" | grep -qi "usage"
}

@test "enable without args fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable
    [ "$status" -ne 0 ]
}

@test "disable without args fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" disable
    [ "$status" -ne 0 ]
}

@test "enable with only profile fails" {
    run sh "$SCRIPT_DIR/scripts/website-blocking.sh" enable eli
    [ "$status" -ne 0 ]
}