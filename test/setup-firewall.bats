#!/usr/bin/env bats
# Tests for setup-firewall.sh (nftables MAC allowlist)

load "${BATS_TEST_DIRNAME}/test_helper/mocks"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

setup() {
    export MAC_ALLOWLIST="${BATS_TMPDIR}/mac_allowlist"
    export PARENTAL_WAN_IF="eth1"
    export PARENTAL_LAN_IF="br-lan"
    export MOCK_LOG_DIR="/tmp/mock-state"

    cat > "$MAC_ALLOWLIST" << 'EOF'
# Parents
aa:bb:cc:dd:ee:f1  # Dad's phone
aa:bb:cc:dd:ee:f2  # Mom's phone

# Kids
aa:bb:cc:dd:ee:01  # Alice's phone
aa:bb:cc:dd:ee:02  # Alice's laptop
EOF

    mkdir -p "$MOCK_LOG_DIR"
    reset_mocks
}

teardown() {
    nft delete table inet parental_control 2>/dev/null || true
}

@test "generate outputs nftables set elements for each MAC" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f1"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f2"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:01"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:02"
}

@test "generate outputs nftables accept and drop rules" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "accept"
    echo "$output" | grep -q "drop"
}

@test "generate skips comment lines" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    # Comments should not appear as nft commands
    ! echo "$output" | grep -q "nft.*#.*add element"
}

@test "generate skips empty lines" {
    echo "" >> "$MAC_ALLOWLIST"
    echo "" >> "$MAC_ALLOWLIST"
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f1"
}

@test "apply creates nftables table and set" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    [ "$status" -eq 0 ]
    # Table should exist
    nft list table inet parental_control 2>/dev/null
    # Set should exist with MACs
    nft list set inet parental_control allowed_macs 2>/dev/null | grep -q "aa:bb:cc:dd:ee:f1"
}

@test "apply blocks unknown MACs (not in allowlist)" {
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    # The forward chain should have a drop rule for unknown MACs
    nft list chain inet parental_control forward 2>/dev/null | grep -q "drop"
}

@test "apply allows known MACs" {
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    # The forward chain should have an accept rule for allowed MACs
    nft list chain inet parental_control forward 2>/dev/null | grep -q "accept"
}

@test "generate handles empty allowlist" {
    : > "$MAC_ALLOWLIST"
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    # Should still have the drop rule
    echo "$output" | grep -q "drop"
}

@test "generate handles missing allowlist file" {
    rm -f "$MAC_ALLOWLIST"
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "drop"
}