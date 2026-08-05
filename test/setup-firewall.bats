#!/usr/bin/env bats
# Tests for setup-firewall.sh (nftables MAC allowlist from parental_profiles)

load "${BATS_TEST_DIRNAME}/test_helper/mocks"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

setup() {
    export PARENTAL_CONFIG="${BATS_TMPDIR}/parental_profiles"
    export PARENTAL_WAN_IF="eth1"
    export PARENTAL_LAN_IF="br-lan"
    export MOCK_LOG_DIR="/tmp/mock-state"

    # Profiles config: all MACs from all profiles = allowlist
    cat > "$PARENTAL_CONFIG" << 'EOF'
# Profiles: name|budget|mac1,mac2
dad|0|aa:bb:cc:11:22:31,aa:bb:cc:11:22:32
mom|0|aa:bb:cc:11:22:41,aa:bb:cc:11:22:42
smart_tv|0|aa:bb:cc:99:88:77
alice|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
bob|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
EOF

    mkdir -p "$MOCK_LOG_DIR"
    reset_mocks
}

teardown() {
    nft delete table inet parental_control 2>/dev/null || true
}

@test "generate outputs all MACs from all profiles" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    # Adults
    echo "$output" | grep -q "aa:bb:cc:11:22:31"
    echo "$output" | grep -q "aa:bb:cc:11:22:42"
    # Kids
    echo "$output" | grep -q "aa:bb:cc:dd:ee:01"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:04"
    # IoT
    echo "$output" | grep -q "aa:bb:cc:99:88:77"
}

@test "generate outputs accept and drop rules" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "accept"
    echo "$output" | grep -q "drop"
}

@test "generate skips comment and empty lines" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    ! echo "$output" | grep -q "nft.*#.*add element"
}

@test "apply creates nftables table and set with all MACs" {
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    [ "$status" -eq 0 ]
    nft list table inet parental_control 2>/dev/null
    nft list set inet parental_control allowed_macs 2>/dev/null | grep -q "aa:bb:cc:11:22:31"
    nft list set inet parental_control allowed_macs 2>/dev/null | grep -q "aa:bb:cc:dd:ee:01"
    nft list set inet parental_control allowed_macs 2>/dev/null | grep -q "aa:bb:cc:99:88:77"
}

@test "apply blocks unknown MACs" {
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    nft list chain inet parental_control forward 2>/dev/null | grep -q "drop"
}

@test "apply allows known MACs" {
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    nft list chain inet parental_control forward 2>/dev/null | grep -q "accept"
}

@test "update adds new MACs without flushing forward chain" {
    # First apply
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    # Add a block rule (simulating active ticket block)
    nft add rule inet parental_control forward ether saddr aa:bb:cc:dd:ee:01 drop comment \"blocked_macs\"

    # Update should not flush the forward chain
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" update
    [ "$status" -eq 0 ]

    # The block rule should still exist (forward chain not flushed)
    nft -a list chain inet parental_control forward 2>/dev/null | grep -q "blocked_macs"
}

@test "update removes MACs no longer in config" {
    # Apply with all MACs
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" apply
    nft list set inet parental_control allowed_macs 2>/dev/null | grep -q "aa:bb:cc:11:22:31"

    # Remove a profile
    grep -v "^smart_tv|" "$PARENTAL_CONFIG" > "$PARENTAL_CONFIG.tmp"
    mv "$PARENTAL_CONFIG.tmp" "$PARENTAL_CONFIG"

    # Update
    sh "$SCRIPT_DIR/scripts/setup-firewall.sh" update
    # Smart TV MAC should be gone from the set
    ! nft get element inet parental_control allowed_macs "{ aa:bb:cc:99:88:77 }" 2>/dev/null
}

@test "generate handles empty config" {
    : > "$PARENTAL_CONFIG"
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "drop"
}

@test "generate handles missing config" {
    rm -f "$PARENTAL_CONFIG"
    run sh "$SCRIPT_DIR/scripts/setup-firewall.sh" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "drop"
}