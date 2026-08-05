#!/usr/bin/env bats
# Tests for setup-firewall.sh

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/scripts/setup-firewall.sh"

setup() {
    export MAC_ALLOWLIST="${BATS_TMPDIR}/mac_allowlist"
    export PARENTAL_WAN_IF="eth1"
    export PARENTAL_LAN_IF="br-lan"
    export FIREWALL_USER="${BATS_TMPDIR}/firewall.user"
    export IPTABLES="${BATS_TMPDIR}/mock-iptables"

    cat > "$MAC_ALLOWLIST" << 'EOF'
# Parents
aa:bb:cc:dd:ee:f1  # Dad's phone
aa:bb:cc:dd:ee:f2  # Mom's phone

# Kids
aa:bb:cc:dd:ee:01  # Alice's phone
aa:bb:cc:dd:ee:02  # Alice's laptop
EOF

    # Create mock iptables that logs calls
    mkdir -p "${BATS_TMPDIR}/mock-state"
    cat > "$IPTABLES" << 'MOCK'
#!/bin/sh
state_file="${BATS_TMPDIR}/mock-state/iptables_rules"
echo "$@" >> "${BATS_TMPDIR}/mock-state/iptables_calls.log"
exit 0
MOCK
    chmod +x "$IPTABLES"
    : > "${BATS_TMPDIR}/mock-state/iptables_calls.log"
}

teardown() {
    true
}

@test "generate outputs ACCEPT rules for each MAC" {
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f1.*ACCEPT"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f2.*ACCEPT"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:01.*ACCEPT"
    echo "$output" | grep -q "aa:bb:cc:dd:ee:02.*ACCEPT"
}

@test "generate outputs DROP rule at the end" {
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    # DROP should be the last non-empty, non-comment line
    echo "$output" | grep -q "iptables -A FORWARD.*-j DROP"
}

@test "generate skips comment lines" {
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    # Comments from the allowlist should not appear as iptables rules
    ! echo "$output" | grep -q "iptables.*#.*ACCEPT"
}

@test "generate skips empty lines" {
    # Add empty lines to allowlist
    echo "" >> "$MAC_ALLOWLIST"
    echo "" >> "$MAC_ALLOWLIST"
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    # Should still work fine
    echo "$output" | grep -q "aa:bb:cc:dd:ee:f1.*ACCEPT"
}

@test "write creates firewall.user file" {
    run sh "$SCRIPT" write
    [ "$status" -eq 0 ]
    [ -f "$FIREWALL_USER" ]
    grep -q "aa:bb:cc:dd:ee:f1" "$FIREWALL_USER"
    grep -q "DROP" "$FIREWALL_USER"
}

@test "apply writes file and calls iptables" {
    run sh "$SCRIPT" apply
    [ "$status" -eq 0 ]
    [ -f "$FIREWALL_USER" ]
    # iptables should have been called
    [ -s "${BATS_TMPDIR}/mock-state/iptables_calls.log" ]
}

@test "generate handles empty allowlist" {
    : > "$MAC_ALLOWLIST"
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    # Should still have the DROP rule
    echo "$output" | grep -q "DROP"
    # Should have no ACCEPT rules
    ! echo "$output" | grep -q "ACCEPT"
}

@test "generate handles missing allowlist file" {
    rm -f "$MAC_ALLOWLIST"
    run sh "$SCRIPT" generate
    [ "$status" -eq 0 ]
    # Should still have the DROP rule
    echo "$output" | grep -q "DROP"
}