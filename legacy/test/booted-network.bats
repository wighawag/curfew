#!/usr/bin/env bats
# Enforcement with NO environment overrides, against OpenWrt's real network
# stack: ubusd and netifd running, br-lan created and addressed by netifd, and
# the WAN device resolved through ifstatus exactly as on the router.
#
# Every other test file pins the interface with PARENTAL_WAN_IF, because
# ifstatus cannot answer when netifd is not running. That leaves the WAN
# resolution branch permanently untested, and it is not a hypothetical gap:
# commit c20d341 fixed a bug living precisely there, where the allowlist drop
# rule matched the wrong interface and "unknown devices could access the
# internet". These tests are the ones that could have caught it.

load "${BATS_TEST_DIRNAME}/test_helper/booted"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
FIREWALL="$SCRIPT_DIR/scripts/setup-firewall.sh"

ALLOWED_MAC="aa:bb:cc:dd:ee:01"
UNKNOWN_MAC="aa:bb:cc:dd:ee:99"

setup_file() {
    booted_setup
}

teardown_file() {
    booted_teardown
}

setup() {
    export PARENTAL_CONFIG="${BATS_TMPDIR}/booted_profiles"
    cat > "$PARENTAL_CONFIG" << EOF
alice|120|$ALLOWED_MAC
EOF
    # Deliberately NOT set: PARENTAL_WAN_IF and PARENTAL_LAN_IF. The whole
    # point of this file is that the scripts resolve them unaided.
    unset PARENTAL_WAN_IF PARENTAL_LAN_IF
    nft delete table inet parental_control 2>/dev/null || true
}

@test "OpenWrt's network stack is actually running" {
    run booted_services_running
    [ "$status" -eq 0 ]
}

@test "netifd created and addressed br-lan from uci config" {
    # The bridge is not created by the test: netifd builds it from
    # /etc/config/network the way it does on the router.
    run ip -o -4 addr show br-lan
    [ "$status" -eq 0 ]
    [[ "$output" == *"10.99.1.1/24"* ]]
}

@test "ifstatus resolves the WAN device, the branch other tests cannot reach" {
    [ "$(booted_l3 wan)" = "pppoe-wan" ]
    [ "$(booted_l3 lan)" = "br-lan" ]
}

@test "setup-firewall.sh resolves the WAN interface with no override" {
    # The regression guard for c20d341. If resolution ever falls back to the
    # configured device instead of the live L3 device, the generated rules
    # match the wrong interface and enforcement silently stops working.
    run sh "$FIREWALL" generate
    [ "$status" -eq 0 ]
    [[ "$output" == *'oifname "pppoe-wan"'* ]]
    [[ "$output" != *'oifname "eth1"'* ]]
}

@test "an allowlisted device reaches the internet, unaided" {
    booted_client_mac "$ALLOWED_MAC"
    sh "$FIREWALL" apply >/dev/null 2>&1
    run booted_probe
    [ "$status" -eq 0 ]
}

@test "an unknown device is blocked, unaided" {
    # The end-to-end claim: real netifd interfaces, real uci config, real
    # ifstatus resolution, real packets, no environment overrides anywhere.
    booted_client_mac "$UNKNOWN_MAC"
    sh "$FIREWALL" apply >/dev/null 2>&1
    run booted_probe
    [ "$status" -ne 0 ]
}

@test "baseline: the topology forwards when no firewall rules exist" {
    # Without this, a broken topology would report every device as blocked and
    # look like a flawless firewall.
    booted_client_mac "$ALLOWED_MAC"
    run booted_probe
    [ "$status" -eq 0 ]
}
