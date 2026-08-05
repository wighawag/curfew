#!/usr/bin/env bats
# Tests for router_config parsing and application

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

setup() {
    export MOCK_LOG_DIR="/tmp/mock-state"
    mkdir -p "$MOCK_LOG_DIR"
}

@test "router_config.example has all required keys" {
    [ -f "$SCRIPT_DIR/config/router_config.example" ]
    grep -q "PPPOE_USERNAME" "$SCRIPT_DIR/config/router_config.example"
    grep -q "PPPOE_PASSWORD" "$SCRIPT_DIR/config/router_config.example"
    grep -q "WIFI_SSID" "$SCRIPT_DIR/config/router_config.example"
    grep -q "WIFI_PASSWORD" "$SCRIPT_DIR/config/router_config.example"
    grep -q "WIFI_ENCRYPTION" "$SCRIPT_DIR/config/router_config.example"
    grep -q "WIFI_CIPHER" "$SCRIPT_DIR/config/router_config.example"
    grep -q "WIFI_COUNTRY" "$SCRIPT_DIR/config/router_config.example"
    grep -q "ROUTER_PASSWORD" "$SCRIPT_DIR/config/router_config.example"
    grep -q "TIMEZONE" "$SCRIPT_DIR/config/router_config.example"
    grep -q "HARDWARE_OFFLOADING" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config.example has WPA2-PSK encryption" {
    grep -q "WIFI_ENCRYPTION=WPA2-PSK" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config.example has ccmp cipher" {
    grep -q "WIFI_CIPHER=ccmp" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config.example has Europe/London timezone" {
    grep -q "TIMEZONE=Europe/London" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config.example has hardware offloading enabled" {
    grep -q "HARDWARE_OFFLOADING=true" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config.example has comment lines starting with #" {
    grep -q "^#" "$SCRIPT_DIR/config/router_config.example"
}

@test "router_config can be sourced as shell variables" {
    cat > "${MOCK_LOG_DIR}/test_router_config" << 'EOF'
PPPOE_USERNAME=test@plusdsl.net
PPPOE_PASSWORD=testpass
WIFI_SSID=TestNet
WIFI_PASSWORD=TestPass123
WIFI_ENCRYPTION=WPA2-PSK
WIFI_CIPHER=ccmp
WIFI_COUNTRY=GB
ROUTER_PASSWORD=adminpass
TIMEZONE=Europe/London
HARDWARE_OFFLOADING=true
EOF
    . "${MOCK_LOG_DIR}/test_router_config"
    [ "$PPPOE_USERNAME" = "test@plusdsl.net" ]
    [ "$PPPOE_PASSWORD" = "testpass" ]
    [ "$WIFI_SSID" = "TestNet" ]
    [ "$WIFI_PASSWORD" = "TestPass123" ]
    [ "$WIFI_ENCRYPTION" = "WPA2-PSK" ]
    [ "$WIFI_COUNTRY" = "GB" ]
    [ "$TIMEZONE" = "Europe/London" ]
    [ "$HARDWARE_OFFLOADING" = "true" ]
}

@test "install.sh references router_config" {
    grep -q "router_config" "$SCRIPT_DIR/install.sh"
}