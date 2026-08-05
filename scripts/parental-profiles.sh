#!/bin/sh
# ============================================================================
# parental-profiles.sh - Profile-based parental control for OpenWrt
#
# Works with both nftables (default in OpenWrt 22.03+) and iptables.
# Auto-detects which firewall is available.
#
# Uses a dedicated nftables table (inet parental_control) with MAC address sets.
# This is cleaner than adding individual rules and doesn't mix with fw4.
#
# Features:
#   - Block/unblock all devices in a profile
#   - Time-limited tickets (temporary unblock, auto-expires)
#   - Daily time budgets shared across all devices in a profile
#   - Schedule-based blocking via cron
#
# Config file: /etc/config/parental_profiles
# Format: profile_name|budget_minutes_per_day|mac1,mac2,mac3
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u  # Error on unset variables

CONFIG="${PARENTAL_CONFIG:-/etc/config/parental_profiles}"
STATE_DIR="${PARENTAL_STATE_DIR:-/tmp/parental-profiles}"
WAN_IF="${PARENTAL_WAN_IF:-$(uci get network.wan.device 2>/dev/null || echo "eth1")}"
# For PPPoE, the actual L3 device is pppoe-wan, not eth1
WAN_L3_IF="$(ifstatus wan 2>/dev/null | grep -o '"l3_device".*' | cut -d'"' -f4)"
[ -n "$WAN_L3_IF" ] && WAN_IF="$WAN_L3_IF"
LAN_IF="${PARENTAL_LAN_IF:-br-lan}"
LOGGER="${LOGGER:-logger}"
SLEEP="${SLEEP:-sleep}"
DATE="${DATE:-date}"

# Firewall backend detection
NFT_BIN="${NFT:-nft}"
IPTABLES_BIN="${IPTABLES:-iptables}"
NFT_TABLE="parental_control"
NFT_SET="blocked_macs"

# Detect which firewall backend to use
detect_firewall() {
    if command -v "$NFT_BIN" >/dev/null 2>&1 && $NFT_BIN --version >/dev/null 2>&1; then
        echo "nft"
    elif command -v "$IPTABLES_BIN" >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

FIREWALL_BACKEND="${PARENTAL_FIREWALL:-$(detect_firewall)}"

# Ensure state directory exists
WEBSITE_BLOCKING_BIN="${WEBSITE_BLOCKING:-website-blocking.sh}"

mkdir -p "$STATE_DIR" 2>/dev/null || true

# ----------------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------------

log() {
    $LOGGER -t parental "$1" 2>/dev/null || echo "[parental] $1" >&2
}

get_profile_macs() {
    grep "^$1|" "$CONFIG" 2>/dev/null | cut -d'|' -f3 | tr ',' ' '
}

get_profile_budget() {
    local budget
    budget=$(grep "^$1|" "$CONFIG" 2>/dev/null | cut -d'|' -f2)
    echo "${budget:-0}"
}

profile_exists() {
    grep -q "^$1|" "$CONFIG" 2>/dev/null
}

# ----------------------------------------------------------------------------
# nftables operations
# ----------------------------------------------------------------------------

# Initialize the nftables table and set (idempotent)
nft_init() {
    $NFT_BIN list table inet "$NFT_TABLE" 2>/dev/null && return 0
    $NFT_BIN add table inet "$NFT_TABLE" 2>/dev/null
    $NFT_BIN add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority -10; policy accept; }' 2>/dev/null
    $NFT_BIN add set inet "$NFT_TABLE" "$NFT_SET" '{ type ether_addr; }' 2>/dev/null
    $NFT_BIN add rule inet "$NFT_TABLE" forward ether saddr "@$NFT_SET" drop 2>/dev/null
}

# Block a MAC via nftables (add to set)
nft_block_mac() {
    local mac="$1"
    nft_init
    $NFT_BIN add element inet "$NFT_TABLE" "$NFT_SET" "{ $mac }" 2>/dev/null
}

# Unblock a MAC via nftables (remove from set)
nft_unblock_mac() {
    local mac="$1"
    $NFT_BIN delete element inet "$NFT_TABLE" "$NFT_SET" "{ $mac }" 2>/dev/null
}

# Check if a MAC is blocked via nftables
nft_is_mac_blocked() {
    local mac="$1"
    $NFT_BIN get element inet "$NFT_TABLE" "$NFT_SET" "{ $mac }" 2>/dev/null
}

# List all blocked MACs via nftables
nft_list_blocked() {
    $NFT_BIN list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null | grep -o '[0-9a-fA-F:]\{17\}'
}

# ----------------------------------------------------------------------------
# iptables operations (fallback)
# ----------------------------------------------------------------------------

iptables_block_mac() {
    local mac="$1"
    $IPTABLES_BIN -C FORWARD -m mac --mac-source "$mac" -j DROP 2>/dev/null && return 0
    $IPTABLES_BIN -I FORWARD 1 -m mac --mac-source "$mac" -j DROP 2>/dev/null
}

iptables_unblock_mac() {
    local mac="$1"
    while $IPTABLES_BIN -D FORWARD -m mac --mac-source "$mac" -j DROP 2>/dev/null; do
        :
    done
}

iptables_is_mac_blocked() {
    local mac="$1"
    $IPTABLES_BIN -C FORWARD -m mac --mac-source "$mac" -j DROP 2>/dev/null
}

iptables_list_blocked() {
    $IPTABLES_BIN -L FORWARD -n 2>/dev/null | grep -o '[0-9a-fA-F:]\{17\}'
}

# ----------------------------------------------------------------------------
# Firewall abstraction layer
# ----------------------------------------------------------------------------

block_mac() {
    local mac="$1"
    case "$FIREWALL_BACKEND" in
        nft)      nft_block_mac "$mac" ;;
        iptables) iptables_block_mac "$mac" ;;
        none)     log "WARNING: no firewall backend available, cannot block $mac" ;;
    esac
    log "Blocked MAC: $mac"
}

unblock_mac() {
    local mac="$1"
    case "$FIREWALL_BACKEND" in
        nft)      nft_unblock_mac "$mac" ;;
        iptables) iptables_unblock_mac "$mac" ;;
        none)     log "WARNING: no firewall backend available, cannot unblock $mac" ;;
    esac
    log "Unblocked MAC: $mac"
}

is_mac_blocked() {
    local mac="$1"
    case "$FIREWALL_BACKEND" in
        nft)      nft_is_mac_blocked "$mac" ;;
        iptables) iptables_is_mac_blocked "$mac" ;;
        none)     return 1 ;;
    esac
}

list_blocked_macs() {
    case "$FIREWALL_BACKEND" in
        nft)      nft_list_blocked ;;
        iptables) iptables_list_blocked ;;
        none)     echo "" ;;
    esac
}

# ----------------------------------------------------------------------------
# Profile operations
# ----------------------------------------------------------------------------

block_profile() {
    local profile="$1"
    if ! profile_exists "$profile"; then
        echo "Error: profile '$profile' not found" >&2
        return 1
    fi
    for mac in $(get_profile_macs "$profile"); do
        block_mac "$mac"
    done
    echo "blocked" > "$STATE_DIR/${profile}_status"
    log "Profile '$profile' blocked"
}

unblock_profile() {
    local profile="$1"
    if ! profile_exists "$profile"; then
        echo "Error: profile '$profile' not found" >&2
        return 1
    fi
    for mac in $(get_profile_macs "$profile"); do
        unblock_mac "$mac"
    done
    echo "allowed" > "$STATE_DIR/${profile}_status"
    log "Profile '$profile' unblocked"
}

# ----------------------------------------------------------------------------
# Ticket system
# ----------------------------------------------------------------------------

issue_ticket() {
    local profile="$1"
    local minutes="$2"

    if ! profile_exists "$profile"; then
        echo "Error: profile '$profile' not found" >&2
        return 1
    fi

    if [ -z "$minutes" ]; then
        echo "Error: invalid duration '$minutes'" >&2
        return 1
    fi

    # Check that minutes is a positive integer
    case "$minutes" in
        ''|*[!0-9]*)
            echo "Error: invalid duration '$minutes'" >&2
            return 1
            ;;
    esac

    if [ "$minutes" -lt 1 ]; then
        echo "Error: invalid duration '$minutes'" >&2
        return 1
    fi

    unblock_profile "$profile"

    # Also disable any active website blocking rules for this profile
    # (tickets override everything: internet block + website blocks)
    # Save which rules were active so we can re-enable them on expiry
    local saved_rules_file="$STATE_DIR/${profile}_ticket_saved_rules"
    : > "$saved_rules_file"
    if [ -n "$(command -v sh 2>/dev/null)" ]; then
        for f in "$STATE_DIR"/${profile}_*_websites; do
            [ -f "$f" ] || continue
            local wstatus
            wstatus=$(cat "$f")
            [ "$wstatus" = "enabled" ] || continue
            local wname
            wname=$(basename "$f" _websites)
            local wrule
            wrule=$(echo "$wname" | sed 's/^[^_]*_//')
            echo "$wrule" >> "$saved_rules_file"
            $WEBSITE_BLOCKING_BIN disable "$profile" "$wrule" 2>/dev/null
        done
    fi

    local timestamp
    timestamp=$($DATE +%s)
    echo "$profile $minutes $timestamp" >> "$STATE_DIR/tickets"

    # Schedule auto-block after X minutes (background process)
    # Skip in tests if PARENTAL_SKIP_AUTOBLOCK is set
    if [ -z "${PARENTAL_SKIP_AUTOBLOCK:-}" ]; then
        (
            $SLEEP $((minutes * 60))
            block_profile "$profile"
            # Re-enable website blocking rules that were active before the ticket
            if [ -f "$saved_rules_file" ]; then
                while read -r wrule; do
                    [ -n "$wrule" ] && $WEBSITE_BLOCKING_BIN enable "$profile" "$wrule" 2>/dev/null
                done < "$saved_rules_file"
                rm -f "$saved_rules_file"
            fi
            sed -i "/^$profile $minutes $timestamp$/d" "$STATE_DIR/tickets" 2>/dev/null
        ) &
    fi

    log "Ticket issued: '$profile' for $minutes minutes"
    return 0
}

list_tickets() {
    if [ ! -f "$STATE_DIR/tickets" ] || [ ! -s "$STATE_DIR/tickets" ]; then
        echo "No active tickets"
        return 0
    fi
    echo "Active tickets:"
    echo "Profile    | Minutes | Issued at"
    echo "-----------|---------|----------"
    while read -r profile mins ts; do
        local issued_at
        issued_at=$($DATE -d "@$ts" "+%H:%M:%S" 2>/dev/null || echo "$ts")
        printf "%-10s | %-7s | %s\n" "$profile" "$mins" "$issued_at"
    done < "$STATE_DIR/tickets"
}

# ----------------------------------------------------------------------------
# Time budget system
# ----------------------------------------------------------------------------

get_today() {
    $DATE +%Y-%m-%d
}

get_used_minutes() {
    local profile="$1"
    cat "$STATE_DIR/${profile}_used" 2>/dev/null || echo "0"
}

reset_usage() {
    local profile="$1"
    echo "0" > "$STATE_DIR/${profile}_used"
    echo "$(get_today)" > "$STATE_DIR/${profile}_day"
    unblock_profile "$profile" 2>/dev/null || true
}

check_budget() {
    local profile="${1:-}"
    local today
    today=$(get_today)

    if [ -z "$profile" ]; then
        for p in $(grep -v '^#' "$CONFIG" 2>/dev/null | cut -d'|' -f1); do
            _check_single_budget "$p" "$today"
        done
    else
        _check_single_budget "$profile" "$today"
    fi
}

_check_single_budget() {
    local profile="$1"
    local today="$2"
    local budget
    budget=$(get_profile_budget "$profile")

    [ "$budget" = "0" ] || [ -z "$budget" ] && return 0

    local last_day
    last_day=$(cat "$STATE_DIR/${profile}_day" 2>/dev/null)
    if [ "$last_day" != "$today" ]; then
        reset_usage "$profile"
    fi

    local used
    used=$(get_used_minutes "$profile")
    used=$((used + 1))
    echo "$used" > "$STATE_DIR/${profile}_used"

    if [ "$used" -ge "$budget" ]; then
        block_profile "$profile"
        log "Budget exceeded: '$profile' ($used/$budget min)"
    fi
}

# ----------------------------------------------------------------------------
# Status and listing
# ----------------------------------------------------------------------------

show_status() {
    echo "Profile    | Budget(min) | Used(min) | Status   | MACs"
    echo "-----------|-------------|-----------|----------|----"
    while IFS='|' read -r name budget macs; do
        [ -z "$name" ] && continue
        case "$name" in \#*) continue ;; esac
        local status
        status=$(cat "$STATE_DIR/${name}_status" 2>/dev/null || echo "unknown")
        local used
        used=$(get_used_minutes "$name")
        [ "$budget" = "0" ] && budget="unlimited"
        printf "%-10s | %-11s | %-9s | %-8s | %s\n" "$name" "$budget" "$used" "$status" "$macs"
    done < "$CONFIG"
    echo ""
    echo "Firewall backend: $FIREWALL_BACKEND"
    echo "Blocked MACs:"
    list_blocked_macs | while read -r mac; do
        [ -n "$mac" ] && echo "  $mac"
    done
}

list_profiles() {
    echo "Profiles configured:"
    if [ ! -f "$CONFIG" ]; then
        echo "  (no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r name budget macs; do
        [ -z "$name" ] && continue
        case "$name" in \#*) continue ;; esac
        if [ "$budget" = "0" ]; then
            echo "  $name: budget=unlimited, devices=$macs"
        else
            echo "  $name: budget=${budget}min/day, devices=$macs"
        fi
    done < "$CONFIG"
}

# ----------------------------------------------------------------------------
# Main command handler
# ----------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: parental-profiles.sh <command> [args]

Commands:
  status                  Show status of all profiles
  list                    List all configured profiles
  block <profile>         Block all devices in a profile
  unblock <profile>       Unblock all devices in a profile
  ticket <profile> <min>  Grant temporary access to a profile (all devices)
  tickets                 List active tickets
  budget-check [profile]  Check time budgets (for cron, runs all if no profile)
  reset <profile>         Reset usage counter for a profile (new day)
  backend                 Show which firewall backend is in use

Options (via environment variables):
  PARENTAL_CONFIG          Config file path (default: /etc/config/parental_profiles)
  PARENTAL_STATE_DIR       State directory (default: /tmp/parental-profiles)
  PARENTAL_WAN_IF          WAN interface (default: auto-detect or eth1)
  PARENTAL_LAN_IF          LAN interface (default: br-lan)
  PARENTAL_FIREWALL        Force firewall backend: nft, iptables, or none
  PARENTAL_SKIP_AUTOBLOCK  Set to 1 to skip background auto-block (for testing)
  NFT                      nft binary path (default: nft)
  IPTABLES                 iptables binary path (default: iptables)
EOF
}

case "${1:-}" in
    block)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        block_profile "$2"
        ;;
    unblock)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        unblock_profile "$2"
        ;;
    ticket)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        [ -z "${3:-}" ] && { echo "Error: missing duration" >&2; exit 1; }
        issue_ticket "$2" "$3"
        ;;
    tickets)
        list_tickets
        ;;
    status)
        show_status
        ;;
    list)
        list_profiles
        ;;
    budget-check)
        check_budget "${2:-}"
        ;;
    reset)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        reset_usage "$2"
        ;;
    backend)
        echo "Firewall backend: $FIREWALL_BACKEND"
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "Unknown command: $1" >&2
        usage
        exit 1
        ;;
esac