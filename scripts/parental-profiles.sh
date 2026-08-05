#!/bin/sh
# ============================================================================
# parental-profiles.sh - Profile-based parental control for OpenWrt
#
# Manages internet access for groups of devices (profiles). Each profile
# contains multiple MAC addresses (e.g. a child's phone + laptop).
# Features:
#   - Block/unblock all devices in a profile
#   - Time-limited tickets (temporary unblock, auto-expires)
#   - Daily time budgets shared across all devices in a profile
#   - Schedule-based blocking via cron
#
# Config file: /etc/config/parental_profiles
# Format: profile_name|budget_minutes_per_day|mac1,mac2,mac3
#   - budget of 0 means unlimited (schedule-only)
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u  # Error on unset variables, but don't exit on non-zero (needed for function returns)

CONFIG="${PARENTAL_CONFIG:-/etc/config/parental_profiles}"
STATE_DIR="${PARENTAL_STATE_DIR:-/tmp/parental-profiles}"
WAN_IF="${PARENTAL_WAN_IF:-$(uci get network.wan.device 2>/dev/null || echo "eth1")}"
LAN_IF="${PARENTAL_LAN_IF:-br-lan}"
IPTABLES="${IPTABLES:-iptables}"
LOGGER="${LOGGER:-logger}"
SLEEP="${SLEEP:-sleep}"
DATE="${DATE:-date}"

# Ensure state directory exists
mkdir -p "$STATE_DIR" 2>/dev/null || true

# ----------------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------------

# Log a message via syslog (or stderr if logger unavailable)
log() {
    $LOGGER -t parental "$1" 2>/dev/null || echo "[parental] $1" >&2
}

# Read a profile's MAC addresses (space-separated)
# $1 = profile name
get_profile_macs() {
    grep "^$1|" "$CONFIG" 2>/dev/null | cut -d'|' -f3 | tr ',' ' '
}

# Read a profile's daily budget in minutes
# $1 = profile name
# Returns: budget minutes, or 0 if unlimited/not found
get_profile_budget() {
    local budget
    budget=$(grep "^$1|" "$CONFIG" 2>/dev/null | cut -d'|' -f2)
    echo "${budget:-0}"
}

# Check if a profile exists in the config
# $1 = profile name
# Returns: 0 if exists, 1 if not
profile_exists() {
    grep -q "^$1|" "$CONFIG" 2>/dev/null
}

# Check if a MAC is currently blocked (has a DROP rule in FORWARD chain)
# $1 = MAC address
# Returns: 0 if blocked, 1 if not
is_mac_blocked() {
    $IPTABLES -C FORWARD -m mac --mac-source "$1" -j DROP 2>/dev/null
}

# ----------------------------------------------------------------------------
# Firewall operations
# ----------------------------------------------------------------------------

# Block a single MAC address (idempotent)
# $1 = MAC address
block_mac() {
    local mac="$1"
    if is_mac_blocked "$mac"; then
        return 0
    fi
    $IPTABLES -I FORWARD 1 -m mac --mac-source "$mac" -j DROP 2>/dev/null
    log "Blocked MAC: $mac"
}

# Unblock a single MAC address (idempotent)
# $1 = MAC address
unblock_mac() {
    local mac="$1"
    # Remove all DROP rules for this MAC (may be multiple)
    while $IPTABLES -D FORWARD -m mac --mac-source "$mac" -j DROP 2>/dev/null; do
        log "Unblocked MAC: $mac"
    done
}

# Block all devices in a profile
# $1 = profile name
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

# Unblock all devices in a profile
# $1 = profile name
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

# Issue a ticket: unblock profile for X minutes, then auto-block
# $1 = profile name
# $2 = minutes
issue_ticket() {
    local profile="$1"
    local minutes="$2"

    if ! profile_exists "$profile"; then
        echo "Error: profile '$profile' not found" >&2
        return 1
    fi

    # Validate input
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

    # Record the ticket
    local timestamp
    timestamp=$($DATE +%s)
    echo "$profile $minutes $timestamp" >> "$STATE_DIR/tickets"

    # Schedule auto-block after X minutes (background process)
    # Skip in tests if PARENTAL_SKIP_AUTOBLOCK is set
    if [ -z "${PARENTAL_SKIP_AUTOBLOCK:-}" ]; then
        (
            $SLEEP $((minutes * 60))
            block_profile "$profile"
            # Remove the ticket record
            sed -i "/^$profile $minutes $timestamp$/d" "$STATE_DIR/tickets" 2>/dev/null
        ) &
    fi

    log "Ticket issued: '$profile' for $minutes minutes"
    return 0
}

# List active tickets
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

# Get today's date string (YYYY-MM-DD)
get_today() {
    $DATE +%Y-%m-%d
}

# Get the used minutes for a profile today
# $1 = profile name
get_used_minutes() {
    local profile="$1"
    cat "$STATE_DIR/${profile}_used" 2>/dev/null || echo "0"
}

# Reset the usage counter for a profile (called on new day)
# $1 = profile name
reset_usage() {
    local profile="$1"
    echo "0" > "$STATE_DIR/${profile}_used"
    echo "$(get_today)" > "$STATE_DIR/${profile}_day"
    # Remove any budget-based block
    unblock_profile "$profile" 2>/dev/null || true
}

# Check and enforce time budget for a profile
# Called by cron every minute
# $1 = profile name (optional, checks all if not specified)
check_budget() {
    local profile="${1:-}"
    local today
    today=$(get_today)

    if [ -z "$profile" ]; then
        # Check all profiles
        for p in $(cut -d'|' -f1 "$CONFIG" 2>/dev/null); do
            _check_single_budget "$p" "$today"
        done
    else
        _check_single_budget "$profile" "$today"
    fi
}

# Internal: check budget for a single profile
# $1 = profile name
# $2 = today's date
_check_single_budget() {
    local profile="$1"
    local today="$2"
    local budget
    budget=$(get_profile_budget "$profile")

    # Skip if budget is 0 (unlimited)
    [ "$budget" = "0" ] || [ -z "$budget" ] && return 0

    # Reset if new day
    local last_day
    last_day=$(cat "$STATE_DIR/${profile}_day" 2>/dev/null)
    if [ "$last_day" != "$today" ]; then
        reset_usage "$profile"
    fi

    # Increment usage
    local used
    used=$(get_used_minutes "$profile")
    used=$((used + 1))
    echo "$used" > "$STATE_DIR/${profile}_used"

    # Check if budget exceeded
    if [ "$used" -ge "$budget" ]; then
        block_profile "$profile"
        log "Budget exceeded: '$profile' ($used/$budget min)"
    fi
}

# ----------------------------------------------------------------------------
# Status and listing
# ----------------------------------------------------------------------------

# Show status of all profiles
show_status() {
    echo "Profile    | Budget(min) | Used(min) | Status   | MACs"
    echo "-----------|-------------|-----------|----------|----"
    while IFS='|' read -r name budget macs; do
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_status" 2>/dev/null || echo "unknown")
        local used
        used=$(get_used_minutes "$name")
        [ "$budget" = "0" ] && budget="unlimited"
        printf "%-10s | %-11s | %-9s | %-8s | %s\n" "$name" "$budget" "$used" "$status" "$macs"
    done < "$CONFIG"
}

# List all configured profiles
list_profiles() {
    echo "Profiles configured:"
    if [ ! -f "$CONFIG" ]; then
        echo "  (no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r name budget macs; do
        [ -z "$name" ] && continue
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

Options (via environment variables):
  PARENTAL_CONFIG    Config file path (default: /etc/config/parental_profiles)
  PARENTAL_STATE_DIR State directory (default: /tmp/parental-profiles)
  PARENTAL_WAN_IF    WAN interface (default: auto-detect or eth1)
  PARENTAL_LAN_IF    LAN interface (default: br-lan)
  IPTABLES           iptables binary (default: iptables)
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
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "Unknown command: $1" >&2
        usage
        exit 1
        ;;
esac