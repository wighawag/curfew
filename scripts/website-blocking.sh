#!/bin/sh
# ============================================================================
# website-blocking.sh - Per-profile website blocking with time-based scheduling
#
# Blocks specific websites for specific profiles, independently of the
# internet on/off schedule. Uses nftables with DNS resolution.
#
# Config file: /etc/config/parental_websites
# Format: profile_name|domain1,domain2,domain3
#
# The script resolves domains to IPs and adds them to per-profile nftables
# sets. A rule blocks traffic from the profile's MACs to those IPs.
#
# Enable/disable is controlled separately from internet blocking,
# so you can have:
#   - Internet allowed 15:30-20:00 (via parental-profiles.sh schedule)
#   - YouTube blocked 15:30-17:00 (via website-blocking.sh schedule)
#   - YouTube allowed 17:00-20:00 (website blocking disabled)
#
# Usage with cron:
#   # Block YouTube for alice after school until 17:00
#   30 15 * * 1-5 /usr/bin/website-blocking.sh enable alice
#   0 17 * * 1-5 /usr/bin/website-blocking.sh disable alice
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u

CONFIG="${PARENTAL_WEBSITES_CONFIG:-/etc/config/parental_websites}"
PROFILES_CONFIG="${PARENTAL_CONFIG:-/etc/config/parental_profiles}"
STATE_DIR="${PARENTAL_STATE_DIR:-/tmp/parental-profiles}"
NFT_BIN="${NFT:-nft}"
NFT_TABLE="parental_control"
LOGGER="${LOGGER:-logger}"
NSLOOKUP="${NSLOOKUP:-nslookup}"

mkdir -p "$STATE_DIR" 2>/dev/null || true

log() {
    $LOGGER -t parental-websites "$1" 2>/dev/null || echo "[parental-websites] $1" >&2
}

# Get MACs for a profile from the parental_profiles config
get_profile_macs() {
    grep "^$1|" "$PROFILES_CONFIG" 2>/dev/null | cut -d'|' -f3 | tr ',' ' '
}

# Get domains for a profile from the parental_websites config
get_profile_domains() {
    grep "^$1|" "$CONFIG" 2>/dev/null | cut -d'|' -f2 | tr ',' '\n' | grep -v '^$'
}

# Check if a profile has website blocking configured
profile_has_websites() {
    grep -q "^$1|" "$CONFIG" 2>/dev/null
}

# Get the nftables set name for a profile's blocked sites
get_set_name() {
    echo "blocked_sites_$1"
}

# Initialize nftables table if needed
nft_init() {
    $NFT_BIN list table inet "$NFT_TABLE" 2>/dev/null || \
        $NFT_BIN add table inet "$NFT_TABLE" 2>/dev/null
    $NFT_BIN list chain inet "$NFT_TABLE" forward 2>/dev/null || \
        $NFT_BIN add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority -10; policy accept; }' 2>/dev/null
}

# Resolve a domain to IP addresses
resolve_domain() {
    local domain="$1"
    # Try nslookup first, fall back to host, then dig
    if command -v "$NSLOOKUP" >/dev/null 2>&1; then
        $NSLOOKUP "$domain" 2>/dev/null | awk '/^Address: / && !/127\.|::1/ {print $2}' | head -10
    elif command -v host >/dev/null 2>&1; then
        host "$domain" 2>/dev/null | awk '/has address/ {print $4}' | head -10
    elif command -v dig >/dev/null 2>&1; then
        dig +short "$domain" A 2>/dev/null | head -10
    else
        # Fallback: use /etc/hosts or getent
        getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -10
    fi
}

# Enable website blocking for a profile
enable_profile() {
    local profile="$1"
    local set_name
    set_name=$(get_set_name "$profile")

    if ! profile_has_websites "$profile"; then
        echo "Error: profile '$profile' has no website blocking configured" >&2
        return 1
    fi

    nft_init

    # Create or flush the per-profile IP set
    $NFT_BIN list set inet "$NFT_TABLE" "$set_name" 2>/dev/null && \
        $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null || \
        $NFT_BIN add set inet "$NFT_TABLE" "$set_name" '{ type ipv4_addr; flags interval; }' 2>/dev/null

    # Resolve all domains and add their IPs to the set
    local domains
    domains=$(get_profile_domains "$profile")
    local ip_count=0
    for domain in $domains; do
        log "Resolving $domain for profile '$profile'"
        for ip in $(resolve_domain "$domain"); do
            $NFT_BIN add element inet "$NFT_TABLE" "$set_name" "{ $ip }" 2>/dev/null && \
                ip_count=$((ip_count + 1))
        done
    done

    # Remove old rules for this profile (if any)
    # We use a comment to identify our rules
    $NFT_BIN -a list chain inet "$NFT_TABLE" forward 2>/dev/null | \
        grep "blocked_sites_$profile" | grep -o 'handle [0-9]*' | awk '{print $2}' | \
        while read -r handle; do
            $NFT_BIN delete rule inet "$NFT_TABLE" forward handle "$handle" 2>/dev/null
        done

    # Add a rule for each MAC in the profile
    for mac in $(get_profile_macs "$profile"); do
        $NFT_BIN add rule inet "$NFT_TABLE" forward \
            ether saddr "$mac" ip daddr @"$set_name" drop \
            comment \"block_sites_${profile}\" 2>/dev/null
    done

    echo "enabled" > "$STATE_DIR/${profile}_websites"
    log "Website blocking enabled for '$profile' ($ip_count IPs blocked)"
    echo "Website blocking enabled for '$profile' ($ip_count IPs blocked)"
    return 0
}

# Disable website blocking for a profile
disable_profile() {
    local profile="$1"
    local set_name
    set_name=$(get_set_name "$profile")

    # Remove all rules for this profile
    $NFT_BIN -a list chain inet "$NFT_TABLE" forward 2>/dev/null | \
        grep "blocked_sites_$profile" | grep -o 'handle [0-9]*' | awk '{print $2}' | \
        while read -r handle; do
            $NFT_BIN delete rule inet "$NFT_TABLE" forward handle "$handle" 2>/dev/null
        done

    # Flush the set
    $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null

    echo "disabled" > "$STATE_DIR/${profile}_websites"
    log "Website blocking disabled for '$profile'"
    echo "Website blocking disabled for '$profile'"
    return 0
}

# Show status of all website blocking
show_status() {
    echo "Profile    | Domains                          | Status"
    echo "-----------|----------------------------------|--------"
    if [ ! -f "$CONFIG" ]; then
        echo "(no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r name domains; do
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_websites" 2>/dev/null || echo "disabled")
        printf "%-10s | %-32s | %s\n" "$name" "$domains" "$status"
    done < "$CONFIG"
}

# List all configured website blocks
list_profiles() {
    echo "Website blocking configured:"
    if [ ! -f "$CONFIG" ]; then
        echo "  (no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r name domains; do
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_websites" 2>/dev/null || echo "disabled")
        echo "  $name: domains=$domains, status=$status"
    done < "$CONFIG"
}

# Refresh all enabled profiles (re-resolve domains to update IPs)
refresh_all() {
    while IFS='|' read -r name domains; do
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_websites" 2>/dev/null || echo "disabled")
        if [ "$status" = "enabled" ]; then
            enable_profile "$name" 2>/dev/null
        fi
    done < "$CONFIG"
    log "Refreshed all website blocking rules"
}

usage() {
    cat << EOF
Usage: website-blocking.sh <command> [args]

Commands:
  status                  Show status of all website blocking
  list                    List all configured website blocks
  enable <profile>        Enable website blocking for a profile
  disable <profile>       Disable website blocking for a profile
  refresh                 Re-resolve domains and update IPs (for cron)

Config files:
  $CONFIG           (profile|domain1,domain2,...)
  $PROFILES_CONFIG  (profile|budget|mac1,mac2,...)

Cron examples:
  # Block YouTube for alice after school until 17:00
  30 15 * * 1-5 /usr/bin/website-blocking.sh enable alice
  0 17 * * 1-5 /usr/bin/website-blocking.sh disable alice

  # Refresh DNS resolution every hour (IPs can change)
  0 * * * * /usr/bin/website-blocking.sh refresh
EOF
}

case "${1:-}" in
    enable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        enable_profile "$2"
        ;;
    disable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        disable_profile "$2"
        ;;
    status)
        show_status
        ;;
    list)
        list_profiles
        ;;
    refresh)
        refresh_all
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