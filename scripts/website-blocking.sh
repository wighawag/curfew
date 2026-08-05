#!/bin/sh
# ============================================================================
# website-blocking.sh - Per-profile website blocking with time-based groups
#
# Blocks specific websites for specific profiles, independently of the
# internet on/off schedule. Uses nftables with DNS resolution.
#
# Supports "groups" so you can have different domain lists at different times:
#   alice|after_school|youtube.com,tiktok.com
#   alice|evening|youtube.com,tiktok.com,netflix.com,disneyplus.com
#
# Config file: /etc/config/parental_websites
# Format: profile_name|group_name|domain1,domain2,domain3
#    (or backward compat: profile_name|domain1,domain2 → uses "default" group)
#
# Usage with cron:
#   # After school: block YouTube + TikTok
#   30 15 * * 1-5 /usr/bin/website-blocking.sh enable alice after_school
#   0 17 * * 1-5 /usr/bin/website-blocking.sh disable alice after_school
#   # Evening: block all streaming
#   0 18 * * * /usr/bin/website-blocking.sh enable alice evening
#   0 20 * * * /usr/bin/website-blocking.sh disable alice evening
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

# Get domains for a profile+group from the parental_websites config
# Supports both 2-field (no group) and 3-field (with group) formats
get_group_domains() {
    local profile="$1"
    local group="${2:-default}"

    # Try 3-field format first: profile|group|domains
    local domains
    domains=$(grep "^${profile}|${group}|" "$CONFIG" 2>/dev/null | cut -d'|' -f3)
    if [ -n "$domains" ]; then
        echo "$domains" | tr ',' '\n' | grep -v '^$'
        return 0
    fi

    # Fall back to 2-field format: profile|domains (only for "default" group)
    if [ "$group" = "default" ]; then
        # Match lines with exactly 2 fields (profile|domains)
        grep "^${profile}|" "$CONFIG" 2>/dev/null | while IFS='|' read -r p rest; do
            # Check if rest contains a pipe (3-field) or not (2-field)
            if echo "$rest" | grep -q '|'; then
                continue  # 3-field line, skip
            fi
            echo "$rest" | tr ',' '\n' | grep -v '^$'
        done
    fi
}

# Check if a profile+group has website blocking configured
group_has_websites() {
    local profile="$1"
    local group="${2:-default}"
    [ -n "$(get_group_domains "$profile" "$group")" ]
}

# Get the nftables set name for a profile+group
get_set_name() {
    local profile="$1"
    local group="${2:-default}"
    echo "blocked_sites_${profile}_${group}"
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
    if command -v "$NSLOOKUP" >/dev/null 2>&1; then
        $NSLOOKUP "$domain" 2>/dev/null | awk '/^Address: / && !/127\.|::1/ {print $2}' | head -10
    elif command -v host >/dev/null 2>&1; then
        host "$domain" 2>/dev/null | awk '/has address/ {print $4}' | head -10
    elif command -v dig >/dev/null 2>&1; then
        dig +short "$domain" A 2>/dev/null | head -10
    else
        getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -10
    fi
}

# Remove all nftables rules for a profile+group
remove_group_rules() {
    local profile="$1"
    local group="${2:-default}"
    local set_name
    set_name=$(get_set_name "$profile" "$group")
    local rule_tag="block_sites_${profile}_${group}"

    $NFT_BIN -a list chain inet "$NFT_TABLE" forward 2>/dev/null | \
        grep "$rule_tag" | grep -o 'handle [0-9]*' | awk '{print $2}' | \
        while read -r handle; do
            $NFT_BIN delete rule inet "$NFT_TABLE" forward handle "$handle" 2>/dev/null
        done
}

# Enable website blocking for a profile+group
enable_profile() {
    local profile="$1"
    local group="${2:-default}"
    local set_name
    set_name=$(get_set_name "$profile" "$group")

    if ! group_has_websites "$profile" "$group"; then
        echo "Error: profile '$profile' group '$group' has no website blocking configured" >&2
        return 1
    fi

    nft_init

    # Create or flush the per-group IP set
    $NFT_BIN list set inet "$NFT_TABLE" "$set_name" 2>/dev/null && \
        $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null || \
        $NFT_BIN add set inet "$NFT_TABLE" "$set_name" '{ type ipv4_addr; flags interval; }' 2>/dev/null

    # Resolve all domains and add their IPs to the set
    local domains
    domains=$(get_group_domains "$profile" "$group")
    local ip_count=0
    for domain in $domains; do
        log "Resolving $domain for '$profile/$group'"
        for ip in $(resolve_domain "$domain"); do
            $NFT_BIN add element inet "$NFT_TABLE" "$set_name" "{ $ip }" 2>/dev/null && \
                ip_count=$((ip_count + 1))
        done
    done

    # Remove old rules for this group (if any)
    remove_group_rules "$profile" "$group"

    # Add a rule for each MAC in the profile
    local rule_tag="block_sites_${profile}_${group}"
    for mac in $(get_profile_macs "$profile"); do
        $NFT_BIN add rule inet "$NFT_TABLE" forward \
            ether saddr "$mac" ip daddr @"$set_name" drop \
            comment "$rule_tag" 2>/dev/null
    done

    echo "enabled" > "$STATE_DIR/${profile}_${group}_websites"
    log "Website blocking enabled for '$profile/$group' ($ip_count IPs blocked)"
    echo "Website blocking enabled for '$profile/$group' ($ip_count IPs blocked)"
    return 0
}

# Disable website blocking for a profile+group
disable_profile() {
    local profile="$1"
    local group="${2:-default}"
    local set_name
    set_name=$(get_set_name "$profile" "$group")

    remove_group_rules "$profile" "$group"

    # Flush and delete the set
    $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null
    $NFT_BIN delete set inet "$NFT_TABLE" "$set_name" 2>/dev/null

    echo "disabled" > "$STATE_DIR/${profile}_${group}_websites"
    log "Website blocking disabled for '$profile/$group'"
    echo "Website blocking disabled for '$profile/$group'"
    return 0
}

# Show status of all website blocking
show_status() {
    echo "Profile/Group              | Domains                          | Status"
    echo "--------------------------|----------------------------------|--------"
    if [ ! -f "$CONFIG" ]; then
        echo "(no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r f1 f2 f3; do
        # Handle both 2-field and 3-field formats
        if [ -z "$f3" ]; then
            # 2-field: f1=profile, f2=domains, group=default
            local name="$f1" group="default" domains="$f2"
        else
            # 3-field: f1=profile, f2=group, f3=domains
            local name="$f1" group="$f2" domains="$f3"
        fi
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_${group}_websites" 2>/dev/null || echo "disabled")
        printf "%-25s | %-32s | %s\n" "$name/$group" "$domains" "$status"
    done < "$CONFIG"
}

# List all configured website blocks
list_profiles() {
    echo "Website blocking configured:"
    if [ ! -f "$CONFIG" ]; then
        echo "  (no config file at $CONFIG)"
        return 0
    fi
    while IFS='|' read -r f1 f2 f3; do
        if [ -z "$f3" ]; then
            local name="$f1" group="default" domains="$f2"
        else
            local name="$f1" group="$f2" domains="$f3"
        fi
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_${group}_websites" 2>/dev/null || echo "disabled")
        echo "  $name/$group: domains=$domains, status=$status"
    done < "$CONFIG"
}

# Refresh all enabled groups (re-resolve domains to update IPs)
refresh_all() {
    while IFS='|' read -r f1 f2 f3; do
        if [ -z "$f3" ]; then
            local name="$f1" group="default"
        else
            local name="$f1" group="$f2"
        fi
        [ -z "$name" ] && continue
        local status
        status=$(cat "$STATE_DIR/${name}_${group}_websites" 2>/dev/null || echo "disabled")
        if [ "$status" = "enabled" ]; then
            enable_profile "$name" "$group" 2>/dev/null
        fi
    done < "$CONFIG"
    log "Refreshed all website blocking rules"
}

usage() {
    cat << EOF
Usage: website-blocking.sh <command> [args]

Commands:
  status                          Show status of all website blocking
  list                            List all configured website blocks
  enable <profile> [group]        Enable website blocking (default group if none)
  disable <profile> [group]       Disable website blocking
  refresh                         Re-resolve domains and update IPs (for cron)

Config: $CONFIG
  Format: profile|group|domain1,domain2  (with groups)
      or: profile|domain1,domain2        (without, uses "default" group)

Cron examples:
  # After school: block YouTube + TikTok
  30 15 * * 1-5 /usr/bin/website-blocking.sh enable alice after_school
  0 17 * * 1-5 /usr/bin/website-blocking.sh disable alice after_school
  # Evening: block all streaming (different domain list)
  0 18 * * * /usr/bin/website-blocking.sh enable alice evening
  0 20 * * * /usr/bin/website-blocking.sh disable alice evening
  # Refresh DNS hourly
  0 * * * * /usr/bin/website-blocking.sh refresh
EOF
}

case "${1:-}" in
    enable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        enable_profile "$2" "${3:-default}"
        ;;
    disable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        disable_profile "$2" "${3:-default}"
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