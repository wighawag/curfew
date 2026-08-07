#!/bin/sh
# ============================================================================
# website-blocking.sh - Per-profile website blocking with reusable block rules
#
# Block rules (domain lists) are defined once in block_rules and associated
# with profiles in parental_websites. This avoids duplicating domain lists.
#
# Config files:
#   /etc/config/block_rules       rule_name|domain1,domain2,...
#   /etc/config/parental_websites  profile_name|rule_name
#   /etc/config/parental_profiles  profile_name|budget|mac1,mac2,...
#
# Cron example:
#   0 20 * * * website-blocking.sh enable eli no_streaming
#   0 8 * * * website-blocking.sh disable eli no_streaming
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u

BLOCK_RULES_CONFIG="${BLOCK_RULES_CONFIG:-/etc/config/block_rules}"
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

# Get MACs for a profile from parental_profiles
get_profile_macs() {
    grep "^$1|" "$PROFILES_CONFIG" 2>/dev/null | cut -d'|' -f3 | tr ',' ' '
}

# Get domains for a rule from block_rules
get_rule_domains() {
    local rule="$1"
    grep "^${rule}|" "$BLOCK_RULES_CONFIG" 2>/dev/null | cut -d'|' -f2 | tr ',' '\n' | grep -v '^$'
}

# Check if a rule is defined in block_rules
rule_exists() {
    grep -q "^$1|" "$BLOCK_RULES_CONFIG" 2>/dev/null
}

# Get the nftables set name for a profile+rule
get_set_name() {
    echo "blocked_sites_${1}_${2}"
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

# Remove all nftables rules for a profile+rule
remove_rule_entries() {
    local profile="$1"
    local rule="$2"
    local rule_tag="block_sites_${profile}_${rule}"

    $NFT_BIN -a list chain inet "$NFT_TABLE" forward 2>/dev/null | \
        grep "$rule_tag" | grep -o 'handle [0-9]*' | awk '{print $2}' | \
        while read -r handle; do
            $NFT_BIN delete rule inet "$NFT_TABLE" forward handle "$handle" 2>/dev/null
        done
}

# Enable website blocking for a profile+rule
enable_profile() {
    local profile="$1"
    local rule="${2:-default}"
    local set_name
    set_name=$(get_set_name "$profile" "$rule")

    # Check the rule exists in block_rules
    if ! rule_exists "$rule"; then
        echo "Error: rule '$rule' not found in $BLOCK_RULES_CONFIG" >&2
        return 1
    fi

    nft_init

    # Create or flush the per-rule IP set
    $NFT_BIN list set inet "$NFT_TABLE" "$set_name" 2>/dev/null && \
        $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null || \
        $NFT_BIN add set inet "$NFT_TABLE" "$set_name" '{ type ipv4_addr; flags interval; }' 2>/dev/null

    # Resolve all domains and add their IPs to the set
    local domains
    domains=$(get_rule_domains "$rule")
    local ip_count=0
    for domain in $domains; do
        log "Resolving $domain for '$profile/$rule'"
        for ip in $(resolve_domain "$domain"); do
            $NFT_BIN add element inet "$NFT_TABLE" "$set_name" "{ $ip }" 2>/dev/null && \
                ip_count=$((ip_count + 1))
        done
    done

    # Remove old rules for this profile+rule
    remove_rule_entries "$profile" "$rule"

    # Add a rule for each MAC in the profile
    local rule_tag="block_sites_${profile}_${rule}"
    for mac in $(get_profile_macs "$profile"); do
        $NFT_BIN add rule inet "$NFT_TABLE" forward \
            ether saddr "$mac" ip daddr @"$set_name" drop \
            comment "$rule_tag" 2>/dev/null
    done

    echo "enabled" > "$STATE_DIR/${profile}_${rule}_websites"
    log "Website blocking enabled for '$profile/$rule' ($ip_count IPs blocked)"
    echo "Website blocking enabled for '$profile/$rule' ($ip_count IPs blocked)"
    return 0
}

# Disable website blocking for a profile+rule
disable_profile() {
    local profile="$1"
    local rule="${2:-default}"
    local set_name
    set_name=$(get_set_name "$profile" "$rule")

    remove_rule_entries "$profile" "$rule"

    $NFT_BIN flush set inet "$NFT_TABLE" "$set_name" 2>/dev/null
    $NFT_BIN delete set inet "$NFT_TABLE" "$set_name" 2>/dev/null

    echo "disabled" > "$STATE_DIR/${profile}_${rule}_websites"
    log "Website blocking disabled for '$profile/$rule'"
    echo "Website blocking disabled for '$profile/$rule'"
    return 0
}

# Show status of currently active website blocking (from state files)
show_status() {
    echo "Active website blocking:"
    local found=0
    for f in "$STATE_DIR"/*_websites; do
        [ -f "$f" ] || continue
        local status
        status=$(cat "$f")
        [ "$status" = "enabled" ] || continue
        local name
        name=$(basename "$f" _websites)
        local profile rule
        profile=$(echo "$name" | sed 's/_.*//')
        rule=$(echo "$name" | sed 's/^[^_]*_//')
        printf "  %-22s | %s\n" "$profile/$rule" "$status"
        found=1
    done
    if [ $found -eq 0 ]; then
        echo "  (none active)"
    fi
}

# List all defined block rules
list_rules() {
    echo "Block rules defined:"
    if [ ! -f "$BLOCK_RULES_CONFIG" ]; then
        echo "  (no config at $BLOCK_RULES_CONFIG)"
        return 0
    fi
    while IFS='|' read -r name domains; do
        [ -z "$name" ] && continue
        local count
        count=$(echo "$domains" | tr ',' '\n' | grep -c '.')
        echo "  $name: $count domains"
    done < "$BLOCK_RULES_CONFIG"
}



# Refresh all currently enabled rules (re-resolve domains)
refresh_all() {
    for f in "$STATE_DIR"/*_websites; do
        [ -f "$f" ] || continue
        local status
        status=$(cat "$f")
        [ "$status" = "enabled" ] || continue
        local name
        name=$(basename "$f" _websites)
        local profile rule
        profile=$(echo "$name" | sed 's/_.*//')
        rule=$(echo "$name" | sed 's/^[^_]*_//')
        enable_profile "$profile" "$rule" 2>/dev/null
    done
    log "Refreshed all website blocking rules"
}

usage() {
    cat << EOF
Usage: website-blocking.sh <command> [args]

Commands:
  status                        Show currently active website blocking
  rules                         List all defined block rules
  enable <profile> <rule>       Enable website blocking for a profile
  disable <profile> <rule>      Disable website blocking for a profile
  refresh                       Re-resolve domains and update IPs (for cron)

Config files:
  $BLOCK_RULES_CONFIG       rule_name|domain1,domain2,...
  $PROFILES_CONFIG          profile_name|budget|mac1,mac2,...
  crontab                       schedule (enable/disable at set times)

Cron examples:
  0 20 * * * /usr/bin/website-blocking.sh enable eli no_streaming
  0 8 * * * /usr/bin/website-blocking.sh disable eli no_streaming
  0 * * * * /usr/bin/website-blocking.sh refresh
EOF
}

case "${1:-}" in
    enable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        [ -z "${3:-}" ] && { echo "Error: missing rule name" >&2; exit 1; }
        enable_profile "$2" "$3"
        ;;
    disable)
        [ -z "${2:-}" ] && { echo "Error: missing profile name" >&2; exit 1; }
        [ -z "${3:-}" ] && { echo "Error: missing rule name" >&2; exit 1; }
        disable_profile "$2" "$3"
        ;;
    status)
        show_status
        ;;
    rules)
        list_rules
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