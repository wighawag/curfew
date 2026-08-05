#!/bin/sh
# ============================================================================
# setup-firewall.sh - Unknown device blocking via nftables MAC allowlist
#
# Blocks all internet access for unknown (non-allowlisted) MAC addresses.
# The allowlist is derived automatically from parental_profiles config.
# Only MACs listed in any profile are allowed internet access.
#
# Config: /etc/config/parental_profiles (same file used by parental-profiles.sh)
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u

PROFILES_CONFIG="${PARENTAL_CONFIG:-/etc/config/parental_profiles}"
WAN_IF="${PARENTAL_WAN_IF:-$(uci get network.wan.device 2>/dev/null || echo "eth1")}"
LAN_IF="${PARENTAL_LAN_IF:-br-lan}"
NFT_BIN="${NFT:-nft}"
NFT_TABLE="parental_control"
NFT_ALLOWED_SET="allowed_macs"
LOGGER="${LOGGER:-logger}"

log() {
    $LOGGER -t parental "$1" 2>/dev/null || echo "[parental] $1" >&2
}

# Extract all MACs from all profiles (the allowlist)
get_all_macs() {
    grep -v '^#' "$PROFILES_CONFIG" 2>/dev/null | \
        cut -d'|' -f3 | tr ',' '\n' | \
        grep -v '^$' | sort -u
}

# Initialize the nftables table and sets
nft_init_allowlist() {
    $NFT_BIN list table inet "$NFT_TABLE" 2>/dev/null || \
        $NFT_BIN add table inet "$NFT_TABLE"

    $NFT_BIN list set inet "$NFT_TABLE" "$NFT_ALLOWED_SET" 2>/dev/null || \
        $NFT_BIN add set inet "$NFT_TABLE" "$NFT_ALLOWED_SET" '{ type ether_addr; }'

    $NFT_BIN list chain inet "$NFT_TABLE" forward 2>/dev/null || \
        $NFT_BIN add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority -10; policy accept; }'
}

# Generate nftables rules from the profiles config
generate_nft_rules() {
    echo "# === Parental Control: MAC Allowlist (from $PROFILES_CONFIG) ==="
    echo "# All MACs from all profiles are allowed. Everything else is blocked."
    echo ""

    for mac in $(get_all_macs); do
        echo "nft add element inet $NFT_TABLE $NFT_ALLOWED_SET { $mac }"
    done

    echo ""
    echo "# Allow known MACs to reach the internet"
    echo "nft add rule inet $NFT_TABLE forward iifname \"$LAN_IF\" oifname \"$WAN_IF\" ether saddr @$NFT_ALLOWED_SET accept"
    echo ""
    echo "# Block everything else from reaching the internet"
    echo "nft add rule inet $NFT_TABLE forward iifname \"$LAN_IF\" oifname \"$WAN_IF\" drop"
}

# Apply rules immediately using nftables
apply_nft() {
    nft_init_allowlist

    # Clear the allowed set and repopulate from profiles
    $NFT_BIN flush set inet "$NFT_TABLE" "$NFT_ALLOWED_SET" 2>/dev/null

    for mac in $(get_all_macs); do
        $NFT_BIN add element inet "$NFT_TABLE" "$NFT_ALLOWED_SET" "{ $mac }" 2>/dev/null
    done

    # Flush and recreate the forward chain rules (only allowlist rules, not profile blocks)
    $NFT_BIN flush chain inet "$NFT_TABLE" forward 2>/dev/null

    # Allow known MACs
    $NFT_BIN add rule inet "$NFT_TABLE" forward iifname "$LAN_IF" oifname "$WAN_IF" ether saddr @"$NFT_ALLOWED_SET" accept 2>/dev/null

    # Block everything else
    $NFT_BIN add rule inet "$NFT_TABLE" forward iifname "$LAN_IF" oifname "$WAN_IF" drop 2>/dev/null

    log "MAC allowlist applied from $PROFILES_CONFIG ($(get_all_macs | wc -l) MACs)"
}

# Update the allowed set without flushing the forward chain (idempotent)
update_set_only() {
    nft_init_allowlist

    local current_macs
    current_macs=$($NFT_BIN list set inet "$NFT_TABLE" "$NFT_ALLOWED_SET" 2>/dev/null | grep -o '[0-9a-fA-F:]\{17\}' | sort)
    local new_macs
    new_macs=$(get_all_macs | sort)

    # Add new MACs
    for mac in $new_macs; do
        $NFT_BIN add element inet "$NFT_TABLE" "$NFT_ALLOWED_SET" "{ $mac }" 2>/dev/null
    done

    # Remove MACs no longer in any profile
    for mac in $current_macs; do
        if ! echo "$new_macs" | grep -q "$mac"; then
            $NFT_BIN delete element inet "$NFT_TABLE" "$NFT_ALLOWED_SET" "{ $mac }" 2>/dev/null
        fi
    done

    log "MAC allowlist updated ($(echo "$new_macs" | wc -l) MACs)"
}

# Generate an init script that runs on boot
generate_init_script() {
    cat << EOF
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    $(apply_nft | sed 's/\\/\\\\/g')
}
stop_service() {
    nft flush chain inet parental_control forward 2>/dev/null
}
EOF
}

case "${1:-}" in
    generate)
        generate_nft_rules
        ;;
    apply)
        apply_nft
        echo "MAC allowlist applied ($(get_all_macs | wc -l) MACs allowed)"
        echo "Allowed MACs:"
        get_all_macs | while read -r mac; do
            echo "  $mac"
        done
        ;;
    update)
        update_set_only
        echo "MAC allowlist updated ($(get_all_macs | wc -l) MACs allowed)"
        ;;
    init-script)
        generate_init_script > /etc/init.d/parental-allowlist
        chmod +x /etc/init.d/parental-allowlist
        /etc/init.d/parental-allowlist enable
        echo "Init script created and enabled at /etc/init.d/parental-allowlist"
        ;;
    -h|--help|help|"")
        echo "Usage: setup-firewall.sh <command>"
        echo ""
        echo "Commands:"
        echo "  generate      Print nftables rules to stdout (dry run)"
        echo "  apply         Full apply: flush forward chain and recreate (first install)"
        echo "  update        Update allowed set only (preserves active blocks/tickets)"
        echo "  init-script   Create boot script for auto-apply on startup"
        echo ""
        echo "Config: $PROFILES_CONFIG (all MACs from all profiles = allowlist)"
        ;;
    *)
        echo "Unknown command: $1" >&2
        exit 1
        ;;
esac