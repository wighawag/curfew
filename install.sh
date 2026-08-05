#!/bin/bash
# ============================================================================
# install.sh - Install/update parental control system on OpenWrt router
#
# Usage: ./install.sh <router-ip> [options]
#
# Examples:
#   ./install.sh 192.168.1.1              # Install or update
#   ./install.sh 192.168.1.1 --user root  # Specify SSH user
#   ./install.sh 192.168.1.1 --force      # Full re-apply (clears active blocks)
#
# Idempotent: safe to run repeatedly. Active tickets and budgets are preserved.
# Uses config/local/ files if they exist, otherwise creates templates on router.
#
# Prerequisites:
#   - OpenWrt flashed and running on the router
#   - SSH access to the router (root password set)
# ============================================================================

set -e

ROUTER_IP="${1:-}"
SSH_USER="root"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
FORCE=0

if [ -z "$ROUTER_IP" ]; then
    echo "Usage: ./install.sh <router-ip> [--user root] [--force]"
    echo "Example: ./install.sh 192.168.1.1"
    exit 1
fi

shift
while [ $# -gt 0 ]; do
    case "$1" in
        --user) SSH_USER="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) shift ;;
    esac
done

SSH_TARGET="${SSH_USER}@${ROUTER_IP}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_DIR="$SCRIPT_DIR/config/local"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}OK${NC} $1"; }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1"; }

echo "=== Parental Control Installer ==="
echo "Router: $SSH_TARGET"
echo "Mode: $([ $FORCE -eq 1 ] && echo "FORCE (full re-apply)" || echo "idempotent (preserves active state)")"
echo ""

# Step 1: Test SSH
echo "1. Testing SSH connection..."
if ! ssh $SSH_OPTS "$SSH_TARGET" "echo ok" >/dev/null 2>&1; then
    echo "   ERROR: Cannot SSH to $SSH_TARGET"
    echo "   Set a root password in LuCI first: http://${ROUTER_IP}"
    exit 1
fi
ok "SSH connection"

# Step 2: Copy scripts (always overwrite)
echo "2. Installing scripts..."
scp $SSH_OPTS "$SCRIPT_DIR/scripts/parental-profiles.sh" "$SSH_TARGET:/usr/bin/parental-profiles.sh" 2>/dev/null
scp $SSH_OPTS "$SCRIPT_DIR/scripts/setup-firewall.sh" "$SSH_TARGET:/usr/bin/setup-firewall.sh" 2>/dev/null
scp $SSH_OPTS "$SCRIPT_DIR/scripts/website-blocking.sh" "$SSH_TARGET:/usr/bin/website-blocking.sh" 2>/dev/null
scp $SSH_OPTS "$SCRIPT_DIR/scripts/blocklists.sh" "$SSH_TARGET:/usr/bin/blocklists.sh" 2>/dev/null
ssh $SSH_OPTS "$SSH_TARGET" "chmod +x /usr/bin/parental-profiles.sh /usr/bin/setup-firewall.sh /usr/bin/website-blocking.sh /usr/bin/blocklists.sh" 2>/dev/null
ok "Scripts installed"

# Step 3: Copy web interface
echo "3. Installing web interface..."
ssh $SSH_OPTS "$SSH_TARGET" "mkdir -p /www/cgi-bin" 2>/dev/null
scp $SSH_OPTS "$SCRIPT_DIR/web/cgi-bin/ticket" "$SSH_TARGET:/www/cgi-bin/ticket" 2>/dev/null
ssh $SSH_OPTS "$SSH_TARGET" "chmod +x /www/cgi-bin/ticket" 2>/dev/null

# Use local tickets.html if it exists, otherwise use default
if [ -f "$LOCAL_DIR/tickets.html" ]; then
    scp $SSH_OPTS "$LOCAL_DIR/tickets.html" "$SSH_TARGET:/www/tickets.html" 2>/dev/null
    ok "Web interface (custom tickets.html from config/local/)"
else
    scp $SSH_OPTS "$SCRIPT_DIR/web/tickets.html" "$SSH_TARGET:/www/tickets.html" 2>/dev/null
    ok "Web interface (default tickets.html - customize in config/local/)"
fi

# Step 4: Upload configs
echo "4. Configuring..."

upload_config() {
    local local_file="$1"
    local remote_file="$2"
    local name="$3"

    if [ -f "$local_file" ]; then
        scp $SSH_OPTS "$local_file" "$SSH_TARGET:$remote_file" 2>/dev/null
        ok "$name (from config/local/)"
    else
        # Only create if it doesn't exist on the router
        if ! ssh $SSH_OPTS "$SSH_TARGET" "test -f $remote_file" 2>/dev/null; then
            skip "$name (no local file, created template on router)"
        else
            skip "$name (no local file, keeping existing on router)"
        fi
    fi
}

upload_config "$LOCAL_DIR/parental_profiles"  "/etc/config/parental_profiles"   "Profiles + MAC allowlist (single file)"
upload_config "$LOCAL_DIR/block_rules"       "/etc/config/block_rules"         "Block rules (reusable domain lists)"
upload_config "$LOCAL_DIR/device_ips"        "/etc/config/device_ips"          "Static IP assignments"
upload_config "$LOCAL_DIR/parental_blocklists" "/etc/config/parental_blocklists" "Global blocklists"

# Create default blocklists config if neither local nor remote exists
ssh $SSH_OPTS "$SSH_TARGET" 'if [ ! -f /etc/config/parental_blocklists ]; then
cat > /etc/config/parental_blocklists << "BLKEOF"
https://blocklistproject.github.io/Lists/dnsmasq-version/gambling-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/porn-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/malware-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/phishing-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/ransomware-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/scam-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/fraud-dnsmasq.txt
BLKEOF
fi' 2>/dev/null

# Step 5: Set up cron
echo "5. Setting up cron..."

if [ -f "$LOCAL_DIR/crontab" ]; then
    # Use local crontab file
    scp $SSH_OPTS "$LOCAL_DIR/crontab" "$SSH_TARGET:/tmp/parental_crontab" 2>/dev/null
    ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE' 2>/dev/null
# Merge: keep non-parental cron jobs, replace parental ones
if crontab -l 2>/dev/null | grep -q "parental\|website-blocking\|blocklists"; then
    crontab -l 2>/dev/null | grep -v "parental-profiles\|website-blocking\|blocklists" > /tmp/existing_cron
    cat /tmp/existing_cron /tmp/parental_crontab > /tmp/merged_cron
    crontab /tmp/merged_cron
else
    if crontab -l >/dev/null 2>&1; then
        (crontab -l; cat /tmp/parental_crontab) | crontab -
    else
        crontab /tmp/parental_crontab
    fi
fi
rm -f /tmp/parental_crontab /tmp/existing_cron /tmp/merged_cron
REMOTE
    ok "Cron installed (from config/local/crontab)"
else
    # Generate default crontab
    ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE' 2>/dev/null
cat > /tmp/parental_crontab << 'EOF'
# === Parental Control ===
* * * * * /usr/bin/parental-profiles.sh budget-check
0 * * * * /usr/bin/website-blocking.sh refresh
0 3 * * 0 /usr/bin/blocklists.sh update

# Internet: block 22:00-08:00
0 22 * * * /usr/bin/parental-profiles.sh block alice
0 22 * * * /usr/bin/parental-profiles.sh block bob
0 22 * * * /usr/bin/parental-profiles.sh block charlie
0 8 * * * /usr/bin/parental-profiles.sh unblock alice
0 8 * * * /usr/bin/parental-profiles.sh unblock bob
0 8 * * * /usr/bin/parental-profiles.sh unblock charlie

# Streaming: block 20:00-08:00
0 20 * * * /usr/bin/website-blocking.sh enable alice no_streaming
0 20 * * * /usr/bin/website-blocking.sh enable bob no_streaming
0 20 * * * /usr/bin/website-blocking.sh enable charlie no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable alice no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable bob no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable charlie no_streaming

# Gaming: block 08:00-10:00
0 8 * * * /usr/bin/website-blocking.sh enable alice no_gaming
0 8 * * * /usr/bin/website-blocking.sh enable bob no_gaming
0 8 * * * /usr/bin/website-blocking.sh enable charlie no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable alice no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable bob no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable charlie no_gaming
EOF

if crontab -l 2>/dev/null | grep -q "parental\|website-blocking\|blocklists"; then
    crontab -l 2>/dev/null | grep -v "parental-profiles\|website-blocking\|blocklists" > /tmp/existing_cron
    cat /tmp/existing_cron /tmp/parental_crontab > /tmp/merged_cron
    crontab /tmp/merged_cron
else
    if crontab -l >/dev/null 2>&1; then
        (crontab -l; cat /tmp/parental_crontab) | crontab -
    else
        crontab /tmp/parental_crontab
    fi
fi
rm -f /tmp/parental_crontab /tmp/existing_cron /tmp/merged_cron
REMOTE
    ok "Cron installed (default schedule - customize in config/local/crontab)"
fi

echo "6. Applying firewall rules..."

# Check if this is a first install or a re-install
FIRST_INSTALL=$(ssh $SSH_OPTS "$SSH_TARGET" "nft list table inet parental_control 2>/dev/null | head -1" 2>/dev/null)

if [ -n "$FIRST_INSTALL" ] && [ $FORCE -eq 0 ]; then
    # Re-install: update the allowed_macs set without flushing the forward chain
    # This preserves active profile blocks, website blocks, and tickets
    ssh $SSH_OPTS "$SSH_TARGET" "/usr/bin/setup-firewall.sh update" 2>/dev/null
        ok "MAC allowlist updated (preserved active blocks/tickets)"
else
    # First install or --force: full apply
    ssh $SSH_OPTS "$SSH_TARGET" "/usr/bin/setup-firewall.sh apply" 2>/dev/null
    if [ $FORCE -eq 1 ]; then
        ok "MAC allowlist applied (FORCE - active blocks cleared)"
    else
        ok "MAC allowlist applied (first install)"
    fi
fi

# Step 7: Apply static IPs
echo "7. Setting up static IPs..."
if [ -f "$LOCAL_DIR/device_ips" ]; then
    ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE' 2>/dev/null
# Remove old parental static leases
uci -q delete dhcp.parental_static_leases 2>/dev/null
uci set dhcp.parental_static_leases=odhcpd 2>/dev/null || true

# Add static leases from config
while IFS='|' read -r mac ip name; do
    case "$mac" in
        \#*|"") continue ;;
    esac
    [ -z "$mac" ] || [ -z "$ip" ] && continue
    local_name=$(echo "$name" | tr -cd 'a-zA-Z0-9_-')
    uci add dhcp host
    uci set dhcp.@host[-1].mac="$mac"
    uci set dhcp.@host[-1].ip="$ip"
    [ -n "$local_name" ] && uci set dhcp.@host[-1].name="$local_name"
done < /etc/config/device_ips
uci commit dhcp
/etc/init.d/dnsmasq restart 2>/dev/null
REMOTE
    ok "Static IPs applied from config/local/device_ips"
else
    skip "Static IPs (no config/local/device_ips)"
fi

# Step 8: Init script for boot
echo "8. Setting up boot script..."
ssh $SSH_OPTS "$SSH_TARGET" 'cat > /etc/init.d/parental-allowlist << "EOF"
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    /usr/bin/setup-firewall.sh apply
}
stop_service() {
    nft flush chain inet parental_control forward 2>/dev/null
}
EOF
chmod +x /etc/init.d/parental-allowlist
/etc/init.d/parental-allowlist enable' 2>/dev/null
ok "Boot script enabled"

# Step 9: Show status
echo "9. Current status:"
ssh $SSH_OPTS "$SSH_TARGET" "/usr/bin/parental-profiles.sh status 2>/dev/null; echo '---'; /usr/bin/website-blocking.sh status 2>/dev/null; echo '---'; /usr/bin/blocklists.sh status 2>/dev/null" 2>/dev/null || true

echo ""
echo "=== Installation Complete ==="
echo ""
echo "YOUR CONFIGS:"
if [ -d "$LOCAL_DIR" ] && ls "$LOCAL_DIR"/* >/dev/null 2>&1; then
    echo "  config/local/ contains:"
    ls "$LOCAL_DIR"/*.html "$LOCAL_DIR"/parental_* "$LOCAL_DIR"/mac_* "$LOCAL_DIR"/crontab 2>/dev/null | sed 's|.*/|    - |'
else
    echo "  (empty - copy examples to config/local/ and fill in your values)"
fi

echo ""
echo "CONNECTED DEVICES (for MAC addresses):"
ssh $SSH_OPTS "$SSH_TARGET" "cat /tmp/dhcp.leases 2>/dev/null | awk '{printf \"  %s  %s  %s\n\", \$2, \$3, \$4}'" 2>/dev/null || echo "  (none found)"

echo ""
echo "WIFE'S PHONE:"
echo "  Bookmark: http://${ROUTER_IP}/tickets.html"
echo ""
echo "TO UPDATE LATER:"
echo "  1. Edit files in config/local/"
echo "  2. Run: ./install.sh ${ROUTER_IP}"
echo "  3. Active tickets and budgets are preserved"
echo ""
echo "TO FORCE FULL RE-APPLY (clears active state):"
echo "  ./install.sh ${ROUTER_IP} --force"