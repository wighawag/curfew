#!/bin/bash
# ============================================================================
# install.sh - Install parental control system on OpenWrt router
#
# Usage: ./install.sh <router-ip> [options]
#
# Example:
#   ./install.sh 192.168.1.1
#   ./install.sh 192.168.1.1 --user root
#
# What it does:
#   1. Copies all scripts to the router
#   2. Copies the web interface
#   3. Creates config files from examples (if they don't exist)
#   4. Sets up cron schedules (bedtime, lunch, budget tracking)
#   5. Sets up the MAC allowlist init script
#
# Prerequisites:
#   - OpenWrt flashed and running on the router
#   - PPPoE configured (internet working)
#   - Wi-Fi configured
#   - SSH access to the router (password set)
# ============================================================================

set -e

ROUTER_IP="${1:-}"
SSH_USER="root"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

if [ -z "$ROUTER_IP" ]; then
    echo "Usage: ./install.sh <router-ip> [--user root]"
    echo "Example: ./install.sh 192.168.1.1"
    exit 1
fi

# Parse --user option
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --user) SSH_USER="$2"; shift 2 ;;
        *) shift ;;
    esac
done

SSH_TARGET="${SSH_USER}@${ROUTER_IP}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Installing Parental Control System ==="
echo "Router: $SSH_TARGET"
echo ""

# Step 1: Test SSH connection
echo "1. Testing SSH connection..."
if ! ssh $SSH_OPTS "$SSH_TARGET" "echo ok" >/dev/null 2>&1; then
    echo "   ERROR: Cannot SSH to $SSH_TARGET"
    echo "   Make sure OpenWrt is running and SSH is accessible."
    echo "   Set a root password in LuCI first: http://${ROUTER_IP}"
    exit 1
fi
echo "   SSH connection OK"

# Step 2: Copy scripts
echo "2. Copying scripts..."
scp $SSH_OPTS "$SCRIPT_DIR/scripts/parental-profiles.sh" "$SSH_TARGET:/usr/bin/parental-profiles.sh"
scp $SSH_OPTS "$SCRIPT_DIR/scripts/setup-firewall.sh" "$SSH_TARGET:/usr/bin/setup-firewall.sh"
scp $SSH_OPTS "$SCRIPT_DIR/scripts/website-blocking.sh" "$SSH_TARGET:/usr/bin/website-blocking.sh"
scp $SSH_OPTS "$SCRIPT_DIR/scripts/blocklists.sh" "$SSH_TARGET:/usr/bin/blocklists.sh"
ssh $SSH_OPTS "$SSH_TARGET" "chmod +x /usr/bin/parental-profiles.sh /usr/bin/setup-firewall.sh /usr/bin/website-blocking.sh /usr/bin/blocklists.sh"
echo "   Scripts installed"

# Step 3: Copy web interface
echo "3. Copying web interface..."
ssh $SSH_OPTS "$SSH_TARGET" "mkdir -p /www/cgi-bin"
scp $SSH_OPTS "$SCRIPT_DIR/web/tickets.html" "$SSH_TARGET:/www/tickets.html"
scp $SSH_OPTS "$SCRIPT_DIR/web/cgi-bin/ticket" "$SSH_TARGET:/www/cgi-bin/ticket"
ssh $SSH_OPTS "$SSH_TARGET" "chmod +x /www/cgi-bin/ticket"
echo "   Web interface installed at http://${ROUTER_IP}/tickets.html"

# Step 4: Create config files (only if they don't exist)
echo "4. Setting up config files..."
ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE'
# Profile config
if [ ! -f /etc/config/parental_profiles ]; then
    cat > /etc/config/parental_profiles << 'EOF'
# Edit this file with your profiles
# Format: profile_name|budget_minutes_per_day|mac1,mac2,mac3
# budget of 0 = unlimited (schedule-only)
alice|120|CHANGEME:MAC1,CHANGEME:MAC2
bob|90|CHANGEME:MAC3,CHANGEME:MAC4
EOF
    echo "   Created /etc/config/parental_profiles (EDIT ME!)"
else
    echo "   /etc/config/parental_profiles already exists"
fi

# Website blocking config
if [ ! -f /etc/config/parental_websites ]; then
    cat > /etc/config/parental_websites << 'EOF'
# Edit this file with websites to block per profile
# Format: profile_name|domain1,domain2,domain3
alice|youtube.com,www.youtube.com,tiktok.com,www.tiktok.com
bob|tiktok.com,www.tiktok.com
EOF
    echo "   Created /etc/config/parental_websites (EDIT ME!)"
else
    echo "   /etc/config/parental_websites already exists"
fi

# MAC allowlist
if [ ! -f /etc/config/mac_allowlist ]; then
    cat > /etc/config/mac_allowlist << 'EOF'
# Edit this file with ALL your devices' MAC addresses
# One MAC per line. Only these MACs will have internet access.
# Run: ssh root@ROUTER_IP "cat /tmp/dhcp.leases"
# to see connected devices and their MACs.

# Parents
CHANGEME:MAC  # Dad's phone
CHANGEME:MAC  # Mom's phone

# Kids (must match parental_profiles)
CHANGEME:MAC  # Alice's phone
CHANGEME:MAC  # Alice's laptop
CHANGEME:MAC  # Bob's phone
CHANGEME:MAC  # Bob's tablet
EOF
    echo "   Created /etc/config/mac_allowlist (EDIT ME!)"
else
    echo "   /etc/config/mac_allowlist already exists"
fi

# Global blocklists (gambling, porn, malware, etc.)
if [ ! -f /etc/config/parental_blocklists ]; then
    cat > /etc/config/parental_blocklists << 'EOF'
# Global content filtering - applies to ALL devices
https://blocklistproject.github.io/Lists/dnsmasq-version/gambling-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/porn-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/malware-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/phishing-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/ransomware-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/scam-dnsmasq.txt
https://blocklistproject.github.io/Lists/dnsmasq-version/fraud-dnsmasq.txt
EOF
    echo "   Created /etc/config/parental_blocklists"
else
    echo "   /etc/config/parental_blocklists already exists"
fi
REMOTE

# Step 5: Set up cron
echo "5. Setting up cron schedules..."
ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE'
cat > /tmp/crontab << 'EOF'
# === Parental Control Cron Jobs ===
# Edit times as needed. Times are in 24h format.

# Time budget tracking (every minute - MUST run)
* * * * * /usr/bin/parental-profiles.sh budget-check

# Refresh website blocking DNS (hourly - keeps IPs updated)
0 * * * * /usr/bin/website-blocking.sh refresh

# Refresh global blocklists (weekly - gambling/porn/malware lists)
0 3 * * 0 /usr/bin/blocklists.sh update

# === Internet schedules (edit for your family) ===
# Bedtime: block at 20:00, unblock at 07:00
0 20 * * * /usr/bin/parental-profiles.sh block alice
0 20 * * * /usr/bin/parental-profiles.sh block bob
0 7 * * * /usr/bin/parental-profiles.sh unblock alice
0 7 * * * /usr/bin/parental-profiles.sh unblock bob

# Lunch block: block 12:00-13:00 (weekdays only)
0 12 * * 1-5 /usr/bin/parental-profiles.sh block alice
0 12 * * 1-5 /usr/bin/parental-profiles.sh block bob
0 13 * * 1-5 /usr/bin/parental-profiles.sh unblock alice
0 13 * * 1-5 /usr/bin/parental-profiles.sh unblock bob

# Weekend: allow until 21:00
0 21 * * 6,0 /usr/bin/parental-profiles.sh block alice
0 21 * * 6,0 /usr/bin/parental-profiles.sh block bob

# === Website blocking schedules (independent of internet, per group) ===
# After school: block YouTube + TikTok (weekdays)
30 15 * * 1-5 /usr/bin/website-blocking.sh enable alice after_school
0 17 * * 1-5 /usr/bin/website-blocking.sh disable alice after_school
# Evening: block all streaming (different domain list)
0 18 * * * /usr/bin/website-blocking.sh enable alice evening
0 20 * * * /usr/bin/website-blocking.sh disable alice evening
# Bob: block TikTok all day (uses default group)
0 7 * * * /usr/bin/website-blocking.sh enable bob
0 20 * * * /usr/bin/website-blocking.sh disable bob
EOF

# Merge with existing crontab (don't overwrite other jobs)
if crontab -l 2>/dev/null | grep -q "parental"; then
    # Already has parental control jobs, replace them
    crontab -l 2>/dev/null | grep -v "parental-profiles\|website-blocking" > /tmp/existing_cron
    cat /tmp/existing_cron /tmp/crontab > /tmp/merged_cron
    crontab /tmp/merged_cron
else
    # No existing parental control jobs, append
    if crontab -l >/dev/null 2>&1; then
        (crontab -l; cat /tmp/crontab) | crontab -
    else
        crontab /tmp/crontab
    fi
fi
rm -f /tmp/crontab /tmp/existing_cron /tmp/merged_cron
echo "   Cron schedules installed (edit with: ssh $ROUTER_IP crontab -e)"
REMOTE

# Step 6: Set up init script for MAC allowlist on boot
echo "6. Setting up boot-time firewall..."
ssh $SSH_OPTS "$SSH_TARGET" << 'REMOTE'
# Create init script
cat > /etc/init.d/parental-allowlist << 'EOF'
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
/etc/init.d/parental-allowlist enable
echo "   Init script enabled (MAC allowlist applies on boot)"
REMOTE

# Step 7: Show connected devices (for filling in MAC addresses)
echo "7. Currently connected devices:"
ssh $SSH_OPTS "$SSH_TARGET" "cat /tmp/dhcp.leases 2>/dev/null | awk '{printf \"  %s  %s  %s\n\", \$2, \$3, \$4}'" 2>/dev/null || echo "   (no leases found)"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "NEXT STEPS:"
echo "  1. Edit configs on the router:"
echo "     ssh ${SSH_USER}@${ROUTER_IP}"
echo "     vi /etc/config/parental_profiles    # Set profile names, budgets, MACs"
echo "     vi /etc/config/parental_websites    # Set websites to block per profile"
echo "     vi /etc/config/mac_allowlist        # Add ALL device MACs"
echo ""
echo "  2. Apply the MAC allowlist and download blocklists:"
echo "     ssh ${SSH_USER}@${ROUTER_IP} setup-firewall.sh apply"
echo "     ssh ${SSH_USER}@${ROUTER_IP} blocklists.sh update    # gambling/porn/malware"
echo ""
echo "  3. Adjust cron schedules:"
echo "     ssh ${SSH_USER}@${ROUTER_IP} crontab -e"
echo ""
echo "  4. Test it:"
echo "     ssh ${SSH_USER}@${ROUTER_IP} parental-profiles.sh status"
echo "     ssh ${SSH_USER}@${ROUTER_IP} parental-profiles.sh block alice"
echo "     ssh ${SSH_USER}@${ROUTER_IP} parental-profiles.sh ticket alice 30"
echo ""
echo "  5. Wife's phone bookmark:"
echo "     http://${ROUTER_IP}/tickets.html"
echo ""
echo "  6. Disable MAC randomization on kids' devices:"
echo "     iPhone: Settings > Wi-Fi > tap 'i' > Private Wi-Fi Address > OFF"
echo "     Android: Settings > Wi-Fi > tap network > Privacy > Use device MAC"