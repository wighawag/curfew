#!/bin/sh
# ============================================================================
# panic-off.sh - Disable ALL parental control and restore open internet
#
# Removes all firewall rules, clears all blocks, restores default forwarding.
# Does NOT delete configs or scripts — just disables everything.
#
# Usage: ssh root@192.168.1.1 /usr/bin/panic-off.sh
#
# To re-enable: ./install.sh 192.168.1.1
# ============================================================================

set -u

NFT_BIN="${NFT:-nft}"
NFT_TABLE="parental_control"

echo "=== Disabling ALL parental control ==="

# 1. Flush and delete the entire parental_control nftables table
echo "1. Removing firewall rules..."
$NFT_BIN flush table inet "$NFT_TABLE" 2>/dev/null
$NFT_BIN delete table inet "$NFT_TABLE" 2>/dev/null
echo "   nftables table 'parental_control' removed"

# 2. Stop AdGuard Home (restores dnsmasq as sole DNS)
echo "2. Stopping AdGuard Home..."
/etc/init.d/adguardhome stop 2>/dev/null
killall AdGuardHome 2>/dev/null
echo "   AdGuard Home stopped"

# 3. Restore dnsmasq to port 53
echo "3. Restoring dnsmasq to port 53..."
uci set dhcp.@dnsmasq[0].port="53"
uci -q delete dhcp.lan.dhcp_option 2>/dev/null
uci -q delete dhcp.@dnsmasq[0].confdir 2>/dev/null
rm -f /etc/dnsmasq.d/blocklists.conf 2>/dev/null
rm -rf /tmp/dnsmasq-blocklists 2>/dev/null
uci commit dhcp
/etc/init.d/dnsmasq restart 2>/dev/null
echo "   dnsmasq on port 53 (DNS + DHCP)"

# 4. Stop cron jobs
echo "4. Disabling parental control cron jobs..."
if crontab -l 2>/dev/null | grep -q "parental\|website-blocking\|blocklists"; then
    crontab -l 2>/dev/null | grep -v "parental-profiles\|website-blocking\|blocklists" | crontab -
    echo "   Parental control cron jobs removed"
else
    echo "   No parental control cron jobs found"
fi

# 5. Clear state files
echo "5. Clearing state..."
rm -rf /tmp/parental-profiles 2>/dev/null
echo "   State cleared (tickets, budgets, website blocking)"

# 6. Stop init scripts
echo "6. Disabling boot scripts..."
/etc/init.d/parental-allowlist disable 2>/dev/null
/etc/init.d/adguardhome disable 2>/dev/null
echo "   Boot scripts disabled"

# 7. Verify
sleep 2
echo ""
echo "=== Verification ==="
echo "nftables tables:"
$NFT_BIN list tables 2>/dev/null | grep -v "fw4" || echo "  (only fw4 remains - good)"
echo "DNS:"
nslookup google.com 127.0.0.1 2>&1 | head -4
echo "Internet:"
ping -c 1 -W 2 8.8.8.8 2>&1 | tail -2

echo ""
echo "=== ALL parental control disabled ==="
echo ""
echo "All devices now have unrestricted internet access."
echo "DNS filtering (gambling/porn/malware) is OFF."
echo "MAC allowlist is OFF — unknown devices can connect."
echo ""
echo "To re-enable: ./install.sh 192.168.1.1"
echo "To re-enable AdGuard Home: ssh root@192.168.1.1 /etc/init.d/adguardhome start"