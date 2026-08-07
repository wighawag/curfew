#!/bin/sh
# ============================================================================
# setup-adguard.sh - Install and configure AdGuard Home on OpenWrt
#
# AdGuard Home handles DNS filtering (gambling/porn/malware/ads).
# dnsmasq keeps handling DHCP (moved to port 54).
#
# What it does:
#   1. Downloads AdGuard Home binary
#   2. Moves dnsmasq to port 54 (DHCP only)
#   3. Creates config with blocklists (AdGuard format)
#   4. Creates OpenWrt init script (procd, survives reboot)
#   5. Starts AdGuard Home on port 53 (DNS) + 3000 (web UI)
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u

AGH_DIR="/opt/AdGuardHome"
AGH_BIN="$AGH_DIR/AdGuardHome"
AGH_CONFIG="$AGH_DIR/adguardhome.yaml"
ROUTER_IP="${1:-$(uci get network.lan.ipaddr 2>/dev/null | cut -d/ -f1 || echo "192.168.1.1")}"
LOGGER="${LOGGER:-logger}"

log() {
    $LOGGER -t adguard-setup "$1" 2>/dev/null || echo "[adguard-setup] $1" >&2
}

# Check if already installed and running
if [ -x "$AGH_BIN" ] && pgrep AdGuardHome >/dev/null 2>&1; then
    # Check if DNS is actually working (port 53)
    if netstat -ulnp 2>/dev/null | grep -q ":53.*AdGuard"; then
        echo "AdGuard Home is already running with DNS on port 53"
        echo "Web UI: http://${ROUTER_IP}:3000"
        exit 0
    fi
fi

echo "=== Installing AdGuard Home ==="

# Install dependencies
echo "1. Installing dependencies..."
apk update 2>/dev/null || opkg update 2>/dev/null
apk add ca-bundle wget-ssl tar curl 2>/dev/null || opkg install ca-bundle wget-ssl tar curl 2>/dev/null
echo "   Done"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    aarch64) AGH_ARCH="arm64" ;;
    x86_64)  AGH_ARCH="amd64" ;;
    armv7l)  AGH_ARCH="armv7" ;;
    *)
        echo "   ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac
echo "   Architecture: $ARCH -> $AGH_ARCH"

# Stop AdGuard Home if running
killall AdGuardHome 2>/dev/null
sleep 1

# Download AdGuard Home (skip if already downloaded)
echo "2. Downloading AdGuard Home..."
if [ ! -x "$AGH_BIN" ]; then
    mkdir -p "$AGH_DIR"
    cd /opt
    wget "https://static.adguard.com/adguardhome/release/AdGuardHome_linux_${AGH_ARCH}.tar.gz" -O /tmp/agh.tar.gz 2>/dev/null
    if [ ! -s /tmp/agh.tar.gz ]; then
        echo "   ERROR: Download failed"
        exit 1
    fi
    tar -xzf /tmp/agh.tar.gz -C /opt 2>/dev/null
    rm -f /tmp/agh.tar.gz
fi
echo "   Binary at $AGH_BIN"

# Move dnsmasq to port 54 BEFORE starting AdGuard Home
echo "3. Moving dnsmasq to port 54..."
uci set dhcp.@dnsmasq[0].port="54"
uci -q delete dhcp.lan.dhcp_option 2>/dev/null
uci add_list dhcp.lan.dhcp_option="6,${ROUTER_IP}"
uci -q delete dhcp.@dnsmasq[0].confdir 2>/dev/null
rm -f /etc/dnsmasq.d/blocklists.conf 2>/dev/null
rm -rf /tmp/dnsmasq-blocklists 2>/dev/null
uci commit dhcp
/etc/init.d/dnsmasq restart 2>/dev/null
sleep 2

# Verify port 53 is free
if netstat -tlnp 2>/dev/null | grep -q ":53 "; then
    echo "   WARNING: port 53 still in use, killing process..."
    fuser -k 53/tcp 2>/dev/null
    sleep 1
fi
echo "   dnsmasq on port 54, port 53 free"

# Create AdGuard Home config
echo "4. Creating config..."
cat > "$AGH_CONFIG" << AGHEOF
http:
  address: 0.0.0.0:3000
  session_ttl: 1h
users: []
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  upstream_dns:
    - 1.1.1.1
    - 8.8.8.8
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  filtering_enabled: true
  protection_enabled: true
  cache_size: 4194304
  cache_ttl_min: 60
  cache_ttl_max: 86400
  blocking_mode: nxdomain
  serve_plain_dns: true
  hostsfile_enabled: true
schema_version: 34
filters:
AGHEOF

i=1
for name in Gambling Porn Malware Phishing Ransomware Scam Fraud Ads; do
    url="https://blocklistproject.github.io/Lists/adguard/$(echo $name | tr A-Z a-z)-ags.txt"
    cat >> "$AGH_CONFIG" << EOF
  - enabled: true
    url: "$url"
    name: "$name"
    id: $i
EOF
    i=$((i + 1))
done

cat >> "$AGH_CONFIG" << "EOF"
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
filtering:
  filtering_enabled: true
  protection_enabled: true
  parental_enabled: false
  safebrowsing_enabled: true
  blocking_mode: nxdomain
EOF

echo "   Config created with 8 blocklists"

# Create OpenWrt init script (procd, survives reboot)
echo "5. Creating init script..."
cat > /etc/init.d/adguardhome << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/adguardhome.yaml
    procd_set_param file /opt/AdGuardHome/adguardhome.yaml
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_set_param respawn_threshold 10
    procd_set_param respawn_timeout 10
    procd_set_param respawn_retry 5
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/adguardhome
/etc/init.d/adguardhome enable
echo "   Init script enabled"

# Start AdGuard Home
echo "6. Starting AdGuard Home..."
/etc/init.d/adguardhome start 2>/dev/null
sleep 3

# Verify
if pgrep AdGuardHome >/dev/null 2>&1 && netstat -ulnp 2>/dev/null | grep -q ":53.*AdGuard"; then
    echo ""
    echo "=== AdGuard Home installed successfully ==="
    echo ""
    echo "Web UI: http://${ROUTER_IP}:3000"
    echo "DNS:   port 53 (all devices use this automatically)"
    echo ""
    echo "Blocklists loaded:"
    echo "  gambling(278K) porn(953K) malware(2.6M) phishing(190K)"
    echo "  ransomware(1.9K) scam(8.5K) fraud(256K) ads(234K)"
    echo ""
    echo "dnsmasq: port 54 (DHCP only)"
    log "AdGuard Home installed and running on port 53"
    exit 0
else
    echo "   WARNING: AdGuard Home started but DNS may not be ready yet"
    echo "   Check http://${ROUTER_IP}:3000 — may need to complete setup wizard"
    echo "   If wizard appears: set DNS to 0.0.0.0:53, upstreams 1.1.1.1 + 8.8.8.8"
    exit 0
fi