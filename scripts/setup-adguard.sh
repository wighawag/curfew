#!/bin/sh
# ============================================================================
# setup-adguard.sh - Install and configure AdGuard Home on OpenWrt
#
# AdGuard Home is a DNS filtering server that handles millions of domains
# efficiently. It replaces dnsmasq for DNS (dnsmasq keeps handling DHCP).
#
# What it does:
#   1. Downloads AdGuard Home binary for aarch64
#   2. Moves dnsmasq to port 54 (DHCP only, forwards DNS to AdGuard Home)
#   3. Pre-configures AdGuard Home with blocklists
#   4. Starts AdGuard Home on port 53 (DNS) and 3000 (web UI)
#
# Author: wighawag
# License: AGPL-3.0-only
# ============================================================================

set -u

AGH_DIR="/opt/AdGuardHome"
AGH_BIN="$AGH_DIR/AdGuardHome"
AGH_CONFIG="$AGH_DIR/adguardhome.yaml"
AGH_WORKDIR="/var/adguardhome"
ROUTER_IP="${1:-$(uci get network.lan.ipaddr 2>/dev/null | cut -d/ -f1 || echo "192.168.1.1")}"
LOGGER="${LOGGER:-logger}"

log() {
    $LOGGER -t adguard-setup "$1" 2>/dev/null || echo "[adguard-setup] $1" >&2
}

# Check if already installed
if [ -x "$AGH_BIN" ] && pgrep AdGuardHome >/dev/null 2>&1; then
    echo "AdGuard Home is already running"
    echo "Web UI: http://${ROUTER_IP}:3000"
    exit 0
fi

echo "=== Installing AdGuard Home ==="

# Install dependencies
echo "1. Installing dependencies..."
apk update 2>/dev/null || opkg update 2>/dev/null
apk add ca-bundle wget-ssl tar 2>/dev/null || opkg install ca-bundle wget-ssl tar 2>/dev/null
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

# Download AdGuard Home
echo "2. Downloading AdGuard Home..."
mkdir -p "$AGH_DIR" "$AGH_WORKDIR"
cd /opt

wget "https://static.adguard.com/adguardhome/release/AdGuardHome_linux_${AGH_ARCH}.tar.gz" -O /tmp/agh.tar.gz 2>/dev/null
if [ ! -s /tmp/agh.tar.gz ]; then
    echo "   ERROR: Download failed"
    exit 1
fi
tar -xzf /tmp/agh.tar.gz -C /opt 2>/dev/null
rm -f /tmp/agh.tar.gz
echo "   Downloaded to $AGH_BIN"

# Move dnsmasq to port 54 (DHCP only)
echo "3. Configuring dnsmasq (moving to port 54)..."
uci set dhcp.@dnsmasq[0].port="54"
uci -q delete dhcp.@dnsmasq[0].confdir 2>/dev/null
# Remove any blocklist configs that might crash dnsmasq
rm -f /etc/dnsmasq.d/blocklists.conf 2>/dev/null
rm -rf /tmp/dnsmasq-blocklists 2>/dev/null
uci commit dhcp
/etc/init.d/dnsmasq restart 2>/dev/null
echo "   dnsmasq on port 54 (DHCP only)"

# Configure DHCP to advertise router as DNS server
echo "4. Configuring DHCP DNS..."
uci -q delete dhcp.lan.dhcp_option 2>/dev/null
uci add_list dhcp.lan.dhcp_option="6,${ROUTER_IP}"
uci commit dhcp
/etc/init.d/dnsmasq restart 2>/dev/null
echo "   DHCP advertises ${ROUTER_IP} as DNS server"

# Wait for port 53 to be free
sleep 2

# Pre-configure AdGuard Home
echo "5. Creating AdGuard Home config..."
cat > "$AGH_CONFIG" << AGHEOF
bind_port: 3000
acl:
  allowed_clients:
    - 0.0.0.0/0
    - ::/0
dns:
  bind_address: 0.0.0.0
  port: 53
  upstream_dns:
    - 1.1.1.1
    - 8.8.8.8
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  filtering_enabled: true
  protection_enabled: true
  safebrowsing_enabled: true
  parental_enabled: true
  safe_search:
    enabled: true
  blocking_mode: nxdomain
  ratelimit: 0
  cache_size: 4194304
  cache_ttl_min: 60
  cache_ttl_max: 86400
  upstream_mode: load_balance
users: []
http:
  address: 0.0.0.0:3000
  session_ttl: 60min
log_file: ""
verbose: false
schema_version: 30
filters:
AGHEOF

# Add blocklist filters (using Block List Project AdGuard format)
add_filter() {
    local name="$1"
    local url="$2"
    cat >> "$AGH_CONFIG" << EOF
  - enabled: true
    url: "$url"
    name: "$name"
    id: $(echo "$name" | cksum | cut -d' ' -f1)
EOF
}

add_filter "Gambling" "https://blocklistproject.github.io/Lists/adguard/gambling-ags.txt"
add_filter "Porn" "https://blocklistproject.github.io/Lists/adguard/porn-ags.txt"
add_filter "Malware" "https://blocklistproject.github.io/Lists/adguard/malware-ags.txt"
add_filter "Phishing" "https://blocklistproject.github.io/Lists/adguard/phishing-ags.txt"
add_filter "Ransomware" "https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt"
add_filter "Scam" "https://blocklistproject.github.io/Lists/adguard/scam-ags.txt"
add_filter "Fraud" "https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt"
add_filter "Ads" "https://blocklistproject.github.io/Lists/adguard/ads-ags.txt"

echo "" >> "$AGH_CONFIG"
echo "whitelist_filters: []" >> "$AGH_CONFIG"
echo "blacklist_filters: []" >> "$AGH_CONFIG"
echo "user_rules: []" >> "$AGH_CONFIG"
echo "dhcp:" >> "$AGH_CONFIG"
echo "  enabled: false" >> "$AGH_CONFIG"

echo "   Config created with 8 blocklists"

# Install and start AdGuard Home service
echo "6. Starting AdGuard Home..."
cd "$AGH_DIR"
chmod +x "$AGH_BIN"
"$AGH_BIN" -s install 2>/dev/null
"$AGH_BIN" -s start 2>/dev/null
sleep 2

if pgrep AdGuardHome >/dev/null 2>&1; then
    echo ""
    echo "=== AdGuard Home installed successfully ==="
    echo ""
    echo "Web UI: http://${ROUTER_IP}:3000"
    echo "DNS:   port 53 (all devices use this automatically)"
    echo ""
    echo "Blocklists loaded:"
    echo "  gambling, porn, malware, phishing, ransomware, scam, fraud, ads"
    echo ""
    echo "dnsmasq: port 54 (DHCP only)"
    log "AdGuard Home installed and running"
else
    echo "   ERROR: AdGuard Home failed to start"
    echo "   Try manually: cd $AGH_DIR && ./AdGuardHome"
    exit 1
fi