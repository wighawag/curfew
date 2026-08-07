#!/bin/bash
# ============================================================================
# booted.bash - bring up OpenWrt's real network stack inside the container
#
# The rest of the suite runs against an OpenWrt userland whose services are NOT
# started, so `ifstatus` cannot answer and every test must pin the interface
# with PARENTAL_WAN_IF. That leaves one branch permanently unexercised:
#
#     WAN_L3_IF="$(ifstatus wan | ... l3_device ...)"
#     [ -n "$WAN_L3_IF" ] && WAN_IF="$WAN_L3_IF"
#
# which is exactly where a real enforcement failure once lived (commit c20d341:
# "Fix MAC allowlist: match pppoe-wan not eth1 for PPPoE connections ... The
# drop rule never matched, so unknown devices could access the internet").
#
# Starting ubusd and netifd against a real /etc/config/network makes netifd
# create and address br-lan itself and makes `ifstatus wan` answer, so the
# scripts resolve their interfaces the way they do on the router, with no
# environment override at all.
#
# Notes on what this needs, each found by hitting the failure:
#   - /var/run/ubus must exist or ubusd starts but never creates its socket,
#     which presents as "ubus is running but does not respond".
#   - /etc/config/network does not exist in the rootfs image (a real board
#     generates it during first boot), so it is written here. That is better
#     for a test anyway: the topology is explicit rather than board-derived.
#   - The bridge ports must exist BEFORE netifd starts, as they would on real
#     hardware, or netifd declines to create the bridge.
#   - PID 1 does NOT need to be init, and no privileged container is required.
# ============================================================================

BOOTED_LAN_IP="10.99.1.1"
BOOTED_CLIENT_IP="10.99.1.2"
BOOTED_WAN_IP="10.99.2.1"
BOOTED_INTERNET_IP="10.99.2.2"
BOOTED_PAGE="BOOTED-PATH-OK"
BOOTED_DOCROOT="/tmp/booted-docroot"

_booted_run() { nsenter --net=/var/run/netns/"$1" "${@:2}"; }

booted_write_network_config() {
    cat > /etc/config/network << EOF
config device
    option name 'br-lan'
    option type 'bridge'
    list ports 'lan0'

config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '$BOOTED_LAN_IP'
    option netmask '255.255.255.0'

config interface 'wan'
    option device 'pppoe-wan'
    option proto 'static'
    option ipaddr '$BOOTED_WAN_IP'
    option netmask '255.255.255.0'
EOF
}

booted_setup() {
    booted_teardown
    mkdir -p /var/run/ubus /var/lock /var/state /var/run

    # Physical ends first, as on a real board. The WAN device is named
    # pppoe-wan so that what netifd reports matches the production router.
    ip link add lan0 type veth peer name cl0
    ip link add pppoe-wan type veth peer name inet0

    booted_write_network_config

    setsid /sbin/ubusd </dev/null >/dev/null 2>&1 &
    local i
    for i in $(seq 1 15); do ubus list >/dev/null 2>&1 && break; sleep 1; done
    ubus list >/dev/null 2>&1 || { echo "ubusd never answered" >&2; return 1; }

    setsid /sbin/netifd </dev/null >/dev/null 2>&1 &
    for i in $(seq 1 20); do
        [ -n "$(booted_l3 wan)" ] && [ -n "$(booted_l3 lan)" ] && break
        sleep 1
    done
    [ -n "$(booted_l3 wan)" ] || { echo "netifd never brought up wan" >&2; return 1; }

    # Client and internet hosts on either side of the netifd-managed router.
    ip netns add client
    ip netns add internet
    ip link set cl0 netns client
    _booted_run client ip link set lo up
    _booted_run client ip addr add "$BOOTED_CLIENT_IP"/24 dev cl0
    _booted_run client ip link set cl0 up
    _booted_run client ip route add default via "$BOOTED_LAN_IP"

    ip link set inet0 netns internet
    _booted_run internet ip link set lo up
    _booted_run internet ip addr add "$BOOTED_INTERNET_IP"/24 dev inet0
    _booted_run internet ip link set inet0 up
    _booted_run internet ip route add default via "$BOOTED_WAN_IP"

    mkdir -p "$BOOTED_DOCROOT"
    echo "$BOOTED_PAGE" > "$BOOTED_DOCROOT/index.html"
    # No -f: that means "do NOT fork", and a foreground server here holds the
    # test runner's output pipe open so the suite hangs after the last test.
    _booted_run internet /usr/sbin/uhttpd -h "$BOOTED_DOCROOT" -p "$BOOTED_INTERNET_IP":80 \
        >/dev/null 2>&1 </dev/null

    for i in $(seq 1 10); do
        wget -q -T 1 -O /dev/null "http://$BOOTED_INTERNET_IP/" 2>/dev/null && return 0
        sleep 1
    done
    echo "internet host never became ready" >&2
    return 1
}

# What netifd reports as an interface's L3 device, read exactly the way the
# enforcement scripts read it.
booted_l3() {
    ifstatus "$1" 2>/dev/null | grep -o '"l3_device".*' | cut -d'"' -f4
}

booted_client_mac() {
    local mac="$1"
    _booted_run client ip link set cl0 down
    _booted_run client ip link set cl0 address "$mac"
    _booted_run client ip link set cl0 up
    # Taking the link down deletes the default route; without re-adding it
    # every probe fails for a routing reason that looks like a firewall block.
    _booted_run client ip route add default via "$BOOTED_LAN_IP" 2>/dev/null || true
    _booted_run client ip neigh flush all 2>/dev/null || true
    ip neigh flush dev br-lan 2>/dev/null || true
}

booted_probe() {
    _booted_run client wget -q -T 3 -O /dev/null "http://$BOOTED_INTERNET_IP/" 2>/dev/null
}

# Teardown must be thorough, and specifically must stop netifd. The scripts let
# ifstatus OVERRIDE PARENTAL_WAN_IF, so a surviving netifd would silently change
# WAN resolution for every other test file in the suite.
# Uses killall, NOT pgrep. Busybox pgrep -x matches nothing here, so an earlier
# version silently failed to stop netifd at all; and pgrep -f netifd matches the
# test shell's own command line, so killing what it returns would take out the
# runner. killall matches on process name and does neither.
booted_teardown() {
    killall uhttpd 2>/dev/null || true
    killall netifd 2>/dev/null || true
    killall ubusd 2>/dev/null || true
    sleep 1
    ip netns delete client 2>/dev/null || true
    ip netns delete internet 2>/dev/null || true
    ip link delete br-lan 2>/dev/null || true
    ip link delete lan0 2>/dev/null || true
    ip link delete pppoe-wan 2>/dev/null || true
    rm -f /etc/config/network
    rm -rf "$BOOTED_DOCROOT"
    nft delete table inet parental_control 2>/dev/null || true
    return 0
}

# A CAPABILITY check, not a process count: what matters is that ubus answers
# and netifd can report an interface, which is precisely what the enforcement
# scripts depend on. Counting processes would also have to contend with busybox
# pgrep's surprises.
booted_services_running() {
    ubus list >/dev/null 2>&1 && [ -n "$(booted_l3 lan)" ]
}
