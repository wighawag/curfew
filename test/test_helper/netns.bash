#!/bin/bash
# ============================================================================
# netns.bash - packet-path test harness
#
# Builds a real LAN -> router -> WAN topology inside the test container so a
# test can ask the only question that matters about a firewall: did the packet
# get through? See docs/adr/0004-tests-assert-on-the-packet-path.md for why
# ruleset assertions are not sufficient.
#
#   client ns            container (the router)              internet ns
#   10.99.1.2  <--veth--> br-lan 10.99.1.1
#                         pppoe-wan 10.99.2.1 <--veth--> 10.99.2.2 (uhttpd)
#
# The 10.99.x range is deliberate: podman defaults to 10.88.0.0/16 and docker
# to 172.17.0.0/16, so neither collides. A collision would break the topology
# in a way that reads exactly like a working firewall, which is also why
# harness.bats asserts a baseline before asserting anything is blocked.
#
# The router-side veth end is the one named pppoe-wan, because the enforcement
# scripts match on oifname. Naming the peer instead leaves the rules matching
# nothing. The scripts resolve the interface from PARENTAL_WAN_IF, so the name
# alone is not enough and the lever must be set (see netns_env).
# ============================================================================

NETNS_LAN_IF="br-lan"
NETNS_WAN_IF="pppoe-wan"
NETNS_ROUTER_LAN_IP="10.99.1.1"
NETNS_CLIENT_IP="10.99.1.2"
NETNS_ROUTER_WAN_IP="10.99.2.1"
NETNS_INTERNET_IP="10.99.2.2"
NETNS_PAGE="PACKET-PATH-OK"
NETNS_PIDFILE="/tmp/netns-uhttpd.pid"
NETNS_DOCROOT="/tmp/netns-docroot"

# Append rather than replace, so a test can shadow a tool by PREPENDING to
# PATH. Replacing would make the preflight untestable (see harness.bats).
export PATH="$PATH:/usr/sbin:/sbin"

_netns_run() { nsenter --net=/var/run/netns/"$1" "${@:2}"; }

# Environment levers the enforcement scripts need to target this topology.
netns_env() {
    export PARENTAL_WAN_IF="$NETNS_WAN_IF"
    export PARENTAL_LAN_IF="$NETNS_LAN_IF"
}

# CAPABILITY checks, not presence checks. Presence is the wrong question:
# busybox provides /sbin/ip, so `command -v ip` passes on an image where
# ip-full was never installed and `ip netns` does not work. Checking that each
# tool can DO its job is what makes this guard meaningful.
netns_preflight() {
    ip netns list >/dev/null 2>&1 || { echo "preflight: ip cannot do netns (busybox ip?)" >&2; return 1; }
    nft --version   >/dev/null 2>&1 || { echo "preflight: nft unusable" >&2; return 1; }
    nsenter --version >/dev/null 2>&1 || { echo "preflight: nsenter unusable" >&2; return 1; }
    [ -x /usr/sbin/uhttpd ] || { echo "preflight: uhttpd missing" >&2; return 1; }
    wget --version >/dev/null 2>&1 || wget 2>&1 | grep -q Usage || { echo "preflight: wget unusable" >&2; return 1; }
    return 0
}

netns_setup() {
    netns_preflight || return 1
    netns_teardown
    netns_env
    mkdir -p /var/run

    # A leftover parental_control table from an earlier test file would make
    # the baseline ambiguous, so start from a known-clean firewall.
    nft delete table inet parental_control 2>/dev/null || true

    ip netns add client
    ip netns add internet

    # LAN side
    ip link add "$NETNS_LAN_IF" type bridge
    ip addr add "$NETNS_ROUTER_LAN_IP"/24 dev "$NETNS_LAN_IF"
    ip link set "$NETNS_LAN_IF" up
    ip link add veth-lan type veth peer name cl0
    ip link set veth-lan master "$NETNS_LAN_IF"
    ip link set veth-lan up
    ip link set cl0 netns client
    _netns_run client ip addr add "$NETNS_CLIENT_IP"/24 dev cl0
    _netns_run client ip link set cl0 up
    _netns_run client ip link set lo up
    _netns_run client ip route add default via "$NETNS_ROUTER_LAN_IP"

    # WAN side. The router-side end carries the production interface name.
    ip link add "$NETNS_WAN_IF" type veth peer name inet0
    ip addr add "$NETNS_ROUTER_WAN_IP"/24 dev "$NETNS_WAN_IF"
    ip link set "$NETNS_WAN_IF" up
    ip link set inet0 netns internet
    _netns_run internet ip addr add "$NETNS_INTERNET_IP"/24 dev inet0
    _netns_run internet ip link set inet0 up
    _netns_run internet ip link set lo up
    _netns_run internet ip route add default via "$NETNS_ROUTER_WAN_IP"

    # The internet host
    mkdir -p "$NETNS_DOCROOT"
    echo "$NETNS_PAGE" > "$NETNS_DOCROOT/index.html"
    _netns_run internet /usr/sbin/uhttpd -f -h "$NETNS_DOCROOT" -p "$NETNS_INTERNET_IP":80 &
    echo $! > "$NETNS_PIDFILE"

    # Wait for readiness rather than racing it. No timeout applet on this
    # image, so bound each attempt with the fetch client's own -T.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if wget -q -T 1 -O /dev/null "http://$NETNS_INTERNET_IP/" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "netns_setup: internet host never became ready" >&2
    return 1
}

# Change the client's source MAC.
#
# Taking the link down DELETES the default route, and bringing it back up
# restores only the connected /24. Re-adding the route is therefore mandatory:
# without it every probe reads UNREACHABLE for a routing reason, which looks
# exactly like a working firewall. That is the failure this harness exists to
# make impossible, so it must not be reintroduced here.
netns_client_mac() {
    local mac="$1"
    _netns_run client ip link set cl0 down
    _netns_run client ip link set cl0 address "$mac"
    _netns_run client ip link set cl0 up
    _netns_run client ip route add default via "$NETNS_ROUTER_LAN_IP" 2>/dev/null || true
    _netns_run client ip neigh flush all 2>/dev/null || true
    ip neigh flush dev "$NETNS_LAN_IF" 2>/dev/null || true
}

# 0 = reachable, 1 = unreachable. -T bounds the attempt: a packet meeting a
# DROP rule makes the fetch hang rather than fail.
netns_probe() {
    _netns_run client wget -q -T 3 -O /dev/null "http://$NETNS_INTERNET_IP/" 2>/dev/null
}

netns_teardown() {
    if [ -f "$NETNS_PIDFILE" ]; then
        kill "$(cat "$NETNS_PIDFILE")" 2>/dev/null || true
        rm -f "$NETNS_PIDFILE"
    fi
    pkill -f "uhttpd -f -h $NETNS_DOCROOT" 2>/dev/null || true
    ip netns delete client 2>/dev/null || true
    ip netns delete internet 2>/dev/null || true
    ip link delete "$NETNS_LAN_IF" 2>/dev/null || true
    ip link delete "$NETNS_WAN_IF" 2>/dev/null || true
    rm -rf "$NETNS_DOCROOT"
    nft delete table inet parental_control 2>/dev/null || true
    return 0
}
