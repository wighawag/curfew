#!/usr/bin/env bats
# Proves the test environment itself, through the gate.
#
# These assertions exist because the environment's requirements are subtle and
# their failure modes are silent: a packet-path suite whose topology is broken
# reports every probe as unreachable, which is indistinguishable from a
# perfectly working firewall. Asserting the environment here means such a
# regression fails loudly and specifically instead of quietly inverting the
# meaning of every harness assertion.

@test "the container runs a real OpenWrt userland, not a lookalike" {
    run grep -q "OpenWrt" /etc/openwrt_release
    [ "$status" -eq 0 ]
}

@test "system tools are the real binaries, not mocks" {
    for tool in uci logger nft uhttpd nsenter cksum nl; do
        run command -v "$tool"
        [ "$status" -eq 0 ] || { echo "missing: $tool"; return 1; }
    done
    # The mocks these replaced wrote to /usr/local/bin; none should remain.
    run test -e /usr/local/bin/mock-uci
    [ "$status" -ne 0 ]
    run test -e /usr/local/bin/mock-logger
    [ "$status" -ne 0 ]
    run test -e /usr/local/bin/mock-iptables
    [ "$status" -ne 0 ]
}

@test "bats is the pinned version" {
    run bats --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"1.11.0"* ]]
}

@test "ip is ip-full, not busybox (busybox ip cannot do netns)" {
    # A presence check would pass on busybox and tell us nothing. This is a
    # capability check on purpose.
    run ip netns list
    [ "$status" -eq 0 ]
}

@test "ip netns add works (proves /var/run exists and SYS_ADMIN is granted)" {
    ip netns delete envprobe 2>/dev/null || true
    run ip netns add envprobe
    [ "$status" -eq 0 ]
    ip netns delete envprobe 2>/dev/null || true
}

@test "ip_forward is enabled, and came from the runtime not from inside" {
    # /proc/sys is read-only in the container, so neither a test nor the
    # harness can set this for itself: it comes from the compose sysctls key,
    # or is inherited from the host's value when the namespace is created.
    # Asserting it either way keeps a forwarding regression loud.
    run cat /proc/sys/net/ipv4/ip_forward
    [ "$status" -eq 0 ]
    [ "$output" = "1" ]
}
