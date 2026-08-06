#!/usr/bin/env bats
# Does AdGuard Home actually BLOCK?
#
# Until now nothing here tested that. test/setup-adguard.bats writes its own
# YAML fixture and greps it, so it never starts AdGuard and could not tell a
# working filter from a broken one. Per docs/adr/0002 AdGuard owns DNS
# filtering for the whole household, so "does it block" is the load-bearing
# question and it was entirely unasserted.
#
# The topology mirrors the router's: AdGuard on port 53, dnsmasq on port 54 as
# its upstream. That keeps the test fully OFFLINE (dnsmasq answers from
# fixtures, no internet) and exercises the same two-resolver arrangement
# setup-adguard.sh creates in production.
#
# Offline matters for correctness here, not just speed: an earlier probe of
# this used .test domains against a real upstream and read NXDOMAIN as proof
# of blocking, when a reserved TLD returns NXDOMAIN anyway. With a fixture
# upstream, every domain below resolves unless AdGuard blocks it, so an
# NXDOMAIN can only have come from the filter.

# Resolvers are started once per FILE, not per test. Two reasons: starting
# AdGuard four times is slow, and a background process launched from bats'
# per-test setup does not reliably survive that subshell exiting, which is
# what made an earlier version of this file fail with "never became ready"
# while the identical commands worked by hand.
AGH_BIN="/opt/AdGuardHome/AdGuardHome"
AGH_CONF="${BATS_TMPDIR}/agh.yaml"
AGH_WORK="${BATS_TMPDIR}/aghwork"

setup_file() {
    export AGH_CONF AGH_WORK
    _stop_resolvers
    mkdir -p "$AGH_WORK"

    # Fixture upstream: every test domain resolves here, so a non-answer is
    # unambiguously AdGuard's doing.
    # NOTE: no --no-resolv. With it, dnsmasq answers REFUSED to everything,
    # including names it has an --address for, which presents identically to
    # AdGuard being broken. Every domain used below is --address-matched, so
    # dnsmasq answers them locally and no upstream is ever consulted; the test
    # stays deterministic without needing --no-resolv.
    dnsmasq --port=54 --no-hosts --bind-interfaces --listen-address=127.0.0.1 \
        --address=/allowed.example/10.99.9.9 \
        --address=/blocked.example/10.99.9.9 \
        --address=/exception.example/10.99.9.9 \
        >/dev/null 2>&1

    cat > "$AGH_CONF" << 'EOF'
http: {address: 127.0.0.1:3000, session_ttl: 1h}
users: []
dns:
  bind_hosts: [127.0.0.1]
  port: 53
  upstream_dns: ["127.0.0.1:54"]
  bootstrap_dns: ["127.0.0.1:54"]
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
  serve_plain_dns: true
schema_version: 34
filters: []
whitelist_filters: []
user_rules:
  - "||blocked.example^"
  - "||exception.example^"
  - "@@||exception.example^"
dhcp: {enabled: false}
filtering: {filtering_enabled: true, protection_enabled: true, blocking_mode: nxdomain}
EOF

    setsid "$AGH_BIN" -c "$AGH_CONF" -w "$AGH_WORK" --no-check-update \
        </dev/null >"${AGH_WORK}/agh.log" 2>&1 &
    _wait_for_resolver
}

teardown_file() {
    _stop_resolvers
}

_stop_resolvers() {
    # pkill does not exist on this image; pgrep exits 1 on no match and bats
    # runs setup/teardown under errexit, hence the guard.
    local p
    for p in $(pgrep -f "AdGuardHome -c ${AGH_CONF}" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    for p in $(pgrep -f "dnsmasq --port=54" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    return 0
}

_wait_for_resolver() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if nslookup allowed.example 127.0.0.1 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    # Dump what actually happened rather than just asserting failure: a silent
    # "never became ready" is what made this hard to diagnose the first time.
    echo "AdGuard never became ready. Diagnostics:" >&2
    echo "-- AdGuardHome processes: $(pgrep -f AdGuardHome 2>/dev/null | wc -l)" >&2
    echo "-- dnsmasq processes: $(pgrep -f 'dnsmasq --port=54' 2>/dev/null | wc -l)" >&2
    echo "-- direct upstream query: $(nslookup allowed.example 127.0.0.1 2>&1 | tail -2 | tr '\n' ' ')" >&2
    echo "-- agh.log:" >&2
    tail -20 "${AGH_WORK}/agh.log" >&2 2>/dev/null || echo "   (no log)" >&2
    return 1
}

_resolves_to() {
    nslookup "$1" 127.0.0.1 2>/dev/null | grep -q "^Address: $2"
}

_is_blocked() {
    nslookup "$1" 127.0.0.1 2>&1 | grep -q "NXDOMAIN"
}

@test "a domain with no rule resolves through AdGuard to its upstream" {
    # The control. Without this, a suite where AdGuard was dead or answering
    # nothing would report every domain as blocked and look like a perfect
    # filter, which is the same false-green the packet-path harness guards
    # against with its baseline assertion.
    run _resolves_to allowed.example 10.99.9.9
    [ "$status" -eq 0 ]
}

@test "AdGuard blocks a domain matched by a filter rule" {
    run _is_blocked blocked.example
    [ "$status" -eq 0 ]
}

@test "an allow rule overrides a block rule" {
    # This is the mechanism behind the household's *.eth.limo exception: a
    # domain the filters block, un-blocked by a hand-written user rule. ADR
    # 0002 records that such exceptions were silently lost on reinstall, so
    # the behaviour they depend on is worth pinning down.
    run _resolves_to exception.example 10.99.9.9
    [ "$status" -eq 0 ]
}

@test "blocking is not an artefact of a dead upstream" {
    # Guards the trap that a reserved or non-existent domain returns NXDOMAIN
    # regardless of filtering. Both of these resolve upstream, so the
    # difference between them can only be AdGuard.
    run _resolves_to allowed.example 10.99.9.9
    [ "$status" -eq 0 ]
    run _is_blocked blocked.example
    [ "$status" -eq 0 ]
}
