#!/usr/bin/env bats
# Packet-path assertions against UNMODIFIED enforcement scripts.
#
# These do not test new behaviour: they establish that the harness can observe
# enforcement at all, by proving the one claim currently believed true (the
# unknown-device allowlist). If assertion "unknown MAC is blocked" ever fails,
# suspect the harness before the firewall.

load "${BATS_TEST_DIRNAME}/test_helper/netns"

SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
FIREWALL="$SCRIPT_DIR/scripts/setup-firewall.sh"

ALLOWED_MAC="aa:bb:cc:dd:ee:01"
UNKNOWN_MAC="aa:bb:cc:dd:ee:99"

setup() {
    export PARENTAL_CONFIG="${BATS_TMPDIR}/harness_profiles"
    cat > "$PARENTAL_CONFIG" << EOF
alice|120|$ALLOWED_MAC
EOF
    netns_setup
}

teardown() {
    netns_teardown
}

@test "baseline: with no firewall rules the client reaches the internet" {
    # Mandatory, not redundant. Any topology failure (a dead server, a missing
    # route, forwarding disabled) makes every probe read unreachable, which is
    # indistinguishable from a perfectly blocking firewall. Without this
    # assertion the suite would report a flawless pass while testing nothing.
    # This is the assertion that makes the other two mean something.
    netns_client_mac "$ALLOWED_MAC"
    run netns_probe
    [ "$status" -eq 0 ]
}

@test "an allowlisted MAC reaches the internet once the allowlist is applied" {
    netns_client_mac "$ALLOWED_MAC"
    sh "$FIREWALL" apply >/dev/null 2>&1
    run netns_probe
    [ "$status" -eq 0 ]
}

@test "an unknown MAC is blocked once the allowlist is applied" {
    netns_client_mac "$UNKNOWN_MAC"
    sh "$FIREWALL" apply >/dev/null 2>&1
    run netns_probe
    [ "$status" -ne 0 ]
}

@test "preflight fails when a required tool cannot do its job" {
    # Shadow nft with a stub that exits non-zero. This works because the
    # harness APPENDS to PATH rather than replacing it; a replacing pin would
    # wipe the stub and make this assertion theatre.
    local stubdir="${BATS_TMPDIR}/stub"
    mkdir -p "$stubdir"
    printf '#!/bin/sh\nexit 1\n' > "$stubdir/nft"
    chmod +x "$stubdir/nft"

    PATH="$stubdir:$PATH" run netns_preflight
    [ "$status" -ne 0 ]

    # And it passes without the stub, so the assertion above means something.
    run netns_preflight
    [ "$status" -eq 0 ]
}

@test "teardown leaves no server running" {
    # A leaked server does NOT fail a test. It keeps the output pipe open, so
    # bats never sees EOF and the whole suite hangs AFTER the last test passes,
    # which looks like a green run that never ends. That happened: five stray
    # servers accumulated, one per test, because the server was started with
    # -f (do NOT fork) in the background and the cleanup used pkill, which does
    # not exist on this image and failed silently under `|| true`.
    [ "$(netns_server_count)" -ge 1 ]
    netns_teardown
    [ "$(netns_server_count)" -eq 0 ]
}

@test "the harness writes nothing into the mounted repository" {
    # The compose file bind-mounts the repo read-write, so a harness that
    # wrote fixtures under it would dirty the host worktree. Neither git nor
    # diff is installed in this image, so snapshot with find and compare the
    # strings directly rather than reaching for a tool that is not there.
    local before after
    before=$(find /opt/my-router -path /opt/my-router/.git -prune -o -print | sort)
    netns_client_mac "$ALLOWED_MAC"
    netns_probe || true
    after=$(find /opt/my-router -path /opt/my-router/.git -prune -o -print | sort)
    [ "$before" = "$after" ]
}
