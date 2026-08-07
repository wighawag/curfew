#!/bin/sh
# Host-side acceptance runner.
#
# The Go packet-path tests need a real OpenWrt userland and a real kernel
# (docs/adr/0005), but that image has no Go toolchain. So the test binaries are
# compiled HERE, statically, and executed in there. That keeps the assertions
# in Go next to the code they test while still running them against the target.
set -eu
cd "$(dirname "$0")/.."

mkdir -p .acceptance
rm -f .acceptance/*.test .acceptance/curfew-daemon

# Every package with packet-path or userland-dependent tests goes here.
# internal/enforce proves the ordering contract on packets; internal/policy
# proves what survives a reboot, which needs real files, a fresh process and
# the kernel together.
CGO_ENABLED=0 go test -c -o .acceptance/enforce.test ./internal/enforce
CGO_ENABLED=0 go test -c -o .acceptance/policy.test ./internal/policy

# The daemon's own boot path is tested by RUNNING the daemon, so the binary
# ships alongside its test. Nothing else covers that startup order, and it is
# where the system this replaces failed: it came up and enforced nothing.
CGO_ENABLED=0 go test -c -o .acceptance/daemon.test ./cmd/curfew-daemon
CGO_ENABLED=0 go build -o .acceptance/curfew-daemon ./cmd/curfew-daemon

exec podman compose -f docker/docker-compose.yml run --build --rm test
