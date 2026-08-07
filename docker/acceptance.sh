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
rm -f .acceptance/*.test

# Every package with packet-path or userland-dependent tests goes here.
CGO_ENABLED=0 go test -c -o .acceptance/enforce.test ./internal/enforce

exec podman compose -f docker/docker-compose.yml run --build --rm test
