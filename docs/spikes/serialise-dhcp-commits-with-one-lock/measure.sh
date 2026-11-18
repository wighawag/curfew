#!/bin/sh
# Measurements behind work/tasks/*/serialise-dhcp-commits-with-one-lock.md.
# Runs INSIDE the test image (OpenWrt 25.12.4 userland), never on a router.
#
#   CGO_ENABLED=0 go build -o /tmp/curfew-spike/goflock docs/spikes/serialise-dhcp-commits-with-one-lock/goflock.go
#   podman run --rm -v /tmp/curfew-spike:/spike -v "$PWD":/opt/curfew localhost/docker_test \
#     sh /opt/curfew/docs/spikes/serialise-dhcp-commits-with-one-lock/measure.sh
set -u
say() { printf '\n### %s\n' "$*"; }
has() { uci -q get "dhcp.lan.$1" >/dev/null && echo "$1 IN /etc/config/dhcp" || echo "$1 absent"; }
committed() { grep -q "option $1 " /etc/config/dhcp && echo "$1 COMMITTED" || echo "$1 not committed"; }

say "1. Is the default staging area shared between processes?"
sh -c "uci set dhcp.lan.curfewa=1"                          # process A stages, exits
sh -c "uci set dhcp.lan.curfewb=1; uci commit dhcp"          # process B commits its own
committed curfewa; committed curfewb
ls -la /tmp/.uci 2>&1

say "2. A private save path (-t): invisible to a default commit, committed by its own?"
sh -c "uci -t /tmp/.uci-curfew set dhcp.lan.curfewc=1"
sh -c "uci commit dhcp"
committed curfewc
echo "default show sees it?  $(uci -q get dhcp.lan.curfewc || echo no)"
echo "-t show sees it?       $(uci -t /tmp/.uci-curfew -q get dhcp.lan.curfewc || echo no)"
echo "-P show sees it?       $(uci -P /tmp/.uci-curfew -q get dhcp.lan.curfewc || echo no)"
sh -c "uci set dhcp.lan.curfewd=1"                           # someone else stages in default
sh -c "uci -t /tmp/.uci-curfew commit dhcp"
committed curfewc; committed curfewd
uci revert dhcp 2>/dev/null; uci commit dhcp

say "2b. -P (search + save path): does its commit sweep up default-staged changes?"
sh -c "uci set dhcp.lan.curfewe=1"
sh -c "uci -P /tmp/.uci-curfew2 set dhcp.lan.curfewf=1"
echo "staged files: $(ls /tmp/.uci-curfew2 2>&1) | default: $(cat /tmp/.uci/dhcp 2>&1)"
sh -c "uci -P /tmp/.uci-curfew2 commit dhcp; echo commit exit \$?"
committed curfewe; committed curfewf
echo "after: private: $(cat /tmp/.uci-curfew2/dhcp 2>&1) | default: $(cat /tmp/.uci/dhcp 2>&1)"
uci revert dhcp 2>/dev/null; uci commit dhcp

say "3. Does uci serialise concurrent commits? Two writers, private save paths, 60 commits each"
w() { i=0; while [ $i -lt 60 ]; do uci -t /tmp/.uci-$1 set dhcp.lan.$1$i=1; uci -t /tmp/.uci-$1 commit dhcp; i=$((i+1)); done; }
w wa & w wb & wait
echo "wa options kept: $(grep -c 'option wa' /etc/config/dhcp) of 60"
echo "wb options kept: $(grep -c 'option wb' /etc/config/dhcp) of 60"

say "4. flock(1), lock(1) and Go flock(2) on one file"
mkdir -p /var/lock; L=/var/lock/curfew-dhcp-test
/spike/goflock $L hold 3 & sleep 1
flock -n $L true && echo "flock(1) -n while Go holds: ACQUIRED" || echo "flock(1) -n while Go holds: BUSY"
lock -n $L && echo "lock(1) -n while Go holds: ACQUIRED" || echo "lock(1) -n while Go holds: BUSY"
wait
flock $L sleep 3 & sleep 1
/spike/goflock $L try
wait
sh -c "lock $L"; echo "lock(1) caller exited"
/spike/goflock $L try
echo "after the caller of lock(1) exited, the lock is still held by: $(ps w | grep '[l]ock ' | head -2)"
lock -u $L; sleep 1
/spike/goflock $L try

say "4b. A Go flock dies with its process"
/spike/goflock $L hold 30 & P=$!; sleep 1; kill $P; sleep 1
/spike/goflock $L try
