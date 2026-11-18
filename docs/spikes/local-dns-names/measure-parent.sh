#!/bin/sh
# Does a household entry for a PARENT domain beat curfew's *.x records in
# dnsmasq 2.91? Same rig as measure.sh: a sentinel upstream on 5454.
#   podman run --rm -v /tmp/curfew-spike:/spike -v "$PWD":/opt/curfew localhost/docker_test \
#     sh /opt/curfew/docs/spikes/local-dns-names/measure-parent.sh
Q=/spike/dnsq
q() { "$Q" "$@" 2>&1; }
say() { printf '\n### %s\n' "$*"; }
dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
  --address=/telemaque.ska.sh/93.184.216.66 --address=/telemaque.ska.sh/2606:4700::66 \
  --address=/other.example/93.184.216.77
sleep 1
run() {
  killall -q dnsmasq; sleep 1
  dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
    --address=/telemaque.ska.sh/93.184.216.66 --address=/telemaque.ska.sh/2606:4700::66 \
    --address=/other.example/93.184.216.77
  dnsmasq --port=54 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
    --stop-dns-rebind --server=127.0.0.1#5454 \
    "--address=/*.lan.telemaque.ska.sh/192.168.1.122" "--server=/*.lan.telemaque.ska.sh/" "$@"
  sleep 1
  for t in A AAAA; do q 127.0.0.1:54 breakoutbunny.lan.telemaque.ska.sh $t; done
}
say "curfew's records alone (control)"; run
say "plus a household address=/lan.telemaque.ska.sh/10.1.1.1 (bare parent, 1 level up)"; run --address=/lan.telemaque.ska.sh/10.1.1.1
say "plus a household address=/telemaque.ska.sh/10.1.1.1 (bare grandparent)"; run --address=/telemaque.ska.sh/10.1.1.1
say "plus a household server=/lan.telemaque.ska.sh/127.0.0.1#5454 (bare parent, forward)"; run "--server=/lan.telemaque.ska.sh/127.0.0.1#5454"
say "plus a household address=/*.telemaque.ska.sh/10.1.1.1 (wildcard grandparent)"; run "--address=/*.telemaque.ska.sh/10.1.1.1"
say "plus a household address=/breakoutbunny.lan.telemaque.ska.sh/10.1.1.2 (more specific child)"; run --address=/breakoutbunny.lan.telemaque.ska.sh/10.1.1.2
killall -q dnsmasq
