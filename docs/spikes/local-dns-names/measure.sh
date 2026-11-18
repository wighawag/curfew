#!/bin/sh
# Measurements behind work/specs/tasked/local-dns-names-for-a-device.md.
#
# Runs INSIDE the test image (real dnsmasq 2.91, real AdGuard v0.107.78), never
# on a router. Needs the dnsq probe built from dnsq.go next to this file.
#
#   CGO_ENABLED=0 go build -o /tmp/curfew-spike/dnsq docs/spikes/local-dns-names/dnsq.go
#   CGO_ENABLED=0 go build -o /tmp/curfew-spike/aghapi docs/spikes/local-dns-names/aghapi.go
#   podman run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW \
#     -v /tmp/curfew-spike:/spike -v "$PWD":/opt/curfew localhost/docker_test \
#     sh /opt/curfew/docs/spikes/local-dns-names/measure.sh
#
# The fixture UPSTREAM answers every name under test with a SENTINEL
# (A 93.184.216.66, AAAA 2606:4700::66). So an answer carrying a sentinel is a
# question that FELL THROUGH to upstream, which is the thing the AAAA claim
# must rule out; and an answer carrying 192.168.1.122 is the local answer.
# rebind.example upstream answers a PRIVATE address, to reproduce what
# rebind protection does to today's public Cloudflare record.
set -u
Q=/spike/dnsq
ADDR=192.168.1.122

say() { printf '\n### %s\n' "$*"; }
q() { "$Q" "$@" 2>&1; }

killall AdGuardHome dnsmasq 2>/dev/null; sleep 1
ip addr add 127.0.0.8/8 dev lo 2>/dev/null

# Fixture upstream on 5454.
dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
  --address=/lan.telemaque.ska.sh/93.184.216.66 --address=/lan.telemaque.ska.sh/2606:4700::66 \
  --address=/exact.example/93.184.216.66 --address=/exact.example/2606:4700::66 \
  --address=/alt.example/93.184.216.66 --address=/alt.example/2606:4700::66 \
  --address=/rebind.example/192.168.1.122 \
  --address=/example.com/93.184.216.10

say "baseline: the fixture upstream answers with the sentinels"
q 127.0.0.1:5454 x.lan.telemaque.ska.sh A
q 127.0.0.1:5454 x.lan.telemaque.ska.sh AAAA

# ---------------------------------------------------------------- dnsmasq ----
# A router-shaped dnsmasq: rebind protection, rebind_localhost, local=/lan/,
# forwarding to the fixture. Each case restarts it with one --address form.
router_dnsmasq() {
  killall -q dnsmasq 2>/dev/null; sleep 1
  dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
    --address=/lan.telemaque.ska.sh/93.184.216.66 --address=/lan.telemaque.ska.sh/2606:4700::66 \
    --address=/exact.example/93.184.216.66 --address=/exact.example/2606:4700::66 \
    --address=/alt.example/93.184.216.66 --address=/alt.example/2606:4700::66 \
    --address=/rebind.example/192.168.1.122 --address=/example.com/93.184.216.10 --address=/pair.example/93.184.216.66 --address=/pair.example/2606:4700::66
  dnsmasq --port="${PORT:-54}" --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
    --stop-dns-rebind --rebind-localhost-ok --local=/lan/ --server=127.0.0.1#5454 \
    "$@" >/tmp/dm.log 2>&1
  echo "dnsmasq started with: $* (exit $?)"; cat /tmp/dm.log
  sleep 1
}
probe_dm() {
  for n in lan.telemaque.ska.sh breakoutbunny.lan.telemaque.ska.sh a.b.lan.telemaque.ska.sh; do
    for t in A AAAA HTTPS; do q 127.0.0.1:"${PORT:-54}" $n $t; done
  done
}

say "dnsmasq: no local record; upstream gives a PRIVATE address (today's public record after panic-off)"
router_dnsmasq
q 127.0.0.1:54 rebind.example A
q 127.0.0.1:54 example.com A

say "dnsmasq: --address=/lan.telemaque.ska.sh/$ADDR"
router_dnsmasq --address=/lan.telemaque.ska.sh/$ADDR
probe_dm

say "dnsmasq: --address=/*.lan.telemaque.ska.sh/$ADDR (dnsmasq 2.86+ wildcard)"
router_dnsmasq "--address=/*.lan.telemaque.ska.sh/$ADDR"
probe_dm

say "dnsmasq: --address=/lan.telemaque.ska.sh/$ADDR --server=/lan.telemaque.ska.sh/ (answer locally, never forward)"
router_dnsmasq --address=/lan.telemaque.ska.sh/$ADDR --server=/lan.telemaque.ska.sh/
probe_dm

say "dnsmasq: --address=/*.lan.telemaque.ska.sh/$ADDR --server=/*.lan.telemaque.ska.sh/ (wildcard, local-only)"
router_dnsmasq "--address=/*.lan.telemaque.ska.sh/$ADDR" "--server=/*.lan.telemaque.ska.sh/"
probe_dm

say "dnsmasq: --address=/*.lan.telemaque.ska.sh/$ADDR --local=/*.lan.telemaque.ska.sh/ (--local spelling)"
router_dnsmasq "--address=/*.lan.telemaque.ska.sh/$ADDR" "--local=/*.lan.telemaque.ska.sh/"
probe_dm

say "dnsmasq: --address=/lan.telemaque.ska.sh/$ADDR --address=/lan.telemaque.ska.sh/:: (what does :: mean?)"
router_dnsmasq --address=/lan.telemaque.ska.sh/$ADDR --address=/lan.telemaque.ska.sh/::
probe_dm

say "dnsmasq: one --address line naming two domains, plus local for both"
router_dnsmasq --address=/one.example/two.example/$ADDR --server=/one.example/two.example/
for n in one.example x.two.example; do for t in A AAAA; do q 127.0.0.1:54 $n $t; done; done

say "dnsmasq on port 53 (panic-off moved it back), same records"
PORT=53 router_dnsmasq "--address=/*.lan.telemaque.ska.sh/$ADDR" "--server=/*.lan.telemaque.ska.sh/"
PORT=53 probe_dm
q 127.0.0.1:53 example.com A

say "dnsmasq: --address=/rebind.example/$ADDR (a LOCAL answer to a private address, under rebind protection)"
router_dnsmasq --address=/rebind.example/$ADDR
q 127.0.0.1:54 rebind.example A
q 127.0.0.1:54 rebind.example AAAA

say "dnsmasq: --host-record=exact.example,$ADDR (exact name only)"
router_dnsmasq --host-record=exact.example,$ADDR
for n in exact.example sub.exact.example; do for t in A AAAA HTTPS; do q 127.0.0.1:54 $n $t; done; done

say "dnsmasq: --address=/exact.example/$ADDR (does it cover subdomains too?)"
router_dnsmasq --address=/exact.example/$ADDR
for n in exact.example sub.exact.example; do for t in A AAAA; do q 127.0.0.1:54 $n $t; done; done

say "dnsmasq: both --address=/*.x/ and --address=/x/ forms together, plus a more specific sibling"
router_dnsmasq "--address=/*.lan.telemaque.ska.sh/$ADDR" --address=/other.lan.telemaque.ska.sh/192.168.1.150
for n in lan.telemaque.ska.sh a.lan.telemaque.ska.sh other.lan.telemaque.ska.sh x.other.lan.telemaque.ska.sh; do q 127.0.0.1:54 $n A; done

say "dnsmasq: a name under the router's own local=/lan/ domain"
router_dnsmasq --address=/printer.lan/$ADDR
q 127.0.0.1:54 printer.lan A
q 127.0.0.1:54 nothing.lan A

say "dnsmasq --test accepts the wildcard form as a conf-file line (init script writes address= lines)"
printf 'address=/*.lan.telemaque.ska.sh/%s\n' $ADDR >/tmp/t.conf
dnsmasq --test -C /tmp/t.conf 2>&1

killall -q dnsmasq; sleep 1

# ---------------------------------------------------------------- AdGuard ----
dnsmasq --port=5454 --no-hosts --no-resolv --bind-interfaces --listen-address=127.0.0.1 \
  --address=/lan.telemaque.ska.sh/93.184.216.66 --address=/lan.telemaque.ska.sh/2606:4700::66 \
  --address=/exact.example/93.184.216.66 --address=/exact.example/2606:4700::66 \
  --address=/alt.example/93.184.216.66 --address=/alt.example/2606:4700::66 \
  --address=/example.com/93.184.216.10 --address=/pair.example/93.184.216.66 --address=/pair.example/2606:4700::66
mkdir -p /opt/AdGuardHome
cat >/opt/AdGuardHome/AdGuardHome.yaml <<'EOF'
http:
  address: 0.0.0.0:3000
  session_ttl: 720h
users:
- name: parent
  password: $2a$10$.6bIAEMTEJaj5v0.XcVKu.75uMSX5Bt9JWmgR/7rwyVfqBSPod4u6
dns:
  bind_hosts:
  - 127.0.0.1
  port: 53
  upstream_dns:
  - 127.0.0.1:5454
  bootstrap_dns:
  - 127.0.0.1:5454
  cache_size: 4194304
  serve_plain_dns: true
schema_version: 34
filters: []
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
clients:
  runtime_sources:
    whois: false
    arp: false
    rdns: false
    dhcp: false
    hosts: false
  persistent:
  - name: unfiltered-client
    ids:
    - 127.0.0.8
    use_global_settings: false
    filtering_enabled: false
    use_global_blocked_services: true
filtering:
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: nxdomain
EOF
/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome --no-check-update --verbose >/tmp/agh.log 2>&1 &
for i in $(seq 1 120); do q 127.0.0.1:53 example.com A | grep -q 93.184.216.10 && break; sleep 1; done
api() { /spike/aghapi "$@" 2>&1; }
probe_agh() { # [source]
  for n in lan.telemaque.ska.sh breakoutbunny.lan.telemaque.ska.sh a.b.lan.telemaque.ska.sh exact.example sub.exact.example; do
    for t in A AAAA HTTPS; do q 127.0.0.1:53 $n $t $1; done
  done
}

say "AdGuard: baseline, no rewrites; every name falls through to the sentinel"
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh A
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh AAAA
say "AdGuard API: rewrite list (empty), and the add/list shape"
api GET /control/rewrite/list
api POST /control/rewrite/add "{\"domain\":\"*.lan.telemaque.ska.sh\",\"answer\":\"$ADDR\"}"
api POST /control/rewrite/add "{\"domain\":\"exact.example\",\"answer\":\"$ADDR\"}"
api GET /control/rewrite/list
api POST /control/rewrite/add "{\"domain\":\"*.lan.telemaque.ska.sh\",\"answer\":\"$ADDR\"}"
echo "(the line above: adding an exact duplicate)"
api GET /control/rewrite/list
sleep 1

say "AdGuard: rewrites *.lan.telemaque.ska.sh and exact.example -> $ADDR (filtered client 127.0.0.1)"
probe_agh 127.0.0.1

say "AdGuard: same, from a client with filtering_enabled=false (127.0.0.8)"
probe_agh 127.0.0.8

say "AdGuard: protection DISABLED globally"
api POST /control/protection '{"enabled":false}'
sleep 1
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh A
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh AAAA
api POST /control/protection '{"enabled":true}'

say "AdGuard: filtering DISABLED globally (filtering/config enabled=false)"
api POST /control/filtering/config '{"enabled":false,"interval":24}'
sleep 1
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh A
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh AAAA
api POST /control/filtering/config '{"enabled":true,"interval":24}'

say "AdGuard: rewrite with enabled=false (newer API field), and the settings endpoint"
api POST /control/rewrite/add "{\"domain\":\"off.example\",\"answer\":\"$ADDR\",\"enabled\":false}"
api GET /control/rewrite/list
api GET /control/rewrite/settings

say "AdGuard: delete by exact (domain, answer); a wrong answer deletes nothing"
api POST /control/rewrite/delete "{\"domain\":\"exact.example\",\"answer\":\"10.0.0.1\"}"
api GET /control/rewrite/list
api POST /control/rewrite/delete "{\"domain\":\"exact.example\",\"answer\":\"$ADDR\"}"
api GET /control/rewrite/list
q 127.0.0.1:53 exact.example A

say "AdGuard: deleting a DUPLICATED rewrite once: does it remove one or both?"
api POST /control/rewrite/delete "{\"domain\":\"*.lan.telemaque.ska.sh\",\"answer\":\"$ADDR\"}"
api GET /control/rewrite/list
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh A

say "AdGuard: the pair 'x' + '*.x' (how curfew would render a bare name)"
api POST /control/rewrite/add "{\"domain\":\"pair.example\",\"answer\":\"$ADDR\"}"
api POST /control/rewrite/add "{\"domain\":\"*.pair.example\",\"answer\":\"$ADDR\"}"
for n in pair.example a.pair.example a.b.pair.example; do for t in A AAAA; do q 127.0.0.1:53 $n $t; done; done

say "AdGuard: update (domain, answer) in place, as a set-ip move would"
api PUT /control/rewrite/update "{\"target\":{\"domain\":\"pair.example\",\"answer\":\"$ADDR\"},\"update\":{\"domain\":\"pair.example\",\"answer\":\"192.168.1.150\",\"enabled\":true}}"
api GET /control/rewrite/list
q 127.0.0.1:53 pair.example A

say "AdGuard: an exact rewrite nested under another wildcard: which wins?"
api POST /control/rewrite/add "{\"domain\":\"*.nest.example\",\"answer\":\"$ADDR\"}"
api POST /control/rewrite/add "{\"domain\":\"nas.nest.example\",\"answer\":\"192.168.1.150\"}"
api POST /control/rewrite/add "{\"domain\":\"*.deep.nest.example\",\"answer\":\"192.168.1.151\"}"
for n in a.nest.example nas.nest.example x.nas.nest.example x.deep.nest.example; do q 127.0.0.1:53 $n A; done

say "AdGuard: does a rewrite write touch the filtering engine? (log lines mentioning filters, before/after)"
grep -ci "filter" /tmp/agh.log
api POST /control/rewrite/add "{\"domain\":\"engine.example\",\"answer\":\"$ADDR\"}"
sleep 1
grep -ci "filter" /tmp/agh.log
tail -3 /tmp/agh.log

say "AdGuard: \$dnsrewrite in a filter rule (the considered alternative), A only"
api POST /control/filtering/set_rules "{\"rules\":[\"||alt.example^\$dnsrewrite=NOERROR;A;$ADDR\"]}"
sleep 1
for n in alt.example sub.alt.example; do for t in A AAAA HTTPS; do q 127.0.0.1:53 $n $t 127.0.0.1; done; done
q 127.0.0.1:53 alt.example A 127.0.0.8
echo "(the line above: from the filtering_enabled=false client)"

say "AdGuard: AAAA with an explicit empty-AAAA rewrite? (answer '::'?)"
api POST /control/rewrite/add "{\"domain\":\"*.lan.telemaque.ska.sh\",\"answer\":\"AAAA\"}"
api GET /control/rewrite/list
q 127.0.0.1:53 breakoutbunny.lan.telemaque.ska.sh AAAA

killall AdGuardHome dnsmasq 2>/dev/null
echo; echo "AdGuard log tail:"; tail -5 /tmp/agh.log
