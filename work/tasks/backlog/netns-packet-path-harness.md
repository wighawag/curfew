---
title: Network-namespace harness that asserts on the packet path
slug: netns-packet-path-harness
spec: openwrt-packet-path-test-harness
blockedBy: [openwrt-test-image]
covers: [1, 2, 3, 6, 7]
---

## What to build

A reusable test harness that builds a real network topology inside the test container and lets a test ask the only question that matters about a firewall: **did the packet get through?**

Today every one of the 104 tests inspects nftables set membership or rule presence, and none sends a packet. That blind spot is not theoretical: replaying the production boot order showed the block command reporting success, writing `blocked` to its state file, logging "Profile blocked", and leaving the child with working internet, while the suite stayed green.

**The topology.** A `br-lan` bridge in the container's own namespace holding the router address; a `client` namespace attached by veth whose MAC is settable per test; an `internet` namespace reached through a veth pair whose **router-side (container-side) end is named `pppoe-wan`**, serving a known page over HTTP. The container is the router between them.

The router-side end is the one that must carry the name: `oifname` matches the interface the router sends OUT of, so naming the peer inside the `internet` namespace instead leaves the rules matching nothing and the assertions failing for a reason this task told you not to expect.

**Addressing plan**, fixed here so it is not invented: LAN `10.99.1.0/24` with the router at `10.99.1.1` and the client at `10.99.1.2`; WAN `10.99.2.0/24` with the router at `10.99.2.1` and the internet host at `10.99.2.2`, serving on port 80. Namespaces `client` and `internet`. This range is deliberate: rootless podman defaults to `10.88.0.0/16` and docker to `172.17.0.0/16` (both verified), so `10.99` collides with neither. A collision here would break the topology in a way that reads exactly like a working firewall, which is the failure this whole spec exists to prevent.

**Server and client.** Use what the image already provides rather than adding packages: `/usr/sbin/uhttpd` serves the page and `/usr/bin/wget` fetches it. Note `wget` here is **uclient-fetch**, not busybox wget and not GNU wget: it supports `-q`, `-O <file>` and `--timeout=N | -T N`. Bounding the probe is mandatory, not optional, because a packet meeting a DROP rule makes the fetch hang rather than fail (confirmed the hard way), and there is no `timeout` applet on this image to wrap it with. So a probe is roughly `nsenter --net=/var/run/netns/client wget -q -T 3 -O /dev/null http://10.99.2.2/`, treating a non-zero exit as unreachable.

**Server lifecycle**, all of which needs handling rather than assuming: start `uhttpd -f` inside the `internet` namespace against a docroot holding a known page, capture its pid, wait for readiness before the baseline probe rather than racing it, kill it in teardown, and make teardown idempotent so a mid-test failure does not strand namespaces, the bridge or a stale server that then collides with the next run.

**Changing the client MAC needs more than setting the address.** Take the link down, set the address, bring it up, and then flush neighbour entries on BOTH sides (the router's `br-lan` and inside the client namespace). Without the flush a stale ARP entry sends return traffic to a MAC that no longer exists, and the symptom is that assertion 3 reads UNREACHABLE. That is worth stating because the task warns you elsewhere that a red assertion 2 means the harness is wrong; a red assertion 3 most likely means this.

Constrained by `docs/adr/0004-tests-assert-on-the-packet-path.md`, which records why enforcement claims are proven with packets rather than ruleset text, and why the baseline assertion is mandatory rather than redundant.

**The harness MUST set `PARENTAL_WAN_IF=pppoe-wan` and `PARENTAL_LAN_IF=br-lan`.** Naming the veth is not sufficient, and this is the single most important detail in the task. No script matches the literal name `pppoe-wan`: both the allowlist script and the profiles script resolve the WAN interface from `PARENTAL_WAN_IF`, falling back to `uci get network.wan.device` and then to a literal `eth1`, and the existing suite pins `PARENTAL_WAN_IF=eth1`. Without the levers the generated rules match `oifname "eth1"` against a veth called `pppoe-wan` and every assertion fails. Do not "fix" that by renaming the veth to `eth1`: the production interface name is what makes these tests represent the real router.

Both scripts also override that lever from `ifstatus wan` when it returns a non-empty L3 device. On this image `ifstatus` exists but ubus is not running, so it returns nothing and the override does not fire. This was confirmed by running the suite; know it so you are not surprised by it.

**The API**, as a loadable test helper: `netns_setup`, `netns_client_mac <mac>`, `netns_probe` returning reachable/unreachable, `netns_teardown`.

**The preflight must test CAPABILITY, not presence**, and this distinction is the whole point of it. Checking that `ip` exists PASSES on this image even when `ip-full` was never installed, because busybox provides `/sbin/ip`; what is missing is `ip netns` support. A presence check therefore reproduces the exact silent-false-result failure the preflight exists to prevent. Check that each tool can DO the thing: `ip netns list` succeeds, `nft --version` succeeds, `nsenter --version` succeeds, the server binary is executable, and the fetch client runs. The server and client belong in the list because a dead server is indistinguishable from a perfectly blocking firewall except via the baseline assertion.

**`netns_setup` must start from a clean firewall.** The `parental_control` table can survive from an earlier test file (one existing bats file has an empty `teardown`), and a leftover table makes the baseline ambiguous. Delete or flush it in setup so assertion 1 means what it claims.

**Container capabilities are delivered by the blocking task**, not by this one: `SYS_ADMIN`, `NET_RAW` and `sysctls: net.ipv4.ip_forward=1` are already in the compose file when you start. Do not re-add them. Understand why they matter, though, because the failure mode is silent: `SYS_ADMIN` is what lets `ip netns add` work at all, and the sysctl is what makes the topology forward. Without the sysctl nothing forwards, so every probe reads unreachable INCLUDING the baseline, which looks exactly like a perfectly working firewall. That is why the baseline assertion below is mandatory rather than redundant.

**Preflight `mkdir -p /var/run` in the harness too.** The image creates it at build time, but `/var` is a symlink to `/tmp` on OpenWrt, so any runtime that mounts a fresh tmpfs over `/tmp` erases it and `ip netns add` fails with the image still perfectly correct.

**Use `nsenter --net=/var/run/netns/<ns>`, never `ip netns exec`**, which fails with `mount of /sys failed: Operation not permitted` on this image.

**The four assertions**, all satisfiable against unmodified scripts:

1. Baseline: with no firewall rules, the client reaches the internet.
2. An unknown MAC (in no profile) is unreachable once the allowlist is applied.
3. An allowlisted MAC is reachable once the allowlist is applied.
4. Preflight: when a required tool cannot do its job, the harness FAILS rather than reporting a pass. Exercise this by prepending a directory to `PATH` containing a stub that shadows one of the tools and exits non-zero, then asserting the preflight fails. Do it this way deliberately: an earlier draft asked for "a tool removed from `PATH`", which cannot work, because the harness also pins an explicit `PATH` covering `/usr/sbin` and invokes the server by absolute path, so removal is unreachable and the assertion would be theatre. Shadowing tests the real capability check.

Why 2 and 3 work against unmodified scripts, so you do not have to re-derive it when one of them reads red: `apply` installs exactly two rules, an allowlist `accept` and then a terminal `drop`, both narrowed by `iifname`/`oifname`. An allowlisted MAC hits the accept; an unknown MAC falls to the drop; and return traffic from the internet side matches neither rule, so it falls through to the chain's `accept` policy and the HTTP response completes.

Assertion 2 is deliberately the one enforcement claim currently believed true. If it fails, the harness is wrong, not the firewall. Assertion 1 is what stops a dead topology from masquerading as a working firewall.

## Acceptance criteria

- [ ] The gate passes: `podman compose -f docker/docker-compose.yml run --build --rm test`
- [ ] All four assertions above pass, and every test that passed before this task still passes. Stated relatively on purpose: a sibling backlog task may remove tests independently, so an absolute count would bounce this task for someone else's landing
- [ ] The harness sets `PARENTAL_WAN_IF=pppoe-wan` and `PARENTAL_LAN_IF=br-lan`, and the internet-side interface really is named `pppoe-wan`
- [ ] Acceptance is the real gate command, never a hand-rolled `podman run`. The capabilities it depends on arrive from the blocking task; this task must not add or duplicate them
- [ ] `--privileged` is NOT used
- [ ] The preflight fails loudly on a missing tool, demonstrated by assertion 4 rather than asserted in prose
- [ ] The harness API is reusable: a test can set a client MAC and probe reachability without rebuilding the topology itself
- [ ] **Shared-write isolation, stated as a mechanism:** the compose file bind-mounts the repository read-write into the container, so the harness must write its served page, fixtures and namespace state only under `BATS_TMPDIR` or `/tmp`. Prove it with a `find`-based before/after snapshot of the mounted repository path, excluding `.git`, asserting no file is added or removed. Use `find` rather than `git status` because git is NOT installed in the image. Note the compose command's own `chmod +x` modifies existing files without adding any, so a snapshot keyed on added/removed paths is the right comparison

## Blocked by

- `openwrt-test-image` — the harness needs `ip-full`, `nsenter` and the `/var/run` fix that task delivers, and its assertions run on that image.

## Prompt

> Build a network-namespace test harness for this OpenWrt parental-control repo, so tests can assert on the packet path instead of on nftables ruleset text.
>
> Why this exists: the existing 104-test suite asserts set membership and rule presence, and it stayed green while the firewall enforced nothing at all after a reboot. Ruleset text looked correct; packets flowed anyway. A test that sends a real packet from a chosen source MAC is the only assertion that would have caught it.
>
> The full topology, the required environment levers, the container capabilities and the four assertions are in the What-to-build section above. Read `work/notes/findings/rootless-container-netns-nftables-requirements.md` first: it carries the verified recipe, including why `nsenter` rather than `ip netns exec`, why `mkdir -p /var/run` is needed, and why the ip_forward sysctl must be set at container start.
>
> The trap to internalise: if the sysctl is missing, the topology never forwards and EVERY probe reads unreachable, including the baseline. A firewall test suite that does not assert its own baseline will report a perfect pass while testing nothing. Assertion 1 exists for that reason and must not be dropped as redundant.
>
> The second trap: naming the internet-side veth `pppoe-wan` does not make the scripts match it. They resolve `PARENTAL_WAN_IF`. Set the levers.
>
> Where to look: the container definition and compose file live in the docker directory; test helpers live under the test directory. `docs/architecture.md` explains the enforcement layers and the env-override pattern the harness should follow.
>
> Do NOT change any script under `scripts/` or any enforcement behaviour. This task delivers a testbed and assertions that pass against the code exactly as it is today. A later spec changes enforcement and will write the failing tests; if you find yourself needing to modify a script to make an assertion pass, stop, because that means the assertion is out of scope for this task.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does the blocking task's image match what is described, and do the scripts still resolve the WAN interface the way stated? If not, route to needs-attention with the discrepancy rather than building on a stale premise.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record: the harness API shape and how a test declares its topology are choices a later spec will build on heavily.
