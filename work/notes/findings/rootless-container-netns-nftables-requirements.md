---
title: Running a netns + nftables packet-path harness in a rootless container
slug: rootless-container-netns-nftables-requirements
source: 'measured side by side with podman 5.4.2 and docker 29.5.2, both rootless, on Debian, 2026-08-06'
---

Requirements for building a real LAN-to-WAN topology inside a container and asserting on the packet path, established by trial rather than documentation.

## Capabilities and sysctl

- `--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW` is sufficient. **`--privileged` is not required**, which matters because it keeps the harness viable in CI.
- **`--sysctl net.ipv4.ip_forward=1` must be passed at container start.** Setting it from inside the container fails with "Read-only file system" on `/proc/sys` in rootless mode. This is the single most dangerous omission: without forwarding, the topology never routes, so *every* probe reads unreachable, including the baseline, and a firewall test suite that does not assert its own baseline will report a perfect pass while testing nothing.

## Tooling inside the container

- `ip netns exec` fails with "mount of /sys failed: Operation not permitted" because it tries to remount sysfs. Use **`nsenter --net=/var/run/netns/<ns>`** instead, which needs no mount privileges.
- BusyBox's `ip` applet is **not sufficient**: it has no `link add` and no `netns` subcommand. Real `iproute2` must be installed.
- BusyBox `httpd` is provided by `busybox-extras` as a separate `/usr/sbin/httpd` binary, not as an applet of `/bin/busybox`, so `busybox httpd` fails while `/usr/sbin/httpd` works.
- Set an explicit `PATH` covering `/usr/sbin`. A harness that silently loses `nft` from `PATH` produces confident, completely wrong results when the scripts under test swallow errors with `2>/dev/null`.

## podman and docker are interchangeable here

Verified side by side with an identical probe, both rootless:

| | podman 5.4.2 | docker 29.5.2 |
|---|---|---|
| baseline reachability | REACHED | REACHED |
| after an nftables MAC drop rule | UNREACHABLE | UNREACHABLE |
| `ether_addr` timeout set readout | `expires 4m56s996ms` | `expires 4m56s992ms` |

podman additionally delegates `podman compose` to the docker-compose plugin when one is present, so a single compose file serves both engines and the choice is a preference rather than a constraint.

## Running this harness on a real OpenWrt image (verified recipe)

The requirements above were established on Alpine. Reproducing them on `openwrt/rootfs:x86-64-25.12.4` needs the extra steps below, each found by hitting the failure rather than by inspection. Verified working end to end: a 6-test bats suite covering real `nft`, an `ether_addr` timeout set, real `uci`/`logger`, netns plus veth plus bridge via `nsenter`, the sysctl, and the presence of the real `uhttpd` binary.

- **Package names differ.** `apk add bash ip-full jq coreutils-nl nsenter`. `iproute2` is called **`ip-full`** on OpenWrt. `bash` is needed because bats is a bash program and OpenWrt ships only ash.
- **`bats` is NOT packaged for OpenWrt** (`apk search bats` returns nothing, against 11269 available packages). Vendor `bats-core` from its release tarball and run it from the extracted tree. Its own `install.sh` FAILS with `install: command not found`, because OpenWrt has no coreutils `install`.
- **`coreutils-nl` is required.** bats calls `nl`, which busybox does not provide; without it bats reports `Executed 0 instead of expected N tests` while appearing to run.
- **`coreutils-cksum` is required** if any test uses `cksum`, which busybox also lacks. Found by running a real suite, not by inspection: the failure is a plain `cksum: command not found` inside the test.
- **`mkdir -p /var/run` before any `ip netns` call.** On OpenWrt `/var/run` is a symlink to `/tmp/run`, which procd creates at boot, so in a container it does not exist and `ip netns add` fails.
- **`ip netns exec` fails here too** (`mount of /sys failed: Operation not permitted`), exactly as on Alpine, so `nsenter --net=/var/run/netns/<ns>` remains the required primitive. `nsenter` IS packaged.
- **Do not combine `--network host` with `--sysctl net.ipv4.ip_forward=1`**: the runtime refuses to set a host-namespace sysctl. The default bridge network provides both outbound access and a private netns.
- **`podman compose` DOES honour the compose `sysctls:` key**, verified directly on podman 5.4.2 delegating to the docker-compose plugin (a service declaring `sysctls: {net.ipv4.ip_forward: "1"}` reads back `1` from `/proc/sys` inside the container). So a compose-driven gate can carry the requirement and no raw `podman run` fallback is needed. Worth recording because the rest of this note was established with `podman run` CLI flags and the two paths are not automatically equivalent; worth re-checking on a machine whose `podman compose` resolves to a different backend. This is not OpenWrt-specific, it is a compose-versus-CLI fact.
- **`CAP_SYS_ADMIN` is required for `ip netns add`, not just `CAP_NET_ADMIN`.** Measured: with `--cap-add NET_ADMIN` alone, `ip netns add` fails at `mount --make-shared /var/run/netns: Operation not permitted`; adding `SYS_ADMIN` succeeds. Easy to miss if every probe you run happens to pass all three capabilities, because then you never see the boundary.

## A measured baseline for the existing suite

Running the repo's 104-test suite on `openwrt/rootfs:x86-64-25.12.4` with the packages above (before `coreutils-cksum` was added) and no mocks at all:

```
ok:     102
not ok: 2
  not ok 49 block works with iptables backend     <- needs the Alpine-only mock iptables
  not ok 71 filter IDs are unique integers        <- cksum: command not found
```

Both causes are understood: the first is removed deliberately along with the dead iptables backend, the second is closed by installing `coreutils-cksum`. Recorded here so that a later run producing a different number has something concrete to reconcile against, rather than a bare expectation.

## Real OpenWrt images are available for testing

`openwrt/rootfs` publishes images matching router releases, including `x86-64-25.12.4`, `x86-64-25.12-SNAPSHOT` and the 24.10 line. A pulled image provides real busybox ash, `uci`, `ubus`, `procd`, `crontab`, the real `nft` build and real `uhttpd`, which removes the need to mock `uci` and `logger` or to substitute busybox httpd for uhttpd. The architecture difference from an aarch64 router is irrelevant for nftables semantics, shell behaviour and HTTP; it matters only for testing a compiled binary.
