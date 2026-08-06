---
title: OpenWrt nftables supports JSON output and ether_addr timeout sets
slug: openwrt-nftables-json-and-ether-timeout-sets
source: 'measured in openwrt/rootfs:x86-64-25.12.4 (nftables v1.1.6), 2026-08-06. The dependency reasoning comes from the firewall4 and nftables Makefiles on openwrt/openwrt MAIN, retrieved 2026-08-06, which is a different branch from the 25.12.4 image tested; the live measurement is what carries the conclusion, the Makefiles only explain it.'
---

## `nft -j` IS available on a stock fw4 router

Reasoning from the nftables Makefile alone gives the wrong answer. It defines two variants and marks `nftables-nojson` as `DEFAULT_VARIANT:=1`, which reads as "no JSON on a stock image". But `firewall4` declares `DEPENDS:= ... +nftables-json ...`, and fw4 is in the default image, so the JSON variant is pulled in and displaces the nojson default on any router running fw4.

Measured on a real 25.12.4 rootfs:

```
nftables v1.1.6 (Commodore Bullmoose #7)
$ nft -j list set inet t s
{"nftables": [{"metainfo": {...}}, {"set": {..., "type": "ether_addr", "flags": ["timeout"],
  "elem": [{"elem": {"val": "aa:bb:cc:dd:ee:01", "timeout": 900, "expires": 899}}]}}]}
```

Caveat on usefulness: there is no `jq` on the router, so a shell implementation still hand-parses either way, and the text output is no harder to parse than the JSON. JSON availability matters mainly if the logic moves to a language with a JSON decoder.

## `ether_addr` sets with `flags timeout` work, and the kernel reclaims them

```
$ nft add set inet t s '{ type ether_addr; flags timeout; }'
$ nft add element inet t s '{ aa:bb:cc:dd:ee:01 timeout 15m }'
$ nft list set inet t s
  elements = { aa:bb:cc:dd:ee:01 timeout 15m expires 14m59s996ms }
```

An element added with a 3s timeout was confirmed present immediately and gone after 5s (`nft get element` fails with "No such file or directory"). The remaining time is readable from the `expires` field in both text and JSON.

This is the mechanism that lets ticket and guest expiry be kernel-managed rather than depending on a background `sleep` surviving, and it means a countdown shown in a UI can be the kernel's own number rather than a separately-tracked one that can drift.

Also verified on the same image: `flags timeout` is accepted on a set whose elements may also be added *without* a timeout, so one set can hold both permanent and expiring members.
