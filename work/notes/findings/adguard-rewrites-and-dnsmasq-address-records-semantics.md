---
title: What an AdGuard DNS rewrite and a dnsmasq address record each answer, and what they let through
slug: adguard-rewrites-and-dnsmasq-address-records-semantics
source: 'measured 2026-11-18 in the test image (openwrt/rootfs x86-64-25.12.4: dnsmasq 2.91, AdGuard Home v0.107.78), against an offline fixture upstream that answers every name under test with a sentinel (A 93.184.216.66, AAAA 2606:4700::66), so a forwarded question is visible as a sentinel. Script, probes and full output: docs/spikes/local-dns-names/ (measure.sh, dnsq.go, aghapi.go, measured-2026-11-18.txt). Live router facts read-only over ssh the same day. OpenWrt init-script behaviour read from /etc/init.d/dnsmasq in that image.'
---

# AdGuard DNS rewrites and dnsmasq address records: what each covers, and what falls through

Ground truth for `work/specs/tasked/local-dns-names-for-a-device.md`. "Falls through" means the question was forwarded upstream and the sentinel came back; "NODATA" means NOERROR with zero answers and nothing forwarded.

## AdGuard Home v0.107.78 rewrites (`/control/rewrite/*`)

| Rewrite (answer 192.168.1.122) | `x` | `a.x` | `a.b.x` |
|---|---|---|---|
| `*.x` | falls through | answered | answered |
| `x` | answered | falls through | (not tested) |
| `x` and `*.x` together | answered | answered | answered |

- **A-only rewrite, AAAA and HTTPS questions: NODATA, never forwarded.** For a covered name, AAAA and HTTPS (type 65) both returned NOERROR with no answers while the upstream would have given the AAAA sentinel. No extra rewrite is needed to suppress AAAA.
- **The special answer `AAAA` means the opposite**: a rewrite `*.x -> AAAA` made AAAA questions fall through to upstream. Never write it.
- **A client with `filtering_enabled: false` gets NO rewrites**: every name fell through to the sentinel. Same with filtering disabled globally (`/control/filtering/config enabled=false`). **Protection disabled** (`/control/protection enabled=false`) does NOT stop rewrites: they still answered.
- Rewrites also have a global switch, `GET /control/rewrite/settings` -> `{"enabled":true}` (`rewrites_enabled` in the yaml).
- Object shape is exactly `{"domain","answer","enabled"}`: **no name, comment or owner field**, so an object cannot carry an ownership marker.
- `add` of an exact duplicate returns 200 and **creates a second identical object**. `delete` by `{domain, answer}` with a wrong answer deletes nothing, and with the right one **deletes every identical object at once** (two identical `*.x` objects, one delete, both gone).
- `PUT /control/rewrite/update {"target":{domain,answer},"update":{domain,answer,enabled}}` replaces one object in place (POST is 405). That is an answer change with no window where the name falls through.
- Specificity: an exact rewrite beats a wildcard covering it, and a deeper wildcard beats a shallower one (`*.nest`, `nas.nest`, `*.deep.nest` answered .122, .150, .151 for `a.nest`, `nas.nest`, `x.deep.nest`; `x.nas.nest` fell back to `*.nest`).
- A rewrite write does not touch the filter engine: the verbose log shows `filtering: added rewrite element` and a config write, and no list reload. (Contrast curfew's own filter list, whose refresh rebuilds the engine: `adguard-filter-refresh-has-no-per-list-scope.md`.)
- The `$dnsrewrite` filter-rule form (`||x^$dnsrewrite=NOERROR;A;ip`) covers `x` and every subdomain, gives NODATA for AAAA and HTTPS, and is likewise ignored for a filtering-disabled client.

## dnsmasq 2.91 `address` records

Router-shaped instance: `--stop-dns-rebind --rebind-localhost-ok --local=/lan/`, forwarding to the fixture.

| Records (address 192.168.1.122) | `x` A | `a.x` / `a.b.x` A | AAAA / HTTPS for covered names |
|---|---|---|---|
| `--address=/x/ip` | answered | answered | **falls through** |
| `--address=/x/ip --server=/x/` | answered | answered | NODATA |
| `--address=/*.x/ip` | falls through | answered | **falls through** |
| `--address=/*.x/ip --server=/*.x/` | falls through | answered | NODATA |
| `--host-record=x,ip` | answered | falls through | **falls through** |

- **An IPv4 `address` record alone does NOT stop AAAA**: dnsmasq forwards the AAAA (and HTTPS) question upstream. Adding the local-only form `--server=/<same domain>/` (or its alias `--local=`) makes every other type NODATA. `--address=/x/::` is not a NODATA: it answers AAAA `::`.
- The `*.` wildcard works in 2.91 for both `--address` and `--server`/`--local`, and means "strictly below x": `x` itself is untouched (forwarded) for every type. `dnsmasq --test` accepts it as a conf-file line.
- More specific wins: with `/*.lan.../.122` and `/other.lan.../.150`, `other.lan...` and `x.other.lan...` answer .150.
- One line may carry several domains (`--address=/one/two/ip`).
- **Rebind protection drops an upstream private answer** (upstream A 192.168.1.122 came back as NOERROR with no answers), and **does not touch a local `address` answer** to the same private address. So a local record needs no `rebind_domain`. (dnsmasq also treats the RFC 5737 documentation ranges as private: an upstream 203.0.113.x answer was dropped the same way.)
- Same records, same answers on port 53 as on 54 (the post-`panic-off` arrangement).
- There is no exact-name-only form that also keeps AAAA local: `host-record` forwards AAAA, and `--server=/x/` covers every subdomain of x.

## dnsmasq: does somebody else's entry for a PARENT domain beat curfew's wildcard?

Measured separately (`docs/spikes/local-dns-names/measure-parent.sh`, output in `measured-parent-2026-11-18.txt`), because dnsmasq's man page says a non-wildcard pattern takes priority over a wildcard one. With curfew's `address=/*.lan.telemaque.ska.sh/192.168.1.122` and `server=/*.lan.telemaque.ska.sh/` in place, `breakoutbunny.lan.telemaque.ska.sh` still answered 192.168.1.122 (and AAAA NODATA) next to each of: `address=/lan.telemaque.ska.sh/10.1.1.1`, `address=/telemaque.ska.sh/10.1.1.1`, `server=/lan.telemaque.ska.sh/127.0.0.1#5454` and `address=/*.telemaque.ska.sh/10.1.1.1`. Only a MORE SPECIFIC entry won: `address=/breakoutbunny.lan.telemaque.ska.sh/10.1.1.2` answered 10.1.1.2 for that one name. So a broader entry cannot silently override a local name; a narrower one carves out exactly the name it names, which is the household's own deliberate choice and is left alone. Not measured: the household entries were given AFTER curfew's on the command line; on a router the order follows the uci list. dnsmasq 2.86+ sorts domain matches by specificity rather than order, so the reverse order is expected to behave the same, but that is inference.

## How OpenWrt's init script renders them (25.12.4 `/etc/init.d/dnsmasq`)

- `list address '<v>'` in `dhcp.@dnsmasq[0]` becomes `address=<v>` verbatim (`append_address`, line 172), and with `address_as_local '1'` also a `local=` line for EVERY address entry (a global switch, so not something curfew should flip).
- `list server '<v>'` becomes `server=<v>` verbatim (`append_server`, line 164).
- `option local` is a single value (`append_parm`), not a list: the household's `local='/lan/'` lives there.
- `rebind_domain` list values become `--rebind-domain-ok=<v>`.
- Both lists land in the generated `/var/etc/dnsmasq.conf.<cfg>` with the `dhcp-host` lines curfew's pins already produce, so they are picked up by the same `/etc/init.d/dnsmasq reload` the pins use.

## Live router, read-only, 2026-11-18

- `dhcp.@dnsmasq[0]` has no `address`, `server`, `rebind_domain` or `confdir`; `port='54'`, `rebind_protection='1'`, `rebind_localhost='1'`, `local='/lan/'`, `domain='lan'`, `localservice='1'`.
- dnsmasq listens on `192.168.1.1:54` (and 127.0.0.1, ULA, link-local), AdGuardHome on `:::53`.
- `/opt/AdGuardHome/adguardhome.yaml`: `rewrites: []`, `rewrites_enabled: true`, global `filtering_enabled: true`, upstreams `1.1.1.1` and `8.8.8.8` (plain), one persistent client, with `use_global_settings: true` and `filtering_enabled: true`.
- The daemon is `dev+e8a8cb3` and reports the feature `fixed-address` only.
