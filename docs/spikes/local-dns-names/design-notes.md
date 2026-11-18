# Local DNS names: design decisions at tasking time

Relocated verbatim from the Implementation and Testing Decisions of `work/specs/tasked/local-dns-names-for-a-device.md` when it was tasked (2026-11-18), so the tasks can cite them by number from a home that never moves. A launch snapshot like the spec: current truth is ADR 0013, ADR 0014 and the code. Evidence: `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md` and `measure.sh` beside this file.

## Implementation Decisions

### 1. The data model

- `registry.Device` gains `dns_names` (`json:"dns_names,omitempty"`), a SET of local DNS names. It lives on the device for the same reason the fixed address does (ADR 0012, ADR 0008): it is a property of one device, it travels with push and pull for free, and it needs no new file.
- Load canonicalises each name (trim, lowercase, strip one trailing dot), drops exact duplicates and sorts, so two spellings never compare unequal and order never reads as a change. A name that does not parse is KEPT, exactly as a bad fixed address is, and refused by the checks that run before any write: refusing to load would refuse the whole allowlist over a DNS nicety.
- Registry mutation: `AddDNSName(mac, name)` and `RemoveDNSName(mac, name)`, both STRICT like `Rename` and `SetIP` (an unregistered MAC is an error, never a quiet insert). `AddDNSName` refuses when the device has no fixed address and when another device in the file covers the name (Decision 3). `SetIP(mac, "")` refuses while the device has names.

### 2. What a name means, and how it is rendered (ADR 0013)

Measured in the test image, recorded in `work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md`. Neither resolver can express "exactly this name" with AAAA kept local on the dnsmasq side, so curfew offers the two forms both sides render faithfully:

| `dns_names` entry | Covers | AdGuard rewrites (answer = fixed address) | dnsmasq entries in `dhcp.@dnsmasq[0]` |
|---|---|---|---|
| `x` | `x` and every name below it | `x` and `*.x` | `list address '/x/<ip>'`, `list server '/x/'` |
| `*.x` | every name strictly below `x`, not `x` | `*.x` | `list address '/*.x/<ip>'`, `list server '/*.x/'` |

- The `server '/<domain>/'` line is the local-only form. It is what makes AAAA, HTTPS and every other type NODATA instead of forwarded: an `address` line alone forwards AAAA upstream (measured).
- On AdGuard an A-only rewrite already answers AAAA and HTTPS with NODATA and does not forward (measured). curfew NEVER writes the special answers `A` or `AAAA`, which mean "use upstream for that type" (measured: `AAAA` makes AAAA fall through).
- IPv6 is deliberately not answered. The device's LAN IPv6 is a router-assigned ULA whose stability is not established (ADR 0011 follows IPv6, it does not pin it), and an AAAA that went stale would send clients to the wrong host by name. A fixed IPv6 is out of scope.
- Rejected: exact-only via `host-record` (AAAA falls through, measured); exact plus `server=/x/` (makes every subdomain of `x` local-only, silently breaking its public names); `address=/x/::` (answers AAAA `::`, measured).

### 3. Validation (one pure function, three callers)

The same function runs in `add-dns-name` (offline: what the file alone can decide), in `push` (with the router's uci read over ssh before anything is written) and on the devices page (with the router's own uci), and again in the daemon's pass as defence in depth. Hard errors refuse; warnings are printed and allowed.

Hard errors:

- **Syntax.** After canonicalising: an optional single leading `*.`, then a hostname of at least two labels, each 1 to 63 of `[a-z0-9-]` with no leading or trailing hyphen, 253 characters at most. ASCII only (an IDN is written in its `xn--` form). No other `*`, no underscore, no IP literal.
- **No fixed address** on the device.
- **Overlap with another device** (owner decision 3): refused when the two names' coverage intersects, naming the other device. Within one device, a name already covered by another of its own names is refused as redundant (`*.x` next to `x`).
- **The router's local domain.** Refused when the name is, or is under, a domain dnsmasq treats as local (`option local`, `option domain`; `lan` on the live router), because DHCP clients register their hostnames there and dnsmasq answers them from its leases.
- **Special-use domains the network depends on**: `localhost`, `local` (mDNS: printers, AirPlay, casting), `invalid`, `onion`, and `arpa` (all reverse lookups), and anything under them. `home.arpa` is the one exception, since RFC 8375 reserves it for exactly this use.
- **A whole top-level domain.** Implied by the two-label minimum, and stated in the message, since `*.sh` would answer for every name in the TLD.
- **Names the router itself resolves to work**: any name covering a hostname in `system.ntp.server` (a wrong clock moves every schedule), and, in the daemon where AdGuard is reachable, any hostname among AdGuard's upstream and bootstrap resolvers. Today the live router's upstreams are IP addresses, so only the NTP pool can actually match.
- **A foreign record for the same domain** (a rewrite or an `address`/`server` entry curfew did not create, Decision 4): the name is not refused at the CLI, which cannot see AdGuard, but `push` and the daemon report it and write nothing for that name on that side.

Warnings:

- The name covers a whole registrable domain (exactly two labels, `x` or `*.x`): "this answers for every name in example.com on your LAN".
- A public record for the same name is fine and does not need checking: on the LAN the local answer wins (measured on both resolvers), and the public record keeps serving devices that bypass the router (Further Notes).

### 4. Ownership: a ledger, because neither object can carry a marker (ADR 0014)

ADR 0010 says curfew owns only its own objects; until now ownership was syntactic (`curfew-*` clients, `curfew_*` host sections, one URL-identified list). Neither new object can carry such a marker, measured: an AdGuard rewrite is exactly `{domain, answer, enabled}`, and a uci list entry is a bare string. So ownership is a **ledger**: a router-local file the daemon owns, `/etc/config/curfew/dns-records.json` (persistent flash, preserved across sysupgrade like the rest of `/etc/config`), listing every AdGuard rewrite `{domain, answer}` and every dnsmasq list entry (`address` or `server` value) curfew has written.

- **curfew may change or delete an object only if it is in the ledger AND present.** Everything else is foreign and is never written, whatever it says.
- **A foreign object for the same domain is yielded to and reported** (the pins' rule, ADR 0011): curfew does not add its own next to it (two answers for one name), and does not take it over. A foreign object that is IDENTICAL to what curfew wants is also left alone and not claimed, because deleting it later would destroy the household's record (and on AdGuard a delete removes every identical copy at once, measured). The name still resolves, which is what the household asked for.
- **Write-ahead.** An entry is recorded before the object is created and dropped only after the object is gone, so a crash leaves the ledger a SUPERSET of what exists, never a subset. After each successful pass the ledger is pruned to entries that are present or still desired.
- **AdGuard object changes**: a new name is `add`; a moved address is `PUT /control/rewrite/update` (measured: replaces in place, so the name never falls through mid-move); a removed name is `delete` by `{domain, answer}`. Before any `delete`, the list must hold exactly one copy of that object; with two, one is the household's, so curfew deletes nothing and reports it.
- **The ledger is not pushed or pulled.** It describes what this router holds, like `state.json`; the device registry is still the only thing a person edits.
- Rejected: `$dnsrewrite` rules in curfew's own served filter list. It needs no ledger (the list is the owned object) and answers the same way (measured), but every change re-fetches that list, which rebuilds AdGuard's filter engine and is gated by the memory headroom check, so a name could be DEFERRED by that check; a rewrite write touches no list (measured). It would also hide the names from AdGuard's own "DNS rewrites" page, where a household looks for them.
- Rejected: a curfew-owned dnsmasq conf file in the `confdir`. It needs no ledger either, but the default confdir is tmpfs, so after a reboot the names exist only once the daemon has run again, and not at all if the daemon is down; `panic-off` would then depend on curfew being alive. uci entries persist with the rest of the DHCP config.

### 5. AdGuard clients that get no rewrites (owner decision 4)

Measured: a client with `filtering_enabled: false`, or filtering off globally, gets no rewrites at all; its questions go upstream and see the public record. Rewrites can also be switched off globally (`/control/rewrite/settings`). Protection off does NOT stop them. The daemon reads all three each pass and reports any that applies, with which clients; it changes none of them, because they are the household's settings. Rejected: an AdGuard upstream rule `[/x/]127.0.0.1:54` sending the names to dnsmasq for every client, because it means curfew editing `upstream_dns`, a shared setting it does not own (ADR 0010), and it would make the AdGuard path depend on dnsmasq.

### 6. Where it runs, and in what order

- **dnsmasq half: in the same DHCP transaction as the pins.** `leases.Pass` (run by the DNS layer, and by `leaseLoop` when AdGuard is off) plans the pins AND the name entries, then `Apply` runs them as ONE uci transaction with ONE backup, ONE `uci commit dhcp`, ONE `/etc/init.d/dnsmasq reload`, ONE liveness check and ONE rollback. Two transactions per tick would be two reloads and two rollback windows. The names follow the fixed address, so a `set-ip` move rewrites the pin and the `address` value in the same commit. A device's names are rendered only when its fixed address was actually PINNED this pass: a fixed address Reconcile refused (a clash) must not get names pointing at an address the device does not hold.
- **AdGuard half: in `dnspolicy.Manager.Tick`**, after the DHCP transaction, reconciled like the clients (on a tick, writes only on difference, scope-guarded by the ledger, ADR 0011's "scope, not frequency"). With no AdGuard credentials it is skipped and the ledger's AdGuard entries are left as they are, reported once.
- Everything is fail-open and reported, like the rest of the refinement layer: a record that cannot be written never stops the firewall or the pass.
- A device deregistered on the router's page loses its records on the next pass, because desired state is computed from the registry every time.

### 7. Never leaving the house without DHCP or DNS

- **Liveness after a reload that carries names.** `Apply`'s existing check is "dnsmasq is running". When dnsmasq is the household's resolver (its configured port is 53 or unset, as after `panic-off`), the check also requires an answer on `127.0.0.1:53`, using the same "any answer, even NXDOMAIN, counts" probe the daemon already uses (`localResolver.Serving`), so a WAN outage does not read as a failed reload. Either failure restores `/etc/config/dhcp` from the backup and restarts dnsmasq, exactly as for a bad pin, and the rolled-back entries stay in the ledger for the next pass to retry.
- **The DNS takeover never touches these entries.** `moveDnsmasqTo54` and `restoreDnsmasqTo53` change only `port` and `dhcp_option`; a test asserts the `address` and `server` lists come out byte-for-byte unchanged through a move to 54 and a rollback to 53.
- **One lock for every `uci commit dhcp`** (owner decision 5). The worst case is not cosmetic: if the takeover commits `port=54` between the daemon's backup of `/etc/config/dhcp` and its rollback, the rollback restores dnsmasq to 53 while AdGuard holds 53. And uci's staging area is shared between processes, so one writer's commit can sweep up the other's half-staged changes. Names add writes and the resolver liveness check adds rollbacks, so the window grows. The fix, MEASURED before relied on:
  1. Measure in the image: whether one process's `uci commit dhcp` commits another process's staged changes; whether uci locks the file during commit; whether OpenWrt's `lock` command and a Go `flock()` on the same file exclude each other.
  2. One lock file, `/var/lock/curfew-dhcp`. The daemon holds it across its whole DHCP transaction (backup, stage, commit, reload, liveness, rollback; seconds). `takeOverDNS` holds it only around `moveDnsmasqTo54` and around `restoreDnsmasqTo53`, never across AdGuard's up-to-43-second bind wait.
  3. The daemon TRY-locks: when busy it skips that pass, logs it and retries next tick (fail-open, like the rest of the layer). The takeover waits, with a timeout, and says so if it gives up.
  4. If step 1 shows the staging area really is shared, the daemon also stages in a private savedir (`uci -P`), so nothing outside the lock can sweep up its changes either.
  5. A real race in the image: the daemon pass held open between its backup and a forced rollback while the takeover runs; the final file must have `port=54`, every name entry, and a running dnsmasq.

### 8. push, pull and old daemons

- **Merge**: `dns_names` is one field of the device, compared as a set. `sameDevice`, `Equal` and `Merge3` gain it, so a rename on one side and a name on the other merge, and names changed differently on both sides are a conflict of a new kind, "local DNS names changed differently on both sides", whose report lists both sets (and the base). `push`'s "router changed since last sync" check uses the same `Equal`, which closes story 19.
- **push** reads `uci show dhcp` and `uci show system` with the existing survey, runs the validator on every device with names (refusing on any hard error before anything is written), and prints the warnings plus a note per changed device ("`*.lan.telemaque.ska.sh` -> 192.168.1.122, answered by the router within a minute").
- **Old daemons**: the daemon's `features` list gains `local-dns-names`. `push` refuses to send a registry with any `dns_names` to a daemon that does not list it, with the same wording as fixed addresses ("run `curfew update <host>` first"), for the same reason: the old daemon's page drops unknown fields on save. The live daemon (`dev+e8a8cb3`) reports only `fixed-address`, so the first push needs an update first.

### 9. Surfaces

- **CLI**: `curfew add-dns-name <mac|name> <dns-name>` and `curfew remove-dns-name <mac|name> <dns-name>`, editing the local device file only (`-registry`, same default as push), in the style of `set-ip`. The `*` must be quoted in a shell, and the usage line says so. `set-ip --clear` refuses on a device with names.
- **Router page**: the devices page shows each device's names next to its fixed address, with add and remove forms, through the same validator with the router's own uci, and the same warnings after saving.
- **Docs**: README command table; CONTEXT.md gains **local DNS name** (a DNS name the router answers with a device's fixed address, A only, from AdGuard and dnsmasq both) and **DNS record ledger**; ADR 0013 and ADR 0014.

## Testing Decisions

Test-first. Tests assert what a client actually gets back from a resolver, the uci commands a plan emits, the registry a merge produces, and what lands in a real `/etc/config/dhcp`; never a config file alone.

- **Validator unit tests**: each hard error and warning in Decision 3, including the overlap matrix (`x` vs `*.x` vs `a.x` across and within devices), the local-domain rule read from both `local='/lan/'` and `domain='lan'`, an NTP hostname, `home.arpa` allowed, and canonicalisation (case, trailing dot, duplicates).
- **Render and reconcile unit tests**: the table in Decision 2 exactly; a converged state emits nothing; a fixed-address move emits one `address` value change in the same plan as the pin change; a foreign identical entry is not claimed; a foreign entry for the same domain blocks that name only; only ledger-and-present entries are ever deleted; write-ahead ordering of the ledger; two identical AdGuard copies block the delete.
- **Merge unit tests**: names on one side merge; names vs rename merge; names changed differently is a conflict naming both sets; `Equal` sees a names-only difference; order and spelling differences are equal after load.
- **Acceptance in the real OpenWrt image** (`docker/acceptance.sh`), with a fixture upstream that answers every name with a SENTINEL (A 93.184.216.66, AAAA 2606:4700::66) so a forwarded question is visible, exactly as `docs/spikes/local-dns-names/measure.sh` does:
  - real uci receives the entries; dnsmasq is started on the config the init script would generate from them (`address`/`server` list values passed verbatim, as `append_address`/`append_server` do) and stays running; foreign `address`/`server` entries and host sections are byte-for-byte unchanged;
  - from dnsmasq on 54: `breakoutbunny.lan.telemaque.ska.sh A` is `192.168.1.122`; AAAA and HTTPS are NOERROR with no answers and no sentinel; the apex `lan.telemaque.ska.sh` is NOT answered locally (it is forwarded, the `*.` meaning);
  - from a real AdGuard on 53 with the daemon's reconcile having run: the same three answers; then the name is removed and AdGuard falls through to the sentinel, with a hand-made rewrite added before the test still present;
  - **simulated `panic-off`**: AdGuard stopped, dnsmasq moved back to 53 by `restoreDnsmasqTo53`, and the same answers from 53, plus a baseline that an upstream private answer IS dropped by rebind protection there (the bug this fixes);
  - **rollback**: a records change that makes dnsmasq refuse its config restores the previous `/etc/config/dhcp` and leaves dnsmasq running and answering;
  - **takeover**: entries survive `moveDnsmasqTo54` and `restoreDnsmasqTo53` unchanged;
  - `curfew-daemon -features` lists `local-dns-names`, and push against a fake old daemon refuses.
- **Isolation**: tests use temp registry and ledger files and the container's own uci and AdGuard; nothing touches `~/.config`, the real `config/local`, or a live router.
- **Owner's acceptance on the live router** (done by the owner, not by an agent): after `curfew update` and `curfew push`,
  - `dig @192.168.1.1 breakoutbunny.lan.telemaque.ska.sh A` gives `192.168.1.122` from AdGuard, and `dig @192.168.1.1 -p 54 breakoutbunny.lan.telemaque.ska.sh A` gives the same from dnsmasq;
  - `dig @192.168.1.1 breakoutbunny.lan.telemaque.ska.sh AAAA` and the same with `-p 54` give NOERROR with no answer;
  - `uci show dhcp.@dnsmasq[0]` shows exactly one `address` and one `server` entry for the name, and AdGuard's rewrites page shows exactly one `*.lan.telemaque.ska.sh` rewrite;
  - the panic-off behaviour is covered by the harness above, not by running `panic-off` on the live router.

