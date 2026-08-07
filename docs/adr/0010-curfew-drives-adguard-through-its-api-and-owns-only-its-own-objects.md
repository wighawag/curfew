# curfew drives AdGuard through its API, and owns only its own objects

**Status:** accepted

`docs/adr/0002-adguard-home-owns-dns-filtering.md` made AdGuard Home the owner of DNS filtering and recorded that its configuration is load-bearing state nothing manages, so hand-made exceptions were destroyed by a reinstall. `docs/adr/0007-the-tool-owns-every-operation-including-recovery-and-deployment.md` then said curfew should bring that configuration under management. This records HOW, and the answer is not the obvious one: **curfew does not own `AdGuardHome.yaml`, and must not try.**

## AdGuard is itself an authoritative writer of that file

Measured on v0.107.78 in the test image. A 470-byte config written at `schema_version: 28` came back as **3673 bytes at schema_version 34** after one start: AdGuard migrates the schema and expands defaults on its own. An unknown top-level key added to the file (`curfew_marker`) was **silently dropped** on the next write, so curfew cannot even keep its own state there.

Two writers over one file is exactly the "which of these owns this?" question ADR 0007 blames for every bug in the investigation, and it is the mechanism behind the lost exceptions ADR 0002 recorded: `legacy/scripts/setup-adguard.sh` does `cat > "$AGH_CONFIG"` on every run.

So the boundary is the same one that already works for the firewall: **curfew owns its own nftables table and never touches fw4; it owns its own AdGuard objects and never rewrites the rest.** Everything curfew changes goes through the REST API, which was measured to work for the things it needs (`set_rules` returns 200 and reaches the yaml; `add_url` validates by fetching and returns 400 when a list is unreachable).

## The one exception, and why it is unavoidable

Creating the first admin user requires editing the file, because AdGuard 0.107 has no API to create one. That edit is a single surgical replacement of an **empty** users list, and `adguard.EnsureUser` refuses when an account already exists, so a household's own login is never disturbed. Measured end to end: after the edit AdGuard answers **401 unauthenticated, 200 with the password, 401 with a wrong one**, and an `@@||eth.limo^` exception survives both the edit and AdGuard's own subsequent rewrite. A backup is kept, because this is the one file curfew writes that another program owns.

## Why that edit is urgent rather than tidy

`setup-adguard.sh` ships `users: []`. Measured: with no admin account, an unauthenticated `POST /control/protection {"enabled":false}` returns **200 OK** and `protection_enabled` becomes false. **Any device on the LAN can turn off DNS filtering for the whole household with one HTTP request, including the device being filtered.**

This is the same defect as the unauthenticated ticket CGI in the enforcement spec, in the other daemon, and it deserves the same treatment: the password and the enforcement precedence are two independent halves, and neither is sufficient alone. A test asserts it as an **attack that stops working**: the baseline confirms the attack succeeds against an unsecured AdGuard, adoption runs, and the same request must then fail while a correct password still works.

## Identity is IP, and that is forced

The obvious design, keying per-profile DNS rules by MAC to match curfew's registry, **does not work**, and fails silently. Measured, with controls:

| Rule | Result |
|---|---|
| `$client=eli`, client added with `ids:["aa:bb:cc:dd:ee:01"]` | RESOLVED (no effect) |
| `$client=aa:bb:cc:dd:ee:01` | RESOLVED (no effect) |
| `$client=10.99.1.2` | BLOCKED |
| global rule, no `$client` (control) | BLOCKED |
| an unrelated domain throughout (control) | RESOLVED |

`POST /control/clients/add` with a MAC returns **200 OK** and stores a client that never matches anything. AdGuard only learns MACs when it runs DHCP itself, and per ADR 0002 dnsmasq keeps DHCP.

So the two layers identify devices differently: **nftables by MAC, AdGuard by IP.** curfew bridges them by assigning static DHCP leases for registered devices, so the mapping is derived from configuration curfew already owns rather than observed from live state that can be stale. Reading leases and ARP live was the alternative and is kept only as the reconciler that reports disagreement.

The safety argument for tolerating that bridge at all: **the load-bearing controls never consult it.** Whether a child is online, their schedule, their budget and manual blocks are all nftables on MAC. Only the domain refinement uses IP. A missing or stale mapping means "no streaming" might not apply while bedtime and budget still do. Fail-open on the refinement, fail-closed on the control.

## curfew owns the clock, not AdGuard

Rule changes were measured to take effect in **10ms in both directions**, with a 4 MiB DNS cache configured, so the cache does not defeat a schedule. AdGuard's own `blocked_services_schedule` does work (it stores milliseconds since midnight with a timezone) and is **not used**: it applies only to AdGuard's built-in service catalogue rather than to arbitrary domains, and a second scheduler with different semantics is precisely the split ownership this decision exists to avoid. curfew already evaluates windows as desired state from the clock, with day selectors, overnight handling and an embedded tzdata, and that model is reused.

## A running AdGuard is not a filtering AdGuard

Found on the live router, and it changed this ADR after the fact. AdGuard was running, authenticated and serving its admin page, while **dnsmasq held port 53** and the household resolved through it unfiltered. AdGuard was fatally exiting on every start with `listen tcp 0.0.0.0:53: bind: address already in use`, and procd eventually gave up.

The verification that missed it is the interesting part. AdGuard serves its web API about **two seconds** after starting and only attempts the DNS bind about **forty-three seconds** later, once its blocklists are loaded. So a check of the admin API immediately after a restart passes against a process that is already doomed. That is the same shape as every other defect this project exists to remove: a healthy-looking report over a system that is doing nothing.

So setup now (a) asks WHO holds port 53 rather than whether the port answers, since dnsmasq and AdGuard are indistinguishable from outside; (b) waits for AdGuard to actually take the port, with a timeout generous enough to cover that 43-second gap, and quotes AdGuard's own fatal line when it does not; (c) moves dnsmasq to 54 when it is in the way, per ADR 0002; and (d) **rolls dnsmasq back to 53 on any failure**, because the one thing worse than an unfiltered household is one with no resolver at all. A rollback that itself fails says so unmistakably and prints the manual fix.

It also enables the service. The live router had the init script but no `rc.d` symlink, so a power cut would have left no AdGuard and nothing to notice.

## Consequences

- Reconciliation of AdGuard is **on action, not on a tick**. The firewall is re-asserted every minute because the kernel can be wiped underneath it; AdGuard's config persists and a human edits it, so a continuous reconciler would revert a change made in AdGuard's own UI. Disagreement is REPORTED instead, which is the same principle as everywhere else here: make drift visible rather than silently correcting or hiding it.
- Secrets never enter the repo. curfew stores no AdGuard config, so the password hash stays in AdGuard's own file, and ADR 0007's open question about what the pull path may store is dissolved rather than answered.
- AdGuard remains OPTIONAL. `-no-adguard` skips it entirely, and its absence degrades nothing else: the allowlist, schedules, budgets and tickets do not depend on it.
- `-password` sets both passwords, with `-curfew-password` and `-adguard-password` overriding it individually. Two systems on this router grant access, and shipping either without a password lets the filtered device free itself.
- Verification runs from the laptop over HTTP rather than by shelling a fetcher on the router: the OpenWrt image's `wget` is uclient-fetch, which fails these requests outright, and `nohup` does not exist there either. When AdGuard cannot be reached to verify, curfew REFUSES to report success and says how to check by hand.
- Installing AdGuard from scratch writes the admin account into the config before AdGuard is ever started, so the open-API window never exists at all. The download step is the one part not covered by a test, because the test image already ships the binary.
