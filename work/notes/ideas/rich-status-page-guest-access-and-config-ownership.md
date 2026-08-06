---
title: Rich status page, guest access, and config ownership
slug: rich-status-page-guest-access-and-config-ownership
---

The third tier of the parental control rework, held as an idea rather than a spec because it depends on decisions `explore-go-tool-for-parental-control` has not made yet. Writing it as a spec now would produce tasks premised on an HTTP seam, a config format and a scheduler that do not exist.

This note is self-contained: the design detail below was consolidated here from the investigation document that has since been deleted.

## The three things wanted

**A live status page** replacing the current static buttons: per-profile blocked/allowed state, active tickets with a countdown, budget used against budget total, which website rules are active, and buttons that give live feedback.

**Guest access** for a device that is **not in the device registry** (not on the MAC allowlist): a passphrase page a visitor loads, with their MAC resolved from `REMOTE_ADDR`, granted as an entry in a `guest_macs` set with a kernel timeout, plus an admin view to list, extend and revoke.

The discriminator is registration, NOT profile membership, and getting it wrong is a live hazard rather than pedantry. A device in no profile is an *ungoverned device* (ADR 0003): registered and permanently allowed, like the printer. Keying the guest flow on "no profile" would hand a 90-minute pass to the printer and to every appliance.

**Config ownership** so schedules and budgets are editable from the UI while still living in git.

## Why it cannot be specced yet

The status page needs a decided HTTP surface and a status document shape. Guest passes need the `guest_macs` set that the enforcement spec introduces. Config editing needs the tool to own config, which needs the config format, the migration story and the schedule model, all open questions in the exploration spec.

## Status must be derived from the firewall

A page fed by `/tmp/*_status` would today show a green "blocked" badge for a child who is online, and a live countdown for a ticket the budget checker already killed.

Proposed shape of a single status document, produced by one owner so there is one place that knows the format and one place that escapes strings:

```json
{
  "now": 1785993502,
  "profiles": [
    {
      "name": "eli",
      "internet": "ticket",
      "reason": "ticket",
      "ticket": { "active": true, "expires_in": 842, "minutes": 30 },
      "budget": { "unlimited": false, "minutes": 240, "used": 96, "remaining": 144 },
      "websites": [ { "rule": "no_streaming", "active": true, "expires_in": null } ],
      "devices": [
        { "mac": "aa:bb:cc:dd:ee:01", "name": "eli-phone", "ip": "192.168.1.42",
          "online": true, "blocked": false }
      ]
    }
  ],
  "guests": [
    { "mac": "d8:...", "name": "pixel-7", "ip": "192.168.1.77", "expires_in": 5400 }
  ],
  "durations": [15, 30, 60, 120],
  "admin": true
}
```

`internet` is derived from set membership: `ticket` if the profile's MACs are in `ticket_macs`, else `blocked` if all are in `blocked_macs`, else `allowed` if none are, else `partial`. Keeping **`partial` as an explicit state is deliberate**: it surfaces drift instead of hiding it behind a green dot, and drift of exactly that kind is what made the original enforcement bug invisible.

`expires_in` comes from the `expires` field of the timeout sets, so the countdown is the kernel's own number rather than a separately tracked one that can disagree with reality.

## Endpoints and trust boundaries

Everything under the web server's CGI prefix is executable by anyone on the LAN, so the split is by trust level, not by convenience:

- a family/admin endpoint: `status`, `ticket`, `block`, `guest-list`, `guest-grant`, `guest-revoke`;
- a public, passphrase-gated guest endpoint that can only grant to the requesting device.

Shared helpers must live outside the web root so they cannot be fetched or executed over HTTP. Mutations are POST only with an `Origin`/`Referer` check, since a page a parent visits could otherwise fire a `GET .../ticket?...` at the router. Every response carries `Cache-Control: no-store`, because phone browsers cache GETs aggressively and a cached status page is worse than no status page. Errors are JSON too, with a proper status line.

## Guest flow

The visitor opens a guest page, enters the household passphrase and picks a duration from an allowed list. The handler resolves `REMOTE_ADDR` to a MAC through `/proc/net/arp` (LAN bridge only, rejecting incomplete entries whose flags are `0x0`), rejects anything outside the LAN subnet, **rejects any MAC already present in the device registry** (which means the page DOES disclose, to the requester only, that their own MAC is known; that is an accepted trade for closing the bypass below, and it is why the no-disclosure rule is scoped to other people's devices), compares a salted SHA-256 against stored config, rate-limits per IP with lockout after N failures, caps the duration at a configured maximum, adds the MAC to `guest_macs` with a kernel timeout, and logs the grant to syslog. The page never displays MACs and never reveals whether a MAC is already known.

The ARP entry is guaranteed fresh because the visitor just completed a TCP request to the router. An unknown device can reach the router's own web server and DNS while having no internet, because the allowlist drop rule only matches LAN-to-WAN traffic; that is what makes the passphrase page reachable at all.

Findability without typing an IP: a dnsmasq `address=/guest.lan/192.168.1.1` entry or an AdGuard rewrite, plus a printed QR code. True captive-portal interception (the "sign in to network" popup) needs DNS/HTTP hijacking and is a different project; explicitly out of scope.

Admin side: list active guests with name, IP and remaining time, revoke, extend, and add a MAC by hand for a device that cannot load a page (a console, a smart TV).

## Security: the real threat model is the kids

The strongest adversary here is a bored twelve year old with a phone on the LAN, who can already open the tickets page and grant themselves two hours. In order of value per unit of effort:

1. **Gate admin actions by requesting MAC.** The IP-to-MAC machinery built for guest access gives this for free: only devices in designated admin profiles can call mutating endpoints. Nothing to remember, nothing to type, and the primary user's experience is unchanged.
2. **PIN fallback** for a new or reinstalled phone: hashed PIN in config, setting a long-lived HttpOnly cookie. Needed because MAC gating has an obvious failure mode.
3. **POST plus Origin check plus no-store** on all mutations.
4. **Document that MAC spoofing defeats both the allowlist and the admin gate.** A determined child who reads the ARP table can impersonate a parent's phone. The only real fixes are per-device PSKs or 802.1X, out of proportion here. Worth one line in the README so the limit is a decision rather than an oversight.
5. Confirm the web server is not reachable from WAN (fw4 blocks WAN input by default, but the check is cheap) and consider pinning the listen address to LAN.

**Dependency:** while the UI only issues tickets, no-login means a child can grant themselves internet. Once it edits schedules and budgets, no-login means a child can move their own bedtime permanently. The admin gate is therefore a hard prerequisite for config editing, not optional hardening.

**The guest endpoint is a bedtime bypass, and the registry check only narrows it.** In the enforcement chain `guest_macs accept` sits ABOVE `blocked_macs drop`, so a guest pass outranks a schedule block by design (a visitor should not be caught by a child's bedtime). A child who learns the household passphrase can therefore grant themselves a pass from the public, unauthenticated endpoint and walk straight past bedtime.

Rejecting registered MACs is necessary but **not sufficient**, and it would be dangerous to record it as if it closed the hole. Private or randomised Wi-Fi MAC addresses are stock on iOS and Android and toggled from the normal Wi-Fi settings screen. A child rotates their MAC, becomes an unregistered device, reaches the router's web server (which the LAN-to-WAN-only drop still permits), enters the passphrase, and is granted a pass that outranks their own bedtime. This is the same MAC-spoofing limit the threat model already accepts for the allowlist, except a passphrase endpoint hands it to anyone who knows a short secret rather than requiring them to read the ARP table.

So the residual has to be designed against, not asserted away. Candidate mitigations, to be chosen when this is specced: keep the passphrase away from the children and make it rotatable; cap guest duration well below a night; make every grant visible in the admin list with its MAC, IP and hostname so an unexplained pass is obvious; require admin approval for a grant rather than making the passphrase sufficient; or refuse guest grants entirely during the hours any profile is schedule-blocked, which removes the bypass by construction at the cost of a visitor arriving late in the evening.

## Config ownership

**Two writers, one config, silent loss.** Config flows one way today (`config/local/` to `install.sh` to `/etc/config/`). Adding UI editing means the installer will overwrite phone-made changes with no error and no diff: a parent moves bedtime to 21:30 on Tuesday, an unrelated deploy on Saturday silently reverts it.

Proposed resolution, inverting the flow:

- the config file on the router is the single source of truth at runtime;
- only the tool writes it, validated, atomic (write temp, fsync, rename), with a bumped revision and a journal entry;
- `install.sh` deploys code and never silently overwrites config;
- explicit `pull` and `push` verbs replace the implicit upload, with a revision plus content hash so `push` refuses when the router holds changes the laptop does not have.

Git stops being the deployment mechanism and becomes history, review and rollback.

**The comments in the config are data.** Profile files carry per-device names and grouping as comments, which any UI rewrite would destroy. Promote them to fields (`name`, `display_name`, `group`, `notes`) and the fidelity problem becomes the feature that lets the page say "Eli's phone is online" instead of showing three raw MACs.

**Schedules must leave crontab.** Editing timings from a web form means rewriting cron lines from a web form, and cron cannot express what is wanted anyway (the current `0 24 * * *` never fires because cron hours are 0-23). The intended precedence is: ticket/override, then manual block, then budget, then schedule, then default allow. Note this is a precedence over *reasons*, and the enforcement chain cannot express it: manual, budget and schedule blocks all collapse into one undifferentiated `blocked_macs` set, so only the ticket/override tier is enforced by rule order. Distinguishing the middle tiers needs the reason to be recorded in state (which is what lets the UI say WHY a child is blocked), so this is a requirement on the config and state model rather than on the chain.

**Format and location.** A single JSON file with a `schema_version` and deterministic serialisation (stable key order, fixed indent) so UI edits produce minimal diffs. `schema_version` matters because a fresh-router restore might happen years later against a much newer tool, which must migrate rather than reject. Placing it under `/etc/config/` gets sysupgrade preservation and inclusion in the router's own backup for free (see `work/notes/findings/openwrt-etc-config-preserved-across-sysupgrade.md`).

**AdGuard's own config must be in scope.** This is a confirmed loss, not a hypothetical: an exception added in AdGuard to un-block `*.eth.limo` (blocked by the default lists) vanished after a `panic-off.sh` and reinstall cycle. AdGuard holds real, hand-made configuration (custom filtering rules, allowed and blocked domain exceptions, upstream DNS settings, the filter list selection) and nothing currently captures it, so every reinstall silently discards it. Whatever pull/push mechanism is built must treat the AdGuard config as part of the router's configuration, which means deciding how to extract and re-apply it: it is a YAML file the daemon owns and rewrites at runtime, so it cannot simply be overwritten while AdGuard is running, and only the hand-made subset (not the downloaded filter contents) is worth versioning. Note that the reinstall path is exactly when this matters, and that a fresh-router restore is worthless if it restores the firewall rules but silently drops the DNS exceptions the household depends on.

**The config schema must accommodate the device/profile split.** Per `docs/adr/0003-devices-are-named-and-profiles-group-them.md`, device names become first-class in their own registry and profiles group devices by name, with ungoverned devices allowed but unrestricted. That decision changes the schema, so it should land with the config-ownership work rather than being implemented once against the current format and again afterwards. It also happily resolves the comments-are-data problem above: the names the UI needs stop being comments because the schema has a field for them.

**Secrets stay out of git.** The PPPoE and Wi-Fi passwords live in `config/local/router_config`, and a guest passphrase hash is about to join them. Split safe config from secrets so that committing a backup cannot leak ISP credentials; exports exclude secrets unless explicitly requested.

**Fresh router in one command**, ending in verification: root password, PPPoE, Wi-Fi, timezone, install, restore config, apply, then check. A `doctor` command running the same assertions as the acceptance tests against the live router is what would make "installed successfully" mean something, since the original bugs survived precisely because nothing ever checked reality on the router. Note that this path is currently dead code: `--setup` never runs because of the argument-parsing bug the enforcement spec fixes.

## Front-end constraints

No CDN, no external font, no favicon request: the page is loaded precisely when someone has no internet, so every asset must be local. Vanilla JS in one file, roughly 200 lines, no build step. Poll every 10 seconds with the countdown ticking locally in between, pause polling when `document.hidden` to save phone battery, and use optimistic buttons that roll back on error. Keep the existing `tickets.html` filename so the bookmark on the primary user's phone keeps working.

## Expected shape when this becomes specs

Roughly three, after the exploration emits its build plan, with the admin gate ordered ahead of the config one:

- **status surface**: the status document, the read endpoint, the page rewrite;
- **guest access**: grant/revoke/list, the public passphrase page, the admin section, rate limiting and lockout;
- **config ownership plus restore**: schema and migrations, `pull`/`push` with drift detection, the journal, UI editing of schedules and budgets, fresh-router restore and `doctor`.

Testing notes carried forward: assert JSON validity and shape with `jq` (test-only, never router code), cover the `partial` mapping and escaping of odd profile names, drive the endpoints over a real server asserting headers and `no-store` and a sub-2-second response as a regression test for the CGI stall, and reject GET mutations and bad `Origin`. Guest resolution should be tested against an ARP fixture via an `ARP_FILE` env override, matching the pattern the existing scripts already use.
