# Architecture

How my-router is put together today. This describes our own code, so the code is the current truth and this document is an orientation map, not a specification. Decisions and their rationale live in `docs/adr/`; intended changes live in `work/specs/`.

## The layers

**Enforcement (nftables).** A dedicated `inet parental_control` table, deliberately separate from OpenWrt's fw4, holding MAC sets (`allowed_macs`, `blocked_macs`) and per-profile-rule IP sets (`blocked_sites_<profile>_<rule>`), plus a `forward` chain hooked at priority -10 with policy accept. Only the allowlist rules narrow to LAN-to-WAN by `iifname` and `oifname` (the WAN device is discovered at runtime, because PPPoE means the L3 device `pppoe-wan` differs from the configured one). The profile-block and website-block rules match on `ether saddr` alone, so they apply to all forwarded traffic including LAN-to-LAN.

**Control (shell scripts in `/usr/bin`).** THREE scripts write to the `forward` chain, and they do so with no ordering contract, which is the hazard the enforcement spec exists to fix:

- `setup-firewall.sh` builds the MAC allowlist from the profiles config and applies the allow/drop rules. Runs at boot from `/etc/init.d/parental-allowlist`. Note it **flushes** the forward chain on `apply` rather than appending, which discards profile blocks on a same-uptime re-apply. (That flush is NOT the reboot bug: after a reboot the ruleset is already empty, so there is nothing to discard. The reboot case has TWO independent causes, and fixing either alone leaves it broken. First, `parental-profiles.sh`'s `nft_init` returns early once the table exists, so `blocked_macs` is never created and every later `add element` fails silently. Second, even with that fixed, all block state lives in `/tmp`, so after a reboot nothing knows which profiles were blocked. A third ordering problem compounds both: an appended `@blocked_macs drop` lands after the allowlist `accept`, where it is unreachable for the only traffic that matters.)
- `parental-profiles.sh` blocks and unblocks profiles, issues tickets, and checks time budgets. Appends its drop rule.
- `website-blocking.sh` resolves a named block rule's domains to IPs and appends a drop rule per MAC.

`panic-off.sh` also touches the table, but only to delete it wholesale (see the recovery seam below). `blocklists.sh` touches the firewall not at all: it is a DNS-layer script that writes dnsmasq config, and it is **not deployed by the installer** (which copies five scripts, not including it), so on a live router it exists only as a leftover from an older install. It is being retired.

**Scheduling (cron).** Every recurring behaviour is a crontab line: per-minute budget checks, hourly re-resolution of blocked domains, and the actual bedtime and website schedules. This means the schedule is not data the system can read about itself, which is why a UI cannot currently render "blocked until 08:00".

**State (`/tmp/parental-profiles/`).** Per-profile status, per-profile daily usage counters and the day marker, active tickets, and per-profile-rule website blocking status, all as small flat files. Being tmpfs, all of it is lost on reboot.

**DNS (AdGuard Home, with dnsmasq displaced).** `setup-adguard.sh` installs AdGuard Home, moves dnsmasq to port 54 for DHCP only, and takes port 53 for filtered DNS plus a web UI on 3000. `panic-off.sh` reverses this.

**Web (uhttpd CGI).** A static page at `/www/tickets.html` with duration buttons, calling `/www/cgi-bin/ticket`, which shells out to `parental-profiles.sh ticket`. No authentication: it is reachable by anyone on the LAN.

**Deployment (`install.sh`, from the laptop over SSH).** Copies scripts to `/usr/bin`, web files to `/www`, configs from `config/local/` to `/etc/config/`, merges the crontab, applies the firewall, installs the boot script and AdGuard. Idempotent by intent, distinguishing a first install (full apply) from a re-run (update the allowlist set only, preserving active blocks).

**Configuration.** Pipe-delimited flat files rather than UCI. `parental_profiles` (`name|budget|mac,mac`) is the single source of truth for both profile membership and the MAC allowlist; `block_rules` (`rule|domain,domain`) defines reusable domain lists; `parental_blocklists` is a URL list; `device_ips` drives static DHCP leases. Real values live in the gitignored `config/local/`, with `.example` templates committed.

**Tests (bats in a container).** The suite runs against a real `nft` binary with `NET_ADMIN`, asserting on set membership and rule presence. The enforcement spec adds a network-namespace harness that asserts on the packet path instead, because set membership was never sufficient to prove enforcement.

## Seams worth knowing

- **The three enforcement scripts are env-overridable**, which is what makes the suite possible, though each honours its own subset rather than a common union. Across them: `PARENTAL_CONFIG`, `PARENTAL_STATE_DIR`, `PARENTAL_WAN_IF`, `PARENTAL_LAN_IF`, `NFT`, `LOGGER`, `SLEEP`, `DATE`, `WEBSITE_BLOCKING`, `PARENTAL_SKIP_AUTOBLOCK`, plus `BLOCK_RULES_CONFIG` and `NSLOOKUP` for website blocking. New code should extend this pattern rather than hardcode paths. Not universal: `setup-adguard.sh` hardcodes its install paths and honours only `LOGGER`; `panic-off.sh` honours only `NFT`; `blocklists.sh` has its own `BLOCKLISTS_CONFIG` and `WGET`; and `web/cgi-bin/ticket` hardcodes the script path and passes no environment at all, which is why testing it needs an install-path decision. `PARENTAL_FIREWALL` and `IPTABLES` are levers today but are removed with the iptables backend, so do not build on them; `SLEEP` and `PARENTAL_SKIP_AUTOBLOCK` go the same way when the backgrounded ticket expiry is deleted.
- **The firewall backend is abstracted** behind `block_mac` / `unblock_mac` / `is_mac_blocked` / `list_blocked_macs`, with an iptables implementation alongside the nftables one.
- **A profile is the unit of action.** Nothing operates on a single device: blocks, tickets and budgets all fan out across every MAC in a profile.
- **`panic-off.sh` is the recovery path**, deliberately dependency-free: it drops the whole nftables table, stops AdGuard and restores dnsmasq to port 53. It is what you run when everything else is what broke.

## Choices carrying no recorded rationale

Asked directly, the repo owner confirmed that several load-bearing-looking choices were made without a specific rationale worth preserving, and are explicitly open to being changed if something better presents itself. They are listed here so a future reader does not mistake them for decisions defended by reasoning that was never written down:

- using a **private `parental_control` nftables table** rather than expressing policy through UCI and fw4;
- **pipe-delimited config files** rather than UCI format;
- **deploying by `scp` over SSH** rather than building an opkg package.

No ADR exists for any of these, deliberately: an ADR records a decision and its why, and inventing a rationale after the fact would corrupt the record. If one of them is later changed for a real reason, THAT is the decision worth an ADR.

The choices that DO carry recorded rationale are in `docs/adr/`.

## Known divergence between claim and reality

The system currently reports success in several places where it enforces nothing, most importantly after a reboot. The failures and their reproductions are recorded in the enforcement spec, and the general principle they taught is worth keeping in mind when reading any of this code: **the firewall is ground truth and the state files are commentary**. Where the two disagree, believe the firewall.
