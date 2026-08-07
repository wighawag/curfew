---
title: Retire the dead dnsmasq blocklists path
slug: retire-dnsmasq-blocklists-path
blockedBy: []
covers: []
---

## What to build

Remove the dnsmasq-based global blocklist mechanism, which no longer filters anything, **after** confirming AdGuard Home covers the same categories.

Per `docs/adr/0002-adguard-home-owns-dns-filtering.md`, AdGuard Home owns port 53 and dnsmasq is relegated to DHCP on port 54. The dnsmasq blocklist script writes a dnsmasq config that nothing reads, since dnsmasq no longer answers DNS. The AdGuard setup script even deletes that config as part of its own setup, so the two mechanisms actively disagree.

Note the script is **not deployed by the installer** (which copies five scripts and this is not among them), so on a live router it exists only as a leftover from an older install. It is not inert in every sense, though: when present it sets a dnsmasq `confdir` via uci and RESTARTS dnsmasq, which is the DHCP server. So the weekly cron job restarts DHCP for no benefit.

Compounding it, the shipped default crontab has the weekly update commented out with a note that AdGuard self-updates, while the deployed crontab still runs it. So the repo's own default and the live configuration disagree about whether this path is alive.

**Verify before deleting, and be explicit about the bar.** The script's default list covers gambling, porn, malware, phishing, ransomware, scam and fraud, though the deployed config has porn, malware and phishing commented out as dnsmasq-crashing, so the live dnsmasq coverage is narrower than the script suggests. The acceptance bar here is a **repo-side comparison**: read the filter list the AdGuard setup script configures and confirm it covers those categories, recording the mapping. A live-router check is better but is not required, because the router's actual AdGuard config is unmanaged state that the repo cannot see (that gap is itself recorded in ADR 0002). If the repo-side comparison shows a gap, close it in the AdGuard configuration first and say what was added.

Note that the recovery script deliberately restores dnsmasq to port 53 and removes the blocklists config, so in the panic state there is no filtering at all. That is intended (panic mode restores connectivity, not policy) and should not be "fixed" as part of this task.

## Acceptance criteria

- [ ] A recorded category-by-category mapping from the dnsmasq lists to AdGuard's configured filters, or gaps closed in AdGuard config and stated
- [ ] The dnsmasq blocklist script, its config file, its `.example`, and its crontab entry are removed from the repo and from the installer
- [ ] The installer no longer creates a default blocklists config on the router
- [ ] The installer still SCRUBS a stale `blocklists.sh` line from a live router's crontab. The crontab merge greps out the literal token `blocklists`; that token is the only thing removing the leftover entry, so keep it (or replace it with an explicit one-shot removal). Deleting it strands the stale line on the router forever
- [ ] On-router leftovers are cleaned up or a documented one-liner is provided, naming `/usr/bin/blocklists.sh`, `/etc/config/parental_blocklists`, `/etc/dnsmasq.d/blocklists.conf`, `/tmp/dnsmasq-blocklists`, and the dnsmasq `confdir` uci value the script may have set
- [ ] Tests covering the removed script are removed; the rest of the suite stays green
- [ ] Documentation sweep across the whole repo, not just the README: `docs/setup-guide.md` carries a numbered setup step telling the user to run this script, and it must go or a reader will follow the guide into a missing command
- [ ] The README's global-filtering feature line is RE-ATTRIBUTED to AdGuard Home rather than deleted; the capability still exists, only the mechanism changed. The README currently never mentions AdGuard at all, and separately claims the installer downloads blocklists, which is already untrue

## Blocked by

- None. Independent of the enforcement and Go work, since it touches only DNS filtering.

## Prompt

> Retire the dead dnsmasq-based global blocklist mechanism from the curfew parental control system, after verifying that AdGuard Home covers the same filtering categories.
>
> Context: this repo controls a home router running OpenWrt. It has two global DNS filtering mechanisms, and only one is live. AdGuard Home owns port 53 and dnsmasq was moved to port 54 for DHCP only, so the dnsmasq blocklists are inert. Read `docs/adr/0002-adguard-home-owns-dns-filtering.md` first: it records why AdGuard replaced dnsmasq (dnsmasq could not handle blocklists of the required size) and that the dnsmasq path is legacy.
>
> The important constraint: this is a household content filter, so do NOT delete the fallback until you have confirmed AdGuard actually blocks the same categories (gambling, porn, malware, phishing, ransomware, scam, fraud). Removing dead code must not narrow real protection. If a category is uncovered, add it to the AdGuard configuration and say so.
>
> Where to look: the blocklists script and its config, the installer step that seeds a default blocklists config, the crontab templates (the shipped default and the deployed one disagree about whether the weekly update runs), and the AdGuard setup script which already deletes the dnsmasq blocklists config. `docs/architecture.md` explains how the DNS layer fits together.
>
> Leave the recovery script alone: it restores dnsmasq to port 53 and drops filtering on purpose.
>
> Done means: verification evidence recorded, the dnsmasq path fully removed from repo, installer and cron, tests green, and the documentation sweep complete across README and setup guide.
>
> FIRST, check this task against current reality (it is a launch snapshot and may have DRIFTED): does it still match the code and the relevant ADRs? This task is premised entirely on ADR 0002 still holding, i.e. that AdGuard owns port 53 and dnsmasq is DHCP-only. If that changed, do NOT build on the stale premise: route the task to needs-attention with the discrepancy as the reason.
>
> RECORD non-obvious in-scope decisions durably and link them from the done record. If you find a category AdGuard does not cover and choose how to close it, that choice is exactly what needs recording: an ADR if it meets the bar, otherwise a note in the done record. An un-recorded in-scope decision is a review finding, not a silent default.
