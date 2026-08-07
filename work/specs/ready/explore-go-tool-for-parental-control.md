---
title: Explore replacing the shell scripts with a Go tool
slug: explore-go-tool-for-parental-control
taskedAfter: [openwrt-packet-path-test-harness]
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this spec settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

The shell implementation's failure mode is not crashing, it is lying, and the enforcement spec fixes instances rather than the category. Every bug found in the investigation is the same bug in different clothes: an error nothing was forced to handle. `nft_init` returns early, the set is never created, `nft add element` fails into `2>/dev/null`, and the caller writes "blocked" and logs success. The ticket file and the firewall are two sources of truth with nothing keeping them equal. The CGI stall is an inherited file descriptor, a thing shell exposes and gives you no way to name or manage.

The investigation itself demonstrated the category live: a probe produced confidently wrong results because `nft` was absent from `PATH` and the scripts' own `2>/dev/null` ate the evidence, and it nearly got reported as a third critical bug.

Meanwhile the features actually wanted next (a live status page, guest access, editable schedules) each need something shell is bad at: structured JSON output, a long-running process that owns expiry, config the tool can validate and rewrite, and a schedule that is data rather than crontab lines.

The question is not "is Go nice". It is whether moving to a single tool removes that whole failure category at a cost worth paying, and whether the one unproven dependency actually works on this router.

## Solution

An exploration, not a build. Done means confidence plus a de-risked, sliced build plan, not shipped capability.

Spike the load-bearing unknown first (netlink against a real OpenWrt kernel), on the narrowest case that answers it: add a MAC to a timeout set, read back its remaining time, delete it, and confirm a packet is actually dropped. If that fails, the whole shape changes and the cheap answer is to shell out to `nft` from Go behind an interface, which is worth knowing before writing anything else.

Then pin the seams that the later specs depend on, decide the boundary between tool and shell, and emit a build plan the follow-on specs can be cut from.

The deliverable of every story below is an ANSWER, recorded, not code kept.

## User Stories

1. As a maintainer, I want to know whether `google/nftables` drives OpenWrt's kernel, so that the tool's core mechanism is proven before anything is built on it. **Partly delivered already**: a spike proved it against the packet path in the OpenWrt userland, including `ether_addr` timeout sets, readable remaining time, and an atomic whole-table replace that carries live tickets (`google-nftables-drives-the-kernel-and-replaces-rulesets-atomically`). What REMAINS for this story is the fidelity gap: that spike ran on the host kernel, not the router's aarch64 OpenWrt kernel, and netlink is a kernel interface, so it needs one confirmation on the real hardware.
2. As a maintainer, I want the netlink spike run inside the real `openwrt/rootfs` image against the packet-path harness, so that the answer reflects the router's kernel interface and not a convenient Linux container.
3. As a maintainer, I want a recorded fallback position if netlink disappoints (shelling out to `nft` behind an interface), so that a negative result costs a day rather than the approach.
4. As a maintainer, I want the tool to serve its own HTTP surface, so that the status page is not shaped by uhttpd's script timeout and a per-request fork. (Decided; the story is now to BUILD that surface, including auth, not to choose it.)
5. As a maintainer, I want exactly one thing that owns the firewall, so that we never have a Go tool and a parallel script that both write the same chain.
6. As a parent, I want a way back that works when the tool itself is broken, so that a bad deploy never leaves the household with no internet and no way to fix it. Note this is now a GUARANTEE story rather than a script story: `panic-off` is a tool command, and what survives outside the tool is a minimal hatch that restores connectivity but not policy (ADR 0007).
7. As a maintainer, I want scheduling to be an in-process reconcile loop, so that "blocked until 08:00" can be rendered and edited rather than parsed out of crontab, and so that a missed moment is self-healing rather than lost.
8. As a maintainer, I want the persistence set kept to the enforcement spec's authoritative list, so that we neither lose bedtime on reboot nor write to flash more than the data actually changes.
8b. As a parent, I want my AdGuard exceptions to survive a reinstall, so that a panic-plus-reinstall cycle stops silently destroying rules I added by hand. This is the gap ADR 0002 recorded and ADR 0007 assigns to the tool's pull and push.
8c. As a parent, I want to install and update the router from one command on my laptop, so that deployment is a tested path rather than a script whose flags were dead for months without anyone noticing.
9. As a parent, I want the budget threshold calibrated against real idle devices, so that "240 minutes" describes something I would recognise as four hours and my child's phone does not spend it sitting in a pocket.
10. As a maintainer, I want the repo layout decided against the house style in `../netcage` (`main.go`, `cmd/`, `internal/<pkg>/`, `docs/adr/`), so that this repo looks like the others.
11. As a maintainer, I want the `verify` gate's future shape decided, so that when Go lands the gate composes cheap-first as in netcage (`gofmt` then `vet` then `build` then `test`) with the container acceptance run last.
12. As a maintainer, I want the acceptance tests to stay language-agnostic across the port, so that the same packet-path assertions gate both the shell implementation and its replacement, and a green-to-green transition is provable.
13. As a maintainer, I want a build plan sliced into follow-on specs with an explicit order, so that the port proceeds one responsibility at a time and each script is deleted only when the tests still pass without it.
14. As a maintainer, I want each answer recorded as an ADR where it carries a real why, so that the next reader does not have to re-derive the reasoning.

### Autonomy notes (the two gate axes)

`needsAnswers` is cleared. All six questions are decided and recorded above, three of them by measurement (the netlink spike, procd `respawn`, uhttpd basic auth) and three as product or ownership judgement supplied by the repo owner. Two were minted as ADRs (0007, 0008) because a launch snapshot is trimmed by `to-task` and these must outlive it.

`taskedAfter: [openwrt-packet-path-test-harness]`, because the acceptance tests are what make the port safe and they must exist before there is anything to hold an implementation to. This originally pointed at `enforcement-contract-and-packet-path-tests`, on the reasoning that the tests had to be green against the SHELL implementation first. That has been reversed by the repo owner, who decided the enforcement floor should be implemented in Go rather than built in shell and then ported, so the floor spec now depends on THIS one and the old edge would have made a cycle. The safety argument survives intact: the harness already exists and its packet-path assertions are language-agnostic by construction, which is what they were designed for.

`humanOnly` is omitted. Once the questions are answered the tasking itself is mechanical.

## Implementation Decisions

Deliberately few, since deciding them is the work.

**The exploration is bounded by its spikes.** Each spike answers one question on the narrowest real case and is then thrown away. The recorded answer is the deliverable; spike code is not kept unless it happens to become the harness.

**Measured starting point.** A cross-compiled aarch64 binary with `net/http`, `encoding/json` and `github.com/google/nftables` is 5.6 MB, static, CGO-free. Against 8 GB eMMC and 1 GB RAM already running AdGuard Home, size is not a constraint, so it should not feature in the decision.

**What a daemon would structurally fix**, and therefore what the exploration must confirm is really available: expiry that does not depend on an orphan process, state that survives a reboot by intent rather than accident, a schedule that is data, JSON that is generated rather than hand-escaped, and no per-request shell fork.

**Recorded decisions that constrain this exploration.** Three ADRs already fix parts of the answer and must not be re-litigated by a spike: budget semantics are actual-use gated by a threshold (`0001`), so the accounting mechanism must be able to measure traffic per profile; AdGuard Home owns DNS filtering and its own configuration is unmanaged state that a config story must capture (`0002`); and the config schema splits into a device registry plus profiles that group devices by name, with ungoverned devices allowed but unrestricted (`0003`). Whatever config format this exploration lands on has to express `0003` and carry AdGuard's hand-made settings.

**House style is the default, not a question.** Follow `../netcage` unless there is a reason not to: module path `github.com/wighawag/my-router`, `main.go` plus `version.go` at root, `cmd/`, `internal/<pkg>/`, ADRs in `docs/adr/`. (Verified: netcage is a Go tool at that layout.)

### The six questions this spec launched with, now decided

Recorded here because several were answered by measurement rather than by choice, and a reader who does not know which is which will reopen them.

**1. The tool serves HTTP on its own port.** It does not stay behind uhttpd as CGI. A daemon has to exist anyway for reconciliation, so CGI would mean the daemon exists AND a per-request fork that shells into the same state, which is two paths to one truth and the exact pattern behind every bug in the Problem Statement. Owning the port also deletes three known defects: uhttpd's `script_timeout` (the CGI stall, recorded in `uhttpd-cgi-timeout-and-backgrounded-children`), the CGI hardcoding its script path and passing no environment (which is why testing it needed an install-path decision), and auth being limited to what a realm file expresses. Accepted cost: the tickets page moves off port 80, so the household's bookmark changes. HTTP basic auth on the real `uhttpd` was measured to work and to gate `/cgi-bin`, so CGI was a viable alternative and is rejected on ownership grounds, not capability.

**2. The tool absorbs everything.** All three enforcement scripts (`setup-firewall.sh`, `parental-profiles.sh`, `website-blocking.sh`), and also `setup-adguard.sh`, `panic-off.sh` and installation. Absorbing the enforcement three is all-or-nothing: a Go tool beside any one of them recreates the shared-chain hazard, which is story 5's whole concern. See `docs/adr/0007-the-tool-owns-every-operation-including-recovery-and-deployment.md`, which also records the ONE thing that stays shell and why it is not a duplicate of the `panic-off` command. `blocklists.sh` is retired outright under ADR 0002, not absorbed.

**3. An in-process reconcile loop replaces cron, with procd `respawn` for resilience.** No cron at all. The restart-resilience cron was providing is better supplied by procd, which supports `respawn` (verified present in the real image at `/lib/functions/procd.sh`). What makes dropping cron safe is not the supervisor but the LEVEL-TRIGGERED design: desired state is recomputed from the clock and config on every tick, so a missed tick, a crash mid-cycle or a restart is self-healing. The requirement is therefore that reconciliation is idempotent; the interval is a tuning knob, not a decision.

**4. Nothing survives a reboot beyond what the enforcement spec already lists.** That list is authoritative and must not be restated: the `manual` reason, the `schedule` reason, the usage counter, the day marker. Tickets and guest passes die with the router by design. **The scheduler is deliberately stateless**, because desired state is derived rather than remembered, which dissolves the question rather than answering it. The one genuine remainder is AdGuard's own configuration, which ADR 0002 records as load-bearing state nothing manages and which was destroyed once by a panic-plus-reinstall cycle; it comes under the pull and push story of ADR 0007.

**5. Installation is a tool command, run from the laptop.** This reverses the initial recommendation, and the reason is worth recording because it was not obvious: bringing AdGuard's config under pull and push means the tool must SSH into the router from the laptop ANYWAY, so keeping `install.sh` in shell would mean maintaining a second SSH implementation for the same job. The house precedent (netcage ships an `install.sh`) does not apply once the tool needs SSH for its own features. `install.sh` shrinks to at most a bootstrap that fetches or builds the binary. Its current defects go with it: every `ssh` call ends in `2>/dev/null`, and `--force` and `--setup` are both dead because they are reset after the argument loop.

**6. Schedules live in their own file, in a tool-owned structured format.** Decided in `docs/adr/0008-configuration-is-tool-owned-structured-files-split-by-concern.md`, which answers the larger question hiding inside this one: pipe-delimited files cannot express a window with a day-of-week set, and a tool rewriting them destroys the hand-written comments that carry every device's name. That ADR also lands the config-schema half of ADR 0003.

## Testing Decisions

The packet-path harness from the enforcement spec is the acceptance surface, unchanged. It asserts on packets and on one HTTP response-time regression guard, so it is indifferent to the implementation language, which is precisely what makes it the right gate for a rewrite: green before, green after. Note that the harness the enforcement spec builds is packet-focused: if the port's green-to-green proof needs a broader HTTP acceptance surface (status endpoint shape, headers, auth), building that surface is part of THIS work, not something to assume already exists.

Spikes are judged by whether they answer their question, not by test coverage. The netlink spike specifically must assert at the packet level (a MAC added to a timeout set actually stops traffic) rather than merely returning success from a netlink call, since "the API returned no error" is exactly the kind of evidence this project has already been burned by.

## Out of Scope

- Building the tool. This spec produces confidence and a plan; the capability is built by the follow-on specs it emits.
- The rich status page and guest access (`work/notes/ideas/rich-status-page-guest-access-and-config-ownership.md`), which the build plan will draw from once the seams are pinned. Config OWNERSHIP is no longer wholly out of scope: ADR 0007 puts pull and push in the tool and ADR 0008 fixes the format, so what remains for the build plan is the migration and the secret-handling question, not the decision.
- Changing what AdGuard Home FILTERS, or the DNS design of ADR 0002. Bringing AdGuard's configuration under pull and push IS in scope, as the thing that closes the gap ADR 0002 recorded; changing the filtering itself is not.
- Rewriting the enforcement fix in shell first. That plan was reversed: the enforcement floor is built in Go, and `enforcement-contract-and-packet-path-tests` is now ordered AFTER this spec rather than before it.

## Further Notes

The reasoning behind the port, the measured numbers and the rejected alternatives were consolidated into this spec when the investigation document was deleted. The external facts that bear on the decision are findings: `openwrt-nftables-json-and-ether-timeout-sets` (structured output is available, which matters mainly once the logic is in a language with a JSON decoder) and `rootless-container-netns-nftables-requirements` (the acceptance surface the port must stay green against).

**The sequencing was reversed, and the trap it was avoiding still has to be handled another way.** The original order put the enforcement fix in shell first, so that a rewrite and a bug fix were never the same change and it was always clear which of the two broke the household's internet. The repo owner reversed it: the floor is built in Go, and the enforcement spec now declares `taskedAfter` this one. The netlink spike is what made that safe to consider, because it showed a whole ruleset can be replaced atomically, which deletes the most defect-prone rule the shell design needed.

The original trap does not disappear, it changes shape. Since there will be no green shell implementation to diff against, the discipline that replaces it is: the packet-path assertions are written and RED first, against the defects they describe, and the Go implementation turns them green one at a time. That is the same protection (a failing test that names the defect) obtained without shipping an implementation twice. The harness already exists and its assertions are language-agnostic, which the spike confirmed matters: a Go ruleset renders differently in `nft` text while behaving identically, so text assertions would not have survived a port and packet assertions do.

One consequence to carry into the build plan: the household keeps a system that reports success while enforcing nothing until the Go floor lands. The repo owner has accepted that explicitly. The `family` profile's `0 24 * * *` line is a live landmine in that window, since it means the profile blocks every hour once enforcement starts working; see `busybox-crond-treats-a-bad-time-field-as-a-wildcard`.
