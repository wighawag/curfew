---
title: Explore replacing the shell scripts with a Go tool
slug: explore-go-tool-for-parental-control
needsAnswers: true
taskedAfter: [enforcement-contract-and-packet-path-tests]
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this spec settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

<!-- open-questions -->
<!--
  TRANSIENT BLOCK — stripped by the apply rung on full resolution.
  While the spec has unresolved questions blocking autonomous tasking:
    1. Set `needsAnswers: true` in the frontmatter above.
    2. List the questions under the `## Open questions` heading below.
    3. Clear the flag (and let apply strip this block) once they are answered.
  Delete the whole fenced block — markers and all — if the spec launches fully resolved.
-->

## Open questions

1. Does the tool serve HTTP itself on its own port, or stay behind uhttpd as CGI? Owning the port removes uhttpd's script timeout and the per-request shell fork; staying behind uhttpd keeps one web server and one firewall hole.
2. How far does the Go tool go? Candidates to absorb: `parental-profiles.sh`, `website-blocking.sh`, `setup-firewall.sh`, `setup-adguard.sh`, `install.sh`. (`blocklists.sh` is NOT a candidate: it is being retired outright, per `docs/adr/0002-adguard-home-owns-dns-filtering.md`.) The argument for keeping `panic-off.sh` as dependency-free shell is that it is what you run when the tool is what broke, so it must share no failure surface with the tool. Note the house precedent: `../netcage` is a Go tool that still ships an `install.sh`.
3. What replaces cron? An in-process scheduler is required for the UI to render "blocked until 08:00" at all, but cron currently provides restart-resilience for free.
4. Beyond block state, what else must survive a reboot? The enforcement spec already decides the two clear cases (per-profile block state persists; tickets and guest passes die with the router, which is correct for a time-limited grant). What remains open is usage counters, the AdGuard exception set, and anything the scheduler needs, weighed against writing to flash.
5. Does `install.sh` become a Go subcommand (`parental install <ip>`) running on the laptop, or stay shell?
6. Should the schedule live in the same config file as profiles and devices, or its own? This is the question that decides whether the UI can render and edit timings.

NOT listed here, deliberately, because they are deliverables rather than decisions a human can supply: whether `github.com/google/nftables` drives OpenWrt's kernel (stories 1 and 2 answer it), and the budget threshold value (story 9 calibrates it). Gating tasking on a question that can only be answered by doing the work would deadlock the spec.

<!-- /open-questions -->

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

1. As a maintainer, I want to know whether `google/nftables` drives OpenWrt's kernel, so that the tool's core mechanism is proven before anything is built on it.
2. As a maintainer, I want the netlink spike run inside the real `openwrt/rootfs` image against the packet-path harness, so that the answer reflects the router's kernel interface and not a convenient Linux container.
3. As a maintainer, I want a recorded fallback position if netlink disappoints (shelling out to `nft` behind an interface), so that a negative result costs a day rather than the approach.
4. As a maintainer, I want the HTTP seam decided (own port versus uhttpd CGI), so that the status page spec can be written against a known surface.
5. As a maintainer, I want the tool-versus-shell boundary decided explicitly, so that we do not end up with a Go tool and a parallel set of scripts that both think they own the firewall.
6. As a parent, I want whatever recovery path survives to work when the tool itself is broken, so that a bad deploy never leaves the household with no internet and no way back.
7. As a maintainer, I want the scheduler approach decided, so that "blocked until 08:00" can be rendered and edited rather than parsed out of crontab.
8. As a maintainer, I want the state-persistence question answered against flash-wear reality, so that we neither lose bedtime on reboot nor write to eMMC every time a ticket is issued.
9. As a parent, I want the budget threshold calibrated against real idle devices, so that "240 minutes" describes something I would recognise as four hours and my child's phone does not spend it sitting in a pocket.
10. As a maintainer, I want the repo layout decided against the house style in `../netcage` (`main.go`, `cmd/`, `internal/<pkg>/`, `docs/adr/`), so that this repo looks like the others.
11. As a maintainer, I want the `verify` gate's future shape decided, so that when Go lands the gate composes cheap-first as in netcage (`gofmt` then `vet` then `build` then `test`) with the container acceptance run last.
12. As a maintainer, I want the acceptance tests to stay language-agnostic across the port, so that the same packet-path assertions gate both the shell implementation and its replacement, and a green-to-green transition is provable.
13. As a maintainer, I want a build plan sliced into follow-on specs with an explicit order, so that the port proceeds one responsibility at a time and each script is deleted only when the tests still pass without it.
14. As a maintainer, I want each answer recorded as an ADR where it carries a real why, so that the next reader does not have to re-derive the reasoning.

### Autonomy notes (the two gate axes)

`needsAnswers: true`, because the seven questions above are genuinely unresolved and several are product judgement rather than technical discovery (5, 6, 7 especially). Auto-tasking this now would fan out tasks premised on decisions nobody has made.

`taskedAfter: [enforcement-contract-and-packet-path-tests]`, because the acceptance tests are what make the port safe: they must exist and be green against the shell implementation before there is anything to hold the Go implementation to.

`humanOnly` is omitted. Once the questions are answered the tasking itself is mechanical.

## Implementation Decisions

Deliberately few, since deciding them is the work.

**The exploration is bounded by its spikes.** Each spike answers one question on the narrowest real case and is then thrown away. The recorded answer is the deliverable; spike code is not kept unless it happens to become the harness.

**Measured starting point.** A cross-compiled aarch64 binary with `net/http`, `encoding/json` and `github.com/google/nftables` is 5.6 MB, static, CGO-free. Against 8 GB eMMC and 1 GB RAM already running AdGuard Home, size is not a constraint, so it should not feature in the decision.

**What a daemon would structurally fix**, and therefore what the exploration must confirm is really available: expiry that does not depend on an orphan process, state that survives a reboot by intent rather than accident, a schedule that is data, JSON that is generated rather than hand-escaped, and no per-request shell fork.

**Recorded decisions that constrain this exploration.** Three ADRs already fix parts of the answer and must not be re-litigated by a spike: budget semantics are actual-use gated by a threshold (`0001`), so the accounting mechanism must be able to measure traffic per profile; AdGuard Home owns DNS filtering and its own configuration is unmanaged state that a config story must capture (`0002`); and the config schema splits into a device registry plus profiles that group devices by name, with ungoverned devices allowed but unrestricted (`0003`). Whatever config format this exploration lands on has to express `0003` and carry AdGuard's hand-made settings.

**House style is the default, not a question.** Follow `../netcage` unless there is a reason not to: module path `github.com/wighawag/my-router`, `main.go` plus `version.go` at root, `cmd/`, `internal/<pkg>/`, ADRs in `docs/adr/`.

## Testing Decisions

The packet-path harness from the enforcement spec is the acceptance surface, unchanged. It asserts on packets and on one HTTP response-time regression guard, so it is indifferent to the implementation language, which is precisely what makes it the right gate for a rewrite: green before, green after. Note that the harness the enforcement spec builds is packet-focused: if the port's green-to-green proof needs a broader HTTP acceptance surface (status endpoint shape, headers, auth), building that surface is part of THIS work, not something to assume already exists.

Spikes are judged by whether they answer their question, not by test coverage. The netlink spike specifically must assert at the packet level (a MAC added to a timeout set actually stops traffic) rather than merely returning success from a netlink call, since "the API returned no error" is exactly the kind of evidence this project has already been burned by.

## Out of Scope

- Building the tool. This spec produces confidence and a plan; the capability is built by the follow-on specs it emits.
- The rich status page, guest access and config ownership (`work/notes/ideas/rich-status-page-guest-access-and-config-ownership.md`), which the build plan will draw from once the seams are pinned.
- Any change to AdGuard Home or DNS filtering.
- Rewriting the enforcement fix. That ships in shell first, deliberately, so the household has working bedtimes while this exploration runs.

## Further Notes

The reasoning behind the port, the measured numbers and the rejected alternatives were consolidated into this spec when the investigation document was deleted. The external facts that bear on the decision are findings: `openwrt-nftables-json-and-ether-timeout-sets` (structured output is available, which matters mainly once the logic is in a language with a JSON decoder) and `rootless-container-netns-nftables-requirements` (the acceptance surface the port must stay green against).

The sequencing trap worth restating: doing the rewrite and the bug fixes as one change means nothing tells you which of the two broke the household's internet. That is why this spec is ordered behind the enforcement work rather than replacing it.
