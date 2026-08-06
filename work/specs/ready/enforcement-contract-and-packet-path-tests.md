---
title: Enforcement contract
slug: enforcement-contract-and-packet-path-tests
needsAnswers: true
taskedAfter: [openwrt-packet-path-test-harness]
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

These are recorded as unresolved after three review rounds in which each attempt to decide them in prose introduced a new defect. They are design decisions with real trade-offs, not details, and guessing at them is what produced the last two rounds of rework.

One question was dropped from this list on review because it turned out to be answerable from the repo rather than a genuine choice: who creates the `websites` chain. nftables rejects a jump to a chain that does not exist, and the alternative (letting `website-blocking.sh` add the jump) would append it after the terminal `accept`, where it never runs. So the skeleton owner must create the empty chain and its jump, and that is now recorded as a decision below rather than a question.

1. **Is a block reason a SET or a SCALAR?** A scalar breaks: a schedule-blocked profile that later crosses its budget has its reason overwritten to `budget`, and the daily reset (which unblocks only budget blocks) then clears the bedtime block, handing out internet from midnight. Either reasons accumulate as a set and a block lifts only when the set empties, or schedule and manual outrank budget and are never overwritten. This decision shapes the whole state model and the status UI that later reads it.
2. **Can the system even distinguish `schedule` from `manual`?** Both are produced by the identical `parental-profiles.sh block <profile>` invocation, from cron and from a parent's shell. There is no lever to tell them apart. Either add an explicit discriminator (a flag or a second verb), or collapse the enum and accept that "a human did this" is not knowable.
3. **Is the usage counter persisted?** Both answers break something. Not persisted: after a reboot the day marker survives so no reset fires, but the counter restarts at zero, the budget crossing is hit a second time the same day, and a profile a parent manually unblocked is re-blocked. Persisted: `budget-check` runs every minute from cron, so the counter is written to flash 1440 times per day per profile. A third option (derive usage from the accounting counters ADR 0001 requires) may dissolve the question entirely.
4. **Which script owns boot restore, and what verb performs it?** Restoring persisted blocks has been assigned both to `setup-firewall.sh apply` and to the init script. It cannot be both: if `apply` restores, then every `install.sh` run and every manual `apply` silently re-imposes old blocks, which the `panic-off.sh` recovery path forbids. No restore subcommand exists in any script today and one must be named.
5. **How far does fail-loud extend?** Removing the `none` backend deletes today's only warning on a missing `nft`. `parental-profiles.sh` is covered below, but `setup-firewall.sh` (the sole owner of the skeleton AND the boot path) and `website-blocking.sh` still swallow every error and exit 0 printing success. Hardening one of three callers leaves the signature defect in the one that matters most at boot.
6. **What tracked change makes the `family` night block fire?** The defect (`0 24 * * *`, an hour cron never runs) exists only in `config/local/crontab`, which is gitignored, and the `family` profile exists only in `config/local/parental_profiles`. The shipped default schedules different profiles at valid hours. So there is no tracked file to fix. Options: validate cron hours in the installer's crontab merge and reject or correct out-of-range values; scrub the bad line during the merge; or drop the story and leave it to the operator. Currently it is promised by a user story and delivered by nothing.

<!-- /open-questions -->

## Problem Statement

The parental control system reports success while enforcing nothing.

On the real router, `/etc/init.d/parental-allowlist` runs `setup-firewall.sh apply` at boot, which creates the `parental_control` table. Afterwards `parental-profiles.sh nft_init` short-circuits on "the table already exists", so the `blocked_macs` set is never created and every `nft add element` fails into `2>/dev/null`. The script still writes `blocked` to its state file and still logs "Profile blocked". Bedtime, budgets, website blocking and ticket expiry are all firewall no-ops after any reboot, while the CLI, the logs and the state files all claim they worked.

Reproduced by replaying the production boot order and sending a real packet from a client with a blocked MAC:

```
after 'block eli'          : INTERNET-REACHED   (script state file says: blocked)
unknown MAC                : UNREACHABLE       (the allowlist genuinely works)
--- test order: block first, then apply ---
block eli (no allowlist)   : UNREACHABLE       (what the test suite exercises)
then boot-time apply runs  : INTERNET-REACHED   (a reboot silently unblocks)
```

The same blind spot hides three more defects: rules appended after a terminal `accept` are unreachable; `budget-check` re-blocks a profile every minute after exhaustion, killing a freshly issued ticket within 60 seconds; and the ticket CGI holds the HTTP response open for the entire ticket duration because a backgrounded `sleep` inherits the command-substitution pipe.

A parent cannot tell any of this from the outside. The system's failure mode is not crashing, it is lying.

## Solution

An explicit ordering contract in the firewall, owned by one script instead of three appending blindly into a shared chain.

Tickets and guests become nftables sets with kernel-managed timeouts, which places ticket precedence above both internet blocks and website blocks by position, and deletes the backgrounded `sleep`, the saved-rules save/restore dance and the CGI stall along with it. Block state is persisted outside tmpfs and restored at boot, so a reboot stops silently handing out internet.

The parent-visible outcome: when the system says a child is blocked, the child is blocked, and it stays that way across a reboot.

The testbed that proves any of this is delivered separately by `openwrt-packet-path-test-harness`, which this spec is ordered after and whose assertions it extends.

## User Stories

1. As a parent, I want a blocked child to actually lose internet access, so that bedtime is enforced rather than merely logged.
2. As a parent, I want a block to survive a router reboot, so that a power cut at 22:30 does not silently hand out internet until morning.
3. As a parent, I want a blocked website to actually be unreachable for that child, so that the streaming and gaming schedules mean something.
4. As a parent, I want a ticket I issue to override a bedtime block and a website block at the same time, so that "30 minutes now" means what it says.
5. As a parent, I want a ticket to expire on its own even if the router reboots or a process dies, so that a child never keeps access indefinitely because a background process vanished.
6. As a parent, I want a ticket to survive the next minute's budget check, so that granting time actually grants time.
7. As a parent, I want an expired ticket to leave the child blocked again, so that expiry restores the schedule rather than leaving a hole.
8. As a parent who manually unblocks a child after their budget ran out, I want that to stick for the rest of the day, so that the budget checker does not immediately undo me.
9. As a parent, I want the system to fail LOUDLY if the firewall tool is missing or broken, so that it can never report a child as blocked while silently enforcing nothing.
10. As a parent tapping a duration on my phone, I want the page to answer immediately, so that I am not left watching a spinner for a minute wondering whether it worked.
11. As a visitor's device that belongs to no profile, I want to stay blocked from the internet, so that the allowlist keeps meaning something. This already works, and it is proven at the packet level by `openwrt-packet-path-test-harness`, so it needs no second assertion here; it is listed to record that this spec must not regress it.
12. As a maintainer, I want one script to own the chain skeleton and the others to touch only their own sets and chains, so that three scripts appending into one chain can no longer produce order-dependent behaviour.
13. As a maintainer, I want a single firewall implementation, so that this restructure is not performed twice across a dead second backend.
14. As a maintainer, I want disabling one profile's website rule to leave every other profile's rules untouched, so that the 08:00 cron sweep does not silently clear the whole household.
15. As a maintainer, I want ticket and guest expiry handled by kernel set timeouts, so that expiry does not depend on an orphaned `sleep` surviving a CGI request.
16. As a maintainer, I want the CGI to return promptly and never inherit a long-lived child's stdout, so that uhttpd's script timeout is not the mechanism that ends the request.
17. As a maintainer, I want `install.sh --force` and `--setup` to actually take effect, so that the documented recovery and provisioning paths are not dead code.
18. As a maintainer, I want the suite to replay the production boot order (`apply` first, then `block`), so that the order that actually happens on the router is the order under test.
19. As a parent, I want the `family` profile's night block to fire, so that a cron hour of `24`, which never runs, stops silently disabling it. (Delivery is open question 6: the defect lives only in a gitignored file, so a tracked mechanism has to be chosen.)

### Autonomy notes (the two gate axes)

`needsAnswers: true`. Seven decisions above are genuinely unresolved, and three review rounds have shown that deciding them in prose without being able to execute the state machine produces a new defect each time. Questions 1, 3 and 5 in particular have each already caused a regression that a subsequent round had to catch. Flagging the spec is the honest outcome; a falsely-complete spec would fan that ambiguity out across seven or more tasks at once.

`taskedAfter: [openwrt-packet-path-test-harness]`, because the packet-path assertions below are unwritable until that harness exists.

`humanOnly` is omitted: once the questions are answered the tasking itself is mechanical.

## Implementation Decisions

Recorded where settled. Where a decision is gated by an open question, that is stated rather than papered over.

**Chain skeleton, owned solely by the allowlist script.** A base `forward` hook (priority -10, policy accept) narrows to LAN-to-WAN and jumps to a regular `parental` chain holding the ordering contract:

```
ether saddr @ticket_macs accept   # 1. tickets override everything (kernel timeout)
ether saddr @guest_macs  accept   # 2. guests (kernel timeout)
ether saddr @blocked_macs drop    # 3. schedule / budget / manual blocks
jump websites                     # 4. per-profile website blocking
ether saddr @allowed_macs accept  # 5. known devices
drop                              # 6. unknown devices
```

Note for later: ADR 0001 requires traffic accounting that counts only traffic surviving enforcement. This skeleton reserves no place for it, so whoever adds counters reopens the ordering contract. Called out here so it is a known seam rather than a surprise.

**`apply` reconciles derived sets and preserves live ones.** `allowed_macs` is DERIVED from the profiles config and must be reconciled against it, because preserving it blindly would let a device removed from config keep internet forever. `blocked_macs`, `ticket_macs` and `guest_macs` are LIVE RUNTIME state and must be preserved: `apply` may rebuild rules, it may not flush those three. It must also leave the `websites` chain and its per-pair children in place.

This is the load-bearing invariant, and it is worth stating precisely what it does and does not fix, because an earlier draft got this wrong. Today `apply` flushes the forward CHAIN and `allowed_macs`; it never flushes `blocked_macs`, which after a reboot does not exist at all. So the reboot bug is not a flush, it is two independent causes: `nft_init` returning early once the table exists, so `blocked_macs` is never created; and all block state living in tmpfs, so nothing knows what to restore. The preservation rule above is a FORWARD invariant protecting the new design once `blocked_macs` is a persistent live set, not a description of today's defect. `docs/architecture.md` states the current-day causes correctly and should be read as the authority on what is broken now.

**Website blocking uses one chain per profile+rule, and the skeleton owner creates the parent chain.** `setup-firewall.sh` creates the empty `websites` chain and its jump as part of the skeleton, because nftables rejects a jump to a nonexistent chain and because a jump added later by `website-blocking.sh` would land after the terminal `accept` and never run. `website-blocking.sh` then owns only the contents: the `websites` chain holds jumps to `websites_<profile>_<rule>` chains, each holding that pair's drop rules and owning its `blocked_sites_<profile>_<rule>` set. `disable <profile> <rule>` removes ONLY that chain, its jump, and its own set. A blanket flush of the shared chain is forbidden: the shipped default has three profiles disabling `no_streaming` at 08:00 in the same minute that gaming rules are enabled, so a shared flush would clear other profiles' live blocks.

**Block state is persisted outside tmpfs and carries a reason.** Per-profile block state moves to a persisted file under `/etc/config/`. Sysupgrade preservation for that directory is VERIFIED (it is listed in the keep list). Inclusion in the router's own backup is an ASSUMPTION, inferred from the backup being built off the same keep list and not measurable from a container; it needs one check on the real router, and it is stated here as an assumption rather than a decision so nobody mistakes it for settled. Its location must be overridable by an env lever alongside `PARENTAL_STATE_DIR`, so tests can isolate it and the boot-restore path can be exercised. The reason model itself is open question 1, and whether the usage counter joins it is open question 3.

The **daily-reset marker is persisted too**, and this is load-bearing. Today `reset_usage` fires whenever the day marker does not match today and calls `unblock_profile` unconditionally. Both facts combine into a boot-time trap: the marker lives in tmpfs, so after a reboot it is missing, the next `budget-check` concludes a new day started, and the profile is unblocked, silently undoing any boot restore within 60 seconds. Persisting the marker removes the spurious trigger. The daily reset must additionally clear only budget state, never a schedule or manual block, subject to open question 1.

**Budget exhaustion blocks on the crossing minute only**, defined as `used-1 < budget <= used`, and does nothing on subsequent minutes. This is correct ONLY under an answer to open question 3 in which the usage counter survives a reboot: if the counter restarts at zero, the crossing is reached a second time the same day and a manually unblocked profile is re-blocked. Pinning it to the crossing rather than to "over budget and not currently marked" is what makes story 8 work: a parent's explicit unblock is not re-blocked a minute later, because the crossing has already passed. `issue_ticket` no longer calls `unblock_profile`: a ticket adds MACs to `ticket_macs`, and chain precedence does the rest, so the underlying block is still there when the ticket expires.

**The iptables backend goes, and its removal must not introduce a silent failure.** The fallback is provably dead: `PARENTAL_FIREWALL` is never exported by the installer, cron, the CGI or the compose file; `setup-firewall.sh` builds the allowlist with `nft` only; and `panic-off.sh` deletes only the nftables table. A router genuinely running the iptables backend would have an nft-only allowlist and a recovery script that could not undo its own blocks, which is the strongest evidence nothing depends on it. The trap is in the removal: `detect_firewall` can return `none`, and `block_mac` then logs a warning. With that branch gone, and every nft call still ending in `2>/dev/null`, a missing `nft` becomes a silent no-op that writes `blocked` and logs success. Scope of the fail-loud requirement is open question 5. The iptables MOCK and its tests are removed by the harness spec; this spec removes the code. That mock removal is a deliberate choice rather than a consequence of the image swap (the mock is plain POSIX shell and would run fine on OpenWrt), so the loss of coverage for the iptables path until this spec lands is knowingly accepted, not incidental.

**`--force` gains a defined meaning.** Non-force `apply` preserves live state as above; `--force` additionally clears the persisted block state and the ticket and guest sets. Without this the flag would print "active blocks cleared" while clearing nothing.

**File-by-file intent**, recorded to seed the tasking:

| File | Change |
|---|---|
| `scripts/setup-firewall.sh` | build the skeleton; sole owner of `forward`/`parental`; create `ticket_macs`, `guest_macs`, `blocked_macs`, `allowed_macs`; reconcile `allowed_macs`, preserve the live sets and the `websites` chains on `apply` |
| `scripts/parental-profiles.sh` | `nft_init` ensures each object individually; delete the background `sleep` expiry and the saved-rules save/restore; `ticket` adds to `ticket_macs` with a timeout and stops calling `unblock_profile`; `tickets` reads the set; persist block state on change |
| `scripts/parental-profiles.sh` | budget: block on the crossing minute only; daily reset clears budget state only |
| `scripts/parental-profiles.sh` | remove the iptables backend, the backend-detection dispatch, the `none` backend, the `backend` subcommand and the "Firewall backend" line in `status` |
| `scripts/website-blocking.sh` | own the per-pair child chains; `disable` removes only its own chain, jump and set |
| `web/cgi-bin/ticket` | detach any remaining background work; note it hardcodes the script path and passes no env, so the isolation lever for tests must be named |
| `install.sh` | fix the `FORCE`/`SETUP` reset bug; implement the `--force` semantics above |
| `scripts/panic-off.sh` | clear the persisted block state too, so its "State cleared" message stays true; its documented re-enable path is a plain `install.sh`, which must not silently restore old blocks |
| `scripts/setup-firewall.sh` | remove `generate_init_script`, a second boot-script generator whose `start_service` body interpolates to empty and which executes `apply_nft` at generation time. `install.sh` writes the working one |
| `/etc/init.d/parental-allowlist` (generated by `install.sh`) | if open question 4 makes the init script the boot-restore owner, this is where the restore call lands, after `setup-firewall.sh apply` |
| `test/parental-profiles.bats`, `test/website-blocking.bats` | drop the now-meaningless `PARENTAL_FIREWALL="nft"` exports once the backend abstraction is gone; the harness spec removes the iptables CASES but not these two lines |
| docs | stale-doc sweep: README (`parental_websites` and the "auto-detected, iptables fallback" feature line), `docs/setup-guide.md`, `docs/example-5-profiles.md`, `config/block_rules.example`, `config/local/README.md`, and **`docs/architecture.md`** (which describes the iptables abstraction and lists `PARENTAL_FIREWALL` as a seam to extend, and which both task prompts tell builders to read first). NOT the test-count and test-environment claims: those ship from `refresh-test-environment-docs` under the harness spec, so do not re-fix them here and do not collide with it |

**Risk control.** This changes the rule that decides whether the household has internet. A wrong ruleset costs WAN, never LAN, so SSH recovery is always available, and `panic-off.sh` remains the escape hatch. First deployment to the live router should apply with a rollback timer cancelled once verified.

## Testing Decisions

The seam is the packet path, using the harness delivered by `openwrt-packet-path-test-harness`. Assert reachable/unreachable, not ruleset text, because ruleset text is what looked correct while the system enforced nothing.

Assertions to write. Each fails against current `main`, which is the point.

1. Production boot order (`apply`, then `block <profile>`) leaves the profile UNREACHABLE.
2. Re-running `apply` (the reboot path) leaves an already-blocked profile UNREACHABLE.
3. A blocked profile is UNREACHABLE after a simulated reboot **and remains so after `budget-check` runs**. The cron step is mandatory: without it the test cannot see the daily-reset trap, and a test that cannot see the failure is the defect this spec exists to remove.
4. A profile blocked by SCHEDULE that then crosses its budget is still UNREACHABLE after the next daily reset. This is the assertion that catches open question 1 getting answered wrongly, and it must drive the profile through budget exhaustion while schedule-blocked rather than merely rolling the day over.
5. A website rule enabled for a profile makes a blocked destination UNREACHABLE for that profile's MAC while another destination stays reachable.
6. Website blocking still enforces after `apply` and after a simulated reboot (the `jump websites` wiring of open question 4).
7. Disabling one profile+rule leaves another profile's active rule still enforcing.
8. A ticket makes a schedule-blocked profile REACHABLE.
9. A ticket makes a website-blocked destination REACHABLE for that profile.
10. After the ticket's kernel timeout elapses, the profile is UNREACHABLE again with no background process involved.
11. Budget exhaustion during a live ticket does NOT make the profile unreachable.
12. An explicit `unblock` after budget exhaustion survives the next `budget-check`, and survives a reboot.
13. With `nft` unavailable, `block <profile>` FAILS loudly: non-zero exit, and the state file NOT left claiming the profile is blocked.
14. The ticket CGI returns in under two seconds, served by the real `uhttpd`.
15. `install.sh --force` and `--setup` reach their decision points. The only existing coverage greps `install.sh` source text and passes today despite the flags being dead, which is exactly the test-that-cannot-see-its-failure pattern this spec abolishes.

**Existing tests that must CHANGE, not be preserved.** The sweep is larger than a passing mention: `test/setup-firewall.bats` asserts `accept`/`drop`/`blocked_macs` in the `forward` chain, which the skeleton moves to `parental`; eleven assertions in `test/website-blocking.bats` grep the forward chain for `blocked_sites_*` comment tags, which the per-pair design removes; `test/parental-profiles.bats` asserts a ticket unblocks the MAC immediately and that a ticket removes the website rule, both of which the new design deliberately stops doing. That last pair is dangerous: an agent told "these must still pass" can satisfy them by re-adding `unblock_profile` to `issue_ticket`, destroying story 7 and reopening a fixed bug. Enumerate them as intended breakages when tasking.

Also note `SLEEP` and `PARENTAL_SKIP_AUTOBLOCK` become dead levers once the backgrounded expiry goes, and no row currently owns removing them from the scripts' usage text and the test setup.

## Out of Scope

- **The test harness itself**, delivered by `openwrt-packet-path-test-harness` and ordered before this spec.
- **What a budget minute MEANS.** Settled by `docs/adr/0001-budget-counts-actual-use-gated-by-a-threshold.md`: actual use above a threshold. The measurement mechanism and threshold belong to the exploration spec. This spec only stops the budget from cancelling a live ticket and from re-blocking every minute.
- **The device registry of ADR 0003.** This spec keeps the allowlist derived from profile membership, deliberately, pending the config-ownership work. Named here because ADR 0003 describes the opposite end state and a tasker reading both would otherwise hit an unrecorded conflict.
- **A reboot that spans a schedule boundary, in both directions.** Boot restore replays the last known block state, not the schedule, so a missed cron event stays missed. Fail-safe: a router down from 07:59 to 08:05 comes back still blocked. Fail-OPEN, which matters more: a router down from 21:58 to 22:05 never runs the `0 22` block, so bedtime does not happen that night. Story 2 promises "a block already in force survives a reboot", not "the schedule is reconstructed".
- **Website blocking state across a reboot.** The per-pair chains and their `_websites` state files are not restored at boot, so a 21:00 power cut drops the streaming block until the next 20:00. A distinct gap from the one above, named rather than implied.
- **`guest_macs` is created but never populated.** The set and its accept rule ship as part of the ordering contract so guest access can be added later without touching the skeleton. Nothing here grants a guest pass.
- The Go tool, the rich status page, guest access UI and config editing.
- AdGuard Home, blocklists and DNS filtering.

## Further Notes

The investigation that produced this spec was consolidated into the work items and its working document deleted. Durable external facts live as findings: `openwrt-nftables-json-and-ether-timeout-sets`, `uhttpd-cgi-timeout-and-backgrounded-children`, and `rootless-container-netns-nftables-requirements`.

This spec absorbed `remove-iptables-fallback` (recorded in `work/tasks/cancelled/`) and was itself split, with its harness half moved to `openwrt-packet-path-test-harness`.

Expect the gate to go RED once this spec's tests land and stay red until the fix completes. `autoBuild` must stay off in between. The harness spec, by contrast, keeps the gate green.
