---
title: Enforcement contract
slug: enforcement-contract-and-packet-path-tests
taskedAfter: [openwrt-packet-path-test-harness, explore-go-tool-for-parental-control]
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this spec settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

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

The same blind spot hides three more defects: rules appended after a terminal `accept` are unreachable; `budget-check` re-blocks a profile every minute after exhaustion, killing a freshly issued ticket within 60 seconds; and the ticket CGI leaves the HTTP request hanging until uhttpd's own script timeout ends it (60 seconds, not the ticket's duration) because a backgrounded `sleep` inherits the command-substitution pipe.

Resolving this spec's open questions surfaced three more, each measured on the real image rather than reasoned about, and each changing a decision that had been taken on a false premise:

**There is no warning to lose.** With `nft` absent, `block <profile>` prints nothing on stdout, nothing on stderr, exits 0, and writes `blocked`. The `none` backend's warning goes to `logger`, which exits 0 whether or not anything is listening, so the fallback `echo` to stderr never fires. `setup-firewall.sh apply` is marginally louder (it leaks "not found" to stderr from the three `nft` calls that lack a redirect) and still prints `MAC allowlist applied` and returns 0 to procd at boot.

**A mistyped cron hour silently inverts a schedule instead of disabling it.** busybox crond treats an unparseable time field as a wildcard, so `0 24 * * * block family` runs at the top of every hour rather than never. With the matching `0 8 * * * unblock family`, which wins the 08:00 tie because same-minute jobs run in file order, the household effect is a profile blocked 23 hours a day and online from 08:00 to 09:00. It is invisible today only because enforcement is a no-op, which means fixing enforcement is what detonates it. Recorded in `work/notes/findings/busybox-crond-treats-a-bad-time-field-as-a-wildcard.md`.

**A blocked child can free themselves.** The block acts on forwarded traffic, not on traffic to the router, so a blocked device still reaches the router's own web server. Measured with the real CGI and the real `uhttpd`: a blocked client loaded the unauthenticated tickets page and issued itself a ticket, and its own state file then read `allowed`. The request appeared to fail (no response, because of the CGI stall) and freed it anyway.

A parent cannot tell any of this from the outside. The system's failure mode is not crashing, it is lying.

## Solution

An explicit ordering contract in the firewall, owned by one component instead of three appending blindly into a shared chain.

Tickets and guests become nftables sets with kernel-managed timeouts, which places ticket precedence above both internet blocks and website blocks by position, and deletes the backgrounded `sleep`, the saved-rules save/restore dance and the CGI stall along with it. Block state is persisted outside tmpfs and restored at boot, so a reboot stops silently handing out internet. The ticket page gains a password, because an unauthenticated page that grants internet is reachable by the child it is blocking.

The parent-visible outcome: when the system says a child is blocked, the child is blocked, and it stays that way across a reboot.

**This spec is the enforcement FLOOR: the nftables contract, and it lands in GO.** The split is by layer, not by time. The floor is which sets exist, what order they match in, what survives a reboot, what fails loudly, and who is allowed to ask for a ticket. That contract is identical in any language, which is why it is settled and packet-proven here rather than discovered during a port.

The implementation language is DECIDED: Go, not shell. An earlier draft planned a shell implementation to be ported later. That was reversed by the repo owner after a netlink spike, and the reversal is why this spec declares `taskedAfter: [explore-go-tool-for-parental-control]`: the exploration settles the repo layout, the netlink-versus-shell-out seam and the HTTP seam this floor is built on. Building the floor in shell first would mean writing the most defect-prone rule in this spec (see `apply` below) for the sole purpose of deleting it.

The POLICY layer above it is explicitly not here. Schedules as windows with day-of-week selectors, continuous reconciliation of desired state, budget accounting and today-extensions, and the status page all belong to the Go work, because they are what a shell implementation is worst at and they must not be built twice. The semantics they must honour are decided below so that the Go work inherits decisions rather than questions.

The testbed that proves any of this is delivered separately by `openwrt-packet-path-test-harness`, which this spec is ordered after and whose assertions it extends.

## User Stories

1. As a parent, I want a blocked child to actually lose internet access, so that bedtime is enforced rather than merely logged.
2. As a parent, I want a block to survive a router reboot, so that a power cut at 22:30 does not silently hand out internet until morning.
3. As a parent, I want a blocked website to actually be unreachable for that child, so that the streaming and gaming schedules mean something.
4. As a parent, I want a ticket I issue to override a bedtime block and a website block at the same time, so that "30 minutes now" means what it says.
5. As a parent, I want a ticket to expire on its own even if the router reboots or a process dies, so that a child never keeps access indefinitely because a background process vanished.
6. As a parent, I want a ticket to survive the next minute's budget check, so that granting time actually grants time.
7. As a parent, I want an expired ticket to leave the child blocked again, so that expiry restores the schedule rather than leaving a hole.
8. As a parent whose child has run out of their daily allowance, I want a way to give them more that actually holds, so that the budget checker does not undo me a minute later. Two gestures cover it, and a bare unblock is not one of them: a **ticket** for a fixed extra period, delivered HERE, and an **extension** that raises today's allowance, delivered by the policy layer and named in Out of Scope as a follow-up rather than silently missing. (Because the budget reason is derived from usage against allowance on every check rather than latched at the crossing minute, clearing the block on its own would simply be recomputed back. That is the intended behaviour, not a limitation: it removes the fragile crossing-minute rule an earlier draft needed to make a bare unblock stick.)
9. As a parent, I want the system to fail LOUDLY if the firewall tool is missing or broken, so that it can never report a child as blocked while silently enforcing nothing.
10. As a parent tapping a duration on my phone, I want the page to answer immediately, so that I am not left watching a spinner for a minute wondering whether it worked.
11. As a visitor's device that belongs to no profile, I want to stay blocked from the internet, so that the allowlist keeps meaning something. This already works, and it is proven at the packet level by `openwrt-packet-path-test-harness`, so it needs no second assertion here; it is listed to record that this spec must not regress it.
12. As a maintainer, I want ONE component to own the chain skeleton and everything else to touch only its own sets and chains, so that three writers appending into one chain can no longer produce order-dependent behaviour.
13. As a maintainer, I want a single firewall implementation, so that this restructure is not performed twice across a dead second backend.
14. As a maintainer, I want disabling one profile's website rule to leave every other profile's rules untouched, so that the 08:00 sweep cannot clear the whole household. This is a FORWARD invariant on the new per-pair-chain design, not a present defect: today's `disable` already removes only its own tagged rules and its own set.
15. As a maintainer, I want ticket and guest expiry handled by kernel set timeouts, so that expiry does not depend on an orphaned `sleep` surviving a CGI request.
16. As a maintainer, I want the CGI to return promptly and never inherit a long-lived child's stdout, so that uhttpd's script timeout is not the mechanism that ends the request.
17. As a maintainer, I want `install.sh --force` and `--setup` to actually take effect, so that the documented recovery and provisioning paths are not dead code.
18. As a maintainer, I want the suite to replay the production boot order (`apply` first, then `block`), so that the order that actually happens on the router is the order under test.
19. As a parent, I want a schedule that cannot silently come to mean something other than what I wrote. The `family` line `0 24 * * *` was believed to be a schedule that never fires; it is measurably a schedule that fires every hour, because busybox crond degrades a bad time field to a wildcard and tells nobody. A tracked validator was considered and rejected, because it hardens one spelling of a model that is wrong in general: cron expresses schedule EDGES, so a missed edge is missed forever and a corrupted field is undetectable. **This story is DELIVERED BY THE POLICY LAYER, not here**, and is listed only so it is not lost. The floor's entire contribution is that its operations are idempotent and re-assertable, so that a reconciler can drive them later without the floor changing; that property is carried by the `apply` and restore decisions below and needs no separate task.
20. As a parent, I want the ticket page to require a password, so that the child it is currently blocking cannot tap a button and let themselves back online. Measured as available on the real `uhttpd` with no extra package, and it gates the CGI as well as the page, which is the half that matters because the CGI is what issues tickets.
21. As a parent, I want an indefinite block I have imposed to outrank a ticket, so that a block means blocked until I say otherwise, and I want issuing a ticket never to resurrect a block I had already cleared.

### Autonomy notes (the two gate axes)

`needsAnswers` is cleared. The six open questions were resolved by a combination of measurement and product decisions from the repo owner. The measurements are recorded inline below where they changed an answer, because three of the six rested on a premise that turned out to be false, and a reader who does not know that will reintroduce the original reasoning. What made these answerable where three prior review rounds had failed was executing them rather than arguing them: every enforcement claim below was driven through the packet-path harness, baseline first.

`taskedAfter: [openwrt-packet-path-test-harness]`, because the packet-path assertions below are unwritable until that harness exists.

`humanOnly` is omitted: once the questions are answered the tasking itself is mechanical.

## Implementation Decisions

All six open questions are resolved here. Where measurement contradicted the premise a question was built on, the measurement is stated, because the false premise is what a future reader would otherwise re-derive.

**Chain skeleton, owned solely by the component that owns the allowlist.** A base `forward` hook (priority -10, policy accept) narrows to LAN-to-WAN and jumps to a regular `parental` chain holding the ordering contract:

```
ether saddr @manual_blocked_macs drop  # 1. a parent's explicit block outranks everything
ether saddr @ticket_macs accept        # 2. tickets override schedule and budget (kernel timeout)
ether saddr @guest_macs  accept        # 3. guests (kernel timeout)
ether saddr @blocked_macs drop         # 4. schedule / budget
jump websites                          # 5. per-profile website blocking
ether saddr @allowed_macs accept       # 6. known devices
drop                                   # 7. unknown devices
```

This ordering is a decision with its own record, `docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md`, because this spec is a launch snapshot that `to-task` trims, and the precedence must outlive it. It REVERSES what `CONTEXT.md` and `work/notes/ideas/rich-status-page-guest-access-and-config-ownership.md` previously said (that a ticket outranks everything); both have been corrected.

**Sole ownership has to be enforced, not just asserted.** Today all three scripts carry their own init that creates the table and a bare `forward` chain, which is how the original defect worked: a non-owner creates the SETS but not the ordering chain, every element write then succeeds, and nothing enforces. Fail-loud does not catch it, because no command fails. So: non-owners create NOTHING. A non-owner that finds the skeleton absent fails loudly and writes no state, exactly as it would for a missing firewall tool. This is a distinct failure mode from the fail-loud rule below and needs its own assertion.

**There are TWO block sets, and that is forced rather than stylistic.** A ticket must override a bedtime window, and a manual block must outrank a ticket. Both cannot hold if schedule, budget and manual blocks share one set, because a set has one position in the chain. So manual blocks sit in `manual_blocked_macs` above the ticket accept, and the reason-driven blocks (`schedule` and `budget`) sit in `blocked_macs` below it. Verified on the packet path, twelve probes, baseline first: a ticket frees a profile inside a blocked window; a manual block then blocks it despite the live ticket; and after the manual block is lifted the profile is reachable again because the block cancelled the ticket rather than suspending it.

**Splitting the set means every derivation of status from the firewall must gain a case.** Per `docs/adr/0004-tests-assert-on-the-packet-path.md` the firewall is ground truth and status is derived from it, which stays true here: `is_blocked` and any status output are computed from SET MEMBERSHIP, not from the state file. The reason set in state says WHY, and never decides WHETHER. Any existing mapping that reads `ticket_macs` then `blocked_macs` must gain a `manual_blocked_macs` case first, or a manually blocked profile reads as allowed. That defect is already latent in the status-page design note, which has been corrected.

Accounting per ADR 0001 hangs off a separate chain at a later hook priority (measured working at `filter` priority 0, with the enforcement chain at -10), which counts only traffic that survived enforcement without being able to influence a verdict. Measured: a blocked profile's retries do not move the counter. That property is load-bearing for the persistence decision below, so it is fixed here rather than left to whoever adds counters.

**`apply` must not lose live state, and the SUPERSEDED way of achieving that is recorded here only as history.** `allowed_macs` is computed from the profiles config and must be reconciled against it, because carrying it over blindly would let a device removed from config keep internet forever. Everything else in the table is live runtime state that an `apply` must not destroy: `manual_blocked_macs`, `blocked_macs`, `ticket_macs`, `guest_macs`, and the `websites` chain with its per-pair children.

The superseded rule said: rebuild the rules but do not flush those sets. Do NOT implement that. It is written down because understanding why it kept failing is what justifies the replacement below.

**That surgical invariant is an artefact of shell, and it is NOT what gets built.** It exists only because a shell script cannot replace a ruleset atomically, so it must rebuild around the live parts without disturbing them. It is also measurably the most defect-prone rule this spec ever contained: every restatement of the live-set list is a place to drop a member, and three successive drafts did exactly that, including one whose entire purpose was to fix the previous two.

A netlink spike removed the need for it (`work/notes/findings/google-nftables-drives-the-kernel-and-replaces-rulesets-atomically.md`). `github.com/google/nftables` drives the kernel directly, and a whole-table replace carrying live elements with their remaining deadlines works in a single transaction: a client that was schedule-blocked and reachable ONLY via a live ticket stayed reachable across a rebuild that also applied a config change, so the carry-over was proven by a packet rather than by inspection.

**So `apply` is a whole-ruleset reconcile, not a surgical edit.** It computes the entire desired ruleset from config plus persisted state, reads back live elements (tickets and guest passes, with their remaining deadlines), and swaps the lot in one transaction. There is no partial rebuild to get wrong, no list of sets to keep in step, and no window in which the household is unprotected. The preservation rule above is retained ONLY as the explanation of why the old design kept failing, and must not be implemented.

Residual risk, stated rather than buried: the spike ran in the OpenWrt userland but on the HOST kernel (Linux 6.12 amd64), not the router's aarch64 OpenWrt kernel. Netlink is a kernel interface, so unlike this repo's shell tests that gap is not self-evidently irrelevant, and it needs one confirmation on the real router. The exploration spec's story 1 owns that confirmation, which is a further reason this spec is ordered after it.

This is the load-bearing invariant, and it is worth stating precisely what it does and does not fix, because an earlier draft got this wrong. Today `apply` flushes the forward CHAIN and `allowed_macs`; it never flushes `blocked_macs`, which after a reboot does not exist at all. So the reboot bug is not a flush, it is two independent causes: `nft_init` returning early once the table exists, so `blocked_macs` is never created; and all block state living in tmpfs, so nothing knows what to restore. The preservation rule above is a FORWARD invariant protecting the new design once `blocked_macs` is a persistent live set, not a description of today's defect. `docs/architecture.md` states the current-day causes correctly and should be read as the authority on what is broken now.

**Website blocking uses one chain per profile+rule, and the skeleton owner creates the parent chain.** `setup-firewall.sh` creates the empty `websites` chain and its jump as part of the skeleton, because nftables rejects a jump to a nonexistent chain and because a jump added later by `website-blocking.sh` would land after the terminal `accept` and never run. `website-blocking.sh` then owns only the contents: the `websites` chain holds jumps to `websites_<profile>_<rule>` chains, each holding that pair's drop rules and owning its `blocked_sites_<profile>_<rule>` set. `disable <profile> <rule>` removes ONLY that chain, its jump, and its own set. A blanket flush of the shared chain is forbidden: the shipped default has three profiles disabling `no_streaming` at 08:00 in the same minute that gaming rules are enabled, so a shared flush would clear other profiles' live blocks.

**A block carries a SET of reasons, and a block lifts only when the set empties.** (Open question 1.) Two models were prototyped over this skeleton and driven through the same household scenarios with real packets. They are indistinguishable on the two scenarios that do not involve `manual`: a bedtime block crossing its budget and surviving the midnight reset, and a ticket letting the budget cross while a bedtime block is in force. They diverge on exactly one thing. With a scalar plus precedence, a parent who imposes a manual block on top of a bedtime block and then lifts the manual block hands the child the rest of the night, because `manual` overwrote `schedule` and lifting it lifted everything. Measured: `reason=<none>`, reachable at 23:00. With a set, `reasons={schedule}` remains and the profile stays blocked. The set is therefore required, and the choice was NOT the load-bearing one it was thought to be: it is downstream of whether `manual` exists at all.

**Each reason is DERIVED or PERSISTED according to what it needs in order to be computed.** (Open questions 1 and 2.) An earlier draft of this section said schedule and budget are both derived, which quietly assumed a scheduler this spec does not deliver and left nothing owning the tick. The split that actually holds:

- **`budget` is DERIVED, and the floor can derive it.** It needs only the usage counter and the allowance, both of which the floor persists, and a per-minute check already exists. Nothing about the schedule is required to compute it, so it is recomputed on every check, never stored as a reason and never restored. (How the counter INCREMENTS is ADR 0001's threshold question and belongs to the exploration; the floor only compares the counter against the allowance.)
- **`schedule` is PERSISTED, for now.** Deriving it needs the window model, which is the policy layer's. Until that lands, cron edges are the only source, so a schedule block is recorded when the edge fires and replayed at boot. When the policy layer arrives this flips to derived and the persisted value simply stops being written. The flip is a non-event, because adding or removing a member of a reason set is the same operation whichever side computed it.
- **`manual` is PERSISTED, always**, because it is the only reason representing a decision rather than a fact.

This also answers open question 2 and dissolves it: the system never infers whether a human issued a block, because a manual block is a distinct operation with a distinct lifetime rather than the same verb from a different caller. (Inference was measured to be technically possible, since a cron-invoked job's parent process is `crond` and its environment carries `LOGNAME`, while the CGI's ancestry reaches `uhttpd`. It is rejected: it guesses intent from mechanism, and it evaporates the moment schedules leave cron.)

Note what is NOT load-bearing here, because an earlier draft claimed it was: derivation is not what fixes the midnight-reset trap. The reason SET fixes it on its own, the moment the daily reset can only remove the `budget` reason and cannot touch a reason it does not own. That is why `schedule` can stay edge-driven now without reopening the defect this spec exists to close.

**Tickets are an override that lapses, not a mutation.** A ticket adds MACs to `ticket_macs` with a kernel timeout and changes nothing else, so when it expires the profile falls back to whatever the reasons say at that moment, with no bookkeeping and no saved-rules dance. Verified: a ticket issued inside a blocked window frees the profile, and on expiry the window is still in force. Two rules complete it. Blocking CANCELS any live ticket, in the core, so that a later unblock cannot resurrect one. Unblocking before ticketing is a FRONTEND gesture, not a fused operation: the ticket page performs an unblock and then an issue as two explicit calls, so "give a blocked child 30 minutes" is visibly two decisions and the ticket still lapses back to the schedule rather than to the block that was deliberately cleared.

**Block state is persisted outside tmpfs. THIS is the authoritative list of what persists, and nothing else in this spec may restate it.** Per profile, exactly four things:

1. the `manual` reason
2. the `schedule` reason (until the policy layer derives it from schedule data it owns, at which point this member disappears)
3. the usage counter
4. the daily-reset day marker

The `budget` reason is deliberately absent, because it is recomputed from the usage counter on the next check. Every other mention of persisted state in this spec, in the tasks derived from it, and in `CONTEXT.md` REFERS to this list rather than repeating it. That rule is not pedantry: restating this list in prose is how three separate drafts of this spec each dropped a different member, and the last one dropped `schedule`, which silently breaks story 2.

It lives in a persisted file under `/etc/config/`, written atomically and only when a value changes. Sysupgrade preservation for that directory is VERIFIED (it is listed in the keep list). Inclusion in the router's own backup is an ASSUMPTION, inferred from the backup being built off the same keep list and not measurable from a container; it needs one check on the real router, and it is stated here as an assumption rather than a decision so nobody mistakes it for settled. Its location must be overridable by a single named lever, **`PARENTAL_PERSIST_DIR`**, alongside the existing `PARENTAL_STATE_DIR`; naming it here rather than leaving it to a builder is deliberate, because an unnamed second state-directory knob is exactly how two knobs meaning the same thing get invented. Per the work contract's shared-write rule, tests must both isolate it via that lever AND assert the real `/etc/config/` location is untouched.

**The usage counter IS persisted, and the write volume that argued against it was wrong.** (Open question 3.) Not persisting was measured to re-cross the budget after a reboot and re-block a child a parent had deliberately let back online, since the persisted day marker suppresses the reset while the counter restarts at zero. The cost argument against persisting rested on 1440 writes per day per profile; measured against the real config, only 3 of 11 profiles carry a non-zero budget at all, so today's wall-clock counting is 4320 writes a day in total, and under ADR 0001 a minute with no traffic above the threshold has nothing to increment and therefore nothing to write. Since a blocked profile's retries were measured not to move the accounting counter, the figure becomes the sum of the budgets: 720 writes a day across all profiles, and zero while nobody is online. Not strictly a ceiling, because story 11 keeps a profile reachable via a ticket after its budget is exhausted, so accounting continues past the allowance for the ticket's duration. The third option, deriving usage from the ADR 0001 counters, does NOT dissolve the question: a counter is a cumulative total rather than a minute tally, so deciding whether a minute exceeded the threshold requires storing the previous value, and the counter itself dies with the table on reboot.

The **daily-reset marker is persisted too**, and this is load-bearing. Today `reset_usage` fires whenever the day marker does not match today and calls `unblock_profile` unconditionally. Both facts combine into a boot-time trap: the marker lives in tmpfs, so after a reboot it is missing, the next `budget-check` concludes a new day started, and the profile is unblocked, silently undoing any boot restore within 60 seconds. Reproduced on the packet path: a bedtime-blocked profile is reachable again immediately after a `budget-check` that rolls the day over. Persisting the marker removes the spurious trigger, and deriving the budget reason continuously removes the unblock call entirely: the reset zeroes usage and the next tick recomputes, so there is no step that can clear a reason it does not own.

**The iptables backend goes, and its removal does not lose a warning, because there is no warning.** The fallback is provably dead: `PARENTAL_FIREWALL` is never exported by the installer, cron, the CGI or the compose file; `setup-firewall.sh` builds the allowlist with `nft` only; and `panic-off.sh` deletes only the nftables table. A router genuinely running the iptables backend would have an nft-only allowlist and a recovery script that could not undo its own blocks, which is the strongest evidence nothing depends on it. The iptables MOCK and its tests are removed by the harness spec; this spec removes the code. That mock removal is a deliberate choice rather than a consequence of the image swap (the mock is plain POSIX shell and would run fine on OpenWrt), so the loss of coverage for the iptables path until this spec lands is knowingly accepted, not incidental.

**Fail-loud covers ALL THREE writers, and the premise for scoping it narrowly was false.** (Open question 5.) The question assumed that removing the `none` backend would delete today's only warning on a missing `nft`. Measured: that warning is already invisible. `log()` sends it to `logger`, which exits 0 whether or not a syslogd is listening, so the fallback `echo` to stderr never runs. `block <profile>` with no `nft` prints nothing on stdout, nothing on stderr, exits 0, and writes `blocked`. `setup-firewall.sh apply` prints its own success line on top of unredirected "not found" noise and returns 0 to procd, which is the boot path. `website-blocking.sh` reports `enabled ... (0 IPs blocked)` and writes `enabled`. So hardening one caller is not a partial improvement over parity, it is a choice to keep shipping silence in the other two.

The requirement, therefore: every firewall command failure is fatal to the operation that issued it; no state file is written claiming a result that was not achieved; and the exit code is non-zero. Cutting the household off is not an option when the firewall tool is broken, so the system fails OPEN by necessity, which makes detectability the whole requirement rather than a nicety. A `degraded` marker is therefore surfaced on the status page, since that is the surface someone in the house actually opens. Resolving a website rule to zero addresses counts as a failure too, and must not report `enabled`: it is a distinct silent failure from the `nft` one and shares its shape.

**The ticket page requires a password.** An unauthenticated page that grants internet is reachable by exactly the device it is blocking, because the block acts on forwarded traffic while the page is served by the router. Measured end to end with the real CGI and the real `uhttpd`: a blocked client loaded the page and issued itself a ticket. HTTP basic auth on the real `uhttpd` was measured to work with no extra package, and to gate `/cgi-bin` as well as the page, which is the half that matters. Gating only the HTML would be theatre, since the CGI is what issues the ticket.

**`--force` gains a defined meaning, and an owner.** A plain `apply` carries live state across the swap. `--force` discards it instead: it clears the persisted state (all four items on the authoritative list) and emits a ruleset with the live sets empty, so blocks, tickets and guest passes are all gone. Both are the same single-transaction reconcile differing only in what they carry, which is what makes `--force` a real behaviour rather than a message. The **tool** performs the clearing, not the deployment script: `install.sh` is a laptop-side driver that shells into the router, so a flag it parses has to be passed through to the component that owns the ruleset, and an earlier draft left that unowned. Without this, the flag prints "active blocks cleared" while clearing nothing, which is the same class of lie as everything else in this spec.

**Boot restore belongs to the boot path, and explicitly NOT to `apply`.** (Open question 4.) `apply` builds the skeleton and never restores; a separate restore step replays persisted state, and the init script is what calls both, in that order. The question's premise needed correcting first: an ordinary re-install does not call `apply` at all, it calls `update`, because `install.sh` branches on whether the table already exists. `apply` is reached on a first install, on `--force` once that flag is repaired (today it cannot be reached that way at all, because `install.sh` resets `FORCE` after parsing it), and on exactly one other path, which is the one that matters: `panic-off.sh` deletes the table, so the next `install.sh` looks like a first install and calls `apply`. Driven on the packet path, an `apply` that restores turns the documented recovery sequence into a no-op: panic-off frees the household, and the reinstall it tells you to run silently re-imposes the blocks. Splitting them keeps recovery recovering. Read from the real OpenWrt `/etc/rc.common`: `enable()` only creates the `rc.d` symlink and does not call `start()`, so an init-script-owned restore does not fire during an install; it fires at the next boot, where `panic-off.sh` having cleared the persisted state means there is correctly nothing to replay.

**The restore verb is named: `restore`.** It is distinct from `apply`, it replays the persisted state listed above, and it is the boot path that calls it, after `apply` has built the skeleton. In the Go tool this is what the service does at startup; it is ALSO exposed as an explicit subcommand, because a boot path that exists only as service startup cannot be driven by a test, and the whole point of this spec is that the boot path is the one nobody was testing.

The restore shrinks as the policy layer lands: once schedules are data the tool owns, member 2 of the persisted list disappears and the first reconciliation after boot computes the schedule from the clock, which is also what closes the fail-open gap where a router down from 21:58 to 22:05 never runs its bedtime.

**Responsibilities to seed the tasking.** Keyed by BEHAVIOUR, not by file, because the floor lands in Go and a table of shell edits would task the wrong work. The middle column is where the behaviour lives today, so a builder can find the defect and the trap that produced it; the shell file is a reference, not a destination. Rows whose only content is a shell cleanup are marked RETIRE, meaning the behaviour disappears with the script rather than moving.


| File | Change |
|---|---|
| Responsibility | Where it lives today | What must be true |
|---|---|---|
| Build the skeleton | `setup-firewall.sh` | sole owner of the table, `parental` chain and all five sets. `apply` computes the WHOLE desired ruleset and swaps it in one transaction, carrying live tickets and guest passes with their remaining deadlines |
| Refuse to half-build it | `nft_init` in all three scripts | non-owners create NOTHING. Finding the skeleton absent is a loud failure, not an opportunity to create a bare table. This is the original defect's actual mechanism |
| Own the reason set | nothing (no reasons exist) | `block`/`unblock` name their reason and add/remove exactly that member. `manual` writes `manual_blocked_macs`; `schedule` and `budget` write `blocked_macs`. WHETHER a profile is blocked is read from set membership, never from the state file |
| Cancel tickets on block | nothing | `block` clears any live ticket for that profile, so a later `unblock` cannot resurrect one (story 21) |
| Budget without a latch | `_check_single_budget` | derive the `budget` reason from usage against allowance on EVERY check. The daily reset zeroes usage and removes only the `budget` reason |
| Ticket as a lapsing override | `issue_ticket` | add to `ticket_macs` with a kernel timeout and change nothing else. RETIRE the background `sleep`, the saved-rules save/restore, and the `unblock_profile` call. `tickets` reads the set |
| Persist and restore | `/tmp` only | write the four persisted items (see the authoritative list above) atomically on change; `restore` replays them; the boot path calls `apply` then `restore` |
| Fail loudly | every `2>/dev/null` | any firewall failure is fatal to its operation, exits non-zero, writes no success-claiming state, and records a `degraded` marker |
| Surface the degradation | nowhere | the marker must have a READER in this spec's era, not only a writer: the CLI status output reports it. Rendering it on a status PAGE is the policy layer's |
| Password-gate ticket issuance | `web/cgi-bin/ticket` (none) | both the page and the issuing endpoint reject unauthenticated requests. Basic auth is measured to work on the real `uhttpd`; if the exploration answers its HTTP-seam question with the tool owning its own port, this becomes in-process and the realm file is irrelevant. The credential has to be provisioned by whatever owns deployment |
| Answer the request promptly | `web/cgi-bin/ticket` | no long-lived child inherits the response stream |
| Website blocking per profile+rule | `website-blocking.sh` | own the per-pair child chains; `disable` removes only its own chain, jump and set. Resolving zero addresses is a failure, not `enabled` |
| Recovery stays recovery | `panic-off.sh` | also clear the persisted state, so "State cleared" is true and the documented reinstall path cannot re-impose old blocks |
| Deployment flags work | `install.sh:52-53` | `--force` and `--setup` currently cannot take effect at all because both are reset after the arg loop. `--force` must additionally clear the persisted state and all live sets, and the component that performs that clearing must be named, not implied |
| RETIRE the second backend | `parental-profiles.sh` | the iptables backend, the detection dispatch, the `none` backend, the `backend` subcommand and the "Firewall backend" status line all go |
| RETIRE the duplicate boot generator | `setup-firewall.sh generate_init_script` | it executes `apply_nft` at generation time and emits that output INTO the generated `start_service` body, producing broken shell once the table exists (it interpolates to empty only on a table-less first run) |
| RETIRE dead levers | `SLEEP`, `PARENTAL_SKIP_AUTOBLOCK`, `PARENTAL_FIREWALL`, `IPTABLES` | remove from usage text, scripts and test setup. Six `PARENTAL_FIREWALL` lines across the two bats files, not two |
| Docs sweep | see below | README, `docs/setup-guide.md`, `docs/example-5-profiles.md`, `config/block_rules.example`, `config/parental_blocklists.example`, `config/local/README.md`, `docs/architecture.md` and **`CONTEXT.md`**. NOT the test-count and test-environment claims, which ship from `refresh-test-environment-docs`. Note `docs/architecture.md` already says `PARENTAL_FIREWALL` is a lever that GOES with the backend, so only its iptables-abstraction bullet needs the sweep |
| docs | stale-doc sweep: README (`parental_websites` and the "auto-detected, iptables fallback" feature line), `docs/setup-guide.md`, `docs/example-5-profiles.md`, `config/block_rules.example`, `config/local/README.md`, and **`docs/architecture.md`** (which describes the iptables abstraction and lists `PARENTAL_FIREWALL` as a seam to extend, and which both task prompts tell builders to read first). NOT the test-count and test-environment claims: those ship from `refresh-test-environment-docs` under the harness spec, so do not re-fix them here and do not collide with it |

**Risk control.** This changes the rule that decides whether the household has internet. A wrong ruleset costs WAN, never LAN, so SSH recovery is always available, and `panic-off.sh` remains the escape hatch. First deployment to the live router should apply with a rollback timer cancelled once verified.

## Testing Decisions

The seam is the packet path, using the harness delivered by `openwrt-packet-path-test-harness`. Assert reachable/unreachable, not ruleset text, because ruleset text is what looked correct while the system enforced nothing.

Assertions to write. Each fails against current `main`, which is the point.

1. Production boot order (`apply`, then `block <profile>`) leaves the profile UNREACHABLE.
2. Re-running `apply` (the reboot path) leaves an already-blocked profile UNREACHABLE.
3. A blocked profile is UNREACHABLE after a simulated reboot **and remains so after `budget-check` runs**. The cron step is mandatory: without it the test cannot see the daily-reset trap, and a test that cannot see the failure is the defect this spec exists to remove.
4. A profile blocked by SCHEDULE that then crosses its budget is still UNREACHABLE after the next daily reset. It must drive the profile through budget exhaustion while schedule-blocked rather than merely rolling the day over.
4b. A profile blocked by SCHEDULE and then blocked MANUALLY is still UNREACHABLE after the manual block is lifted, while the window is still in force. This is the assertion that catches the reason model being collapsed back to a scalar: it is the only scenario on which the two models were measured to differ, and a suite without it would pass against a design that hands out the rest of the night.
5. A website rule enabled for a profile makes a blocked destination UNREACHABLE for that profile's MAC while another destination stays reachable.
6. Website blocking still enforces after `apply` and after a simulated reboot (the `jump websites` wiring).
7. Disabling one profile+rule leaves another profile's active rule still enforcing.
8. A ticket makes a schedule-blocked profile REACHABLE.
9. A ticket makes a website-blocked destination REACHABLE for that profile.
10. After the ticket's kernel timeout elapses, the profile is UNREACHABLE again with no background process involved.
11. Budget exhaustion during a live ticket does NOT make the profile unreachable.
12. Giving a child more time after budget exhaustion via a TICKET survives the next budget check. It deliberately does NOT survive a reboot: a ticket is a kernel-timeout set that is MEANT to die with the router (story 5), so the assertion is that after a reboot the child is blocked again, not that the ticket persists. A bare `unblock` also does not hold, and a test asserting that it does would be pinning the defect. The extension gesture is not asserted here because it is not built here; it is a named follow-up in Out of Scope.
13. With `nft` unavailable, ALL THREE writers FAIL loudly: non-zero exit, and no state file left claiming a result that was not achieved. Asserting this for `block <profile>` alone would leave the boot path, which is the one that matters, untested.
13b. A website rule that resolves zero addresses FAILS rather than reporting `enabled`.
13c. With the skeleton ABSENT (the table deleted, as after `panic-off.sh`), a non-owner asked to block FAILS loudly and creates nothing. This is a separate failure from 13: there, the firewall tool is missing and every command errors; here every command SUCCEEDS and enforcement still does not happen, which is the original defect's exact mechanism and the one fail-loud alone cannot catch.
13d. The `degraded` marker written by any of those failures is READABLE from the CLI status output, so story 9's detectability half has a consumer in this spec's era rather than waiting on a status page.
14. The ticket CGI returns in under two seconds, served by the real `uhttpd`.
14b. The ticket page and `/cgi-bin` both REJECT an unauthenticated request, and both SERVE an authenticated one. The second half is the control: without it, a misconfigured server that rejects everything passes as "secure".
14c. A MANUAL block outranks a live ticket: with a manual block in force, the profile stays UNREACHABLE even with an element in `ticket_macs`. Titled precisely on purpose. A schedule-blocked or budget-blocked profile CAN be ticketed, by design (stories 4 and 6), and generalising this assertion into "a blocked profile cannot be ticketed" would destroy them. What closes the self-service hole from the Problem Statement is the password in 14b, not this.
14d. A manual block CANCELS a live ticket, so that lifting the block does not resurrect it: after block then unblock, the profile is reachable only because the underlying reasons allow it, and the ticket set is empty.
15. `install.sh --force` and `--setup` reach their decision points. The only existing coverage greps `install.sh` source text and passes today despite the flags being dead, which is exactly the test-that-cannot-see-its-failure pattern this spec abolishes.

**Ruleset TEXT assertions do not survive a port, and that is now measured.** The Go library renders `ether saddr` as a raw payload match (`@ll,48,48`), which is semantically identical and enforces correctly on packets, but is textually different from what the shell scripts produce. Any assertion greping ruleset text therefore breaks across a shell-to-Go port even when nothing about the behaviour changed. This is independent support for ADR 0004 and it constrains the sweep below: assertions being rewritten here should be moved to the packet path rather than re-pinned to new text, or they will have to be rewritten a second time.

**Existing tests that must CHANGE, not be preserved.** This list is load-bearing, because an agent told "everything else must still pass" will satisfy a stale test by keeping the very code this spec deletes. Enumerate ALL of these as intended breakages when tasking:

- `test/setup-firewall.bats` asserts `accept`/`drop`/`blocked_macs` in the `forward` chain, which the skeleton moves to `parental`.
- Nine assertions in `test/website-blocking.bats` grep the forward chain for `blocked_sites_*`, which the per-pair design removes. (Two further forward-chain assertions there match MACs, not the set name. Note these match the SET name: the code writes its comment tag as `block_sites_*`, without the `ed`, so anything grepping for the comment tag finds nothing.)
- `test/parental-profiles.bats` asserts a ticket unblocks the MAC immediately, and that a ticket removes the website rule. Both are things the new design deliberately stops doing, and both can be "fixed" by re-adding `unblock_profile` to `issue_ticket`, destroying story 7 and reopening a closed bug.
- `test/parental-profiles.bats` `ticket saves active website rules for re-enabling` pins the saved-rules dance that is retired.
- `test/parental-profiles.bats` `ticket records entry in tickets file` and `tickets command shows active tickets` pin the flat state file that becomes a set read.
- `test/parental-profiles.bats` `backend shows nft when nft is available` and `status shows firewall backend` pin the `backend` subcommand and the status line that are retired with the second backend.

Also note `SLEEP` and `PARENTAL_SKIP_AUTOBLOCK` become dead levers once the backgrounded expiry goes; their removal is owned by the RETIRE row above rather than being left unassigned as it was in an earlier draft.


## Out of Scope

- **The test harness itself**, delivered by `openwrt-packet-path-test-harness` and ordered before this spec.
- **What a budget minute MEANS.** Settled by `docs/adr/0001-budget-counts-actual-use-gated-by-a-threshold.md`: actual use above a threshold. The measurement mechanism and threshold belong to the exploration spec. This spec only stops the budget from cancelling a live ticket, and makes the `budget` reason a derived fact that cannot clear a reason it does not own. Note it deliberately DOES re-evaluate every check; what was wrong before was not the frequency but that re-blocking overwrote other reasons and that a manual unblock had nothing to make it stick.
- **The device registry of ADR 0003.** This spec keeps the allowlist derived from profile membership, deliberately, pending the config-ownership work. Named here because ADR 0003 describes the opposite end state and a tasker reading both would otherwise hit an unrecorded conflict.
- **The POLICY layer, which is the Go work's.** Schedules as windows carrying a day-of-week selector (so weekends, school nights, or just Wednesday and Friday are all expressible, and a profile can have several windows a day such as 22:00 to 08:00 and 12:00 to 13:00); continuous reconciliation of desired state against the firewall; budget accounting and the today-extension gesture; and the status page that renders it. Their SEMANTICS are decided above and must be honoured, but they are not built here, because they are what shell is worst at and building them twice is the one outcome worth avoiding. This is a deliberate reversal of an earlier plan to implement them in shell first.
- **A reboot that spans a schedule boundary, in both directions.** While the schedule remains cron edges, boot restore replays the last known block state and a missed edge stays missed. Fail-safe: a router down from 07:59 to 08:05 comes back still blocked. Fail-OPEN, which matters more: a router down from 21:58 to 22:05 never runs the `0 22` block, so bedtime does not happen that night. The repo owner has ruled this NOT acceptable, and it is out of scope here only because the fix is the policy layer's: desired-state reconciliation converges within a tick of boot regardless of which edges were missed. Recorded so that the gap is understood as deferred with a known remedy rather than accepted.
- **Website blocking state across a reboot.** The per-pair chains and their `_websites` state files are not restored at boot, so a 21:00 power cut drops the streaming block until the next 20:00. A distinct gap from the one above, named rather than implied.
- **`guest_macs` is created but never populated.** The set and its accept rule ship as part of the ordering contract so guest access can be added later without touching the skeleton. Nothing here grants a guest pass.
- The Go tool, the rich status page, guest access UI and config editing.
- AdGuard Home, blocklists and DNS filtering.

## Further Notes

The investigation that produced this spec was consolidated into the work items and its working document deleted. Durable external facts live as findings: `openwrt-nftables-json-and-ether-timeout-sets`, `uhttpd-cgi-timeout-and-backgrounded-children`, `rootless-container-netns-nftables-requirements`, and `busybox-crond-treats-a-bad-time-field-as-a-wildcard` (added while resolving the open questions, and the reason story 19 changed shape).

This spec absorbed `remove-iptables-fallback` (recorded in `work/tasks/cancelled/`) and was itself split, with its harness half moved to `openwrt-packet-path-test-harness`.

Expect the gate to go RED once this spec's tests land and stay red until the fix completes. `autoBuild` must stay off in between. The harness spec, by contrast, keeps the gate green.

**Sequencing, now settled and encoded in the frontmatter.** The order is: harness (done), then `explore-go-tool-for-parental-control`, then this spec. The dependency edge between the exploration and this spec previously pointed the other way, on the reasoning that the acceptance tests had to be green against a shell implementation before they could hold a Go one. The repo owner reversed that, deciding the floor should be built in Go rather than built in shell and ported, so the exploration's `taskedAfter` was repointed at the harness to break the cycle that reversal created. The safety argument survives: the harness exists, and its packet-path assertions are language-agnostic by construction, which is exactly what they were designed for and what the netlink spike independently confirmed is necessary (a Go ruleset is textually different and behaviourally identical, so text assertions would not have survived the port).

**Decisions from this spec that were minted as ADRs**, because a launch snapshot is trimmed by `to-task` and these must outlive it: `docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md` records the reason set and the precedence. Two further decisions here are ADR-shaped and should be minted at tasking rather than left in this file: the accounting hook priority (ADR 0001 deliberately left it open and this spec fixes it at `filter` priority 0, delivering no accounting itself), and whichever way the exploration settles the implementation language.
