# The Go tool owns every operation, including recovery and deployment

**Status:** accepted

Every operation this system performs is a subcommand of the one Go tool: enforcement, schedules, budgets, tickets, website blocking, AdGuard setup, config pull and push, panic-off, and installing the tool onto the router. The shell scripts are absorbed rather than kept alongside, because a Go tool sitting BESIDE a script that writes the same nftables chain recreates the exact hazard the enforcement work exists to remove, and because "which of these two things owns this?" is the question that produced every bug in the investigation.

Deployment is included for a reason that only became visible late: bringing AdGuard's configuration under the same pull and push story as everything else (`docs/adr/0002-adguard-home-owns-dns-filtering.md` records that it is load-bearing state nothing manages, and that a panic-plus-reinstall cycle destroyed hand-made exceptions) means the tool must SSH into the router from the laptop anyway. Once that exists, keeping `install.sh` as shell means maintaining a second SSH implementation for the same job.

## Considered Options

- **One tool owning everything (chosen).** One place where state lives, one thing to test, one thing to reason about. Deployment and recovery stop being second-class paths that nobody exercises, which is what let `install.sh --force` be dead code for however long it was dead.
- **A tool plus surviving scripts (rejected).** This was the earlier position, and the argument for it was real: the recovery path should share no failure surface with the thing it recovers from. It is rejected in this form because it leaves ownership genuinely split, and because a `panic-off` that does not know about the tool's persisted state cannot actually clear it, so its "State cleared" message would be false, which is the class of lie this project is trying to eliminate.

## Consequences

- **A minimal escape hatch survives, and it is deliberately NOT a duplicate of the `panic-off` command.** The distinction is between the OPERATION (disable all policy and restore internet, which the tool owns and which must clear persisted state) and the GUARANTEE (there is always a way back that does not depend on the tool running). The hatch delivers only the guarantee: drop the `curfew` nftables table and put dnsmasq back on port 53. It restores CONNECTIVITY, not policy, it must stay small enough to audit at a glance, and it must not read config or state. This is affordable precisely because a wrong ruleset costs WAN and never LAN, so SSH is always available.
- **The binary has two roles.** On the laptop it is a CLI that talks SSH; on the router it is a procd-managed daemon plus a CLI. Each role carries some code it does not use, which is irrelevant at a measured 5.6 MB, and can be split with build tags later if it ever matters.
- **Cross-compilation becomes part of the deploy path**, since the laptop is x86-64 and the router is aarch64. The tool must build and push the correct architecture, and getting this wrong is a bricked deploy rather than a compile error, so it needs an explicit check.
- **AdGuard's configuration comes under management**, which closes the gap ADR 0002 recorded. Note it contains secrets (at minimum a password hash), so the pull path has to decide what is stored in the repo and what is not.
- `blocklists.sh` is unaffected: it is retired outright under ADR 0002, not absorbed.
