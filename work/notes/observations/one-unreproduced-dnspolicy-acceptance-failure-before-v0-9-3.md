---
title: One unreproduced dnspolicy acceptance failure, seen once before tagging v0.9.3
slug: one-unreproduced-dnspolicy-acceptance-failure-before-v0-9-3
source: 'local acceptance runs on 2026-08-08, worktree at e9fcc0e'
---

`.acceptance/dnspolicy.test` reported `FAIL` on one full `docker/acceptance.sh` run, with no test name captured because the run was piped through `grep ... | head`, which truncates and can SIGPIPE the script. It did not reproduce: seven subsequent runs of the binary on its own and two subsequent full suite runs all exited 0.

Written down because an acceptance failure that is explained away is how a gate rots. Two candidate causes, neither confirmed:

- The rig's known soft spot. `lookupVerdict` retries a UDP query six times and returns `ERROR:` rather than a verdict when every attempt times out, which `mustResolve` and `mustBlock` then fail. The test comments already call this out: a timeout is neither blocked nor resolved, and on a loopback-heavy container it happens.
- Cross-binary interference. `acceptance.sh` runs all eight test binaries in one container, and `deploy.test` also starts a real AdGuard; `startAdGuard` does `killall AdGuardHome` and waits for a real DNS answer, but nothing waits for the previous AdGuard's port 53 to be released. Simulating that order (accounting, daemon, deploy, then dnspolicy) passed once.

If it returns, capture the run with the output going to a file rather than a pipe, so the failing test name and its diagnostic survive.
