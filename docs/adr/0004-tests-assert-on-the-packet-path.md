# Tests assert on the packet path, not on ruleset text

**Status:** accepted

Any test making a claim about enforcement must send a real packet from a chosen source MAC through a real bridge and assert whether it reached the internet, rather than inspecting nftables set membership or rule presence. In the 104-test suite that preceded this decision, **no test sent a packet, and every enforcement assertion was set membership or rule presence** (a third of the suite covers config parsing and state files and does not touch the firewall at all). It stayed green while the firewall enforced nothing at all: after a reboot the `blocked_macs` set was never created, every `nft add element` failed into `2>/dev/null`, and the block command still wrote `blocked` to its state file and logged success. The sets it inspected looked exactly as expected. Ruleset text is precisely the thing that looks correct while packets flow, so it cannot be the evidence.

## Considered Options

- **Packet-path assertions (chosen).** The only evidence that distinguishes "the ruleset looks right" from "the packet is dropped". Catches rule ordering, unreachable rules after a terminal `accept`, and missing sets, none of which set-membership assertions can see.
- **Set-membership and rule-presence assertions (rejected as sufficient, kept as a complement).** Fast and still useful for non-enforcement behaviour such as state files and config parsing. They were never wrong, only insufficient, and they remain in the suite.


## Consequences

- The test container needs elevated capabilities plus `net.ipv4.ip_forward=1` set at container start. The set `NET_ADMIN`, `SYS_ADMIN`, `NET_RAW` is known SUFFICIENT; only `SYS_ADMIN` has a measured lower bound (`ip netns add` fails without it). `NET_RAW` has not been shown necessary and the harness uses no raw sockets. `--privileged` is not required, so CI remains viable.
- **A baseline reachability assertion is mandatory, not redundant.** If the ip_forward sysctl is missing the topology never forwards, so every probe reads unreachable including the baseline, and a suite without a baseline assertion reports a perfect pass while testing nothing. That failure mode is the same class as the bug this decision exists to prevent.
- Enforcement tests are slower than set inspection and cannot run in a plain unprivileged container.
- The rule going forward, scoped deliberately: every **new or changed** enforcement claim gets a packet-path test; everything else may remain a unit test. This is not a retroactive demand on the whole suite. At the time of this decision NO claim was packet-proven by any test; the unknown-device allowlist had been confirmed only by the investigation's manual probe. Profile blocking, website blocking, tickets and budgets stay set-membership-only until the enforcement work reaches them.
- **State at the time of writing:** none of this is built yet. The harness and the first packet-path assertions ship from `openwrt-packet-path-test-harness`; the enforcement claims follow later. Read this ADR as the ratified direction, not as a description of the current suite.
