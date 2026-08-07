# The shell implementation (legacy)

This is the original parental control system: a set of POSIX shell scripts deployed to the router over SSH, driven by cron. It is being replaced by the `curfew` Go tool and is kept here for three reasons.

It is what actually ran on the router, so it is the reference for what the household had. Its bats suite still runs in the gate, so a capability is never dropped before its replacement exists. And every defect recorded here is the reason the replacement is shaped the way it is.

**Do not develop this further.** Each file goes when the Go tool takes over the capability it covers.

## Why it is being replaced

Its failure mode was not crashing, it was lying. Every `nft` call ended in `2>/dev/null`, so the scripts reported success while enforcing nothing. Concretely, after any reboot the `blocked_macs` set was never created, every `nft add element` failed silently, and the CLI, the logs and the state files all still said the child was blocked.

The 104-test suite was green throughout, because no test ever sent a packet.

`docs/architecture.md` describes how this system is put together, and `work/specs/` records the defects in detail.

## Usage, for as long as it is deployed

```sh
./install.sh 192.168.1.1              # install or update
./install.sh 192.168.1.1 --setup      # also apply router config (PPPoE, Wi-Fi, timezone)
./install.sh 192.168.1.1 --force      # full re-apply, clearing active state
```

Note `--setup` and `--force` are both dead: `install.sh` resets their variables immediately after parsing them. That is recorded rather than fixed, since the script is on its way out.

On the router:

```sh
parental-profiles.sh status            # profiles and blocked MACs
parental-profiles.sh block alice       # block all of Alice's devices
parental-profiles.sh ticket alice 30   # 30 minutes of access
website-blocking.sh status             # website blocking state
panic-off.sh                           # disable everything, restore the internet
```

## Configuration

Pipe-delimited flat files in `config/local/` (gitignored), copied to `/etc/config/` on the router. Templates are in `config/`.

- `parental_profiles` — `name|budget_minutes|mac,mac,mac`, and the single source of truth for both profile membership and the MAC allowlist
- `block_rules` — `rule_name|domain,domain`
- `device_ips` — static DHCP leases
- `crontab` — the schedule

`curfew import` reads `parental_profiles` and turns it into the Go tool's device registry, so you do not retype MAC addresses when migrating.

**One live hazard worth knowing** if you redeploy this: a crontab hour outside 0-23 does not disable the line, it makes it run **every hour**, because busybox crond degrades an unparseable field to a wildcard. See `work/notes/findings/busybox-crond-treats-a-bad-time-field-as-a-wildcard.md`.

## Tests

Run from the repo root with the rest of the suite:

```sh
./docker/acceptance.sh
```

125 bats tests on a real OpenWrt userland with no mocked system tools. Most assert on nftables set membership, which was never wrong but was never sufficient either.
