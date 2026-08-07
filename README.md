# curfew

Parental control for a home OpenWrt router, driven from your laptop. Decides which devices may reach the internet, and (in time) when.

Enforcement is done in the **kernel**, with nftables, and every claim it makes is checked against the firewall rather than against its own saved state. That is the whole design brief: the system it replaces reported success while enforcing nothing, and stayed green through 104 tests because none of them ever sent a packet.

Built for a GL.iNet Flint 2 (GL-MT6000) running OpenWrt, but nothing in it is specific to that board beyond the interface names you pass it.

## Two binaries, on purpose

**`curfew`** runs on your **laptop**. It installs the daemon, and pushes and pulls the device list. It cannot enforce anything: it does not import the enforcement code at all, so running the wrong command on your laptop cannot rewrite your laptop's own firewall. A test asserts that against the real import graph, so it cannot quietly stop being true.

**`curfew-daemon`** runs on the **router**. It owns the nftables ruleset and serves the device page. It is placed there by `curfew install`, which detects the router's architecture rather than assuming it.

## Install

```sh
curl -fsSL https://github.com/wighawag/curfew/releases/latest/download/install.sh | sh
```

This detects your OS and architecture, downloads the latest release, **verifies its sha256 checksum before unpacking**, and installs `curfew` to `~/.local/bin`. Override with environment variables:

```sh
curl -fsSL https://github.com/wighawag/curfew/releases/latest/download/install.sh \
  | CURFEW_VERSION=v0.1.0 PREFIX=$HOME/bin sh
```

Only the laptop binary is installed. The daemon belongs on the router and is put there by `curfew install`, which fetches the right architecture for your device. Keeping the enforcement binary off your laptop is the point of the split.

Or build from source: `go build -o curfew .`

## Quick start

```sh
# 1. If you are migrating from the shell scripts, import your existing devices.
#    The allowlist starts EMPTY, and an empty allowlist means nothing in the
#    house reaches the internet.
curfew import

# 2. Install onto the router. --wan is required and deliberately not guessed.
curfew install root@192.168.1.1 --wan pppoe-wan --password 'choose-one'

# 3. Open the page
open http://192.168.1.1:8080
```

`curfew install` prints how many devices **the firewall is actually enforcing**, read back off the router, not how many commands exited zero.

### Finding your WAN interface

`--wan` is required because guessing it is how enforcement silently matches nothing: on a PPPoE line the live device is `pppoe-wan`, not the configured `eth1`.

```sh
ssh root@192.168.1.1 "ifstatus wan | grep l3_device"
```

## Commands

| Command | Runs on | What it does |
|---|---|---|
| `curfew import` | laptop | Build a device list from the legacy pipe-delimited config |
| `curfew install <host>` | laptop | First-time setup: daemon, settings, service, device list |
| `curfew update <host>` | laptop | Update the daemon binary, keeping the router's settings and devices |
| `curfew push <host>` | laptop | Send your local device list to the router |
| `curfew pull <host>` | laptop | Merge the router's device list into yours |
| `curfew probe <host>` | laptop | Check the router's kernel still supports tickets |
| `curfew version` | laptop | Print the version |
| `curfew-daemon -version` | router | Print the version running on the router |

Your existing ssh configuration, keys and agent are used as-is.

## Keeping the two lists in step

Devices can be added, renamed and removed in two places: your local file, and the router's own page. So `push` and `pull` behave like a tiny version control system rather than a blind copy.

Both remember the last state the two sides agreed on. `push` refuses if the router has changed since then, instead of discarding those changes. `pull` performs a **three-way merge**: a rename on your laptop and an addition on the router are not a conflict and merge silently, because the list is keyed by MAC and can be merged structurally rather than as text.

Only a device genuinely changed on both sides stops the world. Then nothing is applied, and a report names each side:

```
aa:bb:cc:00:00:02  (renamed differently on both sides)
    last agreed : tablet
    your laptop : tia tablet
    the router  : living room tablet
```

Resolve by editing your local list and pushing, or take a side wholesale with `--force` on either command.

## What it does today

The **MAC allowlist**: registered devices reach the internet, everything else is dropped. Add, rename and remove devices from the page at `http://<router>:8080`. Names are optional labels: the allowlist works on MAC addresses, so renaming never changes who has internet, while removing a device revokes its access immediately.

Per profile, it also does **schedules** (recurring blocked windows), **manual blocks** and **tickets**:

- **Block** turns a profile off until you turn it back on. It survives a reboot, because it is a decision rather than something the system can recompute.
- **Unblock** lifts that decision and nothing else. A child inside their bedtime window stays offline, because the window is a separate reason and unblocking removes only the reason it owns.
- **A ticket** grants a profile a fixed extra period, by tapping a duration. It overrides a bedtime window while it lasts, and then simply lapses: the kernel holds the deadline and reclaims it, so nothing has to remember to take the access away.

A block you impose **outranks** a ticket, so a child cannot ticket their way out of being grounded, and blocking cancels any ticket already running so that unblocking later cannot resurrect one. Giving a blocked child time is deliberately two taps, unblock and then a duration, rather than one button that quietly cancels an indefinite block. The decisions behind all of this are in `docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md`.

The page is password-gated, and that matters more than it looks: blocking applies to forwarded traffic, so the router still answers the device it is blocking. The password and the precedence above are two independent halves of stopping a child freeing themselves, and neither is sufficient alone.

A ticket is **gone after a reboot**, deliberately. A manual block is not.

Status is read from the **firewall**, never from re-evaluating the schedule or reading back our own config. If the schedule says a profile should be blocked and the firewall disagrees, the page says exactly that instead of showing you what it hoped. A green dot derived from our own config file is precisely the reassurance that let the previous system claim to be working.

The daemon re-asserts the ruleset on a timer, so a table wiped by hand, by a recovery path, or by anything else heals itself on the next tick. That re-assertion replaces the whole table in one transaction and carries live tickets across it with the time they have left, so a reconcile can neither cut a ticket short nor quietly restart its clock.

Time budgets, guest passes and website blocking are designed but not built. The decisions behind them are recorded in `docs/adr/` so they land as decisions rather than guesses.

## If something goes wrong

A wrong ruleset costs WAN, never LAN, so **SSH always works**. To remove all policy and restore connectivity immediately:

```sh
ssh root@192.168.1.1 'nft delete table inet curfew'
ssh root@192.168.1.1 '/etc/init.d/curfew stop'     # or it reconciles straight back
```

The daemon deliberately leaves the ruleset in place when it exits. Stopping it must not silently open the household's internet; removing policy is an explicit act.

### If a ticket behaves oddly

```sh
curfew probe root@192.168.1.1
```

Tickets are nftables elements with **kernel** timeouts, carried across a whole-table rebuild with the time they have left, and all of that is the kernel's behaviour rather than this program's. The test suite measures it on the kernel of whatever machine built the tests, which says nothing about your router after a firmware upgrade or on a new board. This asks the router itself, and prints what it found.

It is safe to run at any time, including with the family online. It works in its own table, creates no chain and no hook, so no packet is ever matched against it, and it removes that table when it finishes. A packet-path test asserts exactly that: a blocked device stays blocked and the enforcement ruleset comes out byte for byte identical.

## Where things live on the router

| Path | Survives a reboot | Survives a firmware upgrade |
|---|---|---|
| `/etc/config/curfew/devices.json` | yes | yes |
| `/etc/config/curfew/profiles.json` | yes | yes |
| `/etc/config/curfew/state.json` | yes | yes |
| `/usr/sbin/curfew-daemon` | yes | yes, via `/lib/upgrade/keep.d/curfew` |
| `/etc/init.d/curfew` | yes | yes, same |
| `/etc/config/curfew/daemon.conf` | yes | yes |

The daemon's settings (WAN interface, listen address, credentials) live in `daemon.conf` as data rather than baked into the service definition. That is what lets `curfew update` replace the binary without being told them again, and it means updating can never change them by accident. `install` writes that file; `update` deliberately never touches it, nor the device list.

`state.json` holds the manual blocks. It is state rather than configuration, and `push` and `pull` deliberately never touch it: it belongs to the router, and copying a laptop's idea of who is grounded over the top of it would undo a decision made on a phone five minutes earlier.

`/etc/config/` is the only location OpenWrt's sysupgrade keep list preserves by default, which is measured, not assumed. `curfew install` registers the binary and the init script for preservation too, so a firmware upgrade cannot leave you with a config that says who is allowed and a firewall that allows everyone.

## First-time router setup

Only needed on a fresh board.

1. Flash OpenWrt from the [Firmware Selector](https://firmware-selector.openwrt.org/?version=25.12.5&target=mediatek%2Ffilogic&id=glinet_gl-mt6000). GL.iNet UI at `http://192.168.8.1` → System → Upgrade, **"Do not keep configuration"**. It reboots to `http://192.168.1.1`.
2. Set a root password, then configure **WAN** (PPPoE credentials), **Wireless** (both radios, SSID, country) and **Timezone**.
3. Turn on Hardware Flow Offloading under Network → Firewall.

Then install curfew as above. Reverting to stock: download from `https://dl.gl-inet.com/router/mt6000/stable`, then System → Backup/Flash, unchecking "Keep settings".

## Testing

```sh
go test ./...          # unit tests, no privileges required
./docker/acceptance.sh # packet-path tests in a real OpenWrt image
```

The acceptance run builds a real LAN-to-WAN topology out of network namespaces and asserts whether a packet from a given source MAC **actually arrives**. Ruleset text is precisely the thing that looks correct while packets flow, so it cannot be the evidence (`docs/adr/0004-tests-assert-on-the-packet-path.md`).

Every packet-path test asserts a **baseline** first. A topology fault makes every probe read unreachable, which is indistinguishable from a perfect firewall, so without that guard a broken harness reports a flawless pass while testing nothing.

The OpenWrt image has no Go toolchain, so the test binaries are compiled on the host and executed inside it. The same run also exercises the legacy shell suite still under `legacy/`.

## Project structure

```
curfew/
├── main.go, version.go        # the laptop CLI
├── cmd/curfew-daemon/         # the router daemon
├── internal/
│   ├── contract/              # nftables object names, shared, dependency-free
│   ├── enforce/               # the ruleset, via netlink (router side only)
│   ├── httpui/                # device page and JSON API
│   ├── registry/              # the device list
│   ├── legacyconfig/          # importer for the old pipe-delimited config
│   └── deploy/                # install, push, pull over ssh
├── config/local/              # your actual config (gitignored)
├── docs/adr/                  # decisions and why
├── work/                      # specs, tasks and findings
├── legacy/                    # the shell implementation being replaced
└── docker/                    # OpenWrt test image and acceptance runner
```

## License

AGPL-3.0-only
