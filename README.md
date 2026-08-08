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
| `curfew install <host>` | laptop | First-time setup: daemon, settings, service, device list, AdGuard |
| `curfew update <host>` | laptop | Update the daemon binary, keeping the router's settings and devices |
| `curfew push <host>` | laptop | Send your local device list to the router |
| `curfew pull <host>` | laptop | Merge the router's device list into yours |
| `curfew probe <host>` | laptop | Check the router's kernel still supports tickets |
| `curfew adopt-leases <host>` | laptop | Take over static DHCP leases written by something else |
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

### Two pages, split by when you need them

The **home page** answers the two questions you have with a child standing in front of you: is this child online, and can I give them twenty minutes? It is one row per profile, showing the state read off the firewall and what is left of the budget, with a block button, the preset ticket durations, and a box for any other number of minutes.

Everything that configures the household lives on **`/settings`**: schedules, which devices belong to which profile, the budgets themselves, and the two household budget knobs. That split is deliberate. Configuration is a sit-down job done rarely, and every control it added to the home page was something to scroll past at the moment it was least welcome.

A ticket is **gone after a reboot**, deliberately. A manual block is not.

Status is read from the **firewall**, never from re-evaluating the schedule or reading back our own config. If the schedule says a profile should be blocked and the firewall disagrees, the page says exactly that instead of showing you what it hoped. A green dot derived from our own config file is precisely the reassurance that let the previous system claim to be working.

The daemon re-asserts the ruleset on a timer, so a table wiped by hand, by a recovery path, or by anything else heals itself on the next tick. That re-assertion replaces the whole table in one transaction and carries live tickets across it with the time they have left, so a reconcile can neither cut a ticket short nor quietly restart its clock.

It also does **daily time budgets**, counted as actual use rather than as wall-clock time.

A profile can have four limits, all optional, and a profile with none of them is unlimited: a **total for the day** (4h), a **limit on one unbroken stretch** (2h), the **inactivity that ends a stretch** (10m), and **how long to wait after burning a stretch** (30m). Two more settings are for the whole household rather than per child: **when the day rolls over** (03:00 by default, because children are awake at midnight) and **how much traffic counts as using the internet**.

A minute only counts if the devices actually sent something. An idle phone in a pocket burns nothing, a blocked child burns nothing while they are blocked, and a ticket overrides a spent budget exactly as it overrides a bedtime. The decisions behind the continuity model, and the measurements behind where the counters live, are in `docs/adr/0009-the-budget-continuity-model.md`.

**The activity threshold's default is a guess, and both the daemon and the settings page say so.** How many bytes a minute mean "in use" cannot be worked out from first principles; it has to be measured against the devices in your house. So the settings page shows what each profile actually sent in the last interval, for every profile including the ones with no budget, right next to the field you set. Leave the budgets off for an evening, watch the figures, and set the threshold above what your idle devices send. Until you do, expect it to be somewhat wrong in one direction or the other.

### AdGuard Home

`curfew install` sets AdGuard up, or **adopts** one you installed yourself, and `-no-adguard` skips it entirely. Adoption changes exactly one thing and only when it is missing: an admin account. Your lists, your exceptions and your own login are left alone, and a backup of the config is kept.

That one change is not cosmetic. **An AdGuard with no admin account serves its entire REST API to every device on your LAN.** Measured: an unauthenticated `POST /control/protection {"enabled":false}` returns `200 OK` and turns off filtering for the whole house, and the request can come from the phone being filtered. The shell script this replaces shipped exactly that. If you set AdGuard up with it, check:

```sh
ssh root@192.168.1.1 "grep -A2 '^users:' /opt/AdGuardHome/adguardhome.yaml"
```

`users: []` means open. A test asserts this as an attack that stops working: it confirms the attack succeeds first, adopts, then requires the same request to fail while a correct password still works.

Setup also makes AdGuard actually own DNS: it checks which process holds port 53, moves dnsmasq to 54 (keeping DHCP) when it is in the way, waits for AdGuard to take the port, and **puts dnsmasq back if it does not**. An unfiltered household is bad; one with no resolver at all is worse.

Passwords: `-password` sets both the device page and AdGuard, and `-curfew-password` or `-adguard-password` override it individually. When adopting an AdGuard that already has a login, pass that existing one with `-adguard-password` so curfew can talk to its API.

curfew deliberately does **not** own `AdGuardHome.yaml`. AdGuard rewrites that file itself and drops anything it does not recognise, so everything else curfew does goes through the REST API. The reasoning and the measurements are in `docs/adr/0010-curfew-drives-adguard-through-its-api-and-owns-only-its-own-objects.md`.

Guest passes are designed but not built. The decisions behind them are recorded in `docs/adr/` so they land as decisions rather than guesses.

### Per-profile website and service restrictions

A profile can lose some of the internet without losing all of it. "Eli has internet from 08:00 to 22:00" is a schedule window, enforced in the firewall by MAC. "And no streaming between 08:00 and 10:00" is a **DNS restriction**, enforced in AdGuard, and the two layer rather than competing.

A restriction draws on two sources, and both work:

- **AdGuard's built-in service catalogue** (`youtube`, `tiktok`, `netflix`, `roblox`, `discord` and many more). Preferred, because it is maintained upstream and keeps working when a service adds new domains.
- **Your own domain lists**, defined once in `profiles.json` under `block_lists` and referenced by name. They live in curfew's config, so they travel with `push` and `pull`.

```json
{
  "block_lists": { "no_streaming": ["twitch.tv", "iplayer.bbc.co.uk"] },
  "profiles": [{
    "name": "eli",
    "devices": ["14:e0:1d:6a:9c:6c"],
    "dns_restrictions": [{
      "name": "no streaming",
      "services": ["youtube", "netflix"],
      "lists": ["no_streaming"],
      "windows": [{"days": ["mon","tue","wed","thu","fri"], "start": "08:00", "end": "10:00"}]
    }]
  }]
}
```

If you are migrating from the shell scripts, they may have left static leases of their own. `curfew adopt-leases <host>` shows you every one whose MAC is a registered device and, with `-yes`, hands it to curfew at the same address, so the device does not move. Without it, curfew leaves such an entry strictly alone and reports it as a conflict on every pass. Entries for devices curfew does not know about are never offered and never touched.

To make this possible curfew **pins a static DHCP lease** for each registered device, because AdGuard identifies a client by IP and cannot be keyed by MAC at all. It writes those as uci entries named `dhcp.curfew_<mac>`, and it owns **only** those: any host entry you or anything else created is left exactly as it was, which a test asserts against a real `/etc/config/dhcp`.

**IPv6 matters here more than it looks.** On this household's router roughly half of all DNS queries arrive over IPv6, including a child's phone, so a rule keyed only to an IPv4 lease would look completely correct and do nothing for half the traffic. curfew therefore adds the device's current IPv6 addresses to the same AdGuard client, read from the router's neighbour table. The two families are treated differently on purpose: IPv4 comes only from the lease curfew pinned, because DHCP reissues addresses and a stale one would restrict the *wrong child*, while a rotating IPv6 privacy address is safe to follow because it is never reused. The reasoning and the measurements are in `docs/adr/0011-curfew-pins-ipv4-leases-and-follows-ipv6-to-identify-a-device-to-adguard.md`.

If a device has no known address, its profile's restrictions **do not apply to it**, and the daemon says so in the log rather than pretending otherwise. Schedules, budgets and manual blocks are unaffected, because those are the firewall and never consult an IP address.

**Encrypted DNS is partly closed.** A restriction is worthless if the child's browser can just ask somebody else, so curfew also blocks the well-known DNS-over-HTTPS endpoint hostnames (`cloudflare-dns.com`, `dns.google`, `quad9.net` and the rest) for any profile that has restrictions. Almost every browser and phone exposes that setting as a provider *name*, so the lookup goes through the router and fails. This applies around the clock rather than only inside the window, because a child sets an endpoint once and it persists. It applies only to profiles that have restrictions, so your own devices keep encrypted DNS, and you can turn it off with `"block_doh_bootstrap": false`.

What it does **not** close: a DoH endpoint entered as a bare IP address, a hardcoded plain resolver like `8.8.8.8`, DNS-over-TLS on port 853, or a VPN. Those need firewall rules rather than DNS rules, and they are specified in `work/specs/proposed/force-dns-through-the-router.md` rather than quietly implied to be handled. Treat the current state as a speed bump against a curious child, not a control against a determined one.

One more limit: a child who **copies a sibling's registered MAC** inherits that sibling's access and restrictions, which no MAC allowlist can see. (A child who *randomises* their MAC is already handled: an unknown MAC matches nothing and is dropped, so they lose the internet entirely.)

This feature needs AdGuard credentials in the daemon's settings file. `curfew install` writes them; `curfew update` deliberately never rewrites that file, so on a router set up before this existed the feature stays off, and `update` tells you so and tells you that one `curfew install` turns it on.

## If something goes wrong

A wrong ruleset costs WAN, never LAN, so **SSH always works**. To remove all policy and restore connectivity immediately:

```sh
ssh root@192.168.1.1 'nft delete table inet curfew'
ssh root@192.168.1.1 '/etc/init.d/curfew stop'     # or it reconciles straight back
```

One table, not two. Budget accounting lives in a second table, `curfew_accounting`, which holds counters and no verdicts, so leaving it in place cannot block anything: a packet-path test asserts that a client reaches the internet with the enforcement table deleted and the accounting table still present. Remove it too if you want a clean ruleset (`nft delete table inet curfew_accounting`), but nothing depends on you remembering to.

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

`state.json` holds the manual blocks and the budget counters. It is state rather than configuration, and `push` and `pull` deliberately never touch it: it belongs to the router, and copying a laptop's idea of who is grounded, or of how much of today a child has used, over the top of it would undo something decided on a phone five minutes earlier. The budgets themselves are configuration and live in `profiles.json`, which push and pull do carry.

The authoritative list of what is in `state.json` is the `blockstate.State` type in `internal/blockstate`, deliberately stated in exactly one place: three drafts of the spec that preceded it each dropped a different member while retyping the list in prose.

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
