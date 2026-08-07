# curfew

Profile-based parental control system for OpenWrt on the GL.iNet Flint 2 (GL-MT6000).

> **Being rewritten in Go.** The section immediately below describes the new tool, which is where new work goes. Everything after it documents the shell implementation being replaced; treat that as the current state of the router, not as the direction. See `docs/adr/0007-the-tool-owns-every-operation-including-recovery-and-deployment.md`.

## The Go tool

Two binaries, and the split is a safety property rather than tidiness.

**`curfew`** runs on your laptop and does three things: `install`, `push`, `pull`. It cannot enforce anything, because it does not import the enforcement code at all. Running the wrong command on a laptop therefore cannot rewrite that laptop's own firewall. A test asserts this against the real import graph, so it cannot rot.

**`curfew-daemon`** runs on the router. It owns the nftables ruleset and serves the device page on port 8080.

```sh
# install (or update) the router, from your laptop
curfew install root@192.168.1.1 --wan pppoe-wan --password <choose-one>

# move the device list around
curfew pull root@192.168.1.1     # router  -> config/local/devices.json
curfew push root@192.168.1.1     # config/local/devices.json -> router
```

`--wan` is required and deliberately not guessed: on this router's PPPoE line the live device is `pppoe-wan`, not the configured `eth1`, and guessing it is exactly how enforcement silently matches nothing. Check with `ssh <host> ifstatus wan`.

The daemon detects the router's architecture over SSH and the correct binary is cross-compiled for it, because pushing the wrong architecture produces something that cannot exec, on a device reached over the very network being configured.

### What it does today

The MAC allowlist, and nothing else yet. Registered devices reach the internet; unregistered ones do not. Add devices from the page at `http://<router>:8080`, giving each an optional name.

The page reports, per device, what the **firewall** currently allows rather than what the saved list claims. If the two ever disagree you see it, because a green dot derived from reading back our own config file is precisely the reassurance that let the previous system report success while enforcing nothing.

The daemon re-asserts the ruleset on a timer, so a table wiped by hand or by a recovery path heals itself on the next tick rather than leaving a state nothing corrects.

### Running the tests

```sh
go test ./...          # unit tests, no privileges needed
./docker/acceptance.sh # packet-path tests in a real OpenWrt image, plus the legacy suite
```

The acceptance run sends real packets through a real LAN-to-WAN topology and asserts whether they arrive, which is the only trustworthy evidence about a firewall (`docs/adr/0004-tests-assert-on-the-packet-path.md`). Go has no toolchain in that image, so the test binaries are compiled on the host and executed inside it.

## Features (shell implementation, being replaced)

- **Profiles**: group multiple devices (phone, laptop) per child
- **Internet schedules**: block internet at certain times per profile
- **Time budgets**: daily limits shared across all devices in a profile
- **Tickets**: grant temporary access from a phone (no login needed)
- **Website blocking**: per-profile, with time groups (e.g. streaming blocked 20:00-08:00, gaming blocked 08:00-10:00)
- **Global filtering**: block gambling/porn/malware for all devices (auto-updated lists)
- **Unknown device blocking**: MAC allowlist prevents MAC randomization bypass
- **nftables**: uses OpenWrt's native firewall (auto-detected, iptables fallback)

## Setup (one time)

### 1. Flash OpenWrt

1. Download the sysupgrade image from the [Firmware Selector](https://firmware-selector.openwrt.org/?version=25.12.5&target=mediatek%2Ffilogic&id=glinet_gl-mt6000)
2. Go to `http://192.168.8.1` (GL.iNet UI) → System → Upgrade
3. Upload the `.bin` file, select **"Do not keep configuration"**
4. Wait 2-3 min. Router reboots to `http://192.168.1.1`

### 2. Set up internet + Wi-Fi

1. Open `http://192.168.1.1`, log in (root, no password initially)
2. Set a root password when prompted
3. **Network → Interfaces → WAN:** Protocol = PPPoE, enter your ISP credentials
4. **Network → Wireless:** Enable both radios, set SSID + password, Country = GB
5. **System → System:** Set Timezone = Europe/London
6. **Network → Firewall:** Enable Hardware Flow Offloading

### 3. Fill in your configs

```bash
cd ~/dev/github/wighawag/curfew/config/local
```

Edit the pre-created files with your actual values:

| File | What to set |
|---|---|
| `parental_profiles` | ALL profiles (adults + kids + IoT): name, budget, MAC addresses |
| `parental_websites` | Websites to block per profile, organized by time groups |
| `parental_blocklists` | Global blocklist URLs (gambling/porn/malware) |
| `crontab` | Your schedule times (bedtime, streaming, gaming blocks) |
| `tickets.html` | Profile names shown in the phone UI |

The `parental_profiles` file is the single source of truth: all MACs across all
profiles form the MAC allowlist. Adults and IoT devices get budget `0` (unlimited).

To find your devices' MAC addresses, connect them to the router first, then:
```bash
ssh root@192.168.1.1 "cat /tmp/dhcp.leases"
```

### 4. Run the installer

```bash
cd ~/dev/github/wighawag/curfew
./install.sh 192.168.1.1
```

This does everything: copies scripts, uploads your configs, sets up cron schedules, applies the firewall, downloads blocklists, and enables the boot script. Active tickets are preserved on re-runs.

### 5. Wife's phone

Bookmark: `http://192.168.1.1/tickets.html`
She taps a child → taps a duration → all their devices get internet. Auto-blocks when it expires.

### 6. Disable MAC randomization on kids' devices

- **iPhone:** Settings → Wi-Fi → tap "i" → Private Wi-Fi Address → OFF
- **Android:** Settings → Wi-Fi → tap network → Privacy → Use device MAC

## Updating later

Edit your files in `config/local/`, then re-run the installer:
```bash
./install.sh 192.168.1.1
```
Idempotent: scripts update, configs upload, cron regenerates, firewall set updates without clearing active blocks or tickets.

Force a full re-apply (clears active state):
```bash
./install.sh 192.168.1.1 --force
```

## Reverting to GL.iNet firmware

1. Download from `https://dl.gl-inet.com/router/mt6000/stable`
2. OpenWrt: System → Backup/Flash → upload GL.iNet firmware → uncheck "Keep settings"
3. Router reboots to GL.iNet at `http://192.168.8.1`

## Useful commands

```bash
ssh root@192.168.1.1
parental-profiles.sh status            # All profiles + blocked MACs
parental-profiles.sh block alice       # Block all Alice's devices
parental-profiles.sh ticket alice 30   # 30-min ticket for Alice
website-blocking.sh status             # Website blocking state
blocklists.sh status                   # Global blocklist counts
blocklists.sh update                   # Re-download blocklists now
```

## Testing

```bash
docker compose -f docker/docker-compose.yml run --rm test
```

113 tests on a real OpenWrt userland (`openwrt/rootfs`), with no mocked system tools. Most assert on nftables state; a network-namespace harness additionally builds a real LAN-to-WAN topology and asserts on the **packet path**, which is the only evidence that distinguishes "the ruleset looks right" from "the packet is dropped".

## Project structure

```
curfew/
├── config/local/              # Your actual configs (gitignored)
├── install.sh                 # One-command installer (idempotent)
├── scripts/
│   ├── parental-profiles.sh   # Internet schedules, budgets, tickets
│   ├── website-blocking.sh    # Per-profile website blocking with groups
│   ├── setup-firewall.sh      # MAC allowlist (block unknown devices)
│   └── blocklists.sh          # Global gambling/porn/malware filtering
├── web/tickets.html           # Phone UI for tickets
├── test/                      # 113 bats tests (incl. packet-path harness)
├── docker/                    # Test environment
└── docs/                      # Examples and guides
```

## License

AGPL-3.0-only
