# my-router

Profile-based parental control system for OpenWrt on the GL.iNet Flint 2 (GL-MT6000).

## Features

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
cd ~/dev/github/wighawag/my-router/config/local
```

Edit the pre-created files with your actual values:

| File | What to set |
|---|---|
| `parental_profiles` | Profile names, daily budget (minutes), MAC addresses |
| `parental_websites` | Websites to block per profile, organized by time groups |
| `mac_allowlist` | ALL device MACs that are allowed internet (one per line) |
| `parental_blocklists` | Global blocklist URLs (gambling/porn/malware) |
| `crontab` | Your schedule times (bedtime, streaming, gaming blocks) |
| `tickets.html` | Profile names shown in the phone UI |

To find your devices' MAC addresses, connect them to the router first, then:
```bash
ssh root@192.168.1.1 "cat /tmp/dhcp.leases"
```

### 4. Run the installer

```bash
cd ~/dev/github/wighawag/my-router
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

81 tests with real nftables (Alpine + NET_ADMIN, same `nft` binary as OpenWrt).

## Project structure

```
my-router/
├── config/local/              # Your actual configs (gitignored)
├── install.sh                 # One-command installer (idempotent)
├── scripts/
│   ├── parental-profiles.sh   # Internet schedules, budgets, tickets
│   ├── website-blocking.sh    # Per-profile website blocking with groups
│   ├── setup-firewall.sh      # MAC allowlist (block unknown devices)
│   └── blocklists.sh          # Global gambling/porn/malware filtering
├── web/tickets.html           # Phone UI for tickets
├── test/                      # 81 bats tests
├── docker/                    # Test environment
└── docs/                      # Examples and guides
```

## License

AGPL-3.0-only
