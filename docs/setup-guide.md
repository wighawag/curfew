# Flint 2 Parental Control Setup Guide

## Prerequisites

- GL.iNet Flint 2 (GL-MT6000) router
- Plusnet FTTP with PPPoE credentials (`username@plusdsl.net` + password)
- Laptop on same network
- This repo at `~/dev/github/wighawag/my-router`

---

## Step 1: Flash OpenWrt

1. Download sysupgrade image:
   `https://firmware-selector.openwrt.org/?version=25.12.5&target=mediatek%2Ffilogic&id=glinet_gl-mt6000`
2. Go to `http://192.168.8.1` (GL.iNet UI) → System → Upgrade
3. Upload the `.bin` file, select **"Do not keep configuration"**
4. Wait 2-3 min. Router reboots to `http://192.168.1.1`

## Step 2: Set up internet + Wi-Fi

1. Open `http://192.168.1.1`, log in (root, no password initially)
2. Set a root password when prompted
3. **Network → Interfaces → WAN:** Protocol = PPPoE, enter Plusnet credentials
4. **Network → Wireless:** Enable both radios, set SSID + password, Country = GB
5. **System → System:** Set Timezone = Europe/London
6. **Network → Firewall:** Enable Hardware Flow Offloading

## Step 3: Fill in your configs

```bash
cd ~/dev/github/wighawag/my-router/config/local
```

Edit the pre-created files with your actual values:

```
parental_profiles    # name|budget_minutes|mac1,mac2
parental_websites    # name|group|domain1,domain2
mac_allowlist        # one MAC per line (ALL devices)
parental_blocklists  # global blocklist URLs (gambling/porn/malware)
crontab              # your schedules
tickets.html         # profile names for the web UI
```

To find your devices' MAC addresses, connect them to the router first,
then run: `ssh root@192.168.1.1 "cat /tmp/dhcp.leases"`

## Step 4: Run the installer

```bash
cd ~/dev/github/wighawag/my-router
./install.sh 192.168.1.1
```

This copies scripts, uploads your configs, sets up cron, and applies the firewall.
Active tickets and budgets are preserved on re-runs.

## Step 5: Download blocklists

```bash
ssh root@192.168.1.1 blocklists.sh update
```

Downloads gambling/porn/malware lists and configures dnsmasq.
Auto-refreshes weekly via cron.

## Step 6: Wife's phone

Bookmark: `http://192.168.1.1/tickets.html`
She taps a child → taps a duration → all their devices get internet.
No login needed. Auto-blocks when the ticket expires.

## Step 7: Disable MAC randomization on kids' devices

- **iPhone:** Settings → Wi-Fi → tap "i" → Private Wi-Fi Address → OFF
- **Android:** Settings → Wi-Fi → tap network → Privacy → Use device MAC

---

## Updating later

```bash
# Edit your local configs
vi ~/dev/github/wighawag/my-router/config/local/parental_profiles

# Re-run installer (idempotent, preserves tickets)
./install.sh 192.168.1.1
```

## Reverting to GL.iNet firmware

1. Download from `https://dl.gl-inet.com/router/mt6000/stable`
2. OpenWrt: System → Backup/Flash → upload → uncheck "Keep settings"
3. Router reboots to GL.iNet at `http://192.168.8.1`

## Useful commands

```bash
ssh root@192.168.1.1
parental-profiles.sh status            # All profiles + blocked MACs
parental-profiles.sh block alice       # Block all Alice's devices
parental-profiles.sh ticket alice 30   # 30-min ticket for Alice
website-blocking.sh status             # Website blocking state
blocklists.sh status                   # Global blocklist counts
setup-firewall.sh apply                # Re-apply MAC allowlist
```
