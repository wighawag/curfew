# Flint 2 Parental Control Setup Guide

## Prerequisites

- GL.iNet Flint 2 (GL-MT6000) router
- Plusnet FTTP with PPPoE credentials (`username@plusdsl.net` + password)
- Laptop on same network
- This repo cloned at `~/dev/github/wighawag/my-router`

---

## Step 1: Flash OpenWrt

1. Download sysupgrade image:
   `https://firmware-selector.openwrt.org/?version=25.12.5&target=mediatek%2Ffilogic&id=glinet_gl-mt6000`
2. Go to `http://192.168.8.1` → System → Upgrade
3. Upload the `.bin` file, select **"Do not keep configuration"**
4. Wait 2-3 minutes. Router reboots to `http://192.168.1.1`

## Step 2: Set up internet + Wi-Fi

1. Open `http://192.168.1.1`, log in (root, no password initially)
2. Set a root password when prompted
3. **Network → Interfaces → WAN:** Protocol = PPPoE, enter Plusnet credentials
4. **Network → Wireless:** Enable both radios, set SSID + password, Country = GB
5. **System → System:** Set Timezone = Europe/London
6. **Network → Firewall:** Enable Hardware Flow Offloading

## Step 3: Run the installer

From your laptop:
```bash
cd ~/dev/github/wighawag/my-router
./install.sh 192.168.1.1
```

This copies all scripts, web interface, configs, and cron schedules to the router.
It prints a list of connected devices with their MAC addresses.

## Step 4: Edit configs with your MAC addresses

```bash
ssh root@192.168.1.1
vi /etc/config/parental_profiles    # Profiles: name|budget_minutes|mac1,mac2
vi /etc/config/parental_websites    # Websites: name|domain1,domain2
vi /etc/config/mac_allowlist        # All allowed MACs (one per line)
setup-firewall.sh apply             # Apply the MAC allowlist
```

## Step 5: Adjust schedules (if needed)

```bash
ssh root@192.168.1.1 crontab -e
```

The installer sets up default schedules (bedtime 20:00, lunch 12-13:00, etc).
Edit the times to match your family's routine.

## Step 6: Wife's phone

Bookmark this on her phone: `http://192.168.1.1/tickets.html`
She taps a child's name → taps a duration → all their devices get internet.
No login needed. Auto-blocks when the ticket expires.

## Step 7: Disable MAC randomization on kids' devices

- **iPhone:** Settings → Wi-Fi → tap "i" → Private Wi-Fi Address → OFF
- **Android:** Settings → Wi-Fi → tap network → Privacy → Use device MAC

---

## Reverting to GL.iNet firmware

1. Download from `https://dl.gl-inet.com/router/mt6000/stable`
2. OpenWrt: System → Backup/Flash → upload GL.iNet firmware → uncheck "Keep settings"
3. Router reboots back to GL.iNet at `http://192.168.8.1`

## Useful commands

```bash
ssh root@192.168.1.1
parental-profiles.sh status           # See all profiles and their state
parental-profiles.sh block alice      # Block all Alice's devices
parental-profiles.sh ticket alice 30  # 30-min ticket for Alice
website-blocking.sh status            # See website blocking state
setup-firewall.sh apply               # Re-apply MAC allowlist
```