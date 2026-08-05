# Example setup: 2 adults, 3 kids with different schedules

# === /etc/config/parental_profiles ===
# Format: profile_name|budget_minutes_per_day|mac1,mac2,mac3
# Budget of 0 = unlimited

# Adults - full internet, no restrictions
dad|0|aa:bb:cc:11:22:31,aa:bb:cc:11:22:32
mom|0|aa:bb:cc:11:22:41,aa:bb:cc:11:22:42

# Kids - with budgets and schedules
alice|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
bob|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
charlie|60|aa:bb:cc:dd:ee:05,aa:bb:cc:dd:ee:06


# === /etc/config/parental_websites ===
# Format: profile_name|group_name|domain1,domain2,...

# Alice: streaming + gaming blocks
alice|no_streaming|youtube.com,www.youtube.com,tiktok.com,www.tiktok.com,netflix.com,www.netflix.com,disneyplus.com,www.disneyplus.com,twitch.tv,www.twitch.tv
alice|no_gaming|roblox.com,www.roblox.com,steam.com,store.steampowered.com,epicgames.com,www.epicgames.com

# Bob: same blocks
bob|no_streaming|youtube.com,www.youtube.com,tiktok.com,www.tiktok.com,netflix.com,www.netflix.com,disneyplus.com,www.disneyplus.com,twitch.tv,www.twitch.tv
bob|no_gaming|roblox.com,www.roblox.com,steam.com,store.steampowered.com,epicgames.com,www.epicgames.com

# Charlie: same blocks
charlie|no_streaming|youtube.com,www.youtube.com,tiktok.com,www.tiktok.com,netflix.com,www.netflix.com,disneyplus.com,www.disneyplus.com,twitch.tv,www.twitch.tv
charlie|no_gaming|roblox.com,www.roblox.com,steam.com,store.steampowered.com,epicgames.com,www.epicgames.com


# === /etc/config/mac_allowlist ===
# All devices that are allowed internet access (one MAC per line)

# Adults
aa:bb:cc:11:22:31  # Dad's phone
aa:bb:cc:11:22:32  # Dad's laptop
aa:bb:cc:11:22:41  # Mom's phone
aa:bb:cc:11:22:42  # Mom's laptop

# Kids
aa:bb:cc:dd:ee:01  # Alice's phone
aa:bb:cc:dd:ee:02  # Alice's laptop
aa:bb:cc:dd:ee:03  # Bob's phone
aa:bb:cc:dd:ee:04  # Bob's tablet
aa:bb:cc:dd:ee:05  # Charlie's phone
aa:bb:cc:dd:ee:06  # Charlie's laptop

# Other household devices
aa:bb:cc:99:88:77  # Smart TV
aa:bb:cc:99:88:78  # NAS
aa:bb:cc:99:88:79  # Printer


# === crontab ===
# Set up by install.sh, edit with: ssh root@192.168.1.1 crontab -e

# Time budget tracking (every minute - MUST run)
* * * * * /usr/bin/parental-profiles.sh budget-check

# Refresh website blocking DNS (hourly)
0 * * * * /usr/bin/website-blocking.sh refresh

# === Internet schedules ===
# No internet 22:00-08:00 for all kids
0 22 * * * /usr/bin/parental-profiles.sh block alice
0 22 * * * /usr/bin/parental-profiles.sh block bob
0 22 * * * /usr/bin/parental-profiles.sh block charlie
0 8 * * * /usr/bin/parental-profiles.sh unblock alice
0 8 * * * /usr/bin/parental-profiles.sh unblock bob
0 8 * * * /usr/bin/parental-profiles.sh unblock charlie

# === Website blocking: no streaming 20:00-08:00 ===
0 20 * * * /usr/bin/website-blocking.sh enable alice no_streaming
0 20 * * * /usr/bin/website-blocking.sh enable bob no_streaming
0 20 * * * /usr/bin/website-blocking.sh enable charlie no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable alice no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable bob no_streaming
0 8 * * * /usr/bin/website-blocking.sh disable charlie no_streaming

# === Website blocking: no gaming 08:00-10:00 ===
0 8 * * * /usr/bin/website-blocking.sh enable alice no_gaming
0 8 * * * /usr/bin/website-blocking.sh enable bob no_gaming
0 8 * * * /usr/bin/website-blocking.sh enable charlie no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable alice no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable bob no_gaming
0 10 * * * /usr/bin/website-blocking.sh disable charlie no_gaming


# === tickets.html ===
# Edit /www/tickets.html on the router to set profile names:
#   var profiles = ["alice", "bob", "charlie"];
# Wife opens http://192.168.1.1/tickets.html and taps a child + duration.
# All devices for that child get internet temporarily, auto-expires.