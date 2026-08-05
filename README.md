# my-router

Profile-based parental control system for OpenWrt on the GL.iNet Flint 2 (GL-MT6000).

## Features

- **Profile-based**: Group multiple devices (phone, laptop, tablet) under one profile
- **Time schedules**: Block/unblock profiles at set times (bedtime, lunch, etc.)
- **Time budgets**: Daily limits shared across all devices in a profile (e.g. 2 hours/day)
- **Internet tickets**: Grant temporary access to a profile (e.g. 30 minutes) — auto-expires
- **Unknown device blocking**: MAC allowlist prevents MAC randomization bypass
- **Web interface**: Simple phone-friendly page for granting tickets (no login required)
- **Website blocking**: Per-device or network-wide domain blocking via dnsmasq

## Project structure

```
my-router/
├── scripts/
│   ├── parental-profiles.sh   # Profile-based parental control (main script)
│   └── setup-firewall.sh      # MAC allowlist firewall setup
├── config/
│   ├── parental_profiles.example  # Example profile config
│   └── mac_allowlist.example      # Example MAC allowlist
├── web/
│   ├── tickets.html           # Phone-friendly ticket UI
│   └── cgi-bin/ticket         # CGI backend for tickets
├── test/
│   ├── test_helper/mocks.sh   # Mock iptables/uci/logger for testing
│   ├── parental-profiles.bats # Unit tests for parental-profiles.sh
│   └── setup-firewall.bats    # Unit tests for setup-firewall.sh
├── docker/
│   ├── Dockerfile             # Test environment (Alpine + BusyBox + bats)
│   └── docker-compose.yml     # Docker Compose for running tests
└── docs/
    └── setup-guide.md         # Full setup guide
```

## Quick start

### Install on your router

```bash
# Copy scripts to router
scp scripts/parental-profiles.sh root@192.168.1.1:/usr/bin/
scp scripts/setup-firewall.sh root@192.168.1.1:/usr/bin/
scp web/tickets.html root@192.168.1.1:/www/
scp web/cgi-bin/ticket root@192.168.1.1:/www/cgi-bin/
ssh root@192.168.1.1 chmod +x /usr/bin/parental-profiles.sh /usr/bin/setup-firewall.sh /www/cgi-bin/ticket

# Create config
cp config/parental_profiles.example /etc/config/parental_profiles
# Edit with your devices' MAC addresses
vi /etc/config/parental_profiles

# Set up MAC allowlist
cp config/mac_allowlist.example /etc/config/mac_allowlist
# Edit with all your devices' MAC addresses
vi /etc/config/mac_allowlist
setup-firewall.sh apply
```

### Set up schedules (cron)

```bash
ssh root@192.168.1.1 crontab -e
```

Add:
```
# Time budget tracking (every minute)
* * * * * /usr/bin/parental-profiles.sh budget-check

# Bedtime (block at 20:00, unblock at 07:00)
0 20 * * * /usr/bin/parental-profiles.sh block alice
0 20 * * * /usr/bin/parental-profiles.sh block bob
0 7 * * * /usr/bin/parental-profiles.sh unblock alice
0 7 * * * /usr/bin/parental-profiles.sh unblock bob
```

### Grant access from your phone

Open `http://192.168.1.1/tickets.html` and tap a button. No login required.

## Testing

### Run tests with Docker

```bash
cd docker
docker compose run test
```

### Run tests locally (requires bats-core)

```bash
# Install bats
sudo apt install bats  # Debian/Ubuntu
# or: brew install bats-core  # macOS

# Run tests
bats test/
```

### Interactive testing shell

```bash
cd docker
docker compose run shell
# Inside container:
./scripts/parental-profiles.sh list
./scripts/parental-profiles.sh block alice
./scripts/parental-profiles.sh status
./scripts/parental-profiles.sh ticket alice 30
```

## Commands

```
parental-profiles.sh status                  Show status of all profiles
parental-profiles.sh list                    List all configured profiles
parental-profiles.sh block <profile>         Block all devices in a profile
parental-profiles.sh unblock <profile>       Unblock all devices in a profile
parental-profiles.sh ticket <profile> <min>  Grant temporary access (all devices)
parental-profiles.sh tickets                 List active tickets
parental-profiles.sh budget-check [profile]  Check time budgets (for cron)
parental-profiles.sh reset <profile>         Reset usage counter
```

## Configuration

### Profile config (`/etc/config/parental_profiles`)

```
# profile_name|budget_minutes_per_day|mac1,mac2,mac3
alice|120|aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02
bob|90|aa:bb:cc:dd:ee:03,aa:bb:cc:dd:ee:04
teen|0|aa:bb:cc:dd:ee:05,aa:bb:cc:dd:ee:06
```

- Budget of `0` = unlimited (schedule-only)
- Budget is shared across all devices in the profile

### MAC allowlist (`/etc/config/mac_allowlist`)

```
# One MAC per line, # = comment
aa:bb:cc:dd:ee:f1  # Dad's phone
aa:bb:cc:dd:ee:01  # Alice's phone
```

Only listed MACs can access the internet. All unknown devices are blocked.

## License

AGPL-3.0-only