package adguard

import (
	"fmt"
	"strings"
)

// The configuration curfew writes when it installs AdGuard itself, and the
// service definition that runs it.
//
// This is the ONLY config curfew authors. Once AdGuard is running, AdGuard
// owns this file and rewrites it (measured: it migrates the schema and expands
// defaults on first start), so nothing here should be treated as the shape of
// the file afterwards.

// ConfigParams are the few things that differ per household.
type ConfigParams struct {
	User         string
	PasswordHash string
	// RouterIP is the LAN address AdGuard serves DNS on. Empty binds to all
	// addresses, which is what a first install on an unknown board needs.
	RouterIP string
	// Upstreams are the resolvers AdGuard forwards to.
	Upstreams []string
	// Categories are the blocklists to subscribe to. Nil means the default
	// set; an EMPTY non-nil slice means a household that wants none, which is
	// a choice curfew must be able to reproduce on a reinstall rather than
	// quietly overriding. See schedule.Profiles.FilterCategories.
	Categories []string
}

// DefaultUpstreams are used when none are configured.
var DefaultUpstreams = []string{"1.1.1.1", "8.8.8.8"}

// Categories are the filter lists a household gets by default, per ADR 0002.
// dnsmasq could not cope with lists of this size, which is the whole reason
// AdGuard owns DNS filtering.
var Categories = []string{
	"Gambling", "Porn", "Malware", "Phishing", "Ransomware", "Scam", "Fraud", "Ads",
}

// CategorySource is where category lists are fetched from.
//
// A variable rather than a constant so a test can point the catalogue at a
// local server and exercise the REAL ownership rule instead of a special case
// compiled in for tests. Nothing in production changes it.
var CategorySource = "https://blocklistproject.github.io/Lists/adguard/"

// CategoryURL is where a category's list comes from.
func CategoryURL(name string) string {
	return CategorySource + strings.ToLower(name) + "-ags.txt"
}

// InitialConfig renders AdGuard's config for a fresh install.
//
// The admin account is present from the very first byte. That is the point:
// the implementation this replaces wrote `users: []`, which leaves AdGuard's
// entire REST API open to every device on the LAN, so a filtered child could
// turn filtering off with one request. Writing the account in up front means
// there is never a window, however short, in which that is true.
func InitialConfig(p ConfigParams) string {
	bind := "0.0.0.0"
	if p.RouterIP != "" {
		bind = p.RouterIP
	}
	ups := p.Upstreams
	if len(ups) == 0 {
		ups = DefaultUpstreams
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by 'curfew install'. AdGuard owns this file from here on:
# it rewrites it on start and on every change made through its own UI or API.
# curfew does NOT reformat or regenerate it, and manages what it needs through
# the REST API instead. See docs/adr/0010.
http:
  address: 0.0.0.0:%d
  session_ttl: 720h
users:
- name: %s
  password: %s
dns:
  bind_hosts:
  - %s
  port: 53
  upstream_dns:
`, DefaultPort, p.User, p.PasswordHash, bind)
	for _, u := range ups {
		fmt.Fprintf(&b, "  - %s\n", u)
	}
	b.WriteString("  bootstrap_dns:\n")
	for _, u := range ups {
		fmt.Fprintf(&b, "  - %s\n", u)
	}
	b.WriteString(`  filtering_enabled: true
  protection_enabled: true
  cache_size: 4194304
  cache_ttl_min: 60
  cache_ttl_max: 86400
  blocking_mode: nxdomain
  serve_plain_dns: true
  hostsfile_enabled: true
schema_version: 34
filters:
`)
	cats := Categories
	if p.Categories != nil {
		cats = p.Categories
	}
	for i, name := range cats {
		fmt.Fprintf(&b, "- enabled: true\n  url: %s\n  name: %s\n  id: %d\n",
			CategoryURL(name), name, i+1)
	}
	b.WriteString(`whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
filtering:
  filtering_enabled: true
  protection_enabled: true
  parental_enabled: false
  safebrowsing_enabled: true
  blocking_mode: nxdomain
`)
	return b.String()
}

// InitScript is the procd service definition, so AdGuard survives a reboot.
func InitScript() string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# Written by 'curfew install'.
START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command %s -c %s -w /opt/AdGuardHome --no-check-update
    procd_set_param file %s
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_close_instance
}
`, BinaryPath, ConfigPath, ConfigPath)
}

// ArchFor maps a router's uname -m to AdGuard's release naming.
//
// It refuses an architecture it does not know rather than guessing, for the
// same reason the WAN interface is never guessed: a wrong answer here is a
// download that produces a binary which cannot run, discovered on the router.
func ArchFor(uname string) (string, error) {
	switch strings.TrimSpace(uname) {
	case "aarch64", "arm64":
		return "arm64", nil
	case "x86_64", "amd64":
		return "amd64", nil
	case "armv7l", "armv7":
		return "armv7", nil
	case "mips":
		return "mips", nil
	case "mipsel", "mipsle":
		return "mipsle", nil
	default:
		return "", fmt.Errorf("no AdGuard build is known for architecture %q; "+
			"install AdGuard yourself and re-run, and curfew will adopt it", uname)
	}
}
