package dnsnames

import (
	"strings"
	"testing"
)

// Real `uci show` output from the test image (OpenWrt 25.12.4) after adding
// list entries, and the live router's NTP servers.
const imageDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].rebind_protection='1'
dhcp.@dnsmasq[0].local='/lan/'
dhcp.@dnsmasq[0].domain='lan'
dhcp.@dnsmasq[0].address='/*.lan.example.test/192.168.1.122' '/other.example/192.168.1.9'
dhcp.@dnsmasq[0].server='/*.lan.example.test/' '/corp.example/10.0.0.1'
dhcp.lan=dhcp
`

const liveSystem = `system.ntp=timeserver
system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org' '2.openwrt.pool.ntp.org' '3.openwrt.pool.ntp.org'
`

// The rendering table of ADR 0013, exactly.
func TestRenderingIsTheADRTable(t *testing.T) {
	bare, wild := mustParse(t, "lan.telemaque.ska.sh"), mustParse(t, "*.lan.telemaque.ska.sh")
	if got := bare.DnsmasqAddress("192.168.1.122"); got != "/lan.telemaque.ska.sh/192.168.1.122" {
		t.Error(got)
	}
	if got := bare.DnsmasqServer(); got != "/lan.telemaque.ska.sh/" {
		t.Error(got)
	}
	if got := wild.DnsmasqAddress("192.168.1.122"); got != "/*.lan.telemaque.ska.sh/192.168.1.122" {
		t.Error(got)
	}
	if got := wild.DnsmasqServer(); got != "/*.lan.telemaque.ska.sh/" {
		t.Error(got)
	}
	if got := strings.Join(bare.AdGuardDomains(), " "); got != "lan.telemaque.ska.sh *.lan.telemaque.ska.sh" {
		t.Error(got)
	}
	if got := strings.Join(wild.AdGuardDomains(), " "); got != "*.lan.telemaque.ska.sh" {
		t.Error(got)
	}
}

func TestReadingTheRoutersUCI(t *testing.T) {
	addr, srv := DnsmasqLists(imageDHCP)
	if strings.Join(addr, "|") != "/*.lan.example.test/192.168.1.122|/other.example/192.168.1.9" {
		t.Errorf("address list: %q", addr)
	}
	if strings.Join(srv, "|") != "/*.lan.example.test/|/corp.example/10.0.0.1" {
		t.Errorf("server list: %q", srv)
	}
	ctx := ContextFromUCI(imageDHCP, liveSystem)
	if !ctx.Known || strings.Join(ctx.LocalDomains, ",") != "lan,lan" {
		t.Errorf("local domains: %+v", ctx)
	}
	if len(ctx.RouterHostnames) != 4 || ctx.RouterHostnames[0] != "0.openwrt.pool.ntp.org" {
		t.Errorf("ntp servers: %+v", ctx.RouterHostnames)
	}
	if got := DomainsOf("/one.example/two.example/1.2.3.4"); strings.Join(got, ",") != "one.example,two.example" {
		t.Errorf("DomainsOf: %v", got)
	}
	if got := DomainsOf("1.2.3.4"); got != nil {
		t.Errorf("a plain server names no domain: %v", got)
	}
	if got := UCIValues(`'it'\''s' 'b'`); strings.Join(got, "|") != "it's|b" {
		t.Errorf("uci escape: %q", got)
	}
}

// Reviewer P2: a NAMED dnsmasq section is the same section curfew writes
// through @dnsmasq[0], so its lists must be read under its name too, or every
// pass would add the same entry again.
func TestANamedDnsmasqSectionIsReadToo(t *testing.T) {
	show := "dhcp.main=dnsmasq\ndhcp.main.local='/lan/'\ndhcp.main.address='/x.home.arpa/192.168.1.5'\n" +
		"dhcp.main.server='/x.home.arpa/'\ndhcp.second=dnsmasq\ndhcp.second.address='/no.example/1.2.3.4'\n"
	addr, srv := DnsmasqLists(show)
	if strings.Join(addr, ",") != "/x.home.arpa/192.168.1.5" || strings.Join(srv, ",") != "/x.home.arpa/" {
		t.Errorf("got %v %v", addr, srv)
	}
	if ctx := ContextFromUCI(show, ""); strings.Join(ctx.LocalDomains, ",") != "lan" {
		t.Errorf("local domain of a named section: %+v", ctx)
	}
}
