// Package dnstest is what the local-DNS-names acceptance tests share: a DNS
// client that tells NODATA from NXDOMAIN from a forwarded answer, a fixture
// upstream that answers every name with a SENTINEL, and the rendering of
// dnsmasq's DNS options from uci the way OpenWrt's init script does.
//
// It is used only by tests, like internal/netnstest, and imports nothing of
// curfew's. The technique is docs/spikes/local-dns-names/measure.sh's: the
// upstream answers every name under test with A 93.184.216.66 and AAAA
// 2606:4700::66, so a sentinel in an answer is a question that FELL THROUGH to
// upstream, which is exactly what "AAAA gets no address and is not forwarded"
// has to rule out.
package dnstest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The fixture upstream's answers. 93.184.216.0/24 is public, so dnsmasq's
// rebind protection lets it through (the RFC 5737 documentation ranges are
// treated as private and dropped, measured).
const (
	SentinelA    = "93.184.216.66"
	SentinelAAAA = "2606:4700::66"
	// UpstreamAddr is where the fixture upstream listens.
	UpstreamAddr = "127.0.0.1:5454"
	// PrivateName is answered by the fixture upstream with a PRIVATE address,
	// to show what rebind protection does to today's public record.
	PrivateName = "rebind.example"
)

// TypeHTTPS is DNS type 65, which browsers ask for alongside A and AAAA.
const TypeHTTPS = dnsmessage.Type(65)

// Answer is what a resolver said.
type Answer struct {
	RCode dnsmessage.RCode
	A     []string
	AAAA  []string
	// Other counts answer records of any other type.
	Other int
}

// NoData reports NOERROR with nothing in the answer section.
func (a Answer) NoData() bool {
	return a.RCode == dnsmessage.RCodeSuccess && len(a.A) == 0 && len(a.AAAA) == 0 && a.Other == 0
}

// Sentinel reports whether the answer came from the fixture upstream.
func (a Answer) Sentinel() bool {
	for _, x := range a.A {
		if x == SentinelA {
			return true
		}
	}
	for _, x := range a.AAAA {
		if x == SentinelAAAA {
			return true
		}
	}
	return false
}

func (a Answer) String() string {
	return fmt.Sprintf("rcode=%s A=%v AAAA=%v other=%d", a.RCode, a.A, a.AAAA, a.Other)
}

// Query asks server (host:port) one question over UDP, retrying a few times
// on timeout, since a loaded container drops the odd packet.
func Query(server, name string, t dnsmessage.Type) (Answer, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return Answer{}, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}},
	}
	buf, err := msg.Pack()
	if err != nil {
		return Answer{}, err
	}
	var last error
	for range 5 {
		conn, err := net.Dial("udp", server)
		if err != nil {
			return Answer{}, err
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(buf); err != nil {
			conn.Close()
			last = err
			continue
		}
		resp := make([]byte, 4096)
		k, err := conn.Read(resp)
		conn.Close()
		if err != nil {
			last = err
			continue
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp[:k]); err != nil {
			return Answer{}, err
		}
		a := Answer{RCode: m.Header.RCode}
		for _, rr := range m.Answers {
			switch b := rr.Body.(type) {
			case *dnsmessage.AResource:
				a.A = append(a.A, net.IP(b.A[:]).String())
			case *dnsmessage.AAAAResource:
				a.AAAA = append(a.AAAA, net.IP(b.AAAA[:]).String())
			default:
				a.Other++
			}
		}
		return a, nil
	}
	return Answer{}, fmt.Errorf("no answer from %s for %s %s: %v", server, name, t, last)
}

// StartUpstream starts the fixture upstream for the given domains: each is
// answered, with every name below it, by the two sentinels, and PrivateName
// by a private address. It returns a stop function.
func StartUpstream(domains ...string) (func(), error) {
	args := []string{"--port=5454", "--no-hosts", "--no-resolv", "--bind-interfaces",
		"--listen-address=127.0.0.1", "--keep-in-foreground", "--pid-file=",
		"--address=/" + PrivateName + "/192.168.1.122", "--address=/example.com/93.184.216.10"}
	for _, d := range domains {
		args = append(args, "--address=/"+d+"/"+SentinelA, "--address=/"+d+"/"+SentinelAAAA)
	}
	cmd := exec.Command("dnsmasq", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }
	for range 50 {
		if a, err := Query(UpstreamAddr, "example.com", dnsmessage.TypeA); err == nil && len(a.A) == 1 {
			return stop, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return nil, fmt.Errorf("the fixture upstream never answered")
}

// DnsmasqDNSOptions renders the DNS-side options of dhcp.@dnsmasq[0] from
// `uci show dhcp`, exactly as OpenWrt 25.12's /etc/init.d/dnsmasq does for the
// ones local names depend on: `list address` and `list server` values passed
// VERBATIM as address= and server= lines, `option local` as local=, and
// rebind_protection / rebind_localhost / rebind_domain.
func DnsmasqDNSOptions(uciShow string) []string {
	var out []string
	get := func(key string) []string {
		for _, line := range strings.Split(uciShow, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "dhcp.@dnsmasq[0]."+key+"="); ok {
				return values(v)
			}
		}
		return nil
	}
	for _, v := range get("local") {
		out = append(out, "local="+v)
	}
	if r := get("rebind_protection"); len(r) == 0 || r[0] == "1" {
		out = append(out, "stop-dns-rebind")
		if l := get("rebind_localhost"); len(l) > 0 && l[0] == "1" {
			out = append(out, "rebind-localhost-ok")
		}
		for _, v := range get("rebind_domain") {
			out = append(out, "rebind-domain-ok="+v)
		}
	}
	for _, v := range get("server") {
		out = append(out, "server="+v)
	}
	for _, v := range get("address") {
		out = append(out, "address="+v)
	}
	return out
}

func values(v string) []string {
	var out []string
	for _, part := range strings.Split(v, "' '") {
		out = append(out, strings.Trim(part, "'"))
	}
	return out
}

// Resolver is a router-shaped dnsmasq answering DNS on one port.
type Resolver struct {
	Port int
	cmd  *exec.Cmd
	Conf string
}

// StartResolver runs dnsmasq on 127.0.0.1:port with the given option lines
// and the fixture upstream as its only upstream. It fails when dnsmasq does
// not stay up, because dnsmasq exits rather than skipping a line it rejects.
func StartResolver(port int, conf string, options []string) (*Resolver, error) {
	body := fmt.Sprintf("port=%d\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\n"+
		"server=%s\n%s\n", port, strings.Replace(UpstreamAddr, ":", "#", 1), strings.Join(options, "\n"))
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		return nil, err
	}
	cmd := exec.Command("dnsmasq", "--keep-in-foreground", "--pid-file=", "-C", conf)
	logf, _ := os.Create(conf + ".log")
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := &Resolver{Port: port, cmd: cmd, Conf: conf}
	exited := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(exited) }()
	for range 50 {
		select {
		case <-exited:
			log, _ := os.ReadFile(conf + ".log")
			return nil, fmt.Errorf("dnsmasq exited on this config:\n%s\n%s", log, body)
		default:
		}
		if _, err := Query(r.Addr(), "example.com", dnsmessage.TypeA); err == nil {
			return r, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.Stop()
	return nil, fmt.Errorf("dnsmasq never answered on port %d", port)
}

// Addr is where it answers.
func (r *Resolver) Addr() string { return fmt.Sprintf("127.0.0.1:%d", r.Port) }

// Stop kills it.
func (r *Resolver) Stop() {
	if r != nil && r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		time.Sleep(200 * time.Millisecond)
	}
}
