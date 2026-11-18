//go:build ignore

// dnsq asks one DNS server one question and prints the whole answer: rcode,
// answer records and authority records. It exists because the test image has
// no dig, and busybox nslookup cannot tell NODATA from NXDOMAIN from "the
// question was forwarded upstream", which is exactly what the local-names
// measurements need to see.
//
// Build (static, for the OpenWrt image):
//
//	CGO_ENABLED=0 go build -o /tmp/dnsq docs/spikes/local-dns-names/dnsq.go
//
// Usage: dnsq <server:port> <name> <A|AAAA|HTTPS|TXT|MX> [source-ip]
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) != 4 && len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: dnsq <server:port> <name> <A|AAAA|HTTPS> [source-ip]")
		os.Exit(2)
	}
	server, name, qtype := os.Args[1], os.Args[2], strings.ToUpper(os.Args[3])
	types := map[string]dnsmessage.Type{
		"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "HTTPS": dnsmessage.Type(65),
		"TXT": dnsmessage.TypeTXT, "MX": dnsmessage.TypeMX,
	}
	t, ok := types[qtype]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown type", qtype)
		os.Exit(2)
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET,
		}},
	}
	buf, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	d := net.Dialer{}
	if len(os.Args) == 5 {
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(os.Args[4])}
	}
	conn, err := d.Dial("udp", server)
	if err != nil {
		fmt.Println("DIAL-ERROR", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(buf); err != nil {
		fmt.Println("WRITE-ERROR", err)
		os.Exit(1)
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Println("TIMEOUT/READ-ERROR", err)
		os.Exit(1)
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp[:n]); err != nil {
		fmt.Println("UNPACK-ERROR", err)
		os.Exit(1)
	}
	var ans, auth []string
	for _, a := range m.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			ans = append(ans, "A "+net.IP(b.A[:]).String())
		case *dnsmessage.AAAAResource:
			ans = append(ans, "AAAA "+net.IP(b.AAAA[:]).String())
		case *dnsmessage.CNAMEResource:
			ans = append(ans, "CNAME "+b.CNAME.String())
		default:
			ans = append(ans, a.Header.Type.String())
		}
	}
	for _, a := range m.Authorities {
		auth = append(auth, a.Header.Type.String())
	}
	fmt.Printf("%s %s @%s: rcode=%s aa=%t answers=%d %v authority=%v\n",
		qtype, strings.TrimSuffix(name, "."), server, m.Header.RCode, m.Header.Authoritative,
		len(m.Answers), ans, auth)
}
