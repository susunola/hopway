package tun

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"context"
	"github.com/miekg/dns"
)

func pipeSniff(t *testing.T, write func(net.Conn)) (string, []byte) {
	client, server := net.Pipe()
	go write(client)
	name, replay := sniff(server)
	replay.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 5)
	io.ReadFull(replay, data)
	client.Close()
	return name, data
}

func TestSniffTLSAndHTTP(t *testing.T) {
	name, data := pipeSniff(t, func(c net.Conn) {
		tls.Client(c, &tls.Config{ServerName: "WWW.Example.Test", InsecureSkipVerify: true}).Handshake()
	})
	if name != "www.example.test" || data[0] != 0x16 {
		t.Fatalf("tls: %q %x", name, data)
	}
	name, data = pipeSniff(t, func(c net.Conn) {
		c.Write([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: api.example.test:8080\r\n\r\n"))
	})
	if name != "api.example.test" || string(data) != "GET /" {
		t.Fatalf("http: %q %q", name, data)
	}
	name, _ = pipeSniff(t, func(c net.Conn) { time.Sleep(sniffWait + 100*time.Millisecond); c.Write([]byte("hello")) })
	if name != "" {
		t.Fatalf("server-first protocol sniffed as %q", name)
	}
}

func TestFakeIPAndDNS(t *testing.T) {
	fake := NewFakeIP(netip.MustParsePrefix("198.18.0.0/29")) // 8 addresses: wraps quickly
	a := fake.Allocate("a.test.")
	if a != fake.Allocate("A.test") {
		t.Fatal("same name must keep its address")
	}
	b := fake.Allocate("b.test")
	if name, _ := fake.Lookup(b); name != "b.test" {
		t.Fatal("lookup")
	}
	if a == b || !fake.Contains(a) {
		t.Fatal("allocation")
	}

	query := new(dns.Msg)
	query.SetQuestion("site.test.", dns.TypeA)
	payload, _ := query.Pack()
	fake = NewFakeIP(DefaultFakeRange)
	reply, err := answerDNS(context.Background(), payload, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	var msg dns.Msg
	msg.Unpack(reply)
	addr, _ := netip.AddrFromSlice(msg.Answer[0].(*dns.A).A.To4())
	if name, _ := fake.Lookup(addr); name != "site.test" || msg.Id != query.Id {
		t.Fatalf("dns answer %v", msg.Answer)
	}
	query.SetQuestion("site.test.", dns.TypeAAAA)
	payload, _ = query.Pack()
	reply, _ = answerDNS(context.Background(), payload, fake, nil)
	msg.Unpack(reply)
	if len(msg.Answer) != 0 || msg.Rcode != dns.RcodeSuccess {
		t.Fatal("AAAA must be answered empty")
	}
	forwarded := false
	query.SetQuestion("printer.local.", dns.TypeA)
	payload, _ = query.Pack()
	answerDNS(context.Background(), payload, fake, func(context.Context, []byte) ([]byte, error) { forwarded = true; return nil, nil })
	if !forwarded {
		t.Fatal(".local names must go to the real resolver")
	}
}

func TestFakeIPWraps(t *testing.T) {
	fake := NewFakeIP(netip.MustParsePrefix("198.18.0.0/29"))
	first := fake.Allocate("first.test")
	for i := 0; i < 5; i++ {
		fake.Allocate(string(rune('a'+i)) + ".test")
	}
	if name, _ := fake.Lookup(first); name == "first.test" {
		t.Fatal("oldest mapping must be replaced after wrapping")
	}
	if name, ok := fake.Lookup(fake.Allocate("first.test")); !ok || name != "first.test" {
		t.Fatal("re-allocation after wrap")
	}
}

func TestFakeIPv6(t *testing.T) {
	fake := NewFakeIP(DefaultFakeRange)
	if fake.Allocate6("a.test").IsValid() {
		t.Fatal("no IPv6 pool configured")
	}
	fake.EnableIPv6(DefaultFakeRange6)
	a := fake.Allocate6("a.test")
	if !DefaultFakeRange6.Contains(a) || !fake.Contains(a) || a != fake.Allocate6("A.test.") {
		t.Fatalf("allocation %v", a)
	}
	if name, ok := fake.Lookup(a); !ok || name != "a.test" {
		t.Fatal("lookup")
	}
	if v4 := fake.Allocate("a.test"); !v4.Is4() || v4 == a {
		t.Fatal("v4 and v6 pools are separate")
	}
	query := new(dns.Msg)
	query.SetQuestion("six.test.", dns.TypeAAAA)
	payload, _ := query.Pack()
	reply, _ := answerDNS(context.Background(), payload, fake, nil)
	var msg dns.Msg
	msg.Unpack(reply)
	if len(msg.Answer) != 1 {
		t.Fatalf("AAAA answer %v", msg.Answer)
	}
	addr, _ := netip.AddrFromSlice(msg.Answer[0].(*dns.AAAA).AAAA)
	if name, _ := fake.Lookup(addr); name != "six.test" {
		t.Fatalf("AAAA maps to %q", name)
	}
}
