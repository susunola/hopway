//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/wire"
)

func TestVirtualDNSTCPReturnsFullReply(t *testing.T) {
	server := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{txtRecord(query.Question[0].Name, 6)}
		_ = w.WriteMsg(reply)
	}))
	backend.SetSocketControl(func(string, string, syscall.RawConn) error { return nil }, server)
	defer backend.SetSocketControl(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	options := Options{}
	options.defaults()
	service := &Service{
		options: options, fake: NewFakeIP(options.FakeRange), dnsCtx: ctx, dnsTCP: make(chan struct{}, 1),
	}
	client, ingress := net.Pipe()
	defer client.Close()
	defer ingress.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	finished := make(chan error, 1)
	go service.NewConnectionEx(ctx, ingress, M.ParseSocksaddr("127.0.0.1:12345"),
		M.Socksaddr{Addr: options.DNSAddress(), Port: 53}, func(err error) { finished <- err })
	query := dnsTestQuery(t, 0)
	for range 2 {
		if err := writeDNSFrame(client, query); err != nil {
			t.Fatal(err)
		}
		data, err := readDNSFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		var reply dns.Msg
		if err := reply.Unpack(data); err != nil || reply.Id != 123 || reply.Truncated || len(data) < 1200 {
			t.Fatalf("TCP DNS reply id=%d size=%d TC=%t err=%v", reply.Id, len(data), reply.Truncated, err)
		}
	}
	client.Close()
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("DNS session stayed open after client closed")
	}
}

func TestFakeIPExceptionsUseSystemDNS(t *testing.T) {
	var localQueries, publicQueries atomic.Int32
	local := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		localQueries.Add(1)
		question := q.Question[0]
		reply := new(dns.Msg).SetReply(q)
		header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
		if question.Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.168.5.2")}}
		} else {
			reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("fd00::2")}}
		}
		_ = w.WriteMsg(reply)
	}))
	public := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		publicQueries.Add(1)
		_ = w.WriteMsg(new(dns.Msg).SetReply(q))
	}))
	options := Options{LocalDNS: []string{local}}
	options.defaults()
	exceptions, err := wire.ParseFakeIPExceptions([]string{" .Home.Example. "})
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{options: options, fake: NewFakeIP(options.FakeRange), exceptions: exceptions}
	service.fake.EnableIPv6(DefaultFakeRange6)
	check := func(name string, qtype uint16, rcode int, address string, synthetic bool) {
		t.Helper()
		payload, err := new(dns.Msg).SetQuestion(name, qtype).Pack()
		if err != nil {
			t.Fatal(err)
		}
		data, err := service.replyDNS(context.Background(), payload, M.ParseSocksaddr(public))
		if err != nil {
			t.Fatal(err)
		}
		var reply dns.Msg
		if err := reply.Unpack(data); err != nil || reply.Rcode != rcode {
			t.Fatalf("%s: response %+v, %v", name, reply, err)
		}
		if rcode != dns.RcodeSuccess || (address == "" && !synthetic) {
			if len(reply.Answer) != 0 {
				t.Fatalf("%s: unexpected answers %v", name, reply.Answer)
			}
			return
		}
		if len(reply.Answer) != 1 {
			t.Fatalf("%s: answers %v", name, reply.Answer)
		}
		switch rr := reply.Answer[0].(type) {
		case *dns.A:
			got := rr.A.String()
			ip, _ := netip.AddrFromSlice(rr.A)
			if synthetic && !service.fake.Contains(ip.Unmap()) {
				t.Fatalf("%s: expected synthetic address, got %s", name, got)
			}
			if !synthetic && got != address {
				t.Fatalf("%s: got %s, want %s", name, got, address)
			}
		case *dns.AAAA:
			if rr.AAAA.String() != address {
				t.Fatalf("%s: got %s, want %s", name, rr.AAAA, address)
			}
		default:
			t.Fatalf("%s: unexpected answer type %T", name, rr)
		}
	}
	check("HOME.EXAMPLE.", dns.TypeA, dns.RcodeSuccess, "192.168.5.2", false)
	check("nas.home.example.", dns.TypeAAAA, dns.RcodeSuccess, "fd00::2", false)
	check("nothome.example.", dns.TypeA, dns.RcodeSuccess, "", true)
	check(`nas\.home.example.`, dns.TypeA, dns.RcodeNameError, "", false)
	check("printer.local.", dns.TypeA, dns.RcodeSuccess, "", false)
	service.options.LocalDNS = nil
	check("nas.home.example.", dns.TypeA, dns.RcodeServerFailure, "", false)
	if localQueries.Load() != 2 || publicQueries.Load() != 1 {
		t.Fatalf("unexpected DNS forwarding counts: local=%d explicit=%d", localQueries.Load(), publicQueries.Load())
	}
}

func TestDNSForwardingUsesConfiguredTimeout(t *testing.T) {
	var udp, tcp atomic.Int32
	server := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if w.RemoteAddr().Network() == "udp" {
			udp.Add(1)
			reply := new(dns.Msg).SetReply(q)
			reply.Truncated = true
			_ = w.WriteMsg(reply)
		} else {
			tcp.Add(1) // Leave the TCP query unanswered.
		}
	}))
	service := &Service{options: Options{DNSTimeoutMS: 250}, fake: NewFakeIP(testFakeRange)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	data, err := service.replyDNS(ctx, dnsTestQuery(t, 0), M.ParseSocksaddr(server))
	elapsed := time.Since(start)
	var reply dns.Msg
	if err != nil || reply.Unpack(data) != nil || reply.Rcode != dns.RcodeServerFailure ||
		elapsed < 200*time.Millisecond || elapsed > 1500*time.Millisecond || udp.Load() != 1 || tcp.Load() != 1 {
		t.Fatalf("forwarded DNS: rcode=%d err=%v elapsed=%v UDP=%d TCP=%d", reply.Rcode, err, elapsed, udp.Load(), tcp.Load())
	}
}
