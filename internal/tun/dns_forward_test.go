package tun

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startDNSTransports(t *testing.T, handler dns.Handler) string {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{
		{PacketConn: udp, Handler: handler},
		{Listener: tcp, Handler: handler},
	} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go server.ActivateAndServe()
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("local DNS server did not start")
		}
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	return tcp.Addr().String()
}

func dnsTestQuery(t *testing.T, edns uint16) []byte {
	t.Helper()
	query := new(dns.Msg).SetQuestion("test.example.", dns.TypeTXT)
	query.Id = 123
	if edns != 0 {
		query.SetEdns0(edns, false)
	}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func txtRecord(name string, count int) *dns.TXT {
	values := make([]string, count)
	for i := range values {
		values[i] = strings.Repeat("x", 250)
	}
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: values,
	}
}

func TestDNSForwardingRetriesTruncatedAndOversizeUDP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		oversize bool
	}{
		{name: "TC"},
		{name: "EDNS exceeds receive budget", oversize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var udpCalls, tcpCalls atomic.Int32
			server := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
				reply := new(dns.Msg).SetReply(query)
				if w.RemoteAddr().Network() == "udp" {
					udpCalls.Add(1)
					// A wrong question with the right ID must not trigger TCP fallback.
					spoof := new(dns.Msg).SetReply(query)
					spoof.Question[0].Name = "spoof.example."
					spoof.Truncated = true
					_ = w.WriteMsg(spoof)
					if tc.oversize {
						reply.Answer = []dns.RR{txtRecord(query.Question[0].Name, 20)}
					} else {
						reply.Truncated = true
					}
				} else {
					tcpCalls.Add(1)
					reply.Answer = []dns.RR{txtRecord(query.Question[0].Name, 6)}
				}
				_ = w.WriteMsg(reply)
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			query := dnsTestQuery(t, 8192)
			dialer := net.Dialer{}
			data, err := forwardDNS(ctx, query, server, dialer.DialContext)
			if err != nil {
				t.Fatal(err)
			}
			var reply dns.Msg
			if err := reply.Unpack(data); err != nil {
				t.Fatal(err)
			}
			if reply.Truncated || reply.Id != 123 || len(reply.Answer) != 1 ||
				reply.Answer[0].Header().Name != "test.example." ||
				len(reply.Answer[0].(*dns.TXT).Txt) != 6 ||
				udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
				t.Fatalf("unexpected fallback: id=%d truncated=%t records=%d udp=%d tcp=%d",
					reply.Id, reply.Truncated, len(reply.Answer), udpCalls.Load(), tcpCalls.Load())
			}
			limited, err := limitDNSUDP(query, data, 1232)
			if err != nil {
				t.Fatal(err)
			}
			if err := reply.Unpack(limited); err != nil || !reply.Truncated || len(limited) > 1232 {
				t.Fatalf("oversized client reply: size=%d TC=%t err=%v", len(limited), reply.Truncated, err)
			}
		})
	}
}

func TestDNSForwardingIgnoresInvalidUDPAndHandlesNextQuery(t *testing.T) {
	var calls atomic.Int32
	server := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		reply := new(dns.Msg).SetReply(query)
		if calls.Add(1) == 1 {
			// An oversized, malformed response from the right socket but
			// with the wrong transaction ID must never trigger a TCP dial.
			data := make([]byte, maxDNSUDP+500)
			data[0] = byte((query.Id + 1) >> 8)
			data[1] = byte(query.Id + 1)
			data[2] = 0x82
			_, _ = w.Write(data)
			return
		}
		reply.Answer = []dns.RR{txtRecord(query.Question[0].Name, 1)}
		_ = w.WriteMsg(reply)
	}))
	query := dnsTestQuery(t, 8192)
	dialer := net.Dialer{}
	dial := func(ctx context.Context, network, server string) (net.Conn, error) {
		if network != "udp" {
			t.Fatalf("invalid UDP response triggered %s retry", network)
		}
		return dialer.DialContext(ctx, network, server)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := forwardDNS(ctx, query, server, dial); err == nil {
		t.Fatal("invalid oversized datagram was accepted")
	}
	next, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	data, err := forwardDNS(next, query, server, dial)
	if err != nil {
		t.Fatal(err)
	}
	var reply dns.Msg
	if err := reply.Unpack(data); err != nil || len(reply.Answer) != 1 || reply.Id != 123 {
		t.Fatalf("query after malformed packet: %v, %v", reply, err)
	}
}

func TestDNSSocketCancellationInterruptsRead(t *testing.T) {
	received := make(chan struct{}, 1)
	server := startDNSTransports(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		received <- struct{}{}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	query := dnsTestQuery(t, 0)
	finished := make(chan error, 1)
	go func() {
		dialer := net.Dialer{}
		_, err := forwardDNS(ctx, query, server, dialer.DialContext)
		finished <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("server did not receive query")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled DNS exchange: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left DNS exchange blocked")
	}
}
