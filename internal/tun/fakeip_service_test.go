//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/peer"
)

func TestTUNConnectionRecordsTargetSource(t *testing.T) {
	const domain = "target.example"
	const address = "203.0.113.1:443"
	for _, tc := range []struct {
		name       string
		disable    bool
		fake       bool
		write      func(net.Conn)
		wantSource peer.TargetSource
	}{
		{name: "HTTP Host", write: func(c net.Conn) {
			_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+domain+"\r\n\r\n")
		}, wantSource: peer.TargetHTTPHost},
		{name: "TLS SNI", write: func(c net.Conn) {
			_ = tls.Client(c, &tls.Config{ServerName: domain}).Handshake()
		}, wantSource: peer.TargetTLSSNI},
		{name: "disabled without client data", disable: true, wantSource: peer.TargetIP},
		{name: "DNS mapping with sniffing disabled", disable: true, fake: true, wantSource: peer.TargetFakeIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := engine.Default()
			config.Rules = []engine.Rule{
				{Type: engine.RuleDomain, Value: domain, Via: "REJECT"},
				{Type: engine.RuleMatch, Via: "REJECT"},
			}
			core, err := engine.New(config, backend.Default())
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			service := &Service{options: Options{DisableSniffing: tc.disable}, fake: NewFakeIP(testFakeRange), dial: core.Dial}
			destination := M.ParseSocksaddr(address)
			if tc.fake {
				destination.Addr = service.fake.Allocate(domain)
			}
			client, ingress := net.Pipe()
			defer client.Close()
			defer ingress.Close()
			finished := make(chan error, 1)
			if tc.write != nil {
				go tc.write(client)
			}
			go service.NewConnectionEx(context.Background(), ingress, M.ParseSocksaddr("127.0.0.1:12345"),
				destination, func(err error) { finished <- err })
			// Disabled flows reach the rule engine without waiting for a client hello.
			timeout := time.Second
			if tc.disable {
				timeout = 250 * time.Millisecond
			}
			select {
			case err := <-finished:
				if !errors.Is(err, outbound.ErrRejected) {
					t.Fatalf("expected rule rejection, got %v", err)
				}
			case <-time.After(timeout):
				t.Fatal("TUN flow did not reach the rule engine")
			}
			wantTarget := domain + ":443"
			if tc.wantSource == peer.TargetIP {
				wantTarget = address
			}
			records := core.Status().Connections
			if len(records) != 1 || records[0].TargetSource != tc.wantSource || records[0].Target != wantTarget {
				t.Fatalf("unexpected connection record: %+v", records)
			}
		})
	}
}

func TestFakeIPLeaseHeldByTCPAndUDPHandlers(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			fake := NewFakeIP(netip.MustParsePrefix("198.18.0.0/30"))
			var offset atomic.Int64
			start := time.Now()
			fake.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
			address := fake.Allocate("active.test")
			target := M.Socksaddr{Addr: address, Port: 443}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, finished := make(chan string, 1), make(chan struct{})
			dial := func(ctx context.Context, _ string, target string) error {
				entered <- target
				<-ctx.Done()
				return ctx.Err()
			}
			service := &Service{
				fake: fake,
				dial: func(ctx context.Context, inbound, target string) (net.Conn, error) {
					return nil, dial(ctx, inbound, target)
				},
				dialPacket: func(ctx context.Context, inbound, target string) (net.PacketConn, error) {
					return nil, dial(ctx, inbound, target)
				},
			}
			go func() {
				defer close(finished)
				if network == "tcp" {
					peer, client := net.Pipe()
					defer client.Close()
					service.NewConnectionEx(ctx, peer, M.Socksaddr{}, target, nil)
				} else {
					service.NewPacketConnectionEx(ctx, &tunPacketFixture{}, M.Socksaddr{}, target, nil)
				}
			}()
			select {
			case dialed := <-entered:
				if dialed != "active.test:443" {
					t.Fatalf("outbound target %s", dialed)
				}
			case <-time.After(time.Second):
				t.Fatal("TUN handler did not route fake address")
			}
			offset.Store(int64(2 * fakeIPRetention))
			if stats := fake.Stats().IPv4; stats.Pinned != 1 {
				t.Fatalf("handler did not hold address: %+v", stats)
			}
			if stolen := fake.Allocate("other.test"); stolen.IsValid() {
				t.Fatalf("address stolen from live handler: %v", stolen)
			}
			cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("handler did not finish")
			}
			if stats := fake.Stats().IPv4; stats.Pinned != 0 {
				t.Fatalf("handler leaked address pin: %+v", stats)
			}
			if _, ok := fake.Lookup(address); !ok {
				t.Fatal("close lost its post-flow retention window")
			}
		})
	}
}

func TestFakeIPSurvivesRuleEngineSwap(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			c.Write([]byte("new-rule"))
			c.Close()
		}
	}()
	backend.Resolver.Pin("reload.test", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	defer backend.Resolver.Pin("reload.test", nil)
	newEngine := func(via string) *engine.Engine {
		t.Helper()
		cfg := engine.Default()
		cfg.Rules = []engine.Rule{
			{Type: engine.RuleDomain, Value: "reload.test", Via: via},
			{Type: engine.RuleMatch, Via: "REJECT"},
		}
		e, err := engine.New(cfg, backend.Default())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.Close() })
		return e
	}
	var current atomic.Pointer[engine.Engine]
	current.Store(newEngine("REJECT"))
	fake := NewFakeIP(testFakeRange)
	address := fake.Allocate("reload.test")
	service := &Service{fake: fake, dial: func(ctx context.Context, inbound, target string) (net.Conn, error) {
		return current.Load().Dial(ctx, inbound, target)
	}}
	target := M.Socksaddr{Addr: address, Port: uint16(listener.Addr().(*net.TCPAddr).Port)}
	dial := func() (net.Conn, <-chan error) {
		t.Helper()
		peer, client := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go service.NewConnectionEx(context.Background(), peer, M.Socksaddr{}, target, func(err error) { done <- err })
		return client, done
	}
	client, closed := dial()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("old engine should reject the fake address")
		}
	case <-time.After(time.Second):
		t.Fatal("old engine did not reject the flow")
	}
	client.Close()
	current.Store(newEngine("DIRECT"))
	client, _ = dial()
	defer client.Close()
	got := make([]byte, len("new-rule"))
	if _, err := client.Read(got); err != nil || string(got) != "new-rule" {
		t.Fatalf("same address after rule swap: %q %v", got, err)
	}
}

func TestTUNPrivatePTRUsesConfiguredLocalDNS(t *testing.T) {
	var queries atomic.Int32
	local := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{
			Name: query.Question[0].Name, Class: dns.ClassINET, Rrtype: dns.TypePTR,
		}, Ptr: "nas.lan."}}
		w.WriteMsg(reply)
	}))
	service := &Service{options: Options{LocalDNS: []string{local}}, fake: NewFakeIP(testFakeRange)}
	// Use a separate loopback DNS server as the query's original destination.
	other := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{
			Name: query.Question[0].Name, Class: dns.ClassINET, Rrtype: dns.TypePTR,
		}, Ptr: "wrong.test."}}
		w.WriteMsg(reply)
	}))
	for _, address := range []string{"192.168.12.3", "fd00::12"} {
		reverse, _ := dns.ReverseAddr(address)
		query := new(dns.Msg).SetQuestion(reverse, dns.TypePTR)
		data, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		reply, err := service.replyDNS(context.Background(), data, M.ParseSocksaddr(other))
		if err != nil {
			t.Fatal(err)
		}
		var parsed dns.Msg
		if err := parsed.Unpack(reply); err != nil || len(parsed.Answer) != 1 ||
			parsed.Answer[0].(*dns.PTR).Ptr != "nas.lan." {
			t.Fatalf("private PTR %s: %v, %v", address, parsed.Answer, err)
		}
	}
	if queries.Load() != 2 {
		t.Fatalf("local DNS got %d queries", queries.Load())
	}
}
