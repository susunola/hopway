package backend

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func serveDialTestDNS(t *testing.T, network, address string, handler dns.HandlerFunc) (string, error) {
	t.Helper()
	packet, err := net.ListenPacket(network, address)
	if err != nil {
		return "", err
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packet, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go server.ActivateAndServe()
	t.Cleanup(func() { _ = server.Shutdown() })
	select {
	case <-ready:
		return packet.LocalAddr().String(), nil
	case <-time.After(time.Second):
		t.Fatal("DNS fixture did not start")
		return "", nil
	}
}

func TestNetDialConnectsWhenAAAAHasNoResponse(t *testing.T) {
	aaaaSeen := make(chan struct{}, 1)
	address, err := serveDialTestDNS(t, "udp4", "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		question := q.Question[0]
		if question.Qtype == dns.TypeAAAA {
			select {
			case aaaaSeen <- struct{}{}:
			default:
			}
			return
		}
		// Require both questions to have actually been sent before answering.
		select {
		case <-aaaaSeen:
		case <-time.After(time.Second):
			return
		}
		reply := new(dns.Msg).SetReply(q)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(127, 0, 0, 1),
		}}
		w.WriteMsg(reply)
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Write([]byte("IPv4"))
			conn.Close()
		}
	}()
	SetSocketControl(func(string, string, syscall.RawConn) error { return nil }, address)
	defer SetSocketControl(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	conn, err := NetDial(ctx, "tcp", net.JoinHostPort("dual.test.", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "IPv4" {
		t.Fatalf("IPv4 connection: %q, %v", buf, err)
	}
}

func TestDialFamiliesStartsFallbackAndClosesLateSocket(t *testing.T) {
	first, second := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	lookup := func(_ context.Context, family string) ([]netip.Addr, error) {
		if family == "ip4" {
			return []netip.Addr{first}, nil
		}
		return []netip.Addr{second}, nil
	}
	loser, peer := net.Pipe()
	defer peer.Close()
	winner, other := net.Pipe()
	defer other.Close()
	defer winner.Close()
	defer loser.Close()
	v4Started, v6Started := make(chan time.Time, 1), make(chan time.Time, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := dialFamilies(ctx, "tcp", "dual.test", 443, lookup, func(ctx context.Context, _, target string) (net.Conn, error) {
		if target == netip.AddrPortFrom(first, 443).String() {
			v4Started <- time.Now()
			<-ctx.Done()
			return loser, nil // emulate a socket completing while cancellation wins
		}
		v6Started <- time.Now()
		return winner, nil
	}, nil)
	if result.err != nil || result.conn != winner {
		t.Fatalf("expected IPv6 fallback, got %+v", result)
	}
	if delay := (<-v6Started).Sub(<-v4Started); delay < familyFallbackDelay-20*time.Millisecond || delay > time.Second {
		t.Fatalf("fallback opened after %v", delay)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("losing socket was not closed: %v", err)
	}
}

func TestDialFamiliesDoesNotQueueIPv4BehindIPv6(t *testing.T) {
	v6Attempted, v6Canceled := make(chan struct{}), make(chan struct{})
	winner, peer := net.Pipe()
	defer peer.Close()
	defer winner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lookup := func(ctx context.Context, family string) ([]netip.Addr, error) {
		if family == "ip6" {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		}
		select {
		case <-v6Attempted:
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	result := dialFamilies(ctx, "tcp", "dual.test", 443, lookup, func(ctx context.Context, _, address string) (net.Conn, error) {
		if netip.MustParseAddrPort(address).Addr().Is6() {
			close(v6Attempted)
			<-ctx.Done()
			close(v6Canceled)
			return nil, ctx.Err()
		}
		return winner, nil
	}, nil)
	if result.err != nil || result.conn != winner {
		t.Fatalf("IPv4 waited for unreachable IPv6: %+v", result)
	}
	select {
	case <-v6Canceled:
	case <-ctx.Done():
		t.Fatal("losing IPv6 attempt remained active")
	}
}

func TestScopedLinkLocalDNSKeepsInterface(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no scoped loopback interface")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var address netip.Addr
	for _, raw := range addresses {
		if prefix, err := netip.ParsePrefix(raw.String()); err == nil && prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() {
			address = prefix.Addr().WithZone(iface.Name)
			break
		}
	}
	if !address.IsValid() {
		t.Skip("no link-local IPv6 on loopback")
	}
	server, err := serveDialTestDNS(t, "udp6", netip.AddrPortFrom(address, 0).String(), func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			}}
		}
		w.WriteMsg(reply)
	})
	if err != nil {
		t.Skipf("host cannot bind scoped loopback DNS: %v", err)
	}
	// Some Darwin versions omit the zone from LocalAddr for a bound socket.
	port := netip.MustParseAddrPort(server).Port()
	var wrong atomic.Int32
	SetSocketControl(func(string, string, syscall.RawConn) error {
		wrong.Add(1)
		return errors.New("unexpected default-interface binding")
	}, netip.AddrPortFrom(address, port).String())
	defer SetSocketControl(nil)
	addrs, err := lookupWithin(t, Resolver, "scoped-dns.test.")
	if err != nil || len(addrs) != 1 || !addrs[0].IsLoopback() || wrong.Load() != 0 {
		t.Fatalf("scoped resolver got %v, %v, default bindings %d", addrs, err, wrong.Load())
	}
}

func TestNetDialReResolvesEndpointAfterNetworkViewChangeAndExpiration(t *testing.T) {
	v4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	port := v4.Addr().(*net.TCPAddr).Port
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("cannot use two loopback families on one port: %v", err)
	}
	defer v6.Close()
	for index, listener := range []net.Listener{v4, v6} {
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Write([]byte{byte(index + 1)})
				conn.Close()
			}
		}()
	}
	var newView atomic.Bool
	server, err := serveDialTestDNS(t, "udp4", "127.0.0.1:0", func(w dns.ResponseWriter, q *dns.Msg) {
		question := q.Question[0]
		reply := new(dns.Msg).SetReply(q)
		hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 600}
		if newView.Load() {
			if question.Qtype == dns.TypeAAAA {
				reply.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6loopback}}
			}
		} else if question.Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)}}
		}
		w.WriteMsg(reply)
	})
	if err != nil {
		t.Fatal(err)
	}
	SetSocketControl(func(string, string, syscall.RawConn) error { return nil }, server)
	defer SetSocketControl(nil)
	check := func(want byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := NetDial(ctx, "tcp", net.JoinHostPort("rotate.test.", strconv.Itoa(port)), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var value [1]byte
		if _, err := io.ReadFull(conn, value[:]); err != nil || value[0] != want {
			t.Fatalf("DNS selected endpoint %d, want %d: %v", value[0], want, err)
		}
	}
	check(1)
	newView.Store(true)
	Resolver.Flush()
	check(2)

	newView.Store(false)
	// Advance the expiry of the cached family without a 30-second test sleep.
	Resolver.mu.Lock()
	entry := Resolver.view.entries[dnsKey{"rotate.test.", "ip6"}]
	if entry != nil {
		cachedAnswer := entry.Value.(cached)
		cachedAnswer.expires = time.Now().Add(-time.Second)
		entry.Value = cachedAnswer
	}
	for _, negative := range Resolver.view.entries {
		answer := negative.Value.(cached)
		if answer.result.err != nil {
			answer.expires = time.Now().Add(-time.Second)
			negative.Value = answer
		}
	}
	Resolver.mu.Unlock()
	if entry == nil {
		t.Fatal("IPv6 answer was not cached")
	}
	check(1)
}
