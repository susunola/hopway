package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

func TestUDPSessionBudgetEvictsLeastRecentAcrossGenerations(t *testing.T) {
	budget := newPacketBudget(3, 4)
	newCore := func() *Engine {
		t.Helper()
		core, err := NewWithPacketBudget(Default(), backend.Native{}, budget)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { core.Close() })
		return core
	}
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	destination := M.ParseSocksaddr(receiver.LocalAddr().String())
	open := func(core *Engine) net.PacketConn {
		t.Helper()
		conn, err := core.DialPacket(context.Background(), "fixture", destination.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	old, replacement := newCore(), newCore()
	recent, idle := open(old), open(old)
	if _, err := recent.WriteTo([]byte("outbound activity keeps this session"), destination); err != nil {
		t.Fatal(err)
	}
	open(replacement)
	open(replacement)
	if _, err := idle.WriteTo([]byte("evicted"), destination); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("least recent session from the old engine still writable: %v", err)
	}
	if _, err := recent.WriteTo([]byte("still usable"), destination); err != nil {
		t.Fatalf("eviction displaced the active old session: %v", err)
	}
	if n := old.Active() + replacement.Active(); n != budget.maxSessions {
		t.Fatalf("%d active UDP sessions after replacement, want %d", n, budget.maxSessions)
	}
	old.Close()
	replacement.Close()
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if len(budget.sessions) != 0 || len(budget.outbounds) != 0 {
		t.Fatal("closed engines left session budget entries")
	}
}

func TestUDPUsesListenerLoopGuard(t *testing.T) {
	core, err := New(Default(), backend.Native{}, 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for _, destination := range []string{"127.0.0.1:8080", "[::1]:8080", "[::ffff:127.0.0.1]:8080", "0.0.0.0:8080", "[::]:8080"} {
		for _, protocol := range []string{"TCP", "UDP"} {
			var conn net.Conn
			var packet net.PacketConn
			var err error
			if protocol == "TCP" {
				conn, err = core.Dial(context.Background(), "fixture", destination)
			} else {
				packet, err = core.DialPacket(context.Background(), "fixture", destination)
			}
			if conn != nil {
				conn.Close()
			}
			if packet != nil {
				packet.Close()
			}
			if !errors.Is(err, backend.ErrLoop) {
				t.Errorf("%s to %s did not reject the proxy listener: %v", protocol, destination, err)
			}
		}
	}
}

func TestDirectUDPEchoIPv4IPv6AndDomain(t *testing.T) {
	core, err := New(Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for _, sample := range []struct {
		name, network, address string
	}{
		{"IPv4", "udp4", "127.0.0.1:0"},
		{"IPv6", "udp6", "[::1]:0"},
		{"domain", "udp4", "127.0.0.1:0"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			receiver, err := net.ListenPacket(sample.network, sample.address)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			target := receiver.LocalAddr().String()
			if sample.name == "domain" {
				const hostname = "udp-address-fixture.test"
				backend.Resolver.Pin(hostname, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
				t.Cleanup(func() { backend.Resolver.Pin(hostname, nil) })
				_, port, err := net.SplitHostPort(target)
				if err != nil {
					t.Fatal(err)
				}
				target = net.JoinHostPort(hostname, port)
			}
			conn, err := core.DialPacket(context.Background(), "fixture", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline := time.Now().Add(time.Second)
			receiver.SetDeadline(deadline)
			conn.SetDeadline(deadline)
			if _, err := conn.WriteTo([]byte(sample.name), M.ParseSocksaddr(target)); err != nil {
				t.Fatal(err)
			}
			var buffer [32]byte
			n, source, err := receiver.ReadFrom(buffer[:])
			if err != nil || string(buffer[:n]) != sample.name {
				t.Fatalf("received %q at origin: %v", buffer[:n], err)
			}
			if _, err := receiver.WriteTo(buffer[:n], source); err != nil {
				t.Fatal(err)
			}
			n, source, err = conn.ReadFrom(buffer[:])
			if err != nil || source.String() != target || string(buffer[:n]) != sample.name {
				t.Fatalf("reply = %q from %v, error %v", buffer[:n], source, err)
			}
		})
	}
}

type packetBudgetDialer struct {
	backend.Dialer
	open func(context.Context, string) (net.PacketConn, error)
}

func (d packetBudgetDialer) ListenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	return d.open(ctx, target)
}

type budgetPacketConn struct {
	net.PacketConn
	write func([]byte, net.Addr) (int, error)
}

func (c budgetPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return c.write(p, addr) }
func (c budgetPacketConn) Close() error                                 { return nil }

func TestBlockedUDPOutboundDoesNotOccupyOtherOutboundsOrTCP(t *testing.T) {
	config := Default()
	config.Nodes = []outbound.Node{
		{Name: "slow", Type: "socks5", Server: "localhost:1080"},
		{Name: "alias", Type: "socks5", Server: "LOCALHOST:1080"},
		{Name: "other", Type: "socks5", Server: "localhost:1081"},
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tcpDial := backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	})
	writeStarted := make(chan struct{}, packetExitSendLimit)
	writesUnblocked := make(chan struct{})
	var unblock sync.Once
	unblockWrites := func() { unblock.Do(func() { close(writesUnblocked) }) }
	var workers sync.WaitGroup
	defer func() { unblockWrites(); workers.Wait() }()
	blocked := budgetPacketConn{write: func(p []byte, _ net.Addr) (int, error) {
		writeStarted <- struct{}{}
		select {
		case <-writesUnblocked:
			return len(p), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}}
	fast := budgetPacketConn{write: func(p []byte, _ net.Addr) (int, error) { return len(p), nil }}
	dialsStarted := make(chan struct{}, packetExitOpenLimit)
	blockDials := make(chan struct{})
	openSlow := func(ctx context.Context, target string) (net.PacketConn, error) {
		select {
		case <-blockDials:
			dialsStarted <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			return blocked, nil
		}
	}
	core.dialers["slow"] = packetBudgetDialer{tcpDial, openSlow}
	core.dialers["alias"] = packetBudgetDialer{tcpDial, func(context.Context, string) (net.PacketConn, error) { return fast, nil }}
	core.dialers["other"] = core.dialers["alias"]
	destination := M.ParseSocksaddr("127.0.0.1:53")
	selectNode := func(node string) {
		t.Helper()
		if err := core.SetPolicy(Policy{Mode: "global", Selected: node}); err != nil {
			t.Fatal(err)
		}
	}
	open := func(node string) net.PacketConn {
		t.Helper()
		selectNode(node)
		conn, err := core.DialPacket(ctx, "fixture", destination.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	alias, other, slow := open("alias"), open("other"), open("slow")
	for range packetExitSendLimit {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = slow.WriteTo([]byte("waiting"), destination)
		}()
	}
	wait := func(started <-chan struct{}, n int) {
		t.Helper()
		for range n {
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("failed to fill outbound budget")
			}
		}
	}
	wait(writeStarted, packetExitSendLimit)
	if _, err := alias.WriteTo([]byte("drop"), destination); !errors.Is(err, backend.ErrPacketCongested) {
		t.Fatalf("alias exceeded the shared send limit: %v", err)
	}
	if _, err := other.WriteTo([]byte("independent"), destination); err != nil {
		t.Fatalf("one UDP exit stalled another: %v", err)
	}
	unblockWrites()
	workers.Wait()
	if _, err := alias.WriteTo([]byte("recovered"), destination); err != nil {
		t.Fatalf("existing association did not recover after congestion: %v", err)
	}
	close(blockDials)
	for range packetExitOpenLimit {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = core.DialPacket(ctx, "fixture", destination.String())
		}()
	}
	defer cancel()
	wait(dialsStarted, packetExitOpenLimit)
	selectNode("alias")
	if _, err := core.DialPacket(ctx, "fixture", destination.String()); !errors.Is(err, backend.ErrPacketCongested) {
		t.Fatalf("alias exceeded the shared open limit: %v", err)
	}
	tcp, err := core.Dial(ctx, "fixture", "example.test:443")
	if err != nil {
		t.Fatalf("UDP open saturation blocked TCP on the same endpoint: %v", err)
	}
	tcp.Close()
	_ = open("other")
}
