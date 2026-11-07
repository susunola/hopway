//go:build !hopway_native && with_quic

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

type quicGate struct {
	ingress *net.UDPConn
	open    atomic.Bool

	mu      sync.Mutex
	latest  netip.AddrPort
	sources map[netip.AddrPort]struct{}
}

// quicTestGate drops packets until the test opens the path to a real server.
func quicTestGate(t *testing.T, upstream string) *quicGate {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp4", upstream)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { origin.Close() })
	ingress, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ingress.Close() })
	gate := &quicGate{ingress: ingress, sources: make(map[netip.AddrPort]struct{})}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, client, err := ingress.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			gate.mu.Lock()
			gate.sources[client] = struct{}{}
			gate.latest = client
			gate.mu.Unlock()
			if gate.open.Load() {
				_, _ = origin.Write(buffer[:n])
			}
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := origin.Read(buffer)
			if err != nil {
				return
			}
			gate.mu.Lock()
			client := gate.latest
			gate.mu.Unlock()
			_, _ = ingress.WriteToUDPAddrPort(buffer[:n], client)
		}
	}()
	return gate
}

func (gate *quicGate) observed() (netip.AddrPort, int) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.latest, len(gate.sources)
}

func quicWait(t *testing.T, check func() bool, reason string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal(reason)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type quicDialResult struct {
	conn io.Closer
	err  error
}

func quicTestDial(t *testing.T, core *Engine, target string, packet bool) (context.CancelFunc, <-chan quicDialResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	result := make(chan quicDialResult, 1)
	go func() {
		var conn io.Closer
		var err error
		if packet {
			conn, err = core.DialPacket(ctx, "QUIC test", target)
		} else {
			conn, err = core.Dial(ctx, "QUIC test", target)
		}
		result <- quicDialResult{conn, err}
	}()
	return cancel, result
}

func readQUICResult(t *testing.T, result <-chan quicDialResult, timeout time.Duration) quicDialResult {
	t.Helper()
	select {
	case value := <-result:
		if value.conn != nil {
			t.Cleanup(func() { value.conn.Close() })
		}
		return value
	case <-time.After(timeout):
		t.Fatal("QUIC dial did not complete")
		return quicDialResult{}
	}
}

func verifyQUICPacket(t *testing.T, conn net.PacketConn, target string) {
	t.Helper()
	payload := []byte("still using the shared QUIC transport")
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo(payload, M.ParseSocksaddr(target)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("UDP echo: %d bytes, %v", n, err)
	}
}

func TestQUICSharedOfferCancellation(t *testing.T) {
	server, nodes := startServer(t)
	udpTarget := udpEchoServer(t).String()

	for _, name := range []string{"hy2", "tuic"} {
		for _, cancelBoth := range []bool{false, true} {
			scenario := "keep survivor"
			if cancelBoth {
				scenario = "cancel last waiter"
			}
			t.Run(name+"/"+scenario, func(t *testing.T) {
				node := nodes[name]
				gate := quicTestGate(t, node.Server)
				node.Server = gate.ingress.LocalAddr().String()
				config := Default()
				config.Mode, config.Selected = "global", node.Name
				config.Nodes = []outbound.Node{node}
				core, err := New(config, backend.Default())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { core.Close() })

				cancelTCP, tcp := quicTestDial(t, core, server.echo, false)
				quicWait(t, func() bool {
					source, _ := gate.observed()
					return source.IsValid()
				}, "server did not receive the initial QUIC datagram")
				original, _ := gate.observed()
				cancelUDP, udp := quicTestDial(t, core, udpTarget, true)
				quicWait(t, func() bool {
					return core.CompactStatus().Resources.Connections == 2
				}, "the second dial did not reserve a connection")
				cancelTCP()
				if result := readQUICResult(t, tcp, time.Second); result.conn != nil || !errors.Is(result.err, context.Canceled) {
					t.Fatalf("TCP dial after cancel: %+v", result)
				}

				if cancelBoth {
					cancelUDP()
					if result := readQUICResult(t, udp, time.Second); result.conn != nil || !errors.Is(result.err, context.Canceled) {
						t.Fatalf("UDP dial after cancel: %+v", result)
					}
					// Rebind the actual source port while the core is alive,
					// and hold it so the retry has to open a different socket.
					released, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(original))
					if err != nil {
						t.Fatalf("canceled offer still owns %s: %v", original, err)
					}
					defer released.Close()
				}
				gate.open.Store(true)
				var survivingPacket net.PacketConn
				if !cancelBoth {
					result := readQUICResult(t, udp, 6*time.Second)
					if result.err != nil {
						t.Fatal(result.err)
					}
					survivingPacket = result.conn.(net.PacketConn)
					verifyQUICPacket(t, survivingPacket, udpTarget)
				}
				_, retry := quicTestDial(t, core, server.echo, false)
				result := readQUICResult(t, retry, 6*time.Second)
				if result.err != nil {
					t.Fatal(result.err)
				}
				stream := result.conn.(net.Conn)
				roundTrip(t, stream, "TCP traffic after cancellation")
				if survivingPacket != nil {
					survivingPacket.Close()
					roundTrip(t, stream, "closing a datagram session preserves other streams")
				}
				_, sockets := gate.observed()
				want := 1
				if cancelBoth {
					want = 2
				}
				if sockets != want {
					t.Fatalf("observed %d client UDP sockets, want %d", sockets, want)
				}
			})
		}
	}
}
