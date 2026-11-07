//go:build linux && !hopway_native

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/socks5"
	"mac-proxy/internal/wire"
)

func TestDeviceUDPQueueSharesBudgetWithSOCKS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	if used := wire.UDPQueue.Bytes(); used != 0 {
		t.Fatalf("UDP queue already holds %d bytes", used)
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			echo.WriteToUDP(buffer[:n], from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	stalledPort := echoPort + 1
	if stalledPort > 65535 {
		stalledPort = echoPort - 1
	}
	const host = "udp-budget.test"
	backend.Resolver.Pin(host, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	t.Cleanup(func() { backend.Resolver.Pin(host, nil) })
	core, err := engine.New(engine.Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	service, err := Start(Options{Name: "hwbudget0", AutoRoute: true, RouteAddress: []netip.Prefix{DefaultFakeRange}},
		core.Dial, func(ctx context.Context, inbound, target string) (net.PacketConn, error) {
			_, port, err := wire.Split(target)
			if err != nil {
				return nil, err
			}
			if int(port) == stalledPort {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-gate:
					return nil, errors.New("fixture rejected outbound after the stall")
				}
			}
			return core.DialPacket(ctx, inbound, target)
		})
	if err != nil {
		t.Skipf("cannot create a TUN device here: %v", err)
	}
	t.Cleanup(func() { service.Close() })
	fake := service.fake.Allocate(host)
	dialUDP := func(addr netip.AddrPort) *net.UDPConn {
		t.Helper()
		client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		return client
	}
	waitFor := func(description string, ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for !ready() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: queued=%d, TUN=%+v, SOCKS=%+v", description,
					wire.UDPQueue.Bytes(), wire.TUNUDPDrops.Snapshot(), wire.SOCKSUDPDrops.Snapshot())
			}
			time.Sleep(time.Millisecond)
		}
	}
	send := func(conn *net.UDPConn, payload []byte) {
		t.Helper()
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("send UDP payload: %d, %v", n, err)
		}
	}
	liveHeap := func() uint64 {
		// A second GC clears buffers left in sync.Pool's victim cache.
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	baselineHeap := liveHeap()
	tunBefore := wire.TUNUDPDrops.Snapshot()
	stalled := netip.AddrPortFrom(fake, uint16(stalledPort))
	first := dialUDP(stalled)
	payload := bytes.Repeat([]byte{0x5a}, 4000)
	for range 72 {
		send(first, payload)
	}
	waitFor("single TUN flow overflow", func() bool {
		return wire.TUNUDPDrops.Snapshot().QueueFull > tunBefore.QueueFull
	})
	if used := wire.UDPQueue.Bytes(); used < 256<<10 || used >= 512<<10 {
		t.Fatalf("single flow used %d bytes", used)
	}
	flows := make([]*net.UDPConn, 40)
	for i := range flows {
		flows[i] = dialUDP(stalled)
	}
	for range 64 {
		for _, flow := range flows {
			send(flow, payload)
		}
		time.Sleep(time.Millisecond)
	}
	const tunPacketCharge = 4096 + 128
	waitFor("shared budget fills across TUN flows", func() bool {
		return wire.UDPQueue.Bytes() > wire.UDPQueueLimit-tunPacketCharge
	})
	used := wire.UDPQueue.Bytes()
	drops := wire.TUNUDPDrops.Snapshot()
	if used > wire.UDPQueueLimit || drops.Upstream != tunBefore.Upstream {
		t.Fatalf("queued=%d, TUN drops=%+v", used, drops)
	}
	send(flows[0], payload)
	waitFor("full TUN budget records further drops", func() bool {
		return wire.TUNUDPDrops.Snapshot().QueueFull > drops.QueueFull
	})
	peakHeap := liveHeap()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			defer conn.Close()
			socks5.HandleWithUDP(conn, core.Dial, core.DialPacket)
		}
	}()
	control, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	handshake := func(command []byte, replyLen int) []byte {
		t.Helper()
		if _, err := control.Write(command); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, replyLen)
		if _, err := io.ReadFull(control, reply); err != nil || reply[0] != 5 || reply[1] != 0 {
			t.Fatalf("SOCKS UDP negotiation: %x, %v", reply, err)
		}
		return reply
	}
	handshake([]byte{5, 1, 0}, 2)
	bind := handshake([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, 10)
	if bind[3] != 1 {
		t.Fatalf("SOCKS relay address: %x", bind)
	}
	socks := dialUDP(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), binary.BigEndian.Uint16(bind[8:])))
	header := binary.BigEndian.AppendUint16([]byte{0, 0, 0, 1, 127, 0, 0, 1}, uint16(echoPort))
	socksBefore := wire.SOCKSUDPDrops.Snapshot()
	send(socks, append(bytes.Clone(header), make([]byte, 60000)...))
	waitFor("SOCKS packet rejected while TUN owns the shared budget", func() bool {
		return wire.SOCKSUDPDrops.Snapshot().QueueFull > socksBefore.QueueFull
	})
	release()
	waitFor("failed TUN outbounds relinquish the queue budget", func() bool {
		return wire.UDPQueue.Bytes() == 0 &&
			wire.TUNUDPDrops.Snapshot().Upstream-tunBefore.Upstream >= uint64(used/tunPacketCharge)
	})
	verifyEcho := func(conn *net.UDPConn, payload []byte) {
		t.Helper()
		send(conn, payload)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply := make([]byte, len(payload)+1)
		n, err := conn.Read(reply)
		if err != nil || !bytes.Equal(reply[:n], payload) {
			t.Fatalf("after pressure, echo received %d bytes, expected %d: %v", n, len(payload), err)
		}
	}
	verifyEcho(socks, append(bytes.Clone(header), payload...))
	verifyEcho(dialUDP(netip.AddrPortFrom(fake, uint16(echoPort))), payload)
	waitFor("recovered ingress queues stay empty", func() bool { return wire.UDPQueue.Bytes() == 0 })
	recoveredHeap := liveHeap()
	if recoveredHeap+uint64(used/2) > peakHeap {
		t.Errorf("live heap failed to fall after draining: %d -> %d -> %d bytes", baselineHeap, peakHeap, recoveredHeap)
	}
	t.Logf("UDP queue charged %d / %d bytes, dropped %d TUN queue-full and %d upstream packets, rejected one SOCKS packet, then recovered",
		used, wire.UDPQueueLimit, wire.TUNUDPDrops.Snapshot().QueueFull-tunBefore.QueueFull,
		wire.TUNUDPDrops.Snapshot().Upstream-tunBefore.Upstream)
	t.Logf("live heap after GC: %d -> %d -> %d bytes", baselineHeap, peakHeap, recoveredHeap)
}
