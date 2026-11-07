//go:build linux && !hopway_native

package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
)

type delayedTUNUDP struct {
	net.PacketConn
	held         chan struct{}
	unblock      <-chan struct{}
	writeStarted chan struct{}
	closed       chan struct{}
}

func (c *delayedTUNUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	n, source, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		close(c.held)
		<-c.unblock
	}
	return n, source, err
}

func (c *delayedTUNUDP) WriteTo(p []byte, address net.Addr) (int, error) {
	if string(p) == "blocked write" {
		close(c.writeStarted)
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.PacketConn.WriteTo(p, address)
}

func (c *delayedTUNUDP) Close() error {
	err := c.PacketConn.Close()
	close(c.closed)
	return err
}

func TestDeviceUDPExpiryDiscardsLateReply(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { origin.Close() })
	go func() {
		var buffer [128]byte
		for {
			n, from, err := origin.ReadFromUDPAddrPort(buffer[:])
			if err != nil {
				return
			}
			origin.WriteToUDPAddrPort(buffer[:n], from)
		}
	}()
	const host = "udp-expiry.test"
	backend.Resolver.Pin(host, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	t.Cleanup(func() { backend.Resolver.Pin(host, nil) })
	unblock := make(chan struct{})
	release := sync.OnceFunc(func() { close(unblock) })
	defer release()
	old := &delayedTUNUDP{
		held: make(chan struct{}), unblock: unblock,
		writeStarted: make(chan struct{}), closed: make(chan struct{}),
	}
	var dials atomic.Int32
	service, err := Start(Options{Name: "hwexpiry0", AutoRoute: true, RouteAddress: []netip.Prefix{DefaultFakeRange},
		UDPIdleTimeout: 300 * time.Millisecond}, nil, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		upstream, err := backend.DirectPacket(ctx, target, nil)
		if err != nil || dials.Add(1) != 1 {
			return upstream, err
		}
		old.PacketConn = upstream
		return old, nil
	})
	if err != nil {
		t.Skipf("cannot create a TUN device here: %v", err)
	}
	t.Cleanup(func() { service.Close() })
	address := netip.AddrPortFrom(service.fake.Allocate(host), origin.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	send := func(payload string) {
		t.Helper()
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(ch <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal(message)
		}
	}
	send("old reply")
	wait(old.held, "first reply did not come from the real origin")
	send("blocked write")
	wait(old.writeStarted, "old flow did not enter the blocked write")
	wait(old.closed, "idle expiry did not close the old outbound socket")
	send("fresh reply")
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [128]byte
	n, err := client.Read(buffer[:])
	if err != nil || string(buffer[:n]) != "fresh reply" || dials.Load() != 2 {
		t.Fatalf("replacement sent %q, dials=%d, err=%v", buffer[:n], dials.Load(), err)
	}
	release()
	client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, err = client.Read(buffer[:])
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("late or unexpected reply %q, err=%v", buffer[:n], err)
	}
	t.Log("real TUN expiry closed a blocked outbound and the replacement exchanged a datagram before the old reply was released")
}
