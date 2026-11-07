//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tunPacketFixture struct {
	N.PacketConn
	targets []M.Socksaddr
}

func (c *tunPacketFixture) ReadPacket(packet *buf.Buffer) (M.Socksaddr, error) {
	if len(c.targets) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	target := c.targets[0]
	c.targets = c.targets[1:]
	_, err := packet.Write([]byte("test"))
	return target, err
}

func (c *tunPacketFixture) Close() error { return nil }

type tunPacketOutbound struct {
	net.PacketConn
	writes []string
	closed chan struct{}
	once   sync.Once
}

func (c *tunPacketOutbound) SetReadDeadline(time.Time) error { return nil }

func (c *tunPacketOutbound) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *tunPacketOutbound) WriteTo(data []byte, destination net.Addr) (int, error) {
	c.writes = append(c.writes, destination.String())
	return len(data), nil
}

func (c *tunPacketOutbound) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestTUNUDPFlowDoesNotReuseRouteForAnotherDestination(t *testing.T) {
	source := M.ParseSocksaddr("10.0.0.1:12345")
	target := M.ParseSocksaddr("198.51.100.1:443")
	other := M.ParseSocksaddr("198.51.100.2:443")
	conn := &tunPacketFixture{targets: []M.Socksaddr{target, other, target}}
	outbound := &tunPacketOutbound{closed: make(chan struct{})}
	var routed []string
	options := Options{}
	options.defaults()
	service := &Service{fake: NewFakeIP(options.FakeRange),
		dialPacket: func(_ context.Context, _, destination string) (net.PacketConn, error) {
			routed = append(routed, destination)
			return outbound, nil
		}}
	service.NewPacketConnectionEx(context.Background(), conn, source, target, nil)
	if !slices.Equal(routed, []string{target.String()}) ||
		!slices.Equal(outbound.writes, []string{target.String(), target.String()}) {
		t.Fatalf("UDP flow reused its outbound for another target: route %v, writes %v", routed, outbound.writes)
	}
}
