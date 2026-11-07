package backend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

// ErrPacketCongested reports a dropped datagram or refused session when
// there is no capacity. An existing session can be used again after a drop.
var ErrPacketCongested = errors.New("UDP outbound is congested")

func PacketDropReason(err error) wire.UDPDropReason {
	switch {
	case errors.Is(err, ErrPacketCongested), errors.Is(err, wire.ErrConnectionLimit), wire.DescriptorExhausted(err):
		return wire.UDPQueueFull
	case errors.Is(err, outbound.ErrRejected):
		return wire.UDPPolicy
	default:
		return wire.UDPUpstream
	}
}

// DirectPacket opens a UDP socket for DIRECT traffic. WriteTo accepts
// M.Socksaddr destinations, names included, and ReadFrom reports replies
// with the address the caller wrote to, so callers treat direct and proxied
// UDP the same way.
func DirectPacket(ctx context.Context, target string, guard Guard) (net.PacketConn, error) {
	host, port, err := wire.Split(target)
	if err != nil {
		return nil, err
	}
	addrs, err := Resolver.Lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses for " + host)
		}
		return nil, err
	}
	first := netip.AddrPortFrom(addrs[0], port)
	if guard != nil {
		if err := guard(first); err != nil {
			return nil, err
		}
	}
	conn, err := ListenPacket(ctx, first.Addr())
	if err != nil {
		return nil, err
	}
	return &directPacket{PacketConn: conn, guard: guard, asked: map[netip.AddrPort]net.Addr{}}, nil
}

type directPacket struct {
	net.PacketConn
	guard Guard
	mu    sync.Mutex
	asked map[netip.AddrPort]net.Addr // resolved address -> what the caller wrote to
}

func (c *directPacket) WriteTo(data []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if socks, ok := addr.(M.Socksaddr); ok {
		destination = socks
	}
	resolved := destination.AddrPort()
	if destination.IsFqdn() {
		addrs, err := Resolver.Lookup(context.Background(), destination.Fqdn)
		if err != nil || len(addrs) == 0 {
			return 0, errors.New("cannot resolve " + destination.Fqdn)
		}
		resolved = netip.AddrPortFrom(addrs[0], destination.Port)
	}
	resolved = netip.AddrPortFrom(resolved.Addr().Unmap(), resolved.Port())
	if c.guard != nil {
		if err := c.guard(resolved); err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	if len(c.asked) > 1024 {
		c.asked = map[netip.AddrPort]net.Addr{}
	}
	c.asked[resolved] = addr
	c.mu.Unlock()
	return c.PacketConn.WriteTo(data, net.UDPAddrFromAddrPort(resolved))
}

func (c *directPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(data)
	if udp, ok := from.(*net.UDPAddr); ok {
		key := udp.AddrPort()
		key = netip.AddrPortFrom(key.Addr().Unmap(), key.Port())
		c.mu.Lock()
		asked, known := c.asked[key]
		c.mu.Unlock()
		if known {
			return n, asked, err
		}
	}
	return n, from, err
}
