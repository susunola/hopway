// Package backend turns configured nodes into dialers. Two implementations
// exist: sing-box (default, every protocol and transport) and native (small,
// no GPL protocol stack, selected with the hopway_native build tag).
package backend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

// Dialer opens a TCP stream to target ("host:port") through one node.
type Dialer interface {
	DialContext(ctx context.Context, target string) (net.Conn, error)
}

// PacketDialer is implemented by dialers that can carry UDP.
type PacketDialer interface {
	ListenPacket(ctx context.Context, target string) (net.PacketConn, error)
}

var ErrNoUDP = errors.New("this node does not carry UDP")

type DialerFunc func(ctx context.Context, target string) (net.Conn, error)

func (f DialerFunc) DialContext(ctx context.Context, target string) (net.Conn, error) {
	return f(ctx, target)
}

// Guard rejects socket destinations, used to stop a node pointing back at
// HopWay's own listeners.
type Guard func(netip.AddrPort) error

type Instance interface {
	Dialer(name string) (Dialer, bool)
	// ResetConnections retires the current pool generation. New traffic
	// cannot reuse sessions created on the previous network.
	ResetConnections()
	Close() error
}

type Backend interface {
	Name() string
	// Check reports whether a single node can be built, without opening it.
	Check(node outbound.Node) error
	Open(nodes []outbound.Node, guard Guard) (Instance, error)
}

var ErrLoop = errors.New("destination points to this proxy")

// SocketControl, when set, is applied to every socket HopWay opens itself.
// In TUN mode it binds sockets to the physical interface, so HopWay's own
// traffic never loops back into the tunnel.
var socketControl atomic.Pointer[func(network, address string, c syscall.RawConn) error]

// upstream DNS servers for HopWay's own lookups while SocketControl is set.
var upstreamDNS atomic.Pointer[[]string]

func SetSocketControl(control func(network, address string, c syscall.RawConn) error, upstreams ...string) {
	Resolver.mu.Lock()
	defer Resolver.mu.Unlock()
	if control == nil {
		socketControl.Store(nil)
		upstreamDNS.Store(nil)
		Resolver.resetLocked(systemLookup)
		return
	}
	// Keep loopback on the host and preserve an explicitly scoped IPv6
	// destination's own interface instead of binding it to the default one.
	bound := func(network, address string, c syscall.RawConn) error {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if addr, err := netip.ParseAddr(host); err == nil && (addr.Unmap().IsLoopback() || wire.IsScopedLinkLocal(addr)) {
				return nil
			}
		}
		return control(network, address, c)
	}
	socketControl.Store(&bound)
	servers := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		// A DNS hostname would itself require resolving, potentially
		// through the fake DNS that this socket is meant to bypass.
		if address, err := netip.ParseAddrPort(upstream); err == nil && address.Port() != 0 {
			servers = append(servers, address.String())
		}
	}
	upstreamDNS.Store(&servers)
	Resolver.resetLocked(func() lookupIP {
		var next atomic.Uint32
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(servers) == 0 {
				return nil, errNoUpstream
			}
			// The system resolver may point at HopWay's fake DNS. Use the
			// pre-TUN servers and socket binding for this network generation.
			address = servers[(next.Add(1)-1)%uint32(len(servers))]
			dialer := net.Dialer{Control: bound}
			return dialer.DialContext(ctx, network, address)
		}}
		return ipLookup(resolver)
	})
}

// UpstreamDNS returns the servers HopWay's own lookups use in TUN mode.
func UpstreamDNS() []string {
	if list := upstreamDNS.Load(); list != nil {
		return append([]string(nil), (*list)...)
	}
	return nil
}

// BoundDial opens a socket with SocketControl applied.
func BoundDial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{}
	if control := socketControl.Load(); control != nil {
		dialer.Control = *control
	}
	return dialer.DialContext(ctx, network, address)
}

// ListenPacket opens an unconnected UDP socket for sending to peer, with
// SocketControl applied unless the peer already identifies a local path.
func ListenPacket(ctx context.Context, peer netip.Addr) (net.PacketConn, error) {
	config := net.ListenConfig{}
	peer = peer.Unmap()
	if control := socketControl.Load(); control != nil && !peer.IsLoopback() && !wire.IsScopedLinkLocal(peer) {
		config.Control = *control
	}
	network := "udp6"
	if peer.Is4() {
		network = "udp4"
	}
	return config.ListenPacket(ctx, network, "")
}
