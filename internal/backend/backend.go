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
	"time"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/trace"
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
	// ResetConnections drops idle pooled and multiplexed sessions, which are
	// dead after the network changes but would otherwise linger until timeout.
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
	// Loopback never goes through the tunnel, and a socket bound to the
	// physical interface cannot receive loopback replies.
	bound := func(network, address string, c syscall.RawConn) error {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if addr, err := netip.ParseAddr(host); err == nil && addr.Unmap().IsLoopback() {
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
// SocketControl applied unless peer is a loopback address.
func ListenPacket(ctx context.Context, peer netip.Addr) (net.PacketConn, error) {
	config := net.ListenConfig{}
	peer = peer.Unmap()
	if control := socketControl.Load(); control != nil && !peer.IsLoopback() {
		config.Control = *control
	}
	network := "udp6"
	if peer.Is4() {
		network = "udp4"
	}
	return config.ListenPacket(ctx, network, "")
}

// NetDial resolves and connects to address over network ("tcp" or "udp"),
// recording DNS and connect timings in the context's trace.
func NetDial(ctx context.Context, network, address string, guard Guard) (net.Conn, error) {
	t := trace.From(ctx)
	host, port, err := wire.Split(address)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	addrs, err := Resolver.Lookup(ctx, host)
	dns := time.Since(start)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses for " + host)
		}
		t.Dial(address, dns, 0, trace.StageDNS)
		return nil, err
	}
	connectStart := time.Now()
	var dialer net.Dialer
	if control := socketControl.Load(); control != nil {
		dialer.Control = *control
	}
	for i, addr := range addrs {
		target := netip.AddrPortFrom(addr, port)
		if guard != nil {
			if err = guard(target); err != nil {
				break
			}
		}
		attempt := ctx
		var cancel context.CancelFunc = func() {}
		if i < len(addrs)-1 {
			// Leave time for the remaining addresses if this one is black-holed.
			attempt, cancel = context.WithTimeout(ctx, 3*time.Second)
		}
		var conn net.Conn
		conn, err = dialer.DialContext(attempt, network, target.String())
		cancel()
		if err == nil {
			t.Dial(address, dns, time.Since(connectStart), "")
			return conn, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	t.Dial(address, dns, time.Since(connectStart), trace.StageConnect)
	return nil, err
}
