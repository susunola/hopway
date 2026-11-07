// Package backend turns configured nodes into dialers. Two implementations
// exist: sing-box (default, every protocol and transport) and native (small,
// no GPL protocol stack, selected with the hopway_native build tag).
package backend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
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

// goResolver, when set, replaces the system resolver for HopWay's own
// lookups. In TUN mode the system resolver's queries would be hijacked and
// answered with fake IPs, so HopWay asks the DNS servers directly over
// bound sockets instead.
var goResolver atomic.Pointer[net.Resolver]

// upstream DNS servers for HopWay's own lookups while SocketControl is set.
var upstreamDNS atomic.Pointer[[]string]

func SetSocketControl(control func(network, address string, c syscall.RawConn) error, upstreams ...string) {
	if control == nil {
		socketControl.Store(nil)
		goResolver.Store(nil)
		upstreamDNS.Store(nil)
		Resolver.Flush()
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
	if len(upstreams) != 0 {
		upstreamDNS.Store(&upstreams)
	}
	var next atomic.Uint32
	goResolver.Store(&net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		// The system's DNS setting may point at the tunnel itself; ask the
		// servers that were configured before it instead.
		if list := upstreamDNS.Load(); list != nil && len(*list) != 0 {
			address = (*list)[int(next.Add(1))%len(*list)]
		}
		return BoundDial(ctx, network, address)
	}})
	Resolver.Flush()
}

// UpstreamDNS returns the servers HopWay's own lookups use in TUN mode.
func UpstreamDNS() []string {
	if list := upstreamDNS.Load(); list != nil {
		return *list
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
	if control := socketControl.Load(); control != nil && !peer.Unmap().IsLoopback() {
		config.Control = *control
	}
	return config.ListenPacket(ctx, "udp", "")
}

// Resolver is the DNS cache shared by DIRECT connections and node servers.
var Resolver = &cache{entries: make(map[string]cached), pinned: make(map[string][]netip.Addr)}

type cached struct {
	addrs   []netip.Addr
	expires time.Time
}

type cache struct {
	mu      sync.Mutex
	entries map[string]cached
	pinned  map[string][]netip.Addr // fixed answers (hosts entries), never flushed
}

// Pin makes host always resolve to addrs; nil removes the entry.
func (c *cache) Pin(host string, addrs []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if addrs == nil {
		delete(c.pinned, host)
		return
	}
	c.pinned[host] = addrs
}

const cacheTTL = 30 * time.Second

func (c *cache) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	c.mu.Lock()
	if addrs, ok := c.pinned[host]; ok {
		c.mu.Unlock()
		return addrs, nil
	}
	entry, ok := c.entries[host]
	c.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.addrs, nil
	}
	resolver := net.DefaultResolver
	if r := goResolver.Load(); r != nil {
		resolver = r
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	// IPv4 first: many home networks advertise IPv6 that does not route.
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Is4() && !addrs[j].Is4() })
	c.mu.Lock()
	if len(c.entries) > 4096 {
		c.entries = make(map[string]cached)
	}
	c.entries[host] = cached{addrs, time.Now().Add(cacheTTL)}
	c.mu.Unlock()
	return addrs, nil
}

// Flush drops cached answers, called when the network changes.
func (c *cache) Flush() {
	c.mu.Lock()
	c.entries = make(map[string]cached)
	c.mu.Unlock()
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
