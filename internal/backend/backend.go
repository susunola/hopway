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
	Close() error
}

type Backend interface {
	Name() string
	// Check reports whether a single node can be built, without opening it.
	Check(node outbound.Node) error
	Open(nodes []outbound.Node, guard Guard) (Instance, error)
}

var ErrLoop = errors.New("destination points to this proxy")

// Resolver is the DNS cache shared by DIRECT connections and node servers.
var Resolver = &cache{entries: make(map[string]cached)}

type cached struct {
	addrs   []netip.Addr
	expires time.Time
}

type cache struct {
	mu      sync.Mutex
	entries map[string]cached
}

const cacheTTL = 30 * time.Second

func (c *cache) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	c.mu.Lock()
	entry, ok := c.entries[host]
	c.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.addrs, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
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
