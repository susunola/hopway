package backend

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	dnsCacheLimit  = 4096
	dnsFlightLimit = 256
	dnsTimeout     = 5 * time.Second
	cacheTTL       = 30 * time.Second
	missingTTL     = 5 * time.Second
)

var (
	errNoUpstream = errors.New("no upstream DNS server")
	errDNSBusy    = errors.New("too many concurrent DNS lookups")
)

// Resolver is the DNS cache shared by DIRECT connections and node servers.
var Resolver = newCache(systemLookup, dnsCacheLimit)

type lookupIP func(context.Context, string) ([]netip.Addr, error)

func ipLookup(resolver *net.Resolver) lookupIP {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", host)
	}
}

func systemLookup() lookupIP {
	// Each generation needs a distinct net.Resolver, including its internal
	// in-flight lookup group.
	base := net.DefaultResolver
	return ipLookup(&net.Resolver{PreferGo: base.PreferGo, StrictErrors: base.StrictErrors, Dial: base.Dial})
}

type dnsResult struct {
	addrs []netip.Addr
	err   error
}

func (r dnsResult) answer() ([]netip.Addr, error) {
	// Callers can sort or mutate their copy without changing the cache.
	return slices.Clone(r.addrs), r.err
}

type cached struct {
	host    string
	result  dnsResult
	expires time.Time
}

type flight struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	waiters int
	result  dnsResult
}

type dnsView struct {
	ctx     context.Context
	cancel  context.CancelFunc
	lookup  lookupIP
	entries map[string]*list.Element
	recent  list.List
	pending map[string]*flight
}

type cache struct {
	mu      sync.Mutex
	factory func() lookupIP
	view    *dnsView
	limit   int
	pinned  map[string][]netip.Addr
}

func newCache(factory func() lookupIP, limit int) *cache {
	c := &cache{limit: limit, pinned: make(map[string][]netip.Addr)}
	c.resetLocked(factory)
	return c
}

func (c *cache) resetLocked(factory func() lookupIP) {
	if c.view != nil {
		c.view.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.factory = factory
	c.view = &dnsView{
		ctx: ctx, cancel: cancel, lookup: factory(),
		entries: make(map[string]*list.Element),
		pending: make(map[string]*flight),
	}
}

// Pin makes host always resolve to addrs; nil removes the entry.
func (c *cache) Pin(host string, addrs []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.TrimSuffix(strings.ToLower(host), ".")
	if addrs == nil {
		delete(c.pinned, key)
		return
	}
	c.pinned[key] = slices.Clone(addrs)
}

func (c *cache) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	host = strings.ToLower(host)
	key := strings.TrimSuffix(host, ".")
	// Share absolute answers across case and trailing-dot variants. A
	// relative input may still use the system search suffix when missing.
	absolute := host
	if strings.Contains(key, ".") {
		absolute = key + "."
	}
	addrs, err := c.lookup(ctx, absolute, key)
	var dnsErr *net.DNSError
	if absolute != host && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return c.lookup(ctx, host, key)
	}
	return addrs, err
}

func (c *cache) lookup(ctx context.Context, host, pin string) ([]netip.Addr, error) {
	c.mu.Lock()
	view := c.view
	if addrs, ok := c.pinned[pin]; ok {
		c.mu.Unlock()
		return slices.Clone(addrs), nil
	}
	if element := view.entries[host]; element != nil {
		entry := element.Value.(cached)
		if time.Now().Before(entry.expires) {
			view.recent.MoveToFront(element)
			c.mu.Unlock()
			return entry.result.answer()
		}
		view.remove(element)
	}
	p := view.pending[host]
	if p == nil {
		if len(view.pending) >= dnsFlightLimit {
			c.mu.Unlock()
			return nil, errDNSBusy
		}
		flightCtx, cancel := context.WithTimeout(view.ctx, dnsTimeout)
		p = &flight{ctx: flightCtx, cancel: cancel, done: make(chan struct{}), waiters: 1}
		view.pending[host] = p
		c.mu.Unlock()
		go c.resolve(view, host, p)
	} else {
		p.waiters++
		c.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		c.mu.Lock()
		if view.pending[host] == p {
			p.waiters--
			if p.waiters == 0 {
				delete(view.pending, host)
				p.cancel()
			}
		}
		c.mu.Unlock()
		return nil, ctx.Err()
	case <-view.ctx.Done():
		return nil, view.ctx.Err()
	case <-p.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := view.ctx.Err(); err != nil {
			return nil, err
		}
		return p.result.answer()
	}
}

func (c *cache) resolve(view *dnsView, host string, p *flight) {
	defer p.cancel()
	addrs, err := view.lookup(p.ctx, host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	// IPv4 first: many home networks advertise IPv6 that does not route.
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Is4() && !addrs[j].Is4() })
	result := dnsResult{addrs, err}
	ttl := time.Duration(0)
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(addrs) != 0:
		ttl = cacheTTL
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		ttl = missingTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p.result = result
	if view.pending[host] == p {
		delete(view.pending, host)
		if c.view == view && p.ctx.Err() == nil && ttl != 0 {
			entry := cached{host, result, time.Now().Add(ttl)}
			view.entries[host] = view.recent.PushFront(entry)
			if len(view.entries) > c.limit {
				view.remove(view.recent.Back())
			}
		}
	}
	close(p.done)
}

func (view *dnsView) remove(element *list.Element) {
	delete(view.entries, element.Value.(cached).host)
	view.recent.Remove(element)
}

// Flush drops cached answers and cancels in-flight work on the old network.
func (c *cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(c.factory)
}
