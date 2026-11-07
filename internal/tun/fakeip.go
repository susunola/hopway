package tun

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
)

// FakeIP hands out addresses from a reserved range (198.18.0.0/15) in DNS
// answers, so a later connection to that address can be mapped back to the
// name the application asked for. Rules then see domains, not IPs, and the
// name is resolved by the proxy (no DNS leak) or by HopWay for DIRECT.
type FakeIP struct {
	mu     sync.Mutex
	prefix netip.Prefix
	base   uint32
	size   uint32
	next   uint32
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
	six    *fakeIP6 // optional IPv6 pool for AAAA answers
}

var (
	DefaultFakeRange  = netip.MustParsePrefix("198.18.0.0/15")
	DefaultFakeRange6 = netip.MustParsePrefix("fc00::/18")
)

// fakeIP6 numbers names in the low 32 bits of an IPv6 prefix.
type fakeIP6 struct {
	prefix netip.Prefix
	next   uint32
	limit  uint32
	byName map[string]netip.Addr
}

// EnableIPv6 adds an IPv6 pool; AAAA queries then get fake addresses too.
func (f *FakeIP) EnableIPv6(prefix netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	limit := uint32(1<<31 - 1)
	if bits := 128 - prefix.Bits(); bits < 31 {
		limit = uint32(1)<<bits - 1
	}
	f.six = &fakeIP6{prefix: prefix.Masked(), next: 2, limit: limit, byName: map[string]netip.Addr{}}
}

// Allocate6 returns the IPv6 address for name, or an invalid one without a pool.
func (f *FakeIP) Allocate6(name string) netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.six == nil {
		return netip.Addr{}
	}
	if addr, ok := f.six.byName[name]; ok {
		return addr
	}
	raw := f.six.prefix.Addr().As16()
	binary.BigEndian.PutUint32(raw[12:], binary.BigEndian.Uint32(raw[12:])+f.six.next)
	addr := netip.AddrFrom16(raw)
	f.six.next++
	if f.six.next >= f.six.limit {
		f.six.next = 2
	}
	if old, ok := f.byAddr[addr]; ok {
		delete(f.six.byName, old)
	}
	f.six.byName[name], f.byAddr[addr] = addr, name
	return addr
}

func NewFakeIP(prefix netip.Prefix) *FakeIP {
	prefix = prefix.Masked()
	a := prefix.Addr().As4()
	size := uint32(1) << (32 - prefix.Bits())
	// Skip the network address and the first host, which some stacks treat
	// as a gateway.
	return &FakeIP{prefix: prefix, base: binary.BigEndian.Uint32(a[:]), size: size, next: 2,
		byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}}
}

func (f *FakeIP) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	if f.prefix.Contains(addr) {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.six != nil && f.six.prefix.Contains(addr)
}

// Allocate returns the address for name, reusing a previous one. When the
// range wraps, the oldest mapping is overwritten.
func (f *FakeIP) Allocate(name string) netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	if addr, ok := f.byName[name]; ok {
		return addr
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], f.base+f.next)
	addr := netip.AddrFrom4(raw)
	f.next++
	if f.next >= f.size-1 {
		f.next = 2
	}
	if old, ok := f.byAddr[addr]; ok {
		delete(f.byName, old)
	}
	f.byName[name], f.byAddr[addr] = addr, name
	return addr
}

// Lookup maps a fake address back to its name.
func (f *FakeIP) Lookup(addr netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, ok := f.byAddr[addr.Unmap()]
	return name, ok
}
