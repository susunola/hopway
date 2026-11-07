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
}

var DefaultFakeRange = netip.MustParsePrefix("198.18.0.0/15")

func NewFakeIP(prefix netip.Prefix) *FakeIP {
	prefix = prefix.Masked()
	a := prefix.Addr().As4()
	size := uint32(1) << (32 - prefix.Bits())
	// Skip the network address and the first host, which some stacks treat
	// as a gateway.
	return &FakeIP{prefix: prefix, base: binary.BigEndian.Uint32(a[:]), size: size, next: 2,
		byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}}
}

func (f *FakeIP) Contains(addr netip.Addr) bool { return f.prefix.Contains(addr.Unmap()) }

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
