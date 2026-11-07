package tun

import (
	"container/list"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	DefaultFakeRange  = netip.MustParsePrefix("198.18.0.0/15")
	DefaultFakeRange6 = netip.MustParsePrefix("fc00::/18")
)

const (
	fakeIPRetention = 2 * time.Minute
	maxFakeIPLeases = 131_072
)

// FakeIP translates DNS answers back to names. An active TCP or UDP flow
// holds its mapping independently of the lifetime advertised in DNS.
type FakeIP struct {
	mu   sync.Mutex
	now  func() time.Time
	four *fakePool
	six  *fakePool
}

type fakePool struct {
	prefix    netip.Prefix
	capacity  uint32
	next      uint32
	byName    map[string]*fakeLease
	byAddr    map[netip.Addr]*fakeLease
	idle      list.List
	pinned    int
	reclaimed uint64
	refused   uint64
}

type fakeLease struct {
	name    string
	address netip.Addr
	expires time.Time
	refs    int
	idle    *list.Element
}

type FakeIPStats struct {
	IPv4 FakePoolStats  `json:"ipv4"`
	IPv6 *FakePoolStats `json:"ipv6,omitempty"`
}

type FakePoolStats struct {
	Capacity  uint32 `json:"capacity"`
	Mapped    int    `json:"mapped"`
	Pinned    int    `json:"pinned"`
	Reclaimed uint64 `json:"reclaimed"`
	Refused   uint64 `json:"refused"`
}

func newFakePool(prefix netip.Prefix) *fakePool {
	capacity := uint32(maxFakeIPLeases)
	if bits := prefix.Addr().BitLen() - prefix.Bits(); bits < 18 {
		if bits < 2 {
			capacity = 0
		} else {
			// Reserve the network, first host (gateway), and last address.
			capacity = (uint32(1) << bits) - 3
		}
	}
	return &fakePool{
		prefix: prefix.Masked(), capacity: capacity, next: 2,
		byName: make(map[string]*fakeLease), byAddr: make(map[netip.Addr]*fakeLease),
	}
}

func NewFakeIP(prefix netip.Prefix) *FakeIP {
	return &FakeIP{now: time.Now, four: newFakePool(prefix)}
}

func (f *FakeIP) EnableIPv6(prefix netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.six == nil {
		f.six = newFakePool(prefix)
	}
}

func (f *FakeIP) hasIPv6() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.six != nil
}

func (f *FakeIP) Contains(addr netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pool(addr.Unmap()) != nil
}

func (f *FakeIP) pool(addr netip.Addr) *fakePool {
	if f.four.prefix.Contains(addr) {
		return f.four
	}
	if f.six != nil && f.six.prefix.Contains(addr) {
		return f.six
	}
	return nil
}

func (f *FakeIP) Allocate(name string) netip.Addr {
	return f.allocate(name, false)
}

func (f *FakeIP) Allocate6(name string) netip.Addr {
	return f.allocate(name, true)
}

func (f *FakeIP) allocate(name string, ipv6 bool) netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return netip.Addr{}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return netip.Addr{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.four
	if ipv6 {
		p = f.six
	}
	if p == nil {
		return netip.Addr{}
	}
	return p.allocate(name, f.now())
}

func (p *fakePool) allocate(name string, now time.Time) netip.Addr {
	if lease := p.byName[name]; lease != nil {
		p.touch(lease, now)
		return lease.address
	}
	var address netip.Addr
	if uint32(len(p.byAddr)) < p.capacity {
		address = p.nextAddress()
	} else {
		// Only inactive leases appear in idle, oldest expiration first.
		first := p.idle.Front()
		if first == nil || now.Before(first.Value.(*fakeLease).expires) {
			p.refused++
			return netip.Addr{}
		}
		old := first.Value.(*fakeLease)
		address = old.address
		p.idle.Remove(first)
		delete(p.byName, old.name)
		p.reclaimed++
	}
	lease := &fakeLease{name: name, address: address}
	p.byName[name], p.byAddr[address] = lease, lease
	p.touch(lease, now)
	return address
}

func (p *fakePool) nextAddress() netip.Addr {
	offset := p.next
	p.next++
	base := p.prefix.Addr()
	if base.Is4() {
		bytes := base.As4()
		binary.BigEndian.PutUint32(bytes[:], binary.BigEndian.Uint32(bytes[:])+offset)
		return netip.AddrFrom4(bytes)
	}
	bytes := base.As16()
	binary.BigEndian.PutUint32(bytes[12:], binary.BigEndian.Uint32(bytes[12:])+offset)
	return netip.AddrFrom16(bytes)
}

func (p *fakePool) touch(lease *fakeLease, now time.Time) {
	lease.expires = now.Add(fakeIPRetention)
	if lease.refs != 0 {
		return
	}
	if lease.idle == nil {
		lease.idle = p.idle.PushBack(lease)
	} else {
		p.idle.MoveToBack(lease.idle)
	}
}

func (p *fakePool) lookup(address netip.Addr, now time.Time) *fakeLease {
	if p == nil {
		return nil
	}
	lease := p.byAddr[address]
	if lease != nil && (lease.refs != 0 || now.Before(lease.expires)) {
		return lease
	}
	return nil
}

func (f *FakeIP) Lookup(address netip.Addr) (string, bool) {
	address = address.Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	if lease := f.pool(address).lookup(address, f.now()); lease != nil {
		return lease.name, true
	}
	return "", false
}

// acquire returns a lease held until release. The caller releases it once.
func (f *FakeIP) acquire(address netip.Addr) (name string, release func()) {
	address = address.Unmap()
	f.mu.Lock()
	p := f.pool(address)
	lease := p.lookup(address, f.now())
	if lease == nil {
		f.mu.Unlock()
		return "", nil
	}
	if lease.refs == 0 {
		p.idle.Remove(lease.idle)
		lease.idle = nil
		p.pinned++
	}
	lease.refs++
	f.mu.Unlock()
	return lease.name, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		lease.refs--
		if lease.refs == 0 {
			p.pinned--
			p.touch(lease, f.now())
		}
	}
}

func (f *FakeIP) Stats() FakeIPStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := FakeIPStats{IPv4: f.four.stats()}
	if f.six != nil {
		ipv6 := f.six.stats()
		out.IPv6 = &ipv6
	}
	return out
}

func (p *fakePool) stats() FakePoolStats {
	return FakePoolStats{
		Capacity: p.capacity, Mapped: len(p.byAddr), Pinned: p.pinned,
		Reclaimed: p.reclaimed, Refused: p.refused,
	}
}
