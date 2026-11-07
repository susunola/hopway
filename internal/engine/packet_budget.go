package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	packetSessionLimit  = 1024
	packetOpenLimit     = 64
	packetExitOpenLimit = 8
	packetExitSendLimit = 16
)

// PacketBudget owns UDP limits for a running proxy, including engines that
// are still draining connections after a configuration reload.
type PacketBudget struct {
	mu          sync.Mutex
	started     time.Time
	sessions    map[*trackedPacket]struct{}
	outbounds   map[string]*packetOutbound
	opening     chan struct{}
	maxSessions int
}

type packetOutbound struct {
	key     string
	refs    atomic.Int64
	opening chan struct{}
	sending chan struct{}
}

func NewPacketBudget() *PacketBudget {
	return newPacketBudget(packetSessionLimit, packetOpenLimit)
}

func newPacketBudget(sessions, opening int) *PacketBudget {
	return &PacketBudget{
		started: time.Now(), maxSessions: sessions, opening: make(chan struct{}, opening),
		sessions: make(map[*trackedPacket]struct{}), outbounds: make(map[string]*packetOutbound),
	}
}

func (b *PacketBudget) retainOutbound(key string) *packetOutbound {
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.outbounds[key]
	if o == nil {
		o = &packetOutbound{
			key: key, opening: make(chan struct{}, packetExitOpenLimit), sending: make(chan struct{}, packetExitSendLimit),
		}
		b.outbounds[key] = o
	}
	o.refs.Add(1)
	return o
}

func (b *PacketBudget) releaseOutbound(o *packetOutbound) {
	if o.refs.Add(-1) == 0 {
		b.pruneOutbound(o)
	}
}

func (b *PacketBudget) pruneOutbound(o *packetOutbound) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o.refs.Load() == 0 && len(o.sending) == 0 && b.outbounds[o.key] == o {
		delete(b.outbounds, o.key)
	}
}

// admit runs only after a socket opens, so failed attempts cannot evict a
// usable session. The caller closes the evicted socket outside both locks.
func (b *PacketBudget) admit(c *trackedPacket) (oldest *trackedPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sessions) == b.maxSessions {
		var earliest int64
		for existing := range b.sessions {
			at := existing.lastActive.Load()
			if oldest == nil || at < earliest {
				oldest, earliest = existing, at
			}
		}
		oldest.closed.Store(true)
		delete(b.sessions, oldest)
	}
	c.touch()
	b.sessions[c] = struct{}{}
	return oldest
}

func (b *PacketBudget) remove(c *trackedPacket) {
	b.mu.Lock()
	delete(b.sessions, c)
	b.mu.Unlock()
	b.releaseOutbound(c.outbound)
}
