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

// ResourceBudget owns connection-opening and UDP limits, including engines that
// are still draining connections after a configuration reload.
type ResourceBudget struct {
	dials       endpointBudget
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

func NewResourceBudget() *ResourceBudget {
	return newResourceBudget(packetSessionLimit, packetOpenLimit)
}

func newResourceBudget(sessions, opening int) *ResourceBudget {
	return &ResourceBudget{
		dials:   endpointBudget{entries: make(map[string]*endpointSlots), probeOpening: make(chan struct{}, probeParallel)},
		started: time.Now(), maxSessions: sessions, opening: make(chan struct{}, opening),
		sessions: make(map[*trackedPacket]struct{}), outbounds: make(map[string]*packetOutbound),
	}
}

func (b *ResourceBudget) retainOutbound(key string) *packetOutbound {
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

func (b *ResourceBudget) releaseOutbound(o *packetOutbound) {
	if o.refs.Add(-1) == 0 {
		b.pruneOutbound(o)
	}
}

func (b *ResourceBudget) pruneOutbound(o *packetOutbound) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o.refs.Load() == 0 && len(o.sending) == 0 && b.outbounds[o.key] == o {
		delete(b.outbounds, o.key)
	}
}

// admit runs only after a socket opens, so failed attempts cannot evict a
// usable session. The caller closes the evicted socket outside both locks.
func (b *ResourceBudget) admit(c *trackedPacket) (oldest *trackedPacket) {
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

func (b *ResourceBudget) remove(c *trackedPacket) {
	b.mu.Lock()
	delete(b.sessions, c)
	b.mu.Unlock()
	b.releaseOutbound(c.outbound)
}
