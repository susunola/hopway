package engine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceLimits bounds work shared by all generations of the proxy.
// A zero field uses the default.
type ResourceLimits struct {
	UDPSessionLimit   int `json:"udpSessionLimit,omitempty"`
	UDPOpenLimit      int `json:"udpOpenLimit,omitempty"`
	EndpointDialLimit int `json:"endpointDialLimit,omitempty"`
}

func (limits ResourceLimits) effective() (ResourceLimits, error) {
	for _, field := range []struct {
		name             string
		value            *int
		minimum, maximum int
	}{
		{"udpSessionLimit", &limits.UDPSessionLimit, 32, packetSessionLimit},
		{"udpOpenLimit", &limits.UDPOpenLimit, 1, packetOpenLimit},
		{"endpointDialLimit", &limits.EndpointDialLimit, endpointProbeLimit, endpointDialLimit},
	} {
		switch {
		case *field.value == 0:
			*field.value = field.maximum
		case *field.value < field.minimum || *field.value > field.maximum:
			return ResourceLimits{}, fmt.Errorf("resources.%s must be between %d and %d", field.name, field.minimum, field.maximum)
		}
	}
	return limits, nil
}

type ResourceStatus struct {
	ResourceLimits
	UDPSessions int `json:"udpSessions"`
	UDPOpening  int `json:"udpOpening"`
}

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

func NewResourceBudget(config ResourceLimits) (*ResourceBudget, error) {
	limits, err := config.effective()
	if err != nil {
		return nil, err
	}
	return newResourceBudget(limits), nil
}

func newResourceBudget(limits ResourceLimits) *ResourceBudget {
	return &ResourceBudget{
		dials: endpointBudget{entries: make(map[string]*endpointSlots), maxOpening: limits.EndpointDialLimit,
			probeOpening: make(chan struct{}, probeParallel), now: time.Now},
		started: time.Now(), maxSessions: limits.UDPSessionLimit, opening: make(chan struct{}, limits.UDPOpenLimit),
		sessions: make(map[*trackedPacket]struct{}), outbounds: make(map[string]*packetOutbound),
	}
}

func (b *ResourceBudget) limits() ResourceLimits {
	return ResourceLimits{UDPSessionLimit: b.maxSessions, UDPOpenLimit: cap(b.opening), EndpointDialLimit: b.dials.maxOpening}
}

func (b *ResourceBudget) Matches(config ResourceLimits) bool {
	limits, err := config.effective()
	return err == nil && limits == b.limits()
}

func (b *ResourceBudget) status() *ResourceStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &ResourceStatus{ResourceLimits: b.limits(), UDPSessions: len(b.sessions), UDPOpening: len(b.opening)}
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
