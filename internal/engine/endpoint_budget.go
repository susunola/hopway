package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/wire"
)

const endpointProbeLimit = 4

var errEndpointBusy = errors.New("proxy endpoint has too many unfinished connections")

type endpointBudget struct {
	mu           sync.Mutex
	entries      map[string]*endpointSlots
	maxOpening   int
	probeOpening chan struct{}
	networkEpoch uint64
	now          func() time.Time
}

type endpointSlots struct {
	key      string
	engines  int
	opening  chan struct{}
	probing  chan struct{}
	tcp, udp endpointCircuit
}

func endpointKey(address string) string {
	host, port, err := wire.Split(address)
	if err != nil {
		return strings.ToLower(address)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func (b *endpointBudget) retain(key string) *endpointSlots {
	b.mu.Lock()
	defer b.mu.Unlock()
	slot := b.entries[key]
	if slot == nil {
		slot = &endpointSlots{
			key: key, opening: make(chan struct{}, b.maxOpening), probing: make(chan struct{}, endpointProbeLimit),
		}
		b.entries[key] = slot
	}
	slot.engines++
	return slot
}

func (b *endpointBudget) release(slot *endpointSlots) {
	b.mu.Lock()
	defer b.mu.Unlock()
	slot.engines--
	b.prune(slot)
}

func (b *endpointBudget) prune(slot *endpointSlots) {
	if slot.engines == 0 && len(slot.opening) == 0 && b.entries[slot.key] == slot {
		delete(b.entries, slot.key)
	}
}

// A saturated endpoint fails fast so the next candidate can still dial.
func (engine *Engine) acquireDialSlot(via string) (*endpointSlots, error) {
	slot := engine.dialSlots[via]
	if slot == nil {
		return nil, nil
	}
	b := &engine.budget.dials
	b.mu.Lock()
	defer b.mu.Unlock()
	if slot.engines == 0 {
		return nil, net.ErrClosed
	}
	select {
	case slot.opening <- struct{}{}:
		return slot, nil
	default:
		return nil, errEndpointBusy
	}
}

func (b *endpointBudget) finish(slot *endpointSlots) {
	b.mu.Lock()
	defer b.mu.Unlock()
	<-slot.opening
	b.prune(slot)
}

// Hold a separate probe permit across the measurement, including its HTTP
// exchange. Waiting for this permit does not consume the network timeout.
func (engine *Engine) reserveProbe(ctx context.Context, name string) (func(), error) {
	endpoint := engine.dialSlots[name]
	if endpoint == nil {
		return func() {}, nil
	}
	b := &engine.budget.dials
	select {
	case endpoint.probing <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case b.probeOpening <- struct{}{}:
		return func() {
			<-b.probeOpening
			<-endpoint.probing
		}, nil
	case <-ctx.Done():
		<-endpoint.probing
		return nil, ctx.Err()
	}
}

func (engine *Engine) limitProbeDial(name string, dialer backend.Dialer) backend.Dialer {
	return backend.DialerFunc(func(ctx context.Context, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		slot, err := engine.acquireDialSlot(name)
		if err != nil {
			return nil, err
		}
		if slot != nil {
			defer engine.budget.dials.finish(slot)
		}
		return dialer.DialContext(engine.withEndpointGate(ctx, name), address)
	})
}
