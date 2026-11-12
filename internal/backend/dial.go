package backend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"mac-proxy/internal/trace"
	"mac-proxy/internal/wire"
)

const (
	familyResolutionDelay = 50 * time.Millisecond
	familyFallbackDelay   = 200 * time.Millisecond
	addressAttemptTimeout = 3 * time.Second
)

var ErrEndpointCooling = errors.New("proxy endpoint is cooling down")

type dialGateKey struct{}

// WithDialGate applies admission to physical sockets opened by this dial.
// The completion callback sees the actual failing DNS or socket stage.
func WithDialGate(ctx context.Context, gate func(network, address string) (func(string, error), error)) context.Context {
	return context.WithValue(ctx, dialGateKey{}, gate)
}

type socketDial func(context.Context, string, string) (net.Conn, error)

type dialResult struct {
	conn          net.Conn
	err           error
	dns           time.Duration
	connect       time.Duration
	stage         string
	guardRejected bool
	dnsName       string
}

// HostResolver resolves a host and reports which upstream answered.
type HostResolver interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, string, error)
}

type resolverContextKey struct{}

// WithResolver attaches a per-engine resolver. Dialers read it from the
// context, so a reload never has to share mutable resolver state.
func WithResolver(ctx context.Context, resolver HostResolver) context.Context {
	return context.WithValue(ctx, resolverContextKey{}, resolver)
}

func resolverFrom(ctx context.Context) HostResolver {
	resolver, _ := ctx.Value(resolverContextKey{}).(HostResolver)
	return resolver
}

// NetDial resolves and connects to address, recording DNS and connect
// timings. Each address family progresses independently within one view.
func NetDial(ctx context.Context, network, address string, guard Guard) (net.Conn, error) {
	Resolver.mu.Lock()
	view, control := Resolver.view, socketControl.Load()
	Resolver.mu.Unlock()
	var dialer net.Dialer
	if control != nil {
		dialer.Control = *control
	}
	host, port, err := wire.Split(address)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result dialResult
	if gate, ok := ctx.Value(dialGateKey{}).(func(string, string) (func(string, error), error)); ok {
		finish, err := gate(network, address)
		if err != nil {
			trace.From(ctx).Dial(address, 0, 0, trace.StageConnect)
			return nil, err
		}
		if finish != nil {
			defer func() { finish(result.stage, result.err) }()
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(view.ctx, cancel)
	defer stop()
	if view.ctx.Err() != nil {
		cancel()
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		result = dialAddresses(ctx, network, port, []netip.Addr{ip.Unmap()}, dialer.DialContext, guard)
	} else {
		var dnsName atomic.Value
		lookup := func(ctx context.Context, family string) ([]netip.Addr, error) {
			resolver := resolverFrom(ctx)
			if resolver == nil {
				return Resolver.lookupNetwork(ctx, view, family, host)
			}
			addrs, name, err := resolver.Lookup(ctx, host)
			if name != "" {
				dnsName.Store(name)
			}
			if err != nil {
				return nil, err
			}
			filtered := make([]netip.Addr, 0, len(addrs))
			for _, addr := range addrs {
				if family == "ip4" && addr.Is4() {
					filtered = append(filtered, addr)
				} else if family != "ip4" && !addr.Is4() {
					filtered = append(filtered, addr)
				}
			}
			return filtered, nil
		}
		result = dialFamilies(ctx, network, host, port, lookup, dialer.DialContext, guard)
		if name, ok := dnsName.Load().(string); ok {
			result.dnsName = name
		}
	}
	err = ctx.Err()
	if err == nil {
		err = view.ctx.Err()
	}
	if result.conn != nil && err != nil {
		result.conn.Close()
		result.conn, result.err, result.stage = nil, err, trace.StageConnect
	}
	if result.dnsName != "" {
		trace.From(ctx).SetDNSServer(result.dnsName)
	}
	trace.From(ctx).Dial(address, result.dns, result.connect, result.stage)
	return result.conn, result.err
}

func dialFamilies(ctx context.Context, network, host string, port uint16, lookup func(context.Context, string) ([]netip.Addr, error), dial socketDial, guard Guard) dialResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := time.Now()
	v4Started := make(chan time.Time, 1)
	v4Done := make(chan struct{})
	results := make(chan dialResult)
	var firstConnect atomic.Int64
	attempt := func(family string, primary bool) {
		if primary {
			defer close(v4Done)
		}
		addrs, err := lookup(ctx, family)
		dnsTime := time.Since(start)
		result := dialResult{err: err, dns: dnsTime, stage: trace.StageDNS}
		if err == nil && len(addrs) == 0 {
			result.err = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
		}
		if len(addrs) > 0 && ctx.Err() == nil {
			if primary {
				v4Started <- time.Now()
			} else {
				waitForIPv4(ctx, v4Started, v4Done)
			}
			if ctx.Err() == nil {
				firstConnect.CompareAndSwap(0, int64(time.Since(start)))
				result = dialAddresses(ctx, network, port, addrs, dial, guard)
				result.dns = dnsTime
			} else {
				result.err = ctx.Err()
			}
		}
		select {
		case results <- result:
		case <-ctx.Done():
			if result.conn != nil {
				result.conn.Close()
			}
		}
	}
	go attempt("ip4", true)
	go attempt("ip6", false)
	var failures dialResult
	failures.stage = trace.StageDNS
	for range 2 {
		select {
		case result := <-results:
			if result.conn != nil || result.guardRejected {
				return result
			}
			if result.stage == trace.StageConnect && failures.stage == trace.StageDNS {
				failures = dialResult{stage: trace.StageConnect}
			}
			if result.stage == failures.stage {
				failures.err = errors.Join(failures.err, result.err)
				failures.dns = max(failures.dns, result.dns)
				failures.connect = max(failures.connect, result.connect)
			}
		case <-ctx.Done():
			failures.err = ctx.Err()
			if first := time.Duration(firstConnect.Load()); first != 0 {
				failures.stage = trace.StageConnect
				failures.dns = first
				failures.connect = time.Since(start) - first
			} else {
				failures.dns = time.Since(start)
			}
			return failures
		}
	}
	return failures
}

func waitForIPv4(ctx context.Context, started <-chan time.Time, done <-chan struct{}) {
	timer := time.NewTimer(familyResolutionDelay)
	defer timer.Stop()
	select {
	case first := <-started:
		timer.Reset(time.Until(first.Add(familyFallbackDelay)))
		select {
		case <-timer.C:
		case <-done:
		case <-ctx.Done():
		}
	case <-timer.C:
	case <-done:
	case <-ctx.Done():
	}
}

func dialAddresses(ctx context.Context, network string, port uint16, addrs []netip.Addr, dial socketDial, guard Guard) dialResult {
	start := time.Now()
	result := dialResult{stage: trace.StageConnect}
	for i, addr := range addrs {
		if err := ctx.Err(); err != nil {
			result.err = err
			break
		}
		target := netip.AddrPortFrom(addr, port)
		if guard != nil {
			if err := guard(target); err != nil {
				result.err, result.guardRejected = err, true
				break
			}
		}
		attempt := ctx
		var cancel context.CancelFunc
		if i < len(addrs)-1 {
			attempt, cancel = context.WithTimeout(ctx, addressAttemptTimeout)
		}
		conn, err := dial(attempt, network, target.String())
		if cancel != nil {
			cancel()
		}
		if err == nil {
			result.conn, result.err, result.stage = conn, nil, ""
			break
		}
		result.err = errors.Join(result.err, err)
	}
	result.connect = time.Since(start)
	return result
}
