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

type socketDial func(context.Context, string, string) (net.Conn, error)

type dialResult struct {
	conn          net.Conn
	err           error
	dns           time.Duration
	connect       time.Duration
	stage         string
	guardRejected bool
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(view.ctx, cancel)
	defer stop()
	var result dialResult
	if ip, err := netip.ParseAddr(host); err == nil {
		result = dialAddresses(ctx, network, port, []netip.Addr{ip.Unmap()}, dialer.DialContext, guard)
	} else {
		result = dialFamilies(ctx, network, host, port, func(ctx context.Context, family string) ([]netip.Addr, error) {
			return Resolver.lookupNetwork(ctx, view, family, host)
		}, dialer.DialContext, guard)
	}
	err = ctx.Err()
	if err == nil {
		err = view.ctx.Err()
	}
	if result.conn != nil && err != nil {
		result.conn.Close()
		result.conn, result.err, result.stage = nil, err, trace.StageConnect
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
