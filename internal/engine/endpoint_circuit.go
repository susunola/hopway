package engine

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/trace"
)

const (
	endpointFailureThreshold = 3
	endpointCooldown         = 5 * time.Second
)

type endpointCircuit struct {
	epoch    uint64
	serial   uint64
	failures int
	until    time.Time
	trial    bool
}

func (engine *Engine) withEndpointGate(ctx context.Context, via string) context.Context {
	slot := engine.dialSlots[via]
	if slot == nil {
		return ctx
	}
	budget := &engine.budget.dials
	budget.mu.Lock()
	epoch := budget.networkEpoch
	budget.mu.Unlock()
	return backend.WithDialGate(ctx, func(network, address string) (func(string, error), error) {
		if endpointKey(address) != slot.key {
			return nil, nil
		}
		state := &slot.tcp
		if strings.HasPrefix(network, "udp") {
			state = &slot.udp
		}
		return budget.startAttempt(state, epoch)
	})
}

func (b *endpointBudget) changeNetwork() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.networkEpoch++
}

func (b *endpointBudget) startAttempt(state *endpointCircuit, epoch uint64) (func(string, error), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.networkEpoch != epoch {
		return nil, context.Canceled
	}
	if state.epoch != epoch {
		*state = endpointCircuit{epoch: epoch}
	}
	if !state.until.IsZero() {
		if b.now().Before(state.until) || state.trial {
			return nil, backend.ErrEndpointCooling
		}
		state.trial = true
	}
	serial := state.serial
	return func(stage string, err error) {
		b.finishAttempt(state, epoch, serial, stage, err)
	}, nil
}

func (b *endpointBudget) finishAttempt(state *endpointCircuit, epoch, serial uint64, stage string, err error) {
	failed := failedEndpointSocket(stage, err)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.networkEpoch != epoch || state.serial != serial {
		return
	}
	if err == nil {
		if state.failures != 0 || state.trial {
			*state = endpointCircuit{epoch: epoch, serial: serial + 1}
		}
		return
	}
	if !failed {
		state.trial = false
		return
	}
	state.failures++
	if state.trial || state.failures >= endpointFailureThreshold {
		state.until = b.now().Add(endpointCooldown)
		state.serial++
		state.trial = false
	}
}

func failedEndpointSocket(stage string, err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.ENETUNREACH) {
		return false
	}
	if stage == trace.StageDNS {
		var dnsError *net.DNSError
		return errors.As(err, &dnsError) || errors.Is(err, context.DeadlineExceeded)
	}
	if stage != trace.StageConnect {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ETIMEDOUT) || errors.Is(err, context.DeadlineExceeded)
}
