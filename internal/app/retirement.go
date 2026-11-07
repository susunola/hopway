package app

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"mac-proxy/internal/engine"
)

type RetirementStatus struct {
	Pending int64  `json:"pending"`
	Forced  uint64 `json:"forced"`
	Slow    uint64 `json:"slow"`
}

type retirement struct {
	pending atomic.Int64
	forced  atomic.Uint64
	slow    atomic.Uint64

	drainLimit time.Duration
	closeLimit time.Duration
}

func (r *retirement) status() RetirementStatus {
	return RetirementStatus{Pending: r.pending.Load(), Forced: r.forced.Load(), Slow: r.slow.Load()}
}

func (r *retirement) retire(ctx context.Context, old *engine.Engine) {
	drainLimit, closeLimit := r.drainLimit, r.closeLimit
	if drainLimit == 0 {
		drainLimit = 10 * time.Minute
	}
	if closeLimit == 0 {
		closeLimit = 2 * time.Second
	}
	if remaining := drain(ctx, old, drainLimit); remaining > 0 {
		r.forced.Add(1)
		log.Printf("retiring engine: drain deadline reached with %d active connections", remaining)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.pending.Add(-1)
		if err := old.Close(); err != nil {
			log.Print("retiring engine: backend close returned an error")
		}
	}()
	deadline := time.NewTimer(closeLimit)
	defer deadline.Stop()
	select {
	case <-done:
	case <-deadline.C:
		r.slow.Add(1)
		log.Print("retiring engine: backend cleanup exceeded its wait limit")
	}
}

func drain(ctx context.Context, old *engine.Engine, limit time.Duration) int {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for old.Active() > 0 {
		select {
		case <-ctx.Done():
			return 0
		case <-deadline.C:
			return old.Active()
		case <-ticker.C:
		}
	}
	return 0
}
