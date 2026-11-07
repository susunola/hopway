// Package lifetime ties background and request work to a component's shutdown.
package lifetime

import (
	"context"
	"sync"
)

type Group struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	work   sync.WaitGroup
}

func New() *Group {
	ctx, cancel := context.WithCancel(context.Background())
	return &Group{ctx: ctx, cancel: cancel}
}

func (group *Group) Context() context.Context { return group.ctx }

// Enter combines the caller and owner lifetimes. Stop excludes new entries,
// so the owner can safely join work before releasing shared resources.
func (group *Group) Enter(caller context.Context) (context.Context, func(), bool) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.ctx.Err() != nil || caller.Err() != nil {
		return nil, nil, false
	}
	group.work.Add(1)
	ctx, cancel := context.WithCancel(caller)
	stop := context.AfterFunc(group.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
		group.work.Done()
	}, true
}

func (group *Group) Start(caller context.Context, run func(context.Context)) bool {
	ctx, done, ok := group.Enter(caller)
	if !ok {
		return false
	}
	go func() {
		defer done()
		run(ctx)
	}()
	return true
}

func (group *Group) Stop() {
	group.mu.Lock()
	defer group.mu.Unlock()
	group.cancel()
}

// Wait joins all previously accepted work. Call Stop before Wait.
func (group *Group) Wait() { group.work.Wait() }
