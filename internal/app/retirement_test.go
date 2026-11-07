package app

import (
	"context"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/sysproxy"
)

type retirementBackend struct {
	backend.Native
	block <-chan struct{}
}

func (b *retirementBackend) Open(nodes []outbound.Node, guard backend.Guard) (backend.Instance, error) {
	instance, err := b.Native.Open(nodes, guard)
	if err == nil && b.block != nil {
		instance = slowRetirement{Instance: instance, block: b.block}
		b.block = nil
	}
	return instance, err
}

type slowRetirement struct {
	backend.Instance
	block <-chan struct{}
}

func (s slowRetirement) Close() error {
	<-s.block
	return s.Instance.Close()
}

func TestRetirementForcesOldSocketAndBoundsBackendWait(t *testing.T) {
	blocked := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(blocked) }) }
	defer unblock()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "config.json"), filepath.Join(dir, "cache"), &retirementBackend{block: blocked})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.retirement.drainLimit, s.retirement.closeLimit = 40*time.Millisecond, 60*time.Millisecond
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	address := echo(t)
	old, err := s.Dial(ctx, "fixture", address)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("retired socket remained open")
	} else if active := s.retirement.forced.Load(); active != 1 {
		t.Fatalf("old socket was not closed by the retirement deadline: %v, %d forced", err, active)
	}
	newConn, err := s.Dial(ctx, "fixture", address)
	if err != nil {
		t.Fatal(err)
	}
	defer newConn.Close()
	newConn.SetDeadline(time.Now().Add(time.Second))
	if _, err := newConn.Write([]byte("new engine")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("new engine"))
	if _, err := io.ReadFull(newConn, reply); err != nil || string(reply) != "new engine" {
		t.Fatalf("new TCP route was interrupted: %s, %v", reply, err)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("shutdown waited for the stalled backend")
	}
	if status := s.Status().Retirement; status != (RetirementStatus{Pending: 1, Forced: 1, Slow: 1}) {
		t.Fatalf("missing retirement diagnostics: %+v", status)
	}
	unblock()
	for s.retirement.pending.Load() != 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if s.retirement.pending.Load() != 0 {
		t.Fatal("completed backend cleanup was still marked pending")
	}
}
