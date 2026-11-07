package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

func TestSaturatedEndpointLeavesOtherEndpointsAvailable(t *testing.T) {
	config := Default()
	config.Nodes = []outbound.Node{
		{Name: "slow", Type: "socks5", Server: "localhost:9000"},
		{Name: "same endpoint", Type: "socks5", Server: "LOCALHOST:9000"},
		{Name: "backup", Type: "socks5", Server: "127.0.0.1:9001"},
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	entered := make(chan struct{}, endpointDialLimit)
	core.dialers["slow"] = backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	core.dialers["same endpoint"] = backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("dial unexpectedly started")
	})
	core.dialers["backup"] = backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
		client, peer := net.Pipe()
		peer.Close()
		return client, nil
	})
	for range endpointDialLimit {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = core.dialOnce(ctx, "slow", "example.test:443", &Record{})
		}()
	}
	for range endpointDialLimit {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("did not reach endpoint dial limit")
		}
	}
	if _, err := core.dialOnce(ctx, "same endpoint", "example.test:443", &Record{}); !errors.Is(err, errEndpointBusy) {
		t.Fatalf("alias did not share the endpoint limit: %v", err)
	}
	conn, err := core.dialOnce(ctx, "backup", "example.test:443", &Record{})
	if err != nil {
		t.Fatalf("saturation blocked an unrelated endpoint: %v", err)
	}
	conn.Close()
}

func TestNetworkChangeCancelsProbeWithoutSavingFailure(t *testing.T) {
	config := Default()
	config.Nodes = []outbound.Node{{Name: "old network", Type: "socks5", Server: "127.0.0.1:1"}}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan struct{}, 1)
	core.dialers["old network"] = backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	var published atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- core.ProbeResults(ctx, []string{"old network"}, func(ProbeResult) error {
			published.Add(1)
			return nil
		})
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	core.NetworkChanged()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("probe exited with %v, want cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("old probe was not canceled")
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.health["old network"] != nil || published.Load() != 0 {
		t.Fatal("stale probe was published or changed health on the new network")
	}
}

func TestAutomaticRoutesNeverDialDirectWhenCandidatesFail(t *testing.T) {
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	config := Default()
	config.Nodes = []outbound.Node{
		{Name: "primary", Type: "socks5", Server: "127.0.0.1:1"},
		{Name: "backup", Type: "socks5", Server: "127.0.0.1:2"},
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var attempts atomic.Int32
	for _, node := range config.Nodes {
		core.dialers[node.Name] = backend.DialerFunc(func(ctx context.Context, address string) (net.Conn, error) {
			if address == destination.Addr().String() {
				attempts.Add(1)
			}
			return nil, errors.New("fixture outbound offline")
		})
	}
	if err := core.SetPolicy(Policy{Mode: "auto", Selected: "DIRECT", Auto: &AutoConfig{
		Region: "HK", Groups: []AutoGroup{{Name: "First", Nodes: []string{"primary"}}, {Name: "Second", Nodes: []string{"backup"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := core.Dial(ctx, "fixture", destination.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("failed automatic routes unexpectedly fell back to a direct connection")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("tried %d candidate routes, want 2", got)
	}
}
