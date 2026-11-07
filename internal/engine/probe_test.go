package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

func TestProbeFallbackAndSharedOutagePreserveHealth(t *testing.T) {
	var primaryHits, fallbackHits atomic.Int32
	var fallbackStatus atomic.Int32
	fallbackStatus.Store(http.StatusNoContent)
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackHits.Add(1)
		w.WriteHeader(int(fallbackStatus.Load()))
	}))
	defer fallback.Close()
	config := Default()
	config.Health = &Health{URL: primary.URL, FallbackURL: strings.Replace(fallback.URL, "127.0.0.1", "localhost", 1)}
	config.Nodes = []outbound.Node{
		{Name: "one", Type: "socks5", Server: "127.0.0.1:1"},
		{Name: "two", Type: "socks5", Server: "127.0.0.1:2"},
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var offline atomic.Bool
	for _, node := range config.Nodes {
		core.dialers[node.Name] = backend.DialerFunc(func(ctx context.Context, target string) (net.Conn, error) {
			if offline.Load() {
				return nil, os.ErrDeadlineExceeded
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		})
	}
	run := func() []ProbeResult {
		t.Helper()
		var results []ProbeResult
		if err := core.ProbeResults(context.Background(), nil, func(result ProbeResult) error {
			results = append(results, result)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(results) != len(config.Nodes) {
			t.Fatalf("got %d results, want %d", len(results), len(config.Nodes))
		}
		return results
	}
	for _, result := range run() {
		if result.Failure != "" || result.Inconclusive || result.Milliseconds < 1 || result.Target != "localhost" || result.CheckedAt == 0 {
			t.Fatalf("successful fallback result: %+v", result)
		}
	}
	if primaryHits.Load() != 2 || fallbackHits.Load() != 2 {
		t.Fatalf("requests = primary %d, fallback %d", primaryHits.Load(), fallbackHits.Load())
	}
	lastGood := core.health["one"].checked
	fallbackStatus.Store(http.StatusBadGateway)
	for _, result := range run() {
		if !result.Inconclusive || result.Failure == "" {
			t.Fatalf("unavailable test sites were reported as a node failure: %+v", result)
		}
	}
	offline.Store(true)
	for _, result := range run() {
		if !result.Inconclusive {
			t.Fatalf("shared dial outage was reported as a node failure: %+v", result)
		}
	}
	if h := core.health["one"]; !h.alive || h.checked != lastGood {
		t.Fatalf("inconclusive probes replaced last good health: %+v", h)
	}
}

func TestProbeBatchReturnsFastSlowAndTimedOutNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := Default()
	config.Health = &Health{URL: server.URL}
	for _, name := range []string{"fast", "slow", "timeout"} {
		config.Nodes = append(config.Nodes, outbound.Node{Name: name, Type: "socks5", Server: "127.0.0.1:1"})
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.dialers["fast"] = backend.DialerFunc(func(ctx context.Context, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	})
	core.dialers["slow"] = backend.DialerFunc(func(ctx context.Context, target string) (net.Conn, error) {
		time.Sleep(40 * time.Millisecond)
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	})
	core.dialers["timeout"] = backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
		return nil, os.ErrDeadlineExceeded
	})
	results := make(map[string]ProbeResult)
	if err := core.ProbeResults(context.Background(), nil, func(result ProbeResult) error {
		if _, duplicate := results[result.Name]; duplicate {
			return errors.New("duplicate result")
		}
		results[result.Name] = result
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || results["fast"].Milliseconds < 1 || results["slow"].Milliseconds < 40 ||
		results["timeout"].Inconclusive || results["timeout"].Failure != os.ErrDeadlineExceeded.Error() {
		t.Fatalf("batch lost a result or misclassified the timed-out node: %+v", results)
	}
}

func TestCancelLargeProbeBatchReleasesInFlightDials(t *testing.T) {
	config := Default()
	for n := range 1000 {
		config.Nodes = append(config.Nodes, outbound.Node{Name: fmt.Sprintf("node-%d", n), Type: "socks5", Server: "127.0.0.1:1"})
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	started, exited := make(chan struct{}, len(config.Nodes)), make(chan struct{}, len(config.Nodes))
	for _, node := range config.Nodes {
		core.dialers[node.Name] = backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
			started <- struct{}{}
			<-ctx.Done()
			exited <- struct{}{}
			return nil, ctx.Err()
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batch := make(chan error, 1)
	go func() { batch <- core.ProbeResults(ctx, nil, nil) }()
	ready := time.NewTimer(3 * time.Second)
	defer ready.Stop()
	for range probeParallel {
		select {
		case <-started:
		case <-ready.C:
			t.Fatal("probe workers did not start")
		}
	}
	stoppedAt := time.Now()
	cancel()
	released := time.NewTimer(time.Second)
	defer released.Stop()
	for range probeParallel {
		select {
		case <-exited:
		case <-released.C:
			t.Fatal("a probe dial continued after its batch was canceled")
		}
	}
	select {
	case err := <-batch:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("batch completed with %v, want cancellation", err)
		}
		t.Logf("released %d dials and canceled 1,000-node batch in %s", probeParallel, time.Since(stoppedAt))
	case <-released.C:
		t.Fatal("probe batch did not stop after cancellation")
	}
}
