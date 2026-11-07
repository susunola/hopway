package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

func TestConfiguredDialDeadline(t *testing.T) {
	config := Default()
	config.Mode, config.Selected = "global", "slow"
	config.Performance = PerformanceConfig{DialTimeoutMS: 250}
	config.Nodes = []outbound.Node{{Name: "slow", Type: "socks5", Server: "127.0.0.1:1"}}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.dialers["slow"] = backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 250*time.Millisecond {
			t.Error("dial did not receive the configured upper bound")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	started := time.Now()
	_, err = core.Dial(context.Background(), "test", "example.test:443")
	if elapsed := time.Since(started); !errors.Is(err, context.DeadlineExceeded) || elapsed < 220*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("250 ms deadline: elapsed %s, error %v", elapsed, err)
	}
	config.Performance.FailoverTimeoutMS = 250
	if err := Validate(config, backend.Native{}); err == nil {
		t.Fatal("accepted a failover deadline that leaves no time for the next outbound")
	}
}

func TestConfiguredProbeTimeoutAndConcurrency(t *testing.T) {
	var active, peak atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); count > old && !peak.CompareAndSwap(old, count); old = peak.Load() {
		}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer target.Close()
	config := Default()
	config.Health = &Health{URL: target.URL}
	config.Performance = PerformanceConfig{ProbeTimeoutMS: 1000, ProbeConcurrency: 2}
	config.Nodes = []outbound.Node{
		{Name: "a", Type: "socks5", Server: "127.0.0.1:1"},
		{Name: "b", Type: "socks5", Server: "127.0.0.1:2"},
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for _, node := range config.Nodes {
		core.dialers[node.Name] = backend.DialerFunc(func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		})
	}
	started := time.Now()
	results := 0
	if err := core.ProbeResults(context.Background(), nil, func(result ProbeResult) error {
		if result.Failure == "" || !result.Inconclusive {
			t.Errorf("slow HTTP response should be an inconclusive timeout: %+v", result)
		}
		results++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); results != 2 || peak.Load() != 2 || elapsed < 950*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("probe limits: %d results, concurrency %d, elapsed %s", results, peak.Load(), elapsed)
	}
	config.Performance.ProbeConcurrency = 1
	serial, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer serial.Close()
	var serialActive atomic.Int32
	for _, node := range config.Nodes {
		serial.dialers[node.Name] = backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
			if serialActive.Add(1) != 1 {
				t.Error("serial batch started a second probe before the first finished")
			}
			defer serialActive.Add(-1)
			time.Sleep(20 * time.Millisecond)
			return nil, errors.New("fixture failure")
		})
	}
	if err := serial.ProbeResults(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
}
