package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/socks5"
	"mac-proxy/internal/trace"
)

func TestEndpointCooldownRecoversThroughLiveProbe(t *testing.T) {
	port, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := port.Addr().(*net.TCPAddr)
	port.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	cfg := Default()
	cfg.Mode, cfg.Selected = "global", "down"
	cfg.Health = &Health{URL: target.URL}
	cfg.Nodes = []outbound.Node{{Name: "down", Type: "socks5", Server: addr.String()}}
	core, err := New(cfg, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var offset atomic.Int64
	b := &core.budget.dials
	start := time.Now()
	b.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for range endpointFailureThreshold {
		if _, err := core.Dial(ctx, "fixture", "example.test:443"); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("expected a real refused socket before cooldown: %v", err)
		}
	}
	recovered, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := recovered.AcceptTCP()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				socks5.Handle(conn, func(ctx context.Context, _, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
				})
			}()
		}
	}()
	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			if conn, err := core.Dial(ctx, "fixture", "example.test:443"); !errors.Is(err, backend.ErrEndpointCooling) {
				if conn != nil {
					conn.Close()
				}
				t.Errorf("cooldown did not reject the retry: %v", err)
			}
		})
	}
	wait.Wait()
	if accepted.Load() != 0 {
		t.Fatalf("cooldown sent %d requests to the recovering endpoint", accepted.Load())
	}
	status := core.Status().Nodes[2]
	if status.Alive == nil || *status.Alive || status.FailureCode != "connection-refused" {
		t.Fatalf("cooldown overwrote the actual failure: %+v", status)
	}
	offset.Store(int64(endpointCooldown + time.Millisecond))
	var result ProbeResult
	if err := core.ProbeResults(ctx, []string{"down"}, func(next ProbeResult) error { result = next; return nil }); err != nil {
		t.Fatal(err)
	}
	if result.Milliseconds < 1 || result.Failure != "" || accepted.Load() != 1 {
		t.Fatalf("first post-cooldown probe did not recover the endpoint: %+v, connections %d", result, accepted.Load())
	}
	status = core.Status().Nodes[2]
	if status.Alive == nil || !*status.Alive || status.HealthAt != result.CheckedAt || status.ProbeTarget != result.Target {
		t.Fatalf("probe and runtime recovery disagree: %+v, %+v", status, result)
	}
}

func TestEndpointCircuitAdmitsOneRecoveryAndIgnoresOldFailures(t *testing.T) {
	b := &NewResourceBudget().dials
	now := time.Now()
	b.now = func() time.Time { return now }
	state := &endpointCircuit{}
	old, _ := b.startAttempt(state, 0)
	for range endpointFailureThreshold {
		finish, err := b.startAttempt(state, 0)
		if err != nil {
			t.Fatal(err)
		}
		finish(trace.StageConnect, syscall.ECONNREFUSED)
	}
	now = now.Add(endpointCooldown)
	trial, err := b.startAttempt(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.startAttempt(state, 0); !errors.Is(err, backend.ErrEndpointCooling) {
		t.Fatalf("second recovery attempt was allowed: %v", err)
	}
	trial("", nil)
	old(trace.StageConnect, syscall.ECONNREFUSED)
	if state.failures != 0 {
		t.Fatal("a late failure changed recovered endpoint health")
	}
	previous, _ := b.startAttempt(state, 0)
	b.changeNetwork()
	next, err := b.startAttempt(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	previous(trace.StageDNS, &net.DNSError{IsTimeout: true})
	next("", nil)
	if state.failures != 0 {
		t.Fatal("old network altered new breaker")
	}
}
