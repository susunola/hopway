package engine

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

func TestEndpointBudgetAcrossReloadTCPUDPAndProbe(t *testing.T) {
	config := Default()
	config.Mode, config.Selected = "global", "alias"
	config.Nodes = []outbound.Node{
		{Name: "busy", Type: "socks5", Server: "localhost:9100"},
		{Name: "alias", Type: "socks5", Server: "LOCALHOST.:9100"},
		{Name: "other", Type: "socks5", Server: "127.0.0.1:9101"},
	}
	budget, err := NewResourceBudget(config.Resources)
	if err != nil {
		t.Fatal(err)
	}
	newCore := func() *Engine {
		t.Helper()
		core, err := NewWithResourceBudget(config, backend.Native{}, budget)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { core.Close() })
		return core
	}
	old, current := newCore(), newCore()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	started := make(chan string, endpointDialLimit)
	stall := func(ctx context.Context, via string) error {
		started <- via
		<-ctx.Done()
		return ctx.Err()
	}
	old.dialers["busy"] = backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		return nil, stall(ctx, "tcp")
	})
	current.dialers["alias"] = packetBudgetDialer{
		backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) { return nil, stall(ctx, "probe") }),
		func(ctx context.Context, _ string) (net.PacketConn, error) { return nil, stall(ctx, "udp") },
	}
	current.dialers["other"] = backend.DialerFunc(func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	})
	runtime.GC()
	var before, peak, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const packets = 4
	for range endpointDialLimit - endpointProbeLimit - packets {
		workers.Go(func() { _, _ = old.dialOnce(ctx, "busy", "target.test:443", &Record{}) })
	}
	for range packets {
		workers.Go(func() { _, _ = current.DialPacket(ctx, "fixture", "target.test:53") })
	}
	workers.Go(func() {
		names := make([]string, endpointProbeLimit)
		for i := range names {
			names[i] = "alias"
		}
		_ = current.ProbeResults(ctx, names, nil)
	})
	seen := map[string]int{}
	for range endpointDialLimit {
		select {
		case path := <-started:
			seen[path]++
		case <-ctx.Done():
			t.Fatalf("did not fill shared budget: %v", seen)
		}
	}
	slot := current.dialSlots["alias"]
	if slot != old.dialSlots["busy"] || seen["tcp"] != 56 || seen["udp"] != packets || seen["probe"] != endpointProbeLimit {
		t.Fatalf("paths did not share the endpoint: %v", seen)
	}
	runtime.ReadMemStats(&peak)
	old.Close() // closing a generation must not drop the held slots
	for range 1000 {
		if _, err := current.dialOnce(ctx, "alias", "target.test:443", &Record{}); !errors.Is(err, errEndpointBusy) {
			t.Fatalf("saturation allowed an extra opening: %v", err)
		}
	}
	conn, err := current.dialOnce(ctx, "other", "target.test:443", &Record{})
	if err != nil {
		t.Fatalf("unrelated endpoint was blocked: %v", err)
	}
	conn.Close()
	cancel()
	workers.Wait()
	if len(slot.opening) != 0 || len(slot.probing) != 0 || len(budget.dials.probeOpening) != 0 {
		t.Fatal("cancellation leaked budget slots")
	}
	current.Close()
	if len(budget.dials.entries) != 0 {
		t.Fatal("closing both generations leaked endpoint state")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("64 held openings, 1,000 refusals, then zero active openings; sampled heap %d → %d → %d bytes",
		before.HeapAlloc, peak.HeapAlloc, after.HeapAlloc)
}

func TestSaturatedEndpointProbeIsInconclusive(t *testing.T) {
	config := Default()
	config.Resources.EndpointDialLimit = 4
	config.Nodes = []outbound.Node{{Name: "busy", Type: "socks5", Server: "127.0.0.1:9200"}}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for range config.Resources.EndpointDialLimit {
		slot, err := core.acquireDialSlot("busy")
		if err != nil {
			t.Fatal(err)
		}
		defer core.budget.dials.finish(slot)
	}
	result := core.probe(context.Background(), "busy")
	if !result.Inconclusive || result.Failure != errEndpointBusy.Error() {
		t.Fatalf("local saturation was reported as a bad node: %+v", result)
	}
}
