package engine

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"mac-proxy/internal/backend"
)

func listenConnectionFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	stopped := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		<-stopped
		handlers.Wait()
	})
	go func() {
		defer close(stopped)
		for {
			peer, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Go(func() {
				defer peer.Close()
				io.Copy(peer, peer)
			})
		}
	}()
	return listener.Addr().String()
}

func TestConnectionFeedTransitionsAndExpiry(t *testing.T) {
	address := listenConnectionFixture(t)
	core, err := New(Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.recentTTL = 150 * time.Millisecond
	initial := core.Connections(nil)
	if !initial.Full || len(initial.Records) != 0 {
		t.Fatalf("initial feed: %+v", initial)
	}
	conn, err := core.Dial(context.Background(), "fixture", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	added := core.Connections(&initial.Cursor)
	if added.Full || len(added.Records) != 1 || added.Records[0].State != "active" {
		t.Fatalf("connection did not appear: %+v", added)
	}
	if idle := core.Connections(&added.Cursor); idle.Full || idle.Cursor != added.Cursor || len(idle.Records)+len(idle.Counters)+len(idle.Removed) != 0 {
		t.Fatalf("idle poll returned changes: %+v", idle)
	}
	const data = "payload"
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len(data))); err != nil {
		t.Fatal(err)
	}
	traffic := core.Connections(&added.Cursor)
	if traffic.Full || len(traffic.Counters) != 1 || len(traffic.Records) != 0 ||
		traffic.Counters[0].ID != added.Records[0].ID || traffic.Counters[0].Sent != uint64(len(data)) ||
		traffic.Counters[0].Received != uint64(len(data)) || traffic.Counters[0].FirstByteMs < 1 {
		t.Fatalf("traffic should contain only numeric fields: %+v", traffic)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed := core.Connections(&traffic.Cursor)
	if closed.Full || len(closed.Records) != 1 || closed.Records[0].State != "closed" || closed.Records[0].Sent != uint64(len(data)) {
		t.Fatalf("final record missing: %+v", closed)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		core.mu.Lock()
		idle := core.recent.entries == nil && core.recent.byID == nil && core.recentTimer == nil
		core.mu.Unlock()
		if idle {
			removed := core.Connections(&closed.Cursor)
			if removed.Full || len(removed.Removed) != 1 || removed.Removed[0] != added.Records[0].ID {
				t.Fatalf("expired connection was not removed: %+v", removed)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("idle connection records did not release their storage")
}

func TestConnectionFeedEvictionAndStaleCursor(t *testing.T) {
	core, err := New(Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	initial := core.Connections(nil)
	remember := func(id uint64) {
		core.remember(Record{ID: id, State: "failed"})
	}
	core.mu.Lock()
	for i := uint64(1); i <= recentConnectionLimit; i++ {
		remember(i)
	}
	core.mu.Unlock()
	full := core.Connections(nil)
	core.mu.Lock()
	remember(recentConnectionLimit + 1)
	core.mu.Unlock()
	edge := core.Connections(&full.Cursor)
	if edge.Full || len(edge.Removed) != 1 || edge.Removed[0] != 1 || len(edge.Records) != 1 || edge.Records[0].ID != recentConnectionLimit+1 {
		t.Fatalf("bounded history did not send both changes: %+v", edge)
	}
	core.mu.Lock()
	for i := uint64(recentConnectionLimit + 2); i <= connectionJournalSize+recentConnectionLimit; i++ {
		remember(i)
	}
	core.mu.Unlock()
	reset := core.Connections(&initial.Cursor)
	if !reset.Full || len(reset.Records) != recentConnectionLimit || reset.Records[len(reset.Records)-1].ID != connectionJournalSize+recentConnectionLimit {
		t.Fatalf("expired cursor did not reset to a bounded view: full=%t len=%d", reset.Full, len(reset.Records))
	}
}

func TestConnectionHistoryCanBeBoundedOrDisabled(t *testing.T) {
	config := Default()
	config.ConnectionHistory = ConnectionHistoryConfig{Limit: 2, RetentionMin: 1}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.mu.Lock()
	core.remember(Record{ID: 1})
	core.remember(Record{ID: 2})
	core.remember(Record{ID: 3})
	core.mu.Unlock()
	recent := core.Connections(nil).Records
	if core.recentTTL != time.Minute || len(recent) != 2 || recent[0].ID != 2 || recent[1].ID != 3 {
		t.Fatalf("unexpected history: %+v", recent)
	}

	config.ConnectionHistory.Disabled = true
	noHistory, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer noHistory.Close()
	conn, err := noHistory.Dial(context.Background(), "fixture", listenConnectionFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	active := noHistory.Connections(nil)
	if len(active.Records) != 1 {
		t.Fatalf("active connection missing: %+v", active)
	}
	conn.Close()
	closed := noHistory.Connections(&active.Cursor)
	if len(closed.Records) != 0 || len(closed.Removed) != 1 || closed.Removed[0] != active.Records[0].ID {
		t.Fatalf("closing must remove the row without retaining details: %+v", closed)
	}
}

func TestBurstReleasesConnectionTrackingStorage(t *testing.T) {
	address := listenConnectionFixture(t)
	core, err := New(Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.recentTTL = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var connections []net.Conn
	for range 520 {
		conn, err := core.Dial(ctx, "fixture", address)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	var peak, idle runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&peak)
	for _, conn := range connections {
		conn.Close()
	}
	connections = nil
	for ctx.Err() == nil {
		core.mu.Lock()
		released := core.recent.entries == nil && core.recent.byID == nil && len(core.live) == 0 && core.peakTCP <= 65
		core.mu.Unlock()
		if released {
			runtime.GC()
			runtime.ReadMemStats(&idle)
			t.Logf("520 loopback TCP connections: heap live bytes peak %d, after expiry and GC %d", peak.HeapAlloc, idle.HeapAlloc)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("idle engine did not release recent records and compact the live index")
}

func BenchmarkLargeConnectionStatus(b *testing.B) {
	for _, view := range []string{"legacy", "compact", "unchanged delta"} {
		b.Run(view, func(b *testing.B) {
			core := &Engine{livePackets: make(map[uint64]*trackedPacket)}
			for id := uint64(1); id <= 1024; id++ {
				core.livePackets[id] = &trackedPacket{record: Record{ID: id, Target: "fixture.test:443", State: "active"}}
			}
			cursor := core.Connections(nil).Cursor
			b.ReportAllocs()
			for b.Loop() {
				switch view {
				case "legacy":
					_ = core.Status()
				case "compact":
					_ = core.CompactStatus()
				default:
					_ = core.Connections(&cursor)
				}
			}
		})
	}
}
