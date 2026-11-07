package netmon

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWatchReportsNetworkChanges(t *testing.T) {
	var mu sync.Mutex
	current := "en0=192.168.1.5"
	var events []Event
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Watch(ctx, 10*time.Millisecond, func() string { mu.Lock(); defer mu.Unlock(); return current },
			func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() })
		close(done)
	}()
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	current = "en0=10.0.0.7"
	mu.Unlock()
	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done
	if len(events) != 1 || events[0].Kind != "network" {
		t.Fatalf("events %+v", events)
	}
	if Fingerprint() == "" {
		t.Log("no non-loopback interfaces in this environment")
	}
}
