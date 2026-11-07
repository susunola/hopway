package lifetime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRepeatedLifetimeShutdownJoinsTimerWorkers(t *testing.T) {
	var workers atomic.Int64
	for range 30 {
		scope := New()
		for range 3 {
			if !scope.Start(context.Background(), func(ctx context.Context) {
				workers.Add(1)
				defer workers.Add(-1)
				timer := time.NewTicker(time.Hour)
				defer timer.Stop()
				select {
				case <-ctx.Done():
				case <-timer.C:
				}
			}) {
				t.Fatal("worker was refused before shutdown")
			}
		}
		scope.Stop()
		scope.Wait()
		if active := workers.Load(); active != 0 || scope.Start(context.Background(), func(context.Context) {}) {
			t.Fatalf("stopped owner still has work: %d", active)
		}
	}
}
