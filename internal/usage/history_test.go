package usage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryAccumulatesAcrossRestartsAndDays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	history, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	day1 := time.Date(2026, 11, 6, 23, 0, 0, 0, time.Local)
	history.Record(map[string][2]uint64{"hk": {100, 1000}}, day1)
	history.Record(map[string][2]uint64{"hk": {150, 1600}}, day1.Add(30*time.Minute))
	// Counters restart from zero after the core restarts.
	history.Record(map[string][2]uint64{"hk": {10, 20}, "DIRECT": {5, 5}}, day1.Add(2*time.Hour))
	if err := history.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	days := reopened.Days(0)
	if len(days) != 2 || days[0].Date != "2026-11-06" || days[1].Date != "2026-11-07" {
		t.Fatalf("unexpected days: %+v", days)
	}
	if got := days[0].Outbounds["hk"]; got.Sent != 150 || got.Recv != 1600 {
		t.Fatalf("day 1 hk = %+v", got)
	}
	if got := days[1].Outbounds["hk"]; got.Sent != 10 || got.Recv != 20 {
		t.Fatalf("day 2 hk = %+v", got)
	}
}

func TestHistoryDropsOldDays(t *testing.T) {
	history, _ := Open("")
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.Local)
	history.Record(map[string][2]uint64{"a": {1, 1}}, now.AddDate(0, 0, -200))
	history.Record(map[string][2]uint64{"a": {2, 2}}, now)
	if days := history.Days(0); len(days) != 1 || days[0].Date != "2026-11-07" {
		t.Fatalf("old day kept: %+v", days)
	}
}
