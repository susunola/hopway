package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTrafficFixture(t *testing.T, path string) *TrafficLedger {
	t.Helper()
	ledger, err := OpenTrafficLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ledger.Close(); err != nil {
			t.Error(err)
		}
	})
	return ledger
}

func abandonTrafficFixture(t *testing.T, ledger *TrafficLedger) {
	t.Helper()
	if err := ledger.lock.Close(); err != nil {
		t.Fatal(err)
	}
	ledger.lock = nil // only simulate loss of memory; the process test sends SIGKILL
}

func readTrafficFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTrafficLedgerIncrementalBatchAndReplay(t *testing.T) {
	now := time.Now()
	day, yesterday := now.Format(trafficDate), now.AddDate(0, 0, -1).Format(trafficDate)
	path := filepath.Join(t.TempDir(), "traffic-history.json")
	legacy, err := json.Marshal(trafficHistory{Since: yesterday, Days: trafficDays{
		yesterday: {"Proxy": {Upload: 11, Download: 13}},
		day:       {"DIRECT": {Upload: 20, Download: 40}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := openTrafficFixture(t, path)
	ledger.add(now, "DIRECT", 5, 7)
	if err := ledger.Flush(); err != nil {
		t.Fatal(err)
	}
	batchPath := filepath.Join(ledger.journal(), "00000000000000000001.json")
	first := readTrafficFixture(t, batchPath)
	var batch trafficBatch
	if err := json.Unmarshal(first, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Days) != 1 || len(batch.Days[day]) != 1 || batch.Days[day]["DIRECT"] != (trafficCount{25, 47}) {
		t.Fatalf("unexpected incremental batch: %s", first)
	}
	if !bytes.Equal(readTrafficFixture(t, path), legacy) {
		t.Fatal("a regular flush rewrote the legacy snapshot")
	}
	abandonTrafficFixture(t, ledger)
	ledger = openTrafficFixture(t, path)
	if ledger.history.Days[day]["DIRECT"] != (trafficCount{25, 47}) ||
		ledger.history.Days[yesterday]["Proxy"] != (trafficCount{11, 13}) ||
		*ledger.sessionTotals() != (trafficCount{}) {
		t.Fatalf("incorrect restart: %+v", ledger.history)
	}

	ledger.add(now, "DIRECT", 10, 20)
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	// A crash after replacing the checkpoint can leave old batches behind.
	if err := os.WriteFile(batchPath, first, 0o600); err != nil {
		t.Fatal(err)
	}
	ledger = openTrafficFixture(t, path)
	if ledger.history.Through != 2 || ledger.history.Days[day]["DIRECT"] != (trafficCount{35, 67}) {
		t.Fatalf("reapplied old batch: %+v", ledger.history)
	}
}

func TestTrafficLedgerRetriesWriteWithConcurrentAdds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-history.json")
	ledger := openTrafficFixture(t, path)
	now := time.Now()
	if err := os.WriteFile(ledger.journal(), []byte("blocking file"), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger.add(now, "DIRECT", 3, 5)
	if err := ledger.Flush(); err == nil {
		t.Fatal("a file at the journal path should block a write")
	}
	if err := os.Remove(ledger.journal()); err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for i := 0; i < 1000; i++ {
			ledger.add(now, "DIRECT", 1, 2)
		}
	}()
	for i := 0; i < 16; i++ {
		if err := ledger.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	group.Wait()
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded := openTrafficFixture(t, path)
	if got := reloaded.history.Days[now.Format(trafficDate)]["DIRECT"]; got != (trafficCount{1003, 2005}) {
		t.Fatalf("lost or double-counted recovered traffic: %+v", got)
	}
}

func TestTrafficLedgerIsolatesBrokenFilesAndRecoversOtherRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-history.json")
	ledger := openTrafficFixture(t, path)
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	for _, delta := range []struct {
		at    time.Time
		node  string
		count uint64
	}{{yesterday, "Proxy", 17}, {now, "DIRECT", 5}, {now, "DIRECT", 7}} {
		ledger.add(delta.at, delta.node, delta.count, 2*delta.count)
		if err := ledger.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	abandonTrafficFixture(t, ledger)
	badBatch := filepath.Join(ledger.journal(), "00000000000000000002.json")
	for _, damaged := range []string{path, badBatch} {
		if err := os.WriteFile(damaged, []byte("{broken"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ledger = openTrafficFixture(t, path)
	if !ledger.Recovered() || ledger.history.Days[now.Format(trafficDate)]["DIRECT"] != (trafficCount{12, 24}) ||
		ledger.history.Days[yesterday.Format(trafficDate)]["Proxy"] != (trafficCount{17, 34}) {
		t.Fatalf("valid records were not recovered: %+v", ledger.history)
	}
	for _, damaged := range []string{path, badBatch} {
		matches, err := filepath.Glob(damaged + ".corrupt-*")
		if err != nil || len(matches) != 1 || string(readTrafficFixture(t, matches[0])) != "{broken" {
			t.Fatalf("damaged file was not preserved: %v", err)
		}
	}
}

func TestTrafficLedgerCompactsAtBatchLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-history.json")
	ledger := openTrafficFixture(t, path)
	now := time.Now()
	for i := 0; i < trafficCheckpointBatches; i++ {
		ledger.add(now, "DIRECT", 1, 2)
		if err := ledger.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	records, err := os.ReadDir(ledger.journal())
	if err != nil || len(records) != 0 {
		t.Fatalf("journal did not compact: %d records, %v", len(records), err)
	}
	var snapshot trafficHistory
	if err := json.Unmarshal(readTrafficFixture(t, path), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Through != trafficCheckpointBatches ||
		snapshot.Days[now.Format(trafficDate)]["DIRECT"] != (trafficCount{trafficCheckpointBatches, 2 * trafficCheckpointBatches}) {
		t.Fatalf("wrong checkpoint: %+v", snapshot)
	}
}
