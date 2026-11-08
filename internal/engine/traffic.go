package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	trafficDate              = "2006-01-02"
	trafficCheckpointBatches = 128
	trafficCheckpointBytes   = 4 << 20
)

type trafficCount struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

func addTrafficCount(a, b trafficCount) trafficCount {
	add := func(x, y uint64) uint64 {
		if y > math.MaxUint64-x {
			return math.MaxUint64
		}
		return x + y
	}
	return trafficCount{Upload: add(a.Upload, b.Upload), Download: add(a.Download, b.Download)}
}

type trafficDays map[string]map[string]trafficCount

type trafficHistory struct {
	Since   string      `json:"since"`
	Days    trafficDays `json:"days"`
	Through uint64      `json:"through,omitempty"`
}

// A batch carries new absolute totals only for the changed day/node pairs.
// A later record for a pair also restores its total if an earlier one is lost.
type trafficBatch struct {
	Since    string      `json:"since"`
	Sequence uint64      `json:"sequence"`
	Days     trafficDays `json:"days"`
}

type TrafficLedger struct {
	flushMu   sync.Mutex // protects the committed history, journal and profile lock
	path      string
	lock      *os.File
	history   trafficHistory
	records   int
	bytes     int64
	recovered bool

	mu      sync.Mutex // never held during I/O
	pending trafficDays
	session trafficCount
	closed  bool
}

func OpenTrafficLedger(path string) (*TrafficLedger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("traffic history is in use: %w", err)
	}
	ledger := &TrafficLedger{path: path, lock: lock, pending: make(trafficDays)}
	if err := ledger.load(); err != nil {
		lock.Close()
		return nil, fmt.Errorf("read traffic history: %w", err)
	}
	return ledger, nil
}

func (ledger *TrafficLedger) Recovered() bool { return ledger.recovered }

func (ledger *TrafficLedger) journal() string { return ledger.path + ".journal" }

func trafficSequence(name string) (uint64, bool) {
	if len(name) != 25 || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	number := name[:20]
	sequence, err := strconv.ParseUint(number, 10, 64)
	return sequence, err == nil && sequence != 0 && fmt.Sprintf("%020d", sequence) == number
}

func (ledger *TrafficLedger) load() error {
	data, err := os.ReadFile(ledger.path)
	if err == nil {
		var snapshot trafficHistory
		if json.Unmarshal(data, &snapshot) == nil && validTrafficDate(snapshot.Since) {
			ledger.history = snapshot
		} else if err := ledger.quarantine(ledger.path); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if ledger.history.Days == nil {
		ledger.history.Days = make(trafficDays)
	}

	records, err := os.ReadDir(ledger.journal()) // names are sorted by sequence
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, record := range records {
		sequence, valid := trafficSequence(record.Name())
		if !valid || !record.Type().IsRegular() {
			continue
		}
		path := filepath.Join(ledger.journal(), record.Name())
		ledger.records++
		if sequence <= ledger.history.Through {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var batch trafficBatch
		if json.Unmarshal(data, &batch) != nil || batch.Sequence != sequence || !validTrafficDate(batch.Since) || batch.Days == nil {
			if err := ledger.quarantine(path); err != nil {
				return err
			}
			ledger.records--
			continue
		}
		ledger.apply(batch)
		ledger.bytes += int64(len(data))
	}
	if ledger.history.Since == "" {
		ledger.history.Since = time.Now().Format(trafficDate)
	}
	ledger.prune()
	return nil
}

func validTrafficDate(date string) bool {
	_, err := time.Parse(trafficDate, date)
	return err == nil
}

func (ledger *TrafficLedger) quarantine(path string) error {
	if err := os.Rename(path, path+".corrupt-"+strconv.FormatInt(time.Now().UnixNano(), 10)); err != nil {
		return err
	}
	ledger.recovered = true
	return nil
}

func (ledger *TrafficLedger) apply(batch trafficBatch) {
	if ledger.history.Since == "" {
		ledger.history.Since = batch.Since
	}
	for day, nodes := range batch.Days {
		current := ledger.history.Days[day]
		if current == nil {
			current = make(map[string]trafficCount, len(nodes))
			ledger.history.Days[day] = current
		}
		for node, count := range nodes {
			current[node] = count
		}
	}
	ledger.history.Through = batch.Sequence
}

func (ledger *TrafficLedger) prune() {
	cutoff := time.Now().AddDate(0, 0, -89).Format(trafficDate)
	for day := range ledger.history.Days {
		if day < cutoff {
			delete(ledger.history.Days, day)
		}
	}
}

func (ledger *TrafficLedger) add(now time.Time, node string, upload, download uint64) {
	if ledger == nil || (upload == 0 && download == 0) {
		return
	}
	day := now.Format(trafficDate)
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.closed {
		return
	}
	delta := trafficCount{Upload: upload, Download: download}
	ledger.session = addTrafficCount(ledger.session, delta)
	nodes := ledger.pending[day]
	if nodes == nil {
		nodes = make(map[string]trafficCount)
		ledger.pending[day] = nodes
	}
	nodes[node] = addTrafficCount(nodes[node], delta)
}

// sessionTotals excludes persisted traffic. The same ledger stays attached
// to current and retiring engines across configuration reloads.
func (ledger *TrafficLedger) sessionTotals() *trafficCount {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	totals := ledger.session
	ledger.mu.Unlock()
	return &totals
}

func (ledger *TrafficLedger) Flush() error {
	ledger.flushMu.Lock()
	defer ledger.flushMu.Unlock()
	if ledger.lock == nil {
		return nil
	}
	return ledger.flush()
}

func (ledger *TrafficLedger) flush() error {
	ledger.mu.Lock()
	pending := ledger.pending
	if len(pending) != 0 {
		ledger.pending = make(trafficDays)
	}
	ledger.mu.Unlock()
	if len(pending) != 0 {
		if err := ledger.commit(pending); err != nil {
			ledger.mu.Lock()
			for day, nodes := range pending {
				next := ledger.pending[day]
				if next == nil {
					ledger.pending[day] = nodes
					continue
				}
				for node, count := range nodes {
					next[node] = addTrafficCount(next[node], count)
				}
			}
			ledger.mu.Unlock()
			return err
		}
	}
	if ledger.records >= trafficCheckpointBatches || ledger.bytes >= trafficCheckpointBytes {
		return ledger.checkpoint()
	}
	return nil
}

func (ledger *TrafficLedger) commit(pending trafficDays) error {
	if ledger.history.Through == math.MaxUint64 {
		return errors.New("traffic sequence exhausted")
	}
	batch := trafficBatch{
		Since: ledger.history.Since, Sequence: ledger.history.Through + 1,
		Days: make(trafficDays, len(pending)),
	}
	for day, nodes := range pending {
		totals := make(map[string]trafficCount, len(nodes))
		for node, delta := range nodes {
			totals[node] = addTrafficCount(ledger.history.Days[day][node], delta)
		}
		batch.Days[day] = totals
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	journal := ledger.journal()
	if err := os.Mkdir(journal, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if ledger.records == 0 {
		if err := syncTrafficDirectory(filepath.Dir(ledger.path)); err != nil {
			return err
		}
	}
	path := filepath.Join(journal, fmt.Sprintf("%020d.json", batch.Sequence))
	if err := WriteAtomic(path, data); err != nil {
		return err
	}
	if err := syncTrafficDirectory(journal); err != nil {
		// A retry uses the same sequence and replaces its absolute totals.
		return err
	}
	ledger.apply(batch)
	ledger.records++
	ledger.bytes += int64(len(data))
	return nil
}

func (ledger *TrafficLedger) checkpoint() error {
	ledger.prune()
	data, err := json.Marshal(ledger.history)
	if err != nil {
		return err
	}
	if err := WriteAtomic(ledger.path, data); err != nil {
		return err
	}
	if err := syncTrafficDirectory(filepath.Dir(ledger.path)); err != nil {
		return err
	}
	entries, err := os.ReadDir(ledger.journal())
	if err != nil {
		return err
	}
	var cleanupErr error
	for _, entry := range entries {
		if sequence, valid := trafficSequence(entry.Name()); valid && sequence <= ledger.history.Through && entry.Type().IsRegular() {
			cleanupErr = errors.Join(cleanupErr, os.Remove(filepath.Join(ledger.journal(), entry.Name())))
		}
	}
	if cleanupErr == nil {
		ledger.records, ledger.bytes = 0, 0
	}
	return cleanupErr
}

func syncTrafficDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (ledger *TrafficLedger) Close() error {
	ledger.flushMu.Lock()
	defer ledger.flushMu.Unlock()
	if ledger.lock == nil {
		return nil
	}
	ledger.mu.Lock()
	ledger.closed = true
	ledger.mu.Unlock()
	err := ledger.flush()
	if err == nil && ledger.records != 0 {
		err = ledger.checkpoint()
	}
	err = errors.Join(err, ledger.lock.Close())
	ledger.lock = nil
	return err
}

// SetTrafficLedger is called before opening the proxy listeners to clients.
func (engine *Engine) SetTrafficLedger(ledger *TrafficLedger) {
	engine.traffic = ledger
}
