package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type trafficCount struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

type trafficHistory struct {
	Since string                             `json:"since"`
	Days  map[string]map[string]trafficCount `json:"days"`
}

type TrafficLedger struct {
	flushMu sync.Mutex
	mu      sync.Mutex
	path    string
	lock    *os.File
	history trafficHistory
	dirty   bool
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
	ledger := &TrafficLedger{path: path, lock: lock}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		ledger.history.Since = time.Now().Format("2006-01-02")
		ledger.dirty = true
	case err == nil:
		err = json.Unmarshal(data, &ledger.history)
		if err == nil && ledger.history.Since == "" {
			err = errors.New("traffic history has no start date")
		}
		if err != nil {
			lock.Close()
			return nil, fmt.Errorf("read traffic history: %w", err)
		}
	default:
		lock.Close()
		return nil, err
	}
	if ledger.history.Days == nil {
		ledger.history.Days = make(map[string]map[string]trafficCount)
	}
	return ledger, nil
}

func (ledger *TrafficLedger) add(now time.Time, node string, upload, download uint64) {
	if ledger == nil || (upload == 0 && download == 0) {
		return
	}
	day := now.Format("2006-01-02")
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.closed {
		return
	}
	nodes := ledger.history.Days[day]
	if nodes == nil {
		nodes = make(map[string]trafficCount)
		ledger.history.Days[day] = nodes
	}
	count := nodes[node]
	count.Upload += upload
	count.Download += download
	nodes[node] = count
	ledger.dirty = true
}

func (ledger *TrafficLedger) Flush() error {
	ledger.flushMu.Lock()
	defer ledger.flushMu.Unlock()
	ledger.mu.Lock()
	if !ledger.dirty {
		ledger.mu.Unlock()
		return nil
	}
	cutoff := time.Now().AddDate(0, 0, -89).Format("2006-01-02")
	for day := range ledger.history.Days {
		if day < cutoff {
			delete(ledger.history.Days, day)
		}
	}
	data, err := json.Marshal(ledger.history)
	if err == nil {
		ledger.dirty = false
	}
	ledger.mu.Unlock()
	if err != nil {
		return err
	}
	if err := ledger.write(data); err != nil {
		ledger.mu.Lock()
		ledger.dirty = true
		ledger.mu.Unlock()
		return err
	}
	return nil
}

func (ledger *TrafficLedger) write(data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(ledger.path), ".traffic-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), ledger.path)
}

func (ledger *TrafficLedger) Close() error {
	ledger.mu.Lock()
	ledger.closed = true
	ledger.mu.Unlock()
	return errors.Join(ledger.Flush(), ledger.lock.Close())
}

// SetTrafficLedger is called before opening the proxy listeners to clients.
func (engine *Engine) SetTrafficLedger(ledger *TrafficLedger) {
	engine.traffic = ledger
}
