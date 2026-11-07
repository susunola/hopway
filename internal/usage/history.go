// Package usage keeps a per-day, per-outbound traffic history on disk so the
// UI can show usage across restarts.
package usage

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const keepDays = 120

// Bytes is traffic in one direction pair.
type Bytes struct {
	Sent uint64 `json:"sent"`
	Recv uint64 `json:"received"`
}

// Day is one local calendar day of traffic, keyed by outbound name.
type Day struct {
	Date      string           `json:"date"`
	Outbounds map[string]Bytes `json:"outbounds"`
}

type History struct {
	mu    sync.Mutex
	path  string
	days  map[string]map[string]Bytes
	last  map[string][2]uint64
	dirty bool
}

// Open loads the history at path. A missing file starts an empty history; a
// corrupt one is reported but still yields a usable empty history.
func Open(path string) (*History, error) {
	history := &History{path: path, days: make(map[string]map[string]Bytes), last: make(map[string][2]uint64)}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return history, nil
	}
	if err != nil {
		return history, err
	}
	var stored struct {
		Days []Day `json:"days"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return history, err
	}
	for _, day := range stored.Days {
		if day.Outbounds != nil {
			history.days[day.Date] = day.Outbounds
		}
	}
	return history, nil
}

// Record adds the traffic since the previous call. totals are cumulative
// counters per outbound; a counter that went backwards (core restart) counts
// from zero.
func (history *History) Record(totals map[string][2]uint64, now time.Time) {
	history.mu.Lock()
	defer history.mu.Unlock()
	date := now.Format(time.DateOnly)
	for name, total := range totals {
		previous := history.last[name]
		sent, recv := total[0]-previous[0], total[1]-previous[1]
		if total[0] < previous[0] || total[1] < previous[1] {
			sent, recv = total[0], total[1]
		}
		if sent == 0 && recv == 0 {
			continue
		}
		day := history.days[date]
		if day == nil {
			day = make(map[string]Bytes)
			history.days[date] = day
		}
		entry := day[name]
		entry.Sent += sent
		entry.Recv += recv
		day[name] = entry
		history.dirty = true
	}
	history.last = totals
	cutoff := now.AddDate(0, 0, -keepDays).Format(time.DateOnly)
	for date := range history.days {
		if date < cutoff {
			delete(history.days, date)
			history.dirty = true
		}
	}
}

// Days returns up to count most recent days, oldest first. count <= 0 returns all.
func (history *History) Days(count int) []Day {
	history.mu.Lock()
	defer history.mu.Unlock()
	days := make([]Day, 0, len(history.days))
	for date, outbounds := range history.days {
		copied := make(map[string]Bytes, len(outbounds))
		for name, bytes := range outbounds {
			copied[name] = bytes
		}
		days = append(days, Day{date, copied})
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Date < days[j].Date })
	if count > 0 && len(days) > count {
		days = days[len(days)-count:]
	}
	return days
}

// Save writes the history atomically when it changed since the last save.
func (history *History) Save() error {
	history.mu.Lock()
	dirty := history.dirty
	history.mu.Unlock()
	if !dirty || history.path == "" {
		return nil
	}
	data, err := json.Marshal(struct {
		Days []Day `json:"days"`
	}{history.Days(0)})
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(history.path, data); err != nil {
		return err
	}
	history.mu.Lock()
	history.dirty = false
	history.mu.Unlock()
	return nil
}

// WriteFileAtomic replaces path with data via a 0600 temp file and rename.
func WriteFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".hopway-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
