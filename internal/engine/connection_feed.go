package engine

import (
	"sort"
	"time"
)

const (
	connectionJournalSize = 4096
	recentConnectionLimit = 300
	recentConnectionTTL   = 15 * time.Minute
)

// Go maps retain buckets after deletion. Compact only after a large peak
// has subsided, and keep small indices for ordinary connection churn.
func shrinkConnectionIndex[T any](entries map[uint64]T, peak *int) map[uint64]T {
	if *peak < 512 || len(entries) > *peak/8 {
		return entries
	}
	compact := make(map[uint64]T, len(entries))
	for id, entry := range entries {
		compact[id] = entry
	}
	*peak = len(compact)
	return compact
}

type ConnectionCounters struct {
	ID          uint64 `json:"id"`
	Sent        uint64 `json:"sent"`
	Received    uint64 `json:"received"`
	FirstByteMs int64  `json:"firstByteMs,omitempty"`
}

type ConnectionDelta struct {
	Cursor   uint64               `json:"cursor"`
	Full     bool                 `json:"full,omitempty"`
	Records  []Record             `json:"records,omitempty"`
	Counters []ConnectionCounters `json:"counters,omitempty"`
	Removed  []uint64             `json:"removed,omitempty"`
}

type connectionEvent struct {
	id     uint64
	record bool
}

// Mutations are recorded under engine.mu. The journal is only allocated
// when a client opens the feed, and never stores a copy of a record.
type connectionJournal struct {
	events []connectionEvent
	head   uint64
}

func (journal *connectionJournal) mark(id uint64, record bool) {
	if len(journal.events) != 0 {
		journal.events[journal.head%uint64(len(journal.events))] = connectionEvent{id, record}
		journal.head++
	}
}

// Connections returns a complete view for a new or out-of-date cursor, or
// only changed records, byte counters and removed IDs for a recent cursor.
func (engine *Engine) Connections(cursor *uint64) ConnectionDelta {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	journal := &engine.journal
	if journal.events == nil {
		journal.events = make([]connectionEvent, connectionJournalSize)
		cursor = nil
	}
	engine.sampleConnectionCounters()
	result := ConnectionDelta{Cursor: journal.head}
	if cursor == nil || *cursor > journal.head || journal.head-*cursor > uint64(len(journal.events)) {
		result.Full = true
		result.Records = engine.connectionSnapshot()
		return result
	}
	if *cursor == journal.head {
		return result
	}
	changed := make(map[uint64]bool)
	for seq := *cursor; seq < journal.head; seq++ {
		event := journal.events[seq%uint64(len(journal.events))]
		changed[event.id] = event.record || changed[event.id]
	}
	for id, record := range changed {
		if conn := engine.live[id]; conn != nil {
			if record {
				result.Records = append(result.Records, conn.snapshot())
			} else {
				result.Counters = append(result.Counters, conn.sampled)
			}
		} else if conn := engine.livePackets[id]; conn != nil {
			if record {
				result.Records = append(result.Records, conn.snapshot())
			} else {
				result.Counters = append(result.Counters, conn.sampled)
			}
		} else if recent := engine.recent.get(id); recent != nil {
			result.Records = append(result.Records, *recent)
		} else {
			result.Removed = append(result.Removed, id)
		}
	}
	return result
}

func (engine *Engine) sampleConnectionCounters() {
	// Reuse the counters the relay already maintains. Idle connections
	// generate no events and the hot path takes no extra locks or atomics.
	for id, conn := range engine.live {
		sample := ConnectionCounters{id, conn.sent.Load(), conn.recv.Load(), conn.firstByte.Load()}
		if sample != conn.sampled {
			conn.sampled = sample
			engine.journal.mark(id, false)
		}
	}
	for id, conn := range engine.livePackets {
		sample := ConnectionCounters{ID: id, Sent: conn.sent.Load(), Received: conn.recv.Load()}
		if sample != conn.sampled {
			conn.sampled = sample
			engine.journal.mark(id, false)
		}
	}
}

func (engine *Engine) connectionSnapshot() []Record {
	records := make([]Record, 0, len(engine.live)+len(engine.livePackets)+engine.recent.size)
	for _, conn := range engine.live {
		records = append(records, conn.snapshot())
	}
	for _, conn := range engine.livePackets {
		records = append(records, conn.snapshot())
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	for i := range engine.recent.size {
		entry := engine.recent.entries[(engine.recent.first+i)%recentConnectionLimit]
		records = append(records, entry.record)
	}
	return records
}

type recentEntry struct {
	record  Record
	expires time.Time
}

type recentRecords struct {
	entries []recentEntry
	byID    map[uint64]int
	first   int
	size    int
}

func (recent *recentRecords) get(id uint64) *Record {
	if index, ok := recent.byID[id]; ok {
		return &recent.entries[index].record
	}
	return nil
}

func (engine *Engine) removeOldestRecord() {
	recent := &engine.recent
	entry := &recent.entries[recent.first]
	delete(recent.byID, entry.record.ID)
	engine.journal.mark(entry.record.ID, true)
	*entry = recentEntry{}
	recent.first = (recent.first + 1) % recentConnectionLimit
	recent.size--
}

func (engine *Engine) remember(record Record) {
	recent := &engine.recent
	if recent.byID == nil {
		recent.byID = make(map[uint64]int)
	}
	if recent.size == recentConnectionLimit {
		engine.removeOldestRecord()
	}
	ttl := engine.recentTTL
	if ttl <= 0 {
		ttl = recentConnectionTTL
	}
	index := (recent.first + recent.size) % recentConnectionLimit
	entry := recentEntry{record: record, expires: time.Now().Add(ttl)}
	if index == len(recent.entries) {
		recent.entries = append(recent.entries, entry)
	} else {
		recent.entries[index] = entry
	}
	recent.byID[record.ID] = index
	recent.size++
	engine.journal.mark(record.ID, true)
	if engine.recentTimer == nil && !engine.closed {
		engine.scheduleRecentExpiry()
	}
}

func (engine *Engine) scheduleRecentExpiry() {
	first := engine.recent.entries[engine.recent.first]
	engine.recentTimer = time.AfterFunc(time.Until(first.expires), engine.expireRecent)
}

func (engine *Engine) expireRecent() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.recentTimer = nil
	if engine.closed {
		return
	}
	now := time.Now()
	for engine.recent.size > 0 && !engine.recent.entries[engine.recent.first].expires.After(now) {
		engine.removeOldestRecord()
	}
	if engine.recent.size > 0 {
		engine.scheduleRecentExpiry()
	} else {
		engine.recent = recentRecords{}
	}
}
