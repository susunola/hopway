package wire

import "sync/atomic"

type UDPDropReason uint8

const (
	UDPInvalid UDPDropReason = iota
	UDPFragment
	UDPQueueFull
	UDPUpstream
	UDPPolicy
	udpReasonCount
)

type UDPDropCounts struct {
	Invalid    uint64 `json:"invalid"`
	Fragmented uint64 `json:"fragmented"`
	QueueFull  uint64 `json:"queueFull"`
	Upstream   uint64 `json:"upstream"`
	Policy     uint64 `json:"policy"`
}

type UDPDropCounter struct {
	counts [udpReasonCount]atomic.Uint64
}

// These counters describe packets discarded by the local proxy. The counts
// survive configuration reloads in the same process.
var SOCKSUDPDrops, TUNUDPDrops UDPDropCounter

func (c *UDPDropCounter) Add(reason UDPDropReason, count int) {
	c.counts[reason].Add(uint64(count))
}

func (c *UDPDropCounter) Snapshot() UDPDropCounts {
	return UDPDropCounts{
		Invalid: c.counts[UDPInvalid].Load(), Fragmented: c.counts[UDPFragment].Load(),
		QueueFull: c.counts[UDPQueueFull].Load(), Upstream: c.counts[UDPUpstream].Load(),
		Policy: c.counts[UDPPolicy].Load(),
	}
}
