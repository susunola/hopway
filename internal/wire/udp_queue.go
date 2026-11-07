package wire

import "sync/atomic"

const UDPQueueLimit = 8 << 20

// UDPQueue is shared by all local UDP ingress queues, including while an
// older configuration drains. Admission never waits for a slow outbound.
var UDPQueue udpQueueBudget

type udpQueueBudget struct {
	bytes atomic.Int64
}

func (q *udpQueueBudget) TryReserve(bytes int) bool {
	cost := int64(bytes)
	for {
		used := q.bytes.Load()
		if cost > UDPQueueLimit-used {
			return false
		}
		if q.bytes.CompareAndSwap(used, used+cost) {
			return true
		}
	}
}

func (q *udpQueueBudget) Release(bytes int) { q.bytes.Add(-int64(bytes)) }

func (q *udpQueueBudget) Bytes() int64 { return q.bytes.Load() }
