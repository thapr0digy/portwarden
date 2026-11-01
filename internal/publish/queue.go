package publish

import "sync"

// outMsg is a fully encoded message waiting to be published.
// Its id and seq are fixed at enqueue time so a retry is a true duplicate.
type outMsg struct {
	subject string
	id      string
	seq     uint64
	data    []byte
}

// queue is a bounded FIFO. push never blocks: when full it drops the oldest entry.
type queue struct {
	mu      sync.Mutex
	items   []outMsg
	max     int
	dropped uint64
	// overflowed counts only the drops caused by a full queue (a subset of dropped).
	overflowed uint64
	ready      chan struct{} // capacity 1; signalled by push
}

func newQueue(max int) *queue {
	return &queue{max: max, ready: make(chan struct{}, 1)}
}

func (q *queue) push(m outMsg) {
	q.mu.Lock()
	if len(q.items) >= q.max {
		q.items[0] = outMsg{}
		q.items = q.items[1:]
		q.dropped++
		q.overflowed++
	}
	q.items = append(q.items, m)
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// head returns the oldest entry without removing it.
func (q *queue) head() (outMsg, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return outMsg{}, false
	}
	return q.items[0], true
}

// pop removes the head only if it still has the given seq; the entry may have been
// dropped for overflow while the sender was publishing it.
func (q *queue) pop(seq uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) > 0 && q.items[0].seq == seq {
		q.items[0] = outMsg{}
		q.items = q.items[1:]
	}
}

// Len is the number of queued entries.
func (q *queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Dropped counts entries discarded because the queue was full.
func (q *queue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// Overflowed counts entries discarded because the queue was full, excluding
// messages discarded as undeliverable.
func (q *queue) Overflowed() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.overflowed
}

// discard removes the head as undeliverable and counts it as dropped.
func (q *queue) discard(seq uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) > 0 && q.items[0].seq == seq {
		q.items[0] = outMsg{}
		q.items = q.items[1:]
		q.dropped++
	}
}
