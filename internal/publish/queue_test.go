package publish

import "testing"

func TestQueueDropsOldestWhenFull(t *testing.T) {
	q := newQueue(3)
	for i := uint64(1); i <= 5; i++ {
		q.push(outMsg{seq: i})
	}
	if got := q.Dropped(); got != 2 {
		t.Fatalf("Dropped = %d, want 2", got)
	}
	var seqs []uint64
	for {
		m, ok := q.head()
		if !ok {
			break
		}
		seqs = append(seqs, m.seq)
		q.pop(m.seq)
	}
	if len(seqs) != 3 || seqs[0] != 3 || seqs[1] != 4 || seqs[2] != 5 {
		t.Fatalf("contents = %v, want [3 4 5]", seqs)
	}
}

func TestQueuePopIgnoresDroppedHead(t *testing.T) {
	q := newQueue(2)
	q.push(outMsg{seq: 1})
	m, _ := q.head()
	q.push(outMsg{seq: 2})
	q.push(outMsg{seq: 3}) // drops seq 1 while the sender still holds it
	q.pop(m.seq)           // must not remove seq 2
	if h, _ := q.head(); h.seq != 2 {
		t.Fatalf("head = %d, want 2", h.seq)
	}
}
