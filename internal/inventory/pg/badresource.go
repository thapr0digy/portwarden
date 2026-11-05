package pg

import (
	"container/list"
	"hash/fnv"
	"sync"
)

// maxBadResourceHosts bounds the hosts remembered for an invalid cloud_resource.
const maxBadResourceHosts = 4096

// badResources remembers, per host, a hash of the last invalid cloud_resource it sent, so
// each distinct bad value is logged once. It holds at most max hosts and forgets the
// least recently seen first (that host may then be logged once more).
type badResources struct {
	mu    sync.Mutex
	max   int
	order *list.List // of *badEntry, most recently seen first
	hosts map[string]*list.Element
}

type badEntry struct {
	host string
	hash uint64
}

func newBadResources(max int) *badResources {
	return &badResources{max: max, order: list.New(), hosts: map[string]*list.Element{}}
}

// changed records value as host's latest bad value and reports whether it is new for
// that host (not seen before, or different from the last one).
func (b *badResources) changed(host, value string) bool {
	h := fnv.New64a()
	_, _ = h.Write([]byte(value)) // a hash.Hash never returns an error
	sum := h.Sum64()
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.hosts[host]; ok {
		b.order.MoveToFront(el)
		e := el.Value.(*badEntry)
		if e.hash == sum {
			return false
		}
		e.hash = sum
		return true
	}
	b.hosts[host] = b.order.PushFront(&badEntry{host: host, hash: sum})
	if b.order.Len() > b.max {
		oldest := b.order.Back()
		b.order.Remove(oldest)
		delete(b.hosts, oldest.Value.(*badEntry).host)
	}
	return true
}

func (b *badResources) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.order.Len()
}
