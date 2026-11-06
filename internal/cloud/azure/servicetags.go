package azure

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TagSet is a location's service tags: lowercased name → address prefixes.
type TagSet map[string][]string

// tagCache holds each location's service-tag list for tagTTL (Microsoft publishes changes
// weekly). A failed read is kept for tagFailTTL, so a denied or throttled call is not
// repeated for every host; a failed refresh keeps the last good list (retried after
// tagFailTTL). Reads run on their own deadline (tagTimeout), outside any host's budget: a
// host whose time runs out stops waiting, the read goes on.
type tagCache struct {
	read func(ctx context.Context, subscription, location string) (TagSet, error)
	now  func() time.Time

	mu       sync.Mutex
	entries  map[string]tagEntry
	inflight map[string]*tagCall
}

type tagEntry struct {
	tags TagSet
	err  string
	at   time.Time
}

type tagCall struct {
	done chan struct{}
	e    tagEntry
}

const (
	tagTTL       = 24 * time.Hour
	tagFailTTL   = 10 * time.Minute
	tagTimeout   = 2 * time.Minute
	maxLocations = 64
	maxTagPages  = 10
)

func newTagCache(read func(context.Context, string, string) (TagSet, error), now func() time.Time) *tagCache {
	return &tagCache{read: read, now: now, entries: map[string]tagEntry{}, inflight: map[string]*tagCall{}}
}

// get returns the location's tags, or why they are not available ("" error string with
// tags). subscription is the (allow-listed) subscription the read is made under.
func (c *tagCache) get(ctx context.Context, subscription, location string) (TagSet, string) {
	if !locationRe.MatchString(location) {
		return nil, fmt.Sprintf("location %q is not a region name", truncate(location, 40))
	}
	c.mu.Lock()
	if e, ok := c.entries[location]; ok {
		ttl := tagTTL
		if e.err != "" {
			ttl = tagFailTTL
		}
		if c.now().Sub(e.at) < ttl {
			c.mu.Unlock()
			return e.tags, e.err
		}
	}
	call := c.inflight[location]
	if call == nil {
		if _, known := c.entries[location]; !known && len(c.entries) >= maxLocations {
			c.mu.Unlock()
			return nil, fmt.Sprintf("more than %d locations cached", maxLocations)
		}
		call = &tagCall{done: make(chan struct{})}
		c.inflight[location] = call
		go c.run(subscription, location, call)
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.e.tags, call.e.err
	case <-ctx.Done():
		return nil, "still being read when the host's time ran out"
	}
}

func (c *tagCache) run(subscription, location string, call *tagCall) {
	ctx, cancel := context.WithTimeout(context.Background(), tagTimeout)
	defer cancel()
	tags, err := c.read(ctx, subscription, location)
	e := tagEntry{tags: tags, at: c.now()}
	if err != nil {
		e = tagEntry{err: err.Error(), at: c.now()}
	}
	c.mu.Lock()
	if old, ok := c.entries[location]; ok && err != nil && old.err == "" {
		e = tagEntry{tags: old.tags, at: c.now().Add(tagFailTTL - tagTTL)}
	}
	c.entries[location] = e
	delete(c.inflight, location)
	c.mu.Unlock()
	call.e = e
	close(call.done)
}

// lookup finds a tag by name (case-insensitive).
func (t TagSet) lookup(name string) ([]string, bool) {
	p, ok := t[strings.ToLower(name)]
	return p, ok
}
