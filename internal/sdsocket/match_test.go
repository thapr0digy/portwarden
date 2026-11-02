package sdsocket

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

const hostNS = 4026531840

type fakeLister struct {
	mu    sync.Mutex
	units []Unit
	err   error
	calls int
}

func (f *fakeLister) SocketUnits(context.Context) ([]Unit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.units, f.err
}

func (f *fakeLister) set(units []Unit, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.units, f.err = units, err
}

func (f *fakeLister) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func key(netns uint32, proto, addr string, port uint16) model.ListenerKey {
	return model.NewKey(netns, proto, netip.MustParseAddr(addr), port)
}

// warmedMatcher builds a matcher whose first refresh has completed.
func warmedMatcher(t *testing.T, l Lister, ttl time.Duration) *Matcher {
	t.Helper()
	m := NewMatcher(l, ttl, hostNS)
	m.Match(key(hostNS, model.ProtoTCP, "127.0.0.1", 1)) // miss triggers the first refresh
	m.wait()
	return m
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name   string
		listen Listen
		key    model.ListenerKey
		want   bool
	}{
		{"stream any-v6 matches tcp", Listen{"Stream", "[::]:22"}, key(hostNS, "tcp", "::", 22), true},
		{"stream v4 matches only v4", Listen{"Stream", "0.0.0.0:22"}, key(hostNS, "tcp", "0.0.0.0", 22), true},
		{"stream v4 does not match v6 wildcard", Listen{"Stream", "0.0.0.0:22"}, key(hostNS, "tcp", "::", 22), false},
		{"stream v6 does not match v4 wildcard", Listen{"Stream", "[::]:22"}, key(hostNS, "tcp", "0.0.0.0", 22), false},
		{"stream does not match udp", Listen{"Stream", "[::]:22"}, key(hostNS, "udp", "::", 22), false},
		{"datagram matches udp", Listen{"Datagram", "127.0.0.53:53"}, key(hostNS, "udp", "127.0.0.53", 53), true},
		{"datagram does not match tcp", Listen{"Datagram", "127.0.0.53:53"}, key(hostNS, "tcp", "127.0.0.53", 53), false},
		{"different port", Listen{"Stream", "0.0.0.0:22"}, key(hostNS, "tcp", "0.0.0.0", 23), false},
		{"zone dropped", Listen{"Datagram", "[fe80::1]:53%eth0"}, key(hostNS, "udp", "fe80::1", 53), true},
		{"mapped address unmapped", Listen{"Stream", "[::ffff:127.0.0.1]:80"}, key(hostNS, "tcp", "127.0.0.1", 80), true},
		{"sequential packet ignored", Listen{"SequentialPacket", "0.0.0.0:22"}, key(hostNS, "tcp", "0.0.0.0", 22), false},
		{"netlink ignored", Listen{"Netlink", "route 0"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"special ignored", Listen{"Special", "/dev/log"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"message queue ignored", Listen{"MessageQueue", "/q"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"fifo ignored", Listen{"FIFO", "/run/x"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"usb function ignored", Listen{"USBFunction", "/f"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"unix path ignored", Listen{"Stream", "/run/x.sock"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"abstract unix ignored", Listen{"Stream", "@abstract"}, key(hostNS, "tcp", "0.0.0.0", 0), false},
		{"vsock ignored", Listen{"Stream", "vsock:2:1234"}, key(hostNS, "tcp", "0.0.0.0", 1234), false},
		{"only host netns matches", Listen{"Stream", "0.0.0.0:22"}, key(hostNS+1, "tcp", "0.0.0.0", 22), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &fakeLister{units: []Unit{{Name: "x.socket", Service: "x.service", Listens: []Listen{tc.listen}}}}
			m := warmedMatcher(t, l, time.Hour)
			unit, service, ok := m.Match(tc.key)
			if ok != tc.want {
				t.Fatalf("Match(%v) ok = %v, want %v", tc.key, ok, tc.want)
			}
			if ok && (unit != "x.socket" || service != "x.service") {
				t.Fatalf("Match = %q, %q", unit, service)
			}
		})
	}
}

func TestMatcherKeepsLastGoodListOnError(t *testing.T) {
	l := &fakeLister{units: []Unit{{Name: "ssh.socket", Service: "ssh.service", Listens: []Listen{{"Stream", "0.0.0.0:22"}}}}}
	clock := time.Unix(1000, 0)
	m := NewMatcher(l, 30*time.Second, hostNS)
	m.now = func() time.Time { return clock }
	k := key(hostNS, "tcp", "0.0.0.0", 22)

	m.Match(k)
	m.wait()
	if _, _, ok := m.Match(k); !ok {
		t.Fatal("expected a match after the first refresh")
	}

	l.set(nil, errors.New("bus gone"))
	clock = clock.Add(time.Minute) // stale: next Match triggers a refresh that fails
	if _, _, ok := m.Match(k); !ok {
		t.Fatal("stale list must still answer while refreshing")
	}
	m.wait()
	if _, _, ok := m.Match(k); !ok {
		t.Fatal("last good list must survive a lister error")
	}
}

func TestMatcherRefreshesOnMissAtMostEvery5s(t *testing.T) {
	l := &fakeLister{}
	clock := time.Unix(1000, 0)
	m := NewMatcher(l, time.Hour, hostNS)
	m.now = func() time.Time { return clock }
	miss := key(hostNS, "tcp", "0.0.0.0", 9999)

	m.Match(miss)
	m.wait()
	if got := l.callCount(); got != 1 {
		t.Fatalf("calls after first miss = %d, want 1", got)
	}

	clock = clock.Add(4 * time.Second)
	m.Match(miss)
	m.wait()
	if got := l.callCount(); got != 1 {
		t.Fatalf("calls within 5s = %d, want 1", got)
	}

	clock = clock.Add(time.Second) // 5s since the last attempt
	l.set([]Unit{{Name: "new.socket", Service: "new.service", Listens: []Listen{{"Stream", "0.0.0.0:9999"}}}}, nil)
	m.Match(miss)
	m.wait()
	if got := l.callCount(); got != 2 {
		t.Fatalf("calls after 5s = %d, want 2", got)
	}
	if unit, _, ok := m.Match(miss); !ok || unit != "new.socket" {
		t.Fatalf("Match after refresh = %q, %v", unit, ok)
	}
}

func TestMatcherRefreshesWhenOlderThanTTL(t *testing.T) {
	l := &fakeLister{units: []Unit{{Name: "a.socket", Service: "a.service", Listens: []Listen{{"Stream", "0.0.0.0:1"}}}}}
	clock := time.Unix(1000, 0)
	m := NewMatcher(l, 30*time.Second, hostNS)
	m.now = func() time.Time { return clock }
	hit := key(hostNS, "tcp", "0.0.0.0", 1)

	m.Match(hit)
	m.wait()
	m.Match(hit) // fresh hit: no refresh
	m.wait()
	if got := l.callCount(); got != 1 {
		t.Fatalf("calls on fresh hit = %d, want 1", got)
	}

	clock = clock.Add(31 * time.Second)
	m.Match(hit)
	m.wait()
	if got := l.callCount(); got != 2 {
		t.Fatalf("calls after ttl = %d, want 2", got)
	}
}
