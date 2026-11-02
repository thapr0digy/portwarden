// Package sdsocket maps listening sockets to the systemd socket units that own them.
package sdsocket

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Listen is one pair of a socket unit's Listen property, e.g. {"Stream", "0.0.0.0:22"}.
type Listen struct{ Type, Address string }

// Unit is an active socket unit and the service it triggers.
type Unit struct {
	Name, Service string
	Listens       []Listen
}

// Lister reads the active socket units from systemd.
type Lister interface {
	SocketUnits(ctx context.Context) ([]Unit, error)
}

const (
	// minRefreshGap bounds how often a miss (or an expired list) may trigger a refresh.
	minRefreshGap = 5 * time.Second
	// refreshTimeout bounds one lister call.
	refreshTimeout = 10 * time.Second
)

type matchKey struct {
	proto string
	addr  netip.Addr
	port  uint16
}

type owner struct{ unit, service string }

// Matcher answers which socket unit owns a listener. Match never blocks on the lister:
// refreshes run in their own goroutine and Match answers from the last good list.
type Matcher struct {
	lister    Lister
	ttl       time.Duration
	hostNetNS uint64
	now       func() time.Time // test seam

	mu          sync.Mutex
	index       map[matchKey]owner
	fetched     time.Time // last successful refresh
	attempted   time.Time // last refresh start
	refreshing  bool
	errLogged   bool // an error has been logged in the current failure streak
	refreshesWG sync.WaitGroup
}

// NewMatcher builds a matcher that refreshes from l when its list is older than ttl or
// on a miss, at most once per 5 s. Only listeners in the host netns (hostNetNS) match.
func NewMatcher(l Lister, ttl time.Duration, hostNetNS uint64) *Matcher {
	return &Matcher{lister: l, ttl: ttl, hostNetNS: hostNetNS, now: time.Now}
}

// Match returns the socket unit and service owning k, if any.
func (m *Matcher) Match(k model.ListenerKey) (socketUnit, service string, ok bool) {
	if uint64(k.NetNS) != m.hostNetNS {
		return "", "", false
	}
	mk := matchKey{proto: k.Proto, addr: k.Addr.Unmap(), port: k.Port}

	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.index[mk]
	if !ok || m.now().Sub(m.fetched) > m.ttl {
		m.maybeRefreshLocked()
	}
	return o.unit, o.service, ok
}

// maybeRefreshLocked starts an asynchronous refresh unless one is running or the last
// attempt was under minRefreshGap ago.
func (m *Matcher) maybeRefreshLocked() {
	now := m.now()
	if m.refreshing || (!m.attempted.IsZero() && now.Sub(m.attempted) < minRefreshGap) {
		return
	}
	m.refreshing = true
	m.attempted = now
	m.refreshesWG.Add(1)
	go m.refresh()
}

func (m *Matcher) refresh() {
	defer m.refreshesWG.Done()
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	units, err := m.lister.SocketUnits(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshing = false
	if err != nil {
		if !m.errLogged {
			slog.Warn("systemd socket unit list failed; keeping the last good list", "err", err)
			m.errLogged = true
		}
		return
	}
	m.errLogged = false
	m.index = buildIndex(units)
	m.fetched = m.now()
}

// wait blocks until running refreshes finish; tests use it to stay deterministic.
func (m *Matcher) wait() { m.refreshesWG.Wait() }

func buildIndex(units []Unit) map[matchKey]owner {
	index := make(map[matchKey]owner)
	for _, u := range units {
		for _, l := range u.Listens {
			mk, ok := parseListen(l)
			if !ok {
				continue
			}
			if _, taken := index[mk]; !taken {
				index[mk] = owner{unit: u.Name, service: u.Service}
			}
		}
	}
	return index
}

// parseListen turns a Listen pair into a match key. Only Stream (tcp) and Datagram (udp)
// IP addresses qualify; unix paths, abstract names, vsock and the other types do not.
func parseListen(l Listen) (matchKey, bool) {
	var proto string
	switch l.Type {
	case "Stream":
		proto = model.ProtoTCP
	case "Datagram":
		proto = model.ProtoUDP
	default:
		return matchKey{}, false
	}
	addr := l.Address
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "@") {
		return matchKey{}, false
	}
	// systemd prints a link-local zone after the port ("[fe80::1]:53%eth0").
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return matchKey{}, false
	}
	return matchKey{proto: proto, addr: ap.Addr().Unmap(), port: ap.Port()}, true
}
