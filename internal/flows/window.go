package flows

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// MaxFlowsPerDirection caps a window's rows per direction, so a host serving many
	// clients cannot crowd out the connections it makes (Signal takes 4,096 in all).
	MaxFlowsPerDirection = 2048
	// maxEventBytes is where a window's event is split: well under Signal's 1 MiB event
	// cap, with room for the envelope.
	maxEventBytes = 768 << 10
	// Signal's caps on a flow's process fields; a longer exe or unit is sent as "" (a
	// clipped path or unit would name another), a longer comm is clipped (the kernel's
	// is at most 15 bytes anyway).
	maxExe  = 1024
	maxComm = 16
	maxUnit = 256
)

// Directions, as Flow.direction spells them.
const (
	Out = "out"
	In  = "in"
)

// Conn is one connection with its process identified: made by this host (Out) or
// accepted by a listener on it (In).
type Conn struct {
	Direction       string
	Exe, Comm, Unit string
	// LocalPort is the port accepted on (In); an Out connection's ephemeral port is not kept.
	LocalPort uint16
	// Remote is the peer; an Out connection's port is the one connected to.
	Remote netip.AddrPort
	// App and Service are what the client's first bytes named (Out only; Sniff).
	App, Service string
	At           time.Time
}

// key is what a window aggregates by. remote is the zero Addr for In's summed public clients.
type key struct {
	direction             string
	exe, comm, unit       string
	localPort, remotePort uint16
	remote                netip.Addr
	app, service          string
}

type row struct {
	count       uint64
	first, last time.Time
}

// Window aggregates one window's connections. It is not safe for concurrent use.
type Window struct {
	start   time.Time
	rows    map[key]*row
	perDir  map[string]int
	dropped uint64
}

// NewWindow starts an empty window at start.
func NewWindow(start time.Time) *Window {
	return &Window{start: start, rows: make(map[key]*row), perDir: make(map[string]int)}
}

// Add counts c. A connection whose key is new once its direction holds MaxFlowsPerDirection
// rows is counted as dropped.
func (w *Window) Add(c Conn) {
	k := keyOf(c)
	if r, ok := w.rows[k]; ok {
		r.count++
		r.first, r.last = minTime(r.first, c.At), maxTime(r.last, c.At)
		return
	}
	if w.perDir[k.direction] >= MaxFlowsPerDirection {
		w.dropped++
		return
	}
	w.perDir[k.direction]++
	w.rows[k] = &row{count: 1, first: c.At, last: c.At}
}

// Drop counts n connections seen but in no row (lost in the kernel's buffer).
func (w *Window) Drop(n uint64) { w.dropped += n }

// keyOf normalizes c into its aggregation key: an Out connection keeps the peer and its
// port, an In one the local port and only a non-public peer (Signal never takes a public
// client's address); process fields are made valid UTF-8 without control characters and
// held to Signal's caps.
func keyOf(c Conn) key {
	k := key{
		direction: c.Direction,
		exe:       fieldOrEmpty(c.Exe, maxExe),
		comm:      clip(clean(c.Comm), maxComm),
		unit:      fieldOrEmpty(c.Unit, maxUnit),
		remote:    c.Remote.Addr().Unmap().WithZone(""),
	}
	switch c.Direction {
	case Out:
		k.remotePort = c.Remote.Port()
		k.app, k.service = c.App, c.Service
	case In:
		k.localPort = c.LocalPort
		if publicIP(k.remote) {
			k.remote = netip.Addr{}
		}
	}
	return k
}

// sharedAddressSpace is RFC 6598's carrier-grade NAT range.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// publicIP reports whether a is public as Signal holds an inbound peer to (its validator's
// publicIP): not private (RFC 1918, unique-local fc00::/7), shared (100.64.0.0/10),
// link-local or loopback.
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(a)
}

// clean makes s valid UTF-8 and replaces its control characters with '?'.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

// fieldOrEmpty is clean(s), or "" when that is longer than limit bytes.
func fieldOrEmpty(s string, limit int) string {
	if s = clean(s); len(s) > limit {
		return ""
	}
	return s
}

// clip cuts s to at most limit bytes on a rune boundary.
func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Flush returns the window's events, ending it at now and starting the next at now: one
// event, or several with the same bounds when the rows would pass the event size Signal
// takes (it adds them up). Flows are sorted by key; the dropped count rides on the first.
func (w *Window) Flush(now time.Time) []*eventsv1.HostFlows {
	start, end := w.start, now
	if !end.After(start) {
		end = start.Add(time.Nanosecond) // Signal wants a window that ends after it starts
	}
	keys := make([]key, 0, len(w.rows))
	for k := range w.rows {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareKeys)
	newEvent := func() *eventsv1.HostFlows {
		return &eventsv1.HostFlows{WindowStart: timestamppb.New(start), WindowEnd: timestamppb.New(end), Read: true}
	}
	out := []*eventsv1.HostFlows{newEvent()}
	out[0].Dropped = w.dropped
	size := proto.Size(out[0])
	for _, k := range keys {
		f := w.flow(k, start, end)
		n := proto.Size(f) + 4 // the field's tag and length
		if size+n > maxEventBytes && len(out[len(out)-1].GetFlows()) > 0 {
			out = append(out, newEvent())
			size = proto.Size(out[len(out)-1])
		}
		last := out[len(out)-1]
		last.Flows = append(last.Flows, f)
		size += n
	}
	*w = *NewWindow(now)
	return out
}

// flow is k's row as Signal's Flow, its times held within the window.
func (w *Window) flow(k key, start, end time.Time) *eventsv1.Flow {
	r := w.rows[k]
	f := &eventsv1.Flow{
		Direction: k.direction, Proto: "tcp", Exe: k.exe, Comm: k.comm, Unit: k.unit,
		LocalPort: uint32(k.localPort), RemotePort: uint32(k.remotePort),
		AppProto: k.app, ServiceName: k.service, Count: r.count,
		FirstSeen: timestamppb.New(within(r.first, start, end)),
		LastSeen:  timestamppb.New(within(r.last, start, end)),
	}
	if k.remote.IsValid() {
		f.RemoteAddr = k.remote.String()
	}
	return f
}

// compareKeys orders keys as Signal sorts HostFlows.flows: direction, remote_addr,
// remote_port, local_port, exe, comm, unit, app_proto, service_name.
func compareKeys(a, b key) int {
	return cmp.Or(
		cmp.Compare(a.direction, b.direction),
		cmp.Compare(addrString(a.remote), addrString(b.remote)),
		cmp.Compare(a.remotePort, b.remotePort),
		cmp.Compare(a.localPort, b.localPort),
		cmp.Compare(a.exe, b.exe),
		cmp.Compare(a.comm, b.comm),
		cmp.Compare(a.unit, b.unit),
		cmp.Compare(a.app, b.app),
		cmp.Compare(a.service, b.service),
	)
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func within(t, start, end time.Time) time.Time {
	return maxTime(start, minTime(t, end))
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
