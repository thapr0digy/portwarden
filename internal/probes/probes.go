//go:build linux

package probes

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Event kinds and counter slots, as defined in bpf/listen.bpf.c.
const (
	kindOpened = 1
	kindClosed = 2

	counterRingbufReserveFailed = 0
)

const eventsBuffer = 4096

// Probes owns the loaded listener programs, their links and the ring buffer reader.
type Probes struct {
	objs   listenObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan model.Observation
	done   chan struct{}
	wg     sync.WaitGroup

	readErr   error // set by the reader goroutine before it closes events
	closeOnce sync.Once
	closeErr  error
}

// verifierError keeps the wrapped *ebpf.VerifierError but prints its full log.
type verifierError struct{ err *ebpf.VerifierError }

func (v verifierError) Error() string { return fmt.Sprintf("%+v", v.err) }
func (v verifierError) Unwrap() error { return v.err }

// WithVerifierLog returns err unchanged unless it holds an *ebpf.VerifierError, which
// it wraps so that the error message carries the full verifier log.
func WithVerifierLog(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return verifierError{ve}
	}
	return err
}

// Start loads the TCP and UDP listener programs, which watch every network namespace,
// attaches them and starts draining the ring buffer into Events.
func Start() (*Probes, error) {
	spec, err := loadListen()
	if err != nil {
		return nil, err
	}

	p := &Probes{events: make(chan model.Observation, eventsBuffer), done: make(chan struct{})}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("load listen programs: %w", WithVerifierLog(err))
	}

	for _, prog := range p.programs() {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog.prog})
		if err != nil {
			p.closeResources()
			return nil, fmt.Errorf("attach %s: %w", prog.name, err)
		}
		p.links = append(p.links, l)
	}

	p.reader, err = ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.closeResources()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	p.wg.Add(1)
	go p.readLoop()
	return p, nil
}

// Events delivers one observation per listener open or close, in kernel order.
// The channel is closed after Close, or when reading fails (see Err).
func (p *Probes) Events() <-chan model.Observation { return p.events }

// Err returns the error that stopped the reader early, or nil.
// It is meaningful once Events has been closed.
func (p *Probes) Err() error {
	p.wg.Wait()
	return p.readErr
}

type namedProgram struct {
	name string
	prog *ebpf.Program
}

// programs lists the loaded programs under their names in bpf/listen.bpf.c.
func (p *Probes) programs() []namedProgram {
	return []namedProgram{
		{listenProgOnListen, p.objs.OnListen},
		{listenProgOnStop, p.objs.OnStop},
		{listenProgOnUdpBind, p.objs.OnUdpBind},
		{listenProgOnUdpUnhash, p.objs.OnUdpUnhash},
	}
}

// Counters returns, summed over CPUs, the events dropped because the ring buffer
// was full. A failed map lookup reads as zero.
func (p *Probes) Counters() (ringbufDrops uint64) {
	return p.counter(counterRingbufReserveFailed)
}

func (p *Probes) counter(index uint32) uint64 {
	var perCPU []uint64
	if err := p.objs.Counters.Lookup(index, &perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// RunCounts returns how many times each program has run, keyed by program name
// (on_listen, on_stop, on_udp_bind, on_udp_unhash). The kernel only counts while
// kernel.bpf_stats_enabled is 1.
func (p *Probes) RunCounts() (map[string]uint64, error) {
	counts := make(map[string]uint64)
	for _, prog := range p.programs() {
		stats, err := prog.prog.Stats()
		if err != nil {
			return nil, fmt.Errorf("stats of %s: %w", prog.name, err)
		}
		counts[prog.name] = stats.RunCount
	}
	return counts, nil
}

// Close detaches the programs, stops the reader and releases the kernel objects.
// Events is closed when it returns.
func (p *Probes) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		var errs []error
		for _, l := range p.links {
			errs = append(errs, l.Close())
		}
		p.links = nil
		errs = append(errs, p.reader.Close())
		p.wg.Wait()
		errs = append(errs, p.objs.Close())
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}

// closeResources releases whatever Start acquired before it failed.
func (p *Probes) closeResources() {
	for _, l := range p.links {
		_ = l.Close()
	}
	_ = p.objs.Close()
}

func (p *Probes) readLoop() {
	defer p.wg.Done()
	defer close(p.events)

	var rec ringbuf.Record
	for {
		if err := p.reader.ReadInto(&rec); err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				p.readErr = fmt.Errorf("read ring buffer: %w", err)
			}
			return
		}
		obs, err := decode(rec.RawSample)
		if err != nil {
			p.readErr = err
			return
		}
		select {
		case p.events <- obs:
		case <-p.done:
			return
		}
	}
}

func decode(raw []byte) (model.Observation, error) {
	var ev listenEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &ev); err != nil {
		return model.Observation{}, fmt.Errorf("decode event of %d bytes: %w", len(raw), err)
	}

	obs := model.Observation{
		Cookie: ev.Cookie,
		Proc:   model.Process{PID: ev.Tgid, Comm: CommString(ev.Comm), CgroupID: ev.CgroupId},
		At:     monotonicToWall(ev.TsNs),
		Source: model.SourceEBPF,
	}
	switch ev.Kind {
	case kindClosed:
		obs.Kind = model.Closed
	case kindOpened:
		addr, err := address(ev.Family, ev.Addr)
		if err != nil {
			return model.Observation{}, err
		}
		proto, err := protocol(ev.Proto)
		if err != nil {
			return model.Observation{}, err
		}
		obs.Kind = model.Opened
		obs.Key = model.NewKey(ev.Netns, proto, addr, ev.Port)
		obs.Proc.UID = ev.Uid
		obs.Proc.Exe = ExePath(ev.Tgid)
	default:
		return model.Observation{}, fmt.Errorf("unknown event kind %d", ev.Kind)
	}
	return obs, nil
}

func protocol(raw uint8) (string, error) {
	switch raw {
	case unix.IPPROTO_TCP:
		return model.ProtoTCP, nil
	case unix.IPPROTO_UDP:
		return model.ProtoUDP, nil
	}
	return "", fmt.Errorf("unknown protocol %d", raw)
}

func address(family uint16, raw [16]uint8) (netip.Addr, error) {
	switch family {
	case unix.AF_INET:
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case unix.AF_INET6:
		return netip.AddrFrom16(raw), nil
	}
	return netip.Addr{}, fmt.Errorf("unknown address family %d", family)
}

// CommString converts a NUL-terminated task comm, as bpf2go types char[16], to a string.
func CommString(raw [16]int8) string {
	b := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// ExePath resolves the process's executable from /proc/<pid>/exe, or "" if it has
// exited or is not readable.
func ExePath(tgid uint32) string {
	exe, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(tgid), 10) + "/exe")
	if err != nil {
		return ""
	}
	return exe
}

// monotonicToWall converts a bpf_ktime_get_ns (CLOCK_MONOTONIC) stamp to wall-clock time.
func monotonicToWall(tsNs uint64) time.Time {
	now := time.Now()
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return now
	}
	return now.Add(-time.Duration(uint64(mono.Nano()) - tsNs))
}
