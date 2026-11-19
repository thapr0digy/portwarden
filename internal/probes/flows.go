//go:build linux

package probes

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/thapr0digy/portwarden/internal/flows"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

// The flow_head record of bpf/flows.bpf.c, read by offset (bpf2go types only the ring's
// declared value, flow_conn): cookie, kind, length, then the bytes.
const (
	flowHeadKindOffset = 8
	flowHeadLenOffset  = 12
	flowHeadDataOffset = 16
	flowHeadMax        = 2048
	flowEventsBuffer   = 4096
	// flowDrainEvery is how often the reader drains the ring when no wakeup came (the
	// programs wake it only once 256 KiB wait).
	flowDrainEvery = 200 * time.Millisecond
)

// Flows owns the connection programs of bpf/flows.bpf.c, their links and the ring buffer
// reader, which turns records into flows.Events. A record of first bytes is sniffed in the
// reader (flows.Sniff) and only its result leaves it.
type Flows struct {
	objs     flowsObjects
	links    []link.Link
	attached []attachedLink
	mu       sync.Mutex
	reader   *ringbuf.Reader
	events   chan flows.Event
	done     chan struct{}
	wg       sync.WaitGroup

	readErr   error
	closeOnce sync.Once
	closeErr  error
}

// StartFlows loads and attaches the connection programs and starts reading their records.
func StartFlows() (*Flows, error) {
	spec, err := loadFlows()
	if err != nil {
		return nil, err
	}
	f := &Flows{events: make(chan flows.Event, flowEventsBuffer), done: make(chan struct{})}
	if err := spec.LoadAndAssign(&f.objs, nil); err != nil {
		return nil, fmt.Errorf("load flows programs: %w", WithVerifierLog(err))
	}
	for _, prog := range f.programs() {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog.prog})
		if err != nil {
			f.closeResources()
			return nil, fmt.Errorf("attach %s: %w", prog.name, err)
		}
		f.links = append(f.links, l)
		a, err := newAttachedLink(prog.name, "", prog.prog, l)
		if err != nil {
			f.closeResources()
			return nil, err
		}
		f.attached = append(f.attached, a)
	}
	if f.reader, err = ringbuf.NewReader(f.objs.FlowEvents); err != nil {
		f.closeResources()
		return nil, fmt.Errorf("open flows ring buffer reader: %w", err)
	}
	f.wg.Add(1)
	go f.readLoop()
	return f, nil
}

func (f *Flows) programs() []namedProgram {
	return []namedProgram{
		{flowsProgOnConnect, f.objs.OnConnect},
		{flowsProgOnAccept, f.objs.OnAccept},
		{flowsProgOnSendmsg, f.objs.OnSendmsg},
	}
}

// Events delivers the decoded records; it is closed after Close or when reading fails (Err).
func (f *Flows) Events() <-chan flows.Event { return f.events }

// Err returns the error that stopped the reader early, or nil, once Events is closed.
func (f *Flows) Err() error {
	f.wg.Wait()
	return f.readErr
}

// Drops returns the connection records lost to a full ring buffer, summed over CPUs (0 when unread).
func (f *Flows) Drops() uint64 {
	var perCPU []uint64
	if err := f.objs.FlowCounters.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// RunCounts returns how often each program ran (needs kernel.bpf_stats_enabled).
func (f *Flows) RunCounts() (map[string]uint64, error) {
	counts := make(map[string]uint64)
	for _, prog := range f.programs() {
		st, err := prog.prog.Stats()
		if err != nil {
			return nil, fmt.Errorf("stats of %s: %w", prog.name, err)
		}
		counts[prog.name] = st.RunCount
	}
	return counts, nil
}

// Attachments reports, for the tamper checks, each link with what the kernel reports now.
func (f *Flows) Attachments() ([]tamper.Attachment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return observe(f.attached, nil)
}

// Close detaches the programs, stops the reader and releases the kernel objects.
func (f *Flows) Close() error {
	f.closeOnce.Do(func() {
		close(f.done)
		var errs []error
		f.mu.Lock()
		for _, l := range f.links {
			errs = append(errs, l.Close())
		}
		f.links, f.attached = nil, nil
		f.mu.Unlock()
		errs = append(errs, f.reader.Close())
		f.wg.Wait()
		errs = append(errs, f.objs.Close())
		f.closeErr = errors.Join(errs...)
	})
	return f.closeErr
}

func (f *Flows) closeResources() {
	for _, l := range f.links {
		_ = l.Close()
	}
	_ = f.objs.Close()
}

func (f *Flows) readLoop() {
	defer f.wg.Done()
	defer close(f.events)
	var rec ringbuf.Record
	for {
		f.reader.SetDeadline(time.Now().Add(flowDrainEvery))
		if err := f.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if !errors.Is(err, ringbuf.ErrClosed) {
				f.readErr = fmt.Errorf("read flows ring buffer: %w", err)
			}
			return
		}
		e, err := decodeFlow(rec.RawSample)
		clear(rec.RawSample) // first bytes never outlive their record
		if err != nil {
			f.readErr = err
			return
		}
		select {
		case f.events <- e:
		case <-f.done:
			return
		}
	}
}

// decodeFlow decodes one ring record: a connection, or first bytes, which it sniffs.
func decodeFlow(raw []byte) (flows.Event, error) {
	if len(raw) < flowHeadDataOffset {
		return flows.Event{}, fmt.Errorf("flows record of %d bytes", len(raw))
	}
	cookie := binary.NativeEndian.Uint64(raw)
	switch kind := flows.EventKind(binary.NativeEndian.Uint32(raw[flowHeadKindOffset:])); kind {
	case flows.KindHead:
		n := int(binary.NativeEndian.Uint32(raw[flowHeadLenOffset:]))
		if n > flowHeadMax || flowHeadDataOffset+n > len(raw) {
			return flows.Event{}, fmt.Errorf("flows head record claims %d bytes in %d", n, len(raw))
		}
		app, service := flows.Sniff(raw[flowHeadDataOffset : flowHeadDataOffset+n])
		return flows.Event{Kind: kind, Cookie: cookie, App: app, Service: service}, nil
	case flows.KindOut, flows.KindIn:
		var c flowsFlowConn
		if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &c); err != nil {
			return flows.Event{}, fmt.Errorf("decode flows record of %d bytes: %w", len(raw), err)
		}
		addr, err := address(c.Family, c.Raddr)
		if err != nil {
			return flows.Event{}, err
		}
		return flows.Event{Kind: kind, Cookie: cookie, TGID: c.Tgid, Comm: CommString(c.Comm), CgroupID: c.CgroupId,
			LocalPort: c.Lport, Remote: netip.AddrPortFrom(addr.Unmap(), c.Rport)}, nil
	default:
		return flows.Event{}, fmt.Errorf("unknown flows record kind %d", kind)
	}
}
