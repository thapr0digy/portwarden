// Package validate holds the checks the ingest server runs on every asm.events.v1
// event, so a producer can run exactly the same checks before it sends. The checks
// sit at a trust boundary: every size and count is bounded, nothing panics on
// hostile input, and a failure is always reported, never dropped.
package validate

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/slidehq/signal/schema/eventsv1"
)

// Code is a stable rejection code (IngestResponse.rejected[].code).
type Code string

const (
	// CodeInvalidPayload means a required field is missing or a value is malformed.
	CodeInvalidPayload Code = "invalid_payload"
	// CodeTypeMismatch means the payload, or dataschema, is not the one the type names.
	CodeTypeMismatch Code = "type_mismatch"
	// CodeForbiddenSubject means the subject's scheme is not allowed for the type.
	CodeForbiddenSubject Code = "forbidden_subject"
	// CodeTooLarge means an event, a field or a count is over its limit.
	CodeTooLarge Code = "too_large"
	// CodeUnknownType means a type string or payload case this version does not know.
	CodeUnknownType Code = "unknown_type"
	// CodeBadTime means the time is missing, invalid, or too far in the future.
	CodeBadTime Code = "bad_time"
	// CodeInvalidBatch means the batch as a whole is invalid (count, order); the
	// endpoint answers 413 or 422 for the request rather than a per-event rejection.
	CodeInvalidBatch Code = "invalid_batch"
)

// BatchIndex is the Problem.Index of a problem with the whole batch.
const BatchIndex = -1

// Problem is one failed check. Index is the event's position in its batch (0 for
// a single event, BatchIndex for the batch itself); Path names the field.
type Problem struct {
	Index  int
	ID     string
	Code   Code
	Path   string
	Reason string
}

func (p *Problem) Error() string {
	if p.Path == "" {
		return fmt.Sprintf("validate: %s: %s", p.Code, p.Reason)
	}
	return fmt.Sprintf("validate: %s: %s: %s", p.Code, p.Path, p.Reason)
}

// Options are the limits and the clock the checks use.
type Options struct {
	// Limits; the zero value means Default.
	Limits *Limits
	// Now is the clock for the "not in the future" rule; nil means time.Now.
	Now func() time.Time
}

func (o Options) limits() Limits {
	if o.Limits == nil {
		return Default
	}
	return *o.Limits
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// Event checks one event. The error, when not nil, is a *Problem.
func Event(ev *eventsv1.Event, o Options) error {
	if p := checkEvent(ev, o.limits(), o.now()); p != nil {
		return p
	}
	return nil
}

// Batch checks a batch: the batch-level rules (count, request id, the order of
// each sequenced run) and then every event. Problems come back in batch order; a
// batch-level problem has Index BatchIndex. An empty result means valid.
func Batch(b *eventsv1.Batch, o Options) []Problem {
	out := BatchLevel(b, o)
	if len(out) > 0 && out[0].Code == CodeTooLarge {
		return out
	}
	l, now := o.limits(), o.now()
	for i, ev := range b.GetEvents() {
		if p := checkEvent(ev, l, now); p != nil {
			p.Index = i
			out = append(out, *p)
		}
	}
	return out
}

// BatchLevel runs only the batch-level rules of Batch; every problem has Index
// BatchIndex. A nil event in b stands for an element that could not be decoded:
// it counts towards the batch size and leaves a hole in its run's order.
func BatchLevel(b *eventsv1.Batch, o Options) []Problem {
	l := o.limits()
	if b == nil {
		return []Problem{{Index: BatchIndex, Code: CodeInvalidBatch, Reason: "no batch"}}
	}
	var out []Problem
	if n := len(b.GetEvents()); n == 0 {
		out = append(out, Problem{Index: BatchIndex, Code: CodeInvalidBatch, Path: "events", Reason: "empty batch"})
	} else if n > l.MaxBatchEvents {
		return []Problem{{Index: BatchIndex, Code: CodeTooLarge, Path: "events", Reason: fmt.Sprintf("%d events > %d", n, l.MaxBatchEvents)}}
	}
	if id := b.GetRequestId(); id != "" && !IsULID(id) {
		out = append(out, Problem{Index: BatchIndex, Code: CodeInvalidBatch, Path: "request_id", Reason: "not a ULID"})
	}
	if p := checkRunOrder(b.GetEvents()); p != nil {
		out = append(out, *p)
	}
	return out
}

// checkRunOrder enforces the batch rule for sequenced producers: within a run,
// seq increases by exactly one, and a run, once left, does not come back. Two
// exceptions: a spool_overflow event may follow the gap it explains (first_seq is
// one past the previous seq, last_seq one before its own), and a nil event (an
// element the JSON decoder could not read, so its seq is unknown) lets the next
// seq of the run be any higher number.
func checkRunOrder(evs []*eventsv1.Event) *Problem {
	var (
		run  string
		last uint64
		hole bool
		done = map[string]bool{}
	)
	for i, ev := range evs {
		if ev == nil {
			hole = true
			continue
		}
		seq := ev.GetSequence()
		if seq.GetSeq() == 0 || seq.GetRunId() == "" {
			continue
		}
		switch {
		case seq.GetRunId() == run:
			if !followsInRun(ev, last, hole) {
				return &Problem{Index: BatchIndex, Code: CodeInvalidBatch, Path: fmt.Sprintf("events[%d].sequence.seq", i),
					Reason: fmt.Sprintf("%d after %d in one run: not contiguous", seq.GetSeq(), last)}
			}
		case done[seq.GetRunId()]:
			return &Problem{Index: BatchIndex, Code: CodeInvalidBatch, Path: fmt.Sprintf("events[%d].sequence.run_id", i),
				Reason: "a run's events are split by another run"}
		default:
			if run != "" {
				done[run] = true
			}
			run = seq.GetRunId()
		}
		last, hole = seq.GetSeq(), false
	}
	return nil
}

// followsInRun reports whether ev may come next in its run after seq last.
func followsInRun(ev *eventsv1.Event, last uint64, hole bool) bool {
	seq := ev.GetSequence().GetSeq()
	switch {
	case seq == last+1:
		return true
	case seq <= last:
		return false
	case hole:
		return true
	}
	o := ev.GetSpoolOverflow()
	return o != nil && o.GetRunId() == ev.GetSequence().GetRunId() &&
		o.GetFirstSeq() == last+1 && o.GetLastSeq() == seq-1
}

// ErrBatchTooLarge is returned (wrapped) by the decoders for a body over
// Limits.MaxBatchBytes or a batch over Limits.MaxBatchEvents.
var ErrBatchTooLarge = errors.New("batch too large")

// ErrMalformed is returned (wrapped) by the decoders for a body that is not a
// batch at all.
var ErrMalformed = errors.New("malformed batch")

// maxDepth bounds message nesting on decode. The schema has no recursive message
// (eventsv1 tests assert it), so this is a second guard.
const maxDepth = 32

// Element is one event of a decoded batch, binary or JSON.
type Element struct {
	// Index is the element's position in the batch.
	Index int
	// Raw is the element as received, for the quarantine.
	Raw []byte
	// Event is the decoded event; nil when it did not decode. When Problem is set,
	// only its envelope is kept (Data is cleared), so a refused event holds no more
	// memory than its bytes but still names its id and sequence for the cursor.
	Event *eventsv1.Event
	// Problem is why the element was refused; nil when Event is valid.
	Problem *Problem
}

// Decoded is a decoded and validated binary batch.
type Decoded struct {
	RequestID string
	Elements  []Element
}

// Settle records p on e and, for a refused event, drops its payload (see Element).
func (e *Element) Settle(p *Problem) {
	if p == nil {
		return
	}
	p.Index = e.Index
	e.Problem = p
	if e.Event != nil {
		e.Event.Data = nil
		e.Event.ProtoReflect().SetUnknown(nil)
	}
}

// DecodeBinary decodes and validates a binary Batch (application/x-protobuf). An
// error is a problem with the whole batch (too large, framing, run order); a bad
// event is an Element with a Problem. Events are decoded and checked one at a time
// (each at most MaxEventBytes on the wire) and a refused one is cut down to its
// envelope before the next is decoded, so memory stays near one event's decoded
// size plus what valid events hold. Unknown fields are kept on valid events (a
// newer producer's data survives a store and a replay), up to MaxUnknownBytes per
// message.
func DecodeBinary(body []byte, o Options) (*Decoded, error) {
	l, now := o.limits(), o.now()
	if len(body) > l.MaxBatchBytes {
		return nil, fmt.Errorf("validate: %d bytes > %d: %w", len(body), l.MaxBatchBytes, ErrBatchTooLarge)
	}
	raws, requestID, err := splitBatch(body, l.MaxBatchEvents)
	if err != nil {
		return nil, err
	}
	d := &Decoded{RequestID: requestID, Elements: make([]Element, len(raws))}
	batch := &eventsv1.Batch{RequestId: requestID, Events: make([]*eventsv1.Event, len(raws))}
	for i, raw := range raws {
		e := &d.Elements[i]
		e.Index, e.Raw = i, raw
		if len(raw) > l.MaxEventBytes {
			e.Settle(&Problem{Code: CodeTooLarge, Reason: fmt.Sprintf("event is %d bytes > %d", len(raw), l.MaxEventBytes)})
			continue
		}
		ev := &eventsv1.Event{}
		if err := (proto.UnmarshalOptions{RecursionLimit: maxDepth}).Unmarshal(raw, ev); err != nil {
			e.Settle(&Problem{Code: CodeInvalidPayload, Reason: "does not decode: " + truncate(err.Error())})
			continue
		}
		e.Event = ev
		e.Settle(checkEvent(ev, l, now))
		batch.Events[i] = ev
	}
	if ps := BatchLevel(batch, o); len(ps) > 0 {
		return nil, fmt.Errorf("validate: %w", &ps[0])
	}
	return d, nil
}

// splitBatch reads a Batch's top level without decoding events: the raw bytes of
// each event (field 1) and the request id (field 2). Other fields are skipped (a
// newer producer's). It stops at maxEvents+1 events.
func splitBatch(body []byte, maxEvents int) (raws [][]byte, requestID string, err error) {
	for len(body) > 0 {
		num, typ, m := protowire.ConsumeTag(body)
		if m < 0 {
			return nil, "", fmt.Errorf("validate: tag: %w: %w", ErrMalformed, protowire.ParseError(m))
		}
		body = body[m:]
		k := protowire.ConsumeFieldValue(num, typ, body)
		if k < 0 {
			return nil, "", fmt.Errorf("validate: field %d: %w: %w", num, ErrMalformed, protowire.ParseError(k))
		}
		field := body[:k]
		body = body[k:]
		if num == 1 || num == 2 {
			if typ != protowire.BytesType {
				return nil, "", fmt.Errorf("validate: field %d: wrong wire type: %w", num, ErrMalformed)
			}
			v, _ := protowire.ConsumeBytes(field) // framed above, so it parses
			if num == 2 {
				requestID = string(v)
				continue
			}
			if len(raws) == maxEvents {
				return nil, "", fmt.Errorf("validate: more than %d events: %w", maxEvents, ErrBatchTooLarge)
			}
			raws = append(raws, v)
		}
	}
	return raws, requestID, nil
}
