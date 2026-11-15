// Package cejson is the CloudEvents 1.0 JSON form of asm.events.v1: a structured
// batch (application/cloudevents-batch+json) whose elements carry the envelope as
// CloudEvents attributes and the payload, in protojson, as "data".
//
// Decoding is strict: unknown attributes, unknown data fields, duplicate keys,
// invalid UTF-8 and non-string attribute values are refused. Every decoded event
// also passes the validate package, so a decoded event is a valid one.
package cejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

// ContentType is the media type of a batch in this form.
const ContentType = "application/cloudevents-batch+json"

// SpecVersion is the only CloudEvents version accepted.
const SpecVersion = "1.0"

// dataContentType is the only datacontenttype accepted (and the one written).
const dataContentType = "application/json"

// maxDepth bounds JSON nesting inside data (the schema itself is shallower).
const maxDepth = 32

// Attribute names (README.md, CloudEvents mapping).
const (
	attrSpecVersion     = "specversion"
	attrID              = "id"
	attrSource          = "source"
	attrType            = "type"
	attrSubject         = "subject"
	attrTime            = "time"
	attrDataSchema      = "dataschema"
	attrDataContentType = "datacontenttype"
	attrData            = "data"
	attrProducer        = "producer"
	attrAdapter         = "adapter"
	attrRunID           = "runid"
	attrSequence        = "sequence"
	attrBootID          = "bootid"
	attrRunNumber       = "runnumber"
	attrTraceparent     = "traceparent"
	attrCorrelationID   = "correlationid"
	attrCausationID     = "causationid"
)

var knownAttrs = map[string]bool{
	attrSpecVersion: true, attrID: true, attrSource: true, attrType: true, attrSubject: true,
	attrTime: true, attrDataSchema: true, attrDataContentType: true, attrData: true,
	attrProducer: true, attrAdapter: true, attrRunID: true, attrSequence: true,
	attrBootID: true, attrRunNumber: true, attrTraceparent: true, attrCorrelationID: true,
	attrCausationID: true,
}

// Element is one element of a decoded batch; the same type the binary decoder
// returns.
type Element = validate.Element

// DecodeBatch decodes and validates a JSON batch. An error is a problem with the
// whole batch (too large, not UTF-8, not a JSON array, out of run order); a bad
// element is an Element with a Problem, so one bad event does not refuse the rest.
func DecodeBatch(body []byte, o validate.Options) ([]Element, error) {
	l := limits(o)
	if len(body) > l.MaxBatchBytes {
		return nil, fmt.Errorf("cejson: %d bytes > %d: %w", len(body), l.MaxBatchBytes, validate.ErrBatchTooLarge)
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("cejson: not valid UTF-8: %w", validate.ErrMalformed)
	}
	raws, err := splitArray(body, l.MaxBatchEvents)
	if err != nil {
		return nil, err
	}
	out := make([]Element, len(raws))
	batch := &eventsv1.Batch{}
	for i, raw := range raws {
		ev, p := decodeElement(raw, l)
		if p == nil {
			if verr := validate.Event(ev, o); verr != nil {
				p = asProblem(verr)
			}
		}
		out[i] = Element{Index: i, Raw: raw, Event: ev}
		// A refused event keeps only its envelope, so it holds no more than its bytes.
		out[i].Settle(p)
		// An element that did not decode stays as a nil hole, so indexes match the
		// body and the order rule accepts the unknown seq it stands for.
		batch.Events = append(batch.Events, ev)
	}
	// The order of each run (the count was checked above).
	if ps := validate.BatchLevel(batch, o); len(ps) > 0 {
		return nil, fmt.Errorf("cejson: %w", &ps[0])
	}
	return out, nil
}

// DecodeEvent decodes and validates one JSON event (structured mode). The error is
// a *validate.Problem for an event that decoded as JSON but is invalid.
func DecodeEvent(body []byte, o validate.Options) (*eventsv1.Event, error) {
	l := limits(o)
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("cejson: not valid UTF-8: %w", validate.ErrMalformed)
	}
	ev, p := decodeElement(body, l)
	if p != nil {
		return nil, p
	}
	if err := validate.Event(ev, o); err != nil {
		return nil, fmt.Errorf("cejson: %w", err)
	}
	return ev, nil
}

func limits(o validate.Options) validate.Limits {
	if o.Limits == nil {
		return validate.Default
	}
	return *o.Limits
}

func asProblem(err error) *validate.Problem {
	var p *validate.Problem
	if errors.As(err, &p) {
		return p
	}
	return &validate.Problem{Code: validate.CodeInvalidPayload, Reason: err.Error()}
}

// splitArray returns the elements of a JSON array without decoding them, refusing
// more than maxEvents and anything after the closing bracket.
func splitArray(body []byte, maxEvents int) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return nil, fmt.Errorf("cejson: not a JSON array: %w", validate.ErrMalformed)
	}
	var out []json.RawMessage
	for dec.More() {
		if len(out) == maxEvents {
			return nil, fmt.Errorf("cejson: more than %d events: %w", maxEvents, validate.ErrBatchTooLarge)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("cejson: element %d: %w: %w", len(out), validate.ErrMalformed, err)
		}
		out = append(out, raw)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, fmt.Errorf("cejson: unterminated array: %w", validate.ErrMalformed)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("cejson: data after the array: %w", validate.ErrMalformed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("cejson: empty batch: %w", validate.ErrMalformed)
	}
	return out, nil
}

// decodeElement turns one CloudEvents JSON object into an Event. It does not run
// the validators.
func decodeElement(raw []byte, l validate.Limits) (*eventsv1.Event, *validate.Problem) {
	if len(raw) > l.MaxEventBytes {
		return nil, &validate.Problem{Code: validate.CodeTooLarge, Reason: fmt.Sprintf("event is %d bytes > %d", len(raw), l.MaxEventBytes)}
	}
	attrs, data, p := readObject(raw)
	if p != nil {
		return nil, p
	}
	if attrs[attrSpecVersion] != SpecVersion {
		return nil, bad(attrSpecVersion, `want "1.0"`)
	}
	if ct, ok := attrs[attrDataContentType]; ok && ct != dataContentType {
		return nil, bad(attrDataContentType, "want "+dataContentType)
	}
	ev := &eventsv1.Event{
		Id:            attrs[attrID],
		Type:          attrs[attrType],
		Source:        attrs[attrSource],
		Subject:       attrs[attrSubject],
		Dataschema:    attrs[attrDataSchema],
		Traceparent:   attrs[attrTraceparent],
		Correlationid: attrs[attrCorrelationID],
		Causationid:   attrs[attrCausationID],
	}
	if t, ok := attrs[attrTime]; ok {
		ts, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			return nil, &validate.Problem{Code: validate.CodeBadTime, Path: attrTime, Reason: "not RFC 3339"}
		}
		ev.Time = timestamppb.New(ts)
	}
	ev.Producer = producer(attrs)
	if p := sequence(attrs, ev); p != nil {
		return nil, p
	}
	if p := payload(ev, data); p != nil {
		return nil, p
	}
	return ev, nil
}

// readObject reads the top-level attributes: string values only (CloudEvents
// attribute values in this form), each key once, only known names; data is kept
// raw.
func readObject(raw []byte) (map[string]string, json.RawMessage, *validate.Problem) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, bad("", "not a JSON object")
	}
	attrs := map[string]string{}
	var data json.RawMessage
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, bad("", "malformed JSON")
		}
		key, _ := tok.(string)
		switch {
		case seen[key]:
			return nil, nil, bad(short(key), "duplicate attribute")
		case !knownAttrs[key]:
			return nil, nil, bad(short(key), "unknown attribute")
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, bad(key, "malformed JSON")
		}
		if key == attrData {
			data = v
			continue
		}
		var s string
		if bytes.Equal(v, []byte("null")) || json.Unmarshal(v, &s) != nil {
			return nil, nil, bad(key, "not a string")
		}
		// encoding/json turns a lone surrogate escape into U+FFFD; no attribute
		// (ids, URIs, versions) legitimately holds one.
		if strings.ContainsRune(s, utf8.RuneError) {
			return nil, nil, bad(key, "invalid character (a lone surrogate?)")
		}
		attrs[key] = s
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, bad("", "malformed JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, bad("", "data after the object")
	}
	return attrs, data, nil
}

// producer maps the producer ("name/version", split at the last slash, so a name
// may hold slashes and a version may not) and adapter attributes; nil when neither
// is present.
func producer(attrs map[string]string) *eventsv1.Producer {
	pr, hasPr := attrs[attrProducer]
	ad, hasAd := attrs[attrAdapter]
	if !hasPr && !hasAd {
		return nil
	}
	name, version := pr, ""
	if i := strings.LastIndexByte(pr, '/'); i >= 0 {
		name, version = pr[:i], pr[i+1:]
	}
	return &eventsv1.Producer{Name: name, Version: version, Adapter: ad}
}

func sequence(attrs map[string]string, ev *eventsv1.Event) *validate.Problem {
	run, hasRun := attrs[attrRunID]
	seq, hasSeq := attrs[attrSequence]
	boot, hasBoot := attrs[attrBootID]
	num, hasNum := attrs[attrRunNumber]
	if !hasRun && !hasSeq && !hasBoot && !hasNum {
		return nil
	}
	s := &eventsv1.Sequence{RunId: run, BootId: boot}
	var err error
	if hasSeq {
		if s.Seq, err = decimal(seq); err != nil {
			return bad(attrSequence, "not a decimal string")
		}
	}
	if hasNum {
		if s.RunNumber, err = decimal(num); err != nil {
			return bad(attrRunNumber, "not a decimal string")
		}
	}
	ev.Sequence = s
	return nil
}

// decimal parses a canonical unsigned decimal (no sign, no leading zeros).
func decimal(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cejson: %w", err)
	}
	if strconv.FormatUint(n, 10) != s {
		return 0, errors.New("cejson: not canonical")
	}
	return n, nil
}

// payload decodes data, strictly, into the oneof case the type names. An unknown
// type is left for the validator to name (unknown_type).
func payload(ev *eventsv1.Event, data json.RawMessage) *validate.Problem {
	if data == nil {
		return nil
	}
	if ev.GetType() == "" {
		return bad(attrType, "required") // as in binary: invalid_payload, not unknown_type
	}
	info, ok := eventsv1.Lookup(ev.GetType())
	if !ok {
		return &validate.Problem{Code: validate.CodeUnknownType, Path: attrType, Reason: "not in the registry"}
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return bad(attrData, "not a JSON object")
	}
	m := ev.ProtoReflect()
	fd := m.Descriptor().Fields().ByNumber(info.Case)
	if fd == nil {
		return &validate.Problem{Code: validate.CodeUnknownType, Path: attrData, Reason: "the registry names a case the schema lacks"}
	}
	v := m.NewField(fd)
	opts := protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: maxDepth}
	if err := opts.Unmarshal(data, v.Message().Interface()); err != nil {
		return bad(attrData, "does not decode as "+string(info.Message)+": "+protojsonReason(err))
	}
	m.Set(fd, v)
	return nil
}

// protojsonReason keeps the decoder's message but bounds its length (it may quote
// input).
func protojsonReason(err error) string {
	const max = 200
	s := err.Error()
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strings.ToValidUTF8(s, "?")
}

func bad(path, reason string) *validate.Problem {
	return &validate.Problem{Code: validate.CodeInvalidPayload, Path: path, Reason: reason}
}

// short keeps a hostile attribute name from making an error message large.
func short(s string) string {
	const max = 32
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strconv.Quote(s)
}
