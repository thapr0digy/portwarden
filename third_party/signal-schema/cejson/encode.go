package cejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slidehq/signal/schema/eventsv1"
)

// EncodeEvent writes ev in the canonical JSON form: attributes in a fixed order,
// only those set, data in protojson with proto field names, compacted. It writes
// what ev holds and does not validate it.
func EncodeEvent(ev *eventsv1.Event) ([]byte, error) {
	if ev == nil {
		return nil, errors.New("cejson: no event")
	}
	var buf bytes.Buffer
	w := objectWriter{buf: &buf}
	buf.WriteByte('{')
	w.attr(attrSpecVersion, SpecVersion)
	w.attr(attrID, ev.GetId())
	w.attr(attrType, ev.GetType())
	w.attr(attrSource, ev.GetSource())
	w.attr(attrSubject, ev.GetSubject())
	if ts := ev.GetTime(); ts != nil {
		w.attr(attrTime, ts.AsTime().UTC().Format(time.RFC3339Nano))
	}
	w.attr(attrDataSchema, ev.GetDataschema())
	if p := ev.GetProducer(); p != nil {
		// The decoder splits at the last slash, so a name with a slash always gets
		// the separator, even before an empty version.
		name := p.GetName()
		if p.GetVersion() != "" || strings.Contains(name, "/") {
			name += "/" + p.GetVersion()
		}
		w.attr(attrProducer, name)
		w.attr(attrAdapter, p.GetAdapter())
	}
	if s := ev.GetSequence(); s != nil {
		w.attr(attrRunID, s.GetRunId())
		if s.GetSeq() != 0 {
			w.attr(attrSequence, strconv.FormatUint(s.GetSeq(), 10))
		}
		w.attr(attrBootID, s.GetBootId())
		if s.GetRunNumber() != 0 {
			w.attr(attrRunNumber, strconv.FormatUint(s.GetRunNumber(), 10))
		}
	}
	w.attr(attrTraceparent, ev.GetTraceparent())
	w.attr(attrCorrelationID, ev.GetCorrelationid())
	w.attr(attrCausationID, ev.GetCausationid())
	if fd := ev.ProtoReflect().WhichOneof(eventsv1.DataOneof()); fd != nil {
		w.attr(attrDataContentType, dataContentType)
		data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(ev.ProtoReflect().Get(fd).Message().Interface())
		if err != nil {
			return nil, fmt.Errorf("cejson: data: %w", err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, data); err != nil {
			return nil, fmt.Errorf("cejson: data: %w", err)
		}
		w.key(attrData)
		buf.Write(compact.Bytes())
	}
	if w.err != nil {
		return nil, w.err
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// EncodeBatch writes the events as a JSON batch.
func EncodeBatch(b *eventsv1.Batch) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, ev := range b.GetEvents() {
		if i > 0 {
			buf.WriteByte(',')
		}
		one, err := EncodeEvent(ev)
		if err != nil {
			return nil, fmt.Errorf("cejson: event %d: %w", i, err)
		}
		buf.Write(one)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

type objectWriter struct {
	buf     *bytes.Buffer
	written bool // a member was written: the next one needs a comma
	err     error
}

func (w *objectWriter) key(k string) {
	if w.written {
		w.buf.WriteByte(',')
	}
	w.written = true
	w.buf.WriteString(strconv.Quote(k))
	w.buf.WriteByte(':')
}

// attr writes a string attribute, skipping an empty one.
func (w *objectWriter) attr(k, v string) {
	if v == "" || w.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		w.err = fmt.Errorf("cejson: %s: %w", k, err)
		return
	}
	w.key(k)
	w.buf.Write(b)
}
