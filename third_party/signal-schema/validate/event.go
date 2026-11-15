package validate

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/slidehq/signal/schema/eventsv1"
)

// checkEvent runs the envelope rules, then the generic bounds and the payload rules
// over the whole event. The first failure wins.
func checkEvent(ev *eventsv1.Event, l Limits, now time.Time) *Problem {
	if ev == nil {
		return &Problem{Code: CodeInvalidPayload, Reason: "no event"}
	}
	p := envelope(ev, l, now)
	if p == nil {
		p = walker{l: l}.message(ev.ProtoReflect(), "", 0)
	}
	if p != nil {
		if IsULID(ev.GetId()) {
			p.ID = ev.GetId()
		}
		return p
	}
	return nil
}

func envelope(ev *eventsv1.Event, l Limits, now time.Time) *Problem {
	if n := proto.Size(ev); n > l.MaxEventBytes {
		return &Problem{Code: CodeTooLarge, Reason: fmt.Sprintf("event is %d bytes > %d", n, l.MaxEventBytes)}
	}
	if !IsULID(ev.GetId()) {
		return invalid("id", "not a ULID")
	}
	info, p := typeAndCase(ev)
	if p != nil {
		return p
	}
	if ds := ev.GetDataschema(); ds != "" && ds != info.DataSchema() {
		return &Problem{Code: CodeTypeMismatch, Path: "dataschema", Reason: fmt.Sprintf("want %s", info.DataSchema())}
	}
	if ev.GetSource() == "" {
		return invalid("source", "required")
	}
	if p := subject(ev, info); p != nil {
		return p
	}
	if p := eventTime(ev, l, now); p != nil {
		return p
	}
	if strings.Contains(ev.GetProducer().GetVersion(), "/") {
		return invalid("producer.version", `must not contain "/" (the JSON form joins name/version)`)
	}
	if p := sequence(ev, info); p != nil {
		return p
	}
	if tp := ev.GetTraceparent(); tp != "" && !isTraceparent(tp) {
		return invalid("traceparent", "not a W3C traceparent")
	}
	if c := ev.GetCorrelationid(); c != "" && !IsULID(c) {
		return invalid("correlationid", "not a ULID")
	}
	if c := ev.GetCausationid(); c != "" && !IsULID(c) {
		return invalid("causationid", "not a ULID")
	}
	switch info.Type {
	case "asm.scan.started":
		if ev.GetSubject() != string(eventsv1.SchemeScan)+ev.GetId() {
			return invalid("subject", "a scan.started subject is scan:<its own id>")
		}
	case "asm.scan.completed":
		if ev.GetCorrelationid() == "" {
			return invalid("correlationid", "required: the scan.started id")
		}
		if ev.GetSubject() != string(eventsv1.SchemeScan)+ev.GetCorrelationid() {
			return invalid("subject", "a scan.completed subject is scan:<the scan.started id>")
		}
	}
	return nil
}

func typeAndCase(ev *eventsv1.Event) (eventsv1.TypeInfo, *Problem) {
	if ev.GetType() == "" {
		return eventsv1.TypeInfo{}, invalid("type", "required")
	}
	info, ok := eventsv1.Lookup(ev.GetType())
	if !ok {
		return info, &Problem{Code: CodeUnknownType, Path: "type", Reason: "not in the registry"}
	}
	switch c := eventsv1.CaseOf(ev); {
	case c == info.Case:
		return info, nil
	case c != 0:
		return info, &Problem{Code: CodeTypeMismatch, Path: "data", Reason: fmt.Sprintf("payload case %d, the type needs %s (%d)", c, info.Message, info.Case)}
	case eventsv1.HasUnknownCase(ev):
		return info, &Problem{Code: CodeUnknownType, Path: "data", Reason: "a payload case this schema version does not know"}
	default:
		return info, invalid("data", "required")
	}
}

func subject(ev *eventsv1.Event, info eventsv1.TypeInfo) *Problem {
	if n := len(ev.GetSubject()); n > maxKeyLen {
		return &Problem{Code: CodeTooLarge, Path: "subject", Reason: fmt.Sprintf("%d bytes > %d", n, maxKeyLen)}
	}
	s, err := Key(ev.GetSubject())
	if err != nil {
		return invalid("subject", err.Error())
	}
	if !slices.Contains(info.Subjects, s) {
		return &Problem{Code: CodeForbiddenSubject, Path: "subject", Reason: fmt.Sprintf("%s subjects are not allowed for %s", s, info.Type)}
	}
	return nil
}

func eventTime(ev *eventsv1.Event, l Limits, now time.Time) *Problem {
	ts := ev.GetTime()
	if ts == nil {
		return &Problem{Code: CodeBadTime, Path: "time", Reason: "required"}
	}
	if err := ts.CheckValid(); err != nil {
		return &Problem{Code: CodeBadTime, Path: "time", Reason: "invalid timestamp"}
	}
	if ahead := ts.AsTime().Sub(now); ahead > l.MaxFuture {
		return &Problem{Code: CodeBadTime, Path: "time", Reason: fmt.Sprintf("%s ahead of the clock > %s", ahead.Round(time.Second), l.MaxFuture)}
	}
	return nil
}

func sequence(ev *eventsv1.Event, info eventsv1.TypeInfo) *Problem {
	seq := ev.GetSequence()
	// An empty Sequence is absent: the JSON form cannot tell the two apart.
	if seq == nil || proto.Size(seq) == 0 {
		if info.Sequenced {
			return invalid("sequence", "required for "+info.Type)
		}
		return nil
	}
	if !IsULID(seq.GetRunId()) {
		return invalid("sequence.run_id", "not a ULID")
	}
	if info.Sequenced && seq.GetSeq() == 0 {
		return invalid("sequence.seq", "starts at 1 for "+info.Type)
	}
	return nil
}

// isTraceparent checks the W3C trace-context form vv-<32 hex>-<16 hex>-ff, with a
// version other than ff and trace and parent ids not all zero.
func isTraceparent(s string) bool {
	if len(s) != 55 || s[2] != '-' || s[35] != '-' || s[52] != '-' {
		return false
	}
	ver, trace, parent, flags := s[0:2], s[3:35], s[36:52], s[53:55]
	if !IsHex(ver, 2) || ver == "ff" || !IsHex(trace, 32) || !IsHex(parent, 16) || !IsHex(flags, 2) {
		return false
	}
	return trace != "00000000000000000000000000000000" && parent != "0000000000000000"
}

func invalid(path, reason string) *Problem {
	return &Problem{Code: CodeInvalidPayload, Path: path, Reason: reason}
}
