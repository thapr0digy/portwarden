package publish

import (
	"fmt"
	"strings"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/spool"
)

// producerName names the agent in Signal's envelope (Producer.name).
const producerName = "portwarden-agent"

// legacyEnvelope is what every asm.v1 message carries about its run and place in it.
type legacyEnvelope interface {
	proto.Message
	GetEventId() string
	GetHostId() string
	GetRunId() string
	GetSeq() uint64
	GetBootId() string
	GetRunNumber() uint64
}

// keepPayload decodes a spooled asm.v1 body as Signal's payload message. Signal's agent
// payloads are asm.v1's messages with the same field numbers (schema common.proto,
// agent.proto) and the legacy envelope fields reserved, so the same bytes decode with
// those fields dropped as unknown.
var keepPayload = proto.UnmarshalOptions{DiscardUnknown: true}

// signalEvent converts one spooled message (subject asm.<host>.<suffix>, an asm.v1 body)
// to Signal's event: the type from the suffix, the id, time and run cursor (run id, seq,
// boot id, run number) from the legacy fields, so a message spooled under NATS goes out
// unchanged. A message of another host, an unknown subject or a body that does not decode
// can never be sent and is an error.
func signalEvent(m spool.Msg, hostID, agentVersion string) (*eventsv1.Event, error) {
	suffix, ok := strings.CutPrefix(m.Subject, "asm."+hostID+".")
	if !ok {
		return nil, fmt.Errorf("subject %q is not this host's", m.Subject)
	}
	if signalOnly(m.Subject) {
		ev, err := spooledSignalEvent(m, suffix, hostID)
		if err != nil {
			return nil, err
		}
		stampProducer(ev, hostID, agentVersion)
		return ev, nil
	}
	ev := &eventsv1.Event{}
	var env legacyEnvelope
	var at *timestamppb.Timestamp
	var err error
	switch suffix {
	case "listener.opened", "listener.closed", "listener.owner_changed":
		l, p := &asmv1.ListenerEvent{}, &eventsv1.ListenerChange{}
		err = decode(m.Data, l, p)
		env, at, ev.Type, ev.Data = l, l.GetObservedAt(), "asm."+suffix, &eventsv1.Event_ListenerChange{ListenerChange: p}
	case "snapshot":
		l, p := &asmv1.Snapshot{}, &eventsv1.HostSnapshot{}
		err = decode(m.Data, l, p)
		p.ListenerCount = uint32(len(p.GetListeners())) //nolint:gosec // at most the schema's 16,384
		env, at, ev.Type, ev.Data = l, l.GetTakenAt(), "asm.host.snapshot", &eventsv1.Event_HostSnapshot{HostSnapshot: p}
	case "heartbeat":
		l, p := &asmv1.Heartbeat{}, &eventsv1.Heartbeat{}
		err = decode(m.Data, l, p)
		env, at, ev.Type, ev.Data = l, l.GetAt(), "asm.agent.heartbeat", &eventsv1.Event_Heartbeat{Heartbeat: p}
	case "exposure.changed":
		l, p := &asmv1.ExposureEvent{}, &eventsv1.ExposureChange{}
		err = decode(m.Data, l, p)
		env, at, ev.Type, ev.Data = l, l.GetObservedAt(), "asm.exposure.changed", &eventsv1.Event_ExposureChange{ExposureChange: p}
	case "host.changed":
		l, p := &asmv1.HostEvent{}, &eventsv1.HostChange{}
		err = decode(m.Data, l, p)
		env, at = l, l.GetObservedAt()
		if l.GetStopping() {
			ev.Type, ev.Data = "asm.agent.stopping", &eventsv1.Event_AgentStopping{AgentStopping: &eventsv1.AgentStopping{}}
		} else {
			ev.Type, ev.Data = "asm.host.changed", &eventsv1.Event_HostChange{HostChange: p}
		}
	case "tamper":
		l, p := &asmv1.TamperEvent{}, &eventsv1.TamperChange{}
		err = decode(m.Data, l, p)
		env, at, ev.Type, ev.Data = l, l.GetObservedAt(), "asm.agent.tamper", &eventsv1.Event_TamperChange{TamperChange: p}
	case "proxy.routes":
		l, p := &asmv1.ProxyRoutes{}, &eventsv1.ProxyRoutes{}
		err = decode(m.Data, l, p)
		env, at, ev.Type, ev.Data = l, l.GetObservedAt(), "asm.proxy.routes", &eventsv1.Event_ProxyRoutes{ProxyRoutes: p}
	default:
		return nil, fmt.Errorf("subject %q has no Signal event type", m.Subject)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", m.Subject, err)
	}
	if env.GetHostId() != hostID || env.GetEventId() != m.ID || at == nil {
		return nil, fmt.Errorf("%s: the body's host, id or time does not match the message", m.Subject)
	}
	ev.Id, ev.Time = m.ID, at
	ev.Sequence = &eventsv1.Sequence{RunId: env.GetRunId(), Seq: env.GetSeq(), BootId: env.GetBootId(), RunNumber: env.GetRunNumber()}
	stampProducer(ev, hostID, agentVersion)
	return ev, nil
}

// stampProducer sets who sends ev: this host's agent, at this version.
func stampProducer(ev *eventsv1.Event, hostID, agentVersion string) {
	ev.Source, ev.Subject = "urn:asm:agent:"+hostID, string(eventsv1.SchemeHost)+hostID
	ev.Producer = &eventsv1.Producer{Name: producerName, Version: agentVersion}
}

// decode reads data as the legacy message (for its envelope fields) and as the payload.
func decode(data []byte, legacy, payload proto.Message) error {
	if err := proto.Unmarshal(data, legacy); err != nil {
		return err
	}
	return keepPayload.Unmarshal(data, payload)
}
