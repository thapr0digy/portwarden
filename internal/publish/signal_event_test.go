package publish

import (
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/spool"
)

// legacyOnly are asm.v1 fields Signal's payloads leave out on purpose: the per-message
// envelope (now Event's id, time and sequence) and what the event type carries instead.
var legacyOnly = map[protoreflect.Name]bool{
	"event_id": true, "host_id": true, "run_id": true, "seq": true, "boot_id": true, "run_number": true,
	"observed_at": true, "at": true, "taken_at": true,
	"kind":                  true, // ListenerEvent: the type says opened, closed or owner_changed
	"stopping":              true, // HostEvent: asm.agent.stopping is its own type
	"origin":                true, // ExposureEvent: agent events are the agent's
	"dropped_foreign_netns": true, // Heartbeat: deprecated, always 0
	"routes":                true, // ProxyState: unused since M4 (each set is its own event)
}

// sameShape fails when a field the agent fills would not arrive in Signal's message with
// the same meaning: every asm.v1 field number is in the payload with the same name, kind
// and cardinality (recursively), or is one the payload leaves out on purpose.
func sameShape(t *testing.T, legacy, payload protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[legacy.FullName()] {
		return
	}
	seen[legacy.FullName()] = true
	fields := legacy.Fields()
	for i := range fields.Len() {
		lf := fields.Get(i)
		pf := payload.Fields().ByNumber(lf.Number())
		where := string(legacy.FullName()) + "." + string(lf.Name())
		if pf == nil {
			if !legacyOnly[lf.Name()] {
				t.Errorf("%s (#%d) has no field in %s", where, lf.Number(), payload.FullName())
			}
			continue
		}
		if pf.Name() != lf.Name() || pf.Kind() != lf.Kind() || pf.Cardinality() != lf.Cardinality() || pf.IsMap() != lf.IsMap() {
			t.Errorf("%s (#%d) is %s %s %s in %s", where, lf.Number(), pf.Cardinality(), pf.Kind(), pf.Name(), payload.FullName())
			continue
		}
		switch {
		case lf.IsMap():
			if lf.MapValue().Kind() != pf.MapValue().Kind() || lf.MapKey().Kind() != pf.MapKey().Kind() {
				t.Errorf("%s: map types differ", where)
			}
		case lf.Kind() == protoreflect.MessageKind:
			sameShape(t, lf.Message(), pf.Message(), seen)
		case lf.Kind() == protoreflect.EnumKind:
			lv, pv := lf.Enum().Values(), pf.Enum().Values()
			for j := range lv.Len() {
				if v := pv.ByNumber(lv.Get(j).Number()); v == nil || v.Name() != lv.Get(j).Name() {
					t.Errorf("%s: enum value %s (%d) differs", where, lv.Get(j).Name(), lv.Get(j).Number())
				}
			}
		}
	}
}

// The design's assumption: Signal's agent payloads are asm.v1's messages with the same
// field numbers, so signalEvent decodes the spooled bytes as the payload directly.
func TestSignalPayloadsKeepAsmV1FieldNumbers(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	for _, pair := range []struct{ legacy, payload proto.Message }{
		{&asmv1.ListenerEvent{}, &eventsv1.ListenerChange{}},
		{&asmv1.Snapshot{}, &eventsv1.HostSnapshot{}},
		{&asmv1.Heartbeat{}, &eventsv1.Heartbeat{}},
		{&asmv1.ExposureEvent{}, &eventsv1.ExposureChange{}},
		{&asmv1.HostEvent{}, &eventsv1.HostChange{}},
		{&asmv1.TamperEvent{}, &eventsv1.TamperChange{}},
		{&asmv1.ProxyRoutes{}, &eventsv1.ProxyRoutes{}},
	} {
		sameShape(t, pair.legacy.ProtoReflect().Descriptor(), pair.payload.ProtoReflect().Descriptor(), seen)
	}
}

func spooled(t *testing.T, suffix string, m proto.Message) spool.Msg {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r := m.ProtoReflect()
	id := r.Get(r.Descriptor().Fields().ByName("event_id")).String()
	seq := r.Get(r.Descriptor().Fields().ByName("seq")).Uint()
	return spool.Msg{Subject: "asm." + testHost + "." + suffix, ID: id, Seq: seq, Data: b}
}

func TestSignalEventMapsEveryAgentSubject(t *testing.T) {
	run, at := ulid.Make().String(), timestamppb.New(time.Now().Add(-time.Minute))
	id := func() string { return ulid.Make().String() }
	host := &asmv1.HostInfo{Cloud: "aws", InstanceId: "i-1", AgentVersion: "v1"}
	lis := &asmv1.Listener{Netns: 4026531840, Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Key: "4026531840/tcp/0.0.0.0:8080"}
	proc := &asmv1.Process{Pid: 7, Comm: "svc", Cmdline: []string{"svc", "--token=***"}}
	cases := []struct {
		suffix, wantType string
		msg              proto.Message
		check            func(*eventsv1.Event) bool
	}{
		{"listener.opened", "asm.listener.opened", &asmv1.ListenerEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 1, ObservedAt: at,
			Kind: asmv1.Kind_OPENED, Source: asmv1.Source_EBPF, Listener: lis, Processes: []*asmv1.Process{proc}, Host: host},
			func(e *eventsv1.Event) bool {
				lc := e.GetListenerChange()
				return lc.GetListener().GetPort() == 8080 && lc.GetSource() == eventsv1.ListenerChange_EBPF &&
					lc.GetProcesses()[0].GetCmdline()[1] == "--token=***" && lc.GetHost().GetInstanceId() == "i-1"
			}},
		{"listener.closed", "asm.listener.closed", &asmv1.ListenerEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 2, ObservedAt: at, Kind: asmv1.Kind_CLOSED, Listener: lis},
			func(e *eventsv1.Event) bool { return e.GetListenerChange().GetListener().GetKey() == lis.Key }},
		{"listener.owner_changed", "asm.listener.owner_changed", &asmv1.ListenerEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 3, ObservedAt: at,
			Kind: asmv1.Kind_OWNER_CHANGED, Listener: lis, PreviousProcesses: []*asmv1.Process{proc}},
			func(e *eventsv1.Event) bool { return e.GetListenerChange().GetPreviousProcesses()[0].GetPid() == 7 }},
		{"snapshot", "asm.host.snapshot", &asmv1.Snapshot{EventId: id(), HostId: testHost, RunId: run, Seq: 4, TakenAt: at,
			Listeners: []*asmv1.ListenerState{{Listener: lis}, {Listener: lis}}, Host: host},
			func(e *eventsv1.Event) bool {
				s := e.GetHostSnapshot()
				return len(s.GetListeners()) == 2 && s.GetListenerCount() == 2 && !s.GetUnchanged()
			}},
		{"heartbeat", "asm.agent.heartbeat", &asmv1.Heartbeat{EventId: id(), HostId: testHost, RunId: run, Seq: 5, At: at, RingbufDrops: 3, QueueDrops: 4},
			func(e *eventsv1.Event) bool {
				return e.GetHeartbeat().GetRingbufDrops() == 3 && e.GetHeartbeat().GetQueueDrops() == 4
			}},
		{"exposure.changed", "asm.exposure.changed", &asmv1.ExposureEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 6, ObservedAt: at, Listener: lis,
			Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_BOUND}, Trigger: "firewall"},
			func(e *eventsv1.Event) bool {
				return e.GetExposureChange().GetExposure().GetLevel() == eventsv1.ExposureLevel_EXPOSURE_BOUND && e.GetExposureChange().GetTrigger() == "firewall"
			}},
		{"host.changed", "asm.host.changed", &asmv1.HostEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 7, ObservedAt: at, Host: host, Previous: &asmv1.HostInfo{}},
			func(e *eventsv1.Event) bool { return e.GetHostChange().GetHost().GetCloud() == "aws" }},
		{"host.changed", "asm.agent.stopping", &asmv1.HostEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 8, ObservedAt: at, Host: host, Previous: host, Stopping: true},
			func(e *eventsv1.Event) bool { return e.GetAgentStopping() != nil }},
		{"tamper", "asm.agent.tamper", &asmv1.TamperEvent{EventId: id(), HostId: testHost, RunId: run, Seq: 9, ObservedAt: at,
			Raised: []*asmv1.TamperFlag{{Kind: "ptraced", Subject: "self"}}},
			func(e *eventsv1.Event) bool { return e.GetTamperChange().GetRaised()[0].GetKind() == "ptraced" }},
		{"proxy.routes", "asm.proxy.routes", &asmv1.ProxyRoutes{EventId: id(), HostId: testHost, RunId: run, Seq: 10, ObservedAt: at,
			Proxy: &asmv1.Proxy{Id: "nginx", Kind: "nginx"}, Routes: []*asmv1.ProxyRoute{{ServerNames: []string{"example.com"}}}, Trigger: "config"},
			func(e *eventsv1.Event) bool {
				return e.GetProxyRoutes().GetRoutes()[0].GetServerNames()[0] == "example.com"
			}},
	}
	for _, c := range cases {
		m := spooled(t, c.suffix, c.msg)
		ev, err := signalEvent(m, testHost, "v1.2.3")
		if err != nil {
			t.Fatalf("%s: %v", c.wantType, err)
		}
		if ev.GetType() != c.wantType || ev.GetId() != m.ID || !ev.GetTime().AsTime().Equal(at.AsTime()) ||
			ev.GetSubject() != "host:"+testHost || ev.GetSource() != "urn:asm:agent:"+testHost ||
			ev.GetSequence().GetRunId() != run || ev.GetSequence().GetSeq() != m.Seq ||
			ev.GetProducer().GetName() != "portwarden-agent" || ev.GetProducer().GetVersion() != "v1.2.3" {
			t.Errorf("%s: envelope %v", c.wantType, ev)
		}
		if !c.check(ev) {
			t.Errorf("%s: payload %v", c.wantType, ev)
		}
		// What Signal's door runs first.
		if err := validate.Event(ev, validate.Options{}); err != nil {
			t.Errorf("%s: the schema refuses it: %v", c.wantType, err)
		}
	}
}

func TestSignalEventRefusesWhatCanNeverBeSent(t *testing.T) {
	at := timestamppb.Now()
	good := &asmv1.Heartbeat{EventId: ulid.Make().String(), HostId: testHost, RunId: ulid.Make().String(), Seq: 1, At: at}
	m := spooled(t, "heartbeat", good)
	for name, bad := range map[string]spool.Msg{
		"another host's subject":       {Subject: "asm.ffffffffffffffffffffffffffffffff.heartbeat", ID: m.ID, Data: m.Data},
		"an unknown subject":           {Subject: "asm." + testHost + ".probe.request", ID: m.ID, Data: m.Data},
		"a body that is not one":       {Subject: m.Subject, ID: m.ID, Data: []byte{0xff, 0xff, 0xff}},
		"an id that is not the body's": {Subject: m.Subject, ID: ulid.Make().String(), Data: m.Data},
	} {
		if _, err := signalEvent(bad, testHost, "v1"); err == nil {
			t.Errorf("%s: converted", name)
		}
	}
	other := proto.Clone(good).(*asmv1.Heartbeat)
	other.HostId = strings.Repeat("e", 32)
	if _, err := signalEvent(spooled(t, "heartbeat", other), testHost, "v1"); err == nil {
		t.Error("a body of another host converted")
	}
	noTime := proto.Clone(good).(*asmv1.Heartbeat)
	noTime.At = nil
	if _, err := signalEvent(spooled(t, "heartbeat", noTime), testHost, "v1"); err == nil {
		t.Error("a body with no time converted")
	}
}
