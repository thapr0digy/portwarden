package inventory

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

func ptr(s string) *string { return &s }

func TestFirewallFingerprintCarried(t *testing.T) {
	withFP := &asmv1.HostInfo{FirewallFingerprint: ptr("aa")}
	cases := []struct {
		name string
		msg  proto.Message
		fp   string
		ok   bool
	}{
		{"heartbeat", &asmv1.Heartbeat{FirewallFingerprint: ptr("aa")}, "aa", true},
		{"heartbeat unreadable", &asmv1.Heartbeat{FirewallFingerprint: ptr("")}, "", true},
		{"heartbeat from an agent without M7", &asmv1.Heartbeat{}, "", false},
		{"snapshot", &asmv1.Snapshot{Host: withFP}, "aa", true},
		{"snapshot without host block", &asmv1.Snapshot{}, "", false},
		{"snapshot host block without fingerprint", &asmv1.Snapshot{Host: &asmv1.HostInfo{Cloud: "aws"}}, "", false},
		{"listener", &asmv1.ListenerEvent{Host: withFP}, "aa", true},
		{"exposure", &asmv1.ExposureEvent{Host: withFP}, "aa", true},
		{"cloud exposure", &asmv1.ExposureEvent{Host: withFP, Origin: "cloud"}, "", false},
		{"host.changed", &asmv1.HostEvent{Host: withFP, Previous: &asmv1.HostInfo{FirewallFingerprint: ptr("bb")}}, "aa", true},
		{"proxy routes", &asmv1.ProxyRoutes{}, "", false},
		{"confirmation", &asmv1.ExposureConfirmation{}, "", false},
	}
	for _, c := range cases {
		fp, ok := FirewallFingerprint(c.msg)
		if fp != c.fp || ok != c.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, fp, ok, c.fp, c.ok)
		}
	}
}

func TestFirewallObserve(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	t1, t2 := t0.Add(time.Minute), t0.Add(2*time.Minute)

	var f Firewall
	f, write, changed := f.Observe("aa", t0)
	if !write || changed || f.Fingerprint != "aa" || !f.ChangedAt.Equal(t0) || !f.Known {
		t.Fatalf("first sight: %+v write=%v changed=%v (first sight sets it, and is not a change)", f, write, changed)
	}
	f, write, changed = f.Observe("aa", t1)
	if write || changed || !f.ChangedAt.Equal(t0) {
		t.Fatalf("same value: %+v write=%v changed=%v", f, write, changed)
	}
	f, write, changed = f.Observe("bb", t2)
	if !write || !changed || f.Fingerprint != "bb" || !f.ChangedAt.Equal(t2) {
		t.Fatalf("new value: %+v write=%v changed=%v", f, write, changed)
	}
	f, write, changed = f.Observe("", t2.Add(time.Minute))
	if !write || !changed || f.Fingerprint != "" {
		t.Fatalf("became unreadable: %+v write=%v changed=%v", f, write, changed)
	}
}

// fwStore is a fakeStore that keeps the firewall state the way the pg store does.
type fwStore struct {
	*fakeStore
	fw Firewall
}

func (f *fwStore) Apply(ctx context.Context, e Event) error {
	if e.Cursor != nil {
		if fp, ok := FirewallFingerprint(e.Msg); ok {
			f.fw, _, _ = f.fw.Observe(fp, e.Meta.StreamTime)
		}
	}
	return f.fakeStore.Apply(ctx, e)
}

func hb(run string, seq uint64, boot string, num uint64, fp string) *asmv1.Heartbeat {
	return &asmv1.Heartbeat{HostId: host, RunId: run, Seq: seq, BootId: boot, RunNumber: num, FirewallFingerprint: ptr(fp)}
}

func TestFirewallStaleMessagesDoNotRollBack(t *testing.T) {
	f := &fwStore{fakeStore: newFake()}
	c := &Consumer{Store: f}
	handle(t, c, "heartbeat", hb("01A", 1, "b1", 5, "aa"))
	handle(t, c, "heartbeat", hb("01A", 3, "b1", 5, "bb")) // a gap: applied, host needs a resync
	at := f.fw.ChangedAt
	handle(t, c, "heartbeat", hb("01A", 2, "b1", 5, "aa")) // late, older: skipped
	if f.fw.Fingerprint != "bb" || !f.fw.ChangedAt.Equal(at) {
		t.Fatalf("a late message rolled the fingerprint back: %+v", f.fw)
	}
	handle(t, c, "heartbeat", hb("01B", 1, "b1", 6, "cc")) // the next run
	handle(t, c, "heartbeat", hb("01Z", 9, "b1", 4, "aa")) // a leftover of an earlier run
	snapOld := &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 4, BootId: "b1", RunNumber: 5, Host: &asmv1.HostInfo{FirewallFingerprint: ptr("aa")}}
	handle(t, c, "snapshot", snapOld) // the retired run
	if f.fw.Fingerprint != "cc" {
		t.Fatalf("an earlier run's message rolled the fingerprint back: %+v", f.fw)
	}
	cloud := &asmv1.ExposureEvent{HostId: host, RunId: "svc", Listener: &asmv1.Listener{Key: "k"}, Host: &asmv1.HostInfo{FirewallFingerprint: ptr("dd")}}
	handle(t, c, "cloud", cloud)
	if f.fw.Fingerprint != "cc" {
		t.Fatalf("a backend event set the fingerprint: %+v", f.fw)
	}
}
