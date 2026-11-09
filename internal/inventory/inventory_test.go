package inventory

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
)

const host = "h1"

type fakeStore struct {
	cursors   map[string]Cursor
	applied   []Event
	silent    map[string]time.Time
	last      map[string]time.Time
	forgotten map[string]Mark
	forgets   int
}

func newFake() *fakeStore {
	return &fakeStore{cursors: map[string]Cursor{}, silent: map[string]time.Time{}, last: map[string]time.Time{},
		forgotten: map[string]Mark{}}
}

func (f *fakeStore) Forget(_ context.Context, h string, m Mark) (bool, error) {
	f.forgets++
	_, existed := f.cursors[h]
	delete(f.cursors, h)
	delete(f.last, h)
	if old, ok := f.forgotten[h]; !ok || !old.Stream.Equal(m.Stream) || m.Seq > old.Seq {
		f.forgotten[h] = m
	}
	return existed, nil
}

func (f *fakeStore) ForgottenMark(_ context.Context, h string) (Mark, bool, error) {
	m, ok := f.forgotten[h]
	return m, ok, nil
}

func (f *fakeStore) PruneMarks(_ context.Context, stream time.Time, last uint64) (int64, error) {
	var n int64
	for h, m := range f.forgotten {
		if !m.Stream.Equal(stream) || m.Seq > last {
			delete(f.forgotten, h)
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) Cursor(_ context.Context, h string) (Cursor, bool, error) {
	c, ok := f.cursors[h]
	return c, ok, nil
}

func (f *fakeStore) Apply(_ context.Context, e Event) error {
	f.applied = append(f.applied, e)
	if e.Cursor != nil {
		f.cursors[e.Meta.Host] = *e.Cursor
	}
	return nil
}

func (f *fakeStore) SetCursor(_ context.Context, h string, c Cursor) error {
	f.cursors[h] = c
	return nil
}

func (f *fakeStore) SetSilent(_ context.Context, h string, since time.Time) error {
	f.silent[h] = since
	return nil
}

func (f *fakeStore) LastHeartbeats(context.Context) (map[string]time.Time, error) { return f.last, nil }

type fakeSnaps struct {
	snap *asmv1.Snapshot
}

func (f *fakeSnaps) LatestSnapshot(_ context.Context, h string) (*asmv1.Snapshot, Meta, error) {
	if f.snap == nil {
		return nil, Meta{}, ErrNoSnapshot
	}
	return f.snap, Meta{StreamSeq: 99}, nil
}

func marshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func opened(run string, seq uint64) *asmv1.ListenerEvent {
	return &asmv1.ListenerEvent{HostId: host, RunId: run, Seq: seq, Kind: asmv1.Kind_OPENED,
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: uint32(8000 + seq), Key: "1/tcp/0.0.0.0:80"}}
}

func handle(t *testing.T, c *Consumer, kind string, m proto.Message) {
	t.Helper()
	subject := "asm." + host + "." + kind
	switch kind {
	case "cloud":
		subject = "pwb.cloud." + host + ".exposure"
	case "verifier":
		subject = "pwb.verifier." + host + ".exposure"
	}
	if err := c.Handle(context.Background(), subject, marshal(t, m), Meta{StreamTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func handleErr(c *Consumer, subject string, m proto.Message) error {
	b, _ := proto.Marshal(m)
	return c.Handle(context.Background(), subject, b, Meta{StreamTime: time.Now()})
}

// seqs lists the agent seq of each applied event (0 for backend events).
func seqs(f *fakeStore) []uint64 {
	var out []uint64
	for _, e := range f.applied {
		out = append(out, e.Msg.(interface{ GetSeq() uint64 }).GetSeq())
	}
	return out
}

func TestInOrderAndDuplicates(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	handle(t, c, "listener.opened", opened("01A", 2))
	handle(t, c, "listener.opened", opened("01A", 2)) // redelivery
	handle(t, c, "listener.opened", opened("01A", 3))
	if got := seqs(f); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("applied seqs %v", got)
	}
	if cur := f.cursors[host]; cur.LastSeq != 3 || cur.RunID != "01A" || cur.NeedsResync {
		t.Fatalf("cursor %+v", cur)
	}
}

func TestGapReloadsNewerSnapshot(t *testing.T) {
	f := newFake()
	snaps := &fakeSnaps{}
	c := &Consumer{Store: f, Snapshots: snaps}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	handle(t, c, "listener.opened", opened("01A", 2))
	snaps.snap = &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 5}
	handle(t, c, "listener.opened", opened("01A", 4)) // 3 is lost; snapshot 5 covers it
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 5})
	handle(t, c, "listener.opened", opened("01A", 6))
	if got := seqs(f); !slices.Equal(got, []uint64{1, 2, 5, 6}) {
		t.Fatalf("applied seqs %v", got)
	}
	if cur := f.cursors[host]; cur.LastSeq != 6 || cur.NeedsResync {
		t.Fatalf("cursor %+v", cur)
	}
}

func TestGapWithOlderSnapshotNeedsResync(t *testing.T) {
	f := newFake()
	snaps := &fakeSnaps{snap: &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1}}
	c := &Consumer{Store: f, Snapshots: snaps}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	handle(t, c, "listener.opened", opened("01A", 4))
	if cur := f.cursors[host]; cur.LastSeq != 4 || !cur.NeedsResync {
		t.Fatalf("cursor %+v", cur)
	}
	handle(t, c, "listener.opened", opened("01A", 5))
	if !f.cursors[host].NeedsResync {
		t.Fatal("resync cleared before a snapshot")
	}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 6})
	if cur := f.cursors[host]; cur.NeedsResync || cur.LastSeq != 6 {
		t.Fatalf("cursor after snapshot %+v", cur)
	}
}

func TestRuns(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01B", Seq: 1})
	handle(t, c, "listener.opened", opened("01A", 7)) // older run's leftover
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01C", Seq: 1})
	handle(t, c, "listener.opened", opened("01C", 2))
	if got := seqs(f); !slices.Equal(got, []uint64{1, 1, 2}) {
		t.Fatalf("applied seqs %v", got)
	}
	if cur := f.cursors[host]; cur.RunID != "01C" || cur.LastSeq != 2 {
		t.Fatalf("cursor %+v", cur)
	}
	// A new run whose first message is not seq 1 is a gap.
	handle(t, c, "heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01D", Seq: 3})
	if !f.cursors[host].NeedsResync {
		t.Fatal("new run starting at seq 3 must need a resync")
	}
}

func TestBackendEventsLeaveTheCursor(t *testing.T) {
	f := newFake()
	var changed []string
	c := &Consumer{Store: f, Changed: func(h string) { changed = append(changed, h) }}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	handle(t, c, "cloud", &asmv1.ExposureEvent{HostId: host, RunId: "cloud-01X"})
	handle(t, c, "verifier", &asmv1.ExposureConfirmation{HostId: host, RunId: "verifier-01Y", Result: "confirmed"})
	if len(f.applied) != 3 || f.applied[1].Cursor != nil || f.applied[2].Cursor != nil {
		t.Fatalf("applied %+v", f.applied)
	}
	if f.applied[1].Msg.(*asmv1.ExposureEvent).GetOrigin() != "cloud" || f.applied[1].Meta.Origin != "cloud" {
		t.Fatal("origin must come from the subject")
	}
	if cur := f.cursors[host]; cur.LastSeq != 1 {
		t.Fatalf("cursor moved: %+v", cur)
	}
	if len(changed) != 1 { // only the agent's snapshot triggers the cloud look-up
		t.Fatalf("changed calls %v", changed)
	}
}

// Forgeries in the host's own namespace are permanent errors (quarantined), and a body
// naming another host too.
func TestForgedOriginsAreQuarantined(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	for _, tc := range []struct {
		subject string
		m       proto.Message
	}{
		{"asm." + host + ".exposure.changed", &asmv1.ExposureEvent{HostId: host, RunId: "01A", Seq: 2, Origin: "cloud"}},
		{"asm." + host + ".exposure.confirmed", &asmv1.ExposureConfirmation{HostId: host, Result: "confirmed"}},
		{"asm." + host + ".listener.opened", &asmv1.ListenerEvent{HostId: "other", RunId: "01A", Seq: 2}},
		{"pwb.verifier." + host + ".exposure", &asmv1.ExposureConfirmation{HostId: "other"}},
	} {
		if err := handleErr(c, tc.subject, tc.m); !svc.IsPermanent(err) {
			t.Errorf("%s: err %v, want permanent", tc.subject, err)
		}
	}
	if err := c.Handle(context.Background(), "asm."+host+".heartbeat", []byte{0xff, 0xff}, Meta{}); !svc.IsPermanent(err) {
		t.Errorf("undecodable: %v", err)
	}
	if len(f.applied) != 1 {
		t.Fatalf("forgeries applied: %d", len(f.applied))
	}
}

// Runs are ordered by (boot id, run number), not by the run id's clock: a later run whose
// ULID sorts lower (the clock stepped back) is still the new run, and the old run's late
// messages are skipped.
func TestRunOrderByBootAndCounter(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01Z", Seq: 1, BootId: "b1", RunNumber: 7})
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1, BootId: "b1", RunNumber: 8})
	if cur := f.cursors[host]; cur.RunID != "01A" || cur.RunNumber != 8 || !slices.Contains(cur.Retired, "01Z") {
		t.Fatalf("clock-stepped-back run not adopted: %+v", cur)
	}
	handle(t, c, "listener.opened", &asmv1.ListenerEvent{HostId: host, RunId: "01Z", Seq: 2, BootId: "b1", RunNumber: 7})
	if len(f.applied) != 2 {
		t.Fatal("retired run's leftover applied")
	}
	// A new boot is always a new run, whatever its counter (the spool may have been wiped).
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01B", Seq: 1, BootId: "b2", RunNumber: 1})
	if cur := f.cursors[host]; cur.RunID != "01B" || cur.BootID != "b2" {
		t.Fatalf("new boot: %+v", cur)
	}
	// A run id never seen, with a lower counter in the same boot, is not adopted.
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01C", Seq: 1, BootId: "b2", RunNumber: 0})
	if f.cursors[host].RunID != "01B" {
		t.Fatal("an unnumbered run replaced a numbered one")
	}
	if got := runOrder(Cursor{RunID: "01B", RunNumber: 3, BootID: "b"}, true, "01X", "b", 2); got != runSkip {
		t.Fatalf("lower counter same boot: %v", got)
	}
}

func TestSilenceAndRecovery(t *testing.T) {
	f := newFake()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	after := 90 * time.Second
	c := &Consumer{Store: f, Liveness: liveness.New(after), Feed: liveness.NewFeed(after, now), Now: func() time.Time { return now }}
	f.last["old"] = now.Add(-time.Hour)
	if err := c.SeedLiveness(context.Background()); err != nil {
		t.Fatal(err)
	}
	hb := func(seq uint64, h string) {
		t.Helper()
		if err := handleErr(c, "asm."+h+".heartbeat", &asmv1.Heartbeat{HostId: h, RunId: "01A", Seq: seq}); err != nil {
			t.Fatal(err)
		}
	}
	other := 0
	beat := func() { other++; hb(uint64(other), "busy") } // keeps the feed alive
	beat()
	hb(1, host)
	now = now.Add(time.Minute)
	beat()
	_ = c.CheckSilence(context.Background())
	if len(f.silent) != 0 {
		t.Fatal("judged within the start-up grace")
	}
	now = now.Add(time.Minute)
	beat()
	_ = c.CheckSilence(context.Background())
	if since := f.silent[host]; since.IsZero() {
		t.Fatal("host not silent after 2 minutes")
	}
	if _, ok := f.silent["old"]; !ok {
		t.Fatal("a seeded host that never spoke again must go silent")
	}
	if _, ok := f.silent["busy"]; ok {
		t.Fatal("live host silent")
	}
	hb(2, host)
	if since, ok := f.silent[host]; !ok || !since.IsZero() {
		t.Fatalf("host not recovered: %v %v", since, ok)
	}
}

// When nothing arrives from any host, the feed is stalled and no host is marked silent.
func TestFeedStallSuppressesHostSilence(t *testing.T) {
	f := newFake()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	c := &Consumer{Store: f, Liveness: liveness.New(time.Minute), Feed: liveness.NewFeed(time.Minute, now), Now: func() time.Time { return now }}
	_ = handleErr(c, "asm.a.heartbeat", &asmv1.Heartbeat{HostId: "a", RunId: "01A", Seq: 1})
	_ = handleErr(c, "asm.b.heartbeat", &asmv1.Heartbeat{HostId: "b", RunId: "01A", Seq: 1})
	for range 10 {
		now = now.Add(30 * time.Second)
		_ = c.CheckSilence(context.Background())
	}
	if len(f.silent) != 0 {
		t.Fatalf("hosts marked silent while the feed was stalled: %v", f.silent)
	}
}

// The clean-shutdown marker changes no host block, so it must not start a cloud look-up.
func TestStoppingHostEventSkipsLookup(t *testing.T) {
	f := newFake()
	var changed []string
	c := &Consumer{Store: f, Changed: func(h string) { changed = append(changed, h) }}
	hb := &asmv1.HostInfo{Cloud: "aws"}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1, Host: hb})
	handle(t, c, "host.changed", &asmv1.HostEvent{HostId: host, RunId: "01A", Seq: 2, Host: hb, Previous: hb, Stopping: true})
	if len(f.applied) != 2 || f.cursors[host].LastSeq != 2 {
		t.Fatalf("the marker must be applied and move the cursor: %+v", f.cursors[host])
	}
	if len(changed) != 1 {
		t.Fatalf("changed calls %v, want only the snapshot's", changed)
	}
}
