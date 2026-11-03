package inventory

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
)

const host = "h1"

type fakeStore struct {
	cursors map[string]Cursor
	applied []Event
	silent  map[string]time.Time
	last    map[string]time.Time
}

func newFake() *fakeStore {
	return &fakeStore{cursors: map[string]Cursor{}, silent: map[string]time.Time{}, last: map[string]time.Time{}}
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
	if err := c.Handle(context.Background(), "asm."+host+"."+kind, marshal(t, m), Meta{StreamTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
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
	handle(t, c, "exposure.changed", &asmv1.ExposureEvent{HostId: host, RunId: "cloud-01X", Origin: "cloud"})
	handle(t, c, "exposure.confirmed", &asmv1.ExposureConfirmation{HostId: host, RunId: "verifier-01Y", Result: "confirmed"})
	if len(f.applied) != 3 || f.applied[1].Cursor != nil || f.applied[2].Cursor != nil {
		t.Fatalf("applied %+v", f.applied)
	}
	if cur := f.cursors[host]; cur.LastSeq != 1 {
		t.Fatalf("cursor moved: %+v", cur)
	}
	if len(changed) != 2 { // snapshot and the cloud exposure; not the probe result
		t.Fatalf("changed calls %v", changed)
	}
	// A body naming another host than its subject is dropped.
	handle(t, c, "listener.opened", &asmv1.ListenerEvent{HostId: "other", RunId: "01A", Seq: 2})
	if len(f.applied) != 3 {
		t.Fatal("impersonating message applied")
	}
}

func TestSilenceAndRecovery(t *testing.T) {
	f := newFake()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	c := &Consumer{Store: f, Liveness: liveness.New(90 * time.Second), Now: func() time.Time { return now }}
	f.last["old"] = now.Add(-time.Hour)
	if err := c.SeedLiveness(context.Background()); err != nil {
		t.Fatal(err)
	}
	hb := func(seq uint64, at time.Time) {
		t.Helper()
		if err := c.Handle(context.Background(), "asm."+host+".heartbeat",
			marshal(t, &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: seq}), Meta{StreamTime: at}); err != nil {
			t.Fatal(err)
		}
	}
	hb(1, now)
	if err := c.CheckSilence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.silent["old"]; !ok {
		t.Fatal("seeded host with an hour-old heartbeat not silent")
	}
	if _, ok := f.silent[host]; ok {
		t.Fatal("live host silent")
	}
	now = now.Add(2 * time.Minute)
	_ = c.CheckSilence(context.Background())
	if since := f.silent[host]; since.IsZero() {
		t.Fatal("host not silent after 2 minutes")
	}
	hb(2, now)
	if since, ok := f.silent[host]; !ok || !since.IsZero() {
		t.Fatalf("host not recovered: %v %v", since, ok)
	}
}
