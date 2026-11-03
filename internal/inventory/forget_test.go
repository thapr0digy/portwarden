package inventory

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
)

// handleAt handles a message stored at stream sequence seq.
func handleAt(t *testing.T, c *Consumer, subject string, m proto.Message, seq uint64) {
	t.Helper()
	if err := c.Handle(context.Background(), subject, marshal(t, m), Meta{StreamSeq: seq, StreamTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

type fakeAnnouncer struct {
	hosts []string
	seq   uint64
	err   error
}

func (a *fakeAnnouncer) announce(_ context.Context, h string) (uint64, error) {
	if a.err != nil {
		return 0, a.err
	}
	a.hosts = append(a.hosts, h)
	return a.seq, nil
}

func TestForgetAnnouncesThenForgets(t *testing.T) {
	f := newFake()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	ann := &fakeAnnouncer{seq: 20}
	c := &Consumer{Store: f, Liveness: liveness.New(time.Minute), Now: func() time.Time { return now }, Announce: ann.announce}
	c.SetStream(streamT)
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	handleAt(t, c, "asm.keep.heartbeat", &asmv1.Heartbeat{HostId: "keep", RunId: "01A", Seq: 1}, 11)

	res, err := c.Forget(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ann.hosts, []string{host}) || res != (ForgetResult{Host: host, Existed: true, StreamSeq: 20}) {
		t.Fatalf("announced %v, result %+v", ann.hosts, res)
	}
	if f.forgotten[host] != (Mark{Seq: 20, Stream: streamT}) {
		t.Fatalf("store mark %+v, want seq 20 of this stream", f.forgotten[host])
	}
	if _, ok := f.cursors[host]; ok {
		t.Fatal("the host's state is still stored")
	}
	if _, _, _, known := c.Liveness.State(host); known {
		t.Fatal("the forgotten host is still tracked for silence")
	}
	if _, _, _, known := c.Liveness.State("keep"); !known {
		t.Fatal("another host was dropped")
	}

	// Forgetting a host the inventory does not hold still announces it (the alerter may).
	res, err = c.Forget(context.Background(), "gone")
	if err != nil || res.Existed || res.StreamSeq != 20 {
		t.Fatalf("unknown host: %+v %v", res, err)
	}
}

func TestForgetRefusesBadHostIDs(t *testing.T) {
	ann := &fakeAnnouncer{seq: 1}
	c := &Consumer{Store: newFake(), Announce: ann.announce}
	c.SetStream(streamT)
	for _, bad := range []string{"", "a.b", "*", ">", "a b", "inventory"} {
		if _, err := c.Forget(context.Background(), bad); !errors.Is(err, ErrBadHost) {
			t.Errorf("%q: err %v, want ErrBadHost", bad, err)
		}
	}
	if len(ann.hosts) != 0 {
		t.Fatalf("announced %v", ann.hosts)
	}
}

// Without the announcement the alerter would keep paging: nothing is forgotten.
func TestForgetAnnounceFailureChangesNothing(t *testing.T) {
	f := newFake()
	ann := &fakeAnnouncer{err: errors.New("nats down")}
	c := &Consumer{Store: f, Liveness: liveness.New(time.Minute), Announce: ann.announce}
	c.SetStream(streamT)
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	if _, err := c.Forget(context.Background(), host); err == nil {
		t.Fatal("forget succeeded without its announcement")
	}
	if _, ok := f.cursors[host]; !ok || f.forgets != 0 {
		t.Fatal("the store changed")
	}
	if _, _, _, known := c.Liveness.State(host); !known {
		t.Fatal("liveness changed")
	}
}

var streamT = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func TestForgetRefusedBeforeTheStreamIsKnown(t *testing.T) {
	c := &Consumer{Store: newFake(), Announce: (&fakeAnnouncer{seq: 1}).announce}
	if _, err := c.Forget(context.Background(), host); !errors.Is(err, ErrNoStream) {
		t.Fatalf("err %v, want ErrNoStream", err)
	}
}

// Forget waits for the message being handled only as long as its context allows.
func TestForgetWaitsUnderItsContext(t *testing.T) {
	c := &Consumer{Store: newFake(), Announce: (&fakeAnnouncer{seq: 1}).announce}
	c.SetStream(streamT)
	if err := c.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Forget(ctx, host); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want a deadline", err)
	}
	c.unlock()
	if _, err := c.Forget(context.Background(), host); err != nil {
		t.Fatal(err)
	}
}

// A recreated stream starts its sequences over: a mark from the old one means nothing,
// and a host id reused on the new stream is applied from its first message.
func TestAnotherStreamsMarkIsIgnored(t *testing.T) {
	f := newFake()
	old := streamT.Add(-24 * time.Hour)
	f.forgotten[host] = Mark{Seq: 500, Stream: old}
	c := &Consumer{Store: f}
	c.SetStream(streamT)
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	handleAt(t, c, "pwb.cloud."+host+".exposure", &asmv1.ExposureEvent{HostId: host, Listener: &asmv1.Listener{Key: "k"}}, 11)
	if len(f.applied) != 2 {
		t.Fatalf("applied %d of 2: an old stream's mark was used", len(f.applied))
	}
	// At start the stale marks go: another stream's, and one past the last sequence.
	f.forgotten["reset"] = Mark{Seq: 900, Stream: streamT}
	f.forgotten["keep"] = Mark{Seq: 5, Stream: streamT}
	if n, _ := f.PruneMarks(context.Background(), streamT, 100); n != 2 || len(f.forgotten) != 1 {
		t.Fatalf("pruned %d, left %v", n, f.forgotten)
	}
}

// The inventory consumes its own announcement: one whose database step failed is applied
// when the consumer reaches it; one already applied is not applied again.
func TestOwnAnnouncementIsApplied(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f, Liveness: liveness.New(time.Minute)}
	c.SetStream(streamT)
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	handleAt(t, c, "pwb.inventory."+host+".forgotten", &asmv1.HostForgotten{HostId: host}, 30)
	if f.forgotten[host] != (Mark{Seq: 30, Stream: streamT}) || f.forgets != 1 {
		t.Fatalf("mark %+v after %d forgets", f.forgotten[host], f.forgets)
	}
	if _, _, _, known := c.Liveness.State(host); known {
		t.Fatal("liveness kept the host")
	}
	handleAt(t, c, "pwb.inventory."+host+".forgotten", &asmv1.HostForgotten{HostId: host}, 30) // redelivery
	if f.forgets != 1 {
		t.Fatal("an applied announcement was applied again")
	}
	if err := handleErr(c, "pwb.inventory."+host+".forgotten", &asmv1.HostForgotten{HostId: "other"}); !svc.IsPermanent(err) {
		t.Fatalf("a body naming another host: %v", err)
	}
}

func TestForgetWithoutAnnouncerIsRefused(t *testing.T) {
	c := &Consumer{Store: newFake()}
	if _, err := c.Forget(context.Background(), host); err == nil {
		t.Fatal("forget without an announcer succeeded")
	}
}

// Messages stored before the announcement are leftovers of the forgotten host; later ones
// are a new host.
func TestForgottenHostLeftoversSkipped(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f, Announce: (&fakeAnnouncer{seq: 20}).announce}
	c.SetStream(streamT)
	handleAt(t, c, "asm."+host+".snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1}, 10)
	if _, err := c.Forget(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	before := len(f.applied)
	handleAt(t, c, "asm."+host+".listener.opened", opened("01A", 2), 15)
	handleAt(t, c, "pwb.cloud."+host+".exposure", &asmv1.ExposureEvent{HostId: host, Listener: &asmv1.Listener{Key: "k"}}, 18)
	handleAt(t, c, "pwb.verifier."+host+".exposure", &asmv1.ExposureConfirmation{HostId: host, Listener: &asmv1.Listener{Key: "k"}}, 19)
	if len(f.applied) != before {
		t.Fatalf("applied %d leftovers of the forgotten host", len(f.applied)-before)
	}
	// A verdict the cloud look-up or verifier started before the forget may be stored after
	// the announcement: while the host has not come back it is dropped too (backend events
	// are only ever about hosts the inventory holds).
	handleAt(t, c, "pwb.cloud."+host+".exposure", &asmv1.ExposureEvent{HostId: host, Listener: &asmv1.Listener{Key: "k"}}, 20)
	if len(f.applied) != before {
		t.Fatal("a late verdict for the forgotten host was applied")
	}
	// The host comes back: a new host, from whatever seq its agent is at.
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 3}, 21)
	if len(f.applied) != before+1 || f.cursors[host].LastSeq != 3 {
		t.Fatalf("the returning host was not applied: %d, cursor %+v", len(f.applied)-before, f.cursors[host])
	}
	handleAt(t, c, "pwb.cloud."+host+".exposure", &asmv1.ExposureEvent{HostId: host, Listener: &asmv1.Listener{Key: "k"}}, 22)
	if len(f.applied) != before+2 {
		t.Fatal("a backend event after the announcement was skipped")
	}
	// Another host is not affected by the watermark.
	handleAt(t, c, "asm.other.heartbeat", &asmv1.Heartbeat{HostId: "other", RunId: "01A", Seq: 1}, 5)
	if len(f.applied) != before+3 {
		t.Fatal("another host's message was skipped")
	}
}
