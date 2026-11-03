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
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	handleAt(t, c, "asm.keep.heartbeat", &asmv1.Heartbeat{HostId: "keep", RunId: "01A", Seq: 1}, 11)

	res, err := c.Forget(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ann.hosts, []string{host}) || res != (ForgetResult{Host: host, Existed: true, StreamSeq: 20}) {
		t.Fatalf("announced %v, result %+v", ann.hosts, res)
	}
	if f.forgotten[host] != 20 {
		t.Fatalf("store watermark %d, want 20", f.forgotten[host])
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
	handleAt(t, c, "asm."+host+".heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1}, 10)
	if _, err := c.Forget(context.Background(), host); err == nil {
		t.Fatal("forget succeeded without its announcement")
	}
	if _, ok := f.cursors[host]; !ok || f.forgotten[host] != 0 {
		t.Fatal("the store changed")
	}
	if _, _, _, known := c.Liveness.State(host); !known {
		t.Fatal("liveness changed")
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
