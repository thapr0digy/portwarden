package publish

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/spool"
)

func testAccess(digest string) *eventsv1.HostAccess {
	return &eventsv1.HostAccess{Sshd: &eventsv1.Sshd{Read: true, AuthorizedKeysFile: "none"},
		Accounts: []*eventsv1.AccountAccess{{Account: "pants", PrincipalsRead: true, Principals: []string{"pants"}}},
		Digest:   digest}
}

// The wire rule: a full state, then only its digest while it holds, and the full state
// again when Signal asks for a resync (it forgets the digest then).
func TestHostAccessSendsTheDigestWhileUnchangedAndTheStateOnResync(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var mu sync.Mutex
	var got []*eventsv1.HostAccess
	ic, _ := scriptedDoor(t, func(call int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range b.GetEvents() {
			if err := validate.Event(e, validate.Options{}); err != nil {
				t.Errorf("the door would refuse %v: %v", e, err)
			}
			got = append(got, e.GetHostAccess())
		}
		if call == 2 {
			return http.StatusOK, ok(len(b.GetEvents()), &eventsv1.Directive{Kind: eventsv1.Directive_RESYNC_SNAPSHOT})
		}
		return http.StatusOK, ok(len(b.GetEvents()))
	})
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	digest := strings.Repeat("a", 64)
	p.HostAccess(testAccess(digest))
	n := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	eventually(t, "the full state", func() bool { return n() == 1 })
	p.HostAccess(testAccess(digest))
	eventually(t, "the digest, then the full state again on the resync", func() bool { return n() == 3 })
	mu.Lock()
	defer mu.Unlock()
	if got[0].GetUnchanged() || len(got[0].GetAccounts()) != 1 ||
		!got[1].GetUnchanged() || got[1].GetDigest() != digest || got[1].GetSshd() != nil ||
		got[2].GetUnchanged() || !proto.Equal(got[2], got[0]) {
		t.Fatalf("sent %v", got)
	}
}

func TestHostAccessChangedStateIsSentInFull(t *testing.T) {
	p := memPublisher(t)
	p.HostAccess(testAccess(strings.Repeat("1", 64)))
	p.HostAccess(testAccess(strings.Repeat("2", 64)))
	p.HostAccess(testAccess(strings.Repeat("2", 64)))
	var kinds []bool
	for _, m := range p.q.Peek(10, 1<<20) {
		ev, err := signalEvent(m, testHost, "v1")
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, ev.GetHostAccess().GetUnchanged())
	}
	if len(kinds) != 3 || kinds[0] || kinds[1] || !kinds[2] {
		t.Fatalf("unchanged flags = %v", kinds)
	}
}

// memPublisher is an ingest publisher whose door is always unavailable: messages stay in
// its spool for the test to read.
func memPublisher(t *testing.T) *Publisher {
	t.Helper()
	keyFile, _ := hostSeed(t)
	ic, _ := scriptedDoor(t, func(int, *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		return http.StatusServiceUnavailable, &eventsv1.IngestResponse{}
	})
	ic.KeyFile = keyFile
	return ingestPublisher(t, ic)
}

func TestSpooledSignalEventIsCheckedAgainstTheMessage(t *testing.T) {
	p := memPublisher(t)
	p.SignIns(&eventsv1.SignInSummary{WindowEnd: timestamppb.Now(), JournalUnreadable: true, Unreadable: "no group"})
	m := p.q.Peek(1, 1<<20)[0]
	if m.Subject != "asm."+testHost+".host.sign_ins" {
		t.Fatalf("subject %s", m.Subject)
	}
	ev, err := signalEvent(m, testHost, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if ev.GetType() != "asm.host.sign_ins" || ev.GetProducer().GetVersion() != "v1.2.3" || ev.GetSource() != "urn:asm:agent:"+testHost ||
		ev.GetSequence().GetSeq() != m.Seq || ev.GetSequence().GetRunId() != p.runID || !ev.GetSignIns().GetJournalUnreadable() {
		t.Fatalf("event %v", ev)
	}
	if err := validate.Event(ev, validate.Options{}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]spool.Msg{
		"another id":   {Subject: m.Subject, ID: "01JC8Z6X4Q00000000000000A9", Seq: m.Seq, Data: m.Data},
		"another seq":  {Subject: m.Subject, ID: m.ID, Seq: m.Seq + 1, Data: m.Data},
		"another type": {Subject: "asm." + testHost + ".host.access", ID: m.ID, Seq: m.Seq, Data: m.Data},
		"not an event": {Subject: m.Subject, ID: m.ID, Seq: m.Seq, Data: []byte{0xff}},
	} {
		if _, err := signalEvent(bad, testHost, "v1"); err == nil {
			t.Errorf("%s: converted", name)
		}
	}
}

// Assumption: a Signal-only event left in the spool never reaches NATS, where a host's user
// may not publish it and a denied publish would stop the agent.
func TestNATSDropsSignalOnlyEventsWithoutPublishing(t *testing.T) {
	tr := &natsTransport{} // no connection: delivering anything else would panic
	for _, subject := range []string{"asm." + testHost + ".host.access", "asm." + testHost + ".host.sign_ins"} {
		d := tr.deliver(context.Background(), []spool.Msg{{Subject: subject}})
		if !d.undeliverable || d.denied || d.sent != 0 {
			t.Fatalf("%s: %+v", subject, d)
		}
	}
}
