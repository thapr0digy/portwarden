//go:build integration

package pg

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/inventory"
)

// sender drives the real consumer over the store, one stream sequence per message.
type sender struct {
	t   *testing.T
	c   *inventory.Consumer
	seq uint64
}

func (s *sender) send(host, kind string, m proto.Message, at time.Time) uint64 {
	s.t.Helper()
	s.seq++
	subject := "asm." + host + "." + kind
	switch kind {
	case "cloud":
		subject = "pwb.cloud." + host + ".exposure"
	case "verifier":
		subject = "pwb.verifier." + host + ".exposure"
	}
	b, _ := proto.Marshal(m)
	if err := s.c.Handle(context.Background(), subject, b, inventory.Meta{StreamSeq: s.seq, StreamTime: at}); err != nil {
		s.t.Fatalf("%s %s: %v", host, kind, err)
	}
	return s.seq
}

func TestTamperStatusStored(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	snd := &sender{t: t, c: &inventory.Consumer{Store: s}}
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	snd.send(h1, "snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1, BootId: "b", RunNumber: 1}, t0)
	hv, _, err := s.Host(ctx, h1)
	if err != nil || hv.Tamper != nil || hv.TamperAt != nil {
		t.Fatalf("before any status: %s %v %v", hv.Tamper, hv.TamperAt, err)
	}
	flag := &asmv1.TamperFlag{Kind: "ptraced", Subject: "self", Detail: "pid 7\x00 (gdb)", Since: timestamppb.New(t0), Fingerprint: "7"}
	st := &asmv1.TamperStatus{Flags: []*asmv1.TamperFlag{flag}, CheckedAt: timestamppb.New(t0), Checks: []string{"ptrace"},
		ProgRunCounts: map[string]uint64{"on_listen": 4}}
	snd.send(h1, "tamper", &asmv1.TamperEvent{HostId: h1, RunId: "01A", Seq: 2, BootId: "b", RunNumber: 1, Status: st}, t0.Add(time.Minute))
	tamper := func() inventory.TamperView {
		t.Helper()
		hv, _, err := s.Host(ctx, h1)
		if err != nil || hv.Tamper == nil {
			t.Fatalf("host %+v %v", hv, err)
		}
		var v inventory.TamperView
		if err := json.Unmarshal(hv.Tamper, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := tamper(); len(v.Flags) != 1 || v.Flags[0].Kind != "ptraced" || v.Flags[0].Detail != "pid 7 (gdb)" {
		t.Fatalf("tamper event: %+v", v)
	}
	// A tamper event takes its place in the sequence: no gap.
	if hv, _, _ := s.Host(ctx, h1); hv.NeedsResync || hv.LastSeq != 2 || !hv.TamperAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("after the tamper event: resync %v last_seq %d tamper_at %v", hv.NeedsResync, hv.LastSeq, hv.TamperAt)
	}
	// A heartbeat without status keeps it; one with an all-clear status replaces it.
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 3, BootId: "b", RunNumber: 1}, t0.Add(2*time.Minute))
	if v := tamper(); len(v.Flags) != 1 {
		t.Fatalf("a heartbeat without status changed it: %+v", v)
	}
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 4, BootId: "b", RunNumber: 1,
		Tamper: &asmv1.TamperStatus{CheckedAt: timestamppb.New(t0.Add(3 * time.Minute)), Checks: []string{"ptrace"}}}, t0.Add(3*time.Minute))
	if v := tamper(); len(v.Flags) != 0 || v.CheckedAt == nil || !v.CheckedAt.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("all clear: %+v", v)
	}
	// The same status from a later pass (only checked_at differs) is no write.
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 5, BootId: "b", RunNumber: 1,
		Tamper: &asmv1.TamperStatus{CheckedAt: timestamppb.New(t0.Add(4 * time.Minute)), Checks: []string{"ptrace"}}}, t0.Add(4*time.Minute))
	if hv, _, _ := s.Host(ctx, h1); !hv.TamperAt.Equal(t0.Add(3 * time.Minute)) {
		t.Fatalf("an unchanged status moved tamper_at to %v", hv.TamperAt)
	}
	// A late tamper event of an earlier run never rolls it back.
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01B", Seq: 1, BootId: "b", RunNumber: 2}, t0.Add(4*time.Minute))
	snd.send(h1, "tamper", &asmv1.TamperEvent{HostId: h1, RunId: "01A", Seq: 6, BootId: "b", RunNumber: 1, Status: st}, t0.Add(5*time.Minute))
	if v := tamper(); len(v.Flags) != 0 {
		t.Fatalf("an earlier run's tamper event was applied: %+v", v)
	}
}

func TestForgetHost(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var announced uint64
	c := &inventory.Consumer{Store: s, Announce: func(context.Context, string) (uint64, error) { return announced, nil }}
	c.SetStream(stream1)
	snd := &sender{t: t, c: c}
	t0 := time.Now()
	snap := &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1, BootId: "b", RunNumber: 1, Listeners: []*asmv1.ListenerState{lst(22, "ssh.service")},
		Proxies: []*asmv1.ProxyState{{Proxy: &asmv1.Proxy{Id: "nginx/1/x", Kind: "nginx"}}}}
	snd.send(h1, "snapshot", snap, t0)
	snd.send("keep", "snapshot", &asmv1.Snapshot{HostId: "keep", RunId: "01A", Seq: 1, Listeners: []*asmv1.ListenerState{lst(80, "")}}, t0)
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 2, BootId: "b", RunNumber: 1}, t0)

	announced = snd.seq + 1 // the announcement's place in the stream
	snd.seq = announced
	res, err := c.Forget(ctx, h1)
	if err != nil || !res.Existed || res.StreamSeq != announced {
		t.Fatalf("forget: %+v %v", res, err)
	}
	if _, ok, _ := s.Host(ctx, h1); ok {
		t.Fatal("the host is still listed")
	}
	for _, q := range []string{"SELECT count(*) FROM listeners WHERE host_id = $1", "SELECT count(*) FROM proxies WHERE host_id = $1",
		"SELECT count(*) FROM exposure_history WHERE host_id = $1"} {
		var n int
		if err := s.pool.QueryRow(ctx, q, h1).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d rows left (%v)", q, n, err)
		}
	}
	hb, err := s.LastHeartbeats(ctx)
	if _, has := hb[h1]; err != nil || has {
		t.Fatal("the forgotten host would seed liveness at the next start")
	}
	if ls, _ := s.Listeners(ctx, inventory.ListenerFilter{Host: "keep"}); len(ls) != 1 {
		t.Fatal("another host lost its listeners")
	}
	if m, ok, _ := s.ForgottenMark(ctx, h1); !ok || m.Seq != announced || !m.Stream.Equal(stream1) {
		t.Fatalf("mark %+v %v", m, ok)
	}

	// A redelivered leftover (stored before the announcement) does not bring it back.
	b, _ := proto.Marshal(&asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 3, BootId: "b", RunNumber: 1})
	if err := c.Handle(ctx, "asm."+h1+".heartbeat", b, inventory.Meta{StreamSeq: announced - 1, StreamTime: t0}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Host(ctx, h1); ok {
		t.Fatal("a leftover recreated the host")
	}
	// Coming back: a new host (first_seen is now, its run starts over).
	snd.send(h1, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 4, BootId: "b", RunNumber: 1}, time.Now())
	hv, ok, err := s.Host(ctx, h1)
	if err != nil || !ok || hv.Listeners != 0 || !hv.FirstSeen.After(t0) {
		t.Fatalf("returned host %+v %v %v", hv, ok, err)
	}
	// Forgetting twice keeps the highest mark of a stream; forgetting an unknown host
	// records one.
	if _, err := s.Forget(ctx, h1, inventory.Mark{Seq: 1, Stream: stream1}); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := s.ForgottenMark(ctx, h1); m.Seq != announced {
		t.Fatalf("mark went back to %d", m.Seq)
	}
	if existed, err := s.Forget(ctx, "never", inventory.Mark{Seq: 9, Stream: stream1}); err != nil || existed {
		t.Fatalf("unknown host: %v %v", existed, err)
	}
	// A mark of a new stream replaces the old one even with a lower sequence.
	if _, err := s.Forget(ctx, "never", inventory.Mark{Seq: 3, Stream: stream2}); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := s.ForgottenMark(ctx, "never"); m.Seq != 3 || !m.Stream.Equal(stream2) {
		t.Fatalf("new stream's mark %+v", m)
	}
}

var (
	stream1 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	stream2 = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
)

// The stream was deleted and created again: its sequences start over, so a host id
// reused on it must not be judged by the old stream's mark.
func TestRecreatedStreamReusedHostID(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Forget(ctx, "reused", inventory.Mark{Seq: 5000, Stream: stream1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget(ctx, "same-stream-past-end", inventory.Mark{Seq: 900, Stream: stream2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Forget(ctx, "kept", inventory.Mark{Seq: 7, Stream: stream2}); err != nil {
		t.Fatal(err)
	}
	// Even before the prune, the consumer ignores another stream's mark.
	c := &inventory.Consumer{Store: s}
	c.SetStream(stream2)
	snd := &sender{t: t, c: c}
	snd.send("reused", "snapshot", &asmv1.Snapshot{HostId: "reused", RunId: "01A", Seq: 1}, time.Now())
	if _, ok, _ := s.Host(ctx, "reused"); !ok {
		t.Fatal("the reused host id was skipped by the old stream's mark")
	}
	n, err := s.PruneMarks(ctx, stream2, 100)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d (%v), want the old stream's and the one past the last seq", n, err)
	}
	if _, ok, _ := s.ForgottenMark(ctx, "kept"); !ok {
		t.Fatal("a current mark was pruned")
	}
}

func TestRetentionPrunesInBatches(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	for i := range 25 {
		age := time.Duration(i) * 24 * time.Hour
		if _, err := s.pool.Exec(ctx, `INSERT INTO exposure_history (host_id, key, at, origin, level, stream_seq)
			VALUES ('h', 'k', $1, 'agent', 2, $2)`, now.Add(-age), 5000+i); err != nil {
			t.Fatal(err)
		}
		if err := s.Quarantine(ctx, uint64(i), "asm.h.x", "bad", []byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, "UPDATE quarantine SET at = $1 WHERE stream_seq = $2", now.Add(-age), i); err != nil {
			t.Fatal(err)
		}
	}
	// History older than 10 days (rows 11..24: 14), quarantine older than 20 (21..24: 4).
	r := inventory.Retention{History: 10*24*time.Hour + time.Hour, Quarantine: 20*24*time.Hour + time.Hour, Batch: 4}
	h, q, err := r.Pass(ctx, s)
	if err != nil || h != 14 || q != 4 {
		t.Fatalf("pruned %d/%d (%v), want 14/4", h, q, err)
	}
	var left, oldest int
	_ = s.pool.QueryRow(ctx, "SELECT count(*), max(stream_seq) - 5000 FROM exposure_history").Scan(&left, &oldest)
	if left != 11 || oldest != 10 {
		t.Fatalf("history left %d (oldest age %d days)", left, oldest)
	}
	var idx int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname IN ('exposure_history_at', 'quarantine_at')`).Scan(&idx); err != nil || idx != 2 {
		t.Fatalf("retention indexes: %d (%v)", idx, err)
	}
}

func TestPaging(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	snd := &sender{t: t, c: &inventory.Consumer{Store: s}}
	now := time.Now()
	for i := range 7 {
		h := "host-" + strconv.Itoa(i)
		snd.send(h, "snapshot", &asmv1.Snapshot{HostId: h, RunId: "01A", Seq: 1,
			Listeners: []*asmv1.ListenerState{lst(22, ""), lst(443, ""), lst(8080, "")}}, now)
	}
	// Hosts, three at a time, are every host once, in id order.
	var ids []string
	var after *inventory.HostCursor
	for range 10 {
		page, err := s.Hosts(ctx, inventory.HostQuery{Limit: 3, After: after})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range page {
			ids = append(ids, h.ID)
		}
		if len(page) < 3 {
			break
		}
		after = &inventory.HostCursor{ID: page[len(page)-1].ID}
	}
	if len(ids) != 7 || ids[0] != "host-0" || ids[6] != "host-6" {
		t.Fatalf("hosts %v", ids)
	}
	// Listeners, filtered and paged by (host, proto, port, key): 21 rows, pages of 4.
	var got []string
	var la *inventory.ListenerCursor
	for range 10 {
		page, err := s.Listeners(ctx, inventory.ListenerFilter{MinLevel: 1, Limit: 4, After: la})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range page {
			got = append(got, l.Host+"/"+strconv.Itoa(l.Port))
		}
		if len(page) < 4 {
			break
		}
		l := page[len(page)-1]
		la = &inventory.ListenerCursor{Host: l.Host, Proto: l.Proto, Port: l.Port, Key: l.Key}
	}
	if len(got) != 21 || got[0] != "host-0/22" || got[3] != "host-1/22" || got[20] != "host-6/8080" {
		t.Fatalf("listeners %v", got)
	}
	// History newest first with ties on at broken by id.
	at := now.Add(-time.Hour)
	for i := range 5 {
		if _, err := s.pool.Exec(ctx, `INSERT INTO exposure_history (host_id, key, at, origin, level, stream_seq)
			VALUES ('host-0', 'k', $1, 'agent', 2, $2)`, at.Add(time.Duration(i/2)*time.Minute), 9000+i); err != nil {
			t.Fatal(err)
		}
	}
	var seen []time.Time
	var ha *inventory.HistoryCursor
	n := 0
	for range 10 {
		page, err := s.History(ctx, inventory.HistoryQuery{Host: "host-0", Key: "k", Limit: 2, After: ha})
		if err != nil {
			t.Fatal(err)
		}
		n += len(page)
		for _, h := range page {
			seen = append(seen, h.At)
		}
		if len(page) < 2 {
			break
		}
		last := page[len(page)-1]
		ha = &inventory.HistoryCursor{At: last.At, ID: last.ID}
	}
	if n != 5 {
		t.Fatalf("history pages gave %d rows, want 5", n)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i].After(seen[i-1]) {
			t.Fatalf("history not newest first: %v", seen)
		}
	}
}

func TestHostsAllIsUnbounded(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := range 1005 {
		if err := ensureHostTx(ctx, s, "h-"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Hosts(ctx, inventory.HostQuery{All: true})
	if err != nil || len(all) != 1005 {
		t.Fatalf("all hosts: %d %v", len(all), err)
	}
	page, err := s.Hosts(ctx, inventory.HostQuery{})
	if err != nil || len(page) != 1000 {
		t.Fatalf("default page: %d %v", len(page), err)
	}
}

func ensureHostTx(ctx context.Context, s *Store, h string) error {
	_, err := s.pool.Exec(ctx, "INSERT INTO hosts (host_id) VALUES ($1)", h)
	return err
}
