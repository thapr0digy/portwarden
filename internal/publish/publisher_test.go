package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	testHost = "0123456789abcdef0123456789abcdef"
	deadline = 30 * time.Second
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconnectWait = 100 * time.Millisecond
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startServer(t *testing.T, port int, storeDir string) *server.Server {
	t.Helper()
	return startServerWith(t, &server.Options{Port: port, StoreDir: storeDir})
}

func startServerWith(t *testing.T, opts *server.Options) *server.Server {
	t.Helper()
	opts.Host, opts.JetStream, opts.NoLog, opts.NoSigs = "127.0.0.1", true, true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	return s
}

func stop(s *server.Server) { s.Shutdown(); s.WaitForShutdown() }

func natsURL(port int) string { return "nats://127.0.0.1:" + itoa(port) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func newPublisher(t *testing.T, port int) *Publisher {
	t.Helper()
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

type got struct {
	subject string
	msgID   string
	data    []byte
}

// readStream polls the ASM_EVENTS stream until it holds n messages and returns them in order.
func readStream(t *testing.T, port, n int) []got {
	t.Helper()
	nc, err := nats.Connect(natsURL(port))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, ok := tryRead(ctx, js, n)
		cancel()
		if ok {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stream did not reach %d messages in %s", n, deadline)
	return nil
}

func tryRead(ctx context.Context, js jetstream.JetStream, n int) ([]got, bool) {
	st, err := js.Stream(ctx, "ASM_EVENTS")
	if err != nil {
		return nil, false
	}
	info, err := st.Info(ctx)
	if err != nil || info.State.Msgs < uint64(n) {
		return nil, false
	}
	var out []got
	for seq := uint64(1); seq <= info.State.LastSeq && len(out) < n; seq++ {
		raw, err := st.GetMsg(ctx, seq)
		if err != nil {
			continue // purged or deleted
		}
		out = append(out, got{raw.Subject, raw.Header.Get("Nats-Msg-Id"), raw.Data})
	}
	return out, len(out) == n
}

func openedChange(port uint16) state.Change {
	return state.Change{
		Kind:   model.Opened,
		Key:    model.NewKey(4026531840, "tcp", netip.MustParseAddr("0.0.0.0"), port),
		Procs:  []model.Process{{PID: 7, UID: 1000, Comm: "nginx", Exe: "/usr/sbin/nginx"}},
		At:     time.Unix(1700000000, 0),
		Source: model.SourceEBPF,
	}
}

func closedChange(port uint16) state.Change {
	c := openedChange(port)
	c.Kind = model.Closed
	return c
}

func snapshotOf(ports ...uint16) []state.Listener {
	var ls []state.Listener
	for _, p := range ports {
		ls = append(ls, state.Listener{Key: openedChange(p).Key, Procs: openedChange(p).Procs})
	}
	return ls
}

func seqOf(t *testing.T, g got) uint64 {
	t.Helper()
	switch {
	case g.subject == "asm."+testHost+".snapshot":
		var m asmv1.Snapshot
		mustUnmarshal(t, g.data, &m)
		return m.Seq
	case g.subject == "asm."+testHost+".heartbeat":
		var m asmv1.Heartbeat
		mustUnmarshal(t, g.data, &m)
		return m.Seq
	default:
		var m asmv1.ListenerEvent
		mustUnmarshal(t, g.data, &m)
		return m.Seq
	}
}

func mustUnmarshal(t *testing.T, b []byte, m proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(b, m); err != nil {
		t.Fatal(err)
	}
}

func TestOpenedLandsOnSubject(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.Snapshot(snapshotOf())
	c := openedChange(8080)
	p.Changes([]state.Change{c})

	msgs := readStream(t, port, 2)
	g := msgs[1]
	if g.subject != "asm."+testHost+".listener.opened" {
		t.Fatalf("subject = %q", g.subject)
	}
	var ev asmv1.ListenerEvent
	mustUnmarshal(t, g.data, &ev)
	if ev.Seq != 2 || ev.Listener.Key != c.Key.String() || ev.Kind != asmv1.Kind_OPENED ||
		ev.Source != asmv1.Source_EBPF || ev.HostId != testHost || ev.RunId == "" ||
		ev.Listener.Port != 8080 || ev.Listener.Addr != "0.0.0.0" || ev.Listener.Netns != 4026531840 ||
		len(ev.Processes) != 1 || ev.Processes[0].Comm != "nginx" ||
		ev.ObservedAt.AsTime().Unix() != 1700000000 {
		t.Fatalf("unexpected event: %v", &ev)
	}
	if g.msgID == "" || g.msgID != ev.EventId {
		t.Fatalf("Nats-Msg-Id = %q, event_id = %q", g.msgID, ev.EventId)
	}
}

func TestSeqStrictlyIncreasesAcrossKinds(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.Snapshot(snapshotOf(80))
	p.Changes([]state.Change{openedChange(8080), closedChange(8080)})
	p.Heartbeat(3, 4)

	msgs := readStream(t, port, 4)
	for i, g := range msgs {
		if s := seqOf(t, g); s != uint64(i+1) {
			t.Errorf("message %d (%s) seq = %d, want %d", i, g.subject, s, i+1)
		}
	}
	wantSubjects := []string{"snapshot", "listener.opened", "listener.closed", "heartbeat"}
	for i, w := range wantSubjects {
		if msgs[i].subject != "asm."+testHost+"."+w {
			t.Errorf("message %d subject = %q, want suffix %q", i, msgs[i].subject, w)
		}
	}
	var hb asmv1.Heartbeat
	mustUnmarshal(t, msgs[3].data, &hb)
	if hb.RingbufDrops != 3 || hb.DroppedForeignNetns != 4 || hb.QueueDrops != 0 {
		t.Fatalf("heartbeat = %v", &hb)
	}
}

func TestReconnectPublishesSnapshot(t *testing.T) {
	port := freePort(t)
	store := t.TempDir()
	s := startServer(t, port, store)
	p := newPublisher(t, port)

	p.Snapshot(snapshotOf(80))
	readStream(t, port, 1)

	stop(s)
	p.Changes([]state.Change{openedChange(8080), closedChange(8080)})
	startServer(t, port, store)

	msgs := readStream(t, port, 4)
	want := []string{"snapshot", "listener.opened", "listener.closed", "snapshot"}
	for i, g := range msgs {
		if g.subject != "asm."+testHost+"."+want[i] {
			t.Errorf("message %d subject = %q, want %q", i, g.subject, want[i])
		}
		if s := seqOf(t, g); s != uint64(i+1) {
			t.Errorf("message %d seq = %d, want %d", i, s, i+1)
		}
	}
	var first, resnap asmv1.Snapshot
	mustUnmarshal(t, msgs[0].data, &first)
	mustUnmarshal(t, msgs[3].data, &resnap)
	if first.EventId == resnap.EventId {
		t.Fatal("resnapshot reused the event_id")
	}
	if len(resnap.Listeners) != 1 || resnap.Listeners[0].Listener.Port != 80 {
		t.Fatalf("resnapshot content = %v", &resnap)
	}
}

func TestStartsWithNATSDown(t *testing.T) {
	port := freePort(t)
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost})
	if err != nil {
		t.Fatalf("New with NATS down: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	p.Snapshot(snapshotOf(80))
	p.Changes([]state.Change{openedChange(8080)})
	startServer(t, port, t.TempDir())

	msgs := readStream(t, port, 2)
	if msgs[0].subject != "asm."+testHost+".snapshot" || msgs[1].subject != "asm."+testHost+".listener.opened" {
		t.Fatalf("subjects = %q, %q", msgs[0].subject, msgs[1].subject)
	}
	for i, g := range msgs {
		if s := seqOf(t, g); s != uint64(i+1) {
			t.Errorf("message %d seq = %d, want %d", i, s, i+1)
		}
	}
}

func TestQueueOverflowCountedInHeartbeat(t *testing.T) {
	port := freePort(t)
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, QueueMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	for i := 0; i < 4; i++ {
		p.Changes([]state.Change{openedChange(uint16(1000 + i))})
	}
	p.Heartbeat(0, 0) // 5th message; reports the 2 drops so far, its own push drops a 3rd
	startServer(t, port, t.TempDir())

	msgs := readStream(t, port, 2)
	var hb asmv1.Heartbeat
	mustUnmarshal(t, msgs[1].data, &hb)
	if hb.QueueDrops != 2 || hb.Seq != 5 {
		t.Fatalf("heartbeat = %v, want queue_drops 2 seq 5 (gap shows the drops)", &hb)
	}
}

func TestNewRejectsUnreadableFiles(t *testing.T) {
	_, err := New(context.Background(), Config{URL: "nats://127.0.0.1:1", HostID: testHost, CredsFile: "/nonexistent/creds"})
	if err == nil {
		t.Fatal("want error for unreadable creds file")
	}
	_, err = New(context.Background(), Config{URL: "nats://127.0.0.1:1", HostID: testHost, CAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("want error for unreadable CA file")
	}
}

func TestCloseFlushesQueue(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		p.Changes([]state.Change{openedChange(uint16(2000 + i))})
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	readStream(t, port, 20)
}

func TestResnapshotReflectsChangesMadeDuringOutage(t *testing.T) {
	port := freePort(t)
	store := t.TempDir()
	s := startServer(t, port, store)
	p := newPublisher(t, port)

	p.Snapshot(snapshotOf(80))
	readStream(t, port, 1)

	stop(s)
	p.Changes([]state.Change{openedChange(8080)})
	startServer(t, port, store)

	msgs := readStream(t, port, 3)
	if msgs[2].subject != "asm."+testHost+".snapshot" {
		t.Fatalf("message 3 subject = %q", msgs[2].subject)
	}
	var resnap asmv1.Snapshot
	mustUnmarshal(t, msgs[2].data, &resnap)
	if resnap.Seq != 3 || len(resnap.Listeners) != 2 ||
		resnap.Listeners[0].Listener.Port != 80 || resnap.Listeners[1].Listener.Port != 8080 {
		t.Fatalf("resnapshot = %v, want listeners 80 and 8080 at seq 3", &resnap)
	}
}

func TestPermanentPublishErrorIsDroppedAndNextMessageArrives(t *testing.T) {
	port := freePort(t)
	startServerWith(t, &server.Options{Port: port, StoreDir: t.TempDir(), MaxPayload: 2048})
	p := newPublisher(t, port)

	huge := openedChange(9000)
	huge.Procs = []model.Process{{Exe: string(make([]byte, 4096))}}
	p.Changes([]state.Change{huge, openedChange(9001)})

	msgs := readStream(t, port, 1)
	var ev asmv1.ListenerEvent
	mustUnmarshal(t, msgs[0].data, &ev)
	if ev.Seq != 2 || ev.Listener.Port != 9001 {
		t.Fatalf("event = %v, want the second message with seq 2 (gap marks the dropped one)", &ev)
	}
	if got := p.q.Dropped(); got != 1 {
		t.Fatalf("Dropped = %d, want 1", got)
	}
}

func TestStreamManagementDeniedStillPublishes(t *testing.T) {
	port := freePort(t)
	startServerWith(t, &server.Options{
		Port: port, StoreDir: t.TempDir(),
		Users: []*server.User{
			{Username: "admin", Password: "pw"},
			{Username: "agent", Password: "pw", Permissions: &server.Permissions{
				Publish:   &server.SubjectPermission{Allow: []string{"asm.>"}},
				Subscribe: &server.SubjectPermission{Allow: []string{InboxPrefix(testHost) + ".>"}},
			}},
		},
	})

	admin, err := nats.Connect("nats://admin:pw@127.0.0.1:" + itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name: streamName, Subjects: []string{"asm.>"}, Storage: jetstream.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}

	p, err := New(context.Background(), Config{URL: "nats://agent:pw@127.0.0.1:" + itoa(port), HostID: testHost})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.Snapshot(snapshotOf())
	p.Changes([]state.Change{openedChange(8080)})

	tryAdmin := func() ([]got, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return tryRead(ctx, js, 2)
	}
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if msgs, ok := tryAdmin(); ok {
			if s := seqOf(t, msgs[1]); s != 2 {
				t.Fatalf("second message seq = %d", s)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("messages did not arrive with stream management denied")
}

func TestConfigRefusedClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"name in use with other config", &jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeStreamNameInUse}, true},
		{"invalid config", &jetstream.APIError{Code: 500, ErrorCode: 10052}, true},
		{"subjects overlap", &jetstream.APIError{Code: 400, ErrorCode: 10065}, true},
		{"forbidden", &jetstream.APIError{Code: 403, ErrorCode: 0}, true},
		{"wrapped refusal", fmt.Errorf("x: %w", &jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeStreamNameInUse}), true},
		{"insufficient resources", &jetstream.APIError{Code: 500, ErrorCode: 10023}, false},
		{"no leader", &jetstream.APIError{Code: 503, ErrorCode: 10008}, false},
		{"generic update error", &jetstream.APIError{Code: 500, ErrorCode: 10069}, false},
		{"jetstream not enabled", &jetstream.APIError{Code: 503, ErrorCode: jetstream.JSErrCodeJetStreamNotEnabled}, false},
		{"timeout", context.DeadlineExceeded, false},
		{"not an api error", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := configRefused(c.err); got != c.want {
			t.Errorf("%s: configRefused = %v, want %v", c.name, got, c.want)
		}
	}
	var p Publisher
	if p.ensureRefused(errors.New("timeout"), 0) {
		t.Error("plain error must not be refused without a recorded permission violation")
	}
	p.perms.record(fmt.Errorf("%w: Permissions Violation for Publish to \"$JS.API.STREAM.UPDATE.ASM_EVENTS\"", nats.ErrPermissionViolation))
	if !p.ensureRefused(context.DeadlineExceeded, 0) {
		t.Error("permission violation on stream API must be refused")
	}
	if p.ensureRefused(context.DeadlineExceeded, p.perms.count()) {
		t.Error("violation recorded before the attempt must not count")
	}
}

func TestStreamDeletedWhilePublishingIsReensured(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.Snapshot(snapshotOf())
	readStream(t, port, 1)

	admin, err := nats.Connect(natsURL(port))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := js.DeleteStream(context.Background(), streamName); err != nil {
		t.Fatal(err)
	}

	p.Changes([]state.Change{openedChange(8080)})
	msgs := readStream(t, port, 1)
	var ev asmv1.ListenerEvent
	mustUnmarshal(t, msgs[0].data, &ev)
	if ev.Seq != 2 || ev.Listener.Port != 8080 {
		t.Fatalf("event = %v, want seq 2 port 8080 after the stream was recreated", &ev)
	}
}

// assertStreamCount waits briefly for stragglers, then checks the stream holds exactly n.
func assertStreamCount(t *testing.T, port, n int) {
	t.Helper()
	time.Sleep(5 * reconnectWait)
	nc, err := nats.Connect(natsURL(port))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := js.Stream(ctx, streamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := st.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != uint64(n) {
		t.Fatalf("stream holds %d messages, want exactly %d", info.State.Msgs, n)
	}
}

func TestExistingStreamConfigIsNotChanged(t *testing.T) {
	port := freePort(t)
	store := t.TempDir()
	serverOpts := func() *server.Options {
		return &server.Options{
			Port: port, StoreDir: store,
			Users: []*server.User{{Username: "admin", Password: "pw"}},
		}
	}
	s := startServerWith(t, serverOpts())
	url := "nats://admin:pw@127.0.0.1:" + itoa(port)
	ctx := context.Background()
	operatorCfg := jetstream.StreamConfig{
		Name: streamName, Subjects: []string{"asm.>"}, Storage: jetstream.FileStorage,
		MaxAge: 30 * 24 * time.Hour, Duplicates: 5 * time.Minute, Replicas: 1,
		MaxMsgs: 123_456, MaxBytes: 64 << 20, MaxMsgsPerSubject: 1000,
		Description: "managed by the operator",
	}
	withAdmin(t, url, func(js jetstream.JetStream) {
		if _, err := js.CreateStream(ctx, operatorCfg); err != nil {
			t.Fatal(err)
		}
	})
	var before jetstream.StreamConfig
	withAdmin(t, url, func(js jetstream.JetStream) { before = streamConfig(t, js) })

	p, err := New(ctx, Config{URL: url, HostID: testHost})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.Snapshot(snapshotOf(80))
	p.Changes([]state.Change{openedChange(8080)})
	withAdmin(t, url, func(js jetstream.JetStream) { waitForMsgs(t, js, 2) })

	// A reconnect re-runs the stream check; it must not modify the stream either.
	stop(s)
	startServerWith(t, serverOpts())
	p.Changes([]state.Change{closedChange(8080)})
	withAdmin(t, url, func(js jetstream.JetStream) {
		waitForMsgs(t, js, 4) // the change and the reconnect resnapshot
		after := streamConfig(t, js)
		if after.MaxAge != before.MaxAge || after.Duplicates != before.Duplicates ||
			after.MaxMsgs != before.MaxMsgs || after.MaxBytes != before.MaxBytes ||
			after.MaxMsgsPerSubject != before.MaxMsgsPerSubject || after.Replicas != before.Replicas ||
			after.Description != before.Description {
			t.Fatalf("stream config changed:\nbefore %+v\nafter  %+v", before, after)
		}
		if after.MaxAge != operatorCfg.MaxAge {
			t.Fatalf("MaxAge = %v, want the operator's %v", after.MaxAge, operatorCfg.MaxAge)
		}
	})
}

func withAdmin(t *testing.T, url string, f func(jetstream.JetStream)) {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	f(js)
}

func TestMissingStreamIsCreatedWithAgentConfig(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)
	p.Snapshot(snapshotOf())
	readStream(t, port, 1)

	nc, err := nats.Connect(natsURL(port))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	cfg := streamConfig(t, js)
	if cfg.MaxAge != streamMaxAge || cfg.Duplicates != dedupeWindow || !slices.Equal(cfg.Subjects, []string{"asm.>"}) {
		t.Fatalf("created stream config = %+v", cfg)
	}
}

func streamConfig(t *testing.T, js jetstream.JetStream) jetstream.StreamConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := js.Stream(ctx, streamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := st.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return info.Config
}

func waitForMsgs(t *testing.T, js jetstream.JetStream, n int) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, ok := tryRead(ctx, js, n)
		cancel()
		if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stream did not reach %d messages", n)
}

func TestReplyInboxesUseHostPrefix(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)
	if got, want := p.nc.NewRespInbox(), InboxPrefix(testHost)+"."; !strings.HasPrefix(got, want) {
		t.Fatalf("resp inbox = %q, want prefix %q", got, want)
	}
	if got, want := p.nc.NewInbox(), InboxPrefix(testHost)+"."; !strings.HasPrefix(got, want) {
		t.Fatalf("inbox = %q, want prefix %q", got, want)
	}
}

func TestNewRejectsHostIDThatIsNotOneToken(t *testing.T) {
	for _, id := range []string{"a.b", "a*", "a>", "a b"} {
		if _, err := New(context.Background(), Config{URL: "nats://127.0.0.1:1", HostID: id}); err == nil {
			t.Errorf("HostID %q: want error", id)
		}
	}
}

func TestSnapshotDroppedBeforeFirstConnectIsResent(t *testing.T) {
	port := freePort(t)
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, QueueMax: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	p.Snapshot(snapshotOf(80)) // seq 1, dropped by the third change
	p.Changes([]state.Change{openedChange(8080), openedChange(8081), openedChange(8082)})
	startServer(t, port, t.TempDir())

	msgs := readStream(t, port, 4)
	want := []string{"listener.opened", "listener.opened", "listener.opened", "snapshot"}
	for i, g := range msgs {
		if g.subject != "asm."+testHost+"."+want[i] {
			t.Errorf("message %d subject = %q, want %q", i, g.subject, want[i])
		}
		if s := seqOf(t, g); s != uint64(i+2) {
			t.Errorf("message %d seq = %d, want %d", i, s, i+2)
		}
	}
	var snap asmv1.Snapshot
	mustUnmarshal(t, msgs[3].data, &snap)
	var ports []uint32
	for _, l := range snap.Listeners {
		ports = append(ports, l.Listener.Port)
	}
	if !slices.Equal(ports, []uint32{80, 8080, 8081, 8082}) {
		t.Fatalf("resnapshot ports = %v, want [80 8080 8081 8082]", ports)
	}
	assertStreamCount(t, port, 4) // one resnapshot per drop episode, not a loop
}

func TestDropWhileConnectedTriggersOneResnapshot(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, QueueMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.Snapshot(snapshotOf(80))
	readStream(t, port, 1)

	// Changes holds p.mu for the whole batch, so the sender cannot drain in between:
	// three pushes into a queue of two drop at least one.
	p.Changes([]state.Change{openedChange(8080), openedChange(8081), openedChange(8082)})
	if p.q.Overflowed() == 0 {
		t.Skip("sender drained the queue during the batch; no overflow to test")
	}
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		nc, _ := nats.Connect(natsURL(port))
		js, _ := jetstream.New(nc)
		st, err := js.Stream(ctx, streamName)
		var last uint64
		if err == nil {
			if info, err := st.Info(ctx); err == nil {
				last = info.State.LastSeq
			}
		}
		if last > 0 {
			if raw, err := st.GetMsg(ctx, last); err == nil && raw.Subject == "asm."+testHost+".snapshot" && last > 1 {
				var snap asmv1.Snapshot
				mustUnmarshal(t, raw.Data, &snap)
				cancel()
				nc.Close()
				if len(snap.Listeners) != 4 {
					t.Fatalf("resnapshot has %d listeners, want 4", len(snap.Listeners))
				}
				assertStreamCount(t, port, int(last))
				return
			}
		}
		cancel()
		nc.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no resnapshot after an overflow while connected")
}

func TestNoResnapshotWithoutDrops(t *testing.T) {
	port := freePort(t)
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, QueueMax: 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.Snapshot(snapshotOf(80))
	p.Changes([]state.Change{openedChange(8080), closedChange(8080)})
	startServer(t, port, t.TempDir())
	readStream(t, port, 3)
	p.Heartbeat(0, 0)
	readStream(t, port, 4)
	assertStreamCount(t, port, 4)
}

// captureLogs routes slog to a buffer for the test's duration.
type logCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logCapture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(c, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return c
}

func TestUnmatchedPermissionViolationIsLogged(t *testing.T) {
	logs := captureLogs(t)
	port := freePort(t)
	startServerWith(t, &server.Options{
		Port: port, StoreDir: t.TempDir(),
		Users: []*server.User{
			{Username: "admin", Password: "pw"},
			// Missing its inbox permission: publish acks can never reach it.
			{Username: "agent", Password: "pw", Permissions: &server.Permissions{
				Publish:   &server.SubjectPermission{Allow: []string{"asm.>"}},
				Subscribe: &server.SubjectPermission{Allow: []string{"nothing"}},
			}},
		},
	})
	p, err := New(context.Background(), Config{URL: "nats://agent:pw@127.0.0.1:" + itoa(port), HostID: testHost})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.Snapshot(snapshotOf())

	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		out := logs.String()
		if strings.Contains(out, "level=WARN") && strings.Contains(out, `msg="nats permission violation"`) &&
			strings.Contains(out, "subject="+InboxPrefix(testHost)+".") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no Warn for the inbox subscription violation; logs:\n%s", logs.String())
}

func TestPermTrackerMatchesPendingRequest(t *testing.T) {
	var tr permTracker
	viol := func(subj string) error {
		return fmt.Errorf("%w: Permissions Violation for Publish to %q", nats.ErrPermissionViolation, subj)
	}
	if tr.record(viol("asm.x.snapshot")) {
		t.Error("nothing pending: must not match")
	}
	tr.expect("asm.x.snapshot")
	if !tr.record(viol("asm.x.snapshot")) {
		t.Error("pending publish: must match")
	}
	if tr.record(viol("_INBOX_x.abc.*")) {
		t.Error("inbox violation during a publish must not match")
	}
	tr.expect("")
	if got := violationSubject(viol("_INBOX_x.abc.*")); got != "_INBOX_x.abc.*" {
		t.Errorf("violationSubject = %q", got)
	}
	if got := violationSubject(errors.New("no quotes")); got != "" {
		t.Errorf("violationSubject = %q, want empty", got)
	}
}
