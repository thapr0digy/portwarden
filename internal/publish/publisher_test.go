package publish

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/listener-watch/gen/asm/v1"
	"github.com/thapr0digy/listener-watch/internal/model"
	"github.com/thapr0digy/listener-watch/internal/state"
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
	s, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: port, JetStream: true, StoreDir: storeDir,
		NoLog: true, NoSigs: true,
	})
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
