package dpkg

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

// liveHost is a host's file system that a test changes while Run polls it.
type liveHost struct {
	mu    sync.Mutex
	files fstest.MapFS
}

func (h *liveHost) Open(name string) (fs.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := make(fstest.MapFS, len(h.files))
	for k, v := range h.files {
		f := *v
		c[k] = &f
	}
	return c.Open(name)
}

// dpkgWrite replaces the status file as dpkg does: new content, new time.
func (h *liveHost) dpkgWrite(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files["var/lib/dpkg/status"] = &fstest.MapFile{Data: []byte(status), ModTime: time.Now()}
}

type sink struct {
	mu   sync.Mutex
	got  []*eventsv1.HostPackages
	seen chan struct{}
}

func (s *sink) HostPackages(l *eventsv1.HostPackages) {
	s.mu.Lock()
	s.got = append(s.got, l)
	s.mu.Unlock()
	s.seen <- struct{}{}
}

func (s *sink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.got) }

func (s *sink) last() *eventsv1.HostPackages {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[len(s.got)-1]
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func wait(t *testing.T, s *sink, what string) {
	t.Helper()
	select {
	case <-s.seen:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Assumption: dpkg rewrites its status file many times during one apt run; the list goes
// out once, after the file has stayed unchanged for Settle, and it is the final one.
func TestRunReportsAtStartThenOnceAfterTheChangeSettles(t *testing.T) {
	h := &liveHost{files: host(ubuntuStatus)}
	s := &sink{seen: make(chan struct{}, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, Config{Root: h, Poll: 5 * time.Millisecond, Settle: 150 * time.Millisecond, Recheck: time.Hour, Log: quietLog()}, s)
	wait(t, s, "the start report")
	start := s.last()

	for i := range 5 { // an apt run: several writes 20 ms apart
		h.dpkgWrite(strings.Replace(ubuntuStatus, "5.2.21-2ubuntu4", "5.2.21-2ubuntu"+string(rune('5'+i)), 1))
		time.Sleep(20 * time.Millisecond)
	}
	wait(t, s, "the report after dpkg settled")
	time.Sleep(300 * time.Millisecond)
	if n := s.count(); n != 2 {
		t.Fatalf("%d reports, want the start and one after the apt run", n)
	}
	after := s.last()
	if after.GetDigest() == start.GetDigest() || !strings.Contains(names(after), "bash") {
		t.Fatalf("after = %v", after)
	}
	for _, p := range after.GetPackages() {
		if p.GetName() == "bash" && p.GetVersion() != "5.2.21-2ubuntu9" {
			t.Fatalf("the list sent is the one dpkg left: %v", p)
		}
	}
}

// A zero Poll or Recheck turns that trigger off rather than panicking: only the start
// report goes out.
func TestRunZeroIntervalsReportOnlyAtStart(t *testing.T) {
	s := &sink{seen: make(chan struct{}, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, Config{Root: host(ubuntuStatus), Log: quietLog()}, s); close(done) }()
	wait(t, s, "the start report")
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if n := s.count(); n != 1 {
		t.Fatalf("%d reports, want 1", n)
	}
}

// Assumption: the daily recheck reports whatever the list is (the publisher turns an
// unchanged one into its digest), and a status file that cannot be read is reported as
// such, not skipped.
func TestRunRecheckReportsEvenWhenUnchanged(t *testing.T) {
	h := &liveHost{files: fstest.MapFS{"etc/os-release": {Data: []byte(ubuntuOSRelease)}}}
	s := &sink{seen: make(chan struct{}, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, Config{Root: h, Poll: time.Hour, Settle: time.Hour, Recheck: 30 * time.Millisecond, Log: quietLog()}, s)
	wait(t, s, "the start report")
	wait(t, s, "a recheck")
	wait(t, s, "another recheck")
	if l := s.last(); l.GetRead() || !strings.Contains(l.GetUnreadable(), "does not exist") {
		t.Fatalf("a host without dpkg reports that it cannot tell: %v", l)
	}
}
