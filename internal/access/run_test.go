package access

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

type sink struct {
	mu      sync.Mutex
	access  []*eventsv1.HostAccess
	signIns []*eventsv1.SignInSummary
}

func (s *sink) HostAccess(a *eventsv1.HostAccess) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access = append(s.access, a)
}

func (s *sink) SignIns(x *eventsv1.SignInSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signIns = append(s.signIns, x)
}

func (s *sink) got() ([]*eventsv1.HostAccess, []*eventsv1.SignInSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*eventsv1.HostAccess(nil), s.access...), append([]*eventsv1.SignInSummary(nil), s.signIns...)
}

// fakeJournal hands each follow a pipe the test writes records into, and records the
// cursor each follow started after.
type fakeJournal struct {
	mu      sync.Mutex
	cursors []string
	follows chan *io.PipeWriter
	fail    error
}

func newFakeJournal() *fakeJournal { return &fakeJournal{follows: make(chan *io.PipeWriter, 4)} }

func (j *fakeJournal) follow(ctx context.Context, cursor string) (io.ReadCloser, error) {
	j.mu.Lock()
	j.cursors = append(j.cursors, cursor)
	fail := j.fail
	j.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	r, w := io.Pipe()
	// As journalctl under exec.CommandContext: the follow ends with ctx.
	go func() { <-ctx.Done(); _ = w.CloseWithError(ctx.Err()) }()
	j.follows <- w
	return r, nil
}

func (j *fakeJournal) followCursors() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.cursors...)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testConfig(h *hostFS, j Journal, cursorFile string) Config {
	return Config{Root: h, Accounts: []string{"root", "pants"}, SharedKeys: SharedKeys{underpantsFP: "underpants"},
		Journal: j, CursorFile: cursorFile, Poll: 10 * time.Millisecond, Recheck: time.Hour, Flush: 20 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// The reader end to end: the access state at start and on a change, sign-ins from the
// journal grouped into a summary, the journal position kept across runs.
func TestRunReportsAccessAndSignIns(t *testing.T) {
	h := ansibleHost()
	j := newFakeJournal()
	cursorFile := filepath.Join(t.TempDir(), "ingest", "journal-cursor")
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, testConfig(h, j.follow, cursorFile), s); close(done) }()

	waitUntil(t, "the access state at start", func() bool { a, _ := s.got(); return len(a) == 1 })
	waitUntil(t, "the first summary (the host reports)", func() bool { _, x := s.got(); return len(x) >= 1 })
	w := <-j.follows
	now := time.Now()
	for i, line := range [][]byte{
		entryJSON("ssh.service", "0", certLine, now, "c1"),
		entryJSON("ssh.service", "0", certLine, now, "c2"),
		entryJSON("ssh.service", "1000", keyLine, now, "c3"), // a user's forged line
		entryJSON("ssh.service", "0", keyLine, now, "c4"),
	} {
		if _, err := w.Write(append(line, '\n')); err != nil {
			t.Fatal(i, err)
		}
	}
	waitUntil(t, "the sign-ins", func() bool {
		_, x := s.got()
		var n uint64
		for _, sum := range x {
			for _, g := range sum.GetGroups() {
				n += g.GetCount()
			}
		}
		return n == 3
	})
	waitUntil(t, "the cursor saved", func() bool { b, _ := os.ReadFile(cursorFile); return strings.TrimSpace(string(b)) == "c4" })

	h.write("etc/ssh/authorized_principals/pants", "pants\nintruder\n")
	waitUntil(t, "the changed access state", func() bool { a, _ := s.got(); return len(a) == 2 })
	a, _ := s.got()
	if a[0].GetDigest() == a[1].GetDigest() || len(accountOf(t, a[1], "pants").GetPrincipals()) != 2 {
		t.Fatalf("access = %v", a)
	}
	cancel()
	<-done

	// A new run starts after the saved cursor.
	j2 := newFakeJournal()
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { Run(ctx, testConfig(h, j2.follow, cursorFile), &sink{}); close(done) }()
	<-j2.follows
	cancel()
	<-done
	if c := j2.followCursors(); c[0] != "c4" {
		t.Fatalf("second run followed after %q, want c4", c[0])
	}
}

func TestRunRechecksWithTheSameDigest(t *testing.T) {
	cfg := testConfig(ansibleHost(), nil, "")
	cfg.Recheck = 20 * time.Millisecond
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, cfg, s); close(done) }()
	waitUntil(t, "two rechecks", func() bool { a, _ := s.got(); return len(a) >= 3 })
	cancel()
	<-done
	a, x := s.got()
	if a[0].GetDigest() != a[2].GetDigest() {
		t.Fatal("a recheck of an unchanged state carries the same digest")
	}
	// No journal: every summary says it cannot be read; the first says so once.
	if len(x) != 1 || !x[0].GetJournalUnreadable() || x[0].GetUnreadable() == "" {
		t.Fatalf("summaries = %v", x)
	}
}

// Assumption: a journal the agent cannot read is reported as unreadable (never as "no
// sign-ins"), and reading resumes once it can.
func TestRunReportsAnUnreadableJournal(t *testing.T) {
	j := newFakeJournal()
	j.fail = ErrJournalAccess
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, testConfig(ansibleHost(), j.follow, ""), s); close(done) }()
	waitUntil(t, "an unreadable summary", func() bool {
		_, x := s.got()
		return len(x) > 0 && x[len(x)-1].GetJournalUnreadable()
	})
	_, x := s.got()
	if !strings.Contains(x[len(x)-1].GetUnreadable(), "systemd-journal") || len(x[len(x)-1].GetGroups()) != 0 {
		t.Fatalf("summary = %v", x[len(x)-1])
	}
	cancel()
	<-done
}

// A follow that ends without a record after the saved cursor drops the cursor, so a
// cursor journald no longer knows does not stop sign-ins for good.
func TestRunDropsAStaleCursor(t *testing.T) {
	cursorFile := filepath.Join(t.TempDir(), "cursor")
	if err := os.WriteFile(cursorFile, []byte("gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := newFakeJournal()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, testConfig(ansibleHost(), j.follow, cursorFile), &sink{}); close(done) }()
	w := <-j.follows
	_ = w.CloseWithError(errors.New("journalctl: Failed to seek to cursor"))
	<-j.follows // the retry (after journalRetryMin)
	cancel()
	<-done
	if c := j.followCursors(); c[0] != "gone" || c[1] != "" {
		t.Fatalf("cursors = %q", c)
	}
}

// Assumption: what the window holds when the agent stops is still sent.
func TestRunFlushesOnStop(t *testing.T) {
	j := newFakeJournal()
	cfg := testConfig(ansibleHost(), j.follow, "")
	cfg.Flush = time.Hour
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, cfg, s); close(done) }()
	w := <-j.follows
	if _, err := w.Write(append(entryJSON("ssh.service", "0", certLine, time.Now(), "c1"), '\n')); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	_, x := s.got()
	if len(x) != 1 || len(x[0].GetGroups()) != 1 {
		t.Fatalf("summaries = %v", x)
	}
}
