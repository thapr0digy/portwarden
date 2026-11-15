package access

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

const (
	// DefaultPoll is how often the configuration files are re-read for a change.
	DefaultPoll = 5 * time.Second
	// DefaultFlush is how often, at most, a sign-in summary goes out.
	DefaultFlush = time.Minute
	// journal restarts back off from journalRetryMin to journalRetryMax.
	journalRetryMin = 5 * time.Second
	journalRetryMax = 5 * time.Minute
	// maxCursorBytes bounds the saved journal cursor.
	maxCursorBytes = 4096
	// unlistedKey names, in the trust log, a plain key the shared-key list does not hold.
	unlistedKey = "unlisted"
)

// Sink takes what the reader finds (the publisher). Neither call may block.
type Sink interface {
	// HostAccess is called at start, on a change and at each recheck (same digest).
	HostAccess(*eventsv1.HostAccess)
	// SignIns is called at most every Config.Flush.
	SignIns(*eventsv1.SignInSummary)
}

// Config configures Run.
type Config struct {
	// Root is the host's file system ("/").
	Root fs.FS
	// Accounts are the local accounts whose access is reported (README "Host identity facts").
	Accounts []string
	// SharedKeys is the reviewed shared-key list (nil: no plain key's fingerprint is sent).
	SharedKeys SharedKeys
	// Journal follows sshd's journal; nil reports the journal as unreadable.
	Journal Journal
	// CursorFile keeps the journal position across runs ("" starts a day back each run).
	CursorFile string
	// Poll, Recheck (0: never) and Flush pace the reads and reports.
	Poll, Recheck, Flush time.Duration
	Log                  *slog.Logger
}

type reader struct {
	cfg  Config
	sink Sink

	mu     sync.Mutex
	window *Window
	// cursor is the last journal record read; saved the cursor last written to CursorFile.
	cursor, saved string
	// journalErr is why the journal cannot be read ("" when it can); reported is the value
	// the last summary carried (nil before the first summary).
	journalErr string
	reported   *string
	// keysSeen are the plain keys seen signing in this run: a shared key's name or unlistedKey.
	keysSeen map[string]bool
	access   *eventsv1.HostAccess
	sshd     SSHD
	trust    string
}

// Run reports the host's SSH access state and its sign-ins to sink until ctx ends, then
// sends what the last window holds and returns.
func Run(ctx context.Context, cfg Config, sink Sink) {
	r := &reader{cfg: cfg, sink: sink, window: NewWindow(time.Now(), cfg.SharedKeys), keysSeen: map[string]bool{}}
	r.cursor = r.loadCursor()
	r.saved = r.cursor
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.followJournal(ctx) }()
	go func() { defer wg.Done(); r.watchAccess(ctx) }()
	t := time.NewTicker(cfg.Flush)
	defer t.Stop()
	for done := false; !done; {
		select {
		case <-ctx.Done():
			done = true
		case now := <-t.C:
			r.flush(now)
		}
	}
	wg.Wait()
	r.flush(time.Now())
}

// watchAccess reads the access state at start, re-reads it every Poll and reports it when
// its digest changes, and at every Recheck whatever it is.
func (r *reader) watchAccess(ctx context.Context) {
	r.readAccess(true)
	poll := time.NewTicker(r.cfg.Poll)
	defer poll.Stop()
	var recheck <-chan time.Time
	if r.cfg.Recheck > 0 {
		t := time.NewTicker(r.cfg.Recheck)
		defer t.Stop()
		recheck = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			r.readAccess(false)
		case <-recheck:
			r.readAccess(true)
		}
	}
}

func (r *reader) readAccess(always bool) {
	a, sshd := ReadHostAccess(r.cfg.Root, r.cfg.Accounts)
	r.mu.Lock()
	changed := r.access == nil || r.access.GetDigest() != a.GetDigest()
	if changed {
		r.access, r.sshd = a, sshd
		r.logTrustLocked()
	}
	r.mu.Unlock()
	if changed || always {
		r.sink.HostAccess(a)
	}
}

// logTrustLocked logs the host's trust state when it changes.
func (r *reader) logTrustLocked() {
	if r.access == nil {
		return
	}
	s := TrustState(r.access, r.sshd, len(r.keysSeen) > 0)
	if s == r.trust {
		return
	}
	r.trust = s
	r.cfg.Log.Info("ssh trust state", "state", s,
		"trusted_cas", len(r.access.GetSshd().GetTrustedUserCaKeys()),
		"keys_seen", slices.Sorted(maps.Keys(r.keysSeen)),
		"password_authentication", r.sshd.PasswordAuthentication,
		"permit_root_login", r.sshd.PermitRootLogin,
		"sshd_unreadable", r.access.GetSshd().GetUnreadable())
}

// followJournal reads sshd's journal records into the window, restarting the follow with
// a backoff when it ends.
func (r *reader) followJournal(ctx context.Context) {
	if r.cfg.Journal == nil {
		r.setJournalErr(errors.New("the journal is not read on this host"))
		return
	}
	wait := journalRetryMin
	for ctx.Err() == nil {
		r.mu.Lock()
		cursor := r.cursor
		r.mu.Unlock()
		stream, err := r.cfg.Journal(ctx, cursor)
		if err == nil {
			r.setJournalErr(nil)
			started, lines := time.Now(), 0
			if rerr := readLines(stream, func(line []byte) { lines++; r.entry(line) }); rerr != nil {
				r.cfg.Log.Warn("reading the journal", "error", rerr.Error())
			}
			err = stream.Close()
			if ctx.Err() != nil {
				return
			}
			ran := time.Since(started)
			if lines == 0 && cursor != "" && ran < journalRetryMin {
				// A cursor journald no longer knows (the journal was rotated away or the
				// machine id changed) fails every follow at once: start over a day back.
				r.dropCursor(cursor)
			}
			if ran > journalRetryMax {
				wait = journalRetryMin
			}
		}
		if ctx.Err() != nil {
			return
		}
		r.setJournalErr(err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, journalRetryMax)
	}
}

func (r *reader) entry(line []byte) {
	cursor, login, ok := ParseEntry(line)
	r.mu.Lock()
	defer r.mu.Unlock()
	if cursor != "" {
		r.cursor = cursor
	}
	if !ok {
		return
	}
	r.window.Add(login)
	if login.Method == eventsv1.SignInGroup_KEY {
		name, listed := r.cfg.SharedKeys[login.KeyFingerprint]
		if !listed {
			name = unlistedKey
		}
		if !r.keysSeen[name] {
			r.keysSeen[name] = true
			r.logTrustLocked()
		}
	}
}

// setJournalErr records whether the journal can be read, logging a change.
func (r *reader) setJournalErr(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if msg == r.journalErr {
		return
	}
	r.journalErr = msg
	if msg == "" {
		r.cfg.Log.Info("following sshd's journal for sign-ins")
	} else {
		r.cfg.Log.Warn("sshd's journal cannot be read; sign-ins are reported as unknown", "error", msg)
	}
}

func (r *reader) dropCursor(cursor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cursor == cursor {
		r.cfg.Log.Warn("the journal follow ended at once without a record after the saved cursor; starting a day back")
		r.cursor = ""
	}
}

// flush sends the window's summary when it holds sign-ins, when the journal's readability
// changed since the last summary, or when none was sent yet this run (so Signal knows the
// host reports), then saves the journal position it covers.
func (r *reader) flush(now time.Time) {
	r.mu.Lock()
	if r.window.Empty() && r.reported != nil && *r.reported == r.journalErr {
		r.mu.Unlock()
		return
	}
	s := r.window.Flush(now)
	s.JournalUnreadable, s.Unreadable = r.journalErr != "", clip(r.journalErr, maxReasonBytes)
	reported := r.journalErr
	r.reported = &reported
	cursor := r.cursor
	r.mu.Unlock()
	r.sink.SignIns(s)
	r.saveCursor(cursor)
}

func (r *reader) loadCursor() string {
	if r.cfg.CursorFile == "" {
		return ""
	}
	data, err := os.ReadFile(r.cfg.CursorFile)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	c := strings.TrimSpace(string(data))
	if err != nil || len(c) > maxCursorBytes || strings.ContainsFunc(c, isControl) {
		r.cfg.Log.Warn("journal cursor unusable; starting a day back", "file", r.cfg.CursorFile, "error", fmt.Sprint(err))
		return ""
	}
	return c
}

// saveCursor writes the cursor the last summary covers (atomically), when it moved.
func (r *reader) saveCursor(cursor string) {
	if r.cfg.CursorFile == "" || cursor == "" || cursor == r.saved {
		return
	}
	tmp := r.cfg.CursorFile + ".tmp"
	err := os.MkdirAll(filepath.Dir(r.cfg.CursorFile), 0o700)
	if err == nil {
		err = os.WriteFile(tmp, []byte(cursor+"\n"), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, r.cfg.CursorFile)
	}
	if err != nil {
		r.cfg.Log.Warn("journal cursor not saved; a restart may count sign-ins twice", "error", err.Error())
		return
	}
	r.saved = cursor
}
