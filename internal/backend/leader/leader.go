// Package leader elects one working instance of a backend service (the alerter, the
// inventory) among several sharing a PostgreSQL database, so the others run as hot
// standbys.
//
// The leader holds a session-level advisory lock on a connection of its own: the lock is
// freed the moment that session ends (a clean stop, a killed process, or the server
// dropping a vanished client, which the session's TCP keepalives bound to about 11 s). A
// standby polls for the lock. On taking it the new leader bumps an epoch row; every write
// of the service first checks the epoch with FOR SHARE (Lease.Fence), so an old leader
// that has not noticed its loss yet can no longer commit. The leader pings its lock
// session every Check; a failed ping or a failed fence closes Lost, and the service stops
// its work and exits (systemd restarts it as a standby). See README "Running a standby".
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrFenced is a write refused because another instance took the lead (the epoch moved
// on). Whoever gets it must stop working: the lease is lost.
var ErrFenced = errors.New("leader: fenced: another instance is the leader now")

// ErrLost is a lease whose lock session failed its check.
var ErrLost = errors.New("leader: lost the lock session")

// Role is what an instance is doing.
type Role int32

const (
	// Standby waits for the lock and does no work.
	Standby Role = iota
	// Leader holds the lock and does the work.
	Leader
)

func (r Role) String() string {
	if r == Leader {
		return "leader"
	}
	return "standby"
}

// State is an instance's role and epoch, read by its health endpoint; safe for
// concurrent use. The zero value is a standby.
type State struct {
	role  atomic.Int32
	epoch atomic.Int64
}

// Role is the current role.
func (s *State) Role() Role { return Role(s.role.Load()) }

// Epoch is the epoch led (0 while standing by).
func (s *State) Epoch() int64 { return s.epoch.Load() }

func (s *State) set(r Role, epoch int64) {
	s.epoch.Store(epoch)
	s.role.Store(int32(r))
}

// Options says which lock and epoch row a service uses.
type Options struct {
	// Service names the service in logs and in the lock session's application_name.
	Service string
	// Key is the advisory lock key; distinct from the service's migration lock.
	Key int64
	// Table holds the epoch row (id 1); created by the service's migrations.
	Table string
	// Poll is how often a standby asks for the lock (0: 1 s).
	Poll time.Duration
	// Check is how often the leader checks its lock session (0: 1 s); a check times out
	// after twice this, at least 2 s.
	Check time.Duration
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

var tableName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Lease is a held leadership.
type Lease interface {
	// Epoch is this lease's epoch.
	Epoch() int64
	// Lost is closed when the lease is lost (Err says why); never on Release.
	Lost() <-chan struct{}
	// Err is why the lease was lost (ErrLost or ErrFenced, wrapped), nil while held.
	Err() error
	// Release stops checking, frees the lock and closes the lock session.
	Release(ctx context.Context) error
}

// PGLease is a Lease held on a PostgreSQL session.
type PGLease struct {
	opts  Options
	conn  *pgx.Conn
	epoch int64
	state *State
	fence string

	lost     chan struct{}
	lostOnce sync.Once
	errMu    sync.Mutex
	err      error

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

var _ Lease = (*PGLease)(nil)

// Wait connects a lock session with base's settings and polls for the lock as a standby
// (state says so) until it is held or ctx ends. The lock session sets TCP keepalives so
// the server frees a vanished leader's lock in about 11 s. Errors are logged without the
// connection's password (pgx redacts it) and retried with backoff (1 s doubling to 30 s);
// only ctx ending returns an error.
func Wait(ctx context.Context, base *pgx.ConnConfig, opts Options, state *State) (*PGLease, error) {
	if !tableName.MatchString(opts.Table) {
		return nil, fmt.Errorf("leader: bad epoch table name %q", opts.Table)
	}
	poll := orDefault(opts.Poll, time.Second)
	state.set(Standby, 0)
	slog.Info("standby: waiting for the leader lock", "service", opts.Service, "poll", poll.String())
	backoff := time.Second
	var conn *pgx.Conn
	for {
		if conn == nil {
			c, err := connect(ctx, base, opts.Service)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				slog.Warn("standby: lock session failed; retrying", "service", opts.Service, "err", err, "in", backoff.String())
				if !sleep(ctx, backoff) {
					return nil, ctx.Err()
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			conn, backoff = c, time.Second
		}
		l, err := tryAcquire(ctx, conn, opts, state)
		switch {
		case err != nil:
			_ = conn.Close(context.Background())
			conn = nil
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			slog.Warn("standby: lock session lost; reconnecting", "service", opts.Service, "err", err)
		case l != nil:
			return l, nil
		}
		if !sleep(ctx, poll) {
			if conn != nil {
				_ = conn.Close(context.Background())
			}
			return nil, ctx.Err()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// connect opens the lock session: its own connection (not the pool), named after the
// service, with server-side keepalives idle 5 s, interval 2 s, count 3.
func connect(ctx context.Context, base *pgx.ConnConfig, service string) (*pgx.Conn, error) {
	cfg := base.Copy()
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["application_name"] = "portwarden-" + service + "-lock"
	cfg.RuntimeParams["tcp_keepalives_idle"] = "5"
	cfg.RuntimeParams["tcp_keepalives_interval"] = "2"
	cfg.RuntimeParams["tcp_keepalives_count"] = "3"
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("leader: lock session: %w", err)
	}
	return conn, nil
}

// tryAcquire asks for the lock once; holding it, it bumps the epoch and starts the
// lease's checks. It returns nil, nil when another instance holds the lock.
func tryAcquire(ctx context.Context, conn *pgx.Conn, opts Options, state *State) (*PGLease, error) {
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", opts.Key).Scan(&ok); err != nil {
		return nil, fmt.Errorf("leader: try lock: %w", err)
	}
	if !ok {
		return nil, nil
	}
	// The bump waits for any write of the old leader holding the row FOR SHARE; once it
	// commits, every later write of the old leader sees another epoch and fails.
	var epoch int64
	err := conn.QueryRow(ctx, "UPDATE "+opts.Table+" SET epoch = epoch + 1, holder = $1, since = now() WHERE id = 1 RETURNING epoch",
		holder()).Scan(&epoch)
	if err != nil {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", opts.Key)
		return nil, fmt.Errorf("leader: bump epoch: %w", err)
	}
	l := &PGLease{opts: opts, conn: conn, epoch: epoch, state: state,
		fence: "SELECT epoch FROM " + opts.Table + " WHERE id = 1 FOR SHARE",
		lost:  make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	state.set(Leader, epoch)
	slog.Info("became leader", "service", opts.Service, "epoch", epoch)
	go l.keep()
	return l, nil
}

// holder names this instance in the epoch row (host name and pid; never served).
func holder() string {
	h, err := os.Hostname()
	if err != nil {
		h = "unknown"
	}
	return h + "/" + strconv.Itoa(os.Getpid())
}

// keep checks the lock session every Check until Release or a failed check. It is the
// only user of the lock session while the lease is held.
func (l *PGLease) keep() {
	defer close(l.done)
	check := orDefault(l.opts.Check, time.Second)
	timeout := max(2*check, 2*time.Second)
	t := time.NewTicker(check)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err := l.conn.Exec(ctx, "SELECT 1")
		cancel()
		if err != nil {
			l.lose(fmt.Errorf("%w: %v", ErrLost, err))
			return
		}
	}
}

func (l *PGLease) lose(err error) {
	l.lostOnce.Do(func() {
		l.errMu.Lock()
		l.err = err
		l.errMu.Unlock()
		l.state.set(Standby, 0)
		slog.Error("lost leadership", "service", l.opts.Service, "epoch", l.epoch, "err", err)
		close(l.lost)
	})
}

// Epoch is the lease's epoch.
func (l *PGLease) Epoch() int64 { return l.epoch }

// Lost is closed when the lease is lost.
func (l *PGLease) Lost() <-chan struct{} { return l.lost }

// Err is why the lease was lost.
func (l *PGLease) Err() error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	return l.err
}

// Fence checks, inside the write transaction tx, that this lease's epoch is still the
// current one, holding the epoch row FOR SHARE until tx ends. A moved epoch (or a lease
// already lost) is ErrFenced and loses the lease.
func (l *PGLease) Fence(ctx context.Context, tx pgx.Tx) error {
	select {
	case <-l.lost:
		return fmt.Errorf("%w (lease lost: %v)", ErrFenced, l.Err())
	default:
	}
	var epoch int64
	if err := tx.QueryRow(ctx, l.fence).Scan(&epoch); err != nil {
		return fmt.Errorf("leader: fence: %w", err)
	}
	if epoch != l.epoch {
		err := fmt.Errorf("%w (epoch %d, ours %d)", ErrFenced, epoch, l.epoch)
		l.lose(err)
		return err
	}
	return nil
}

// Release stops the checks, unlocks and closes the lock session; the next standby's poll
// takes the lock. Safe to call more than once and after a loss.
func (l *PGLease) Release(ctx context.Context) error {
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
	l.state.set(Standby, 0)
	if l.Err() != nil || l.conn.IsClosed() {
		// Lost: the session is broken or fenced; closing it frees the lock if it is not.
		_ = l.conn.Close(ctx)
		return nil
	}
	_, uerr := l.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", l.opts.Key)
	cerr := l.conn.Close(ctx)
	if uerr != nil {
		return fmt.Errorf("leader: unlock: %w", uerr)
	}
	if cerr != nil {
		return fmt.Errorf("leader: close lock session: %w", cerr)
	}
	slog.Info("released leadership", "service", l.opts.Service, "epoch", l.epoch)
	return nil
}
