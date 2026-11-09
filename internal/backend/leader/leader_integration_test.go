//go:build integration

package leader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const testTable = "leader_itest"

func dsn(t *testing.T) string {
	t.Helper()
	d := os.Getenv("PORTWARDEN_TEST_PG")
	if d == "" {
		t.Fatal("PORTWARDEN_TEST_PG is not set; run the integration tests through dev/itest.sh")
	}
	return d
}

func baseConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	c, err := pgx.ParseConfig(dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// admin is an ordinary session for the test's own queries; it creates the epoch table.
func admin(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	if _, err := c.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+testTable+` (id smallint PRIMARY KEY CHECK (id = 1),
		epoch bigint NOT NULL, holder text NOT NULL DEFAULT '', since timestamptz);
		INSERT INTO `+testTable+` (id, epoch) VALUES (1, 0) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	return c
}

// keys gives every test its own lock, so tests never wait on one another.
var nextKey atomic.Int64

func opts(service string) Options {
	return Options{Service: service, Key: 0x7077746573740000 + nextKey.Add(1), Table: testTable,
		Poll: 100 * time.Millisecond, Check: 200 * time.Millisecond}
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func release(t *testing.T, l *PGLease) {
	t.Helper()
	if err := l.Release(context.Background()); err != nil {
		t.Errorf("release: %v", err)
	}
}

// Two instances: exactly one leads, the other stays a standby until the first lets go.
func TestLeaderTwoInstancesOneLeads(t *testing.T) {
	admin(t)
	o := opts("two")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var a, b State
	la, err := Wait(ctx, baseConfig(t), o, &a)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *PGLease, 1)
	go func() {
		lb, err := Wait(ctx, baseConfig(t), o, &b)
		if err != nil {
			t.Error(err)
		}
		got <- lb
	}()
	time.Sleep(500 * time.Millisecond)
	if a.Role() != Leader || b.Role() != Standby || a.Epoch() != la.Epoch() {
		t.Fatalf("roles: a %s (epoch %d), b %s", a.Role(), a.Epoch(), b.Role())
	}
	select {
	case <-got:
		t.Fatal("the standby took a held lock")
	default:
	}
	release(t, la)
	lb := <-got
	defer release(t, lb)
	if lb.Epoch() != la.Epoch()+1 || b.Role() != Leader || a.Role() != Standby {
		t.Fatalf("handover: epochs %d → %d, a %s, b %s", la.Epoch(), lb.Epoch(), a.Role(), b.Role())
	}
}

// Ten instances starting at once: exactly one wins the lock.
func TestLeaderRaceAtStart(t *testing.T) {
	admin(t)
	o := opts("race")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var won atomic.Int32
	var mu sync.Mutex
	var leases []*PGLease
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 10 {
		wg.Go(func() {
			<-start
			l, err := Wait(ctx, baseConfig(t), o, &State{})
			if err != nil {
				return // ctx ended as a standby
			}
			won.Add(1)
			mu.Lock()
			leases = append(leases, l)
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()
	for _, l := range leases {
		release(t, l)
	}
	if won.Load() != 1 {
		t.Fatalf("%d instances lead", won.Load())
	}
}

// Releasing hands over within two polls, and the epoch moves on.
func TestLeaderHandoverOnRelease(t *testing.T) {
	admin(t)
	o := opts("release")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	la, err := Wait(ctx, baseConfig(t), o, &State{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *PGLease, 1)
	go func() {
		l, err := Wait(ctx, baseConfig(t), o, &State{})
		if err != nil {
			t.Error(err)
		}
		got <- l
	}()
	time.Sleep(300 * time.Millisecond)
	released := time.Now()
	release(t, la)
	lb := <-got
	defer release(t, lb)
	if took := time.Since(released); took > 2*o.Poll+500*time.Millisecond {
		t.Fatalf("handover took %s", took)
	}
	if lb.Epoch() <= la.Epoch() {
		t.Fatalf("epoch %d after %d", lb.Epoch(), la.Epoch())
	}
	t.Logf("handover on release: %s", time.Since(released))
}

// TestLeaderHelperHold is the child process of TestLeaderHandoverOnKill: it takes the
// lock, says so on stdout and holds it until killed.
func TestLeaderHelperHold(t *testing.T) {
	key := os.Getenv("PORTWARDEN_LEADER_HOLD_KEY")
	if key == "" {
		t.Skip("child process of TestLeaderHandoverOnKill")
	}
	k, _ := strconv.ParseInt(key, 10, 64)
	o := opts("hold")
	o.Key = k
	if _, err := Wait(context.Background(), baseConfig(t), o, &State{}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOLDING")
	select {}
}

// A leader killed with SIGKILL: its session ends with the process, so the standby leads
// within a second or two.
func TestLeaderHandoverOnKill(t *testing.T) {
	admin(t)
	o := opts("kill")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLeaderHelperHold$", "-test.v")
	cmd.Env = append(os.Environ(), "PORTWARDEN_LEADER_HOLD_KEY="+strconv.FormatInt(o.Key, 10))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitFor(t, "the child to hold the lock", 15*time.Second, func() bool { return bytes.Contains(out.Bytes(), []byte("HOLDING")) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var st State
	got := make(chan *PGLease, 1)
	go func() {
		l, err := Wait(ctx, baseConfig(t), o, &st)
		if err != nil {
			t.Error(err)
		}
		got <- l
	}()
	time.Sleep(500 * time.Millisecond)
	if st.Role() != Standby {
		t.Fatal("led while the child held the lock")
	}
	killed := time.Now()
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	l := <-got
	defer release(t, l)
	if took := time.Since(killed); took > 3*time.Second {
		t.Fatalf("handover after SIGKILL took %s", took)
	}
	t.Logf("handover after SIGKILL: %s", time.Since(killed))
}

// An administrator terminating the leader's lock session: the lease is lost within a few
// checks (ErrLost), the state drops to standby, and a standby leads.
func TestLeaderLockSessionTerminated(t *testing.T) {
	adm := admin(t)
	o := opts("terminated")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var a State
	la, err := Wait(ctx, baseConfig(t), o, &a)
	if err != nil {
		t.Fatal(err)
	}
	defer release(t, la)
	got := make(chan *PGLease, 1)
	go func() {
		l, err := Wait(ctx, baseConfig(t), o, &State{})
		if err != nil {
			t.Error(err)
		}
		got <- l
	}()
	pid := la.conn.PgConn().PID()
	if _, err := adm.Exec(ctx, "SELECT pg_terminate_backend($1)", int32(pid)); err != nil {
		t.Fatal(err)
	}
	terminated := time.Now()
	select {
	case <-la.Lost():
	case <-time.After(3 * time.Second):
		t.Fatal("the lease was not lost within 3 s of its session ending")
	}
	if !errors.Is(la.Err(), ErrLost) || a.Role() != Standby {
		t.Fatalf("err %v, role %s", la.Err(), a.Role())
	}
	t.Logf("lease lost %s after its session was terminated", time.Since(terminated))
	lb := <-got
	defer release(t, lb)
	if lb.Epoch() <= la.Epoch() {
		t.Fatalf("epoch %d after %d", lb.Epoch(), la.Epoch())
	}
}

// The fence: a write of the old leader after the new epoch is refused (ErrFenced, the
// lease lost, nothing committed), and a write in flight while the new leader takes over
// commits before the epoch moves, never after.
func TestFenceBlocksOldLeader(t *testing.T) {
	adm := admin(t)
	if _, err := adm.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS leader_itest_rows (v text)"); err != nil {
		t.Fatal(err)
	}
	o := opts("fence")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := Wait(ctx, baseConfig(t), o, &State{})
	if err != nil {
		t.Fatal(err)
	}
	defer release(t, l)
	write := func(v string, before func(pgx.Tx)) error {
		tx, err := adm.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := l.Fence(ctx, tx); err != nil {
			return err
		}
		if before != nil {
			before(tx)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO leader_itest_rows VALUES ($1)", v); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := write("first", nil); err != nil {
		t.Fatal(err)
	}

	// In flight: the epoch bump (another session, as a new leader) waits for the write.
	other, err := pgx.Connect(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	bumped := make(chan time.Time, 1)
	var committed time.Time
	if err := write("in flight", func(pgx.Tx) {
		go func() {
			_, err := other.Exec(ctx, "UPDATE "+testTable+" SET epoch = epoch + 1 WHERE id = 1")
			if err != nil {
				t.Error(err)
			}
			bumped <- time.Now()
		}()
		time.Sleep(300 * time.Millisecond) // the bump is blocked on our FOR SHARE meanwhile
		committed = time.Now()
	}); err != nil {
		t.Fatal(err)
	}
	if at := <-bumped; at.Before(committed) {
		t.Fatal("the epoch moved while the old leader's write was in flight")
	}

	// After: refused, lost, nothing written.
	if err := write("after", nil); !errors.Is(err, ErrFenced) {
		t.Fatalf("write after the new epoch: %v", err)
	}
	select {
	case <-l.Lost():
	default:
		t.Fatal("a fenced lease was not lost")
	}
	var n int
	if err := adm.QueryRow(ctx, "SELECT count(*) FROM leader_itest_rows WHERE v = 'after'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("fenced write committed: %d, %v", n, err)
	}
}

// The design's bound on a vanished leader rests on the server honouring per-session TCP
// keepalives: the lock session must carry them.
func TestKeepalivesSet(t *testing.T) {
	ctx := context.Background()
	c, err := connect(ctx, baseConfig(t), "keepalive")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	for name, want := range map[string]string{"tcp_keepalives_idle": "5", "tcp_keepalives_interval": "2", "tcp_keepalives_count": "3",
		"application_name": "portwarden-keepalive-lock"} {
		var got string
		if err := c.QueryRow(ctx, "SHOW "+name).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// A database that cannot be reached at start: Wait stays a standby, retries, returns only
// when ctx ends, and never logs the password.
func TestDBUnreachableAtStart(t *testing.T) {
	u, err := url.Parse(dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := u.User.Password()
	u.Host = "127.0.0.1:1" // nothing listens there
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	var st State
	if _, err := Wait(ctx, cfg, opts("unreachable"), &st); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if st.Role() != Standby {
		t.Fatal("not a standby")
	}
	if !bytes.Contains(logs.Bytes(), []byte("lock session failed")) {
		t.Fatalf("no retry logged: %s", logs.Bytes())
	}
	if pass != "" && bytes.Contains(logs.Bytes(), []byte(pass)) {
		t.Fatal("the password is in the log")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}
