package natsauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const hostA, hostB = "aaaa1111", "bbbb2222"

// authServer mints every role into a temp dir, renders the config, and starts an
// embedded nats-server with JetStream from it. It returns the server URL and the dir.
func authServer(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, m := range []struct {
		r    Role
		host string
	}{{RoleAdmin, ""}, {RoleHost, hostA}, {RoleHost, hostB}, {RoleInventory, ""}, {RoleAlerter, ""}, {RoleVerifier, ""}} {
		if _, _, err := Mint(filepath.Join(dir, "users"), m.r, m.host); err != nil {
			t.Fatal(err)
		}
	}
	users, err := Load(filepath.Join(dir, "users"))
	if err != nil {
		t.Fatal(err)
	}
	block, err := Render(users)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.conf"), []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen: \"127.0.0.1:-1\"\njetstream { store_dir: %q }\ninclude \"users.conf\"\n", filepath.Join(dir, "js"))
	if err := os.WriteFile(filepath.Join(dir, "server.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(filepath.Join(dir, "server.conf"))
	if err != nil {
		t.Fatalf("rendered config does not load: %v\n%s", err, block)
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	return s.ClientURL(), filepath.Join(dir, "users")
}

type conn struct {
	nc *nats.Conn
	js jetstream.JetStream
	mu sync.Mutex
	// violations seen by the async error handler
	violations []string
}

func (c *conn) denied(subject string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.violations {
		if strings.Contains(v, subject) {
			return true
		}
	}
	return false
}

func connect(t *testing.T, url, usersDir string, r Role, host string) *conn {
	t.Helper()
	opt, err := nats.NkeyOptionFromSeed(filepath.Join(usersDir, UserName(r, host)+".nk"))
	if err != nil {
		t.Fatal(err)
	}
	c := &conn{}
	nc, err := nats.Connect(url, opt, nats.CustomInboxPrefix(InboxPrefix(r, host)),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			c.mu.Lock()
			c.violations = append(c.violations, err.Error())
			c.mu.Unlock()
		}))
	if err != nil {
		t.Fatalf("%s connect: %v", r, err)
	}
	t.Cleanup(nc.Close)
	c.nc = nc
	c.js, err = jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func publish(c *conn, subject string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_, err := c.js.Publish(ctx, subject, []byte("x"))
	return err
}

func TestPermissionMatrix(t *testing.T) {
	url, users := authServer(t)
	admin := connect(t, url, users, RoleAdmin, "")
	ctx := context.Background()
	if _, err := admin.js.CreateStream(ctx, jetstream.StreamConfig{Name: StreamName, Subjects: []string{"asm.>"}, AllowDirect: true}); err != nil {
		t.Fatal(err)
	}

	a := connect(t, url, users, RoleHost, hostA)
	if err := publish(a, "asm."+hostA+".heartbeat"); err != nil {
		t.Fatalf("host A must publish under its own prefix: %v", err)
	}
	if err := publish(a, "asm."+hostB+".heartbeat"); err == nil {
		t.Fatal("host A published under host B's prefix")
	}
	time.Sleep(100 * time.Millisecond)
	if !a.denied("asm." + hostB + ".heartbeat") {
		t.Fatalf("no permission violation for host A on host B's prefix: %v", a.violations)
	}
	if _, err := a.js.Stream(ctx, StreamName); err == nil {
		t.Fatal("a host may not look up the stream")
	}
	sub, err := a.nc.SubscribeSync("asm.>")
	if err == nil {
		_ = a.nc.Flush()
		time.Sleep(100 * time.Millisecond)
		if !a.denied("asm.>") {
			t.Fatal("a host may not subscribe to asm.>")
		}
		_ = sub.Unsubscribe()
	}

	for _, svc := range []struct {
		r       Role
		mayPub  string
		mayNot  string
		durable string
	}{
		{RoleInventory, "asm." + hostA + ".exposure.changed", "asm." + hostA + ".listener.opened", ConsumerInventory},
		{RoleVerifier, "asm." + hostA + ".exposure.confirmed", "asm." + hostA + ".exposure.changed", ConsumerVerifier},
		{RoleAlerter, "", "asm." + hostA + ".exposure.changed", ConsumerAlerter},
	} {
		t.Run(string(svc.r), func(t *testing.T) {
			c := connect(t, url, users, svc.r, "")
			cons, err := c.js.CreateOrUpdateConsumer(ctx, StreamName, jetstream.ConsumerConfig{
				Durable: svc.durable, AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: "asm.>",
			})
			if err != nil {
				t.Fatalf("own durable: %v", err)
			}
			batch, err := cons.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for m := range batch.Messages() {
				if err := m.DoubleAck(ctx); err != nil {
					t.Fatalf("ack: %v", err)
				}
				n++
			}
			if n != 1 {
				t.Fatalf("fetched %d messages (err %v)", n, batch.Error())
			}
			if svc.mayPub != "" {
				if err := publish(c, svc.mayPub); err != nil {
					t.Fatalf("publish %s: %v", svc.mayPub, err)
				}
			}
			if err := publish(c, svc.mayNot); err == nil {
				t.Fatalf("published %s", svc.mayNot)
			}
			other := ConsumerInventory
			if svc.r == RoleInventory {
				other = ConsumerAlerter
			}
			cctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
			defer cancel()
			if _, err := c.js.CreateOrUpdateConsumer(cctx, StreamName, jetstream.ConsumerConfig{Durable: other}); err == nil {
				t.Fatalf("%s created another service's consumer %s", svc.r, other)
			}
			if err := c.js.DeleteStream(cctx, StreamName); err == nil || errors.Is(err, jetstream.ErrStreamNotFound) {
				t.Fatalf("%s deleted the stream (err %v)", svc.r, err)
			}
		})
	}
}

func TestMintNeverOverwritesAndKeepsSeedPrivate(t *testing.T) {
	dir := t.TempDir()
	_, seed, err := Mint(dir, RoleHost, hostA)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(seed)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("seed mode %v err %v", st.Mode(), err)
	}
	if _, _, err := Mint(dir, RoleHost, hostA); err == nil {
		t.Fatal("minting the same user twice must fail, not replace the seed")
	}
}

func TestBadHostIDs(t *testing.T) {
	for _, h := range []string{"", "a.b", "a*", ">", "a b", `a"b`} {
		if _, _, err := Permissions(RoleHost, h); err == nil {
			t.Errorf("host id %q accepted", h)
		}
	}
	if _, _, err := Permissions("nobody", ""); err == nil {
		t.Error("unknown role accepted")
	}
}
