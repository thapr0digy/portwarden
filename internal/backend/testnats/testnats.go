// Package testnats starts an embedded nats-server with JetStream for the backend
// services' tests: every role is minted with natsauth.Mint into a temp dir, the server
// loads the authorization block natsauth.Render writes (so each service connects with its
// real least-privilege permissions), and the admin creates the ASM_EVENTS stream. Import
// it from _test.go files only.
package testnats

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Host is the host id minted for tests that publish agent messages.
const Host = "web-1"

// Server is a running test server.
type Server struct {
	URL string
	// Seeds maps each service role (and RoleAdmin, RoleHost) to its seed file (0600).
	Seeds map[natsauth.Role]string
	// Admin is connected as the admin user (it may publish anywhere and read the stream).
	Admin   *nats.Conn
	AdminJS jetstream.JetStream
	// Host is connected as the host user for Host.
	HostJS jetstream.JetStream
	srv    *server.Server
}

// Start mints the users, starts the server and creates the stream. The server and
// connections stop when the test ends.
func Start(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	seeds := map[natsauth.Role]string{}
	for _, m := range []struct {
		r    natsauth.Role
		host string
	}{{natsauth.RoleAdmin, ""}, {natsauth.RoleHost, Host}, {natsauth.RoleInventory, ""}, {natsauth.RoleAlerter, ""}, {natsauth.RoleVerifier, ""}} {
		_, seed, err := natsauth.Mint(users, m.r, m.host)
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(seed)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("minted seed %s has mode %v, want 0600", seed, fi.Mode().Perm())
		}
		seeds[m.r] = seed
	}
	list, err := natsauth.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	block, err := natsauth.Render(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.conf"), []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen: \"127.0.0.1:-1\"\njetstream { store_dir: %q }\ninclude \"users.conf\"\n", filepath.Join(dir, "js"))
	if err := os.WriteFile(filepath.Join(dir, "server.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(filepath.Join(dir, "server.conf"))
	if err != nil {
		t.Fatalf("rendered config does not load: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	ts := &Server{URL: s.ClientURL(), Seeds: seeds, srv: s}
	ts.Admin, ts.AdminJS = connect(t, ts.URL, seeds[natsauth.RoleAdmin], natsauth.InboxPrefix(natsauth.RoleAdmin, ""))
	_, ts.HostJS = connect(t, ts.URL, seeds[natsauth.RoleHost], natsauth.InboxPrefix(natsauth.RoleHost, Host))
	return ts
}

// CreateStream creates ASM_EVENTS as an operator would.
func (s *Server) CreateStream(t *testing.T) jetstream.Stream {
	t.Helper()
	st, err := s.AdminJS.CreateStream(context.Background(), jetstream.StreamConfig{Name: natsauth.StreamName,
		Subjects: []string{"asm.>", "pwb.>"}, AllowDirect: true})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// WaitConsumer waits until the durable consumer name exists (the service is consuming).
func (s *Server) WaitConsumer(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := s.AdminJS.Consumer(ctx, natsauth.StreamName, name)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer %s never appeared", name)
}

func connect(t *testing.T, url, seed, inbox string) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	opt, err := nats.NkeyOptionFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(url, opt, nats.CustomInboxPrefix(inbox))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return nc, js
}
