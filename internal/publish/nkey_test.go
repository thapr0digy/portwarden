package publish

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

// TestNkeyHostUserPublishes runs the agent's publisher as a minted host user against a
// server configured by natsauth.Render: the host may publish only asm.<host>.>, cannot
// look up the stream, and its acks arrive on _INBOX_<host>.
func TestNkeyHostUserPublishes(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	if _, _, err := natsauth.Mint(users, natsauth.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	_, seed, err := natsauth.Mint(users, natsauth.RoleHost, testHost)
	if err != nil {
		t.Fatal(err)
	}
	list, err := natsauth.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	block, err := natsauth.Render(list)
	if err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen: \"127.0.0.1:-1\"\njetstream { store_dir: %q }\n%s", filepath.Join(dir, "js"), block)
	if err := os.WriteFile(filepath.Join(dir, "s.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(filepath.Join(dir, "s.conf"))
	if err != nil {
		t.Fatal(err)
	}
	opts.NoLog, opts.NoSigs = true, true
	s := startServerWith(t, opts)
	defer stop(s)

	adminOpt, err := nats.NkeyOptionFromSeed(filepath.Join(users, "admin.nk"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := nats.Connect(s.ClientURL(), adminOpt)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	ajs, _ := jetstream.New(admin)
	ctx := context.Background()
	stream, err := ajs.CreateStream(ctx, jetstream.StreamConfig{Name: streamName, Subjects: []string{"asm.>"}})
	if err != nil {
		t.Fatal(err)
	}

	p, err := New(ctx, Config{URL: s.ClientURL(), HostID: testHost, NkeyFile: seed})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Heartbeat(0)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m, err := stream.GetLastMsgForSubject(ctx, "asm."+testHost+".heartbeat")
		if err == nil && m != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("heartbeat from the nkey host user never reached the stream")
}

func TestNewRejectsUnreadableNkey(t *testing.T) {
	if _, err := New(context.Background(), Config{URL: "nats://127.0.0.1:1", HostID: testHost, NkeyFile: "/nonexistent/x.nk"}); err == nil {
		t.Fatal("want error for unreadable nkey seed")
	}
	if _, err := New(context.Background(), Config{URL: "nats://127.0.0.1:1", HostID: testHost, NkeyFile: "x", CredsFile: "y"}); err == nil {
		t.Fatal("want error for both creds and nkey")
	}
}
