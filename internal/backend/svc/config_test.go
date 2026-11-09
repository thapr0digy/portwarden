package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/natsauth"
)

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	var v struct{}
	if err := Load(filepath.Join(dir, "missing.json"), &v); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(p, &v); err == nil || !strings.HasPrefix(err.Error(), p+": ") {
		t.Fatalf("bad json: %v (want the path first)", err)
	}
}

func TestDurationJSON(t *testing.T) {
	var d Duration
	for _, bad := range []string{`90`, `"soon"`, `"-1s"`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := json.Unmarshal([]byte(`"1m30s"`), &d); err != nil || d.D(0) != 90*time.Second {
		t.Fatalf("%v %v", d, err)
	}
	b, err := json.Marshal(Duration(90 * time.Second))
	if err != nil || string(b) != `"1m30s"` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestSecretErrors(t *testing.T) {
	t.Setenv("PW_TEST_SECRET", "")
	dir := t.TempDir()
	if _, err := Secret("PW_TEST_SECRET", ""); err == nil || !strings.Contains(err.Error(), "PW_TEST_SECRET") {
		t.Fatalf("neither set: %v (want the variable named)", err)
	}
	if _, err := Secret("PW_TEST_SECRET", filepath.Join(dir, "gone")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("PW_TEST_SECRET", empty); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty file: %v", err)
	}
	// Whitespace alone in the environment does not count as set.
	t.Setenv("PW_TEST_SECRET", "  ")
	if _, err := Secret("PW_TEST_SECRET", empty); err == nil {
		t.Fatal("blank env accepted")
	}
}

func TestNATSBus(t *testing.T) {
	var called bool
	c := NATS{NkeyFile: "/etc/portwarden/alerter.nk", CAFile: "ca", CertFile: "c", KeyFile: "k"}.Bus(natsauth.RoleAlerter, "portwarden-alerter", func(bool) { called = true })
	if c.URL != "nats://127.0.0.1:4222" || c.NkeyFile != "/etc/portwarden/alerter.nk" || c.Role != natsauth.RoleAlerter ||
		c.Name != "portwarden-alerter" || c.CAFile != "ca" || c.CertFile != "c" || c.KeyFile != "k" || c.Connected == nil {
		t.Fatalf("%+v", c)
	}
	c.Connected(true)
	if !called {
		t.Fatal("connected callback not passed on")
	}
	if c := (NATS{URL: "tls://nats.internal:4222"}).Bus(natsauth.RoleVerifier, "v", nil); c.URL != "tls://nats.internal:4222" {
		t.Fatalf("url %q", c.URL)
	}
}

func TestPermanent(t *testing.T) {
	if Permanent(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	cause := errors.New("invalid byte sequence")
	err := Permanent(cause)
	if !IsPermanent(err) || !errors.Is(err, cause) || err.Error() != "permanent: invalid byte sequence" {
		t.Fatalf("%v", err)
	}
	if IsPermanent(cause) {
		t.Fatal("plain error is permanent")
	}
}

func bareServer(t *testing.T) jetstream.JetStream {
	t.Helper()
	s, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, _ := jetstream.New(nc)
	return js
}

// WaitStream returns the stream once an operator creates it, and ctx's error when it
// ends first.
func TestWaitStream(t *testing.T) {
	js := bareServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := WaitStream(ctx, js); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("no stream: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = js.CreateStream(context.Background(), jetstream.StreamConfig{Name: natsauth.StreamName, Subjects: []string{"asm.>"}})
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := WaitStream(ctx, js)
	if err != nil || s.CachedInfo().Config.Name != natsauth.StreamName {
		t.Fatalf("%v %v", s, err)
	}
}

func TestLeaderValidate(t *testing.T) {
	ok := []Leader{{}, {Poll: Duration(100 * time.Millisecond), Check: Duration(time.Minute)}}
	for _, l := range ok {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	bad := []Leader{{Poll: Duration(50 * time.Millisecond)}, {Check: Duration(2 * time.Minute)}}
	for _, l := range bad {
		if err := l.Validate(); err == nil {
			t.Errorf("%+v: accepted", l)
		}
	}
}
