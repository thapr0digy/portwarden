package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

const testToken = "0123456789abcdef-cli"

func forgetServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.EscapedPath()+" "+r.Header.Get("Authorization"))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestForgetHostCallsTheAPI(t *testing.T) {
	srv, calls := forgetServer(t, 200, `{"host":"web-1","existed":true,"stream_seq":42}`)
	tok := writeFile(t, "token", testToken+"\n")
	var out bytes.Buffer
	if err := forgetHost([]string{"--url", srv.URL, "--token-file", tok, "web-1"}, &out, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != "DELETE /v1/hosts/web-1 Bearer "+testToken {
		t.Fatalf("calls %q", *calls)
	}
	var res inventory.ForgetResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.StreamSeq != 42 {
		t.Fatalf("output %q", out.String())
	}
}

// Without --url the config's listen address and token file are used (loopback for a
// wildcard address).
func TestForgetHostReadsTheConfig(t *testing.T) {
	srv, calls := forgetServer(t, 200, `{}`)
	addr := strings.TrimPrefix(srv.URL, "http://")
	tok := writeFile(t, "token", testToken)
	cfg := writeFile(t, "inventory.json", `{"listen": "`+addr+`", "token_file": "`+tok+`", "nats": {"url": "nats://x:4222"}}`)
	if err := forgetHost([]string{"--config", cfg, "h2"}, &bytes.Buffer{}, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || !strings.HasPrefix((*calls)[0], "DELETE /v1/hosts/h2 ") {
		t.Fatalf("calls %q", *calls)
	}
	if got := apiBase("0.0.0.0:8740"); got != "http://127.0.0.1:8740" {
		t.Fatalf("wildcard listen → %s", got)
	}
	if got := apiBase("[::]:8740"); got != "http://[::1]:8740" {
		t.Fatalf("v6 wildcard listen → %s", got)
	}
	if got := apiBase(""); got != "http://127.0.0.1:8740" {
		t.Fatalf("default listen → %s", got)
	}
}

func TestForgetHostEnvTokenWins(t *testing.T) {
	srv, calls := forgetServer(t, 200, `{}`)
	env := func(k string) string {
		if k == "PORTWARDEN_INVENTORY_TOKEN" {
			return "env-token-0123456789"
		}
		return ""
	}
	if err := forgetHost([]string{"--url", srv.URL, "h3"}, &bytes.Buffer{}, env); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix((*calls)[0], "Bearer env-token-0123456789") {
		t.Fatalf("calls %q", *calls)
	}
}

func TestForgetHostErrors(t *testing.T) {
	tok := writeFile(t, "token", testToken)
	none := func(string) string { return "" }
	srv, calls := forgetServer(t, 503, `{"error":"forget failed; nothing or only part was done, run it again"}`)
	err := forgetHost([]string{"--url", srv.URL, "--token-file", tok, "h1"}, &bytes.Buffer{}, none)
	if err == nil || !strings.Contains(err.Error(), "run it again") {
		t.Fatalf("server error: %v", err)
	}
	for _, args := range [][]string{
		{"--url", srv.URL, "--token-file", tok},              // no host
		{"--url", srv.URL, "--token-file", tok, "a", "b"},    // two hosts
		{"--url", srv.URL, "--token-file", tok, "bad.host"},  // not a subject token
		{"--url", srv.URL, "--token-file", tok, "inventory"}, // reserved
	} {
		if err := forgetHost(args, &bytes.Buffer{}, none); err == nil {
			t.Errorf("%q: accepted", args)
		}
	}
	if len(*calls) != 1 {
		t.Fatalf("invalid invocations reached the API: %q", *calls)
	}
}

func TestRetentionConfig(t *testing.T) {
	var c Config
	if r := c.retention(); r.History != inventory.DefaultHistoryRetention || r.Quarantine != inventory.DefaultQuarantineRetention {
		t.Fatalf("defaults %+v", r)
	}
	cfg := writeFile(t, "inventory.json", `{"retention": {"history": "0s", "quarantine": "48h", "interval": "10m", "batch": 50}}`)
	if err := loadConfig(cfg, &c); err != nil {
		t.Fatal(err)
	}
	r := c.retention()
	if r.History != 0 || r.Quarantine != 48*time.Hour || r.Interval != 10*time.Minute || r.Batch != 50 {
		t.Fatalf("configured %+v", r)
	}
}
