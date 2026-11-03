package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

const token = "0123456789abcdef-test"

type fakeReader struct {
	filter  inventory.ListenerFilter
	hostQ   inventory.HostQuery
	histQ   inventory.HistoryQuery
	fail    bool
	hostIDs []string // served by Hosts, in order (default: just h1)
}

func (f *fakeReader) Hosts(_ context.Context, q inventory.HostQuery) ([]inventory.HostView, error) {
	f.hostQ = q
	ids := f.hostIDs
	if ids == nil {
		ids = []string{"h1"}
	}
	out := []inventory.HostView{}
	for _, id := range ids {
		if (q.After == nil || id > q.After.ID) && (q.All || len(out) < q.Limit) {
			out = append(out, inventory.HostView{ID: id})
		}
	}
	return out, nil
}
func (f *fakeReader) Host(_ context.Context, id string) (inventory.HostView, bool, error) {
	return inventory.HostView{ID: id}, id == "h1", nil
}
func (f *fakeReader) Listeners(_ context.Context, lf inventory.ListenerFilter) ([]inventory.ListenerView, error) {
	f.filter = lf
	if f.fail {
		return nil, errors.New("boom: secret detail")
	}
	return []inventory.ListenerView{{Host: "h1", Port: 22}}, nil
}
func (f *fakeReader) History(_ context.Context, q inventory.HistoryQuery) ([]inventory.HistoryView, error) {
	f.histQ = q
	return []inventory.HistoryView{}, nil
}
func (f *fakeReader) Proxies(context.Context, string, string) ([]inventory.ProxyView, error) {
	return []inventory.ProxyView{}, nil
}
func (f *fakeReader) Ping(context.Context) error { return nil }

func get(t *testing.T, h http.Handler, path, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuth(t *testing.T) {
	s, err := New(&fakeReader{}, token)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for _, tok := range []string{"", "wrong-token-of-some-length", token + "x", token[:len(token)-1]} {
		if rec := get(t, h, "/v1/hosts", tok); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d", tok, rec.Code)
		}
	}
	if rec := get(t, h, "/v1/hosts", token); rec.Code != http.StatusOK {
		t.Fatalf("good token: %d %s", rec.Code, rec.Body)
	}
	if rec := get(t, h, "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	if _, err := New(&fakeReader{}, "short"); err == nil {
		t.Fatal("short token accepted")
	}
}

func TestListenerFilters(t *testing.T) {
	f := &fakeReader{}
	s, _ := New(f, token)
	h := s.Handler()
	rec := get(t, h, "/v1/listeners?host=h1&proto=tcp&port=443&min_level=host_firewall_open&unit=nginx.service&exe=/usr/sbin/nginx&limit=5", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// The API asks for one row more than the page (to know whether another follows).
	want := inventory.ListenerFilter{Host: "h1", Proto: "tcp", Port: 443, MinLevel: 3, Unit: "nginx.service", Exe: "/usr/sbin/nginx", Limit: 6}
	if f.filter != want {
		t.Fatalf("filter %+v", f.filter)
	}
	var ls []inventory.ListenerView
	if err := json.Unmarshal(rec.Body.Bytes(), &ls); err != nil || len(ls) != 1 {
		t.Fatalf("body %s", rec.Body)
	}
	for _, bad := range []string{"proto=sctp", "port=0", "port=70000", "port=x", "min_level=extreme", "min_level=9", "limit=0"} {
		if rec := get(t, h, "/v1/listeners?"+bad, token); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	if rec := get(t, h, "/v1/exposure-history?host=h1", token); rec.Code != http.StatusBadRequest {
		t.Errorf("history without key: %d", rec.Code)
	}
	if rec := get(t, h, "/v1/hosts/nope", token); rec.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", rec.Code)
	}
	f.fail = true
	rec = get(t, h, "/v1/listeners", token)
	if rec.Code != http.StatusInternalServerError || json.Valid(rec.Body.Bytes()) == false || containsSecret(rec.Body.String()) {
		t.Fatalf("db error: %d %s", rec.Code, rec.Body)
	}
}

func containsSecret(s string) bool {
	return strings.Contains(s, "secret") || strings.Contains(s, "boom")
}

// fwReader serves one host with a firewall fingerprint and one that never sent one.
type fwReader struct{ fakeReader }

var fwChanged = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

func (f *fwReader) Host(_ context.Context, id string) (inventory.HostView, bool, error) {
	if id == "old" {
		return inventory.HostView{ID: id}, true, nil
	}
	fp := strings.Repeat("ab", 32)
	return inventory.HostView{ID: id, FirewallFingerprint: &fp, FirewallChangedAt: &fwChanged}, true, nil
}

func TestHostFirewallFields(t *testing.T) {
	s, _ := New(&fwReader{}, token)
	h := s.Handler()
	var got map[string]any
	rec := get(t, h, "/v1/hosts/h1", token)
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got["firewall_fingerprint"] != strings.Repeat("ab", 32) || got["firewall_changed_at"] != "2026-11-03T10:00:00Z" {
		t.Fatalf("host = %s", rec.Body)
	}
	got = nil
	rec = get(t, h, "/v1/hosts/old", token)
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if v, ok := got["firewall_fingerprint"]; !ok || v != nil {
		t.Fatalf("a host that never sent one: firewall_fingerprint must be null, got %s", rec.Body)
	}
	if v, ok := got["firewall_changed_at"]; !ok || v != nil {
		t.Fatalf("a host that never sent one: firewall_changed_at must be null, got %s", rec.Body)
	}
}
