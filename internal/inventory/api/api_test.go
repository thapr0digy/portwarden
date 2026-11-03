package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

const token = "0123456789abcdef-test"

type fakeReader struct {
	filter inventory.ListenerFilter
	fail   bool
}

func (f *fakeReader) Hosts(context.Context) ([]inventory.HostView, error) {
	return []inventory.HostView{{ID: "h1"}}, nil
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
func (f *fakeReader) History(context.Context, string, string, int) ([]inventory.HistoryView, error) {
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
	want := inventory.ListenerFilter{Host: "h1", Proto: "tcp", Port: 443, MinLevel: 3, Unit: "nginx.service", Exe: "/usr/sbin/nginx", Limit: 5}
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
