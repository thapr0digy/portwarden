package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

func hostIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var hs []inventory.HostView
	if err := json.Unmarshal(rec.Body.Bytes(), &hs); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var ids []string
	for _, h := range hs {
		ids = append(ids, h.ID)
	}
	return ids
}

func TestHostsPaging(t *testing.T) {
	f := &fakeReader{hostIDs: []string{"a", "b", "c", "d", "e"}}
	s, _ := New(f, token)
	h := s.Handler()

	var all []string
	path := "/v1/hosts?limit=2"
	for range 5 {
		rec := get(t, h, path, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		all = append(all, hostIDs(t, rec)...)
		next := rec.Header().Get("X-Next-Cursor")
		if next == "" {
			if rec.Header().Get("Link") != "" {
				t.Fatal("Link without a next page")
			}
			break
		}
		link := rec.Header().Get("Link")
		if !strings.HasPrefix(link, "</v1/hosts?") || !strings.HasSuffix(link, `>; rel="next"`) ||
			!strings.Contains(link, "cursor="+url.QueryEscape(next)) || !strings.Contains(link, "limit=2") {
			t.Fatalf("Link %q (cursor %q)", link, next)
		}
		path = "/v1/hosts?limit=2&cursor=" + url.QueryEscape(next)
	}
	if strings.Join(all, ",") != "a,b,c,d,e" {
		t.Fatalf("pages gave %v", all)
	}

	// A full last page has no next cursor (the API fetched one row more and got none).
	f.hostIDs = []string{"a", "b"}
	rec := get(t, h, "/v1/hosts?limit=2", token)
	if got := hostIDs(t, rec); len(got) != 2 || rec.Header().Get("X-Next-Cursor") != "" {
		t.Fatalf("exact page: %v next %q", got, rec.Header().Get("X-Next-Cursor"))
	}
	// Neither limit nor cursor: every host, unpaged, as before M8 (no silent truncation).
	f.hostIDs = []string{"a", "b", "c"}
	rec = get(t, h, "/v1/hosts", token)
	if got := hostIDs(t, rec); len(got) != 3 || !f.hostQ.All || rec.Header().Get("X-Next-Cursor") != "" {
		t.Fatalf("unpaged: %v %+v next %q", got, f.hostQ, rec.Header().Get("X-Next-Cursor"))
	}
	// A cursor alone pages with the default limit (1000, asked as 1001).
	get(t, h, "/v1/hosts?cursor="+inventory.EncodeCursor(inventory.HostCursor{ID: "a"}), token)
	if f.hostQ.Limit != 1001 || f.hostQ.All || f.hostQ.After == nil {
		t.Fatalf("cursor only: %+v", f.hostQ)
	}
}

func TestPagingRejectsBadInput(t *testing.T) {
	s, _ := New(&fakeReader{}, token)
	h := s.Handler()
	other := inventory.EncodeCursor(inventory.HostCursor{ID: "h1"})
	for _, path := range []string{
		"/v1/hosts?cursor=!!!", "/v1/hosts?limit=0", "/v1/hosts?limit=10001",
		"/v1/listeners?cursor=" + other, // a hosts cursor on another list
		"/v1/exposure-history?host=h&key=k&cursor=" + other,
	} {
		if rec := get(t, h, path, token); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestListenerAndHistoryCursorsReachTheReader(t *testing.T) {
	f := &fakeReader{}
	s, _ := New(f, token)
	h := s.Handler()
	lc := inventory.ListenerCursor{Host: "h1", Proto: "tcp", Port: 22, Key: "1/tcp/0.0.0.0:22"}
	if rec := get(t, h, "/v1/listeners?host=h1&cursor="+inventory.EncodeCursor(lc), token); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if f.filter.After == nil || *f.filter.After != lc || f.filter.Host != "h1" {
		t.Fatalf("filter %+v", f.filter)
	}
	hc := inventory.HistoryCursor{ID: 9}
	if rec := get(t, h, "/v1/exposure-history?host=h1&key=k&limit=3&cursor="+inventory.EncodeCursor(hc), token); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if f.histQ.After == nil || f.histQ.After.ID != 9 || f.histQ.Limit != 4 || f.histQ.Host != "h1" || f.histQ.Key != "k" {
		t.Fatalf("history query %+v", f.histQ)
	}
}

// pagedListeners returns limit rows, so the API sees a next page and builds its cursor
// from the last row it returns.
type pagedListeners struct{ fakeReader }

func (p *pagedListeners) Listeners(_ context.Context, f inventory.ListenerFilter) ([]inventory.ListenerView, error) {
	var out []inventory.ListenerView
	for i := range f.Limit {
		out = append(out, inventory.ListenerView{Host: "h1", Proto: "tcp", Port: 1000 + i, Key: "k"})
	}
	return out, nil
}

func TestListenerNextCursorIsTheLastRowOfThePage(t *testing.T) {
	s, _ := New(&pagedListeners{}, token)
	rec := get(t, s.Handler(), "/v1/listeners?limit=3", token)
	var ls []inventory.ListenerView
	if err := json.Unmarshal(rec.Body.Bytes(), &ls); err != nil || len(ls) != 3 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var c inventory.ListenerCursor
	if err := inventory.DecodeCursor(rec.Header().Get("X-Next-Cursor"), &c); err != nil || c.Port != 1002 {
		t.Fatalf("next cursor %+v %v", c, err)
	}
}

func del(t *testing.T, h http.Handler, path, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const adminToken = "admin-0123456789abcdef"

// silentReader serves h1 as silent, busy as live; others are unknown.
type silentReader struct{ fakeReader }

func (f *silentReader) Host(_ context.Context, id string) (inventory.HostView, bool, error) {
	switch id {
	case "h1", "a.b", "down":
		return inventory.HostView{ID: id, Silent: true}, true, nil
	case "busy":
		return inventory.HostView{ID: id}, true, nil
	}
	return inventory.HostView{}, false, nil
}

func TestForgetHost(t *testing.T) {
	var forgot []string
	s, _ := New(&silentReader{}, token)
	if err := s.SetForget(token, nil); err == nil {
		t.Fatal("the read token was accepted as the admin token")
	}
	if err := s.SetForget("short", nil); err == nil {
		t.Fatal("a short admin token was accepted")
	}
	if err := s.SetForget(adminToken, func(_ context.Context, host string) (inventory.ForgetResult, error) {
		switch host {
		case "a.b":
			return inventory.ForgetResult{}, inventory.ErrBadHost
		case "down":
			return inventory.ForgetResult{}, errors.New("nats: secret detail")
		}
		forgot = append(forgot, host)
		return inventory.ForgetResult{Host: host, Existed: true, StreamSeq: 7}, nil
	}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if rec := del(t, h, "/v1/hosts/h1", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := del(t, h, "/v1/hosts/h1", "wrong-token-of-some-length"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := del(t, h, "/v1/hosts/h1", token); rec.Code != http.StatusForbidden {
		t.Fatalf("read token: %d", rec.Code)
	}
	// The admin token reads nothing.
	if rec := get(t, h, "/v1/hosts", adminToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin token on a read: %d", rec.Code)
	}
	if len(forgot) != 0 {
		t.Fatal("forgot without the admin token")
	}
	rec := del(t, h, "/v1/hosts/h1", adminToken)
	var res inventory.ForgetResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != http.StatusOK ||
		res != (inventory.ForgetResult{Host: "h1", Existed: true, StreamSeq: 7}) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// A live host needs force; an unknown one is announced anyway.
	if rec := del(t, h, "/v1/hosts/busy", adminToken); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not silent") {
		t.Fatalf("live host: %d %s", rec.Code, rec.Body)
	}
	if rec := del(t, h, "/v1/hosts/busy?force=1", adminToken); rec.Code != http.StatusOK {
		t.Fatalf("forced: %d %s", rec.Code, rec.Body)
	}
	if rec := del(t, h, "/v1/hosts/gone", adminToken); rec.Code != http.StatusOK {
		t.Fatalf("unknown host: %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(forgot, []string{"h1", "busy", "gone"}) {
		t.Fatalf("forgot %v", forgot)
	}
	if rec := del(t, h, "/v1/hosts/a.b", adminToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad host id: %d", rec.Code)
	}
	if rec := del(t, h, "/v1/hosts/down", adminToken); rec.Code != http.StatusServiceUnavailable || containsSecret(rec.Body.String()) {
		t.Fatalf("failure: %d %s", rec.Code, rec.Body)
	}
}

func TestForgetDisabledWithoutAdminToken(t *testing.T) {
	s, _ := New(&silentReader{}, token)
	rec := del(t, s.Handler(), "/v1/hosts/h1", token)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "forget disabled") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
