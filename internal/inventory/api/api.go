// Package api serves the inventory over HTTP as JSON:
//
//	GET    /healthz                                (no auth) database reachable
//	GET    /v1/hosts?limit=&cursor=                hosts by id
//	GET    /v1/hosts/{id}                          one host
//	DELETE /v1/hosts/{id}                          forget a decommissioned host (M8)
//	GET    /v1/listeners?host=&proto=&port=&addr=&min_level=&unit=&exe=&limit=&cursor=
//	GET    /v1/exposure-history?host=&key=&limit=&cursor=  one listener's level changes, newest first
//	GET    /v1/proxy-routes?host=&proxy=           proxies with their route sets
//
// Lists are keyset-paged (M8): at most limit rows (default 1000, at most 10 000); when
// more follow, the response has "X-Next-Cursor: <cursor>" and "Link: <same query with
// cursor=…>; rel="next"". The body stays a JSON array. A cursor is opaque and belongs to
// its list (another list's, or a mangled one, is 400); keep the other parameters the same
// from page to page.
//
// Every /v1 request needs "Authorization: Bearer <token>"; the token is compared in
// constant time (over SHA-256 digests, so its length does not leak either).
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/inventory"
	"github.com/thapr0digy/portwarden/internal/model"
)

// MinTokenLength is the shortest bearer token accepted.
const MinTokenLength = 16

// Server is the API.
type Server struct {
	r      inventory.Reader
	token  [sha256.Size]byte
	forget func(ctx context.Context, host string) (inventory.ForgetResult, error)
}

// SetForget enables DELETE /v1/hosts/{id} (the consumer's Forget); without it the call
// answers 503.
func (s *Server) SetForget(f func(ctx context.Context, host string) (inventory.ForgetResult, error)) {
	s.forget = f
}

const (
	defaultPage = 1000
	maxPage     = 10000
)

// New returns a server that requires token on /v1.
func New(r inventory.Reader, token string) (*Server, error) {
	token = strings.TrimSpace(token)
	if len(token) < MinTokenLength {
		return nil, errors.New("api: the bearer token must be at least 16 characters")
	}
	return &Server{r: r, token: sha256.Sum256([]byte(token))}, nil
}

// Handler routes requests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /v1/hosts", s.auth(s.hosts))
	mux.Handle("GET /v1/hosts/{id}", s.auth(s.host))
	mux.Handle("DELETE /v1/hosts/{id}", s.auth(s.forgetHost))
	mux.Handle("GET /v1/listeners", s.auth(s.listeners))
	mux.Handle("GET /v1/exposure-history", s.auth(s.history))
	mux.Handle("GET /v1/proxy-routes", s.auth(s.proxies))
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(f func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(strings.TrimSpace(got)))
		if !ok || subtle.ConstantTimeCompare(sum[:], s.token[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="portwarden-inventory"`)
			writeError(w, http.StatusUnauthorized, "missing or wrong bearer token")
			return
		}
		f(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.r.Ping(ctx); err != nil {
		slog.Warn("healthz: database unreachable", "err", err)
		writeError(w, http.StatusServiceUnavailable, "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	limit, err := pageLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q := inventory.HostQuery{Limit: limit + 1}
	if c := r.URL.Query().Get("cursor"); c != "" {
		q.After = &inventory.HostCursor{}
		if inventory.DecodeCursor(c, q.After) != nil {
			writeError(w, http.StatusBadRequest, "cursor: invalid")
			return
		}
	}
	hs, err := s.r.Hosts(r.Context(), q)
	if err == nil && len(hs) > limit {
		hs = hs[:limit]
		setNext(w, r, inventory.EncodeCursor(inventory.HostCursor{ID: hs[limit-1].ID}))
	}
	reply(w, hs, err)
}

func (s *Server) forgetHost(w http.ResponseWriter, r *http.Request) {
	if s.forget == nil {
		writeError(w, http.StatusServiceUnavailable, "forget is unavailable (no bus)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.forget(ctx, r.PathValue("id"))
	switch {
	case errors.Is(err, inventory.ErrBadHost):
		writeError(w, http.StatusBadRequest, "host id must be one plain subject token (and not reserved)")
	case err != nil:
		slog.Error("api: forget failed", "host", r.PathValue("id"), "err", err)
		writeError(w, http.StatusServiceUnavailable, "forget failed; nothing or only part was done, run it again")
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// pageLimit reads ?limit= (default 1000, 1 to 10 000).
func pageLimit(r *http.Request) (int, error) {
	n, err := intParam(r.URL.Query().Get("limit"), 1, maxPage)
	if err != nil {
		return 0, errors.New("limit: " + err.Error())
	}
	if n == 0 {
		n = defaultPage
	}
	return n, nil
}

// setNext announces the next page: X-Next-Cursor, and a Link to the same query with it.
func setNext(w http.ResponseWriter, r *http.Request, cursor string) {
	q := r.URL.Query()
	q.Set("cursor", cursor)
	w.Header().Set("X-Next-Cursor", cursor)
	w.Header().Set("Link", "<"+r.URL.Path+"?"+q.Encode()+`>; rel="next"`)
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	h, ok, err := s.r.Host(r.Context(), r.PathValue("id"))
	if err == nil && !ok {
		writeError(w, http.StatusNotFound, "no such host")
		return
	}
	reply(w, h, err)
}

func (s *Server) listeners(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := inventory.ListenerFilter{Host: q.Get("host"), Proto: q.Get("proto"), Addr: q.Get("addr"), Unit: q.Get("unit"), Exe: q.Get("exe")}
	if f.Proto != "" && f.Proto != "tcp" && f.Proto != "udp" {
		writeError(w, http.StatusBadRequest, "proto must be tcp or udp")
		return
	}
	var err error
	if f.Port, err = intParam(q.Get("port"), 1, 65535); err != nil {
		writeError(w, http.StatusBadRequest, "port: "+err.Error())
		return
	}
	if f.MinLevel, err = levelParam(q.Get("min_level")); err != nil {
		writeError(w, http.StatusBadRequest, "min_level: "+err.Error())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.Limit = limit + 1
	if c := q.Get("cursor"); c != "" {
		f.After = &inventory.ListenerCursor{}
		if inventory.DecodeCursor(c, f.After) != nil {
			writeError(w, http.StatusBadRequest, "cursor: invalid")
			return
		}
	}
	ls, err := s.r.Listeners(r.Context(), f)
	if err == nil && len(ls) > limit {
		ls = ls[:limit]
		l := ls[limit-1]
		setNext(w, r, inventory.EncodeCursor(inventory.ListenerCursor{Host: l.Host, Proto: l.Proto, Port: l.Port, Key: l.Key}))
	}
	reply(w, ls, err)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, key := q.Get("host"), q.Get("key")
	if host == "" || key == "" {
		writeError(w, http.StatusBadRequest, "host and key are required")
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hq := inventory.HistoryQuery{Host: host, Key: key, Limit: limit + 1}
	if c := q.Get("cursor"); c != "" {
		hq.After = &inventory.HistoryCursor{}
		if inventory.DecodeCursor(c, hq.After) != nil {
			writeError(w, http.StatusBadRequest, "cursor: invalid")
			return
		}
	}
	hs, err := s.r.History(r.Context(), hq)
	if err == nil && len(hs) > limit {
		hs = hs[:limit]
		last := hs[limit-1]
		setNext(w, r, inventory.EncodeCursor(inventory.HistoryCursor{At: last.At, ID: last.ID}))
	}
	reply(w, hs, err)
}

func (s *Server) proxies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ps, err := s.r.Proxies(r.Context(), q.Get("host"), q.Get("proxy"))
	reply(w, ps, err)
}

func intParam(v string, lo, hi int) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, errors.New("must be a number from " + strconv.Itoa(lo) + " to " + strconv.Itoa(hi))
	}
	return n, nil
}

// levelParam accepts a level name ("host_firewall_open") or number (1–5).
func levelParam(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 5 {
		return n, nil
	}
	for n := model.ExposureLocal; n <= model.ExposureConfirmed; n++ {
		if n.String() == v {
			return int(n), nil
		}
	}
	return 0, errors.New("must be local, bound, host_firewall_open, cloud_open, confirmed or 1-5")
}

func reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		slog.Error("api: query failed", "err", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("api: write failed", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
