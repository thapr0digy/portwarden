// Package api serves the inventory read-only over HTTP as JSON:
//
//	GET /healthz                                   (no auth) database reachable
//	GET /v1/hosts                                  every host
//	GET /v1/hosts/{id}                             one host
//	GET /v1/listeners?host=&proto=&port=&addr=&min_level=&unit=&exe=&limit=
//	GET /v1/exposure-history?host=&key=&limit=     one listener's level changes, newest first
//	GET /v1/proxy-routes?host=&proxy=              proxies with their route sets
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
	r     inventory.Reader
	token [sha256.Size]byte
}

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
	hs, err := s.r.Hosts(r.Context())
	reply(w, hs, err)
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
	if f.Limit, err = intParam(q.Get("limit"), 1, 10000); err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	ls, err := s.r.Listeners(r.Context(), f)
	reply(w, ls, err)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, key := q.Get("host"), q.Get("key")
	if host == "" || key == "" {
		writeError(w, http.StatusBadRequest, "host and key are required")
		return
	}
	limit, err := intParam(q.Get("limit"), 1, 10000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	hs, err := s.r.History(r.Context(), host, key, limit)
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
