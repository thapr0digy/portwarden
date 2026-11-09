package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/thapr0digy/portwarden/internal/backend/leader"
)

// pinger is what the health endpoint asks of the store.
type pinger interface {
	Ping(ctx context.Context) error
}

// healthBody is GET /healthz's answer: whether the database is reachable, and this
// instance's role ("leader" or "standby") and epoch (0 while standing by). It holds no
// data and needs no token.
type healthBody struct {
	OK    bool   `json:"ok"`
	Role  string `json:"role"`
	Epoch int64  `json:"epoch"`
	Error string `json:"error,omitempty"`
}

// healthHandler answers GET /healthz: 200 with the role, or 503 when the database is
// unreachable.
func healthHandler(p pinger, role *leader.State) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		body, status := healthBody{OK: true, Role: role.Role().String(), Epoch: role.Epoch()}, http.StatusOK
		if err := p.Ping(ctx); err != nil {
			slog.Warn("healthz: database unreachable", "err", err)
			body.OK, body.Error, status = false, "database unreachable", http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Portwarden-Role", body.Role)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	return mux
}

// serveHealth serves the health endpoint on addr ("" serves nothing) until the returned
// stop is called. A busy address is an error at start (two instances on one machine need
// their own health_listen).
func serveHealth(addr string, p pinger, role *leader.State) (func(), error) {
	if addr == "" {
		return func() {}, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("health_listen: %w", err)
	}
	srv := &http.Server{Handler: healthHandler(p, role), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	slog.Info("health endpoint listening", "addr", ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("health endpoint", "err", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close() // Serve may not have taken it yet (a start failure right after)
	}, nil
}
