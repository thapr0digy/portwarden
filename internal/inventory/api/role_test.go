package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/inventory"
)

// A standby serves reads with the same token checks, reports its role on /healthz and in
// X-Portwarden-Role, and refuses to forget (503, Retry-After) only after the admin token
// is checked: an unauthenticated caller learns nothing new. Once it leads, it forgets.
func TestStandbyServesReadsRefusesForget(t *testing.T) {
	s, err := New(&fakeReader{hostIDs: []string{"a"}}, token)
	if err != nil {
		t.Fatal(err)
	}
	forgot := 0
	if err := s.SetForget(adminToken, func(_ context.Context, host string) (inventory.ForgetResult, error) {
		forgot++
		return inventory.ForgetResult{Host: host}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var role leader.State
	s.SetRole(&role)
	h := s.Handler()

	rec := get(t, h, "/healthz", "")
	var body struct {
		OK   bool   `json:"ok"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 || !body.OK || body.Role != "standby" {
		t.Fatalf("healthz on a standby: %d %s", rec.Code, rec.Body)
	}
	if rec := get(t, h, "/v1/hosts", token); rec.Code != http.StatusOK || rec.Header().Get("X-Portwarden-Role") != "standby" {
		t.Fatalf("read on a standby: %d %q", rec.Code, rec.Header().Get("X-Portwarden-Role"))
	}
	for _, tok := range []string{"", "wrong-token-0123456789"} {
		if rec := get(t, h, "/v1/hosts", tok); rec.Code != http.StatusUnauthorized {
			t.Fatalf("read with %q on a standby: %d", tok, rec.Code)
		}
		if rec := del(t, h, "/v1/hosts/gone?force=1", tok); rec.Code != http.StatusUnauthorized {
			t.Fatalf("forget with %q on a standby: %d (want 401, not the standby answer)", tok, rec.Code)
		}
	}
	if rec := del(t, h, "/v1/hosts/gone?force=1", token); rec.Code != http.StatusForbidden {
		t.Fatalf("forget with the read token on a standby: %d", rec.Code)
	}
	rec = del(t, h, "/v1/hosts/gone?force=1", adminToken)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "2" || !strings.Contains(rec.Body.String(), "standby") || forgot != 0 {
		t.Fatalf("forget on a standby: %d %s (forgot %d)", rec.Code, rec.Body, forgot)
	}

	role.Set(leader.Leader, 3)
	if rec := del(t, h, "/v1/hosts/gone?force=1", adminToken); rec.Code != http.StatusOK || forgot != 1 || rec.Header().Get("X-Portwarden-Role") != "leader" {
		t.Fatalf("forget on the leader: %d %s", rec.Code, rec.Body)
	}
	rec = get(t, h, "/healthz", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Role != "leader" {
		t.Fatalf("healthz on the leader: %s", rec.Body)
	}
}

// Without SetRole (a lone instance) the server is the leader.
func TestNoRoleIsLeader(t *testing.T) {
	s, _ := New(&fakeReader{}, token)
	if rec := get(t, s.Handler(), "/healthz", ""); rec.Header().Get("X-Portwarden-Role") != "leader" {
		t.Fatalf("role %q", rec.Header().Get("X-Portwarden-Role"))
	}
}
