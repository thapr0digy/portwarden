package pg

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/backend/leader/leadertest"
)

// Every write of the inventory goes through the fenced tx helper: a write added straight
// on the pool would let an old leader commit after a new one started.
func TestWritesGoThroughTheFence(t *testing.T) {
	leadertest.UnfencedWrites(t, ".", "migrate", "tx")
}
