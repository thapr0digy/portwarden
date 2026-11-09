package leader

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRoleAndState(t *testing.T) {
	var s State
	if s.Role() != Standby || s.Role().String() != "standby" || s.Epoch() != 0 {
		t.Fatalf("zero state: %s %d", s.Role(), s.Epoch())
	}
	s.set(Leader, 7)
	if s.Role() != Leader || s.Role().String() != "leader" || s.Epoch() != 7 {
		t.Fatalf("leader: %s %d", s.Role(), s.Epoch())
	}
}

// The epoch table's name is spliced into SQL: anything but a plain identifier is refused
// before a connection is made.
func TestWaitRefusesABadTableName(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgres://u@127.0.0.1:1/db")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "x; DROP TABLE hosts", "Leader", "a.b"} {
		if _, err := Wait(context.Background(), cfg, Options{Service: "t", Key: 1, Table: name}, &State{}); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}
