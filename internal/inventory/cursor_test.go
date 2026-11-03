package inventory

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 3, 12, 0, 0, 123456789, time.UTC)
	for _, c := range []any{
		HostCursor{ID: "host-1"},
		ListenerCursor{Host: "h", Proto: "tcp", Port: 443, Key: "1/tcp/0.0.0.0:443"},
		HistoryCursor{At: at, ID: 42},
	} {
		s := EncodeCursor(c)
		if strings.ContainsAny(s, "+/=") {
			t.Errorf("cursor %q is not URL-safe", s)
		}
		switch want := c.(type) {
		case HostCursor:
			var got HostCursor
			if err := DecodeCursor(s, &got); err != nil || got != want {
				t.Errorf("host cursor: %+v %v", got, err)
			}
		case ListenerCursor:
			var got ListenerCursor
			if err := DecodeCursor(s, &got); err != nil || got != want {
				t.Errorf("listener cursor: %+v %v", got, err)
			}
		case HistoryCursor:
			var got HistoryCursor
			if err := DecodeCursor(s, &got); err != nil || !got.At.Equal(want.At) || got.ID != want.ID {
				t.Errorf("history cursor: %+v %v", got, err)
			}
		}
	}
}

func TestCursorRejects(t *testing.T) {
	var hc HostCursor
	for _, bad := range []string{"", "!!!", "e30", EncodeCursor(ListenerCursor{Host: "h"}), strings.Repeat("A", 2000)} {
		if err := DecodeCursor(bad, &hc); !errors.Is(err, ErrBadCursor) {
			t.Errorf("%.20q: err %v, want ErrBadCursor", bad, err)
		}
	}
	var lc ListenerCursor
	if err := DecodeCursor(EncodeCursor(HostCursor{ID: "h"}), &lc); !errors.Is(err, ErrBadCursor) {
		t.Error("a hosts cursor was accepted for listeners")
	}
}
