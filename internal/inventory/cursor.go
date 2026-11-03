package inventory

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Keyset paging (M8). A cursor is the sort key of the last row of a page, encoded as
// base64url JSON {"v":1,"k":<kind>,...}: opaque to clients, who pass it back as ?cursor=.
// It is not signed: a forged one only moves the start of a page (every value is a bind
// parameter).

// ErrBadCursor is a cursor that does not decode, or belongs to another list.
var ErrBadCursor = errors.New("bad cursor")

// maxCursor bounds a cursor's encoded length.
const maxCursor = 1024

// HostCursor is a position in /v1/hosts (ordered by host id).
type HostCursor struct {
	ID string `json:"id"`
}

// ListenerCursor is a position in /v1/listeners (ordered by host, proto, port, key).
type ListenerCursor struct {
	Host  string `json:"host"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Key   string `json:"key"`
}

// HistoryCursor is a position in /v1/exposure-history (newest first: at, then id, both
// descending).
type HistoryCursor struct {
	At time.Time `json:"at"`
	ID int64     `json:"id"`
}

type envelope struct {
	V    int             `json:"v"`
	Kind string          `json:"k"`
	Pos  json.RawMessage `json:"p"`
}

func cursorKind(c any) string {
	switch c.(type) {
	case HostCursor, *HostCursor:
		return "hosts"
	case ListenerCursor, *ListenerCursor:
		return "listeners"
	case HistoryCursor, *HistoryCursor:
		return "history"
	}
	return ""
}

// EncodeCursor encodes a HostCursor, ListenerCursor or HistoryCursor.
func EncodeCursor(c any) string {
	pos, _ := json.Marshal(c) // plain structs: cannot fail
	b, _ := json.Marshal(envelope{V: 1, Kind: cursorKind(c), Pos: pos})
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor decodes s into c (a *HostCursor, *ListenerCursor or *HistoryCursor); a
// cursor of another kind is ErrBadCursor.
func DecodeCursor(s string, c any) error {
	if s == "" || len(s) > maxCursor {
		return ErrBadCursor
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ErrBadCursor
	}
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil || e.V != 1 || e.Kind == "" || e.Kind != cursorKind(c) || len(e.Pos) == 0 {
		return ErrBadCursor
	}
	if err := json.Unmarshal(e.Pos, c); err != nil {
		return ErrBadCursor
	}
	return nil
}
