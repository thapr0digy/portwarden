// Package ingesttest is an in-memory reference server for the ingest protocol, for a
// producer's tests: it checks signatures, scopes subjects, keeps the run cursor, dedupes,
// reports gaps with RESYNC_SNAPSHOT, answers unchanged-digest snapshots, quarantines bad
// events, and can be told to answer 413, 429 or 503. It runs the same decision code as the
// product (package protocol), so a producer that passes here meets the same rules there.
// It stores everything in memory and is not for production.
package ingesttest

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slidehq/signal/schema/cejson"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/protocol"
	"github.com/slidehq/signal/schema/sign"
	"github.com/slidehq/signal/schema/validate"
)

// Content types and limits of the protocol.
const (
	ContentBinary   = "application/x-protobuf"
	ContentJSON     = "application/cloudevents-batch+json"
	MaxBodyBytes    = 4 << 20
	MaxDecompressed = 16 << 20
)

type principal struct {
	protocol.Principal
	disabled bool
	state    protocol.State
	ids      map[string]bool
}

// Rejected is a quarantined event.
type Rejected struct {
	PrincipalID string
	Raw         []byte
	Problem     validate.Problem
}

// Server is the reference ingest handler. Its zero value is not usable; call New.
type Server struct {
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// HeartbeatEvery is the heartbeat sampling interval (0: store every heartbeat).
	HeartbeatEvery time.Duration

	mu         sync.Mutex
	keys       map[string]ed25519.PublicKey
	keyOwner   map[string]*principal
	stored     []*eventsv1.Event
	quarantine []Rejected
	gaps       []protocol.Gap
	forced     []forced
}

type forced struct {
	status     int
	retryAfter time.Duration
}

// New returns an empty server.
func New() *Server {
	return &Server{keys: map[string]ed25519.PublicKey{}, keyOwner: map[string]*principal{}}
}

// AddPrincipal registers a principal and one key for it.
func (s *Server) AddPrincipal(p protocol.Principal, keyID string, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = pub
	s.keyOwner[keyID] = &principal{Principal: p, ids: map[string]bool{}, state: protocol.State{Digests: map[string]string{}}}
}

// Disable makes the principal's next request answer 403 with a STOP directive.
func (s *Server) Disable(principalID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.keyOwner {
		if p.ID == principalID {
			p.disabled = true
		}
	}
}

// Fail makes the next request (after authentication) answer status; for 429 and 503 it
// sets Retry-After.
func (s *Server) Fail(status int, retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forced = append(s.forced, forced{status, retryAfter})
}

// Stored returns the events in the log, in order.
func (s *Server) Stored() []*eventsv1.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*eventsv1.Event(nil), s.stored...)
}

// Quarantined returns the quarantined events.
func (s *Server) Quarantined() []Rejected {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Rejected(nil), s.quarantine...)
}

// Gaps returns the recorded sequence gaps.
func (s *Server) Gaps() []protocol.Gap {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Gap(nil), s.gaps...)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ServeHTTP implements POST /v1/ingest/batch.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	w.Header().Set("Date", now.UTC().Format(http.TimeFormat))
	if r.Method != http.MethodPost || r.URL.Path != "/v1/ingest/batch" {
		s.fail(w, r, http.StatusNotFound, "not_found", 0)
		return
	}
	params, err := sign.ParseHeaders(r.Header)
	if err != nil {
		s.fail(w, r, http.StatusUnauthorized, string(sign.CodeOf(err)), 0)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, pub := s.keyOwner[params.KeyID], s.keys[params.KeyID]
	if owner == nil {
		s.fail(w, r, http.StatusUnauthorized, "unknown_key", 0)
		return
	}
	if owner.disabled {
		s.respond(w, r, http.StatusForbidden, &eventsv1.IngestResponse{
			Error:      &eventsv1.ErrorInfo{Code: "principal_disabled"},
			Directives: []*eventsv1.Directive{{Kind: eventsv1.Directive_STOP}},
		}, 0)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, "too_large", 0)
		return
	}
	if err := sign.Verify(r, body, params, pub, now, 0); err != nil {
		s.fail(w, r, http.StatusUnauthorized, string(sign.CodeOf(err)), 0)
		return
	}
	if len(s.forced) > 0 {
		f := s.forced[0]
		s.forced = s.forced[1:]
		s.fail(w, r, f.status, "forced", f.retryAfter)
		return
	}
	raw, status, code := decompress(r.Header.Get("Content-Encoding"), body)
	if status != 0 {
		s.fail(w, r, status, code, 0)
		return
	}
	var els []validate.Element
	switch ct := r.Header.Get("Content-Type"); ct {
	case ContentBinary:
		var d *validate.Decoded
		d, err = validate.DecodeBinary(raw, validate.Options{Now: s.now})
		if d != nil {
			els = d.Elements
		}
	case ContentJSON:
		els, err = cejson.DecodeBatch(raw, validate.Options{Now: s.now})
	default:
		s.fail(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", 0)
		return
	}
	if err != nil {
		st := http.StatusBadRequest
		switch {
		case errors.Is(err, validate.ErrBatchTooLarge):
			st = http.StatusRequestEntityTooLarge
		default:
			var pr *validate.Problem
			if errors.As(err, &pr) {
				st = http.StatusUnprocessableEntity
			}
		}
		s.fail(w, r, st, "bad_batch", 0)
		return
	}
	plan := protocol.PlanBatch(owner.Principal, owner.state, els, protocol.Options{Now: now, HeartbeatEvery: s.HeartbeatEvery})
	resp := &eventsv1.IngestResponse{ServerTime: timestamppb.New(now), Directives: plan.Directives}
	for _, it := range plan.Items {
		switch it.Verdict {
		case protocol.Store:
			if id := it.Event.GetId(); owner.ids[id] {
				resp.Duplicates++
				continue
			} else {
				owner.ids[id] = true
			}
			s.stored = append(s.stored, it.Event)
			resp.Accepted++
		case protocol.Confirm, protocol.Sample:
			resp.Accepted++
		case protocol.Duplicate:
			resp.Duplicates++
		case protocol.Reject:
			s.quarantine = append(s.quarantine, Rejected{PrincipalID: owner.ID, Raw: els[it.Index].Raw, Problem: *it.Problem})
			resp.Rejected = append(resp.Rejected, &eventsv1.Rejection{Index: uint32(it.Index), Id: it.Event.GetId(), Code: string(it.Problem.Code), Reason: it.Problem.Reason}) //nolint:gosec // an index in a batch of at most 1000
		}
	}
	s.gaps = append(s.gaps, plan.Gaps...)
	owner.state = plan.State
	if run := plan.State.Run; run.ID != "" {
		resp.Cursor = &eventsv1.Sequence{RunId: run.ID, Seq: run.LastSeq, BootId: run.BootID, RunNumber: run.RunNumber}
	}
	s.respond(w, r, http.StatusOK, resp, 0)
}

func decompress(enc string, body []byte) ([]byte, int, string) {
	switch enc {
	case "", "identity":
		return body, 0, ""
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, http.StatusBadRequest, "bad_encoding"
		}
		out, err := io.ReadAll(io.LimitReader(zr, MaxDecompressed+1))
		if err != nil {
			return nil, http.StatusBadRequest, "bad_encoding"
		}
		if len(out) > MaxDecompressed {
			return nil, http.StatusRequestEntityTooLarge, "too_large"
		}
		return out, 0, ""
	}
	return nil, http.StatusUnsupportedMediaType, "unsupported_encoding"
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code string, retry time.Duration) {
	s.respond(w, r, status, &eventsv1.IngestResponse{Error: &eventsv1.ErrorInfo{Code: code}}, retry)
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, status int, resp *eventsv1.IngestResponse, retry time.Duration) {
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
	}
	if r.Header.Get("Content-Type") == ContentBinary {
		b, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", ContentBinary)
		w.WriteHeader(status)
		_, _ = w.Write(b)
		return
	}
	b, _ := protojson.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
