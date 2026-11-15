// Package lease is the wire contract between a scan worker and Signal's ingest door for
// leasing jobs: the three request and response bodies, the job-token header and the strict
// decoders both sides use. It imports nothing from the product, like the rest of the schema
// module, so a worker can be built without Signal.
//
// The routes (all signed with the worker's key, RFC 9421, like every ingest request):
//
//	POST /v1/scan/lease                      Request   -> Offer, or 204 when there is no work
//	POST /v1/scan/jobs/{id}/heartbeat        Heartbeat      -> Answer
//	POST /v1/scan/jobs/{id}/finish           Finish         -> 204
//
// Results go through the ordinary blob and batch routes with the Signal-Job-Token header.
package lease

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// Routes.
const (
	RouteLease     = "POST /v1/scan/lease"
	RouteHeartbeat = "POST /v1/scan/jobs/{id}/heartbeat"
	RouteFinish    = "POST /v1/scan/jobs/{id}/finish"
)

// RoutePutBlob is the door's blob upload route (the same route every sender uses); a worker
// reads its method and path from here, so the two cannot drift.
const RoutePutBlob = "PUT /v1/blobs/{sha}"

// TokenHeader carries the job token on blob and batch requests of a worker.
const TokenHeader = "Signal-Job-Token"

// MaxBody is the largest lease-route body either side reads.
const MaxBody = 4 << 10

// Directives of a heartbeat answer.
const (
	Continue = "continue"
	Stop     = "stop"
)

// Phases a heartbeat reports.
const (
	PhaseStarting  = "starting"
	PhaseRunning   = "running"
	PhaseUploading = "uploading"
)

// Outcomes a finish reports.
const (
	OutcomeComplete      = "complete"
	OutcomePartial       = "partial"
	OutcomeFailed        = "failed"
	OutcomeRunnerRefused = "runner_refused"
	OutcomeStopped       = "stopped"
)

// EgressClasses are the keys of the drop counts a worker reports.
var EgressClasses = []string{"non_target", "private", "cgnat", "metadata", "other_vantage", "dns_refused", "other"}

// Request asks for a job.
type Request struct {
	RunnerVersion string `json:"runner_version"`
	ImageDigest   string `json:"image_digest"`
	Vantage       string `json:"vantage"`
}

// Target is what the job may touch: one address and its ports (empty: the profile's own).
type Target struct {
	Address string   `json:"address"`
	Ports   []uint16 `json:"ports,omitempty"`
	Names   []string `json:"names,omitempty"`
	// Templates narrows a nuclei job to these ids (the profile's list is the ceiling): the checks
	// of the products fingerprinted on this address. Empty: the profile's own.
	Templates []string `json:"templates,omitempty"`
}

// Offer is a leased job.
type Offer struct {
	JobID           int64           `json:"job_id"`
	Attempt         int             `json:"attempt"`
	Token           string          `json:"token"`
	LeaseUntil      time.Time       `json:"lease_until"`
	NotAfter        time.Time       `json:"not_after"`
	HeartbeatEvery  string          `json:"heartbeat_every"`
	AuthorizationID int64           `json:"authorization_id"`
	Targets         []Target        `json:"targets"`
	Profile         json.RawMessage `json:"profile"`
}

// Heartbeat is a worker's check-in.
type Heartbeat struct {
	Attempt int              `json:"attempt"`
	Phase   string           `json:"phase"`
	Egress  map[string]int64 `json:"egress,omitempty"`
}

// Answer is the reply to a heartbeat.
type Answer struct {
	Directive  string    `json:"directive"`
	LeaseUntil time.Time `json:"lease_until"`
}

// Finish ends a lease.
type Finish struct {
	Attempt int              `json:"attempt"`
	Outcome string           `json:"outcome"`
	Reason  string           `json:"reason,omitempty"`
	Egress  map[string]int64 `json:"egress,omitempty"`
}

// Error is the body of a refusal.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrInvalid is a body that does not decode or break a rule; the text says which.
var ErrInvalid = errors.New("lease: invalid body")

func decode(b []byte, v any) error {
	if len(b) > MaxBody {
		return fmt.Errorf("%w: over %d bytes", ErrInvalid, MaxBody)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err) //nolint:errorlint // the text is for the refusal
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

func plain(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// DecodeLeaseRequest reads and checks a lease request.
func DecodeLeaseRequest(b []byte) (Request, error) {
	var r Request
	if err := decode(b, &r); err != nil {
		return Request{}, err
	}
	if !plain(r.RunnerVersion, 64) || !plain(r.Vantage, 128) || !ValidImageDigest(r.ImageDigest) {
		return Request{}, fmt.Errorf("%w: runner_version, vantage or image_digest", ErrInvalid)
	}
	return r, nil
}

// ValidImageDigest is sha256: followed by 64 lowercase hex characters.
func ValidImageDigest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validPhase(p string) bool {
	return p == PhaseStarting || p == PhaseRunning || p == PhaseUploading
}

func validEgress(m map[string]int64) bool {
	if len(m) > len(EgressClasses) {
		return false
	}
	for k, v := range m {
		known := false
		for _, c := range EgressClasses {
			known = known || c == k
		}
		if !known || v < 0 || v > 1<<40 {
			return false
		}
	}
	return true
}

// DecodeHeartbeat reads and checks a heartbeat.
func DecodeHeartbeat(b []byte) (Heartbeat, error) {
	var h Heartbeat
	if err := decode(b, &h); err != nil {
		return Heartbeat{}, err
	}
	if h.Attempt < 1 || h.Attempt > 1000 || !validPhase(h.Phase) || !validEgress(h.Egress) {
		return Heartbeat{}, fmt.Errorf("%w: attempt, phase or egress", ErrInvalid)
	}
	return h, nil
}

// DecodeFinish reads and checks a finish.
func DecodeFinish(b []byte) (Finish, error) {
	var f Finish
	if err := decode(b, &f); err != nil {
		return Finish{}, err
	}
	switch f.Outcome {
	case OutcomeComplete, OutcomePartial, OutcomeFailed, OutcomeRunnerRefused, OutcomeStopped:
	default:
		return Finish{}, fmt.Errorf("%w: outcome", ErrInvalid)
	}
	if f.Attempt < 1 || f.Attempt > 1000 || !plain(f.Reason, 500) || !validEgress(f.Egress) {
		return Finish{}, fmt.Errorf("%w: attempt, reason or egress", ErrInvalid)
	}
	return f, nil
}

// DecodeOffer reads an offer strictly (the worker's side): every address parses, every port
// is 1 to 65535, the targets and the profile are present.
func DecodeOffer(b []byte) (Offer, error) {
	var o Offer
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if len(b) > 256<<10 {
		return Offer{}, fmt.Errorf("%w: offer over 256 KiB", ErrInvalid)
	}
	if err := dec.Decode(&o); err != nil {
		return Offer{}, fmt.Errorf("%w: %v", ErrInvalid, err) //nolint:errorlint // the text is for the caller
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Offer{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if o.JobID < 1 || o.Attempt < 1 || len(o.Targets) == 0 || len(o.Targets) > 4096 || len(o.Profile) == 0 || !ValidToken(o.Token) {
		return Offer{}, fmt.Errorf("%w: job, attempt, targets, profile or token", ErrInvalid)
	}
	for _, t := range o.Targets {
		if _, err := netip.ParseAddr(t.Address); err != nil {
			return Offer{}, fmt.Errorf("%w: target %q", ErrInvalid, t.Address)
		}
		for _, p := range t.Ports {
			if p == 0 {
				return Offer{}, fmt.Errorf("%w: port 0", ErrInvalid)
			}
		}
	}
	return o, nil
}

// ValidToken is the shape of a job token: 32 bytes, URL-safe base64 without padding.
func ValidToken(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
