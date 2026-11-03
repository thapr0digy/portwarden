package inventory

import (
	"encoding/json"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

// TamperView is a host's latest tamper status as the inventory stores and the API shows it
// (M8): the agent's TamperStatus without its per-program run counts.
type TamperView struct {
	Flags        []TamperFlagView `json:"flags"`
	CheckedAt    *time.Time       `json:"checked_at"`
	Checks       []string         `json:"checks"`
	Unknown      []string         `json:"unknown"`
	RingbufDrops uint64           `json:"ringbuf_drops"`
}

// TamperFlagView is one raised flag.
type TamperFlagView struct {
	Kind        string     `json:"kind"`
	Subject     string     `json:"subject"`
	Detail      string     `json:"detail,omitempty"`
	Since       *time.Time `json:"since"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	Info        bool       `json:"info"`
}

// TamperOf returns the tamper status an agent message carries: a tamper event's (no status
// means all checks pass) or a heartbeat's. ok is false for a heartbeat without one (an
// agent without tamper checks: the stored status stays) and for every other message.
func TamperOf(m proto.Message) (*asmv1.TamperStatus, bool) {
	switch x := m.(type) {
	case *asmv1.TamperEvent:
		if x.GetStatus() == nil {
			return &asmv1.TamperStatus{}, true
		}
		return x.GetStatus(), true
	case *asmv1.Heartbeat:
		if x.GetTamper() != nil {
			return x.GetTamper(), true
		}
	}
	return nil, false
}

// TamperJSON encodes a status as its TamperView.
func TamperJSON(st *asmv1.TamperStatus) ([]byte, error) {
	v := TamperView{Flags: []TamperFlagView{}, Checks: nonNilStrings(st.GetChecks()), Unknown: nonNilStrings(st.GetUnknown()),
		RingbufDrops: st.GetRingbufDrops(), CheckedAt: timeOf(st.GetCheckedAt())}
	for _, f := range st.GetFlags() {
		v.Flags = append(v.Flags, TamperFlagView{Kind: f.GetKind(), Subject: f.GetSubject(), Detail: f.GetDetail(),
			Since: timeOf(f.GetSince()), Fingerprint: f.GetFingerprint(), Info: f.GetInfo()})
	}
	return json.Marshal(v)
}

func timeOf(ts interface {
	IsValid() bool
	AsTime() time.Time
}) *time.Time {
	if ts == nil || !ts.IsValid() {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func nonNilStrings(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
