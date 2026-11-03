package inventory

import (
	"context"
	"encoding/json"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// LevelName is a stored level's wire name ("host_firewall_open"); levels use the proto's
// numbering, the same as model.ExposureLevel.
func LevelName(n int) string { return model.ExposureLevel(n).String() }

// HostView is a host as the API shows it.
type HostView struct {
	ID             string          `json:"id"`
	Cloud          string          `json:"cloud,omitempty"`
	InstanceID     string          `json:"instance_id,omitempty"`
	Region         string          `json:"region,omitempty"`
	PublicIPs      json.RawMessage `json:"public_ips"`
	Conditions     json.RawMessage `json:"conditions"`
	RunID          string          `json:"run_id"`
	LastSeq        uint64          `json:"last_seq"`
	NeedsResync    bool            `json:"needs_resync"`
	LastSnapshotAt *time.Time      `json:"last_snapshot_at"`
	LastHeartbeat  *time.Time      `json:"last_heartbeat"`
	RingbufDrops   uint64          `json:"ringbuf_drops"`
	QueueDrops     uint64          `json:"queue_drops"`
	Silent         bool            `json:"silent"`
	SilentSince    *time.Time      `json:"silent_since"`
	CloudStatus    string          `json:"cloud_status,omitempty"`
	CloudCheckedAt *time.Time      `json:"cloud_checked_at"`
	Listeners      int             `json:"listeners"`
	FirstSeen      time.Time       `json:"first_seen"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ListenerView is a listener with its exposure from every source.
type ListenerView struct {
	Host          string          `json:"host"`
	Key           string          `json:"key"`
	Netns         uint32          `json:"netns"`
	Proto         string          `json:"proto"`
	Addr          string          `json:"addr"`
	Port          int             `json:"port"`
	Level         string          `json:"level"`
	AgentLevel    string          `json:"agent_level"`
	AgentEvidence json.RawMessage `json:"agent_evidence"`
	CloudLevel    string          `json:"cloud_level"`
	CloudEvidence json.RawMessage `json:"cloud_evidence"`
	CloudAt       *time.Time      `json:"cloud_at"`
	ProbeResult   string          `json:"probe_result,omitempty"`
	Probe         json.RawMessage `json:"probe,omitempty"`
	ProbeAt       *time.Time      `json:"probe_at"`
	Processes     json.RawMessage `json:"processes"`
	BehindProxy   json.RawMessage `json:"behind_proxy"`
	OpenedAt      time.Time       `json:"opened_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// ListenerFilter selects listeners; zero fields match everything.
type ListenerFilter struct {
	Host, Proto, Addr, Unit, Exe string
	Port                         int
	// MinLevel is a level number (1 local … 5 confirmed).
	MinLevel int
	Limit    int
}

// HistoryView is one exposure change of a listener.
type HistoryView struct {
	At            time.Time       `json:"at"`
	Origin        string          `json:"origin"`
	Level         string          `json:"level"`
	PreviousLevel string          `json:"previous_level,omitempty"`
	Evidence      json.RawMessage `json:"evidence"`
	Trigger       string          `json:"trigger,omitempty"`
	Detail        json.RawMessage `json:"detail,omitempty"`
}

// ProxyView is a proxy with its route set.
type ProxyView struct {
	Host         string          `json:"host"`
	ProxyID      string          `json:"proxy_id"`
	Kind         string          `json:"kind"`
	Proxy        json.RawMessage `json:"proxy"`
	Routes       json.RawMessage `json:"routes"`
	RouteCount   int             `json:"route_count"`
	RoutesDigest string          `json:"routes_digest,omitempty"`
	Truncated    bool            `json:"truncated"`
	Trigger      string          `json:"trigger,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// Reader is the read side the API serves.
type Reader interface {
	Hosts(ctx context.Context) ([]HostView, error)
	Host(ctx context.Context, id string) (HostView, bool, error)
	Listeners(ctx context.Context, f ListenerFilter) ([]ListenerView, error)
	History(ctx context.Context, host, key string, limit int) ([]HistoryView, error)
	Proxies(ctx context.Context, host, proxyID string) ([]ProxyView, error)
	Ping(ctx context.Context) error
}

// CloudListener is what the cloud look-up needs about a listener.
type CloudListener struct {
	Key, Proto, Addr string
	Port             int
	Netns            uint32
	AgentLevel       int
	AgentEvidence    []string
	CloudLevel       int
	CloudEvidence    []string
}

// CloudHost is what the cloud look-up needs about a host.
type CloudHost struct {
	ID, Cloud, InstanceID, Region string
	Listeners                     []CloudListener
}

// CloudState reads hosts for the cloud look-up and records its outcome.
type CloudState interface {
	CloudHost(ctx context.Context, host string) (CloudHost, bool, error)
	CloudHosts(ctx context.Context) ([]string, error)
	SetCloudStatus(ctx context.Context, host, status string, at time.Time) error
}
