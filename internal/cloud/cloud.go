// Package cloud is the backend's cloud look-up (design §4 level 3, §5): given a host's
// cloud identity, it decides whether a security group, network ACL or load balancer lets
// a listener's port in from anywhere. Cloud credentials stay in the backend; servers
// never hold them.
//
// AWS is implemented (package aws). GCP and Azure are recognised but unsupported: their
// hosts get the status "unsupported provider" and no level 3 evidence, so their listeners
// keep the level the agent judged (never lowered, never raised by guesswork).
package cloud

import (
	"context"
	"errors"
	"fmt"
)

// Host is a host's cloud identity, from the agent's host block (IMDS).
type Host struct {
	ID, Cloud, InstanceID, Region string
}

// Port is one listener to judge.
type Port struct {
	Key, Proto, Addr string
	Port             int
	// AgentLevel is the agent's level (proto numbering: 2 bound, 3 host_firewall_open).
	AgentLevel int
}

// Verdict says whether the cloud lets a listener in from anywhere, and why.
type Verdict struct {
	Key      string
	Open     bool
	Evidence []string
	// Complete is false when some data was truncated, unreadable or stale: such a
	// verdict may raise a listener to cloud_open but never lower it.
	Complete bool
}

// IncompleteEvidence prefixes the evidence line naming what was not read in full.
const IncompleteEvidence = "cloud:incomplete"

// UndeterminedEvidence prefixes the evidence line of a verdict the cloud's data cannot
// decide (a layer not read, a route to an appliance, a rule naming what cannot be
// resolved). Such a verdict is not open and not complete: the listener keeps its level,
// neither raised nor lowered.
const UndeterminedEvidence = "cloud:undetermined"

// Provider evaluates one host's listeners. Verdicts come in the order of ports.
type Provider interface {
	Evaluate(ctx context.Context, h Host, ports []Port) ([]Verdict, error)
}

// ErrUnsupported is returned for clouds without a look-up.
var ErrUnsupported = errors.New("unsupported provider")

// Unsupported is a Provider for a cloud Portwarden recognises but cannot look up yet.
type Unsupported struct{ Name string }

// Evaluate always fails with ErrUnsupported.
func (u Unsupported) Evaluate(context.Context, Host, []Port) ([]Verdict, error) {
	return nil, fmt.Errorf("%w %s: no level 3 evidence", ErrUnsupported, u.Name)
}

// Level numbers (proto numbering) the look-up compares against.
const (
	LevelBound            = 2
	LevelHostFirewallOpen = 3
	LevelCloudOpen        = 4
)
