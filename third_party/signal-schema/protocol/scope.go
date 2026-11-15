// Package protocol is the ingest protocol's decision logic, pure and free of storage:
// which principal may send which event (Authorize), and what a batch does to a
// producer's cursor (Plan). The product's appender and the ingesttest reference
// server both call it, so a producer tested against ingesttest meets the same rules
// in the product.
package protocol

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

// CodeForbiddenType is the rejection code for a type the principal's kind may not send.
const CodeForbiddenType validate.Code = "forbidden_type"

// Principal is the authenticated sender, derived from its key and never from the body.
type Principal struct {
	ID   string
	Kind eventsv1.ProducerKind
	// HostID is the machine id of an agent principal (32 lowercase hex).
	HostID string
	Scope  Scope
}

// Scope limits what a scanner or importer may speak about, and lets a prober speak about
// any host or service.
type Scope struct {
	// Any allows every asset subject (a prober's "any host: or svc:").
	Any bool `json:"any,omitempty"`
	// CIDRs are IP prefixes, e.g. "203.0.113.0/24".
	CIDRs []string `json:"cidrs,omitempty"`
	// DNSSuffixes are lowercase domain suffixes, e.g. "example.com" (the name itself and
	// every name below it).
	DNSSuffixes []string `json:"dns_suffixes,omitempty"`
	// RepoOwners are "<host>/<owner>" prefixes, e.g. "github.com/acme".
	RepoOwners []string `json:"repo_owners,omitempty"`
}

// Allows reports whether subject (a canonical key, already validated) is inside the scope.
func (s Scope) Allows(subject string) bool {
	scheme, ok := validate.SchemeOf(subject)
	if !ok {
		return false
	}
	rest := subject[len(scheme):]
	switch scheme {
	case eventsv1.SchemeScan:
		return true
	case eventsv1.SchemeHost, eventsv1.SchemeCloud, eventsv1.SchemePkg, eventsv1.SchemeCert:
		return false // an asset a scope cannot bound
	case eventsv1.SchemeIP:
		return s.ip(rest)
	case eventsv1.SchemeCIDR:
		p, err := netip.ParsePrefix(rest)
		return err == nil && s.prefix(p)
	case eventsv1.SchemeDNS:
		return s.dns(strings.TrimPrefix(rest, "*."))
	case eventsv1.SchemeURL:
		u, err := url.Parse(rest)
		return err == nil && s.hostname(u.Hostname())
	case eventsv1.SchemeSvc:
		i := strings.LastIndexByte(rest, ':')
		return i > 0 && s.hostname(strings.Trim(rest[:i], "[]"))
	case eventsv1.SchemeRepo:
		return s.repo(rest)
	case eventsv1.SchemeImage:
		repo, _, _ := strings.Cut(rest, "@")
		return s.repo(repo)
	}
	return false
}

func (s Scope) hostname(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return s.ip(h)
	}
	return s.dns(h)
}

func (s Scope) ip(v string) bool {
	a, err := netip.ParseAddr(v)
	if err != nil {
		return false
	}
	for _, c := range s.CIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

func (s Scope) prefix(q netip.Prefix) bool {
	for _, c := range s.CIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Bits() <= q.Bits() && p.Contains(q.Addr()) {
			return true
		}
	}
	return false
}

func (s Scope) dns(name string) bool {
	for _, suf := range s.DNSSuffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	return false
}

func (s Scope) repo(r string) bool {
	for _, o := range s.RepoOwners {
		if strings.HasPrefix(r, o+"/") {
			return true
		}
	}
	return false
}

// Authorize checks an event that already passed validation against the principal: the
// type must be one its kind may send, and the subject one it may speak about. An agent
// speaks only for "host:<its own host id>". It returns nil, or a Problem (the event is
// quarantined, never retried).
func Authorize(p Principal, ev *eventsv1.Event) *validate.Problem {
	info, ok := eventsv1.Lookup(ev.GetType())
	if !ok {
		return &validate.Problem{Code: validate.CodeUnknownType, Path: "type", Reason: "unknown type"}
	}
	allowed := false
	for _, k := range info.Producers {
		if k == p.Kind {
			allowed = true
		}
	}
	if !allowed {
		return &validate.Problem{Code: CodeForbiddenType, Path: "type", Reason: string(p.Kind) + " principals may not send " + info.Type}
	}
	subject := ev.GetSubject()
	if scheme, _ := validate.SchemeOf(subject); scheme == eventsv1.SchemeScan {
		return nil
	}
	forbidden := &validate.Problem{Code: validate.CodeForbiddenSubject, Path: "subject", Reason: "the subject is outside what this principal may speak about"}
	switch p.Kind {
	case eventsv1.ProducerAgent:
		if p.HostID == "" || subject != string(eventsv1.SchemeHost)+p.HostID {
			return forbidden
		}
	case eventsv1.ProducerService:
	case eventsv1.ProducerProber:
		if !p.Scope.Any && !p.Scope.Allows(subject) {
			return forbidden
		}
	default:
		if !p.Scope.Allows(subject) {
			return forbidden
		}
	}
	return nil
}
