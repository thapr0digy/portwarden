package validate

import (
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	ev "github.com/slidehq/signal/schema/eventsv1"
)

// A rule checks one message's own shape, wherever it appears in an event. The
// walker has already bounded its fields.
type rule func(m proto.Message, path string) *Problem

// typed adapts a rule over one generated type. A message of another Go type (a
// dynamic message built from the same descriptor) is refused rather than asserted.
func typed[T proto.Message](f func(T, string) *Problem) rule {
	return func(m proto.Message, path string) *Problem {
		t, ok := m.(T)
		if !ok {
			return invalid(path, fmt.Sprintf("unexpected Go type %T", m))
		}
		return f(t, path)
	}
}

var rules = map[protoreflect.FullName]rule{
	name(&ev.AssetRef{}):           typed(assetRef),
	name(&ev.BlobRef{}):            typed(blobRef),
	name(&ev.Severity{}):           typed(severity),
	name(&ev.Listener{}):           typed(listener),
	name(&ev.Process{}):            typed(process),
	name(&ev.HostInfo{}):           typed(hostInfo),
	name(&ev.Heartbeat{}):          typed(heartbeat),
	name(&ev.SpoolOverflow{}):      typed(spoolOverflow),
	name(&ev.HostSnapshot{}):       typed(hostSnapshot),
	name(&ev.ProxyState{}):         typed(proxyState),
	name(&ev.ProxyRoutes{}):        typed(proxyRoutes),
	name(&ev.ScanCompleted{}):      typed(scanCompleted),
	name(&ev.ServiceObservation{}): typed(serviceObservation),
	name(&ev.AssetDiscovery{}):     typed(assetDiscovery),
	name(&ev.Relation{}):           typed(relation),
	name(&ev.FindingReport{}):      typed(findingReport),
	name(&ev.SbomPublished{}):      typed(sbomPublished),
	name(&ev.ToolOutput{}):         typed(toolOutput),
}

func name(m proto.Message) protoreflect.FullName { return m.ProtoReflect().Descriptor().FullName() }

var kindScheme = map[ev.AssetRef_Kind]ev.SubjectScheme{
	ev.AssetRef_HOST:            ev.SchemeHost,
	ev.AssetRef_IP:              ev.SchemeIP,
	ev.AssetRef_CIDR:            ev.SchemeCIDR,
	ev.AssetRef_DNS:             ev.SchemeDNS,
	ev.AssetRef_URL:             ev.SchemeURL,
	ev.AssetRef_SERVICE:         ev.SchemeSvc,
	ev.AssetRef_CLOUD_RESOURCE:  ev.SchemeCloud,
	ev.AssetRef_CONTAINER_IMAGE: ev.SchemeImage,
	ev.AssetRef_REPOSITORY:      ev.SchemeRepo,
	ev.AssetRef_PACKAGE:         ev.SchemePkg,
	ev.AssetRef_CERTIFICATE:     ev.SchemeCert,
}

func assetRef(a *ev.AssetRef, path string) *Problem {
	s, err := Key(a.GetKey())
	if err != nil {
		return invalid(join(path, "key"), err.Error())
	}
	if s == ev.SchemeScan {
		return invalid(join(path, "key"), "scan: is not an asset")
	}
	// An unknown kind (a newer schema) is read as unspecified: only a known kind
	// that disagrees with the key is an error.
	if want, ok := kindScheme[a.GetKind()]; ok && want != s {
		return invalid(join(path, "kind"), fmt.Sprintf("%s does not match a %s key", a.GetKind(), s))
	}
	return nil
}

func blobRef(b *ev.BlobRef, path string) *Problem {
	switch {
	case !IsHex(b.GetSha256(), sha256Len):
		return invalid(join(path, "sha256"), "want 64 lowercase hex characters")
	case b.GetSize() == 0:
		return invalid(join(path, "size"), "required")
	case b.GetMediaType() == "":
		return invalid(join(path, "media_type"), "required")
	}
	return nil
}

func severity(s *ev.Severity, path string) *Problem {
	if s.GetScore() == 0 {
		return nil
	}
	maxScore := 10.0
	switch {
	case s.GetScoreSystem() == "epss":
		maxScore = 1
	case strings.HasPrefix(s.GetScoreSystem(), "cvss"):
	default:
		return nil // a tool's own scale
	}
	if s.GetScore() < 0 || s.GetScore() > maxScore {
		return invalid(join(path, "score"), fmt.Sprintf("outside 0-%g for %s", maxScore, s.GetScoreSystem()))
	}
	return nil
}

func listener(l *ev.Listener, path string) *Problem {
	if l.GetProto() != "tcp" && l.GetProto() != "udp" {
		return invalid(join(path, "proto"), "not tcp or udp")
	}
	if l.GetPort() > 65535 {
		return invalid(join(path, "port"), fmt.Sprintf("%d > 65535", l.GetPort()))
	}
	return nil
}

func process(p *ev.Process, path string) *Problem {
	return optionalHex(p.GetSha256(), join(path, "sha256"))
}

func hostInfo(h *ev.HostInfo, path string) *Problem {
	if p := optionalHex(h.GetExeSha256(), join(path, "exe_sha256")); p != nil {
		return p
	}
	return optionalHex(h.GetFirewallFingerprint(), join(path, "firewall_fingerprint"))
}

func heartbeat(h *ev.Heartbeat, path string) *Problem {
	for _, f := range []struct{ v, name string }{
		{h.GetExeSha256(), "exe_sha256"},
		{h.GetFirewallFingerprint(), "firewall_fingerprint"},
		{h.GetStateDigest(), "state_digest"},
	} {
		if p := optionalHex(f.v, join(path, f.name)); p != nil {
			return p
		}
	}
	return nil
}

func spoolOverflow(s *ev.SpoolOverflow, path string) *Problem {
	switch {
	case !IsULID(s.GetRunId()):
		return invalid(join(path, "run_id"), "not a ULID")
	case s.GetFirstSeq() == 0 || s.GetLastSeq() < s.GetFirstSeq():
		return invalid(join(path, "first_seq"), "want 1 <= first_seq <= last_seq")
	}
	return nil
}

func hostSnapshot(s *ev.HostSnapshot, path string) *Problem {
	if s.GetUnchanged() {
		if s.GetDigest() == "" {
			return invalid(join(path, "digest"), "required when unchanged")
		}
		if len(s.GetListeners()) > 0 || len(s.GetProxies()) > 0 {
			return invalid(join(path, "unchanged"), "an unchanged snapshot carries no listeners or proxies")
		}
	}
	return optionalHex(s.GetDigest(), join(path, "digest"))
}

func proxyState(s *ev.ProxyState, path string) *Problem {
	return routesDigest(s.GetRoutesDigest(), join(path, "routes_digest"))
}

func proxyRoutes(r *ev.ProxyRoutes, path string) *Problem {
	if r.GetUnchanged() {
		if r.GetRoutesDigest() == "" {
			return invalid(join(path, "routes_digest"), "required when unchanged")
		}
		if len(r.GetRoutes()) > 0 {
			return invalid(join(path, "unchanged"), "an unchanged route set carries no routes")
		}
	}
	return routesDigest(r.GetRoutesDigest(), join(path, "routes_digest"))
}

// routesDigestLen is Portwarden's route-set digest: the first 16 bytes of a
// SHA-256, in lowercase hex.
const routesDigestLen = 32

func routesDigest(v, path string) *Problem {
	if v != "" && !IsHex(v, routesDigestLen) {
		return invalid(path, fmt.Sprintf("want %d lowercase hex characters", routesDigestLen))
	}
	return nil
}

func scanCompleted(s *ev.ScanCompleted, path string) *Problem {
	if s.GetStatus() == ev.ScanCompleted_STATUS_UNSPECIFIED {
		return invalid(join(path, "status"), "required")
	}
	if a, b := s.GetStartedAt(), s.GetFinishedAt(); a != nil && b != nil && b.AsTime().Before(a.AsTime()) {
		return invalid(join(path, "finished_at"), "before started_at")
	}
	return nil
}

func serviceObservation(s *ev.ServiceObservation, path string) *Problem {
	if err := ProtoPort(s.GetProto(), strconv.FormatUint(uint64(s.GetPort()), 10)); err != nil {
		return invalid(path, err.Error())
	}
	if s.GetAddress() != "" && canonicalIP(s.GetAddress()) != nil {
		return invalid(join(path, "address"), "not a canonical IP address")
	}
	return nil
}

func assetDiscovery(a *ev.AssetDiscovery, path string) *Problem {
	if a.GetAsset() == nil {
		return invalid(join(path, "asset"), "required")
	}
	return nil
}

func relation(r *ev.Relation, path string) *Problem {
	if r.GetKind() == "" {
		return invalid(join(path, "kind"), "required")
	}
	if r.GetTo() == nil {
		return invalid(join(path, "to"), "required")
	}
	return nil
}

func findingReport(f *ev.FindingReport, path string) *Problem {
	switch {
	case f.GetRuleId() == "":
		return invalid(join(path, "rule_id"), "required")
	case f.GetConfidence() > 100:
		return invalid(join(path, "confidence"), fmt.Sprintf("%d > 100", f.GetConfidence()))
	}
	return nil
}

func sbomPublished(s *ev.SbomPublished, path string) *Problem {
	if s.GetDocument() == nil {
		return invalid(join(path, "document"), "required: the SBOM goes as a blob")
	}
	return nil
}

func toolOutput(t *ev.ToolOutput, path string) *Problem {
	switch {
	case t.GetTool() == "":
		return invalid(join(path, "tool"), "required")
	case t.GetFormat() == "":
		return invalid(join(path, "format"), "required")
	case t.GetBody() == nil:
		return invalid(join(path, "body"), "inline or blob required")
	}
	return nil
}

func optionalHex(v, path string) *Problem {
	if v != "" && !IsHex(v, sha256Len) {
		return invalid(path, "want 64 lowercase hex characters")
	}
	return nil
}
