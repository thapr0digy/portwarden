package validate

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	name(&ev.HostAccess{}):         typed(hostAccess),
	name(&ev.Sshd{}):               typed(sshdSettings),
	name(&ev.TrustedKey{}):         typed(trustedKey),
	name(&ev.AccountAccess{}):      typed(accountAccess),
	name(&ev.SignInSummary{}):      typed(signInSummary),
	name(&ev.SignInGroup{}):        typed(signInGroup),
	name(&ev.JumpHop{}):            typed(jumpHop),
	name(&ev.HostPackages{}):       typed(hostPackages),
	name(&ev.Distro{}):             typed(distro),
	name(&ev.OSPackage{}):          typed(osPackage),
	name(&ev.HostFlows{}):          typed(hostFlows),
	name(&ev.Flow{}):               typed(flow),
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

// sshFingerprintRe is an SSH key's SHA-256 fingerprint as ssh-keygen -l prints it.
var sshFingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// accountRe is a POSIX user name.
var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

func fingerprint(v, path string, required bool) *Problem {
	if v == "" && !required {
		return nil
	}
	if !sshFingerprintRe.MatchString(v) {
		return invalid(path, "want SHA256: and 43 unpadded base64 characters")
	}
	return nil
}

func account(v, path string) *Problem {
	if !accountRe.MatchString(v) {
		return invalid(path, "not a POSIX user name")
	}
	return nil
}

func hostAccess(a *ev.HostAccess, path string) *Problem {
	if a.GetUnchanged() {
		if a.GetDigest() == "" {
			return invalid(join(path, "digest"), "required when unchanged")
		}
		if a.GetSshd() != nil || len(a.GetAccounts()) > 0 {
			return invalid(join(path, "unchanged"), "an unchanged access state carries no sshd or accounts")
		}
	}
	return optionalHex(a.GetDigest(), join(path, "digest"))
}

// The values sshd takes for PasswordAuthentication and PermitRootLogin (sshd_config(5)), as
// an agent reports them; "" is "cannot tell".
var (
	passwordAuthValues = map[string]bool{"yes": true, "no": true}
	rootLoginValues    = map[string]bool{"yes": true, "prohibit-password": true, "forced-commands-only": true, "no": true}
)

// sshdSettings holds the two settings to sshd's values, and to "" when the configuration was
// not read (a value then would be a guess).
func sshdSettings(s *ev.Sshd, path string) *Problem {
	switch pa, rl := s.GetPasswordAuthentication(), s.GetPermitRootLogin(); {
	case !s.GetRead() && (pa != "" || rl != ""):
		return invalid(join(path, "read"), "an unread configuration carries no settings")
	case pa != "" && !passwordAuthValues[pa]:
		return invalid(join(path, "password_authentication"), `want "yes" or "no"`)
	case rl != "" && !rootLoginValues[rl]:
		return invalid(join(path, "permit_root_login"), "not a PermitRootLogin value")
	}
	return nil
}

// The forms a dpkg host's package list is held to (Debian Policy 5.6.1, 5.6.12 and os-release(5)).
var (
	debPackageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)
	debVersionRe = regexp.MustCompile(`^[A-Za-z0-9.+~:-]{1,128}$`)
	debArchRe    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	osReleaseRe  = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	osVersionRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// hostPackages holds a package list to one of three shapes: unchanged (a digest and nothing
// else), unreadable (a reason and no list, so it is never read as "no packages") or a list from
// dpkg with the distribution it runs on, each (name, arch) once.
func hostPackages(p *ev.HostPackages, path string) *Problem {
	switch {
	case p.GetUnchanged():
		if p.GetDigest() == "" {
			return invalid(join(path, "digest"), "required when unchanged")
		}
		if p.GetDistro() != nil || len(p.GetPackages()) > 0 || p.GetRead() || p.GetUnreadable() != "" {
			return invalid(join(path, "unchanged"), "an unchanged package list carries only its digest")
		}
	case !p.GetRead():
		if p.GetUnreadable() == "" {
			return invalid(join(path, "unreadable"), "required when the list could not be read")
		}
		if len(p.GetPackages()) > 0 || p.GetTruncated() {
			return invalid(join(path, "packages"), "an unreadable list carries no packages")
		}
	default:
		if p.GetManager() != "dpkg" {
			return invalid(join(path, "manager"), `want "dpkg"`)
		}
		if p.GetDistro() == nil {
			return invalid(join(path, "distro"), "required")
		}
		if uint64(p.GetTotal()) < uint64(len(p.GetPackages())) {
			return invalid(join(path, "total"), "fewer than the packages sent")
		}
		seen := make(map[string]bool, len(p.GetPackages()))
		for i, k := range p.GetPackages() {
			key := k.GetName() + " " + k.GetArch()
			if seen[key] {
				return invalid(fmt.Sprintf("%s[%d]", join(path, "packages"), i), "a package and architecture listed twice")
			}
			seen[key] = true
		}
	}
	return optionalHex(p.GetDigest(), join(path, "digest"))
}

func distro(d *ev.Distro, path string) *Problem {
	switch {
	case !osReleaseRe.MatchString(d.GetId()):
		return invalid(join(path, "id"), "not an os-release ID")
	case !osVersionRe.MatchString(d.GetVersionId()):
		return invalid(join(path, "version_id"), "not an os-release VERSION_ID")
	case d.GetCodename() != "" && !osReleaseRe.MatchString(d.GetCodename()):
		return invalid(join(path, "codename"), "not an os-release VERSION_CODENAME")
	}
	return nil
}

func osPackage(k *ev.OSPackage, path string) *Problem {
	switch {
	case !debPackageRe.MatchString(k.GetName()):
		return invalid(join(path, "name"), "not a Debian package name")
	case !debVersionRe.MatchString(k.GetVersion()):
		return invalid(join(path, "version"), "not a Debian version")
	case !debPackageRe.MatchString(k.GetSource()):
		return invalid(join(path, "source"), "required: the source package, under which advisories are filed")
	case !debVersionRe.MatchString(k.GetSourceVersion()):
		return invalid(join(path, "source_version"), "not a Debian version")
	case !debArchRe.MatchString(k.GetArch()):
		return invalid(join(path, "arch"), "not a Debian architecture")
	}
	return nil
}

// hostFlows holds a window of connections to its window, and an unread window to no flows
// (never "no connections"). Flows are sorted by their key, each key once, so one window has one
// encoding.
func hostFlows(f *ev.HostFlows, path string) *Problem {
	start, end := f.GetWindowStart(), f.GetWindowEnd()
	switch {
	case start == nil:
		return invalid(join(path, "window_start"), "required")
	case end == nil:
		return invalid(join(path, "window_end"), "required")
	case !end.AsTime().After(start.AsTime()):
		return invalid(join(path, "window_end"), "not after window_start")
	case !f.GetRead() && f.GetUnreadable() == "":
		return invalid(join(path, "unreadable"), "required when the connections could not be observed")
	case !f.GetRead() && len(f.GetFlows()) > 0:
		return invalid(join(path, "flows"), "an unread window carries no flows")
	case f.GetRead() && f.GetUnreadable() != "":
		return invalid(join(path, "unreadable"), "set on a read window")
	}
	flows := f.GetFlows()
	for i, fl := range flows {
		at := fmt.Sprintf("%s[%d]", join(path, "flows"), i)
		if fl.GetFirstSeen().AsTime().Before(start.AsTime()) || fl.GetLastSeen().AsTime().After(end.AsTime()) {
			return invalid(at, "seen outside the window")
		}
		if i > 0 && compareFlowKeys(flows[i-1], fl) >= 0 {
			return invalid(at, "not after the flow before it (sorted, each key once)")
		}
	}
	return nil
}

// compareFlowKeys orders flows by their aggregation key, as HostFlows.flows is sorted.
func compareFlowKeys(a, b *ev.Flow) int {
	return cmp.Or(
		cmp.Compare(a.GetDirection(), b.GetDirection()),
		cmp.Compare(a.GetRemoteAddr(), b.GetRemoteAddr()),
		cmp.Compare(a.GetRemotePort(), b.GetRemotePort()),
		cmp.Compare(a.GetLocalPort(), b.GetLocalPort()),
		cmp.Compare(a.GetExe(), b.GetExe()),
		cmp.Compare(a.GetComm(), b.GetComm()),
		cmp.Compare(a.GetUnit(), b.GetUnit()),
		cmp.Compare(a.GetAppProto(), b.GetAppProto()),
		cmp.Compare(a.GetServiceName(), b.GetServiceName()),
	)
}

// appProtos are the application protocols an agent names from a connection's first bytes.
var appProtos = map[string]bool{"": true, "tls": true, "http": true}

func flow(f *ev.Flow, path string) *Problem {
	out := f.GetDirection() == "out"
	switch {
	case !out && f.GetDirection() != "in":
		return invalid(join(path, "direction"), `want "out" or "in"`)
	case f.GetProto() != "tcp":
		return invalid(join(path, "proto"), `want "tcp"`)
	case f.GetLocalPort() > 65535 || f.GetRemotePort() > 65535:
		return invalid(path, "a port > 65535")
	case out && (f.GetLocalPort() != 0 || f.GetRemotePort() == 0):
		return invalid(join(path, "remote_port"), "an outbound flow has a remote port and no local one")
	case !out && (f.GetRemotePort() != 0 || f.GetLocalPort() == 0):
		return invalid(join(path, "local_port"), "an inbound flow has a local port and no remote one")
	case canonicalIP(f.GetRemoteAddr()) != nil:
		return invalid(join(path, "remote_addr"), "not a canonical IP address")
	case !appProtos[f.GetAppProto()]:
		return invalid(join(path, "app_proto"), `want "tls", "http" or ""`)
	case f.GetServiceName() != "" && (f.GetAppProto() == "" || !out):
		return invalid(join(path, "service_name"), "only an outbound flow's TLS or HTTP first bytes name a service")
	case f.GetServiceName() != "" && (strings.HasPrefix(f.GetServiceName(), "*.") || dnsName(f.GetServiceName()) != nil):
		return invalid(join(path, "service_name"), "not a lowercase DNS name")
	case f.GetComm() == "" && f.GetExe() == "":
		return invalid(join(path, "comm"), "required: the process's name")
	case !textual(f.GetComm()) || !textual(f.GetExe()) || !textual(f.GetUnit()):
		return invalid(path, "a process field holds a control character or a byte past ASCII")
	case f.GetCount() == 0:
		return invalid(join(path, "count"), "at least 1")
	case f.GetFirstSeen() == nil || f.GetLastSeen() == nil:
		return invalid(join(path, "first_seen"), "first_seen and last_seen are required")
	case f.GetLastSeen().AsTime().Before(f.GetFirstSeen().AsTime()):
		return invalid(join(path, "last_seen"), "before first_seen")
	}
	return nil
}

func trustedKey(k *ev.TrustedKey, path string) *Problem {
	return fingerprint(k.GetFingerprint(), join(path, "fingerprint"), true)
}

func accountAccess(a *ev.AccountAccess, path string) *Problem {
	if p := account(a.GetAccount(), join(path, "account")); p != nil {
		return p
	}
	for i, k := range a.GetStaticKeys() {
		if p := fingerprint(k, fmt.Sprintf("%s[%d]", join(path, "static_keys"), i), true); p != nil {
			return p
		}
	}
	return nil
}

func signInSummary(s *ev.SignInSummary, path string) *Problem {
	start, end := s.GetWindowStart(), s.GetWindowEnd()
	switch {
	case end == nil:
		return invalid(join(path, "window_end"), "required")
	case start != nil && end.AsTime().Before(start.AsTime()):
		return invalid(join(path, "window_end"), "before window_start")
	}
	for i, g := range s.GetGroups() {
		if g.GetLastAt() != nil && g.GetLastAt().AsTime().After(end.AsTime()) {
			return invalid(fmt.Sprintf("%s[%d].last_at", join(path, "groups"), i), "after window_end")
		}
	}
	return nil
}

func signInGroup(g *ev.SignInGroup, path string) *Problem {
	if p := account(g.GetAccount(), join(path, "account")); p != nil {
		return p
	}
	if g.GetMethod() == ev.SignInGroup_METHOD_UNSPECIFIED {
		return invalid(join(path, "method"), "required")
	}
	if p := fingerprint(g.GetCaFingerprint(), join(path, "ca_fingerprint"), false); p != nil {
		return p
	}
	if p := fingerprint(g.GetKeyFingerprint(), join(path, "key_fingerprint"), false); p != nil {
		return p
	}
	if !printable(g.GetKeyId()) {
		return invalid(join(path, "key_id"), "holds a space or a control character")
	}
	if g.GetSerial() != "" {
		if _, err := strconv.ParseUint(g.GetSerial(), 10, 64); err != nil {
			return invalid(join(path, "serial"), "not a decimal number")
		}
	}
	if g.GetFromIp() != "" && canonicalIP(g.GetFromIp()) != nil {
		return invalid(join(path, "from_ip"), "not a canonical IP address")
	}
	return counted(g.GetCount(), g.GetFirstAt(), g.GetLastAt(), path)
}

func jumpHop(h *ev.JumpHop, path string) *Problem {
	switch {
	case h.GetPerson() == "":
		return invalid(join(path, "person"), "required")
	case h.GetTarget() == "":
		return invalid(join(path, "target"), "required")
	}
	return counted(h.GetCount(), h.GetFirstAt(), h.GetLastAt(), path)
}

// counted checks a group's count and its first and last times.
func counted(n uint64, first, last *timestamppb.Timestamp, path string) *Problem {
	switch {
	case n == 0:
		return invalid(join(path, "count"), "want at least 1")
	case first == nil || last == nil:
		return invalid(join(path, "first_at"), "first_at and last_at are required")
	case last.AsTime().Before(first.AsTime()):
		return invalid(join(path, "last_at"), "before first_at")
	}
	return nil
}

// printable reports whether s holds only printable ASCII other than a space (a key ID as sshd
// logs it).
// textual reports whether s is printable ASCII, spaces allowed (a process name or path may
// hold one).
func textual(s string) bool {
	return printable(strings.ReplaceAll(s, " ", ""))
}

func printable(s string) bool {
	for i := range len(s) {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}
