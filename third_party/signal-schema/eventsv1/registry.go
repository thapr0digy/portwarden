package eventsv1

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The registry is the one place that says which payload each event type carries.
// The validators, the CloudEvents JSON codec and the example check all read it.
// A type string and its case number are frozen once released (COMPATIBILITY.md).

// ProducerKind names the kind of principal expected to send a type. It documents
// the contract and is for the ingest endpoint's authorization; the validators do
// not authorize.
type ProducerKind string

// The producer kinds: a host agent, one of the product's own services, the outside
// prober, a scanner, and a one-off importer.
const (
	ProducerAgent    ProducerKind = "agent"
	ProducerService  ProducerKind = "service"
	ProducerProber   ProducerKind = "prober"
	ProducerScanner  ProducerKind = "scanner"
	ProducerImporter ProducerKind = "importer"
)

// SubjectScheme is the prefix of a subject or AssetRef key, up to and including the
// colon, e.g. "host:".
type SubjectScheme string

// The subject schemes; README.md gives each one's form.
const (
	SchemeHost  SubjectScheme = "host:"
	SchemeIP    SubjectScheme = "ip:"
	SchemeCIDR  SubjectScheme = "cidr:"
	SchemeDNS   SubjectScheme = "dns:"
	SchemeURL   SubjectScheme = "url:"
	SchemeSvc   SubjectScheme = "svc:"
	SchemeCloud SubjectScheme = "cloud:"
	SchemeImage SubjectScheme = "image:"
	SchemeRepo  SubjectScheme = "repo:"
	SchemePkg   SubjectScheme = "pkg:"
	SchemeCert  SubjectScheme = "cert:"
	// SchemeScan is the one non-asset subject: asm.scan.* and a scan's tool output.
	SchemeScan SubjectScheme = "scan:"
)

// AssetSchemes are the subject schemes that name an asset (every scheme but scan:).
var AssetSchemes = []SubjectScheme{
	SchemeHost, SchemeIP, SchemeCIDR, SchemeDNS, SchemeURL, SchemeSvc,
	SchemeCloud, SchemeImage, SchemeRepo, SchemePkg, SchemeCert,
}

// TypeInfo is one registry row.
type TypeInfo struct {
	// Type is the CloudEvents type, e.g. "asm.listener.opened".
	Type string
	// Case is the field number of the payload in Event's data oneof.
	Case protoreflect.FieldNumber
	// Message is the payload message's short name, e.g. "ListenerChange"; the
	// CloudEvents dataschema is "asm.events.v1/" + Message.
	Message protoreflect.Name
	// Producers are the principal kinds expected to send it.
	Producers []ProducerKind
	// Subjects are the schemes the subject may use.
	Subjects []SubjectScheme
	// Sequenced is true when the producer must set Event.sequence (agents).
	Sequenced bool
}

// DataSchema is the CloudEvents dataschema value for the type.
func (t TypeInfo) DataSchema() string {
	return DataSchemaPrefix + string(t.Message)
}

// DataSchemaPrefix prefixes every dataschema value.
const DataSchemaPrefix = "asm.events.v1/"

var (
	agentOnly   = []ProducerKind{ProducerAgent}
	hostOnly    = []SubjectScheme{SchemeHost}
	scanners    = []ProducerKind{ProducerScanner, ProducerService}
	toolSources = []ProducerKind{ProducerScanner, ProducerImporter, ProducerService}
)

func withScan(s []SubjectScheme) []SubjectScheme {
	return append([]SubjectScheme{SchemeScan}, s...)
}

// Registry lists every event type, ordered by case number. Several types may share
// a payload (asm.listener.*); each case number belongs to one payload message.
var Registry = []TypeInfo{
	{Type: "asm.agent.started", Case: 20, Message: "AgentStarted", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.agent.heartbeat", Case: 21, Message: "Heartbeat", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.agent.stopping", Case: 22, Message: "AgentStopping", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.agent.tamper", Case: 23, Message: "TamperChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.agent.spool_overflow", Case: 24, Message: "SpoolOverflow", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.host.changed", Case: 25, Message: "HostChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.host.snapshot", Case: 26, Message: "HostSnapshot", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.listener.opened", Case: 27, Message: "ListenerChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.listener.closed", Case: 27, Message: "ListenerChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.listener.owner_changed", Case: 27, Message: "ListenerChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.exposure.changed", Case: 28, Message: "ExposureChange", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.proxy.routes", Case: 29, Message: "ProxyRoutes", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.host.access", Case: 30, Message: "HostAccess", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.host.sign_ins", Case: 31, Message: "SignInSummary", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},
	{Type: "asm.host.packages", Case: 32, Message: "HostPackages", Producers: agentOnly, Subjects: hostOnly, Sequenced: true},

	{Type: "asm.exposure.cloud_assessed", Case: 40, Message: "CloudExposureAssessment", Producers: []ProducerKind{ProducerService}, Subjects: hostOnly},
	{Type: "asm.exposure.probed", Case: 41, Message: "ProbeResult", Producers: []ProducerKind{ProducerProber, ProducerService}, Subjects: []SubjectScheme{SchemeHost, SchemeSvc}},
	{Type: "asm.host.forgotten", Case: 42, Message: "HostForgotten", Producers: []ProducerKind{ProducerService}, Subjects: hostOnly},

	{Type: "asm.scan.started", Case: 60, Message: "ScanStarted", Producers: scanners, Subjects: []SubjectScheme{SchemeScan}},
	{Type: "asm.scan.completed", Case: 61, Message: "ScanCompleted", Producers: scanners, Subjects: []SubjectScheme{SchemeScan}},
	{Type: "asm.service.observed", Case: 62, Message: "ServiceObservation", Producers: []ProducerKind{ProducerScanner, ProducerProber}, Subjects: []SubjectScheme{SchemeSvc}},
	{Type: "asm.asset.discovered", Case: 63, Message: "AssetDiscovery", Producers: toolSources, Subjects: AssetSchemes},
	{Type: "asm.finding.reported", Case: 64, Message: "FindingReport", Producers: toolSources, Subjects: AssetSchemes},
	{Type: "asm.sbom.published", Case: 65, Message: "SbomPublished", Producers: []ProducerKind{ProducerScanner, ProducerImporter}, Subjects: []SubjectScheme{SchemeHost, SchemeImage, SchemeRepo}},
	{Type: "asm.tool.output", Case: 66, Message: "ToolOutput", Producers: []ProducerKind{ProducerScanner, ProducerImporter}, Subjects: withScan(AssetSchemes)},
}

var byType = func() map[string]TypeInfo {
	m := make(map[string]TypeInfo, len(Registry))
	for _, t := range Registry {
		m[t.Type] = t
	}
	return m
}()

// Lookup returns the registry row for a type string.
func Lookup(typ string) (TypeInfo, bool) {
	t, ok := byType[typ]
	return t, ok
}

// DataOneof is the descriptor of Event's data oneof.
func DataOneof() protoreflect.OneofDescriptor {
	return (&Event{}).ProtoReflect().Descriptor().Oneofs().ByName("data")
}

// CaseOf returns the field number of the payload set on ev, or 0 when none is set
// (no payload, or a case this version does not know: a newer producer's type, kept
// in the unknown fields).
func CaseOf(ev *Event) protoreflect.FieldNumber {
	if ev == nil {
		return 0
	}
	fd := ev.ProtoReflect().WhichOneof(DataOneof())
	if fd == nil {
		return 0
	}
	return fd.Number()
}

// Data cases use field numbers 20 to 999 of Event; envelope growth uses 12 to 19,
// then 1000 and up (COMPATIBILITY.md).
const (
	firstDataCase protowire.Number = 20
	lastDataCase  protowire.Number = 999
)

// HasUnknownCase reports whether ev's unknown fields hold a data case number, i.e.
// a payload from a newer schema that this version cannot read.
func HasUnknownCase(ev *Event) bool {
	if ev == nil {
		return false
	}
	raw := ev.ProtoReflect().GetUnknown()
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return false
		}
		if num >= firstDataCase && num <= lastDataCase {
			return true
		}
		m := protowire.ConsumeFieldValue(num, typ, raw[n:])
		if m < 0 {
			return false
		}
		raw = raw[n+m:]
	}
	return false
}
