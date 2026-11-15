package validate

import (
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Limits bounds every size and count an event or batch may have. Every string,
// bytes, repeated and map field is bounded by the defaults below unless Field names
// it, so a field added later is bounded without anyone remembering to add a limit.
type Limits struct {
	// MaxEventBytes bounds one encoded event (binary size, or the bytes of one
	// element of a JSON batch).
	MaxEventBytes int
	// MaxBatchEvents bounds the events of one batch.
	MaxBatchEvents int
	// MaxBatchBytes bounds a whole batch body as the decoders receive it
	// (decompressed).
	MaxBatchBytes int
	// MaxString is the default cap, in bytes, of a string field (and of each
	// element of a repeated string).
	MaxString int
	// MaxBytes is the default cap of a bytes field. Zero: a new bytes field must
	// name its own limit in Field.
	MaxBytes int
	// MaxRepeated is the default cap on the elements of a repeated field.
	MaxRepeated int
	// MaxMapEntries is the default cap on the entries of a map field.
	MaxMapEntries int
	// MaxUnknownBytes caps the unknown fields (binary only: a newer producer's
	// fields) kept on one message. Their bytes cannot be checked for form, so they
	// get a small budget; the product upgrades before its producers anyway.
	MaxUnknownBytes int
	// MaxFuture is how far after the validator's clock an event's time may be.
	MaxFuture time.Duration
	// Field overrides the defaults for one field, by full name, e.g.
	// "asm.events.v1.FindingReport.description".
	Field map[protoreflect.FullName]FieldLimit
}

// FieldLimit overrides the default cap of one field. A zero member keeps the
// default.
type FieldLimit struct {
	// Bytes caps a string or bytes field (each element when repeated).
	Bytes int
	// Items caps a repeated or map field's element count.
	Items int
}

const (
	kib = 1 << 10
	mib = 1 << 20
)

// Default is the v1 limit set: the scout's ingest limits (README.md) plus the
// per-field caps the proto comments state.
var Default = Limits{
	MaxEventBytes:   1 * mib,
	MaxBatchEvents:  1000,
	MaxBatchBytes:   16 * mib,
	MaxString:       1 * kib,
	MaxBytes:        0,
	MaxRepeated:     256,
	MaxMapEntries:   64,
	MaxUnknownBytes: 16 * kib,
	MaxFuture:       10 * time.Minute,
	Field: map[protoreflect.FullName]FieldLimit{
		// Long text.
		"asm.events.v1.FindingReport.description": {Bytes: 8 * kib},
		"asm.events.v1.FindingReport.remediation": {Bytes: 4 * kib},
		"asm.events.v1.Evidence.output":           {Bytes: 4 * kib},
		"asm.events.v1.Evidence.curl":             {Bytes: 4 * kib},
		"asm.events.v1.Evidence.extracted":        {Bytes: 512, Items: 32},
		"asm.events.v1.ProbeResult.banner":        {Bytes: 256},
		"asm.events.v1.ServiceObservation.banner": {Bytes: 1 * kib},
		"asm.events.v1.Process.cmdline":           {Bytes: 4 * kib, Items: 256},
		"asm.events.v1.HostInfo.cloud_resource":   {Bytes: 512},
		"asm.events.v1.Event.traceparent":         {Bytes: 55},
		"asm.events.v1.BlobRef.media_type":        {Bytes: 128},
		// Raw tool output inline; anything larger goes as a blob.
		"asm.events.v1.ToolOutput.inline": {Bytes: 256 * kib},
		// Large state lists. The 1 MiB event cap bounds them in practice; these
		// keep a hostile count from costing work before that.
		"asm.events.v1.HostSnapshot.listeners":            {Items: 16384},
		"asm.events.v1.HostSnapshot.proxies":              {Items: 1024},
		"asm.events.v1.ProxyRoutes.routes":                {Items: 4096},
		"asm.events.v1.ProxyRoute.backends":               {Items: 1024},
		"asm.events.v1.ListenerState.processes":           {Items: 64},
		"asm.events.v1.ListenerChange.processes":          {Items: 64},
		"asm.events.v1.ListenerChange.previous_processes": {Items: 64},
		"asm.events.v1.ExposureChange.processes":          {Items: 64},
		"asm.events.v1.Proxy.processes":                   {Items: 64},
		"asm.events.v1.ProxyBackend.processes":            {Items: 64},
		"asm.events.v1.Scope.targets":                     {Items: 4096},
		"asm.events.v1.TlsInfo.subject_alt_names":         {Items: 1024},
		"asm.events.v1.TlsInfo.versions_offered":          {Items: 16},
		"asm.events.v1.TlsInfo.weak_ciphers":              {Items: 64},
		"asm.events.v1.FindingReport.ids":                 {Items: 64},
		"asm.events.v1.FindingReport.tags":                {Items: 64},
		"asm.events.v1.FindingReport.references":          {Bytes: 2 * kib, Items: 64},
		"asm.events.v1.ServiceObservation.cpe":            {Items: 32},
		"asm.events.v1.ServiceObservation.evidence":       {Items: 32},
		"asm.events.v1.IngestResponse.rejected":           {Items: 1000},
		"asm.events.v1.Batch.events":                      {Items: 1000},
	},
}

// fieldLimit resolves the caps of one field.
func (l Limits) fieldLimit(fd protoreflect.FieldDescriptor) (maxBytes, maxItems int) {
	maxBytes, maxItems = l.MaxString, l.MaxRepeated
	if fd.Kind() == protoreflect.BytesKind {
		maxBytes = l.MaxBytes
	}
	if fd.IsMap() {
		maxItems = l.MaxMapEntries
	}
	if o, ok := l.Field[fd.FullName()]; ok {
		if o.Bytes > 0 {
			maxBytes = o.Bytes
		}
		if o.Items > 0 {
			maxItems = o.Items
		}
	}
	return maxBytes, maxItems
}
