# ASM event schema v1 (`asm.events.v1`)

The format every security tool uses to send events to Signal: Portwarden's host
agents, scanners, importers and Signal's own services. It is a self-contained Go
module, `github.com/slidehq/signal/schema`, that imports nothing from the product, so
a producer can depend on it without pulling in Signal.

Protobuf package `asm.events.v1` is the source of truth. Producers send it as binary
protobuf (`application/x-protobuf`, a `Batch`) or as a CloudEvents 1.0 JSON batch
(`application/cloudevents-batch+json`). Both decode to the same Go type. The ingest
endpoint that receives them is a later phase; this module is the contract and the
checks.

## Layout

| Path | Holds |
|---|---|
| `proto/asm/events/v1/envelope.proto` | `Event` (envelope + `oneof data`), `Producer`, `Sequence`, `Batch`, `IngestResponse`, `Directive`, `StoredEvent` |
| `proto/asm/events/v1/common.proto` | `AssetRef`, `BlobRef`, `Severity`, and Portwarden's listener, process, exposure, host, proxy and tamper types, with their field numbers unchanged |
| `proto/asm/events/v1/agent.proto` | host-agent payloads (Portwarden) |
| `proto/asm/events/v1/access.proto` | host-agent SSH access state and sign-ins (the identity join) |
| `proto/asm/events/v1/packages.proto` | host-agent installed OS packages (the software inventory) |
| `proto/asm/events/v1/exposure.proto` | product-service payloads: cloud verdict, outside probe, forget |
| `proto/asm/events/v1/discovery.proto` | tool payloads: scans, services, assets, SBOMs, raw tool output |
| `proto/asm/events/v1/finding.proto` | `FindingReport` |
| `eventsv1/` | the generated Go types (`*.pb.go`, checked in) and `registry.go`, the one registry |
| `validate/` | the checks the server runs, for producers to run first: `Event`, `Batch`, `DecodeBinary`, `Element`, `Default` limits |
| `cejson/` | the CloudEvents JSON codec: `DecodeBatch`, `DecodeEvent`, `EncodeEvent`, `EncodeBatch` |
| `sign/` | RFC 9421 Ed25519 request signatures over an RFC 9530 `Content-Digest`: `Sign`, `ParseHeaders` (no body read), `Verify`, `KeyID` (the key id a public key signs with) |
| `protocol/` | the server's decisions, pure: `Authorize` (type and subject scope per principal kind), `PlanBatch` (run cursor, dedupe, gaps, unchanged digests, heartbeat sampling, directives) |
| `ingesttest/` | an in-memory reference server for producers' tests; runs `protocol` and `sign`, can answer 413, 429, 503 on demand |
| `examples/` | one CloudEvents JSON example per type, a batch request and a response |
| `tools/excheck` | the example check (also run by `go test`) |
| `COMPATIBILITY.md` | what may change inside v1, what needs v2 |
| `buf.yaml`, `buf.gen.yaml` | lint, breaking-change and generation settings |

## Use

```go
import (
	"github.com/slidehq/signal/schema/cejson"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

// A tool checking what it is about to send:
ev := &eventsv1.Event{ /* ... */ }
if err := validate.Event(ev, validate.Options{}); err != nil {
	var p *validate.Problem // errors.As(err, &p): p.Code, p.Path, p.Reason
}
body, err := cejson.EncodeBatch(&eventsv1.Batch{Events: []*eventsv1.Event{ev}})

// A receiver:
elems, err := cejson.DecodeBatch(body, validate.Options{}) // err: the whole batch is bad
for _, e := range elems {
	if e.Problem != nil { /* quarantine e.Raw with e.Problem.Code */ }
}
decoded, err := validate.DecodeBinary(protoBody, validate.Options{}) // same Element shape
for _, e := range decoded.Elements { /* e.Problem as above */ }
```

## Registry

`eventsv1.Registry` (`eventsv1/registry.go`) is the authority; this table documents
it, and `tools/excheck` fails when the two list different types. The type string, the
payload and the case number are frozen once released (COMPATIBILITY.md).

| `type` | Payload (`data` case #) | Producers | `subject` | State or delta | Replaces (Portwarden subject) |
|---|---|---|---|---|---|
| `asm.agent.started` | `AgentStarted` (20) | agent | `host:<own id>` | marker | new |
| `asm.agent.heartbeat` | `Heartbeat` (21) | agent | `host:<own id>` | state (counters) | `asm.<h>.heartbeat` |
| `asm.agent.stopping` | `AgentStopping` (22) | agent | `host:<own id>` | marker | `asm.<h>.host.changed` with `stopping` |
| `asm.agent.tamper` | `TamperChange` (23) | agent | `host:<own id>` | delta + status | `asm.<h>.tamper` |
| `asm.agent.spool_overflow` | `SpoolOverflow` (24) | agent | `host:<own id>` | marker (explains a gap) | new |
| `asm.host.changed` | `HostChange` (25) | agent | `host:<own id>` | delta | `asm.<h>.host.changed` |
| `asm.host.snapshot` | `HostSnapshot` (26) | agent | `host:<own id>` | **full state** (or `unchanged` + digest) | `asm.<h>.snapshot` |
| `asm.listener.opened` | `ListenerChange` (27) | agent | `host:<own id>` | delta | `asm.<h>.listener.opened` |
| `asm.listener.closed` | `ListenerChange` (27) | agent | `host:<own id>` | delta | `asm.<h>.listener.closed` |
| `asm.listener.owner_changed` | `ListenerChange` (27) | agent | `host:<own id>` | delta | `asm.<h>.listener.owner_changed` |
| `asm.exposure.changed` | `ExposureChange` (28) | agent | `host:<own id>` | delta | `asm.<h>.exposure.changed` |
| `asm.proxy.routes` | `ProxyRoutes` (29) | agent | `host:<own id>` | full state of one proxy (or `unchanged` + digest) | `asm.<h>.proxy.routes` |
| `asm.host.access` | `HostAccess` (30) | agent | `host:<own id>` | **full state** of SSH trust (or `unchanged` + digest) | new |
| `asm.host.sign_ins` | `SignInSummary` (31) | agent | `host:<own id>` | delta (grouped sign-ins since the last) | new |
| `asm.host.packages` | `HostPackages` (32) | agent | `host:<own id>` | **full state** of installed dpkg packages (or `unchanged` + digest) | new |
| `asm.exposure.cloud_assessed` | `CloudExposureAssessment` (40) | service | `host:<id>` | verdict | `pwb.cloud.<h>.exposure` |
| `asm.exposure.probed` | `ProbeResult` (41) | prober, service | `host:<id>` or `svc:…` | verdict | `pwb.verifier.<h>.exposure` |
| `asm.host.forgotten` | `HostForgotten` (42) | service (operator action) | `host:<id>` | marker | `pwb.inventory.<h>.forgotten` |
| `asm.scan.started` | `ScanStarted` (60) | scanner, service | `scan:<own id>` | marker | new |
| `asm.scan.completed` | `ScanCompleted` (61) | scanner, service | `scan:<started id>` | marker (closes the scope) | new |
| `asm.service.observed` | `ServiceObservation` (62) | scanner, prober | `svc:<addr>:<proto>/<port>` | observation | new |
| `asm.asset.discovered` | `AssetDiscovery` (63) | scanner, importer, service | the asset's key | observation | new |
| `asm.finding.reported` | `FindingReport` (64) | scanner, importer, service | the asset's key | observation | new |
| `asm.sbom.published` | `SbomPublished` (65) | scanner, importer | `host:`, `image:`, `repo:` | full state (document) | new |
| `asm.tool.output` | `ToolOutput` (66) | scanner, importer | `scan:<id>` or the asset | raw evidence for adapters | new |

Agent types also need `sequence` (run id and a seq from 1). `pwb.<h>.probe.request`
(`ProbeRequest`) is not an event: it is a command, and becomes a job in the product.

Subject and AssetRef key forms (at most 1024 bytes of UTF-8, no spaces, control or Unicode format characters):

| Scheme | Form |
|---|---|
| `host:` | a machine-id: 32 lowercase hex |
| `ip:` | a canonical IP (IPv6 compressed, IPv4-mapped unmapped, no zone) |
| `cidr:` | a canonical prefix (no host bits, not IPv4-mapped) |
| `dns:` | lowercase name, no trailing dot; letters, digits, `-`, `_`; a leading `*.` allowed; the last label not all digits |
| `url:` | an absolute http or https URL: lowercase scheme and host; no default port, zone, dot segment, query, fragment or user info |
| `svc:` | `<ip-or-dns>:<tcp|udp>/<port>`, e.g. `svc:198.51.100.7:tcp/443` |
| `cloud:` | `<provider>:<account>:<region>:<resource-id>` |
| `image:` | `<registry/repo>@sha256:<64 hex>` |
| `repo:` | `<host>/<owner>/<name>` |
| `pkg:` | a Package URL |
| `cert:` | `sha256:<64 hex>` |
| `scan:` | a ULID (the `asm.scan.started` id); not an asset |

## Adding an event type (a new tool)

1. **Look for an existing type first.** Most tools fit `asm.service.observed`,
   `asm.asset.discovered` or `asm.finding.reported`; a tool whose output has its own
   format can send it raw as `asm.tool.output` and let a server-side adapter turn it
   into typed events. Add a type only for data none of these can carry.
2. **Add the payload message** to the `.proto` file of its producer family (or a new
   file in `proto/asm/events/v1/`). Every field's zero value must mean "not sent";
   use `optional` where zero is a real value. Say each string's cap in its comment.
3. **Add the case** to `Event.data` in `envelope.proto` with the next free number in
   the family's range (agent 20–39, product services 40–59, tools 60–999). Never reuse
   a number.
4. **Register it**: one row in `Registry` (`eventsv1/registry.go`) with its type
   string (`asm.<noun>.<past-tense verb>`), case, message, producer kinds, allowed
   subject schemes and whether it is sequenced; and one row in the table above.
5. **Bound it**: a field the defaults do not fit (a long text, a big list) gets a
   row in `validate.Default.Field`; a shape rule (a required field, a range) goes in
   `validate/rules.go`.
6. **Add an example**: `examples/<type>.json`, synthetic data only (documentation IP
   ranges, `example.com` or `signal.test` names).
7. **Generate and check**: `make schema-gen`, then `make schema-check`.
8. **Bump the minor version** when the module is next tagged (COMPATIBILITY.md).

## CloudEvents mapping (JSON form)

| `Event` field | CloudEvents attribute | Notes |
|---|---|---|
| — | `specversion` | always `"1.0"`; required |
| `id` | `id` | ULID |
| `type` | `type` | registry |
| `source` | `source` | `urn:asm:<kind>:<name>`; required |
| `subject` | `subject` | key form above; required |
| `time` | `time` | RFC 3339; required |
| `dataschema` | `dataschema` | `asm.events.v1/<Message>`; optional |
| — | `datacontenttype` | `application/json` (optional; the only value accepted) |
| `producer.name` + `.version` | `producer` (extension) | `"nuclei/3.3.7"`; split at the last `/`, so a version has no `/` |
| `producer.adapter` | `adapter` (extension) | |
| `sequence.run_id` | `runid` (extension) | |
| `sequence.seq` | `sequence` (CloudEvents *sequence* extension) | decimal string |
| `sequence.boot_id` | `bootid` (extension) | |
| `sequence.run_number` | `runnumber` (extension) | decimal string |
| `traceparent` | `traceparent` (distributed-tracing extension) | |
| `correlationid` | `correlationid` (extension) | ULID |
| `causationid` | `causationid` (extension) | ULID |
| `oneof data` | `data` | protojson of the payload |

- Every attribute value is a JSON string; each key appears once.
- `data` is written with proto field names (snake_case), 64-bit integers as strings
  and enums by name. On input, camelCase names and integers as numbers are also
  accepted (protojson).
- Unknown attributes and unknown `data` fields are refused. That keeps the JSON form
  and the binary form equivalent, and catches a typo before it becomes silent data
  loss.

The binary form deliberately differs from the CloudEvents *protobuf format* (an
attribute map plus `google.protobuf.Any`). A typed `oneof` gives compile-time types,
one closed registry, and `buf breaking` checks over every payload. Conversion is
lossless in both directions for every attribute above, with three edges: an empty
`producer` or `sequence` message is the same as none (the validator treats an empty
`sequence` as absent in both forms), and unknown fields a binary event kept are not
written to JSON (JSON cannot carry them).

## Key ids

A request names its key in the signature's `keyid`. A key registered from this version on
(an admin command, an import or enrolment) has the id `sign.KeyID(pub)`: the RFC 7638 JWK
thumbprint of the Ed25519 public key as an RFC 8037 OKP key, that is base64url without
padding of the SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"<base64url of the 32-byte key>"}`
(43 characters). A producer computes it from its own key, so nobody has to copy it to the
host; any JOSE library gives the same value. A key registered earlier keeps the random id it
was given (`ak_` and 13 characters), which `signal admin ingest principal list` prints. The id
names the key and proves nothing; the signature does. One key belongs to one sender: the
same key registered twice is refused.

## Limits

`validate.Default` holds them; the ingest endpoint will advertise them.

| Limit | Value |
|---|---|
| batch body (decompressed) | 16 MiB |
| events per batch | 1000 |
| one encoded event | 1 MiB |
| a string field, by default | 1 KiB (each element of a repeated string too) |
| longer strings | description 8 KiB; remediation, evidence output and curl, cmdline elements 4 KiB; `references` 2 KiB; cloud_resource 512 B; extracted values 512 B; probe banner 256 B |
| a repeated field, by default | 256 elements |
| larger lists | snapshot listeners 16,384; route sets 4,096; scope targets 4,096; proxies, backends, SANs 1,024; processes 64; ids, references, tags 64 |
| a map field | 64 entries |
| a bytes field, by default | 0: a new bytes field must name its limit |
| `ToolOutput.inline` | 256 KiB; anything larger goes as a blob (`BlobRef`) |
| unknown fields (binary) | 16 KiB per message |
| `time` | required; at most 10 minutes ahead of the receiver's clock; any past time is allowed (imports) |
| strings | valid UTF-8, no NUL |
| numbers | doubles finite; CVSS scores 0–10, EPSS 0–1 |
| nesting | no message type contains itself; decoders stop at depth 32 |

## Generating and checking

```
make schema-gen     # buf + protoc-gen-go, pinned, installed into ./bin
make schema-check   # buf lint, generation drift, go vet, go test, the example check
```

Inside `schema/` alone: `go test ./... && go vet ./...`.

## Versions

The module is tagged as a nested module, `schema/v1.x.y`, once the repository has a
remote. The import path stays `github.com/slidehq/signal/schema/...` for all of v1; a
v2 is a new protobuf package (`asm.events.v2`) and module path
(`github.com/slidehq/signal/schema/v2`). See COMPATIBILITY.md.
