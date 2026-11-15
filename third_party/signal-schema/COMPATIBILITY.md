# Compatibility policy: `asm.events.v1`

The schema is a public contract. Portwarden agents, scanners and future tools write to
it, and the product reads both the live feed and its stored history (a replay reads
every event still in the log). Most rules below can be checked by a machine
(`buf breaking` with `WIRE_JSON`, and the example corpus).

## 1. What a version is

- **Major** = the protobuf package (`asm.events.v1`) and the Go module's major. A new
  major is a new package (`asm.events.v2`) beside the old one, in a new module path
  (`github.com/slidehq/signal/schema/v2`), never an edit of v1.
- **Minor and patch** = the module's SemVer tag, `schema/v1.MINOR.PATCH` (a nested
  module's tag carries its directory). Additions bump MINOR. Comments, docs, and a
  validator change that still accepts every valid old event bump PATCH.
- An event names its schema by `type` (stable) and optionally `dataschema`
  (`asm.events.v1/<Message>`). There is no per-event minor version: readers handle
  fields by presence, not by version numbers.

## 2. Allowed within v1 (a MINOR bump)

1. **New fields with new numbers.** A proto3 scalar defaults to zero, so a new
   field's zero value must mean "unknown" or "not sent" (use `optional` when zero is a
   real value, as `firewall_fingerprint` does).
2. **New event types**: a new `oneof data` case with a new number, a registry row, a
   README row and an example, in the same change. Case numbers: agent 20–39, product
   services 40–59, tools 60–999. Envelope fields use 12–19, then 1000 and up.
3. **New enum values.** Every enum has a zero `*_UNSPECIFIED` value, and every reader
   treats an unknown value as unspecified (in Go, a `default:` branch; never a panic
   or a rejection).
4. **New key schemes, subject forms, and string values** of `trigger`, `result`,
   `method`, `verdict` and the like: a reader treats an unknown string as opaque.
5. **Loosening a limit** (a larger cap in `validate.Default`). The product advertises
   its limits; a producer may rely on a larger one only once the product it talks to
   has it (section 4).

## 3. Never within v1 (needs v2)

- Removing, renumbering or retyping a field; switching between repeated and singular;
  moving a field into or out of a `oneof`; renaming a field (the JSON form uses the
  names). Retire a field instead: mark it `[deprecated = true]`, stop writing it, keep
  reading it. In v2, `reserved` both its number and its name.
- Changing what a field or a type **means** (units, level numbering, the subject it
  refers to). A new meaning is a new field or a new type.
- Reusing a `type` string or a `data` case number.
- Tightening validation so that an event a released producer sends becomes invalid
  (a smaller limit, a new required field, a narrower form).
- Changing the encoding a digest is defined over (`HostSnapshot.digest`,
  `ProxyRoutes.routes_digest`). A new algorithm is a new field.

## 4. Unknown fields and upgrade order

- **The product upgrades first.** A producer may use a field or a type only once the
  product it sends to is built with a schema version that has it (the endpoint will
  advertise its version).
- **Binary (agents): unknown fields are kept.** Protobuf preserves them, and the
  product stores the bytes as received, so an event from a newer agent loses nothing
  and a replay after the product upgrades sees the new fields (up to 16 KiB of
  unknown fields per message: their form cannot be checked). An unknown `oneof data`
  case (a newer producer's type) is rejected with `unknown_type`: it is quarantined,
  still advances the producer's cursor, so the agent does not stall, and can be
  re-ingested once the product knows the type.
- **JSON (tools): unknown fields are refused.** Unknown `data` fields and unknown
  attributes are an `invalid_payload` rejection for that event (in a 200 answer, not a
  4xx for the batch). Tools pin the schema version they were built against. Being
  strict is what catches a typo before it becomes silent data loss.

## 5. Reading old data (replay)

- Processors must read every event still in the log, that is any minor of the current
  major. The example corpus of each released minor is kept (`examples/` at that tag)
  so a processor can be tested against it.
- A new major ships an **upcaster** (v1 to v2, a pure function in the schema module),
  and the product keeps accepting v1 for at least two agent releases and six months,
  whichever is longer. Stored v1 events are upcast on read, never rewritten in place
  (the log is append-only).

## 6. Deprecation

- Mark the field `[deprecated = true]` with a comment naming its replacement and the
  release that deprecated it.
- The product counts deprecated-field use per producer, so the fleet view can show
  which agents still send it. The field is removed only in the next major, and only
  once that count has been zero for the overlap window.

## 7. Validation is part of the contract

- The validators live in this module (`validate`, `cejson`), not in the product, so a
  producer runs exactly the checks the server runs before it sends.
- A validator change that rejects previously valid data is a breaking change
  (section 3).

## 8. Checks

Now, in `make schema-check` (and so in `make ci`):

- `buf lint`.
- Generation drift: the checked-in Go equals a fresh `buf generate`.
- `go vet` and `go test` inside `schema/`.
- The example check (`tools/excheck`): every registry type has an example; every
  example decodes strictly, passes the validators and survives a JSON and a binary
  round trip; the registry, the `Event.data` oneof and README.md's table agree.

From the first tag (`schema/v1.0.0`) on, added then:

- `buf breaking --against '.git#tag=<latest schema/v1 tag>,subdir=schema/proto'` with
  `WIRE_JSON`.
- Golden encodings: the binary encoding and digest of each example frozen, so a
  generator or dependency upgrade that changes bytes is seen.
- Fuzz targets for the JSON and binary batch decoders and the validators.

## 9. The overlay and the observed address

Signal's ingest door listens only on the NetBird overlay, so the address a request arrives from
(`IngestResponse.observed_remote_addr`) is the overlay address, not a public one. The door leaves the
field empty. A producer must not use it as a public-IP candidate (`via=ingest-observed`); it takes its
public address from its own sources (cloud metadata, `publicip`) or the NetBird management API.

## 10. Key ids

A key registered with the product has the id `sign.KeyID` derives from its public key (README,
"Key ids": the RFC 7638 thumbprint of the RFC 8037 OKP key). The rule is part of the contract:
changing it is a breaking change (a producer computes its id itself), and a second rule would be a
new function beside it, never an edit. The receiver looks a key up by whatever id it stored, so a
key registered before the rule keeps its random id and keeps working. Added in v1 as a MINOR
change (a new function; no wire change).
