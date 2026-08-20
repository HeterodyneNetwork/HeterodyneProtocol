# Test vectors

This directory contains the normative conformance vectors for the Heterodyne
protocol family. A vector is owned by exactly one family document; directory
names do not imply ownership.

When a vector exists for a behavior, an implementation claiming that vector's
coverage MUST reproduce `produce` output byte-for-byte, MUST accept and
validate `consume` input as specified, and MUST preserve the declared
comparison surface for `round-trip` input. During 0.x, current vector IDs and
behaviors MAY change or be retired before release. Released artifact sets and
their exact bytes remain historical records; vector-ID immutability begins at
1.0.

## Family metadata

Every vector validates against
[`schema/vector.schema.json`](schema/vector.schema.json) and carries:

```json
{
  "vector_id": "<topic>/<stable-id>",
  "vector_schema_version": "1.1.0",
  "owner_document": "core | comms | control | social | workspace",
  "spec_version": "heterodyne/0.5.0",
  "profile": "<optional immutable profile id>",
  "spec_refs": ["heterodyne:0.5.0#<permanent-anchor>"],
  "description": "<behavior>",
  "direction": "produce | consume | round-trip",
  "input": {},
  "expected_output": {}
}
```

The schema requires each actual vector's `spec_version` to be the scalar
family version. A `spec_version` inside a tested event's `input` or
`expected_output` is part of that event's wire format and is not the vector
envelope version. The current unreleased corpus contains 499 normative vectors.
Ten transport-independent credential-continuity draft evaluations explicitly set
`conformance_claimable:false`; they do not activate a wire or recovery profile.
Historical released vectors and the signed behavior they describe MUST NOT be
rewritten. Unreleased 0.x vectors may be changed or retired in place under an
accepted specification change.

### Explicit checker applicability

A vector may carry an optional top-level `conformance_checks` array. It is
non-wire checker evidence: it neither changes nor appears within the protocol
input or expected output. The current 499-vector corpus uses schema 1.1.0 and
declares exactly three checks.

Each declaration is a closed object with this shape:

```json
{
  "profile": "core-signed-event-v1",
  "event_pointer": "/input/event",
  "nip01_raw_pointer": "/input/nip01_raw",
  "context_pointer": "/input/vector_context",
  "expected_terminal_stage": "signature"
}
```

The event and raw pointers are required RFC 6901 pointers. The context pointer
is optional for checks terminating before persona resolution and required when
the ordered checker reaches persona resolution or a later stage. The terminal
stage is exactly one of `event_structure`, `nip01_raw`, `identifier`,
`signature`, `persona_resolution`, `version_stamp`, `kel_head`,
`epoch_authority`, `subtype_nid`, or `accept`. A checker runs only explicitly
declared profiles and never infers applicability from the vector topic,
description, object shape, or decision trace. Unknown profiles or members,
malformed pointers, duplicate declarations, and a missing event target are
failures. A missing raw target is reported by the independent raw-binding gate
so existing exact-byte debt can be ratcheted.

Family layering follows this DAG:

```text
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

Core vectors stand alone; Comms, Control, Social, and Workspace behaviors obey
the corresponding family-layering constraints. Optional Control and Social
composition claims add those documents separately.
Control vectors cover Marmot group
admission, enrollment, entitlements, node-scoped tokens, RPC, operation
reservation, failover, retention, and separately advertised recovery profiles.

## Coverage authority

[`coverage/manifest.json`](coverage/manifest.json) is the sole coverage source.
The Core, Comms, Control, Social, Workspace, and family Markdown files in `coverage/` are
deterministic generated projections. Do not maintain parallel maps by hand.

Ownership is declared per vector, never inferred from its directory. In
particular:

- new Nostr-native envelope vectors are Comms;
- `interop/001-003` are Social while `interop/004` is Core;
- `org/001-003` are Core while `org/004` is Comms;
- recovery and config-backup vectors split by the behavior each exercises;
- Core Radicle multi-host redundancy uses new `core-redundancy/` IDs; and
- acceptance gating is split between Comms hook behavior and Social
  tighten-only policy behavior; and
- `marmot-radicle/` covers pinned Marmot interoperability, exact-byte
  carriage, routing generations, group repositories, persona inboxes,
  retention, and node-mediated agent operations.

Four Comms-owned claims/OIDC groups retain their profile-specific allocation
semantics while their vector envelopes carry the current family version:

- `claims/` covers canonical IDs and typed keys, issuer/trust decisions,
  attenuation, proof of possession, visibility, and revocation;
- `claim-ledger/` covers repository confirmation, rollback, confinement,
  reader removal, monotonic multi-writer replay, issuer authority, and mint
  freshness;
- `oidc/` covers exact discovery, required and prohibited grants, consent,
  pairwise subjects, ID/access/assertion token separation, and sender
  constraints; and
- `token-status/` covers the exact draft-21 profile, writer allocation,
  freshness, byte-identical HTTPS/Radicle mirrors, key compromise, and issuer
  succession.

The coverage manifest maps every vector to one permanent Comms anchor. OIDC
vectors test an interoperable projection; they do not make JWTs or HTTPS the
canonical authorization source. Private claims, consent records, issuance
mappings, and audience keys are never public-discovery fixtures.

## Reason codes

The authoritative reason-code allocation container is
[`../registry/reason-codes.json`](../registry/reason-codes.json). The files
under `schema/reason-codes.*` are generated compatibility projections, not a
second authority. These diagnostic strings are test vocabulary; an
implementation does not need to emit them on the wire.

## Determinism

Vectors pin all nondeterministic input. BIP-340 signatures use an all-zero
32-byte auxiliary value; NIP-44 vectors carry fixed nonces; time-sensitive
cases place `simulated_clock` in `input`; and canonical comparisons use signed
NIP-01 bytes rather than pretty JSON or relay framing.

Marmot/Radicle vectors begin at the Heterodyne integration boundary. They
exercise Heterodyne attribution, storage, transport, and authorization rules
without redefining upstream MLS or application-event semantics.

## Generator

[`generator/`](generator/) is non-normative TypeScript authoring and
verification tooling. The committed JSON vectors are the normative artifacts.

From the repository root:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author
npm --prefix docs/spec/vectors/generator run release-check
npm --prefix docs/spec/vectors/generator run check
```

Running `author` also regenerates `fixtures.json`, the vector JSON schema, and
the compatibility reason-code projections from their authoritative sources.
Running `coverage` then regenerates the manifest and all Markdown views.

## Independent conformance harness

[`../conformance/`](../conformance/) independently checks the committed
specification family, registries, schemas, release metadata, and every
normative vector. Its normal verification command is read-only:

```bash
npm --prefix docs/spec/conformance run check
```

Baseline and report authoring are explicit maintainer operations, excluded
from normal verification and CI:

```bash
npm --prefix docs/spec/conformance run baseline-author
npm --prefix docs/spec/conformance run report-author
```

After reviewing intended authoring changes, run the read-only check again.
