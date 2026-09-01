# Test vectors

This directory contains the one rolling, non-normative pre-1.0 validation
snapshot for the Heterodyne protocol family. A vector is owned by exactly one
family document; directory names do not imply ownership. The live
specifications, registry, and protocol schemas remain the current draft
authority even when they have advanced beyond this snapshot.

When a vector exists for a behavior, an implementation claiming that vector's
coverage MUST reproduce `produce` output byte-for-byte, MUST accept and
validate `consume` input as specified, and MUST preserve the declared
comparison surface for `round-trip` input at the pinned source commit. During
0.x, a later periodic reconciliation may replace vector IDs and behavior in
place. Vector-ID immutability, retained historical sets, and release
compatibility are deferred to the future 1.0 release policy.

## Closed snapshot

The closed, canonical `docs/spec/vectors/snapshot.json` manifest is the exact
source of mutable snapshot facts: `source_commit`, `vector_schema_version`,
`vector_count`, and the strictly sorted inventory of every artifact path and
SHA-256 digest. `snapshot-check` derives snapshot identity from the last commit
that changed that manifest. Current-draft checks and the history-bound snapshot
check remain independent.

The three isolated roots have different authority:

- The **source root**, materialized from the exact source pin, supplies the
  specification family, registry, protocol schemas, and behavioral generator
  inputs that exist at that source commit.
- The **snapshot root** supplies the committed vectors, fixtures, packaged
  vector schema, reason/coverage projections, and closed manifest.
- The **snapshot-tool root**, materialized from the snapshot commit, supplies
  only the packager and its lockfile for historical package validation.

The manifest does not assert its own snapshot commit. `snapshot-check` derives
and prints that runtime identity as the last commit that changed `snapshot.json`;
it may change when commits are squashed. The check requires the working
manifest bytes to match that commit and passes explicit source/snapshot roots
and both commit identities to the independent conformance runtime. The pinned
source determines which `conformance_checks` exist and execute. Corpus-wide
static gates execute independently.

## Snapshot envelope

Every packaged vector validates against
[`schema/vector.schema.json`](schema/vector.schema.json) and carries the closed
envelope version named by the manifest:

```json
{
  "vector_id": "<topic>/<stable-id>",
  "vector_schema_version": "<snapshot manifest value>",
  "owner_document": "core | comms | control | social | workspace",
  "profile": "<optional immutable profile id>",
  "spec_refs": ["heterodyne:<document>#<permanent-anchor>"],
  "description": "<behavior>",
  "direction": "produce | consume | round-trip",
  "input": {},
  "expected_output": {}
}
```

Any `spec_version` inside a tested event's `input` or `expected_output` is part
of that event's wire format, not snapshot-envelope authority. The current-draft
generator may produce a different corpus. Draft count changes do not require or
imply a snapshot update.

### Explicit checker applicability

A later snapshot vector may carry an optional top-level `conformance_checks`
array. It is
non-wire checker evidence: it neither changes nor appears within the protocol
input or expected output.

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
failures. A declared context pointer must also resolve when present. A missing
raw target is reported by the independent raw-binding gate so existing
exact-byte debt can be ratcheted.

For checks that reach persona resolution, the closed context carries explicit
`retired_key_evidence`: `first_observed_at` plus a nullable `prior_anchor`.
Anchor objects use type `repository-checkpoint`, `local-receipt`, or
`local-checkpoint` and an `established_at` time. They represent already
verified Core §9.1 evidence; they are not wire fields. A post-retirement
observation is final only with a timely permitted anchor, and the compromise
cutoff remains stronger than every anchor. Observation and anchor times later
than the context evaluation time are contradictory evidence.

G10 raw-binding debt uses the stable locator
`<vector-file> :: event-sha256:<64-lowercase-hex>`. The digest is SHA-256 over
the UTF-8 JSON serialization of the fixed semantic signed-event tuple
`[id,pubkey,created_at,kind,tags,content,sig]`. The checker retains RFC 6901
pointers internally for sibling and declared-raw resolution, but array indexes
do not enter failure keys; byte-identical duplicate signed events in one vector
therefore collapse to one locator.

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
semantics within the pinned source interpretation:

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

[`generator/`](generator/) is non-normative TypeScript authoring,
reconciliation, and verification tooling. Ordinary pre-1.0 draft changes do
not run snapshot authoring.

Both normal lanes are read-only:

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

Only a dedicated periodic reconciliation chooses a stable full source commit
and runs:

```bash
npm --prefix docs/spec/vectors/generator run snapshot-author -- "$PWD" <source-commit>
```

The maintainer reviews the complete transactional replacement and measured
projections, commits it, and then runs `snapshot-check`. That
author → commit → check order is mandatory because the check derives the
snapshot commit from history. The author command is never part of CI.

## Independent conformance harness

[`../conformance/`](../conformance/) independently checks the materialized
source and snapshot roots without importing generator code. Runtime checks are
invoked by `snapshot-check` with explicit roots and commit identities; direct
root selection is an internal interface rather than the contributor workflow.
The shared read-only acceptance gate is:

```bash
scripts/conformance-ci.sh
```

Baseline and report authoring are explicit maintainer operations, excluded
from normal verification and CI:

```bash
npm --prefix docs/spec/conformance run baseline-author
npm --prefix docs/spec/conformance run report-author
```

After reviewing intended authoring changes, run the read-only check again.
