# Test vectors

This directory contains the normative conformance vectors for the Heterodyne
protocol family. A vector is owned by exactly one independently versioned
document; directory names do not imply ownership.

When a vector exists for a behavior, an implementation claiming that vector's
coverage MUST reproduce `produce` output byte-for-byte, MUST accept and
validate `consume` input as specified, and MUST preserve the declared
comparison surface for `round-trip` input. Existing vector IDs are immutable.
Changed behavior receives a new ID.

## Family metadata

Every vector validates against
[`schema/vector.schema.json`](schema/vector.schema.json) and carries:

```json
{
  "vector_id": "<topic>/<stable-id>",
  "vector_schema_version": "1.0.0",
  "owner_document": "core | comms | control | social",
  "owner_version": "<owner>/0.5.0",
  "dependency_versions": {
    "<permitted-lower-document>": "<document>/0.5.0"
  },
  "registry_revision": 1,
  "profile": "<optional immutable profile id>",
  "spec_refs": ["heterodyne:<document>/0.5.0#<permanent-anchor>"],
  "description": "<behavior>",
  "direction": "produce | consume | round-trip",
  "input": {},
  "expected_output": {}
}
```

The former scalar `spec_version` is not vector metadata. A `spec_version`
inside a tested event's `input` or `expected_output` is part of that event's
wire format and is not the vector envelope version.

Dependency versions follow the family DAG:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Core vectors therefore have no dependencies; Comms vectors pin Core; Control
and Social vectors pin Core and Comms. Control currently has no vectors and is
explicitly `incomplete-draft`; no implementation may claim its profile until
ADR-030's minimum corpus exists.

## Coverage authority

[`coverage/manifest.json`](coverage/manifest.json) is the sole coverage source.
The Core, Comms, Control, Social, and family Markdown files in `coverage/` are
deterministic generated projections. Do not maintain parallel maps by hand.

Ownership corrections required by ADR-033 are per vector. In particular:

- existing Matrix envelope and mirror-redundancy vectors are Social;
- new Nostr-native envelope vectors are Comms;
- `interop/001-003` are Social while `interop/004` is Core;
- `org/001-003` are Core while `org/004` is Comms;
- recovery and config-backup vectors split by the behavior each exercises;
- Core Radicle multi-host redundancy uses new `core-redundancy/` IDs; and
- acceptance gating is split between Comms hook behavior and Social
  tighten-only policy behavior.

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
NIP-01 bytes rather than pretty JSON or relay framing. The double-ratchet
transcript uses the exact pinned `nostr-double-ratchet@0.0.138` wire library
with deterministic keys, randomness, and time.

Matrix vectors begin at the adapter boundary after the Matrix SDK has handled
federation and E2EE. They cover Social's Heterodyne-visible payload and policy
semantics, not Matrix server authorization or Megolm internals.

## Generator

[`generator/`](generator/) is non-normative TypeScript authoring and
verification tooling. The committed JSON vectors are the normative artifacts.

From the repository root:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run check
```

Running `author` also regenerates `fixtures.json`, the vector JSON schema, and
the compatibility reason-code projections from their authoritative sources.
Running `coverage` then regenerates the manifest and all Markdown views.
