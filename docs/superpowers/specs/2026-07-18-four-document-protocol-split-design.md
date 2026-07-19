# Four-Document Protocol Split Design

**Date:** 2026-07-18
**Status:** Approved for planning
**Decision source:** ADR-033 and user review on 2026-07-18

## Goal

Execute ADR-033 by replacing the 0.4.x monolithic normative specification with
four independently versioned 0.5.0 normative documents: Heterodyne Core,
Heterodyne Comms, Heterodyne Control, and Heterodyne Social. Preserve the
monolith and its anchors, enforce the one-directional dependency graph, and
make registry, version, conformance, security, and vector ownership executable
rather than editorial conventions.

## Scope and sequencing

This design starts from repository commit `13ec42c`, where ADR-032 has already
been integrated into the monolith. That satisfies ADR-033 requirement 35.

The split is phase one of two. The key-claim repository and OIDC projection are
specified separately in
`docs/superpowers/specs/2026-07-18-key-claims-oidc-design.md` and are integrated
only after the split. The split must be reviewable and conformant to ADR-033
without depending on that later feature.

ADR-030 and ADR-031 remain subject to ADR-033's acceptance and amendment gates.
The split creates the document boundaries and lower-layer extension points
they require; it does not silently treat proposed ADR material as accepted.

## Chosen approach

Use hybrid extraction and boundary rewriting:

1. Preserve the complete source text and map every old section.
2. Extract normative material to the owner assigned by ADR-033.
3. Rewrite cross-boundary language, ownership, version stamps, and conformance
   rules rather than preserving monolith-era leaks.
4. Prove closure with generated manifests and validation checks.

A mechanical section split was rejected because it would retain Social policy
inside Comms and leave invalid upward references. A clean-room rewrite was
rejected because it risks silently dropping normative behavior and vector
coverage.

## Artifacts and document boundaries

`docs/spec/heterodyne.md` becomes a short, explicitly non-normative family
overview and document map.

The pre-split normative bytes are preserved at:

- `docs/spec/archive/heterodyne-0.4.0.md`
- `docs/spec/archive/heterodyne-0.4.0-anchor-map.md`

The four normative documents are:

- `docs/spec/heterodyne-core.md`
- `docs/spec/heterodyne-comms.md`
- `docs/spec/heterodyne-control.md`
- `docs/spec/heterodyne-social.md`

All four first releases are `0.5.0`, descended independently from monolith
0.4.x. They do not share a synchronized family version.

### Core

Core owns identity, KEL replay and verification, `kel_head`, compromise
windows, npub canonicality, Nostr canonical serialization, root attestations,
NID delegation, identity pointers, node roles, repo-relay substrate,
materialized KEL refs, node advertisements, Tor reachability, generic
threshold authority, social-neutral recovery, KERI witnesses, did:webs export,
qualified version grammar, capability negotiation, registry consumption,
conformance methodology, and Core security invariants.

Core contains only generic downward repository primitives plus its complete
local keys-repository protection profile. It does not depend on Comms for
encryption.

### Comms

Comms owns the Nostr-native canonical event envelope, repository privacy
tiers, publishing and fan-out, generic outbox ordering, retrieval and backfill,
feed/outbox discovery, double-ratchet DMs, credential-plane synchronization,
the authenticated acceptance-policy hook, subprotocol negotiation, threshold
authorization for org-owned Comms content, and confidentiality/forward-secrecy
invariants.

### Control

Control is a Comms profile, not an independent transport. Its document starts
as an explicitly incomplete 0.5.0 draft unless ADR-030 has been amended,
accepted, integrated, and covered by its minimum vector corpus. It cannot claim
Control conformance with zero vectors.

### Social

Social owns following, replies, reactions, threading, social discovery,
cross-persona advertisements, moderation, mute and policy lists, labels,
web-of-trust policy, community and org presentation, mixed-tier social fan-out,
starter packs, ATProto integration, and the entire optional Matrix feature.
Social and Social+Matrix are distinct conformance claims.

## Dependency and reference rules

The only normative document edges are:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Social never depends on Control. Client implementations may compose the two
conformance claims without adding a document dependency.

Normative cross-document references use document ID, exact version, and
permanent anchor. A lower document never normatively references a higher
document. The local downref and registry-state rules in ADR-033 requirement 2
are enforced by validation.

## Registry artifact

`docs/spec/registry/` is a Core-owned artifact with its own monotonic revision
and immutable digest. It contains:

- A manifest with revision, digest, and schema version.
- Kind allocations and immutable profile discriminators.
- Reason codes with owner, status, and first-version metadata.
- Namespaced security-invariant identifiers.

Each kind records allocation authority, base-schema owner, stability, and any
profile owners. Entry state transitions only `draft -> stable -> frozen`.
Frozen entries cannot be changed, removed, or reassigned.

Every document release, release manifest, capability example, vector, and
coverage manifest pins the registry revision or immutable digest. Registry
changes to non-Core-owned entries do not change Core semver.

## Versioning and conformance

Core defines qualified identifiers `<doc-id>/<semver>` for `core`, `comms`,
`control`, and `social`. The semver component alone is parsed as semver.

Event stamping follows ADR-033 requirements 22 through 29. Only Core, Comms,
and Social own wire stamps. Control never stamps a wire event. DR outer events
remain unstamped; inner rumors carry the Comms carrier version inside
ciphertext. Adopted upstream events remain unstamped unless an immutable
registered profile says otherwise.

Conformance classes are Core, Core+Comms (Heterodyne persona), Control profile,
Social, and Social+Matrix. Claims name required features and versions. The old
uppercase `CORE` label is retired. Strict mode becomes namespaced,
per-document profiles with explicit composition rules.

## Migration and companion documents

The anchor map covers every numbered section and named schema in the archive.
Unqualified legacy `0.4.0` stamps continue to mean the archived monolith;
existing signed events are never restamped.

`README.md`, `CLAUDE.md`, `AGENTS.md`, `CHANGELOG.md`,
`docs/architecture.md`, `docs/glossary.md`,
`docs/security/threat-model.md`, vector documentation, extension indexes, and
`research/INDEX.md` are updated to describe the family. The threat model uses
`CORE-I*`, `COMMS-I*`, `CONTROL-I*`, and `SOCIAL-I*`; mixed monolith invariants
are decomposed.

Release manifests record the exact dependency and registry combination.
Per-document tag names are `core/v0.5.0`, `comms/v0.5.0`,
`control/v0.5.0`, and `social/v0.5.0`; tags are created only when the
corresponding release satisfies its declared conformance status.

## Vector and generator design

The vector schema replaces a scalar spec version with:

- `owner_document`
- `owner_version`
- `dependency_versions`
- `registry_revision` or registry digest
- qualified spec references
- optional profile ID

Ownership is assigned per vector, never per directory. Changed behavior gets a
new vector ID; existing IDs remain immutable.

The generator emits one machine-readable coverage manifest. Core, Comms,
Control, Social, and family coverage maps are filtered views of that manifest;
no parallel hand-maintained maps exist.

Validation checks:

- byte identity of the archived monolith;
- complete old-section anchor coverage;
- valid dependency direction and qualified references;
- registry ownership, discriminator immutability, and revision pins;
- event stamp placement and legacy inference;
- per-vector ownership and dependency metadata;
- coverage-map derivation and regeneration stability.

## Acceptance criteria

The split is complete only when:

1. The archive checksum matches the pre-split monolith.
2. Every old section resolves through the anchor map.
3. All four documents have permanent anchors and coherent 0.5.0 lineage.
4. The Thin-P1 closure list in ADR-033 requirement 9 is exhausted.
5. No forbidden dependency edge or bare normative cross-reference remains.
6. Registry, version, stamp, conformance, and strict-mode rules are fully
   represented in normative text and schemas.
7. Companion documents describe the protocol family consistently.
8. Generator type-checking, unit tests, vector verification, and byte-drift
   checks pass.
