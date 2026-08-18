# Protocol Simplification Stabilization Design

**Date:** 2026-08-17<br>
**Status:** Approved for implementation planning<br>
**Scope:** Complete and stabilize the in-progress single-version, deduplication,
and optional-feature simplification

## Objective

Finish the current simplification without leaving competing normative models.
After this change, the live specification, registry, schemas, vectors,
authoring documentation, and release metadata will describe one coherent
`heterodyne/<semver>` family release.

The work addresses six confirmed gaps:

1. obsolete per-document and permissive `0.x` version vectors;
2. an incomplete shared key-envelope contract;
3. Control-specific node-scoped JWT semantics incorrectly owned by Comms;
4. missing decision and family-release records;
5. authoring documentation and checks that preserve stale models; and
6. an incomplete `profile_revision` terminology migration.

## Version and capability model

The family has one qualified version, `heterodyne/<semver>`. During `0.x`,
peers and asynchronous consumers accept only an exact supported family
version unless an explicitly declared degraded mode refuses to apply unknown
security semantics. Documents remain conformance and layering boundaries, not
independently negotiated version lineages.

The normative versioning vectors will be rewritten around that model. They
will cover qualified parsing, rejection of unqualified and retired
document-qualified forms, exact-version negotiation, asynchronous unknown
version rejection, and the current capability bootstrap object. Generator
tests will assert those semantics instead of merely reproducing authored JSON.

## Shared key-envelope contract

Core will define five explicit instantiation choices:

1. recipient-set rule;
2. typed-key reference and wrapping profile;
3. carrier;
4. generation-identifier form; and
5. additional rotation triggers, explicitly `none` when absent.

The common contract will continue to require authenticated ciphertext,
authority evidence, removal rotation, future-use rejection for retired
generations, and honest non-erasure disclosure. Each instantiation will state
all five choices without duplicating those rules.

Workspace resource delivery will name its recipient with an allocated typed-key
reference rather than an untyped "device leaf." The type will bind the exact
Marmot MLS leaf identity needed to distinguish independently authorized device
leaves; its canonical encoding and verifier will be defined in Core and the
registry as appropriate. The Workspace schema and vectors will carry the same
typed identity explicitly.

## Control ownership of node-scoped JWTs

The Control-shaped node token belongs entirely to Control. The
`comms.node-scoped-jwt.v1` feature will be removed. Comms will retain only
generic claims and the optional third-party OIDC/JWT projection; it will not
define tokens containing Control groups, entitlements, methods, objects, or
limits.

`control.node-scoped-token.v1` will own the RFC 9068 `at+jwt` profile,
node-local issuer state, sender/group confirmation, token lifetime, current
entitlement revalidation, and Control-specific claims. Its prerequisites will
be the Comms private claim ledger and Control Marmot/entitlement features, not
the third-party OIDC projection. OAuth device enrollment may continue to
require the OIDC projection where its standards-facing flow needs it.

Security invariants, feature closures, prose references, and vectors will be
updated together so no Comms-only or OIDC-only claim inherits Control
semantics.

## Decision and release records

A proposed ADR will record the rationale and the complete normative
integration surface for these changes. It will remain proposed while the patch
is under review and move to the archive only after acceptance, following the
repository workflow.

The deleted per-document release manifests will be replaced by one family
release manifest and schema. The manifest will pin the family version, release
status, registry manifest digest, five normative documents, schemas, normative
vectors, and other normative support artifacts by exact path and SHA-256. It
will represent one family release without restoring independent document
versions or registry-history snapshots.

## Documentation and validation

The vector README, NIP extraction index, glossary, threat model, generator
commands, corpus counts, and terminology will be updated to the single-family
model. `profile_revision` will be the only name used for the frozen v1 claim
profile allocation member; `registry_revision` will refer only to the current
family registry counter or historical prose that explicitly discusses the old
name.

Documentation lint will cover the maintained authoring guides affected by the
cutover. Semantic tests will protect the family-version cases, feature
ownership and prerequisite closure, key-envelope instantiations, family
release-manifest closure, and retired terminology. Generated-artifact
verification will remain deterministic but will no longer be the sole check
for normative vector meaning.

## Verification

Implementation is complete only when all of the following succeed from the
repository root:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
git diff --check
```

Targeted tests must also demonstrate that the old per-document negotiation,
Comms-owned Control token, untyped Workspace envelope recipient, obsolete
vector metadata, and retired claim member terminology are rejected.
