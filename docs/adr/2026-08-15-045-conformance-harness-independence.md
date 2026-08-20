# ADR-045: Independent conformance harness and shared CI gate

**Status:** Proposed
**Date:** 2026-08-15

## Decision

Add a standalone conformance package that imports no generator code, applies
corpus-wide gates, runs explicitly declared Core signed-event checks, and
ratchets measured debt. GitHub and Radicle invoke one read-only shell gate.
Registry revision 13 and vector schema 1.1.0 ship in the same patch; live
specifications and artifacts remain authoritative.

## Context

The vector generator currently authors and verifies much of the conformance
corpus, so checks that share its implementation can agree with generated
output without independently detecting a shared defect. The repository also
needs one deterministic acceptance gate for both GitHub and Radicle, with
corpus-wide structural coverage and an explicit boundary for executable Core
signed-event verification.

The approved design therefore introduces `docs/spec/conformance/` as an
independent, read-only checker. It reads committed specifications, registry
entries, schemas, fixtures, release metadata, and vectors, but does not import
source, build output, fixtures, helpers, or runtime values from the generator.
Its gates report stable failure keys, and measured debt is retained in
ratcheted baselines so new or silently resolved debt cannot pass unnoticed.
The optional `conformance_checks` declaration makes Core checker applicability
explicit rather than inferred from vector topic, description, or shape.

## Consequences

- The conformance package deliberately duplicates some generator coverage so
  the two checkers provide evidence of independence.
- Every committed vector remains subject to static corpus-wide gates, while
  only vectors carrying the declared Core signed-event profile are executed by
  the initial reference subject.
- Registry revision 13 and vector schema 1.1.0 are coupled to the patch; the
  family version remains `heterodyne/0.5.0` and its release remains
  unreleased.
- GitHub Actions and Radicle share one read-only shell gate, reducing drift in
  integration checks while leaving existing generator checks intact.
- The conformance package, its baselines, and its reports are tooling rather
  than normative family artifacts. The live specifications, registry, schemas,
  release metadata, and vectors remain the protocol authority.

## No-deployment scope

This decision prepares continuous-delivery verification only. It does not
publish packages or reports, create a release or tag, push to a remote
repository, change GitHub branch protection, or configure Radicle brokers,
nodes, containers, or delegates.

## Acceptance and archive condition

This ADR remains proposed while the integrated implementation is reviewed.
After the standalone package, registry revision 13, vector schema 1.1.0,
coupled vectors, shared CI gate, and repository guidance are complete and the
family and conformance checks pass, accept this record and move it to
`docs/adr/archive/` before merge. The accepted ADR is historical context only;
the specification and normative machine-readable artifacts must stand on
their own and must not depend on this record.
