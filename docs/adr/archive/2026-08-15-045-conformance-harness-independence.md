# ADR-045: Independent conformance harness and shared CI gate

**Status:** Accepted
**Date:** 2026-08-15

This record is non-canonical. The live specification family and
normative artifacts contain the complete protocol.

## Decision

Maintain a standalone conformance package that imports no generator code,
applies corpus-wide gates, runs explicitly declared Core signed-event checks,
and ratchets measured debt. The checks cover the current repository HEAD as a
draft and can also validate an exact-commit snapshot. GitHub and Radicle invoke
one read-only shell gate.

During the pre-1.0 phase, maintain one rolling snapshot at a time. Replacing
that snapshot does not establish compatibility semantics, and no pre-1.0
snapshot is an immutable compatibility target. This decision does not deploy,
publish, release, tag, push, or configure a remote service.

## Context

The vector generator currently authors and verifies much of the conformance
corpus, so checks that share its implementation can agree with generated
output without independently detecting a shared defect. The repository also
needs one deterministic acceptance gate for both GitHub and Radicle, with
corpus-wide structural coverage and an explicit boundary for executable Core
signed-event verification.

The approved design therefore introduces `docs/spec/conformance/` as an
independent, read-only checker. It reads specifications and authoritative
registry and schema inputs from the pinned source commit, then fixtures and
vectors from the rolling snapshot, but does not import source, build output,
fixtures, helpers, or runtime values from the generator.
Its gates report stable failure keys, and measured debt is retained in
ratcheted baselines so new or silently resolved debt cannot pass unnoticed.
The optional `conformance_checks` declaration makes Core checker applicability
explicit rather than inferred from vector topic, description, or shape.

The lifecycle is intentionally rolling before 1.0: draft checks describe the
current HEAD, while exact-commit checks provide a reproducible snapshot. The
rolling snapshot may be replaced as the protocol evolves; it is not a
pre-1.0 compatibility promise.

## Consequences

- The conformance package deliberately duplicates some generator coverage so
  the two checkers provide evidence of independence.
- Every committed vector remains subject to static corpus-wide gates, while
  only vectors carrying the declared Core signed-event profile are executed by
  the initial reference subject.
- Current-HEAD draft checks and exact-commit snapshot checks are both
  reproducible within the repository's pre-1.0 rolling lifecycle.
- GitHub Actions and Radicle share one read-only shell gate, reducing drift in
  integration checks while leaving existing generator checks intact.
- The conformance package, its baselines, and its reports are tooling rather
  than normative family artifacts. The live specifications, registry, and
  protocol schemas remain the protocol authority; the rolling vectors are
  non-normative evidence for their pinned source commit.
- No pre-1.0 release manifest exists. Periodic reconciliation is author,
  review, commit, then `snapshot-check`; ordinary specification changes are
  independent of that cycle.
- This record does not create compatibility semantics for pre-1.0 snapshots,
  and it does not authorize deployment or publishing.

## No-deployment scope

This decision prepares continuous-delivery verification only. It does not
publish packages or reports, create a release or tag, push to a remote
repository, change GitHub branch protection, or configure Radicle brokers,
nodes, containers, or delegates.

## Acceptance and archive

The amended lifecycle, integrated implementation, security and specification
review waves, and clean acceptance matrix passed before this record was
accepted and moved to `docs/adr/archive/`. The specification and normative
machine-readable artifacts stand on their own and do not depend on this
record.
