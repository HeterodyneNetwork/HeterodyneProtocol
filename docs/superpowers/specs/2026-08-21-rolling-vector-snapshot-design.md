# Rolling Pre-1.0 Vector Snapshot Design

**Date:** 2026-08-21
**Status:** Approved for implementation planning
**Scope:** Pre-1.0 specification and conformance workflow

## Decision

Keep the conformance vectors in this repository, but decouple their lifecycle
from the evolving specification family. Until 1.0, `docs/spec/vectors/`
contains one rolling validation snapshot: the latest corpus reconciled against
one exact, already-committed repository state.

The full Git commit named by the snapshot manifest is authoritative. Any
human-readable draft or family label is descriptive only. Ordinary
specification changes do not update or invalidate the snapshot, and vector
reconciliation occurs periodically in a dedicated change after its source
commit is stable in repository history.

Before 1.0, the specification family describes an evolving protocol idea.
Neither draft labels, registry revisions, schema versions, nor snapshot
sequence numbers establish compatibility or release semantics. At 1.0, a
separate decision will define versioned normative vectors and immutable
release artifacts.

## Why the vectors remain in this repository

The present bottleneck is lifecycle coupling rather than filesystem location.
Today the contributor rules require every protocol change to update vectors,
the family release manifest hashes live specifications and vectors together,
and the generator byte-compares the committed corpus with output derived from
current HEAD. Moving the same model to another repository would retain the
coupling while adding cross-repository permissions, two-change coordination,
pinned dependency fetches, and harder local review.

Keeping the latest snapshot beside the specifications preserves discoverability,
atomic review of reconciliation changes, and simple local tooling. A separate
repository becomes useful only when vector artifacts have independent
maintainers, consumers, access controls, storage requirements, or a release
cadence that justifies that operational boundary.

## Alternatives considered

### Separate vector repository

This gives the corpus an independent release cadence and keeps generated data
out of the specification repository. It also requires cross-repository pins,
coordinated changes, external availability during verification, and a policy
for which repository is authoritative when they disagree. Those costs do not
serve the current pre-1.0 workflow.

### Keep current same-change integration

This guarantees that every commit presents one internally synchronized
specification and vector corpus. It is appropriate for immutable releases but
makes exploratory specification work pay the full authoring, regeneration,
review, and conformance cost on every change. That is the workflow being
replaced.

### Rolling in-repository snapshot

This is the selected approach. It keeps one supported corpus, pins it to an
exact historical input state, and lets current specifications advance without
claiming that the older snapshot describes current HEAD.

## Terminology and authority

- **Draft specification:** the specification, registry, and schema files at
  current HEAD. They may change without a vector update.
- **Source commit:** the full Git commit whose specification, registry,
  protocol schemas, behavioral generator, and authoring inputs define the
  behavior in the latest vector snapshot. The source's legacy vector-envelope
  schema is raw generator input, not the schema applied to the packaged
  snapshot.
- **Vector snapshot:** the current committed vector corpus, projections, and
  snapshot manifest under `docs/spec/vectors/`.
- **Reconciliation:** the explicit operation that replaces the current vector
  snapshot with output generated from a selected source commit.
- **Snapshot commit:** the later commit that stores generated vectors and the
  manifest, plus the behavior-neutral snapshot packager that normalizes the
  envelope and inventories exact output bytes. Its identity is supplied by Git
  and is not embedded in its own contents or committed reports.

Until 1.0, live draft specifications remain the primary design authority and
vectors are non-normative validation evidence. A snapshot proves what the
tooling concluded about its source commit; it does not constrain later draft
changes or activate a protocol release.

## Repository layout

The existing `docs/spec/vectors/` location remains the home of the latest
snapshot. Old snapshots are replaced in place and are supported only through
ordinary Git history.

Add a closed manifest at:

```text
docs/spec/vectors/snapshot.json
```

Its conceptual shape is:

```json
{
  "snapshot_schema": "1",
  "source_commit": "<40-lowercase-hex Git commit>",
  "vector_schema_version": "<vector envelope schema>",
  "vector_count": 0,
  "artifacts": [
    {
      "path": "docs/spec/vectors/<path>.json",
      "sha256": "<64-lowercase-hex>"
    }
  ]
}
```

`source_commit` is the binding source identity. The manifest carries no draft
protocol version or snapshot sequence because neither has compatibility
meaning before 1.0. The artifact array is closed over every file consumed as
snapshot data: vector JSON files, `fixtures.json`, the packaged
vector-envelope schema, reason-code and coverage projections, and any later
deterministic snapshot projection. It does not cover documentation, generator
or checker source, installed dependencies, or the manifest itself. Paths are
repository-relative, safe, unique, and strictly sorted; digests cover exact
bytes. `vector_count` counts only vector documents, not fixtures, schemas, or
projections.

The manifest does not contain the snapshot commit SHA because a commit cannot
contain its own content-addressed identity. Consumers identify the snapshot
commit as the last commit that changed `snapshot.json`, and use
`source_commit` to identify the behavioral inputs that were reconciled. This
derived identity remains valid after a squash merge: the merge commit becomes
the snapshot commit while preserving the reviewed packager and snapshot bytes.
Committed baselines and reports likewise carry `source_commit` and a digest of
the snapshot artifact set, not `snapshot_commit`; the derived snapshot commit
is runtime output only.

## Vector envelope metadata

The snapshot manifest supplies source identity for the corpus. Per-vector
metadata must not repeat a mutable draft version as though it were release
authority.

During migration:

- remove the per-vector scalar `spec_version`;
- remove the fixture-envelope `spec_version` and coverage-entry
  `spec_version`, while preserving nested schema property names and version
  values that are part of behavioral vector inputs or outputs;
- keep `vector_schema_version`, because it identifies the vector envelope
  shape rather than a protocol release;
- keep `owner_document`, direction, profile, and conformance declarations;
- encode specification references as
  `heterodyne:<document>#<stable-anchor>` and resolve them against
  `source_commit`; and
- permit vector IDs and behaviors to change or disappear when the rolling
  snapshot is reconciled before 1.0.

The schema, generator, coverage, and checker migrate to the reference syntax
together. For example, `heterodyne:core#core-verification` identifies the Core
anchor, while the snapshot source commit supplies the historical dimension.
The source generator's native `Vector` type and schema remain raw-authoring
contracts. Raw output is validated against the schema materialized from the
source commit, normalized into a distinct `SnapshotVector`, and then validated
against the packaged snapshot schema. Schema-2 output is never validated with
the source's schema-1 contract.

## Manifest and release separation

The pre-1.0 family release manifest currently binds live specification bytes,
registries, schemas, and vectors into one artifact set. That model makes any
specification edit create release drift and must not remain the normal draft
gate.

Before 1.0:

- the vector snapshot manifest owns vector and projection byte integrity;
- draft-specification checks validate current prose, registry, and schema
  consistency without expecting vector agreement;
- no manifest calls the combination of current draft specifications and an
  older vector snapshot one coherent protocol release; and
- content-addressed versioned family release manifests are deferred until a
  real release model is introduced.

The existing `docs/spec/releases/family/0.5.0.json` should therefore be
retired or re-scoped during implementation. Retaining it unchanged would
preserve the coupling this decision removes.

## Validation architecture

Validation splits into two explicit lanes.

### Draft-specification lane

This lane reads current HEAD and checks only the evolving design sources:

- specification-family structure and links;
- registry and schema shape and internal references;
- maintained-document lint and security-document consistency; and
- other checks whose truth depends only on current draft files.

It does not regenerate vectors, compare vector bytes, require current anchors
to match the older snapshot, or fail because snapshot metadata pins an earlier
commit.

### Vector-snapshot lane

This lane validates the latest snapshot against `source_commit`:

1. Parse the closed snapshot manifest and verify every exact artifact digest.
2. Require the source commit object to exist locally and to be an ancestor of
   the snapshot commit.
3. Derive the snapshot commit as the last commit that changed
   `docs/spec/vectors/snapshot.json`; require the working snapshot manifest
   bytes to equal that commit's manifest bytes; and materialize its snapshot
   packager and pinned lockfile separately from current HEAD.
4. Materialize the specification, registry, schemas, behavioral generator,
   and authoring inputs from the source commit into a temporary isolated
   checkout.
5. Install the source generator's pinned dependencies and generate its native
   corpus into a temporary raw-output directory.
6. Separately install the snapshot commit's pinned generator dependencies and
   run its behavior-neutral packager over the raw output. Neither tool resolves
   dependencies from current HEAD. The packager
   removes pre-1.0 draft-version metadata, converts references to the closed
   document-qualified syntax, builds snapshot projections, and MUST NOT alter
   `input`, `expected_output`, vector identity, direction, or profile behavior.
   The historical entry point is a nonrecursive package-and-compare command;
   it does not derive commits or invoke the outer snapshot checker.
7. Compare the packaged file set and exact bytes with the current snapshot.
8. While the source checkout exists, the snapshot-check orchestrator invokes
   the independent current conformance CLI with explicit source and snapshot
   roots. Specifications, the registry, and protocol schemas come from the
   source checkout; vectors, fixtures, the packaged vector-envelope schema,
   and snapshot projections come from the snapshot checkout. Neither package
   imports the other.
9. Verify that normal check commands leave the current working tree unchanged.

The lane never resolves snapshot `spec_refs` against current HEAD. A later
draft edit can rename or remove an anchor without invalidating an older
snapshot that correctly resolves it at the pinned source commit.

The shared CI entry point may run both lanes on every change for simplicity.
The snapshot lane remains stable during ordinary spec edits because its inputs
are pinned. Path-based skipping is optional optimization and is not required
for the initial implementation.

The orchestrator owns all temporary paths. It accepts only validated full
commit SHAs, creates directories with `mkdtemp`, rejects symlink, submodule,
special, absolute, and traversal tree entries before extraction, never removes
a caller-owned path, and cleans its temporary tree on success or failure.
Authoring stages a complete sibling snapshot tree and swaps it into place only
after validation, with rollback on failure.

## Reconciliation workflow

A source commit must already be stable and reachable in the target branch's
history. Reconciliation MUST NOT pin a transient pull-request commit that may
be rewritten, rebased, or removed by squash merging.

The normal workflow is:

1. Merge any intended specification, registry, schema, generator, or authoring
   changes without touching the snapshot.
2. Select a full source commit from the stable target-branch history.
3. Create a dedicated reconciliation change from a descendant of that commit.
4. Generate vectors using only inputs materialized from the source commit.
5. Replace the current snapshot files and projections in place.
6. Write `snapshot.json` with the source commit and exact artifact inventory.
7. Validate author-time bytes and idempotence without pretending that an
   uncommitted manifest already has a snapshot commit.
8. Commit the reconciliation, then run the history-bound snapshot lane,
   review measured conformance debt, and merge the reconciliation change.

If generator work is needed to express the new draft behavior, it lands before
the selected source commit. This makes the source commit sufficient to recover
all behavioral generation inputs and avoids a separate embedded generator pin.
Envelope-only migration remains the snapshot packager's responsibility and is
tested to preserve every behavioral field byte-for-byte at the parsed JSON
value boundary.

### Bootstrap snapshot for the current draft branch

The first rolling snapshot pins
`2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, an existing commit on
`spec/dedupe-and-delete-machinery`. That commit carries registry revision 11,
vector envelope schema 1.0.0, and 482 authored vector files. The bootstrap
reconciliation runs that commit's generator, then applies the new
behavior-neutral packager to produce the snapshot envelope and manifest.

This intentionally replaces the current branch's same-change 499-vector
corpus with a checkpoint for the already-stable target-branch idea. The newer
draft specification and checker work remain at current HEAD without claiming
that the snapshot covers them. After the infrastructure merges, a later
periodic reconciliation may select the merge commit or any newer stable target
commit and replace the rolling snapshot again.

The bootstrap source predates executable `conformance_checks` declarations, so
the first 482-vector snapshot executes zero declared reference-checker cases.
This is visible, not silent: validation and reports assert and display the
executed declaration count. Corpus-wide static gates still run. A later
reconciliation that selects a source carrying declarations ratchets the count
upward; the snapshot packager does not invent declarations absent from its
source behavior.

Old snapshots need not remain addressable through current paths or CI. They
remain inspectable in Git history, with no promise of continued tooling support
until 1.0.

## Failure behavior

The snapshot lane fails closed when:

- the manifest is malformed, non-canonical, unsafe, duplicated, or incomplete;
- the pinned commit is missing or is not an ancestor of the snapshot commit;
- source material cannot be read from the pinned commit;
- generator dependencies or commands differ from the pinned recipe;
- generated paths or bytes differ from the snapshot;
- a snapshot reference does not resolve in the pinned specification;
- artifact digests, vector counts, coverage, ratchets, or executable outcomes
  disagree; or
- a nominally read-only check changes tracked bytes.

The draft lane does not fail merely because current specification bytes differ
from the snapshot source. It reports the pinned source commit so reviewers can
see how stale the latest reconciliation is without treating age as failure.

CI checkouts must retain or fetch enough Git history to materialize the pinned
commit. A missing object produces an actionable fetch-depth error, not an
attempt to validate the snapshot against current HEAD.

## Testing strategy

Unit tests cover:

- closed snapshot-manifest shape, full-SHA syntax, path safety, ordering,
  duplicate paths, counts, and exact digests;
- rejection of missing, non-ancestor, or unavailable source commits;
- source-versus-snapshot root separation;
- snapshot-commit derivation before and after a simulated squash-shaped
  history;
- behavior-neutral normalization of a schema-1.0 source vector into the
  schema-2.0 snapshot envelope;
- exact agreement among every vector's envelope version, the packaged vector
  schema, and the manifest's `vector_schema_version`;
- spec-reference resolution at the pinned commit despite conflicting current
  HEAD anchors;
- byte regeneration from pinned generator inputs;
- extra, missing, or changed snapshot artifacts; and
- read-only behavior for both lanes.

Integration tests prove:

- an ordinary current-spec edit passes without a vector change;
- the same edit does not silently change the pinned snapshot's interpretation;
- a reconciliation from a stable source commit updates the rolling snapshot;
- current generator changes do not affect an older snapshot until selected in
  a later source commit;
- first-snapshot and replacement-snapshot authoring followed by history-bound
  checking, including a synthetic squash-shaped final tree; and
- GitHub and Radicle invoke the same two-lane entry point.

## Migration of the current draft PR

The independent conformance work in draft PR #24 remains useful, but its
current authority and release coupling must change before merge:

- revise contributor rules so ordinary pre-1.0 spec changes do not require
  vector regeneration;
- reclassify vectors from live normative artifacts to the latest non-normative
  validation snapshot;
- add the rolling snapshot manifest and pin it to a stable source commit;
- split conformance loading and CI into current-draft and pinned-snapshot lanes;
- stop using the combined pre-1.0 family release manifest as a same-commit
  coherence gate;
- resolve vector anchors and checker context against the pinned source tree;
  and
- amend ADR-045 and its changelog description before merge so the historical
  record describes the actual accepted lifecycle.

Because PR #24 is still draft and unmerged, amending that decision and
implementation is clearer than accepting the current coupling and adding a
second reversal ADR immediately afterward.

## Transition at 1.0

This design deliberately does not define the 1.0 release model. Before the
first protocol release, a new decision must specify:

- semantic protocol and artifact versions;
- immutable vector IDs and bytes;
- release-manifest composition and signing;
- compatibility and support windows;
- retention of historical vector sets; and
- whether external consumers or maintainers justify a separate vector
  repository.

Until that decision, there is one supported rolling snapshot and no claim that
draft revisions constitute released protocol versions.
