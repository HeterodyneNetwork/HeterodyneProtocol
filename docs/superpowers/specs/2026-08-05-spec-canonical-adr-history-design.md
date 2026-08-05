# Spec-Canonical ADR History Design

**Status:** Approved for implementation

## Goal

Make the independently versioned Heterodyne specification documents and their
normative artifacts the complete protocol authority. Preserve Architecture
Decision Records (ADRs) only as point-in-time historical rationale, and replace
the repository's duplicated agent guidance with one concise `AGENTS.md`.

## Authority model

The four versioned specification documents, their registries, schemas, release
manifests, and normative conformance vectors are the complete authority for the
current protocol. ADRs record why a change was made at a particular time. They
do not add, amend, activate, or override protocol requirements.

If an ADR and the merged specification disagree, the specification governs.
Current normative prose and automated conformance checks refer to requirements
through specification anchors, registry state, schemas, invariants, profiles,
and vectors rather than ADR numbers.

Historical material may retain ADR references as provenance. This includes
archived specifications, changelog entries, archived plans and designs, and the
archived ADRs themselves.

## ADR lifecycle

Material protocol changes use this workflow:

1. Create one or more proposed ADRs in `docs/adr/`.
2. Develop the corresponding specification changes in the same branch and
   patch or pull request.
3. Before acceptance, update every affected normative artifact, including
   specification prose, registries, schemas, release metadata, and conformance
   vectors.
4. Review the ADR and the complete specification patch together.
5. Once accepted, mark the ADR accepted and move it to `docs/adr/archive/` as
   part of finalizing the same patch.
6. Merge only when the specification stands on its own without requiring the
   ADR to interpret, activate, or complete the change.

An accepted ADR without its complete specification integration is not a
mergeable protocol change.

## Repository changes

- Move ADRs 001 through 038 to `docs/adr/archive/`.
- Record this governance decision as accepted ADR-039 and place it in the
  archive in the same patch.
- Add a short `docs/adr/README.md` explaining the staging directory,
  non-canonical status, archive location, and lifecycle.
- Delete the root `CLAUDE.md`.
- Replace the root `AGENTS.md` with one concise guide containing:
  - the canonical specification map and dependency direction;
  - the ADR-to-spec workflow and the rule that the specification always wins;
  - required registry, schema, release, and vector updates;
  - the protocol family's 0.x compatibility rule;
  - the read-only status of `research/sources/`;
  - the implementation-agnostic and vanilla-server constraints;
  - the two required verification commands.
- Update general repository navigation so `docs/adr/` is described as
  non-canonical decision history.

Only the root tracked `AGENTS.md` remains. Files inside separate local Git
worktrees are not part of this branch and are not modified.

## Self-contained live protocol

Remove ADR-number dependencies from:

- `docs/spec/heterodyne-core.md`
- `docs/spec/heterodyne-comms.md`
- `docs/spec/heterodyne-control.md`
- `docs/spec/heterodyne-social.md`
- current vector documentation and generated coverage prose;
- current conformance tests and documentation linting;
- the live threat model and other current companion documentation where an ADR
  is used as requirement authority.

Replace those dependencies with direct normative language and references to
current specification anchors, registry revisions or digests, schemas,
profiles, invariants, and vector IDs. Remove obsolete split-provenance comments
from live normative documents.

Historical references remain untouched in:

- `CHANGELOG.md`;
- `docs/spec/archive/`;
- archived ADRs;
- archived or completed plans and designs;
- other material whose purpose is explicitly historical.

## Enforcement and verification

Add documentation lint coverage that rejects `ADR-*` and `docs/adr/`
references in the four live normative documents. Rewrite tests that currently
read ADR files or require ADR-numbered wording so they validate the integrated
specification and its normative artifacts directly.

This governance refactor does not alter wire behavior, so it requires no new
kind allocations, schemas, or behavioral vectors.

Verification must include:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

The final review also confirms:

- internal links resolve after the ADR moves;
- no tracked `CLAUDE.md` remains;
- exactly one tracked `AGENTS.md` remains;
- the four live normative documents contain no ADR references;
- existing untracked `docs/reviews/` content remains untouched.
