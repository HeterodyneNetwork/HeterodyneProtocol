# ADR-039: Specification authority and historical ADR lifecycle

**Status:** Accepted  
**Date:** 2026-08-05

## Context

Heterodyne's decision records accumulated enough integrated protocol detail
that current specifications and conformance checks sometimes referred back to
an ADR for interpretation or activation. That made historical rationale look
like a second source of protocol authority and duplicated repository guidance
between `AGENTS.md` and `CLAUDE.md`.

## Decision

The independently versioned specification family and its normative registry,
schemas, release metadata, and conformance vectors are the complete current
protocol authority. ADRs are non-canonical point-in-time records. They cannot
add, amend, activate, or override a protocol requirement; the specification
governs whenever it differs from an ADR.

A material protocol change begins with one or more proposed ADRs. The same
branch and patch or pull request must integrate every accepted decision into
all affected normative artifacts. Before merge, each accepted ADR moves to
`docs/adr/archive/`. The patch is mergeable only when the specification stands
on its own without the ADR.

ADRs 001 through 038 are archived. Live normative documents and conformance
checks replace ADR references with direct specification requirements and
artifact gates. Repository guidance is consolidated into one concise root
`AGENTS.md`; `CLAUDE.md` is removed.

## Consequences

- Historical rationale remains available without competing with the
  specification.
- Reviewers evaluate decision rationale and complete specification integration
  in one change.
- Conformance tooling can detect attempts to reintroduce ADR dependencies into
  live specifications.
- Historical changelogs, archived specifications, completed plans, research,
  and archived decision records may retain ADR references as provenance.
