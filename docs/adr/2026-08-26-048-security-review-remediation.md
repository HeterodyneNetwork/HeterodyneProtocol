# ADR-048: Security review remediation for heterodyne/0.6.0

**Status:** Proposed
**Date:** 2026-08-26

This record is non-canonical. The live specification family, protocol schemas,
and registry contain the complete protocol. If this record and those artifacts
disagree, the specification family and normative artifacts govern.

## Decision

An external model review of the 0.5.0 family identified seven structural
findings. Their substantive disposition is deferred to the approved
[`2026-08-27 closure design`](../superpowers/specs/2026-08-27-heterodyne-0.6-pr28-closure-design.md)
and its implementation plan. This Proposed ADR records only the release
lifecycle: no substantive remediation is accepted until the complete closure
is integrated and passes the acceptance gate below.

The approved closure design preserves **optional Workspace Assurance**: a
Workspace with a bare active Nostr persona key is baseline-conformant, and an
Assurance profile is an optional hardening policy rather than a prerequisite.
It also treats **NIP-03 advisory** material as non-authoritative. In
particular, no OpenTimestamps observation establishes permanent event
refutation or resolves an enrollment contest.

## Proposed risk disposition

- `compromise_time` selection remains a recovery-holder power subject to the
  closure design's final specification and conformance review.
- NIP-03 material remains advisory and does not grant protocol authority.
- Carrier withholding for pure-relay readers is inherited from the Nostr
  carrier model and disclosed as a proposed risk.
- Tier 2 and Tier 3 have no forward secrecy; users needing it use the
  Marmot/MLS path.
- A key thief can deny Assurance enrollment (bounded harm; baseline
  impersonation was already possible with the key).
- SHA-1 remains in the Radicle substrate; it is constrained, not replaced.

## Acceptance gate

ADR-048 remains Proposed until Task 10's exact pre-acceptance matrix succeeds
serially, with every command exiting 0:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
test -z "$(git status --porcelain=v1)"
```

That matrix requires every family dependency, normative artifact, semantic
evaluator, and conformance vector to agree at 0.6.0. Acceptance and archival
also require Task 10's independent specification and security reviews to find
no unresolved Critical or Important findings.
