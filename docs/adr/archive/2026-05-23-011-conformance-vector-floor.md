# ADR-011: §14 conformance vector floor and minimum passing set

**Date:** 2026-05-23
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gpt-5 (via Fuel-IX, two-instance parallel review); local Claude subagent

## Context

§14.3 of the spec lists nine planned test-vector topic directories and states (line 4192): "Any client implementation claiming conformance to this spec version MUST pass every vector in `vectors/`." The directory `docs/spec/vectors/` contains only `README.md` — zero vectors have been authored. The conformance claim is currently vacuous: an implementation claiming conformance is unfalsifiable because there are no vectors to fail.

Three derived problems:

1. **No minimum subset.** §14.4 allows implementations to skip vectors with documented rationale, but there is no normative floor. An implementation that skips every vector and documents "MLS not yet supported" for each would technically satisfy §14.4.
2. **Stale README content.** `vectors/README.md` (authored pre-v0.2.0) still lists "successor chain" as a planned vector category, referring to the v0.1.4 single-key successor-chain mechanism that was deprecated and removed in v0.2.0 (§3.5.4) and replaced by inline KERI (ADR-003).
3. **No baseline-vs-strict-mode split.** ADR-007 introduced the strict-mode profile (§11.7) with additional MUST behaviors; it is unclear whether strict-mode conformance requires a separate vector set or extends the baseline set.

ADRs 008–010 and 012–016 each list "test vectors required" in their consequences sections but no ADR has defined the minimum set or updated the README. The first-party-client milestone (per CLAUDE.md) depends on test vectors for end-to-end validation; without a vector floor, the validation gate is undefined.

## Decision

Define a normative minimum vector set for baseline conformance, a strict-mode delta, and an explicit anti-skip floor. Update `vectors/README.md` to remove the deprecated "successor chain" category and add the categories required by ADRs 003, 005, 006, 007, 009, 010, 012, 013. Vector authoring itself remains out of scope for this ADR; what counts as the floor is what's specified here.

## Requirements (RFC 2119)

### §14.3 normative minimum set

1. The §14.3 coverage map MUST be amended to define the **baseline conformance minimum vector set**. An implementation claiming baseline Heterodyne v0.2 conformance MUST pass every vector in the following directories:
   - `identity/` — all subdirectories.
   - `envelope/` — all subdirectories.
   - `keri/inception`, `keri/rotation`, `keri/fork-resolution-first-seen` (per ADR-003).
   - `index/page-integrity/prev-page-hash`, `index/complete-fetch-attempt` (per ADR-006).
   - `index/room-key-wrap/derivation`, `index/room-key-wrap/encryption` (per ADR-005).
   - `bridge/asymmetric-delivery/nostr-permanent-failure`, `bridge/asymmetric-delivery/matrix-permanent-failure`, `bridge/asymmetric-delivery/idempotent-republish` (per ADR-010).
   - `multi-homing/active-room-election`, `multi-homing/publish-lease`, `multi-homing/single-mxid-revocation`, `multi-homing/kind31005-tiebreaker`, `multi-homing/partition-window-void-requeue` (per ADR-009).
   - `relay-interop/nip43-auth-challenge` (per ADR-013).
2. Implementations MAY skip `encryption/mls-migration/*` vectors (per ADR-012) with documented rationale. MLS support is OPTIONAL in v0.2 per ADR-012 req 9 (receiver-fallback for non-MLS clients).
3. Implementations MAY skip `homeserver-exit/*` vectors (per ADR-015) for read-only clients that never publish; publishing clients MUST pass them.

### Strict-mode delta (per ADR-007)

4. Strict-mode conformance per ADR-007 / §11.7 additionally requires:
   - All `moderation/strict-mode/*` vectors (per ADR-007 reqs 3–6, including `moderation/strict-mode/bare-event-filter` and `moderation/strict-mode/kind5-deletion-30s`).
   - The state-downgrade UX behaviors from ADR-007 reqs 7–8 (rendered as `moderation/strict-mode/state-downgrade-warning` vectors).
5. An implementation MAY claim baseline conformance without strict-mode conformance, but MAY NOT claim strict-mode conformance without first passing all baseline-minimum vectors.

### Anti-skip floor

6. §14.4 MUST be amended: "Implementations that skip mandatory vectors per §14.3 MUST NOT claim baseline conformance. They MAY claim partial or experimental conformance with a documented gap list naming each skipped vector category."
7. The phrase "every vector in `vectors/`" in current §14.3 line 4192 MUST be replaced with "every vector in the baseline minimum set defined in this section."

### README update

8. `docs/spec/vectors/README.md` MUST be updated:
   - Remove the "successor chain" planned category (deprecated per ADR-003).
   - Add the directories enumerated in req 1, with one-line descriptions for each.
   - Add a "Skippable for read-only clients" annotation for `homeserver-exit/*`.
   - Add a "Skippable with rationale" annotation for `encryption/mls-migration/*`.
   - Add a "Strict-mode only (per ADR-007)" annotation for `moderation/strict-mode/*`.

### Vector authoring scope

9. This ADR does NOT author the vector files themselves. Vector authoring is tracked as follow-up work; each ADR (003, 005, 006, 007, 009, 010, 012, 013) is responsible for producing its declared vectors as separate commits.
10. Vector format (input/expected-output schema) MUST follow the existing convention documented in `vectors/README.md`. This ADR does not modify the vector file format.

## Rationale

A normative minimum set converts the conformance claim from aspirational to falsifiable. The baseline set deliberately excludes MLS migration vectors (per ADR-012's deferred-support stance) and homeserver-exit vectors (because read-only clients legitimately don't need them) while making everything else mandatory.

Splitting strict-mode conformance from baseline conformance matches ADR-007's stance: strict-mode is OPTIONAL but, when claimed, requires the additional moderation behaviors. Stacking strict-mode on top of baseline (req 5) prevents an implementation from claiming strict-mode while skipping foundational vectors.

The anti-skip floor (req 6) prevents the "skip every vector with rationale" loophole in current §14.4. Implementations that skip mandatory categories can still claim something — "partial conformance" — but cannot claim baseline conformance.

Keeping vector authoring out of scope (req 9) is a deliberate work-organization choice: this ADR specifies WHAT counts; the vectors themselves are mechanical work tracked separately. Bundling vector authoring into this ADR would make it months-long.

## Alternatives Considered

### (A) Single all-mandatory vector floor
- **Pros:** Simplest rule.
- **Cons:** Forces every implementation to support MLS migration (per ADR-012) and homeserver-exit (per ADR-015) even when those are explicitly OPTIONAL or read-only-not-applicable.
- **Why rejected:** Doesn't respect the OPTIONAL stance of other ADRs.

### (B) Implementer-declared profiles (each implementation picks its own floor)
- **Pros:** Maximum flexibility.
- **Cons:** Conformance becomes uncomparable across implementations; "I'm conformant for my profile" tells a peer nothing about interop.
- **Why rejected:** Defeats the purpose of conformance.

### (C) Defer minimum-set definition to first-party-client experience
- **Pros:** Lets implementation-derived needs guide the floor.
- **Cons:** First-party client validation needs the floor to know what it's validating against; chicken-and-egg.
- **Why rejected:** The floor needs to land before validation begins.

### (D) Bundle vector authoring into this ADR
- **Pros:** Conformance becomes immediately operational.
- **Cons:** Vector authoring is a months-long mechanical job; ADR scope balloons; the floor decision and the vectors are separable.
- **Why rejected:** Separation of concerns. Authoring is follow-up work.

## Assumed Versions (SHOULD)

- Vector file format per existing `vectors/README.md` (no change).
- No external dependencies relevant to this ADR.

## Consequences

- §14.3 amended: minimum baseline set defined; strict-mode delta defined.
- §14.4 amended: anti-skip floor added.
- `docs/spec/vectors/README.md` updated per req 8.
- Each upstream ADR (003, 005, 006, 007, 009, 010, 012, 013) now has an explicit list of vector files to author.
- First-party-client validation gate becomes well-defined: pass the baseline minimum set.
- Two independent implementations can now meaningfully verify interoperability by running vectors against each other's outputs.
- Strict-mode adoption becomes a separately-claimable conformance level.
- This ADR does NOT block on vector authoring; the floor lands now, vectors land incrementally.

## Council Input

Star-chamber's review highlighted that several requirements across ADRs 008–016 use "SHOULD surface to user" or "RECOMMENDED" predicates that are hard to test via vectors. This ADR's approach: UX-only requirements are tested via UI-behavior vectors only at the strict-mode level (per ADR-007's existing strict-mode pattern). Baseline UX requirements like ADR-010's "destination-level granularity" remain SHOULD (testable via inspection of the partial-failure object shape, not by literal UI screenshots).

The review also flagged that authoring vectors is the load-bearing work; defining the floor without authoring is "necessary but not sufficient." This ADR explicitly acknowledges that limitation (req 9) and leaves authoring as tracked follow-up work.
