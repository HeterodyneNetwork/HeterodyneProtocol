# ADR-008: Editorial contradictions — §3.3 valid_until and §10.2 DM-backfill reference

**Date:** 2026-05-23
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gpt-5 (via Fuel-IX, two-instance parallel review); local Claude subagent

## Context

A post-ADR-007 spec audit (research document at `docs/research/2026-05-22-spec-gaps-research.md`) surfaced two pure-textual contradictions in the v0.2.0 spec that ADR-001 through ADR-007 did not catch:

1. **§3.3 active-delegation rule 4 (lines 553–556)** anchors the delegation `valid_until` check to "the strict ±5 minute clock-skew bound of §3.2.1." ADR-004's NOTE block in §3.2.1 states explicitly: "This ±5 minute rule applies ONLY to `m.heterodyne.root.v1` root attestation events … Verifiers MUST NOT apply the ±5 minute rule to other event kinds." These two normative statements are in direct conflict. Two independent implementations resolve the contradiction in opposite ways: one treats the ±5 min as a clock-skew tolerance on delegation expiry (`valid_until > now − 5m`); the other treats it as inapplicable to delegations per the NOTE. A delegation expiring at T+10 minutes, verified at T+9 minutes, becomes silently interop-incompatible.

2. **§10.2 client-capability bullet 3 (lines 3147–3149)** lists "optional DM-based retrieval request/response/push" as a required client capability. §6.9 (lines 2199–2200) and §6.9.3 (line 2293) explicitly remove and forbid that mechanism: "Automated Matrix-DM-based backfill requests are explicitly forbidden." The §10.2 reference is both stale and normatively contradictory.

Both findings were spot-checked against the current spec text and confirmed verbatim.

## Decision

Replace the contradictory clauses with corrected text. Both fixes are pure editorial; no architectural choice is involved. The §3.3 fix preserves a separate local clock-skew tolerance for delegations (RECOMMENDED 5 minutes) that is operationally distinct from the §3.2.1 freshness rule for root attestations.

## Requirements (RFC 2119)

### §3.3 valid_until fix

1. The clause "within the strict ±5 minute clock-skew bound of §3.2.1" MUST be removed from §3.3 active-delegation rule 4 (current lines 553–556).
2. The replacement text for rule 4 MUST read: "`nostr_attestation.tags` includes a `["valid_until", "<unix-seconds>"]` tag that is either empty (no expiry) or strictly greater than the verifier's current wall-clock time. Verifiers MAY apply a small local clock-skew tolerance (RECOMMENDED: 5 minutes) as a clock-drift accommodation. This tolerance is operationally distinct from the §3.2.1 ±5-minute freshness rule, which applies only to `m.heterodyne.root.v1` root attestation events per ADR-004."
3. The corrected rule 4 MUST NOT cross-reference §3.2.1 except to disambiguate scope.

### §10.2 DM-backfill fix

4. §10.2 bullet 3 (current lines 3147–3149) MUST be replaced with: "Event retrieval via two channels (§6.9): NIP-01 REQ to Nostr relays (with complete-fetch-attempt semantics per §6.9.1, see ADR-006) and HTTPS GET against user-hosted archive URLs (§6.9.2). DM-based retrieval is explicitly forbidden (§6.9.3)."
5. No other §10.2 bullet requires modification.

## Rationale

The §3.3 conflict is the kind of bug that surfaces only at interop test time. Removing the cross-reference and explicitly distinguishing "freshness rule" from "clock-skew tolerance" resolves it without weakening the security model: the freshness rule (±5 min on root attestations) prevents replay; the local clock-skew tolerance on delegations is a UX-grade leniency that doesn't affect security boundaries.

The §10.2 reference was left over from a pre-v0.2.0 capability list. The DM-backfill protocol was deliberately removed (preamble line 28–30, §6.9, §6.9.3); the §10.2 bullet was missed during that pass.

Both fixes are textual; bundling into one ADR keeps the editorial batch under one revision rather than scattering it across two trivial ADRs.

## Alternatives Considered

### (A) Two separate one-paragraph ADRs
- **Pros:** Each fix is independently citable.
- **Cons:** No architectural decision in either; the ADR overhead exceeds the change size.
- **Why rejected:** Bundling is cleaner.

### (B) Fold into a future "v0.2.0 editorial sweep" ADR
- **Pros:** Batches multiple small fixes.
- **Cons:** Indefinite timeline; these are interop-affecting bugs that should land now.
- **Why rejected:** The contradictions are load-bearing for two-implementation interop.

### (C) Re-interpret §3.3 to honor the ±5 min as a delegation tolerance
- **Pros:** No spec edit needed.
- **Cons:** Contradicts ADR-004's explicit scope. Two MUSTs in tension are not resolved by re-interpretation.
- **Why rejected:** ADR-004 is the more recent and more carefully reasoned anchor.

## Assumed Versions (SHOULD)

- No external dependencies relevant to this ADR.
- Affects only Heterodyne spec text.

## Consequences

- §3.3 rule 4 rewritten per req 2. ADR-004's NOTE block in §3.2.1 remains unchanged.
- §10.2 bullet 3 rewritten per req 4.
- No new test vectors required (textual fix; existing identity and retrieval vectors continue to apply).
- ADR-004's `±5 minute scope` claim becomes self-consistent across the spec.
- ADR-006's "complete-fetch-attempt" reference in §10.2 strengthens the cross-link from the bridge-model section to the retrieval semantics ADR.

## Council Input

Star-chamber's parallel-mode review confirmed both fixes as pure editorial with no architectural risk. No counter-arguments raised.
