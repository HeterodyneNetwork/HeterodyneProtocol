# ADR-004: Security claims hygiene — differentiated remediation for deniability, ±5 min scope, and nip01_raw rationale

**Date:** 2026-05-21
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gemini-3.1-pro, gpt-5.4 (via Fuel-IX); local Claude subagent

## Context

External critique flagged three security-claim hygiene problems that share a common shape — the wire-level mechanism is sound, but the surrounding security claims are imprecise:

1. **Deniability overclaim (critique item 12).** Lines 1203–1207 and 1371–1372 claim `private_deniable` rooms offer "strong cryptographic deniability" with "no participant can prove to a non-participant who said what." This overstates what Megolm (and even MLS) actually provide: Megolm session keys are shared across room members, so any member who exports the session key and the ciphertext can decrypt and attribute messages to specific senders. The claim "no participant can prove" is false against colluding members.

2. **±5 min clock-skew rule misread by critique (item 4).** §3.2.1 lines 425–432 require the root attestation `created_at` to be within ±5 minutes of the verifier's wall clock. Verification confirmed the critique misreads this — the rule applies only to the `m.heterodyne.root.v1` attestation event, and re-publication with a current `created_at` is the documented mechanism for older identities. However, lines 2627–2628 in §13 reference "the strict ±5 minute clock-skew enforcement" without clarifying scope, which invited the misreading.

3. **`nip01_raw` rationale technically wrong (critique item 5).** §3.0.1.1 lines 252–254 justify the `nip01_raw` field by claiming JSON parsers may "reorder arrays." JSON arrays are ordered per RFC 8259 §5 — a conforming parser cannot reorder them. The actual threats (object key reordering, numeric serialization differences, whitespace normalization) are well-founded but mis-described.

The user chose to handle these with **differentiated remediation** — match remedy to severity — rather than bundle into a single editorial sweep or undertake a full threat-model rewrite.

## Decision

Three separate fixes, each scoped to the actual problem class:

1. **Deniability:** real prose revision in §5.5 and §13 to accurately describe what Megolm/MLS provide. Add a security-model note about the member-collusion attacker.
2. **±5 min rule:** scoped NOTE block in §3.2.1 making the root-attestation scope explicit; forward reference from §13 to the §3.2.1 NOTE.
3. **`nip01_raw` rationale:** one-line correction at §3.0.1.1 replacing the incorrect array-reorder justification with the accurate object-key-reorder / numeric / whitespace concern. The MUST requirement itself stays.

Invariant I1's rewrite (which the original synthesis grouped here) is owned by ADR-001 instead — it's downstream of the client-side MSC reframe, not a wording fix.

## Requirements (RFC 2119)

### Deniability

1. The spec MUST replace the phrase "Strong cryptographic deniability via the underlying Megolm/MLS ratchet — no participant can prove to a non-participant who said what" (lines 1203–1207) with: "No per-message Nostr signature is produced for bare events; messages are not transferable cryptographic authorship proofs. Megolm/MLS session keys are shared among room members, so any member who possesses (or shares) the session key and the message ciphertext can decrypt and attribute messages. Deniability holds against non-members; it does NOT hold against colluding members."
2. The spec MUST replace the phrase "inherits Megolm/MLS-grade deniability — no participant can cryptographically prove to a non-participant who sent what message" (§5.5 lines 1371–1372) with the same accurate framing.
3. §13 SHOULD gain a brief "Attacker capabilities" subsection enumerating: external observer (cannot decrypt), member with session key (can decrypt and attribute), colluding members (can exchange session keys).
4. The room taxonomy table in `CLAUDE.md` MUST be updated in parallel to reflect the corrected deniability framing.

### ±5 min clock-skew scope

5. §3.2.1 MUST add a NOTE block (immediately after line 432) stating: "This ±5 minute rule applies ONLY to `m.heterodyne.root.v1` root attestation events. Other Heterodyne events are not subject to wall-clock freshness enforcement (each has its own freshness mechanism, e.g., KERI sequence numbers per ADR-003). Verifiers MUST NOT apply this rule to other event kinds."
6. §13 lines 2627–2628 (and any other §13 reference to ±5 min) MUST replace generic references with an explicit forward reference: "(see §3.2.1 NOTE for scope)".

### `nip01_raw` rationale

7. §3.0.1.1 lines 252–254 MUST replace "reordering JSON arrays or normalizing whitespace" with: "re-serializing the parsed event object (which may reorder object keys per RFC 8259, normalize numeric representations, or alter whitespace), any of which would invalidate the NIP-01 signature".
8. The MUST requirement for `nip01_raw` itself (lines 254–287 and §3.5.2 lines 939–950) remains unchanged.
9. The spec SHOULD add test vectors demonstrating the failure modes the `nip01_raw` field protects against (object-key-reorder mismatch, numeric-format mismatch).

## Rationale

Bundling all three into one sweep (rejected alternative A) would treat them uniformly when they are not. Deniability is a user-facing security claim with real implications for how users decide to use the protocol; ±5 min is a documentation clarity issue; `nip01_raw` rationale is a one-line factual correction. The differentiated approach matches remedy to severity.

A full threat-model rewrite (rejected alternative B) would inflate v0.2.x scope. The threat model evolution belongs in a future ADR informed by first-party-client experience.

A "Security Claims" appendix (rejected alternative D) is a worthwhile organizational improvement but premature; the security claims aren't numerous enough yet to warrant their own appendix, and pulling them out of §13 risks fragmenting threat-model discussion.

## Alternatives Considered

### (A) Single "security-claims hygiene" editorial sweep
- **Pros:** Cheapest; closes all three in one commit.
- **Cons:** Doesn't differentiate severity; user-visible deniability fix gets buried with documentation-only corrections.
- **Why rejected:** Differentiation is the point.

### (B) Full threat-model rewrite
- **Pros:** Thorough; enumerates attacker capabilities precisely.
- **Cons:** Inflates v0.2.x scope; threat-model rewrite is its own substantial design work.
- **Why rejected:** Premature; better as a future ADR informed by first-party-client implementation.

### (D) Add a Security Claims appendix
- **Pros:** Single auditable surface for security claims.
- **Cons:** Premature given current claim count; risks fragmenting §13.
- **Why rejected:** Worthwhile in v0.3+ once the claims grow; not justified now.

## Assumed Versions (SHOULD)

- Matrix Megolm: ratchet specification stable.
- MLS: RFC 9420 (May 2023).
- NIP-44 v2: stable.
- RFC 8259 (JSON): stable.

## Diagram

<!-- brains:diagram populates this section (likely skip — this ADR is largely prose). -->

## Consequences

- §5.4 lines 1203–1207 (room taxonomy `private_deniable` entry): deniability claim revised.
- §5.5 lines 1371–1372 (`private_deniable` body): same revision.
- §13 gains brief Attacker capabilities subsection.
- §3.2.1 after line 432: scoped NOTE block added.
- §13 lines 2627–2628: forward reference added.
- §3.0.1.1 lines 252–254: rationale corrected (one-line fix).
- `CLAUDE.md` room taxonomy table updated to match the new deniability framing.
- New test vectors required: `nip01_raw` mismatch cases (object key reorder, numeric format).
- Threat-model expansion deferred to future ADR.

## Council Input

Both rounds of review supported the differentiated approach. Round 1 flagged that bundling user-facing claims with documentation fixes obscures the real fix. Round 2 explicitly recommended moving invariant I1 into ADR-001 (since I1's rewrite is downstream of the client-side MSC reframe, not a claim-hygiene wording change) — this ADR no longer covers I1.
