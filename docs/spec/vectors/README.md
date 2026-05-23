# Test vectors

This directory contains conformance test vectors for the Heterodyne
specification. Each vector is a JSON file demonstrating a specific
behavior the spec requires. Implementations MUST produce byte-identical
output for every `produce` vector and MUST accept (and correctly
validate) every `consume` vector.

Vectors are normative: failing a vector means a Heterodyne client is
non-conformant for the corresponding spec section.

## Format

```
vectors/
  <topic>/
    <NN>-<short-description>.json
```

Each JSON file has the following shape:

```json
{
  "vector_id": "<topic>/<NN>",
  "spec_section": "<section number, e.g. '4.2'>",
  "description": "<one-line plain-English summary>",
  "direction": "produce | consume | round-trip",
  "input": {
    "...": "what the implementation is fed"
  },
  "expected_output": {
    "...": "what the implementation must emit, OR the verdict for consume"
  },
  "notes": "<optional clarifications, deferred questions, edge cases>"
}
```

- `produce` vectors: given `input` (e.g. user content + identity
  material), the implementation MUST emit `expected_output` (the wire
  bytes). Compared after canonical JSON serialization.
- `consume` vectors: given `input` (the wire bytes), the implementation
  MUST emit `expected_output` (typically `{ "verdict": "accept" }` or
  `{ "verdict": "reject", "reason": "..." }` plus a normalized view of
  the event).
- `round-trip` vectors: an event survives a wrap → unwrap →
  re-publication cycle byte-identically.

## Planned vector topics

| Topic | Coverage | Status |
|---|---|---|
| `identity/` | root attestation; delegation (active, expired, revoked); revocation post-window; identity room with full state | not yet authored |
| `keri/` (per ADR-003) | inception; rotation (committed strategy); rotation (none strategy with witness threshold); first-seen ordering verifier; fork-resolution with conflicting rotations | not yet authored |
| `envelope/` | wrapped event; bare event; wrap-mode default per room kind | not yet authored |
| `verification/` | signature failures; delegation-mismatch rejection; revoked-key rejection; backdated-event handling | not yet authored |
| `bridge/` (per ADR-010) | asymmetric Matrix/Nostr delivery: Nostr permanent failure (index NOT updated); Matrix permanent failure (index updated; Matrix-out-of-sync warning); idempotent re-publication via Nostr event id reuse | not yet authored |
| `index/` (per ADR-005, ADR-006) | room-key wrap derivation (HKDF from Megolm session); room-key wrap encryption (NIP-44 v2); `prev_page_hash` page-chain integrity; complete-fetch-attempt across relay set | not yet authored |
| `outbox/` | outbox state event; multi-category fan-out; encrypted private outbox entries | not yet authored |
| `multi-homing/` (per ADR-009) | active-room election with lex-min `election_id` tiebreaker; publish-lease acquisition and renewal; single-MXID revocation procedure; `kind:31005` race tiebreaker with KERI witness counts; partition-window void-and-requeue | not yet authored |
| `moderation/` | NIP-72 approval flow; multi-mod requirement; moderator rotation; contributor submission with community-address tag and implicit-rejection window (per ADR-014) | not yet authored |
| `moderation/strict-mode/` (per ADR-007) | Strict-mode only. Bare-event filtering; `kind:5` deletion observed within 30s; state-downgrade warning rendering | not yet authored |
| `encryption/` | encryption_version event; delegation-revocation triggering rotation (SHOULD path) | not yet authored |
| `encryption/mls-migration/` (per ADR-012) | SKIPPABLE with rationale. Eligibility check; intent and ACK; abort on missing ACKs; receiver-verifiable flip; 60s tail period; offline-reconnect re-encryption; non-MLS receiver fallback | not yet authored |
| `relay-interop/` (per ADR-013) | NIP-42 AUTH challenge and response signed by current epoch key (not cold root); AUTH rejection classified as permanent per ADR-010; KERI rotation produces AUTH events under new epoch key | not yet authored |
| `homeserver-exit/` (per ADR-015) | Skippable for read-only clients. Identity-room migration; migration-pointer precedence over stale `kind:31005`; KERI rotation during exit window dual-publishes | not yet authored |
| `interop/` | wrapped event round-tripped through a vanilla Nostr relay; bare DM rendered by vanilla Matrix client | not yet authored |
| `versioning/` | older receiver vs newer sender; capabilities event roundtrip; unknown room-kind tolerance per ADR-016 | not yet authored |
| `config_room/` | minimal config room; persona_config with private mutes; key_backup with various wrapping algorithms | not yet authored |

Vectors will be added as each spec section graduates from stub to drafted
state. Any client implementation claiming conformance MUST run every
vector in the baseline minimum set (see §14.3 / ADR-011) through its CI
pipeline.

## Conformance levels

Per ADR-011:

- **Baseline conformance** requires passing every vector in the
  mandatory categories listed in §14.3 (`identity/`, `keri/`,
  `envelope/`, `verification/`, `bridge/`, `index/`, `outbox/`,
  `multi-homing/`, `relay-interop/`, `moderation/` (excluding the
  `strict-mode/` subdirectory), `encryption/` (excluding the
  `mls-migration/` subdirectory), `interop/`, `versioning/`,
  `config_room/`).
- **Strict-mode conformance** additionally requires every vector in
  `moderation/strict-mode/` (per ADR-007).
- **OPTIONAL skippable categories** are `encryption/mls-migration/`
  (clients without MLS support) and `homeserver-exit/` (read-only
  clients that never publish).

Implementations that skip mandatory vectors MUST NOT claim baseline
conformance; they MAY claim partial or experimental conformance with a
documented gap list.

## Vector format note

The "successor chain" planned category from earlier drafts has been
removed: the v0.1.4 single-key successor-chain mechanism was deprecated
in v0.2.0 (§3.5.4) and replaced by inline KERI per ADR-003. The KERI
categories above (`keri/`) cover the replacement protocol.
