# Test vectors

This directory contains conformance test vectors for the Heterodyne
specification. Each vector is a JSON file demonstrating a specific behavior the
spec requires. When a vector exists for a behavior, implementations claiming
vector-conformance for that category MUST produce byte-identical output for
every `produce` vector and MUST accept (and correctly validate) every
`consume` vector.

Vectors are normative for the behavior they cover: failing an authored vector
means a Heterodyne client is non-conformant for the corresponding vector
category. The current files are a coverage-map suite: every §14.3 topic has
authored vectors for the behaviors listed in the spec, with room for future
edge-case expansion as the 0.x draft stabilizes.

## Format

```
vectors/
  <topic>/
    <NN>-<short-description>.json
```

Each JSON file validates against
[`schema/vector.schema.json`](schema/vector.schema.json) and has the following
shape:

```json
{
  "vector_id": "<topic>/<stable-id>",
  "vector_schema_version": "1.0.0",
  "spec_version": "0.3.0",
  "spec_refs": ["§4.2", "§14.5"],
  "description": "<one-line plain-English summary>",
  "direction": "produce | consume | round-trip",
  "input": {
    "...": "what the implementation is fed"
  },
  "expected_output": {
    "...": "what the implementation must emit, OR the verdict for consume"
  },
  "simulated_clock": 1767225600,
  "decision_trace": ["optional ordered checks"],
  "transport_context": {
    "...": "optional Matrix-to-protocol adapter context"
  },
  "notes": "<optional clarifications, deferred questions, edge cases>"
}
```

- `produce` vectors: given `input` (e.g. user content + identity material),
  the implementation MUST emit `expected_output.canonical_wire`
  byte-identically. Signed events also include the decoded object, `id`, and
  `sig`.
- `consume` vectors: given `input` (the protocol input), the implementation
  MUST emit `expected_output` with `{ "verdict": "accept" }` or
  `{ "verdict": "reject", "reason_code": "..." }` plus a normalized view of the
  event where applicable.
- `round-trip` vectors: an event survives a wrap → unwrap → re-publication
  cycle byte-identically over the declared `comparison_surface`.

## Determinism policy

Vectors pin every value that could otherwise vary between runs:

- BIP-340 signatures use `aux_rand = 0x00 * 32`.
- NIP-44 v2 vectors carry a fixed 32-byte nonce in `input`.
- Time-sensitive vectors carry `simulated_clock`; runners MUST NOT use
  wall-clock time to decide their verdict.
- `created_at` values are fixed offsets from the shared `test_epoch` in
  [`fixtures.json`](fixtures.json).
- `produce` and `round-trip` comparison is against canonical bytes, never
  pretty-printed JSON or relay WebSocket framing.

Megolm ciphertext is intentionally out of scope. Encrypted vectors test the
decrypted Matrix payload plus the room-secret → HKDF → NIP-44 chain.

## Consume contract

`consume` rejects use the closed `reason_code` vocabulary in
[`schema/reason-codes.md`](schema/reason-codes.md). These codes are diagnostic
test vocabulary only; implementations do not need to emit them on the wire.

When an accepted vector includes `expected_output.normalized`, the normalized
object contains only protocol-visible facts: event ids, pubkeys, room ids, room
kind, index-update effect, warnings, or other values a conforming
implementation can observe at the protocol boundary. It MUST NOT encode an
implementation's private data structures.

For inputs that could fail multiple checks, the expected `reason_code` follows
the §4.5 evaluation order, with cheap structural/signature checks before
delegation, revocation, policy, and UI-profile checks.

## Matrix adapter boundary

Transport vectors target the boundary after the Matrix SDK has performed its
normal work. A runner feeds the Heterodyne protocol layer:

- Matrix event type.
- Matrix room id.
- Sender MXID.
- Matrix event id and `origin_server_ts` when the spec uses them.
- Decrypted cleartext payload for encrypted rooms.
- Transport failure classification inputs from §6.4.1.

Vectors do not validate Matrix federation auth, Megolm session rotation,
device trust, withheld keys, redaction semantics, or Matrix event
authorization.

## Planned vector topics

| Topic | Coverage | Status |
|---|---|---|
| `identity/` | root attestation; delegation (active, expired, revoked); revocation post-window; identity room with full state | coverage authored |
| `keri/` (per ADR-003, ADR-021, ADR-022) | inception; rotation (committed strategy); rotation (none strategy with witness threshold); first-seen ordering verifier; fork-resolution with conflicting rotations; `did:key` witness verification; `kind:31008` informal vouch not counted toward threshold | coverage authored |
| `envelope/` | wrapped event; bare event with `heterodyne_persona`; wrap-mode default per room kind | coverage authored |
| `verification/` | signature failures; delegation-mismatch rejection; revoked-key rejection; backdated-event handling | coverage authored |
| `bridge/` (per ADR-010) | asymmetric Matrix/Nostr delivery: Nostr permanent failure (index NOT updated); Matrix permanent failure (index updated; Matrix-out-of-sync warning); idempotent re-publication via Nostr event id reuse | coverage authored |
| `index/` (per ADR-005, ADR-006, ADR-023) | room-key wrap derivation (HKDF from Heterodyne room secret); room-key wrap encryption (NIP-44 v2); `prev_page_hash` page-chain integrity; complete-fetch-attempt across relay set | coverage authored |
| `room-kind/` (per ADR-017) | current room kinds; retired-kind rejection/read-back mapping | coverage authored |
| `broadcast/` (per ADR-017) | `private_broadcast` room-key-wrapped post; decrypt-by-member; non-member-cannot-decrypt; NIP-59 rejection | coverage authored |
| `outbox/` | outbox state event; multi-category fan-out; encrypted private outbox entries; private feed-index descriptor with opaque `d` | coverage authored |
| `multi-homing/` (per ADR-009) | active-room election with lex-min `election_id` tiebreaker; publish-lease acquisition and renewal; single-MXID revocation procedure; `kind:31005` race tiebreaker with KERI witness counts; partition-window void-and-requeue | coverage authored |
| `moderation/` | NIP-72 approval flow; multi-mod requirement; moderator rotation; contributor submission with community-address tag and implicit-rejection window (per ADR-014) | coverage authored |
| `moderation/strict-mode/` (per ADR-007) | Strict-mode only. Invalid-broadcast-signature rejection; bare discussion message not hidden; `kind:5` deletion observed within 30s; state-downgrade warning rendering | coverage authored |
| `encryption/` | encryption_version event; delegation-revocation triggering rotation (SHOULD path) | coverage authored |
| `encryption/mls-migration/` (per ADR-012) | SKIPPABLE with rationale. Eligibility check; intent and ACK; abort on missing ACKs; receiver-verifiable flip; 60s tail period; offline-reconnect re-encryption; non-MLS receiver fallback | coverage authored |
| `relay-interop/` (per ADR-013) | NIP-42 AUTH challenge and response signed by current epoch key (not cold root); AUTH rejection classified as permanent per ADR-010; KERI rotation produces AUTH events under new epoch key | coverage authored |
| `homeserver-exit/` (per ADR-015) | Skippable for read-only clients. Identity-room migration; migration-pointer precedence over stale `kind:31005`; KERI rotation during exit window dual-publishes | coverage authored |
| `transport/` (per ADR-019) | `.onion` relay/homeserver reachability via embedded Tor; no clearnet DNS leak; browser/WASM bridge behavior; egress-over-Tor off by default with active-state indicator | coverage authored |
| `transport/strict-mode/` (per ADR-019 / ADR-007) | Strict-mode egress-over-Tor default-on unless explicitly disabled | coverage authored |
| `redundancy/` (per ADR-020, optional) | mirror group; promotion; dedupe across replicas | coverage authored |
| `social-recovery/` (per ADR-021, optional) | follower caching; cold-root `kind:31005` re-anchor; stale/cache-sourced markings | coverage authored |
| `relay-profile/` (per ADR-022, optional) | Heterodyne-aware relay advertisement; KEL-aware reputation; passive witness-receipt store | coverage authored |
| `interop/` | wrapped event round-tripped through a vanilla Nostr relay; bare DM rendered by vanilla Matrix client; `kind:31005` identity pointer | coverage authored |
| `versioning/` | older receiver vs newer sender; capabilities event roundtrip; unknown room-kind tolerance per ADR-016 | coverage authored |
| `config_room/` | minimal config room; persona_config with private mutes; key_backup with various wrapping algorithms; cross-MXID sync of persona_config/user_prefs/key_backup with device_inventory left room-local | coverage authored |

Protocol conformance is defined by the normative spec; vector-conformance is
claimable only for authored vector files or categories. Once the baseline
minimum set exists, any client implementation claiming full baseline
vector-conformance MUST run every baseline vector (see §14.3 / ADR-011)
through its CI pipeline.

## Conformance levels

Per ADR-011:

- **Baseline vector-conformance** requires passing every authored vector in the
  mandatory categories listed in §14.3 (`identity/`, `keri/`, `envelope/`,
  `verification/`, `bridge/`, `index/`, `room-kind/`, `broadcast/`, `outbox/`,
  `multi-homing/`, `relay-interop/`, `transport/`, `moderation/` excluding
  `strict-mode/`, `encryption/` excluding `mls-migration/`, `interop/`,
  `versioning/`, `config_room/`).
- **Strict-mode vector-conformance** additionally requires every vector in
  `moderation/strict-mode/` and `transport/strict-mode/` (per ADR-007 /
  ADR-019).
- **OPTIONAL skippable categories** are `encryption/mls-migration/` (clients
  without MLS support) and `homeserver-exit/` (read-only clients that never
  publish).

Implementations that skip mandatory authored vectors MUST NOT claim baseline
vector-conformance; they MAY claim partial or experimental vector-conformance
with a documented gap list.

## Generator

[`generator/`](generator/) contains non-normative TypeScript tooling used to
author and verify this corpus. The committed JSON files are the normative
artifact; implementations do not need the generator, TypeScript, Node.js,
`nostr-tools`, or `@noble/*` to claim conformance.

## Vector format note

The "successor chain" planned category from earlier drafts has been removed:
the v0.1.4 single-key successor-chain mechanism was deprecated in v0.2.0
(§3.5.4) and replaced by inline KERI per ADR-003. The KERI categories above
(`keri/`) cover the replacement protocol.
