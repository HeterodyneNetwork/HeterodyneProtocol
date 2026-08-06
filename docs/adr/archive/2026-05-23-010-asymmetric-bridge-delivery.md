# ADR-010: Asymmetric bridge delivery failure contract

**Date:** 2026-05-23
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gpt-5 (via Fuel-IX, two-instance parallel review); local Claude subagent

## Context

§6.4 (lines 1774–1796) describes four fan-out patterns for publishing events to Matrix rooms and Nostr relays concurrently, and §6.3 (lines 1754–1772) defines idempotency by anchoring the Matrix txn_id to the Nostr event id. The spec is silent on the asymmetric failure case: what happens when one transport succeeds and the other permanently fails.

This is not a theoretical edge case. A Nostr relay may permanently reject a write for reasons spanning ADR-013's anti-abuse contract (NIP-13 PoW insufficient, NIP-42 AUTH failed after retry), per-relay content policy (banned npub), or rate limits with window exceeding the retry budget. The Matrix transport may permanently fail with 403/404 (room policy change, MXID kicked, homeserver outage). The current §6.4 says clients SHOULD surface partial-failure state but provides no normative definition of "permanent" failure, no MUST for re-queuing, and no MUST for updating the kind:31007 feed index when the asymmetry resolves.

Without a normative contract, two conformant clients can diverge: one indexes only on full-delivery success, the other indexes on partial success, producing inconsistent feed views for the same persona's followers. Worse, the user has no clear signal which destinations actually have the event.

## Decision

Define the permanent-failure predicate explicitly, specify whether each asymmetric outcome counts as "published" for kind:31007 indexing purposes, and require destination-level UX granularity instead of an opaque "partial failure" message. Re-publication uses Nostr event id idempotency (per §6.3) so retries are recoverable from any state.

## Requirements (RFC 2119)

### Permanent failure predicates

1. A Nostr relay write is **permanently failed** if any of:
   - (a) The relay returns a NIP-01 `["OK", <id>, false, <reason>]` with `reason` starting `"invalid:"`, `"blocked:"`, `"restricted:"`, or `"rate-limited:"` where the rate-limit retry-after window exceeds 1 hour.
   - (b) Three consecutive ADR-006 retry windows fail for the same event id (no successful write to that relay).
   - (c) The relay closes the websocket with an application-level close code in the 4000–4999 range.
   - Anything else MUST be classified as transient (retryable).
2. A Matrix room write is **permanently failed** if any of:
   - (a) The homeserver returns HTTP 403 or 404 after three retries with 2/8/30-second exponential backoff (total elapsed >=40 seconds).
   - (b) The client is no longer a member of the room (`m.room.member` state shows leave/ban/kick).
   - (c) The room has been tombstoned and no successor room is reachable.
   - Anything else (5xx, 429, network errors) MUST be classified as transient.

### Asymmetric outcomes — Nostr-failed, Matrix-success

3. When all configured write relays (per the persona's NIP-65 outbox for the publishing epoch key) return permanent failure for an event id, the event enters **Nostr-failed** state.
4. The corresponding Matrix room event remains in the room (it was already accepted; un-publishing from Matrix is not possible).
5. The kind:31007 feed index MUST NOT be updated to include a Nostr-failed event id. Followers reading the index do not see the event; followers reading the Matrix room directly do see it (with no signed Nostr-side counterpart).
6. The publishing client MUST surface a "not on Nostr — some followers cannot see this" warning to the user.

### Asymmetric outcomes — Matrix-failed, Nostr-success

7. When the Matrix room write permanently fails (per req 2) but at least one Nostr relay accepted the event, the event remains in the kind:31007 feed index. The event IS published as far as Nostr-side discovery is concerned.
8. The publishing client MUST surface a "Matrix-out-of-sync — re-publish required" warning to the user.
9. The client MUST queue the event for re-publication once Matrix connectivity is restored, using the original Nostr event id as the Matrix txn_id (idempotent per §6.3).

### Destination-level UX granularity

10. Partial-delivery state MUST be surfaced to the user with destination-level granularity. Permitted UX shapes include:
    - "Posted to 5/7 relays (rejected by [list with reasons]); pending Matrix room delivery."
    - "Posted to all relays; Matrix room delivery failed (HTTP 403)."
    - "Permanent failure on relay X (blocked: spam policy)."
    Generic "partial failure" messages without destination-level breakdown MUST NOT be used.

### Idempotency and re-publication

11. Re-publication of a Nostr-failed event MUST NOT happen automatically (the failure is permanent by definition). The client MUST require user action to re-publish, with the option to add additional or alternative write relays.
12. Re-publication of a Matrix-failed event MAY happen automatically up to three attempts with 2/8/30-second exponential backoff. After exhaustion, the event MUST be queued for manual re-publication.
13. All re-publication MUST reuse the original Nostr event id as the Matrix txn_id, ensuring at-most-once Matrix delivery per Nostr event id (per §6.3).

### Cross-references

14. Anti-abuse-driven rejections (per ADR-013) follow this contract:
    - First rejection on a write due to NIP-42 AUTH-required is TRANSIENT (the client retries after authenticating).
    - Post-authentication NIP-42 rejection is PERMANENT per req 1(a).
    - NIP-13 PoW insufficient where the client cannot meet the target is PERMANENT per req 1(a).
15. Partition-window publish-lease void events (per ADR-009 reqs 18–20) trigger the re-publication path; the original event id is reused so dedup is automatic on the receiver side.

## Rationale

Defining "permanent" with concrete predicates (relay-side NIP-01 reason prefixes, retry counts, HTTP status codes, time bounds) turns conformance into something testable. "Three retries with exponential backoff" maps to standard Matrix and Nostr SDK behavior; the 1-hour rate-limit cutoff aligns with typical relay operator policies.

Permitting the asymmetric Matrix-success-Nostr-failed event to remain in the Matrix room (req 4) acknowledges Matrix's append-only nature: once an event is in the DAG, the client cannot retroactively remove it. The mitigation is to NOT propagate the event into the kind:31007 feed index (req 5), keeping the Nostr-side view of the persona consistent.

The symmetric case (Matrix-failed but Nostr-success) is treated differently: the event IS on Nostr relays, so the kind:31007 index correctly reflects publication state. Re-publishing to Matrix when connectivity returns simply backfills the room.

Destination-level UX is mandated because the alternative ("partial failure") is operationally useless: the user has no way to know whether to retry, ignore, or escalate without knowing which destinations failed and why.

The cross-reference to ADR-013 makes the AUTH-required first-rejection-is-transient behavior explicit: clients must distinguish "authenticate then retry" from "permanent rejection."

## Alternatives Considered

### (A) Treat any partial failure as failure of the whole intent
- **Pros:** Simpler client UX.
- **Cons:** Wasteful — the user has to re-sign and re-publish even when one side succeeded; loses idempotency benefit; doesn't acknowledge Matrix's append-only nature.
- **Why rejected:** Doesn't match the asymmetric reality of the two transports.

### (B) Never index Matrix-failed events (require both sides to succeed)
- **Pros:** Index is always "Matrix-correct."
- **Cons:** Wastes the successful Nostr publish; followers who read raw relays see the event but the index doesn't; counter-productive given Nostr-side discovery is the kind:31007 index's purpose.
- **Why rejected:** Nostr-success IS publication for index purposes.

### (C) Define permanent failure as relay-reported only (skip retry counts)
- **Pros:** Smaller permanent-failure predicate.
- **Cons:** Many relays drop connections silently or return 5xx — never reporting "permanent" cleanly. The retry-count condition captures these real-world cases.
- **Why rejected:** Real relays don't always cleanly report.

## Assumed Versions (SHOULD)

- NIP-01 (relay protocol): stable. The OK message format is normative.
- NIP-65 (outbox): stable. Write-relay discovery via kind:10002.
- Matrix client-server API r0.6+: 403/404/429 semantics stable.
- ADR-006 (retry-window semantics): foundational for the "three consecutive retries" predicate.

## Diagram

Asymmetric-delivery state machine for a single publish intent.

<details><summary>Mermaid source</summary>

```mermaid
stateDiagram-v2
    [*] --> Submitted: user publishes event
    Submitted --> InFlight: client signs + fan-out begins

    InFlight --> NostrOK_MatrixOK: both succeed
    InFlight --> NostrOK_MatrixTransient: matrix 5xx/429
    InFlight --> NostrTransient_MatrixOK: relay transient
    InFlight --> NostrFailed_MatrixOK: all relays permanent
    InFlight --> NostrOK_MatrixFailed: matrix 403/404 after retries
    InFlight --> NostrFailed_MatrixFailed: both permanent

    NostrOK_MatrixOK --> Indexed: kind:31007 updated, user notified success
    Indexed --> [*]

    NostrOK_MatrixTransient --> InFlight: retry matrix (2/8/30s)
    NostrTransient_MatrixOK --> InFlight: retry relays
    NostrOK_MatrixFailed --> IndexedMatrixOOS: kind:31007 updated;<br/>'Matrix-out-of-sync' warning;<br/>queue for user re-publish to Matrix
    IndexedMatrixOOS --> Indexed: user manually re-publishes (txn_id = nostr_id)

    NostrFailed_MatrixOK --> NotIndexed: kind:31007 NOT updated;<br/>'not on Nostr' warning to user
    NotIndexed --> [*]: user accepts or chooses alternate relays

    NostrFailed_MatrixFailed --> FullFailure: surface destination-level errors
    FullFailure --> [*]: user re-publishes or abandons
```

</details>

## Consequences

- §6.4 amended with a new normative subsection "Asymmetric delivery failure" containing reqs 1–13.
- §6.3 (idempotency) referenced for the txn_id reuse contract.
- §6.7 (kind:31007 feed index) amended to specify that Nostr-failed events MUST NOT enter the index.
- §10.2 cross-referenced from the asymmetric subsection (clients implementing the bridge model must handle these states).
- Test vectors required (per ADR-011): `bridge/asymmetric-delivery/nostr-permanent-failure`, `bridge/asymmetric-delivery/matrix-permanent-failure`, `bridge/asymmetric-delivery/idempotent-republish`.
- First-party client implements the destination-level UX granularity; this is a meaningful but bounded UX surface.
- ADR-013 anti-abuse rejections cleanly slot into the transient/permanent classification (req 14).
- ADR-009 partition-window void leases use the same idempotent re-publish path (req 15).

## Council Input

Star-chamber's review specifically asked for concrete time bounds on the "3 retries with backoff" language. The 2/8/30-second exponential backoff in reqs 2(a) and 12 is the explicit answer. The 1-hour rate-limit cutoff in req 1(a) addresses the boundary between transient and permanent rate limits cleanly.

The review also queried Matrix federation lag vs Nostr relay finality timing. The answer encoded here: Matrix permanent failure requires a hard error (403/404, kick, tombstone) — federation lag is always transient (would resolve under 5xx/429 retries). Nostr relay finality is determined by the NIP-01 OK message or connection close; no federation analogue exists on the Nostr side because relays don't sync.
