# ADR-006: Relay partitioning — normative missing-page handling, relay-set timeout semantics, and page-integrity hashing

**Date:** 2026-05-21
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gemini-3.1-pro, gpt-5.4 (via Fuel-IX); local Claude subagent

## Context

External critique flagged that the spec does not normatively address what clients should do when:

1. A `previous_index`-linked `kind:31007` page is missing from all relays (data loss / partition).
2. Relays go offline mid-fetch (incomplete fetch attempt).
3. Relays return inconsistent versions of historical pages (replay / tampering).

The current spec at §6.7.2 lines 1653–1666 defines `previous_index` chaining as OPTIONAL with no integrity verification between pages — each event has its own BIP-340 signature, but there's no hash linkage to detect a relay swapping a different signed event into the chain. §6.9.1 mentions fallback relay hints but doesn't specify a complete fetch-attempt definition.

Verification confirmed this as a "major" severity issue: real data-loss / data-substitution scenarios for users with no normative client behavior to handle them.

Architecture review (round 2) added that simply specifying missing-page UX is insufficient — without cryptographic page-chain integrity (`prev_page_hash` alongside `previous_index`), a relay can swap pages undetectably. The fix should bundle both behavior and a small additive wire-format extension.

## Decision

Add normative client behavior for missing pages and relay timeouts to §6.7.2 and §6.9.1, AND extend `kind:31007` with a `prev_page_hash` tag enabling page-chain integrity verification.

## Requirements (RFC 2119)

### Page-integrity hashing (wire-format additive change)

1. `kind:31007` events that chain to a prior page via `["previous_index", "<event-id>"]` MUST also include `["prev_page_hash", "<sha256-hex>"]` where `<sha256-hex>` is the SHA-256 of the prior page's canonical NIP-01 serialization (the same serialization used for the Nostr event id).
2. Verifiers traversing a `kind:31007` chain MUST verify that the prior page's computed canonical SHA-256 matches the `prev_page_hash` tag value. A mismatch MUST cause the chain to be marked as broken at that point and surface as a "feed integrity error" to the user.
3. `kind:31007` events without a `previous_index` (i.e., the first page or a chain-restart) MUST omit `prev_page_hash`.
4. Backward compatibility: receivers MAY accept legacy `kind:31007` events that omit `prev_page_hash` from `previous_index`-linked pages, but MUST surface a "legacy/unverifiable chain" indicator to the user. Publishers MUST emit `prev_page_hash` going forward.

### Missing-page handling

5. Heterodyne clients fetching a `kind:31007` chain MUST define a normative "complete fetch attempt": at minimum N relay queries (default: `max(3, ceil(len(known_relays) * 0.5))`) with a per-relay timeout (default: 10 seconds), and exponential-backoff retry across the configured relay set up to a total budget of `R` retries (default: 3) per page.
6. When a `previous_index`-linked page does not resolve after a complete fetch attempt across the persona's published relay set (and any fallback relays from NIP-65), clients MUST surface a "feed truncated at <date> / <page d-tag>" indicator to the user and MUST continue rendering from the most recent resolvable page.
7. Heterodyne clients MUST NOT silently treat a truncated feed as "complete history" — the truncation indicator is a hard normative requirement, not a UX suggestion.
8. Heterodyne clients SHOULD remember which pages were unresolved across fetch attempts and retry them when the user returns or when new relays become reachable.

### Relay-set semantics

9. The spec MUST define in §6.9.1 what constitutes a "complete fetch attempt": the relay-set traversal order, per-relay timeout, retry budget, and exit conditions.
10. Clients MUST publish updates to their NIP-65 relay list (kind:10002) when their relay set changes; readers SHOULD refresh the relay set before declaring a fetch attempt complete.

### Other

11. Test vectors required: page-chain construction with `prev_page_hash`, hash mismatch detection, missing-page truncation indicator, relay timeout exhaustion behavior.

## Rationale

`prev_page_hash` is a small additive wire-format change (one new tag) that closes a real cryptographic gap: without it, even a fully signed chain can be tampered with by relays inserting different (signed) events. The signature-only model relies on persona signing each individual page, which is correct as far as it goes, but does not prevent a relay from swapping page B for an alternate (also-signed) page B′ in the response stream.

The missing-page handling requirements force clients to be honest about data loss. The biggest user-harm scenario is silently presenting a partial feed as complete history. Requirement 7's MUST NOT prevents this.

The relay-set semantics ensure that "we tried" actually means something measurable — a client cannot claim "feed truncated" after asking one relay once.

## Alternatives Considered

### (A) Add only missing-page UX, no page hashing
- **Pros:** Smaller change; no wire-format addition.
- **Cons:** Leaves the relay-tampering hole open. A motivated relay can swap pages undetectably.
- **Why rejected:** The page-hash addition is small (one tag) and closes a real gap.

### (B) Defer to v0.3, mark as known gap in v0.2.0
- **Pros:** Ships v0.2.0 with documented limitation; honest.
- **Cons:** Real data-loss scenario for users right now.
- **Why rejected:** The mechanical client-behavior additions are not blocked on any other design work.

### (C) Page-integrity hashing as its own ADR
- **Pros:** Very explicit treatment of integrity semantics.
- **Cons:** Over-segmentation; the hash and the missing-page handling are both feed-retrieval concerns and benefit from being decided together.
- **Why rejected:** Bundled approach has better cohesion.

### (D) Hash-chain extension via Merkleization or signature aggregation
- **Pros:** Could enable proof-of-inclusion or compact archive attestations.
- **Cons:** Significant complexity; out of scope for fixing the immediate tampering gap.
- **Why rejected:** Defer to v0.3 if/when archive attestation features are designed.

## Assumed Versions (SHOULD)

- NIP-01: stable.
- NIP-65 (relay list metadata): stable.
- SHA-256: FIPS 180-4.

## Diagram

Page-chain fetch sequence with timeout, retry, and `prev_page_hash` verification.

<details><summary>Mermaid source</summary>

```mermaid
sequenceDiagram
    participant C as Client
    participant R1 as Relay 1
    participant R2 as Relay 2
    participant R3 as Relay 3
    participant U as User UX

    C->>R1: REQ kind:31007 latest page (10s timeout)
    R1-->>C: page_N (signed, has prev_page_hash)
    C->>C: verify BIP-340 signature
    C->>C: read prev_page_hash, previous_index → page_N-1
    C->>R1: REQ page_N-1 (10s timeout)
    R1-->>C: timeout
    C->>R2: REQ page_N-1 (10s timeout)
    R2-->>C: page_N-1 (signed)
    C->>C: compute SHA-256(page_N-1 canonical)
    alt hash matches prev_page_hash from page_N
        C->>U: render page_N-1 normally
        C->>C: continue traversal to page_N-2
    else hash mismatch
        C->>U: surface 'feed integrity error at page_N-1'
        C->>C: chain broken; stop traversal
    end
    C->>R1: REQ page_N-2 (retry budget remaining)
    R1-->>C: timeout
    C->>R2: REQ page_N-2 (10s timeout)
    R2-->>C: timeout
    C->>R3: REQ page_N-2 (10s timeout)
    R3-->>C: timeout
    Note over C: complete fetch attempt exhausted
    C->>U: surface 'feed truncated at <page_N-2 d-tag>'
    C->>C: continue from page_N-1 as oldest resolvable
```

</details>

## Consequences

- §6.7.2 extended: `prev_page_hash` tag added to `kind:31007` schema; missing-page handling requirements specified.
- §6.9.1 extended: "complete fetch attempt" defined with normative timeout, retry, and traversal semantics.
- New normative client behavior: hash-mismatch detection and truncation indicator UX.
- New test vectors: chain construction with `prev_page_hash`, hash-mismatch detection, missing-page truncation.
- Existing `kind:31007` events without `prev_page_hash` remain readable with a "legacy/unverifiable" indicator; new publishers MUST emit the tag.
- First-party-client implementation now has a complete normative spec for index retrieval — no more "implementation choice" gaps.

## Council Input

Round 1 reviewers flagged the relay-partitioning question as a real issue with no obvious answer in the current spec. Round 2 specifically recommended bundling `prev_page_hash` with the missing-page handling because both are feed-retrieval concerns and adding hashing as a separate ADR was rated as "over-segmentation for a bounded additive tag." The "feed-integrity hashing in its own ADR" alternative was rejected.
