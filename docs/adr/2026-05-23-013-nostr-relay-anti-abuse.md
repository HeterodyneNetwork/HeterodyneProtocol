# ADR-013: Nostr-relay anti-abuse contract (NIP-42 AUTH MUST, NIP-13 PoW SHOULD)

**Date:** 2026-05-23
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gpt-5 (via Fuel-IX, two-instance parallel review); local Claude subagent

> **Superseded in part (2026-07-31, ADR-037).** Requirement 4's “complete AUTH
> within 10 seconds” formulation is replaced by Core's send/attempt deadline
> semantics with retry and availability accounting.

## Context

The Heterodyne v0.2.0 spec lists Nostr relays as a first-class publish target for all public content and feed indexes (§7.1 lines 2402–2413, §10.5 lines 3190–3225). The research index (CLAUDE.md) catalogs NIP-13 (PoW), NIP-42/NIP-43 (client authentication), NIP-86 (relay admin), NIP-57 (zap-gating), NIP-51 (mute lists), and NIP-72 (community moderation) as relevant anti-spam mechanisms. None appears normatively in the spec.

Without normative guidance, independent implementations will diverge on write-side relay protocol. A client that doesn't implement NIP-42 AUTH cannot write to spam-resistant relays, silently breaking public publishing. A client that doesn't surface relay-rejection NOTICE messages drops events with no user-visible trace.

A subtle but critical issue surfaced during star-chamber's review: NIP-42 AUTH events carry a `pubkey` field, and relays apply per-pubkey reputation and rate limits. Per Heterodyne §3.5 (lines 615–619), routine Nostr events are signed by the **current epoch key** (committed via KERI), NOT by the persona's cold root and NOT by delegated MXID keys. NIP-42 AUTH events must therefore be signed by the current epoch key — and vanilla Nostr relays will see KERI rotations as identity transitions, since they have no awareness of the Heterodyne KEL. Per-persona reputation does not persist across rotations on vanilla relays. This is an unavoidable consequence of the "vanilla relay compatibility" invariant (CLAUDE.md, ADR-001); the constraint must be documented explicitly rather than papered over.

The architect's questionnaire answer was the "Strict MUST baseline" option: NIP-42 AUTH MUST, NIP-13 PoW SHOULD, NIP-57 and NIP-86 explicit non-goals.

## Decision

Specify the write-side relay anti-abuse contract as a strict MUST baseline for NIP-42 AUTH and a SHOULD for NIP-13 PoW. AUTH events are signed by the current epoch key per §3.5; the cold root MUST NOT be used. Per-persona reputation persistence across KERI rotations is acknowledged as a known limitation of the vanilla-relay invariant. NIP-57 zap-gating and NIP-86 admin operations are explicit non-goals for v0.2.

## Requirements (RFC 2119)

### NIP-42 AUTH (MUST)

1. Clients MUST implement NIP-42 (`AUTH`) challenge/response. On receipt of an `["AUTH", <challenge>]` frame from a relay during a write session, the client MUST respond with a signed `kind:22242` authentication event per NIP-42.
2. The `kind:22242` event's `pubkey` field MUST be the persona's **current epoch key** (per §3.5). The corresponding BIP-340 signature is produced by the current epoch private key.
3. The cold root MUST NOT be used to sign AUTH events. (The cold root is reserved for KERI inception and `committed`-strategy rotations per §3.5.)
4. Clients SHOULD complete AUTH within 10 seconds of the challenge to avoid relay timeout. On AUTH failure, clients MUST surface the failure to the user with the relay URL and rejection reason.

### NIP-13 PoW (SHOULD)

5. Clients SHOULD implement NIP-13 (Proof of Work) computation for events destined for relays that advertise a non-zero `limitation.min_pow_difficulty` in their NIP-11 relay-info document.
6. The target difficulty for a given relay MUST be read from NIP-11 `limitation.min_pow_difficulty`. If the field is absent or zero, no PoW is required for that relay.
7. Clients that cannot meet a relay's PoW requirement (CPU budget exceeded or computation cancelled) MUST surface the constraint to the user with the relay URL and required difficulty.

### Relay-rejection surfacing (MUST)

8. Clients MUST surface relay NOTICE messages (per NIP-01) to the user with the relay URL and rejection reason. No silent drops.
9. Per ADR-010 req 1, certain NOTICE-prefixed rejection reasons (`invalid:`, `blocked:`, `restricted:`, `rate-limited:` with retry-after >1 hour) classify the write as permanently failed.

### Explicit non-goals (v0.2)

10. NIP-57 (zap-gating): explicit non-goal for v0.2. Clients MAY opt into zap support but MUST NOT advertise zap-gating via §12 capability negotiation until a future spec version defines the wire semantics.
11. NIP-86 (relay admin operations): explicit non-goal for v0.2. Clients MAY ignore NIP-86 frames; baseline conformance does not require NIP-86 support.

### KERI-rotation-resets-relay-reputation (acknowledged limitation)

12. Vanilla Nostr relays applying per-pubkey reputation, rate limits, or per-pubkey allowlists/denylists will treat the persona's epoch key as the identity. When the persona executes a KERI rotation per §3.5, the relay sees a "new" pubkey and per-persona reputation does NOT carry forward on that relay.
13. This limitation MUST be documented in §13 (security model) as a known property of vanilla-relay interop. Mitigations available to deployers: (a) operate a Heterodyne-aware relay that understands the KEL (out of scope for v0.2 baseline); (b) treat KERI rotations as significant events (they already are per ADR-003) and accept that relay reputation rebuilds after each rotation.

### Cross-references

14. ADR-010 req 1(a) classifies post-AUTH NIP-42 rejections as permanent failures; first-time AUTH challenges are transient (the client retries after authenticating).
15. Per ADR-010 req 14, a first rejection due to AUTH-required is TRANSIENT (client retries after AUTH); a subsequent post-AUTH rejection is PERMANENT.
16. Per ADR-006, retry windows on transient failures use the existing backoff schedule (2/8/30-second exponential per ADR-010 req 2(a)).

## Rationale

NIP-42 AUTH is the practical baseline for writing to the spam-resistant relays that dominate the current Nostr graph. Making AUTH MUST and PoW SHOULD reflects operational reality: AUTH is nearly universal among write-side anti-abuse mechanisms; PoW is policy-dependent and computationally expensive enough to warrant per-relay opt-in.

The cold-root prohibition (req 3) is non-negotiable: the cold root is the persona's permanent identity anchor and MUST stay offline. Signing AUTH events with the cold root would defeat the entire KERI cold-root model.

Acknowledging the rotation-resets-reputation limitation (reqs 12–13) is the honest move. The alternatives are: (a) silently accept the limitation and discover it during first-party client testing (worse — implementers waste time investigating "why my reputation reset"); (b) require relays to understand KERI (violates the vanilla-relay invariant); (c) sign AUTH with the cold root (violates the cold-root invariant). Documenting the limitation lets deployers reason about the tradeoff explicitly.

Treating NIP-57 and NIP-86 as explicit non-goals avoids the trap of accidentally specifying behavior the first-party client hasn't validated. If a future Heterodyne version wants to integrate Lightning-based zap-gating, a dedicated ADR can do so with full design attention.

## Alternatives Considered

### (A) NIP-42 SHOULD with documented fallback (lighter conformance bar)
- **Pros:** Lower implementation bar; simple clients ship faster.
- **Cons:** Two conformant clients can show wildly different publish success rates on AUTH-required relays; "conformance" becomes meaningless for relay interop.
- **Why rejected:** Architect chose strict MUST baseline.

### (B) Strict MUST + zap-gating MUST (full anti-abuse coverage)
- **Pros:** Addresses the rising zap-gated relay tier.
- **Cons:** Pulls Lightning infrastructure into the spec; commits to NIP-57 semantics before Heterodyne has used them in practice; raises implementation cost significantly.
- **Why rejected:** Architect chose to defer NIP-57 as explicit non-goal.

### (C) Sign AUTH with cold root (preserve relay reputation across rotations)
- **Pros:** Relay reputation persists.
- **Cons:** Violates the cold-root-offline invariant. Cold root must be available for every AUTH challenge, which is operationally unacceptable.
- **Why rejected:** Cold root MUST stay offline.

### (D) Define a Heterodyne-aware relay protocol extension
- **Pros:** Solves the KERI-rotation-resets-reputation problem cleanly.
- **Cons:** Violates the vanilla-relay invariant; requires relay-side software changes; turns a client-side bridge into a client-server protocol.
- **Why rejected:** Out of scope for v0.2.

## Assumed Versions (SHOULD)

- NIP-42 (`AUTH`): stable.
- NIP-13 (PoW): stable.
- NIP-11 (relay information document): stable.
- NIP-01 (NOTICE format): stable.
- ADR-003 (KERI inline profile): foundational; epoch key signing model is the basis for AUTH key choice.
- ADR-010 (asymmetric delivery): cross-reference for transient/permanent classification.

## Diagram

NIP-42 AUTH flow on a write attempt to an AUTH-required relay.

<details><summary>Mermaid source</summary>

```mermaid
sequenceDiagram
    participant Client as Heterodyne client
    participant Relay as Nostr write relay

    Client->>Relay: open websocket
    Client->>Relay: EVENT <signed kind:1 by epoch_key>
    Relay-->>Client: AUTH <challenge>

    Note over Client: classify as transient<br/>(ADR-010 req 14)

    Client->>Client: sign kind:22242 with current epoch key<br/>(NOT cold root, NOT delegated MXID)
    Client->>Relay: AUTH <signed kind:22242>

    alt AUTH accepted
        Relay-->>Client: OK <auth_id> true ""
        Client->>Relay: EVENT <re-send kind:1>
        Relay-->>Client: OK <event_id> true ""
    else AUTH rejected
        Relay-->>Client: OK <auth_id> false "<reason>"
        Note over Client: classify as permanent<br/>per ADR-010 req 1(a)
        Client->>Client: surface relay URL + reason<br/>to user (req 8)
    end

    Note over Client,Relay: After KERI rotation per §3.5,<br/>the relay sees a new pubkey;<br/>reputation does not carry forward (req 12)
```

</details>

## Consequences

- §10.5 (vanilla relay interop) gets a new normative subsection (or new §7.6) defining the anti-abuse contract.
- §3.5 (KERI) gets a one-paragraph cross-reference: the current epoch key signs all routine Nostr events including NIP-42 AUTH.
- §13 (security model) gets an explicit "vanilla-relay reputation limitation" subsection per req 13.
- §12 (capability negotiation) NIP-57 capability slot remains unallocated for v0.2.
- Test vectors required (per ADR-011): `relay-interop/nip43-auth-challenge` (challenge→response→accept), `relay-interop/nip43-auth-rejection` (challenge→response→reject), `relay-interop/keri-rotation-new-pubkey` (verifies the rotated AUTH event signs under the new epoch key).
- First-party client implementation must handle AUTH challenges, NIP-13 PoW computation, and NOTICE-message surfacing.
- The cold-root prohibition is normative; client implementations that hold the cold root in a way that risks online exposure (HSM, secure enclave) are still bound by req 3.
- ADR-010's transient/permanent classification is cleanly populated by AUTH and PoW rejection cases.

## Council Input

Star-chamber's parallel-mode review specifically flagged NIP-42/delegated-key compatibility as a concern (the original framing assumed delegated keys could sign AUTH, which would have been wrong). Investigation of §3.5 lines 615–619 confirmed that routine Nostr events (and therefore AUTH events) are signed by the current epoch key. The corrected requirements 1–3 and the explicit limitation acknowledgement in reqs 12–13 directly address the star-chamber finding.

The architect's choice of "Strict MUST baseline" over "Minimal MUST, broad SHOULD" or "Strict MUST + zap-gating in scope" was the recommended option in the synthesis questionnaire; this ADR encodes that choice without modification.
