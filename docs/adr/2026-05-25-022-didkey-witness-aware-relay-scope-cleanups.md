# ADR-022: did:key witnesses, optional Heterodyne-aware relay, and open-question cleanups

**Date:** 2026-05-25
**Status:** Accepted
**Decision makers:** user + multi-LLM council (gemini-3.1-pro, gpt-5.4) via document-mode review

## Context

A cluster of smaller deferrals from the 0.x survey are resolved
together:

1. **`did:key`** was listed out of scope alongside the ATProto DID
   methods (§11.6.2). But `did:key` is a bare self-certifying key with
   no service endpoint — it cannot host a PDS record or a mirror outbox,
   so it does not belong in the ATProto attached-outbox machinery at
   all. Its natural home is as a **KERI witness identifier** (§3.5.0),
   where a bare external key is exactly what is wanted.

2. **Heterodyne-aware relay.** §13.4 names "operate a relay that
   understands the KEL" as a mitigation for KERI-rotation reputation
   reset, but marks it out of scope. The project needs a documented
   *optional* relay profile — without ever compromising the
   non-negotiable rule that **vanilla Nostr relays remain fully
   supported** and baseline conformance never depends on a special
   relay.

3. **Open questions.** Threat-model open question #1 (does identity
   rotation interact with Megolm session keys?) is **already answered**
   by §9.4 — it does not; they are independent. Open question #2
   (warning vs suppression on verification failure) is deliberately
   left loose so clients can decide contextually. Both should be marked
   resolved rather than left dangling.

4. **Compromised devices** remain out of scope, but the framing should
   state *why* the cold root helps and where Heterodyne's
   responsibility ends (its own app surface, not the OS/device).

## Decision

- **`did:key` is supported as a witness-only identifier.** A `did:key`
  MAY appear in a §3.5 inception/rotation witness set (alongside Nostr
  pubkeys and ATProto DIDs). It is verified directly against the key
  material encoded in the identifier — **no network resolution, no DID
  document, no PDS, no SSRF surface**. `did:key` is explicitly NOT a
  valid `m.heterodyne.atproto_link.v1` target or mirror-outbox subject.

- **Optional Heterodyne-aware relay profile.** A new section defines a
  relay that is a **strict superset of a vanilla NIP-01 relay**:
  vanilla Nostr clients use it unchanged, and its Heterodyne features
  are advertised via a NIP-11 relay-info capability flag. The full
  profile is: (a) **KEL-aware reputation continuity** — per-pubkey
  reputation/limits survive a KERI epoch rotation (resolving §13.4);
  (b) **optional KEL-aware discovery** — the relay MAY serve
  epoch-key-signed content in response to `authors:[npub]` queries as a
  server-side convenience (this is the relay's option, NOT a client
  obligation; clients are still not required to bridge epoch-key
  discovery); (c) **passive witness-receipt store** — the relay stores
  and serves KERI witness attestations others produce, signing nothing
  itself. Baseline conformance never depends on any of this.

- **Open-question resolutions.** #1 → resolved, pointing at §9.4
  (rotation is invisible to Megolm). #2 → resolved as intentionally
  loose. #3 → resolved by ADR-021 (involuntary re-anchor).

- **Compromised-device framing.** The threat model retains
  device/OS-level compromise as out of scope but states the cold-root
  rationale: keeping the cold root offline mitigates app-layer key
  theft, and Heterodyne secures its own application, not the host OS.

## Requirements (RFC 2119)

- A conforming client MAY accept a `did:key` identifier in a §3.5
  witness set. When it does, it MUST verify the witness attestation
  against the public key encoded in the `did:key` identifier itself and
  MUST NOT perform any network resolution for a `did:key` witness.
- A `did:key` MUST NOT be used as an `m.heterodyne.atproto_link.v1`
  subject or as a mirror-outbox target; the §11.6 ATProto machinery
  applies to `did:web` / `did:plc` only.
- A Heterodyne-aware relay MUST remain a fully conformant NIP-01 relay:
  vanilla Nostr clients MUST be able to read and write to it using
  unmodified NIP-01, and the relay MUST advertise its Heterodyne
  capabilities in its NIP-11 relay-info document.
- KEL-aware discovery, when offered, MUST be a relay-side convenience
  only; a conforming *client* MUST NOT be required to implement
  epoch-key-signed discovery for vanilla npub-only consumers (that
  bridging remains explicitly not a client responsibility).
- A Heterodyne-aware relay acting as a witness-receipt store MUST store
  and serve attestation events without itself signing them (passive
  store); it is not a KERI witness by virtue of hosting receipts.
- Baseline conformance MUST NOT depend on any Heterodyne-aware relay
  feature; the §14 coverage entry for the relay profile MUST be
  optional/non-baseline.
- The threat model MUST mark open questions #1 and #2 resolved (#1 →
  §9.4; #2 → intentionally loose) and MUST retain compromised-device /
  OS-level compromise as out of scope with the cold-root rationale
  stated.

## Consequences

- `did:key` support lands with essentially zero new attack surface
  (no resolution), and it directly serves the ADR-021 use case of a
  friend's bare key acting as a witness/voucher.
- The §13.4 reputation-reset limitation gains a concrete, in-scope (but
  optional) mitigation; operators who care can run a KEL-aware relay
  without fragmenting the network, because the relay is a vanilla
  superset.
- The KEL-aware-discovery carve-out keeps faith with the prior decision
  that epoch-key discovery is not a client obligation, while still
  letting a relay operator offer it.
- The threat-model open-questions list shrinks to the genuinely-open
  items; #1/#2/#3 are all now resolved (#3 by ADR-021).
- The §14 coverage map gains optional rows for `did:key` witnesses and
  the relay profile; none enter the baseline minimum set.
