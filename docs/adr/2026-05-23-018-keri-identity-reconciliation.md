# ADR-018: KERI/identity reconciliation — epoch-key signing, revocation coherence, moderator-set evaluation

Date: 2026-05-23
Status: Accepted
Spec target: `docs/spec/heterodyne.md` (v0.2.0, revised in place)

## Context

The v0.2.0 KERI rewrite (ADR-003) replaced the v0.1.4 single-key
successor/predecessor/revoke chain with a cold-root + epoch-key KERI
profile (§3.5), and ADR-004 retired the Matrix cross-signing master
key (MSK) co-signature from the delegation model (§3.3). Those changes
landed in §3.5 and §3.3 but were never propagated consistently across
the rest of the spec. The ADR-017 council review surfaced nine
KERI/identity residue items spanning §§3, 4, 8, 13. They predate
ADR-017 and were explicitly deferred to a dedicated reconciliation
pass (ADR-017 Consequences → Follow-up). This ADR is that pass.

The nine items:

1. **Canonical address contradiction (§3.2 vs §3.6).** §3.2 closed by
   declaring the *Matrix room ID* the persona's canonical address,
   contradicting the same section's "npub is the ultimate authority,
   the room is disposable" and the §3.6 authority ladder (the
   `kind:31005` pointer outranks the room).
2. **Cold-root vs epoch-key blur (§3.2.1, §3.3, §3.5, §3.10.1, §11.3).**
   §3.5 says routine attestations are signed by the *current epoch
   key*, but §3.2.1 had the root attestation (`kind:31000`) and §3.3
   had the delegation (`kind:31001`) "signed by the npub's secret
   key," and §3.10.1 said re-signing the root attestation requires
   unsealing the *cold root* — directly contradicting §3.2.1's note
   that it is re-signed with the *epoch key*. No single statement said
   which key signs which event.
3. **Delegation-revocation incoherence (§3.3 vs §3.9.7).** §3.9.7
   revokes a single delegation via a Nostr `kind:5` deletion plus an
   `m.heterodyne.delegation_revoked.v1` Matrix state event, but §3.3's
   active-delegation test consulted neither — a conformant §3.3
   verifier would still treat the delegation as active.
4. **Stale verification pseudocode (§4.5).** Referenced the removed
   single-key chain (`current_npub`, `historical_npubs`, `is_outgoing`,
   the `kind:31002` successor exception, `is_revoked (§3.5.1)`) and
   hashed `nostr.id` directly instead of `nip01_raw`; its bare-message
   branch still applied the ADR-017-reversed `§11.1` hide-bare policy.
5. **Lingering MSK requirements (§3.5.4, §11.6.7).** Both still demanded
   a Matrix MSK co-signature on KERI inception/rotation that §3.3/§3.5
   already retired.
6. **Moderator identity ambiguity (§8.1, §8.2 vs §8.3).** §8.2
   described the listed `npub` as the key that "verifies approvals" and
   called it an "epoch key"; §8.1 step 4 checked the approval `pubkey`
   against "currently-active moderator." §8.3 correctly says the listing
   is the permanent **cold-root** controller and the *current epoch
   key* signs `kind:4550` approvals.
7. **Missing historical moderator-set algorithm (§8.2.1).** "Valid if
   the moderator was active at time T" had no defined way to
   reconstruct the moderator set as-of T.
8. **Stale threat→mitigation map (§13.3).** Cited removed `§3.5.1`
   revocation and "§3.5 chain timestamps."
9. **Residual retired-mechanism terminology.** Confirmed resolved:
   the genuinely stale terms were the `successor`/MSK references folded
   into items 4 and 5; remaining `successor`-chain mentions are
   intentional "deprecated and removed" prose.

## Decision

1. **The persona's npub is its KERI cold-root public key.** State this
   once (§3.5.0). The cold root signs only rare, identity-anchoring
   events: inception (`kind:31002`), `committed`-strategy rotation
   (`kind:31003`), and the `kind:31005` identity pointer (so vanilla
   Nostr clients can discover the room by `authors:[npub]`, §11.3).
   The **current epoch key** signs everything operational: the root
   attestation (`kind:31000`), delegations (`kind:31001`), outbox
   advertisements, feed indexes, posts, and moderator approvals.

2. **Root attestation (`kind:31000`) is epoch-key-signed** (resolves
   item 2). Its `pubkey` is the current epoch key; it carries a new
   `["cold_root", <npub hex>]` tag binding it to the permanent npub.
   Verifiers replay the KEL (§3.5.3) to confirm the signing key is the
   authoritative epoch key and that `cold_root` equals the persona's
   npub. This keeps the cold root offline through identity-room
   re-signing and freshness churn, and makes §3.2.1's existing
   re-sign-with-epoch-key note correct. §3.10.1's cold-root-unsealing
   warning is re-scoped to the `kind:31005` pointer only.

3. **Delegation (`kind:31001`) is epoch-key-signed** with a `cold_root`
   tag; §3.3's active test verifies against the current epoch key via
   KEL replay. Identity discovery (§3.6) is reordered so KEL replay
   precedes root- and delegation-verification.

4. **Delegation revocation: Matrix state is authoritative, the Nostr
   `kind:5` is a relay-side mirror** (resolves item 3). §3.3 gains a
   step: a delegation is inactive if a valid
   `m.heterodyne.delegation_revoked.v1` is in effect for the MXID
   (effective time clamped per §3.9.7). The `kind:5` deletion remains
   so Nostr-only observers learn of the revocation.

5. **§4.5 is rewritten** to the KEL epoch-key model: a signing key is
   accepted iff it was the KERI-authoritative epoch key at the event's
   `created_at` (§3.5.3), subsuming the old historical/revoked/outgoing
   branches; all hashing is over `nip01_raw`. The bare-message branch
   attributes the message to its author's npub via the §3.3 delegation
   and renders it (ADR-017), rather than hiding it.

6. **Moderator approvals are evaluated by cold-root identity and as-of
   Matrix state-at-event** (resolves items 6, 7). The approval's
   epoch-key `pubkey` is mapped to the signing moderator's cold-root
   npub via their KEL; that cold-root npub must appear in the
   `m.heterodyne.moderators.v1` resolved by Matrix state resolution at
   the approval's position in the moderated room — not the
   verification-time set, and not a forgeable Nostr `created_at`. This
   makes moderation a Matrix-room (discussion) activity; the `kind:4550`
   Nostr event remains the NIP-72 interop mirror.

7. **Drop MSK** from §3.5.4 and §11.6.7 (resolves item 5); KERI
   ceremonies use the §3.5 controller-signature model (cold root for
   inception/`committed`; prior epoch key for `none`) plus witnesses.

8. **Repoint §13.3** and other `§3.5.1` references to §3.5.3 / §3.9.7
   (resolves items 4-residue, 8).

## Requirements

- The spec MUST define the persona's npub as the KERI cold-root public
  key and MUST enumerate which event kinds are cold-root-signed
  (`31002`, `committed` `31003`, `31005`) versus current-epoch-key-signed
  (`31000`, `31001`, outbox, `31007`, posts, `4550`).
- `m.heterodyne.root.v1`'s embedded `kind:31000` attestation MUST be
  signed by the persona's current epoch key, MUST carry a
  `["cold_root", <npub hex>]` tag, and verifiers MUST (a) confirm the
  signing `pubkey` is the KEL-authoritative epoch key (§3.5.3) and
  (b) confirm `cold_root` equals the persona's npub. A second
  `m.heterodyne.root.v1` asserting a different `cold_root` MUST cause
  the room to be treated as having no valid root.
- `m.heterodyne.delegation.v1`'s embedded `kind:31001` attestation MUST
  be signed by the current epoch key and carry a `cold_root` tag; §3.3's
  active-delegation test MUST verify the signature against the epoch key
  KERI-authoritative at the evaluation time and MUST treat the
  delegation as inactive when an `m.heterodyne.delegation_revoked.v1`
  for the MXID is in effect (effective time clamped per §3.9.7).
- The §3.6 discovery algorithm MUST replay the KEL before verifying the
  root attestation and delegation.
- `kind:31005` MUST be cold-root-signed; §3.10.1 MUST scope cold-root
  unsealing during migration to the `kind:31005` pointer only and state
  that the re-signed root attestation, delegations, and outbox do NOT
  require the cold root.
- §4.5's verifier MUST accept a Nostr signing key only when it was the
  KERI-authoritative epoch key at the event's `created_at` (§3.5.3),
  MUST hash `nip01_raw` (never trust the embedded `id`), and MUST NOT
  reference `current_npub`, `historical_npubs`, `is_outgoing`,
  `is_revoked (§3.5.1)`, or the successor exception. A bare
  `m.room.message` / `m.reaction` with no signature MUST be attributed
  via the §3.3 delegation when one exists and rendered (not hidden);
  absent a delegation it is vanilla Matrix traffic.
- §3.5.4 and §11.6.7 MUST NOT require a Matrix MSK signature on KERI
  inception or rotation.
- A `kind:4550` approval counts toward the Heterodyne moderated view
  only when its epoch-key `pubkey` maps (via the signer's KEL) to a
  cold-root npub listed in the `m.heterodyne.moderators.v1` resolved at
  the approval's Matrix-state position, AND it is referenced from the
  moderator's current `kind:31007` index. §8.2's field description MUST
  describe the listed `npub` as the moderator's cold-root controller and
  MUST NOT call it an "epoch key" or the approval-signing key.
- §13.3 and §13.1 MUST NOT cite `§3.5.1` for revocation; they MUST cite
  §3.5.3 (KERI ordering) and §3.9.7 (single-MXID revocation).

## Consequences

- **Positive.** One coherent signing model (cold root = identity anchor,
  epoch key = operations); the cold root stays offline through routine
  identity-room maintenance; delegation revocation is actually honored
  by the §3.3 verifier; the §4.5 pseudocode matches the live KERI and
  ADR-017 envelope models; moderator authority is tamper-evident via
  Matrix state resolution rather than forgeable timestamps.
- **Negative / cost.** `kind:31000` and `kind:31001` gain a `cold_root`
  tag (wire-format change; test vectors in `identity/` and
  `verification/` must be regenerated). A modest normative addition:
  Heterodyne moderator approvals that count toward the moderated view
  must have a Matrix-state anchor in the moderated room (the `kind:4550`
  Nostr event alone, off-index, remains NIP-72-only as before). Cold
  root is still needed for a single `kind:31005` signature at voluntary
  homeserver-exit.
- **Out of scope / deferred.** The stable-subscription question (how a
  vanilla Nostr follower who knows only the npub discovers epoch-key-signed
  posts without replaying the KEL) is unchanged by this pass and remains
  for a later discovery ADR. `docs/glossary.md`, `docs/architecture.md`,
  and ADRs 001/002/004/005/007/014/015 still carry retired terminology
  (shared with ADR-017's follow-up) and need a docs-wide sweep.
- **Relation to prior ADRs.** Completes the propagation of ADR-003
  (KERI) and ADR-004 (MSK removal) into §§3, 4, 8, 13; consistent with
  ADR-017's broadcast/discussion taxonomy and pseudonymity stance.
