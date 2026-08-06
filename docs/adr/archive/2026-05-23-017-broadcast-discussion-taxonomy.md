# ADR-017: Broadcast/discussion room taxonomy and room-key-wrapped broadcast posts

Date: 2026-05-23
Status: Accepted
Spec target: `docs/spec/heterodyne.md` (landed in v0.3.0)

> **Superseded in part (2026-07-31, ADR-037).**
> `public_broadcast`/`private_broadcast` are not current Matrix room kinds and
> room-secret-wrapped private-broadcast behavior is retired. The discussion
> taxonomy, deniability retirement, and wrapped/bare envelope decisions remain
> accepted.

## Context

v0.2.0 (ADR-004/ADR-005) defined six social room kinds on a
*verifiable vs deniable* axis — `public_broadcast`, `public_moderated`,
`private_verifiable`, `private_deniable`, `dm_verifiable`,
`dm_deniable` — with the default wrap mode encoded in the kind name.
Two problems surfaced:

1. **Room-level deniability is unsound.** A Heterodyne author's npub is
   bound to the Matrix device that publishes via the §3.3 delegation.
   Any room member can therefore attribute a bare `m.room.message` to
   the author's npub through the delegation link, regardless of whether
   a Nostr signature is attached. Marketing certain rooms as "deniable"
   overstates the guarantee. (ADR-004 already conceded colluding
   members defeat deniability; this goes further — even a single
   honest member attributes via the delegation link.)

2. **No encrypted-broadcast kind existed.** v0.2.0 could broadcast in
   plaintext (`public_broadcast`, content on relays) or hold encrypted
   group conversation (`private_verifiable`/`private_deniable`), but had
   no first-class way for a persona to *broadcast to a closed follower
   set* without per-recipient NIP-59 gift-wrap (`kind:1059`), which
   scales as one event per recipient per post.

The §6.7.4 room-key wrap (ADR-005, key source updated by ADR-023) —
NIP-44 v2 encryption under a key derived from the room's explicit
Heterodyne room secret — already solves encrypt-once-for-the-room for
private *feed indexes*. Generalizing it from indexes to *post content*
yields encrypted broadcast for free.

A cleaner organizing axis emerged: **broadcast vs discussion** ×
**public vs private**. Broadcasting is intentionally publishing *as* a
persona (authenticity intrinsic, Nostr-signed); discussion is
many-party conversation (bare Matrix, low overhead, no mandatory Nostr
signature). Authenticity therefore tracks the broadcast/discussion axis,
making the separate verifiable/deniable axis redundant.

## Decision

1. Replace the six social kinds with four: `public_broadcast`,
   `private_broadcast` (new), `public_discussion`, `private_discussion`.
   `identity_room` and `config_room` remain distinct infrastructure
   kinds with unchanged roles.

2. `private_broadcast` posts are published as **room-key-wrapped Nostr
   events** (NIP-44 v2 under the §6.7.4 room-secret-derived `room_key`) to
   the relays advertised in the room — encrypt-once-for-the-room,
   replacing per-recipient gift-wrap for broadcast. The encrypted Matrix
   room's membership/Megolm session is the follower keyring; the room
   also carries members' bare reactions/replies and status events.

3. Broadcast posts are always Nostr-signed (the persona broadcasts *as*
   a persona). Discussion messages, replies, and reactions default to
   bare Matrix, attributed to the author's npub via the §3.3 delegation
   link. The wrapped/bare envelope split survives only as an OPTIONAL
   per-message authenticity (notarization) **badge**, not a room
   contract; an opt-in signed discussion message stays local unless the
   user explicitly publishes it to their feed.

4. Retire room-level deniability. Moderated communities (NIP-72) fold
   into `public_discussion` with `m.heterodyne.moderators.v1`.

## Requirements

- New rooms' `m.heterodyne.room_kind.v1` `kind` field MUST be one of:
  `identity_room`, `config_room`, `public_broadcast`,
  `private_broadcast`, `public_discussion`, `private_discussion`.
  For read-back compatibility, clients MAY accept rooms asserting a
  retired kind (`public_moderated`, `private_verifiable`,
  `private_deniable`, `dm_verifiable`, `dm_deniable`); when they do,
  they SHOULD map it to the nearest current kind and surface a
  "legacy room kind" indicator (matching the normative rule in spec
  §5.1, which is authoritative).
- In `private_broadcast` rooms, post content MUST NOT appear as a Matrix
  timeline message; it MUST be published as a Nostr event whose
  `content` is NIP-44 v2 encrypted under `room_key` (§6.7.4 derivation),
  signed by the persona's current epoch key, carrying
  `["heterodyne_wrap","room_key.v2"]` and `["key_id", …]` tags. The
  post MUST NOT carry a cleartext `["megolm_session_id", …]` or
  `["matrix_room", …]` tag (room association lives only in the encrypted
  Matrix descriptor, per ADR-023); semantically meaningful tags move to
  the encrypted inner payload. Clients MUST NOT publish broadcast posts
  via NIP-59 gift-wrap (`kind:1059`).
- Broadcast posts (`public_broadcast`, `private_broadcast`) MUST be
  Nostr-signed by an epoch key authorized under §3.5.
- Discussion messages, replies, and reactions MAY be bare
  `m.room.message` / `m.reaction`; clients MUST attribute them to the
  author's npub via the active §3.3 delegation for the sender MXID, and
  MUST NOT require a Nostr signature to render or attribute them.
- A client that attaches an OPTIONAL Nostr signature to a discussion
  message MUST treat it as a local authenticity badge and MUST NOT
  rebroadcast it to relays or add it to a `kind:31007` index absent an
  explicit user action.
- The spec MUST NOT describe any room kind as offering deniability.
  §13 MAY state that bare messages carry no *transferable* third-party
  proof of authorship while remaining attributable in-room; this MUST
  NOT be framed as a deniability guarantee.
- `private_broadcast` and `private_discussion` join `config_room` in the
  set of rooms whose events and Heterodyne state MUST be E2EE (§9.1,
  §9.1.1, I1).

## Consequences

- **Positive.** Cleaner mental model (broadcast vs discussion);
  encrypt-once encrypted broadcast at any follower count; honest
  security posture (pseudonymity + confidentiality, no overstated
  deniability); lower overhead for discussion (no mandatory per-event
  Nostr signature); gift-wrap fan-out retired for broadcast.
- **Negative / cost.** Substantial spec churn (~130 references across
  §§2, 4, 5, 6, 7, 8, 9, 11, 13, 14). Read-back compatibility shims
  needed for v0.1.x/early-v0.2.0 rooms. The notarization use cases that
  motivated `dm_verifiable`/`private_verifiable` now rely on the per-
  message badge rather than a room-wide contract.
- **Follow-up.** `docs/glossary.md`, `docs/architecture.md`, and ADRs
  001/002/004/005/007/014/015 reference retired kind names and need a
  later reconciliation pass (out of scope for this doc-only change,
  which targeted `heterodyne.md`).
- **Pre-existing issues surfaced by the ADR-017 council review** (NOT
  introduced by this change; they predate it and belong to a separate
  KERI/identity reconciliation pass): (1) §3.2 vs §3.6 contradiction
  over whether the identity-room ID or the `kind:31005` pointer is the
  canonical persona address; (2) §3.2.1/§3.5/§3.10.1/§11.3 blur
  cold-root key vs current epoch key (and call the cold root "npub" in
  places); (3) §3.3/§3.9.7 selective delegation revocation via Nostr
  `kind:5` is not coherent with the Matrix-state delegation model the
  §3.3 verifier uses; (4) §4.5 verification pseudocode still references
  the removed single-key successor chain (`current_npub`,
  `historical_npubs`, `is_outgoing`, `kind:31002` successor exception)
  and hashes `nostr.id` directly instead of `nip01_raw`; (5)
  §3.5.4/§11.6.7 still require a Matrix MSK co-signature that §3.5's
  KERI profile removed; (6) §8.2 vs §8.3 inconsistent moderator
  identity (persona npub vs KERI cold-root controller); (7) §8.2.1
  "approval valid at time T" lacks a historical moderator-set
  evaluation algorithm; (8) §13.3 threat→mitigation map cites removed
  successor-chain/§3.5.1 mechanisms. These were reported to the user;
  fixing them requires touching §3/§4/§8/§13 beyond this change's
  taxonomy scope.
- **Relation to prior ADRs.** Refines ADR-004 (security-claims hygiene)
  by removing the deniability *label* while keeping its honesty intent;
  extends ADR-005 (room-key wrap) from indexes to post content.
