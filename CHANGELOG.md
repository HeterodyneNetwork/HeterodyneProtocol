# Changelog

All notable changes to the Heterodyne specification are recorded here.
The spec remains a **DRAFT** — versions are milestones, not a frozen
contract, until first-party-client validation closes the freeze.

## [0.3.0] — 2026-05-23

Structural revision of the room model and a full reconciliation of the
KERI/identity signing model. Builds on the tagged `v0.2.0`.

### Changed — room taxonomy (ADR-017)
- Replaced the six-kind, *verifiable-vs-deniable* taxonomy with four
  kinds on a **broadcast vs discussion × public vs private** axis:
  `public_broadcast`, `private_broadcast` (new), `public_discussion`,
  `private_discussion` (plus `identity_room` / `config_room`).
- `private_broadcast` posts are **room-key-wrapped** Nostr events
  (encrypt-once-for-the-room), retiring per-recipient NIP-59 gift-wrap
  for broadcast.
- Retired room-level **deniability** as an unsound claim: every in-room
  message is attributable to its author's npub via the §3.3 delegation.
  Bare messages carry no *transferable* proof but are not anonymous.
- Moderated NIP-72 communities fold into `public_discussion` +
  `m.heterodyne.moderators.v1`.
- Read-back compatibility: clients MAY accept retired kind names and
  SHOULD map them to the nearest current kind.

### Changed — KERI/identity reconciliation (ADR-018)
- Pinned one signing model: the persona's **npub is its KERI cold-root
  key**. Cold root signs only inception (`kind:31002`), `committed`
  rotation (`kind:31003`), and the `kind:31005` pointer; the **current
  epoch key** signs the root attestation (`kind:31000`), delegations
  (`kind:31001`), outbox, feed index (`kind:31007`), posts, and
  approvals (`kind:4550`).
- `kind:31000` and `kind:31001` now carry a `["cold_root", <npub>]`
  tag (wire-format addition).
- Delegation revocation: `m.heterodyne.delegation_revoked.v1` is
  authoritative; the Nostr `kind:5` deletion is a relay-side mirror.
- Identity discovery (§3.6) replays the KEL **before** verifying the
  root attestation and delegation.
- §4.5 verification rewritten: a signing key is accepted only when it
  was the KERI-authoritative epoch key at the event's `created_at`;
  all hashing is over `nip01_raw`; bare messages are attributed (at
  their Matrix position) and rendered, never hidden.
- Moderator approvals evaluated by cold-root identity and **Matrix
  state-at-event** via a new `m.heterodyne.approval.v1` anchor.
- Removed the retired Matrix MSK co-signature from KERI ceremonies.

### Fixed
- Canonical persona address is the npub, not the identity-room ID.
- Repointed stale `§3.5.1` revocation references to §3.5.3 / §3.9.7.

## [0.2.0] — prior

Nostr-native feed index (`kind:31007`), KERI commitment for root
inception/rotation, ATProto attached outbox, strict clock-skew and
`nip01_raw` canonicalization hardening. See `docs/adr/` (ADRs 001–016)
for the decisions that shaped it.

[0.3.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.3.0
[0.2.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.2.0
