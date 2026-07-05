# Changelog

All notable changes to the Heterodyne specification are recorded here.
The spec is in its **0.x phase**: per the semver 0.x rule (§12.1),
everything is subject to change and any `0.x` release MAY break the
previous one. The strict PATCH/MINOR/MAJOR compatibility contract
takes effect only at `1.0.0`.

## [0.4.0] - 2026-07-01

Substrate pivot: the core moves from Matrix-as-transport to a **Radicle +
Nostr core substrate**, with Matrix demoted to an OPTIONAL layer. This is
a 0.x breaking change (semver 0.x rule, §12.1): v0.4.0 breaks v0.3.0.
Decisions recorded in ADR-026 through ADR-029.

### Changed - Radicle + Nostr core substrate (ADR-026)
- Nostr signed events remain the canonical content unit, now carried over
  **two co-equal MUST backends**: ordinary Nostr relays AND **repo relays**
  (NIP-01 websocket endpoints backed by a Radicle git repository). Radicle's
  Noise XK / TCP peer-to-peer replication lives entirely behind full nodes,
  never in front of a browser/mobile client.
- Three node roles defined (§10.1.1): **full node** (runs a Radicle node +
  NIP-01 repo-relay adapter; the only node type that holds content),
  **routing node** (edge-runtime, answers repo-location queries from
  `kind:31005`/`kind:31010` ads only, holds no content), **light node**
  (fetches directly from full-node repo relays or relays; verifies every
  event's Nostr signature locally).
- `kind:31005` identity pointer repurposed from npub→Matrix room to
  **npub → Radicle RID + optional full-node host hints** (§11.3).
- New `kind:31010` node/repo advertisement - an outer BIP-340 Nostr event
  (valid on the NIP-01 wire) carrying an inner Ed25519 NID possession proof
  (an Ed25519 signature by the NID over the advertisement payload, including
  the current canonical repo head), the RID, endpoints, and an expiry (§7.0).

### Changed - KERI to Radicle identity and organizations (ADR-027)
- The KEL stays the single authority for key lifecycle; the Radicle identity
  document's `delegates` set is a derived projection, and clients trust the
  KEL on any divergence (§3.9.10).
- `kind:31001` delegation extended to authorize an **Ed25519 Radicle NID**;
  NID binding is **bidirectional** (epoch-key Schnorr signature + NID Ed25519
  `nid_proof`), two keys per device (§3.3.1).
- Organizations are first-class personas whose repo delegates + threshold
  (with optional per-ref `crefs`) encode M-of-N governance; a plain user is
  the one-delegate case.
- Two parallel editorial-gating mechanisms (§8): the retained NIP-72
  `kind:4550` approval flow, and a native **Radicle editorial-gating mode**
  (§8.8) where a post is approved iff it is reachable from the
  **delegate-threshold-approved canonical feed branch** (the commit a
  threshold of delegates agree on); the finer per-ref `xyz.radicle.crefs`
  refinement is OPTIONAL and EXPERIMENTAL, pending Heartwood-release
  verification. A community MAY use either mechanism or both.

### Changed - three privacy tiers (ADR-028)
- Broadcast confidentiality recast as three repo-visibility tiers with honest
  trust boundaries (§5.2, §9.0): Tier 1 public repo; Tier 2 private repo
  ("unencrypted-but-not-discoverable" - plaintext on every allowed seeder);
  Tier 3 encrypted-blobs-in-repo (NIP-44 encrypt-before-commit, confidential
  against everyone including seeders).
- Private-tier honesty MUST: a client MUST warn that private-repo content is
  plaintext on every allowed seeder and MUST NOT call it "encrypted."
- New `kind:31011` per-recipient audience-key wrap distributes the Tier 3
  audience key over the repo/Nostr substrate, Matrix-free (§6.7.4).

### Changed - Matrix demoted to OPTIONAL; v0.4.0 (ADR-029)
- Matrix becomes a SHOULD-level layer for discussion groups, DMs, calls, and
  encrypted real-time rooms; no identity, publishing, discovery, or privacy
  requirement depends on it. A Matrix-free client is **fully conformant**
  (§14). Megolm/MLS scoped to the OPTIONAL Matrix layer (§9.2).
- Asynchronous public interaction uses the Nostr **outbox model**: replies /
  reactions are written into the author's own outbox and assembled
  scatter-gather (§6.5).
- Every v0.3.0 Matrix-mandatory MUST superseded per ADR-029's supersession
  table.

### Migration
- Existing v0.3.0 personas republish `kind:31005` in its RID-pointer form and
  stand up (or arrange reachability through) at least one durably-connected
  full node (§12.1).

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

[0.4.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.4.0
[0.3.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.3.0
[0.2.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.2.0
