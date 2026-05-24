# Orientation: broadcast/discussion room taxonomy + room-key-wrapped posts

Date: 2026-05-23
Scope: `docs/spec/heterodyne.md` (v0.2.0, in-place per project convention)

## What changed conceptually

v0.2.0 shipped a **six-kind** social taxonomy organized on a
*verifiable vs deniable* axis (`public_broadcast`, `public_moderated`,
`private_verifiable`, `private_deniable`, `dm_verifiable`,
`dm_deniable`), with the default wrap mode (wrapped vs bare) encoded in
the kind name. This change replaces that with a **four-kind** taxonomy
on a *broadcast vs discussion* × *public vs private* axis and retires
the deniable/verifiable distinction as a room property.

### New taxonomy

Infrastructure kinds (unchanged roles): `identity_room`, `config_room`.

Four social kinds:

1. `public_broadcast` — persona broadcasts; posts + index on Nostr
   relays (plaintext); Matrix room is a pointer/state container that
   also carries members' bare reactions/replies.
2. `private_broadcast` (**new**) — persona broadcasts to a closed
   follower set; the encrypted Matrix room's Megolm session is the
   follower keyring; posts go out **room-key-wrapped** (NIP-44 under a
   Megolm-derived key, the §6.7.4 scheme generalized from indexes to
   posts) to the room's relays; reactions/replies land as bare Matrix
   in the encrypted room.
3. `public_discussion` — many participants; vanilla unencrypted Matrix;
   bare messages by default; Nostr optional. **Moderated communities
   (NIP-72) fold in here** as a `public_discussion` room that declares
   `m.heterodyne.moderators.v1` (old `public_moderated` retired).
4. `private_discussion` — E2EE many-party (or two-party DM) chat; bare
   Matrix by default; Nostr optional. Folds old `private_verifiable`,
   `private_deniable`, `dm_verifiable`, `dm_deniable`.

### Authenticity now tracks broadcast vs discussion

The verifiable/deniable axis collapses because **authenticity is
intrinsic to broadcasting**: a broadcast post is always Nostr-signed
(you are intentionally broadcasting *as* a persona). A discussion
message is bare by default — attributed to the author's npub in-room
via the device-key→delegation link, but not a transferable proof.
Optional per-message Nostr signing remains available everywhere as an
authenticity/notarization **badge** (the surviving meaning of the
wrapped/bare envelope split), and stays local unless the user takes an
explicit "publish to my feed" action.

### Deniability scrub (honest nuance retained)

Room-level "deniability" was unsound: every in-room message is
attributable to the author's npub via the delegation link. The change
removes deniability as a room property but keeps one honest sentence in
§13: bare messages carry no *transferable* third-party proof (the
wrapped badge adds that), which is not a deniability guarantee. This
refines — does not contradict — ADR-004's security-claims-hygiene
spirit.

## Mechanism reused: §6.7.4 room-key wrap

`room_key = HKDF-SHA256(megolm_outbound_session_key, salt=room_id,
info="heterodyne-index-key-v1")`, NIP-44 v2 encryption. Already used
for private feed indexes (ADR-005). Generalized to post `content`. This
replaces per-recipient NIP-59 gift-wrap (`kind:1059`) for broadcast,
which scaled as one event per recipient per post.

## Out-of-scope follow-ups (not edited here; flagged)

`docs/glossary.md`, `docs/architecture.md`, and several ADRs reference
the retired kind names. Target was scoped to `heterodyne.md` only;
those need a follow-up pass.
