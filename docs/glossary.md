# Glossary

Terms used in the Heterodyne specification, in alphabetical order. The
canonical use of each term is in [`spec/heterodyne.md`](spec/heterodyne.md);
this glossary exists so the spec body itself can stay tight.

**Approval (NIP-72).** A `kind:4550` Nostr event published by an
authorized moderator that surfaces a candidate post in a
`public_moderated` room's curated feed view. Wire form is the vanilla
NIP-72 approval embedded in a standard `m.heterodyne.note.v1`
envelope. See spec §8.1.

**Audience-stratified discovery.** Heterodyne's discovery model:
public outbox advertisements live in the identity room (visible to
everyone); scoped outbox advertisements live inside friend-circle and
community rooms (visible only to members). Different audiences see
different sets of feeds. See spec §7.

**Bare event.** A Heterodyne event published as a plain `m.room.message`
with no Nostr signature. Deniable inside an E2EE Matrix room. The
default wrap mode for DMs. See spec §4.3.

**Blind server / blind homeserver.** A homeserver that handles E2EE
traffic but cannot read its plaintext. Heterodyne's client-side bridge
model preserves this property for all private rooms (including the
config room). Spec invariant I1.

**Bridge.** Cross-protocol translation logic between Nostr and Matrix
event formats. In Heterodyne the bridge is **client-side**
(`heterodyne-core`), not a separate process or appservice.

**Capabilities advertisement.** A persona's declaration of which spec
versions and event types its current client supports, recorded as
`m.heterodyne.capabilities.v1` state events. By default scoped to
friend-circle, community, and DM rooms (privacy: avoids
fingerprinting); MAY be opt-in published in the public identity room.
See spec §12.2.

**Config room.** Per-MXID encrypted Matrix room (`config_room` kind in
§5.1) holding portable client configuration, per-persona private state
including private mutes, and Heterodyne-specific key backups. Single
member: the owning MXID and their devices. Discovery via the
`m.heterodyne.config_room` profile field. See spec §3.8.

**Cross-persona attestation.** A double-signed declaration in a
persona's identity room (public) or in a friend-circle / community
room (scoped) that links this persona to another. Required signatures
from both npubs; single-signed claims are rejected. See spec §7.5.

**Delegation.** An attestation in an identity room authorizing a specific
Matrix MXID to publish events on behalf of the persona's npub.
Double-signed by both the npub (proving authorization) and the MXID
(proving acknowledgement). See spec §3.3.

**Distribution list.** UX label for a categorized outbox room (e.g.,
"close friends", "work"). Implementation is a normal Matrix room with
the identity holder as admin and appropriate membership.

**Fallback.** A vanilla-Matrix-compatible rendering inside a wrapped
event's content. Vanilla Matrix clients render the fallback;
Heterodyne clients ignore it and render from the embedded Nostr event.
RECOMMENDED for `kind:1` posts; OMITTED for non-text Nostr kinds. See
spec §4.2, §11.5.

**Feed status.** An encrypted Matrix state event
(`m.heterodyne.feed_status.v1`) in a broadcast-style
`private_community` room that lists the Nostr event IDs of a
persona's posts in intended display order. Sits alongside the
encrypted wrapped posts themselves, providing curated ordering, an
integrity overlay against forged claims, and a manifest for offline
catch-up — *not* a substitute for the content, which stays in the
room as the wrapped events. See spec §6.7.

**Friend circle.** Synonym for distribution list. Different UX surface
("here are my close friends"), same underlying construct (a Matrix
room).

**`heterodyne-core`.** The reference Rust crate implementing the
protocol. Compiled to WASM for browser/mobile clients; used natively in
desktop and headless deployments. Carries the security-critical logic
so client surfaces don't have to re-implement it.

**`heterodyne_nostr_sig`.** Optional field on a bare `m.room.message`
event carrying a Nostr-signed proof of the message content. Lets a
sender opt in to authenticity without abandoning the `m.room.message`
rendering path. See spec §4.3.

**Hide-bare-events.** A user preference in
`m.heterodyne.user_prefs.v1` controlling whether bare
`m.room.message` events from vanilla Matrix clients render normally,
render with a warning indicator, or are hidden. Default:
accept-with-warning. See spec §3.8.3, §11.1.

**Identity chain.** The linked succession of npubs a persona has
rotated through. Each rotation produces a paired
`m.heterodyne.successor.v1` (in the outgoing identity room) and
`m.heterodyne.predecessor.v1` (in the incoming identity room).
Followers walk the chain to follow a persona across key rotations.
See spec §3.5.

**Identity pointer (`kind:31005`).** OPTIONAL Nostr event published to
a persona's vanilla Nostr write relays announcing the matrix-side
identity room. Lets vanilla Nostr clients (or Heterodyne clients
discovering a persona via Nostr) find the full identity context. See
spec §11.3.

**Identity room.** A Matrix room owned by a persona's identity holder
whose state events bind the npub to its delegated Matrix accounts,
declare its outbox addresses, and record the identity chain. The room
ID is the persona's canonical Heterodyne address.

**`matrix:` URI.** Canonical Matrix reference format per MSC2312:
`matrix:roomid/<id-without-bang>:<server>?via=<server>` for rooms by
ID; `matrix:r/<alias-without-hash>:<server>` for rooms by alias;
`matrix:u/<user-without-at>:<server>` for users. New constructs in the
spec use the URI form; legacy `{room_id, via}` structured form
remains valid in §7. See spec §2.

**Moderator.** A persona authorized in `m.heterodyne.moderators.v1`
to issue NIP-72 approval signatures (and only NIP-72 approval
signatures, in v0.1) for a `public_moderated` room. Identified by
both MXID (for Matrix-layer power-level mapping) and npub (for
signature verification). See spec §8.2.

**Mute list (public / private).** A persona's curated set of npubs
they refuse to render in their feeds. Public mutes live as
`m.heterodyne.mutes.public.v1` in the identity room and are
inheritable by other personas; private mutes live in the per-MXID
config room (§3.8) and stay invisible to the homeserver. See spec
§8.5.

**MXID.** A Matrix user identifier, of the form `@local:server.example`.
In Heterodyne, MXIDs are *delegated publishers* of an npub, not
identities in their own right.

**npub / nsec.** A Nostr public / secret key in bech32 form (`npub1...` /
`nsec1...`), corresponding to a `secp256k1` keypair. The npub is the
canonical Heterodyne identity for a persona.

**Outbox room.** A Matrix room where a persona publishes content. The
persona is the room admin. Followers subscribe by joining. Multiple
outbox rooms per persona enable distribution-list semantics.

**Persona.** A distinct Heterodyne identity: one npub, one identity
room, one set of delegations, one set of outbox rooms. A user MAY hold
multiple personas; the protocol does not link them.

**Public outbox.** A persona's publicly-advertised set of outbox
rooms, communities, and Nostr relays, recorded as the
`m.heterodyne.outbox.public.v1` state event in the identity room.
Visible to anyone who can peek the identity room. See spec §7.1.

**Reply inbox.** OPTIONAL hint in a persona's public outbox indicating
where they prefer to observe replies and mentions. Repliers SHOULD
include these destinations in fan-out. Analogous to NIP-65's `read`
marker. See spec §7.1.

**Scoped outbox.** A persona's audience-restricted set of additional
outbox rooms, recorded as `m.heterodyne.outbox.scoped.v1` state events
inside friend-circle or community rooms (NOT the identity room).
Visible only to members of the advertising room. See spec §7.2.

**Successor / predecessor.** Roles in the identity chain. The outgoing
npub publishes a successor pointer in its identity room; the incoming
npub publishes a predecessor pointer in its identity room. Both must
match for the chain step to be valid.

**Topic tag.** A namespaced label attached to a Heterodyne room's
kind state event indicating subject area ("tech", "photos",
"fediverse"). Namespaces SHOULD follow reverse-domain notation or
recognized ISO classifications. Lets followers subscribe selectively
by topic across a persona's broadcast rooms. See spec §5.1.

**Wrap mode.** Whether an event carries the full signed Nostr payload
(**wrapped**) or omits the Nostr signature (**bare**). Defaults vary by
room kind; see spec §4.4.

**Wrapped event.** A Heterodyne event of type `m.heterodyne.note.v1`
carrying a verbatim signed Nostr event. Cross-protocol authenticity is
preserved; the event can be lifted to a vanilla Nostr relay 1:1.

**Wrapping secret.** The user-controlled secret (passphrase, recovery
phrase, or OS-keystore-protected material) that wraps the persona's
encrypted `nsec` backup in the config room. Argon2id (or equivalent
memory-hard KDF) derives the wrapping key when the secret is a
passphrase. See spec §3.8.3, §9.6.
