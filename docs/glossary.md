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

**Archive URL.** A HTTPS endpoint advertised in
`m.heterodyne.archive.v1` in a persona's identity room from which
a receiver can fetch the underlying Nostr event JSON when Nostr
relays do not have it. The archive is operated by the publisher
(or a service of their choosing); the spec does not host,
specify, or guarantee any archive infrastructure. See spec §6.9.2.

**ATProto attached outbox.** An OPTIONAL publish target (a PDS
operated by or on behalf of the persona) that mirrors a configured
subset of the persona's public Heterodyne feed to ATProto / Bluesky
for adoption reach. Non-load-bearing — the persona's canonical
identity and feed remain Nostr-anchored. See spec §11.6.

**ATProto link.** A double-signed cryptographic binding between a
persona's npub and an ATProto DID, published as
`m.heterodyne.atproto_link.v1` in the identity room and mirrored
as a `social.heterodyne.identityLink` record on the persona's PDS.
Receivers MUST verify both signatures before treating the link as
authentic. See spec §11.6.3.

**Attached outbox (general).** A non-load-bearing publish target
in an ecosystem other than the canonical Nostr + Matrix pair (e.g.,
a vanilla Nostr relay, an ATProto PDS). Provides reach without
changing trust roots. Future spec versions MAY define attached
outboxes for additional ecosystems.

**Bridge.** Cross-protocol translation logic between Nostr and Matrix
event formats. In Heterodyne the bridge is **client-side** — part
of the user's client implementation — not a separate process or
appservice.

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

**DID (Decentralized Identifier).** An ATProto-side identifier of
the form `did:web:<host>` (DNS+HTTPS-resolved) or `did:plc:<id>`
(resolved against the PLC directory). In Heterodyne, a DID is a
peer identifier — never canonical — used in §11.6 for the attached
ATProto outbox and as an optional KERI witness key. See spec §11.6.2.

**Distribution list.** UX label for a categorized outbox room (e.g.,
"close friends", "work"). Implementation is a normal Matrix room with
the identity holder as admin and appropriate membership.

**Fallback.** A vanilla-Matrix-compatible rendering inside a wrapped
event's content. Vanilla Matrix clients render the fallback;
Heterodyne clients ignore it and render from the embedded Nostr event.
RECOMMENDED for `kind:1` posts; OMITTED for non-text Nostr kinds. See
spec §4.2, §11.5.

**Feed index (`kind:31007`).** A Nostr replaceable event listing
the event ids of a persona's (or moderator's) curated posts in
intended display order. Each Heterodyne-managed room a persona
posts into is keyed by `<room_id>:<page_id>` in the event's `d`
tag. The index is signed by the persona's epoch key directly,
making it tamper-evident: no homeserver or third party can rewrite
it. Plaintext on the persona's write relays for public rooms;
NIP-44 gift-wrapped to room members for private rooms. Bounded at
500 `e`-tag entries per event; longer feeds are paginated via
`previous_index` tags. Replaces the v0.1.4 `m.heterodyne.feed_status.v1`
Matrix state event. See spec §6.7.

**Feed status.** Deprecated v0.1.4 term for what v0.2.0 calls the
"feed index." The `m.heterodyne.feed_status.v1` Matrix state event
is no longer produced by conformant v0.2.0 clients; verifiers MAY
honor it for read-back compatibility with v0.1.4 publishers.

**Friend circle.** Synonym for distribution list. Different UX surface
("here are my close friends"), same underlying construct (a Matrix
room).

**Heterodyne-aware relay.** An OPTIONAL relay profile (per ADR-022)
defined as a strict superset of a vanilla NIP-01 relay: vanilla Nostr
clients use it unchanged, while Heterodyne clients can use added
KEL-aware reputation continuity, optional KEL-aware discovery, and a
passive witness-receipt store. Advertised via NIP-11. Baseline
conformance never depends on it. See spec §10.6.

**Heterodyne client library.** A conformant implementation of the
protocol's security-critical logic (event composition, signing,
delegation checking, feed-index maintenance, retrieval). The spec
is implementation- and language-agnostic; conformance is determined
by the test vectors (§14), not by language or packaging. See spec
§10.2.

**Indexed event.** An event that belongs in a persona's curated
feed view and therefore appears as a `kind:31007` `e`-tag entry.
Default classification by kind is given in spec §6.8.1; a publisher
MAY override per-event via the `["heterodyne_index", "true"|"false"]`
tag. Contrast with non-indexed event.

**Informal voucher.** An undeclared friend who publishes a signed
`kind:31008` social vouch (§3.5.5) for a persona's key during recovery.
Carries a small capped weight (RECOMMENDED ≤1% of a declared witness)
that can never meet the rotation threshold on its own; surfaced for
manual, user-confirmed promotion into the declared witness set (the
web-of-trust snowball). Contrast **Peer witness**. See spec §3.5.5,
§3.12.3.

**Involuntary re-anchor.** Recovery procedure (per ADR-021) for when a
persona's identity-room homeserver is permanently gone and no mirror
replica remains: the persona republishes a cold-root `kind:31005` to
relays (authoritative), with follower-cached identity state bridging
verification until it propagates. See spec §3.12.

**KERI (Key Event Receipt Infrastructure).** A family of identity
protocols characterized by inception and rotation events
co-signable by the identity holder plus peer witnesses; witnesses
provide social-continuity attestation without granting authority.
In Heterodyne (Cold Root + Epoch Keys design, §3.5), inception and
`committed`-strategy rotation are signed by the cold root, while
`none`-strategy rotation is signed by the prior epoch key and relies
on witness attestations; peer witnesses (including ATProto signatures
per §11.6.7) MAY be added. (No Matrix MSK co-signature — that
requirement was removed per ADR-018.) Particularly load-bearing for `none`-strategy
rotation where no cryptographic chain to the prior cold root
exists.

**`heterodyne_nostr_sig`.** Optional field on a bare `m.room.message`
event carrying a Nostr-signed proof of the message content. Lets a
sender opt in to authenticity without abandoning the `m.room.message`
rendering path. See spec §4.3.

**Hide-bare-events.** A user preference in
`m.heterodyne.user_prefs.v1` controlling whether bare
`m.room.message` events from vanilla Matrix clients render normally,
render with a warning indicator, or are hidden. Default:
accept-with-warning. See spec §3.8.3, §11.1.

**Identity chain.** Deprecated v0.1.4 term for the single-key
successor / predecessor / revoke mechanism. Replaced in v0.2.0 by
KERI inception and rotation events (§3.5).

**Identity pointer (`kind:31005`).** Authoritative Nostr
replaceable event published to a persona's NIP-65 write relays
naming the persona's currently active Matrix identity room. Lets
vanilla Nostr clients (or Heterodyne clients discovering a persona
via Nostr) find the identity context. Verifiers MUST prioritize the
latest valid `kind:31005` over any locally cached room ID, which
makes the identity room itself disposable. See spec §3.2, §11.3.

**Identity room.** A Matrix room owned by a persona's identity
holder whose state events bind the npub to its delegated Matrix
accounts, declare its outbox addresses, and record the persona's
KERI key event log. The identity room is a **disposable container**
— if compromised at the Matrix layer, the persona publishes a fresh
`kind:31005` identity pointer naming a new room, and followers
follow the pointer without needing to abandon the npub. See spec
§3.2.

**`matrix:` URI.** Canonical Matrix reference format per MSC2312:
`matrix:roomid/<id-without-bang>:<server>?via=<server>` for rooms by
ID; `matrix:r/<alias-without-hash>:<server>` for rooms by alias;
`matrix:u/<user-without-at>:<server>` for users. New constructs in the
spec use the URI form; legacy `{room_id, via}` structured form
remains valid in §7. See spec §2.

**Mirror group.** An `m.heterodyne.mirror_group.v1` state event (per
ADR-020) naming a persona's full-replica rooms across the homeservers
it controls and which replica is the **primary** (the one named by the
cold-root `kind:31005` pointer / `kind:31007` feed index). On primary
failure the persona promotes a replica by republishing `kind:31005`.
See spec §3.11.

**Moderator.** A persona authorized in `m.heterodyne.moderators.v1`
to issue NIP-72 approval signatures (and, in the current 0.x draft,
only NIP-72 approval signatures) for a moderated `public_discussion`
room. Identified by
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

**Non-indexed event.** An event that is ephemeral or decorative
(reactions, zaps, follow-list updates, deletion requests, moderation
reports) and is NOT referenced from a `kind:31007` feed index.
Visible on Nostr relays (or in encrypted rooms) but rendered
contextually rather than as a standalone feed item. See spec §6.8.

**npub / nsec.** A Nostr public / secret key in bech32 form (`npub1...` /
`nsec1...`), corresponding to a `secp256k1` keypair. The npub is the
canonical Heterodyne identity for a persona.

**Outbox room.** A Matrix room where a persona publishes content. The
persona is the room admin. Followers subscribe by joining. Multiple
outbox rooms per persona enable distribution-list semantics.

**PDS (Personal Data Server).** ATProto term for the server hosting
a user's signed records. In Heterodyne the PDS is the publish target
for an attached ATProto outbox (§11.6); the spec is agnostic between
hosted (Bluesky-operated) and self-hosted PDSes, though self-hosted
is RECOMMENDED for resilience.

**Peer witness.** A third-party signer on a KERI inception or
rotation event whose signature provides a social-continuity
attestation without granting authority. Witness signatures do NOT
satisfy any MUST signature requirement. Particularly important for
`none`-strategy rotation where they are the primary continuity
signal. ATProto DIDs are one source of peer witness signatures
(§11.6.7).

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

**Retrieval hint.** Optional third element of a `kind:31007`
`e`-tag carrying a relay URL where the referenced event can be
fetched via standard NIP-01 REQ. Covers the common retrieval case;
see spec §6.7.1, §6.9.1.

**Retrieval request / response / push.** Three Matrix event types
defined in v0.1.4 drafts for DM-based backfill of events that
could not be retrieved via Nostr relays. **Removed in v0.2.0**
because they constituted a Matrix-DM DoS / rate-limit vector;
historical retrieval is now Nostr-relay-only (Channel 1) plus the
publisher's optional user-hosted Web Archive (Channel 2). See
spec §6.9.

**Scoped outbox.** A persona's audience-restricted set of additional
outbox rooms, recorded as `m.heterodyne.outbox.scoped.v1` state events
inside friend-circle or community rooms (NOT the identity room).
Visible only to members of the advertising room. See spec §7.2.

**Social vouch (`kind:31008`).** A signed Nostr event by an informal
voucher (§3.5.5) attesting a persona's new key at a given KERI sequence
during recovery. Capped, non-authoritative; cannot meet a rotation
threshold alone. See **Informal voucher**.

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
