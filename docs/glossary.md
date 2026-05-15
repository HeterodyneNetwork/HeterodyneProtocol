# Glossary

Terms used in the Heterodyne specification, in alphabetical order. The
canonical use of each term is in [`spec/heterodyne.md`](spec/heterodyne.md);
this glossary exists so the spec body itself can stay tight.

**Bare event.** A Heterodyne event published as a plain `m.room.message`
with no Nostr signature. Deniable inside an E2EE Matrix room. The default
wrap mode for DMs. See spec §4.3.

**Blind server / blind homeserver.** A homeserver that handles E2EE
traffic but cannot read its plaintext. Heterodyne's client-side bridge
model preserves this property for all private rooms.

**Bridge.** Cross-protocol translation logic between Nostr and Matrix
event formats. In Heterodyne the bridge is **client-side**
(`heterodyne-core`), not a separate process or appservice.

**Delegation.** An attestation in an identity room authorizing a specific
Matrix MXID to publish events on behalf of the persona's npub.
Double-signed by both the npub (proving authorization) and the MXID
(proving acknowledgement). See spec §3.3.

**Distribution list.** UX label for a categorized outbox room (e.g.,
"close friends", "work"). Implementation is a normal Matrix room with the
identity holder as admin and appropriate membership.

**Fallback.** A vanilla-Matrix-compatible rendering inside a wrapped
event's content. Vanilla Matrix clients render the fallback; Heterodyne
clients ignore it and render from the embedded Nostr event.

**Friend circle.** Synonym for distribution list. Different UX surface
("here are my close friends"), same underlying construct (a Matrix room).

**`heterodyne-core`.** The reference Rust crate implementing the
protocol. Compiled to WASM for browser/mobile clients; used natively in
desktop and headless deployments. Carries the security-critical logic so
client surfaces don't have to re-implement it.

**`heterodyne_nostr_sig`.** Optional field on a bare `m.room.message`
event carrying a Nostr-signed proof of the message content. Lets a sender
opt in to authenticity without abandoning the `m.room.message` rendering
path. See spec §4.3.

**Identity chain.** The linked succession of npubs a persona has rotated
through. Each rotation produces a paired `m.heterodyne.successor.v1` (in
the outgoing identity room) and `m.heterodyne.predecessor.v1` (in the
incoming identity room). Followers walk the chain to follow a persona
across key rotations. See spec §3.5.

**Identity room.** A Matrix room owned by a persona's identity holder
whose state events bind the npub to its delegated Matrix accounts,
declare its outbox addresses, and record the identity chain. The room ID
is the persona's canonical Heterodyne address.

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

**Successor / predecessor.** Roles in the identity chain. The outgoing
npub publishes a successor pointer in its identity room; the incoming
npub publishes a predecessor pointer in its identity room. Both must
match for the chain step to be valid.

**Wrap mode.** Whether an event carries the full signed Nostr payload
(**wrapped**) or omits the Nostr signature (**bare**). Defaults vary by
room kind; see spec §4.4.

**Wrapped event.** A Heterodyne event of type `m.heterodyne.note.v1`
carrying a verbatim signed Nostr event. Cross-protocol authenticity is
preserved; the event can be lifted to a vanilla Nostr relay 1:1.
