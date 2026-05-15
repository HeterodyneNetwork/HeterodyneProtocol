# Heterodyne Protocol Specification

**Version:** 0.1 (DRAFT)
**Status:** Working draft. §3 (identity), §4 (envelope), §5 (rooms),
§6 (publishing), §7 (discovery), §10 (bridge) are drafted; §8, §9,
§11, §12, §13, §14 remain as stubs. Not stable. Not yet suitable for
independent re-implementation or interoperability claims.

This document is the normative specification for the Heterodyne protocol: a
decentralized social network built by publishing Nostr events into Matrix
rooms. It is the single source of truth that any independently-implemented
Heterodyne client MUST follow to interoperate.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Table of contents

1. [Scope and non-goals](#1-scope-and-non-goals)
2. [Terminology](#2-terminology)
3. [Identity model](#3-identity-model) — **drafted**
4. [Event envelope](#4-event-envelope) — **drafted**
5. [Room taxonomy](#5-room-taxonomy) — **drafted**
6. [Publishing flow](#6-publishing-flow) — **drafted**
7. [Discovery and subscription](#7-discovery-and-subscription) — **drafted**
8. [Moderation](#8-moderation) — *stub*
9. [Encryption guarantees](#9-encryption-guarantees) — *stub*
10. [Bridge and client model](#10-bridge-and-client-model) — **drafted**
11. [Interoperability with vanilla Nostr and vanilla Matrix](#11-interoperability) — *stub*
12. [Versioning and capability negotiation](#12-versioning-and-capability-negotiation) — *stub*
13. [Security model](#13-security-model) — *stub (see also [`../security/threat-model.md`](../security/threat-model.md))*
14. [Conformance and test vectors](#14-conformance-and-test-vectors) — *stub (see also [`vectors/`](vectors/))*

## 1. Scope and non-goals

### 1.1 Scope

Heterodyne defines:

- An **identity model** binding a Nostr `secp256k1` keypair (the canonical
  identity) to one or more Matrix accounts that act as delegated publishers.
- An **event envelope** for carrying signed Nostr events inside Matrix
  events, with an explicit deniability mode where the Nostr signature is
  omitted.
- A **room taxonomy** distinguishing public broadcast, public moderated,
  private community, and direct-message rooms, each with conventional
  Matrix configurations.
- A **publishing flow** describing how a client fans out a single
  user-level post to one or more rooms and optionally to vanilla Nostr
  relays.
- A **discovery mechanism** so followers can locate an identity's outbox
  rooms and alternate addresses without consulting a central directory.
- A **moderation layering** combining Matrix room-level ACLs with
  NIP-72-style approval signatures for editorial control.
- A **bridge model** that is purely client-side; no homeserver software
  modifications are required.

### 1.2 Non-goals

Heterodyne explicitly does not:

- Define a new transport, relay protocol, or homeserver. It composes the
  Matrix and Nostr networks as they exist.
- Reserve new Nostr event kinds for user content. Existing NIP-defined
  kinds are used verbatim inside the envelope. (A small range of
  Heterodyne-reserved kinds for identity-room state events is defined in
  §3; these never appear as user-visible posts.)
- Provide a global directory of users. Discovery is consent-driven and
  relationship-mediated.
- Replace or compete with vanilla Nostr or vanilla Matrix. A Heterodyne
  user can interact with both networks; a vanilla client of either can
  interact with a Heterodyne user with reduced fidelity.

## 2. Terminology

Defined terms appear in **bold** on first use. The canonical glossary is
[`../glossary.md`](../glossary.md); the most load-bearing terms are
restated here.

- **npub** / **nsec** — a user's Nostr public key (`secp256k1`,
  bech32-encoded with `npub1...` prefix) and secret key (`nsec1...`
  prefix). The npub is the canonical Heterodyne identity.
- **Persona** — a distinct Heterodyne identity (one npub, one identity
  room, one set of delegations). A user MAY hold multiple personas; the
  protocol does not link them.
- **Identity room** — a Matrix room owned by the persona's identity holder
  whose state events bind the npub to its delegated Matrix accounts,
  declare its outbox rooms, and record key-rotation chains.
- **Delegation** — a state event in an identity room authorizing a specific
  Matrix MXID to publish events on behalf of the persona's npub.
  Double-signed by both the npub and the MXID.
- **Outbox room** — a Matrix room where a persona broadcasts content. The
  persona is the room admin. Per-category (public, close-friends, work,
  custom labels).
- **Friend circle** / **distribution list** — UX terms for a categorized
  outbox room. Implementation is just a Matrix room with appropriate power
  levels.
- **Wrap mode** — whether a published event carries the full signed Nostr
  payload (**wrapped**, authentic, forwardable to vanilla Nostr) or only
  Matrix-layer content (**bare**, deniable inside an E2EE room).
- **Identity chain** — the linked succession of npubs a persona has rotated
  through. Followers walk the chain to follow a persona across key
  rotations.

## 3. Identity model

### 3.1 The npub is canonical

A Heterodyne identity is a Nostr `secp256k1` keypair, referred to by its
public key in bech32 form (`npub1...`). The npub is the authoritative
subject of all attestations made by or about this identity. Matrix
accounts in this specification are *delegated publishers* of the npub, not
identities in their own right.

A single human MAY hold any number of npubs (personas). The protocol does
not attempt to link personas to humans; this is a deliberate privacy
property.

### 3.2 Identity room

For each persona an identity holder maintains, there MUST exist exactly
one **identity room**: a Matrix room whose state binds the npub to the
rest of the persona's Heterodyne configuration. The identity room SHOULD
be created on a homeserver the identity holder controls or trusts; it MAY
be replicated across homeservers via standard Matrix federation for
resilience.

The room MUST contain:

- An `m.heterodyne.room_kind.v1` state event with
  `kind: "identity_room"` (§5.1).
- An `m.heterodyne.root.v1` state event proving npub ownership of the
  room (§3.2.1).
- Zero or more `m.heterodyne.delegation.v1` state events, one per active
  delegated Matrix account, keyed by MXID (§3.3).
- At most one `m.heterodyne.outbox.public.v1` state event listing the
  persona's public-facing outbox (§7.1).
- Zero or more `m.heterodyne.successor.v1`,
  `m.heterodyne.predecessor.v1`, and `m.heterodyne.revoke.v1` state
  events forming the identity chain (§3.5).

The Matrix room ID of the identity room is the persona's canonical
Heterodyne address. Resolving a persona means joining (or peeking) the
room and reading its state.

#### 3.2.1 Root attestation

The `m.heterodyne.root.v1` state event:

```json
{
  "type": "m.heterodyne.root.v1",
  "state_key": "",
  "content": {
    "spec_version": "0.1",
    "nostr_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<32-byte hex of the npub>",
      "created_at": 0,
      "kind": 31000,
      "tags": [
        ["heterodyne", "root"],
        ["matrix_room", "<this room's room_id>"]
      ],
      "content": "",
      "sig": "<64-byte hex>"
    }
  }
}
```

The `nostr_attestation` field is a valid Nostr event of Heterodyne-reserved
kind `31000`, signed by the npub's secret key. The `matrix_room` tag MUST
equal the Matrix room ID this state event resides in. Verifiers MUST
reject the attestation if either the Nostr signature fails or the
`matrix_room` tag does not match.

### 3.3 Delegations

Each Matrix account that publishes on behalf of the npub is bound by an
`m.heterodyne.delegation.v1` state event in the identity room, keyed by
the MXID:

```json
{
  "type": "m.heterodyne.delegation.v1",
  "state_key": "@alice:matrix.org",
  "content": {
    "spec_version": "0.1",
    "nostr_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<32-byte hex of the npub>",
      "created_at": 0,
      "kind": 31001,
      "tags": [
        ["heterodyne", "delegation"],
        ["matrix_mxid", "@alice:matrix.org"],
        ["matrix_master_key", "<base64 of MXID's cross-signing master public key>"],
        ["valid_until", ""]
      ],
      "content": "",
      "sig": "<64-byte hex from npub>"
    },
    "matrix_acknowledgement": {
      "acknowledges": "<nostr_attestation.id>",
      "signatures": {
        "@alice:matrix.org": {
          "ed25519:<device_id_or_master_key_id>": "<Matrix signature over a canonical JSON of nostr_attestation.id>"
        }
      }
    }
  }
}
```

A delegation is **active** if and only if:

1. The Nostr signature on `nostr_attestation` validates against the npub.
2. The `matrix_acknowledgement` signature validates against the MXID's
   currently-published cross-signing master key (or a device key chained
   to it).
3. `valid_until` is empty (no expiry) or strictly greater than current
   time.
4. No later `m.heterodyne.delegation.v1` with the same `state_key` and a
   `revoked: true` content flag has overridden it, AND no
   `m.heterodyne.revoke.v1` state event names this delegation's
   attestation `id`.

Receivers verifying a wrapped event (§4.2) MUST check that the event's
`nostr.pubkey` matches the npub asserted by the sender's identity room
and that an active delegation for the sending MXID exists. If verification
fails, the receiver MUST mark the event untrusted; clients MAY render with
a warning or suppress entirely.

### 3.4 Multiple personas

A user MAY operate any number of distinct personas. Each persona has its
own npub, its own identity room, and its own set of delegations. Personas
are not linked at the protocol level. A user's client MAY store
correlations between personas in local-only, encrypted-at-rest storage
for the user's own UI convenience, but MUST NOT publish those
correlations to any room or relay.

### 3.5 Identity chain: persona-preserving key rotation

Heterodyne supports persona-preserving key rotation, which vanilla Nostr
does not natively. A persona's npub MAY be rotated by issuing a paired
succession:

- The **outgoing npub** publishes `m.heterodyne.successor.v1` in its own
  (outgoing) identity room:

```json
{
  "type": "m.heterodyne.successor.v1",
  "state_key": "",
  "content": {
    "spec_version": "0.1",
    "nostr_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<outgoing npub hex>",
      "created_at": 0,
      "kind": 31002,
      "tags": [
        ["heterodyne", "successor"],
        ["successor_npub", "<incoming npub hex>"],
        ["successor_identity_room", "<incoming identity room_id>"],
        ["effective_at", "0"]
      ],
      "content": "",
      "sig": "<sig from outgoing npub>"
    }
  }
}
```

- The **incoming npub** publishes `m.heterodyne.predecessor.v1` in the
  incoming identity room, mirror-signed by the new key, referencing the
  same outgoing npub and the outgoing identity room.

The chain is **valid** only when both directions match: both events
reference each other and both signatures verify. Followers MUST walk the
chain to find the persona's current npub before rendering content.

Events signed by the outgoing npub with `created_at` strictly after
`effective_at` MUST be rejected, with the sole exception of the successor
attestation itself.

#### 3.5.1 Revocation

If a key is suspected compromised, the persona issues
`m.heterodyne.revoke.v1` from the **successor** identity room (because the
predecessor's keys may be in attacker hands and therefore cannot be
trusted to self-revoke):

```json
{
  "type": "m.heterodyne.revoke.v1",
  "state_key": "<revoked npub hex>",
  "content": {
    "spec_version": "0.1",
    "nostr_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<current npub hex>",
      "created_at": 0,
      "kind": 31003,
      "tags": [
        ["heterodyne", "revoke"],
        ["revoked_npub", "<revoked npub hex>"],
        ["revoked_at", "0"],
        ["reason", "compromise"]
      ],
      "content": "",
      "sig": "<sig from current npub>"
    }
  }
}
```

`reason` MUST be one of: `compromise`, `rotation`, `loss`, `other`.

Verifiers MUST reject any event signed by a revoked npub with
`created_at` strictly after `revoked_at`. Events signed before
`revoked_at` retain their validity — the past is not retroactively erased
— subject to a reasonable clock-skew tolerance the client MAY enforce.

### 3.6 Identity discovery

A Heterodyne client resolves "what npub does this Matrix MXID represent?"
as follows:

1. Read the MXID's Matrix profile. The profile SHOULD contain a custom
   field `m.heterodyne.identity_room` whose value is the persona's
   identity room ID. (This requires no Matrix spec change; custom profile
   fields are permitted.)
2. Peek into or join the identity room.
3. Read the `m.heterodyne.root.v1` state event. Verify its Nostr signature
   and the `matrix_room` tag.
4. Find the `m.heterodyne.delegation.v1` state event keyed by the MXID.
   Verify both Nostr and Matrix signatures and confirm it is currently
   active per §3.3.
5. Walk any `m.heterodyne.successor.v1` chain to the current persona npub.
6. Return: the current npub, the persona's outbox addresses (§7), and the
   chain history.

A Heterodyne client SHOULD cache identity-room state locally and
revalidate on a TTL or on receipt of new state events the homeserver
advertises via `/sync`.

### 3.7 Failure modes

- **Identity room unreachable**: if all homeservers replicating the room
  are unavailable, the persona's bindings cannot be verified. Cached
  state MAY be used with an explicit "identity verification stale" UI
  signal. The persona's npub remains usable on vanilla Nostr relays
  regardless.
- **Conflicting state events**: standard Matrix state resolution
  determines winners. Conflicting Heterodyne state is the room admin's
  responsibility to clean up; the spec does not introduce additional
  resolution rules.
- **Compromised delegation**: revoke the delegation per §3.3 and rotate
  Matrix credentials. Already-published events from before the
  delegation's revocation remain valid; subsequent events from that MXID
  fail verification.
- **Compromised root key**: rotate via §3.5 from a clean device. The
  chain preserves persona continuity. Issue a revocation per §3.5.1 to
  invalidate the attacker's window.

## 4. Event envelope

### 4.1 Two envelope types

Heterodyne supports two envelope types, distinguished by Matrix event
`type`:

| Event type | Wrap mode | Forwardable to vanilla Nostr | Vanilla Matrix renders | Use |
|---|---|---|---|---|
| `m.heterodyne.note.v1` | wrapped (Nostr-signed) | yes (1:1 unwrap) | partial (via `fallback`) | authenticity required |
| `m.room.message` (with optional `heterodyne_nostr_sig`) | bare or opt-in wrap | only if `heterodyne_nostr_sig` present | yes (natively) | deniability or vanilla compatibility |

Senders choose the mode per-event based on the room-kind defaults (§4.4)
and explicit user override.

### 4.2 Wrapped event (`m.heterodyne.note.v1`)

```json
{
  "type": "m.heterodyne.note.v1",
  "content": {
    "spec_version": "0.1",
    "nostr": {
      "id": "<32-byte hex>",
      "pubkey": "<npub hex>",
      "created_at": 0,
      "kind": 1,
      "tags": [["e", "..."], ["p", "..."]],
      "content": "Hello, decentralized world.",
      "sig": "<64-byte hex>"
    },
    "fallback": {
      "msgtype": "m.text",
      "body": "Hello, decentralized world."
    }
  }
}
```

Normative rules:

- The `nostr` field MUST contain a valid Nostr event per NIP-01.
- The Nostr event MUST be byte-identical to what would be published on a
  vanilla Nostr relay for the same content. Re-publishing to a relay is a
  1:1 lift with no transformation.
- Receivers MUST verify `nostr.sig` against `nostr.pubkey`. Invalid
  signature → reject.
- Receivers MUST verify that `nostr.pubkey` matches the npub bound to the
  sending Matrix MXID via an active delegation in that npub's identity
  room (§3.3). Mismatched pubkey → reject as impersonation.
- The `fallback` field is OPTIONAL but RECOMMENDED for Nostr kinds whose
  content can reasonably be represented as `m.text` (notably kind `1`
  microblog posts). It permits vanilla Matrix clients to render something
  legible. Heterodyne clients MUST ignore `fallback` and render from
  `nostr` directly.
- All Nostr event kinds used inside `nostr` are *existing* NIP-defined
  kinds (1 microblog, 3 follows, 7 reactions, 30023 long-form, 9735 zap
  receipt, …) — Heterodyne does not introduce a new general-purpose kind
  range for user content. The reserved 31000-range identity-room kinds
  defined in §3 appear in state events, never in `m.heterodyne.note.v1`.

### 4.3 Bare event (`m.room.message`)

A **bare event** is a normal Matrix message — `m.room.message` with the
usual `msgtype` semantics — that carries no Nostr signature and therefore
no cross-protocol authenticity guarantee. Inside an E2EE room a bare event
is deniable in the same way any encrypted Matrix message is: only
recipients know the sender, and the sender can claim the homeserver
forged it.

A bare event MAY include an OPTIONAL `heterodyne_nostr_sig` field carrying
a Nostr-signed proof of the same content, for senders who want
authenticity without giving up the `m.room.message` rendering path:

```json
{
  "type": "m.room.message",
  "content": {
    "msgtype": "m.text",
    "body": "I really sent this.",
    "heterodyne_nostr_sig": {
      "id": "<32-byte hex>",
      "pubkey": "<npub hex>",
      "created_at": 0,
      "kind": 1,
      "tags": [["heterodyne", "bare_sig"]],
      "content": "I really sent this.",
      "sig": "<64-byte hex>"
    }
  }
}
```

Normative rules for bare events:

- A receiver that does not understand `heterodyne_nostr_sig` (vanilla
  Matrix client) MUST be able to render the message exactly as a normal
  `m.room.message`. The optional field is purely additive.
- A Heterodyne receiver that finds `heterodyne_nostr_sig` MUST validate
  the embedded Nostr event per NIP-01, verify the signature, and verify
  that the embedded `content` matches the Matrix `body` byte-for-byte
  after Unicode NFC normalization. The identity-room delegation check
  from §3.3 applies. On full success, display an "authenticated"
  indicator; on any failure, display a "signature invalid" indicator but
  still render the message body.

### 4.4 Wrap mode defaults per room kind

| Room kind | Default wrap mode | Override |
|---|---|---|
| Public unencrypted broadcast | wrapped | none — bare events MUST be rejected |
| Public moderated community | wrapped | none — bare events MUST be rejected |
| Private E2EE community | wrapped | sender MAY send bare per-event |
| Private E2EE DM | bare | sender MAY include `heterodyne_nostr_sig` |

Rationale: deniability matters most in DMs, authenticity matters most in
public rooms. Private communities are in the middle but lean authentic
because you usually want trusted peers to know it's really you.
See [`../architecture.md`](../architecture.md) for the full design
rationale.

### 4.5 Verification summary

A receiving Heterodyne client MUST perform the following checks before
rendering any event:

1. Matrix-layer integrity (handled by the Matrix SDK; mandatory, not
   restated here).
2. If event type is `m.heterodyne.note.v1`:
   - Validate `nostr` per NIP-01.
   - Verify `nostr.sig`.
   - Resolve the sending MXID's identity room and verify an active
     delegation binds `nostr.pubkey` to that MXID.
   - Verify the persona's identity chain has not revoked or rotated past
     this signature (§3.5, §3.5.1).
3. If event type is `m.room.message` and `heterodyne_nostr_sig` is
   present, perform the bare-event signed-attachment checks from §4.3.
4. If event type is `m.room.message` without `heterodyne_nostr_sig`,
   render per Matrix semantics; no Heterodyne checks beyond room-kind
   admission (§4.4) apply.

## 5. Room taxonomy

Heterodyne defines five conventional room kinds. Each is a normal Matrix
room; the "kind" is a UX and conformance contract recorded explicitly as
a state event so clients can present appropriate UI and so other
Heterodyne clients know which behaviors apply.

### 5.1 Kind state event

Every Heterodyne-managed room MUST carry an `m.heterodyne.room_kind.v1`
state event with empty state key:

```json
{
  "type": "m.heterodyne.room_kind.v1",
  "state_key": "",
  "content": {
    "spec_version": "0.1",
    "kind": "identity_room | public_broadcast | public_moderated | private_community | dm",
    "topics": [
      {"namespace": "com.example.tags", "tag": "tech"},
      {"namespace": "com.example.tags", "tag": "rust"}
    ]
  }
}
```

The `kind` field MUST be one of:

- `identity_room` — see §3.2; the conventions in §5.2–§5.6 do not
  apply.
- `public_broadcast` — unencrypted; admin broadcasts; everyone else
  reads.
- `public_moderated` — unencrypted; multiple posters; moderator approval
  gates the feed view (§8).
- `private_community` — E2EE; invitation-only; multiple posters by
  default.
- `dm` — E2EE; two participants or small group; one-to-one or
  many-to-many conversation.

The `topics` array is OPTIONAL but RECOMMENDED for `public_broadcast`,
`public_moderated`, and `private_community` kinds. It tags the room with
one or more topic identifiers; followers can subscribe selectively.
Topic namespaces SHOULD follow reverse-domain notation
(`com.example.tags`) or recognized ISO classifications, mirroring the
NIP-32 labeling convention. Heterodyne reserves the namespace
`org.heterodyne.topics` for future canonical tags.

### 5.2 `public_broadcast`

A room where a single persona (or a small set of co-administrators)
broadcasts content to subscribers. Most Heterodyne users are expected
to operate multiple `public_broadcast` rooms, each topic-tagged
differently ("my-tech-feed", "my-photography-feed"). Followers
subscribe per-topic by joining the rooms whose tags interest them.

REQUIRED:

- `m.room.create.room_version`: latest stable Matrix room version.
- `m.room.encryption`: absent — the room is intentionally unencrypted.
- `m.room.history_visibility`: `world_readable`.
- `m.room.guest_access`: `can_join`.
- Wrap mode: wrapped (`m.heterodyne.note.v1`). Bare events
  (`m.room.message`) MUST be rejected by Heterodyne clients on read and
  SHOULD be rejected by the persona's client on write per §4.4.

RECOMMENDED `m.room.power_levels`:

- `users_default`: 0.
- `events_default`: 50 (only the persona and co-admins can post).
- `state_default`: 100 (only the persona controls room state).
- The persona's MXID (and any co-admin MXIDs): 100.

### 5.3 `public_moderated`

Like `public_broadcast` but with multiple posters whose messages
surface in the moderated feed only after a moderator approval signature
(§8). Conceptually equivalent to a subreddit or a moderated mailing
list.

REQUIRED `m.room.create`, `m.room.history_visibility`,
`m.room.guest_access`, `m.room.encryption`: same as
`public_broadcast`.

REQUIRED wrap mode: wrapped.

RECOMMENDED `m.room.power_levels`:

- `users_default`: 0.
- `events_default`: 0 (members can post).
- `state_default`: 50 (only moderators control state).
- Moderator MXIDs: 50.
- Room owner MXID: 100.

The set of approving moderators MUST be advertised via an
`m.heterodyne.moderators.v1` state event (schema deferred to §8).

### 5.4 `private_community`

An E2EE room with invitation-controlled membership. Examples:
friend-circle rooms, work groups, family chats, semi-private interest
communities. Members typically all post; the configuration MAY also be
tuned for broadcast-only by raising `events_default`.

REQUIRED:

- `m.room.create.room_version`: latest stable.
- `m.room.encryption.algorithm`: `m.megolm.v1.aes-sha2` (today); the
  MLS variant once stabilized.
- Encrypted state events: MUST follow MSC4362. Any
  `m.heterodyne.outbox.scoped.v1` (§7.2), moderation, or kind-state
  events MUST be encrypted.
- `m.room.history_visibility`: `shared` or `invited`.
- `m.room.guest_access`: `forbidden`.
- `m.room.join_rules`: `invite`, or `restricted` to a parent Space or
  gating room.

DEFAULT wrap mode: wrapped (`m.heterodyne.note.v1`). Sender MAY opt to
send bare per-event for deniability within the room (§4.4).

RECOMMENDED `m.room.power_levels`:

- `users_default`: 0.
- `events_default`: 0 for chat-style circles; 50 for broadcast-style
  circles. The intended style SHOULD be reflected in the
  `m.heterodyne.room_kind.v1.topics` array as a meta-tag (e.g.,
  `org.heterodyne.style.chat` vs `org.heterodyne.style.broadcast`).
- `state_default`: 50 or 100.
- Owner MXID: 100.

### 5.5 `dm`

A standard Matrix DM room (two-participant or small-group) reused for
Heterodyne direct messaging. Configuration is whatever the Matrix
client SDK produces for a normal DM, with two soft constraints:

- The room MUST be E2EE.
- The `m.heterodyne.room_kind.v1` state event MUST declare
  `kind: "dm"`.

DEFAULT wrap mode: bare (`m.room.message`). Sender MAY include
`heterodyne_nostr_sig` for opt-in authenticity per message (§4.3).

### 5.6 Multi-room patterns

A persona is expected to maintain multiple Heterodyne rooms
simultaneously:

- Exactly one **identity room** (§3.2).
- Zero or more **`public_broadcast`** rooms, typically one per topic
  the persona broadcasts about. A persona SHOULD prefer multiple
  topic-tagged broadcast rooms over a single catchall room; this
  enables topic-selective subscription.
- Zero or more **`public_moderated`** communities the persona admins
  or participates in.
- Zero or more **`private_community`** rooms (friend circles,
  work-project-X, family).
- DM rooms as needed.

A persona MAY aggregate its public broadcast rooms into a Matrix
**Space** (MSC2946) advertised in the persona's public outbox (§7.1).
This gives a "subscribe to all my topics" affordance for followers;
the Space hierarchy lets followers descend to per-topic rooms.

A `private_community` room MAY list further Heterodyne rooms in its
own audience-scoped outbox advertisement (§7.2). This is how a "close
friends" room can advertise "I also keep an encrypted photo room you
can join" to its members without leaking that room's existence to
non-friends.

## 6. Publishing flow

Publishing is the act of taking one user-level intent (a post, a reply,
a reaction, a long-form article) and emitting it to one or more rooms
and zero or more vanilla Nostr relays. Heterodyne defines the structure
of those emissions and a small set of normative idempotency rules; the
spec deliberately leaves *how to schedule, batch, and retry* deliveries
as a client implementation choice.

### 6.1 One signed Nostr event per intent

A single user-level intent MUST correspond to exactly one signed Nostr
event, computed once from the user's nsec. That single event is then
fanned out to multiple destinations. The Nostr event `id` (SHA-256 over
the canonical Nostr serialization) is the idempotency token across the
entire fan-out.

Implementations MUST NOT re-sign the same intent multiple times.
Re-signing would defeat authenticity: receivers would see distinct
event `id`s for the same intent and could not deduplicate.

### 6.2 Destination set

For a single intent, the client computes a destination set:

| Destination | Wire form |
|---|---|
| `public_broadcast` room | `m.heterodyne.note.v1` (wrapped) |
| `public_moderated` room | `m.heterodyne.note.v1` (wrapped) |
| `private_community` room | `m.heterodyne.note.v1` (wrapped) or `m.room.message` (bare), per per-event choice |
| `dm` room | `m.room.message` (bare) or with `heterodyne_nostr_sig` |
| Vanilla Nostr relay | the unwrapped Nostr event published per NIP-01 |

The destination set is computed from:

- The user's explicit selection ("post to my tech feed and my
  close-friends room").
- The default audiences for the post type (configurable per client).
- The persona's outbox advertisements (§7), especially when replying
  to a specific event or quoting another persona's content.

### 6.3 Idempotency

The Nostr event `id` is the canonical idempotency token.

- Receivers SHOULD deduplicate by `id` when the same event arrives via
  multiple paths (e.g., wrapped via Matrix and unwrapped via a Nostr
  relay subscription).
- For Matrix delivery, the client MAY use the Nostr event `id` (or a
  derivative of it) as the `txn_id` for
  `PUT /_matrix/client/v3/rooms/{room}/send/{type}/{txn_id}` to
  leverage Matrix's per-transaction idempotency.
- For vanilla Nostr delivery, NIP-01 deduplication by `id` is automatic
  at relay level.

### 6.4 Best-effort fan-out: recommended patterns

The spec does NOT mandate a specific fan-out algorithm. Clients MAY
implement any of the following patterns, alone or in combination:

- **Optimistic concurrent.** Dispatch to all destinations in parallel;
  treat each as independent. Surface aggregate success/failure in UI.
  Suitable for low-stakes microblogging.
- **Best-effort with retry queue.** Dispatch concurrently; for each
  destination that fails, queue a retry with exponential backoff. The
  user sees "sent" once the first destination accepts; failures are
  surfaced as transient indicators that resolve as retries succeed.
- **Robust batched delivery.** Withhold the user-visible "sent" state
  until all destinations acknowledge. Suitable for DMs where delivery
  confirmation matters, or for high-value publications where the user
  wants explicit success across every audience.
- **Tiered.** Dispatch to high-priority destinations first (e.g., the
  user's own Matrix outbox rooms), then to secondary destinations
  (vanilla Nostr relays) without blocking user feedback on the latter.

Clients SHOULD surface partial-failure state in UI so the user can
detect when a post failed to reach an audience they care about. Clients
MAY require robust batched delivery for destinations the user
configures as delivery-critical (e.g., DMs to specific recipients,
posts to public broadcast rooms with subscriber counts the user wants
to guarantee).

### 6.5 Replies and threading

A reply is structurally a normal Nostr event of the appropriate kind
(typically `kind:1` for short-form, or NIP-23 `kind:30023` for long-form
comments) with NIP-10 `e` and `p` tags identifying the parent event and
its author. The wrap and fan-out rules above apply unchanged.

A reply's destination set typically includes:

- The room where the parent event was observed (so the conversation
  remains visible to the same audience).
- Optionally, additional rooms the replier wants to broadcast the reply
  to (e.g., quoting a public post into the replier's own
  `public_broadcast` feed).

If the parent author's public outbox (§7.1) advertises a
"reply inbox" hint (analogous to NIP-65's `read` marker), the replier's
client SHOULD include the listed rooms or relays in the destination set
so the parent author observes the reply on infrastructure they
control.

### 6.6 Mixing private Matrix and public Nostr in one fan-out

When a client fans an intent both to a private E2EE Matrix room and to
a public vanilla Nostr relay in the same operation, it publishes:

- To Matrix: the wrapped (or bare) event, inside Megolm.
- To the Nostr relay: the same unwrapped Nostr event, in the clear.

The user is responsible for ensuring this is intended. Clients SHOULD
warn before publishing to a public Nostr relay when the originating
context is a `private_community` or `dm` room — the same user-level
intent SHOULD NOT normally span both private-community Matrix rooms and
public Nostr relays. The warning is a UX guard, not a normative
restriction.

## 7. Discovery and subscription

Discovery in Heterodyne is **consent-driven** and
**audience-stratified**. A persona advertises different sets of feeds
to different audiences: public advertisements live in the identity
room where any peeker can read; audience-scoped advertisements live
inside the friend-circle or community rooms they pertain to, visible
only to members.

This design lets a single persona maintain a public face (advertised
to the world) and any number of private faces (advertised only to
chosen audiences) without leaking the existence of the private faces
to outsiders.

### 7.1 Public outbox advertisement

The persona's public-facing outbox lives in a single state event in
the identity room:

```json
{
  "type": "m.heterodyne.outbox.public.v1",
  "state_key": "",
  "content": {
    "spec_version": "0.1",
    "broadcasts": [
      {
        "room_id": "!techfeed:matrix.org",
        "kind": "public_broadcast",
        "topics": [{"namespace": "com.example.tags", "tag": "tech"}],
        "via": ["matrix.org", "tuwunel.example"]
      },
      {
        "room_id": "!photos:matrix.org",
        "kind": "public_broadcast",
        "topics": [{"namespace": "com.example.tags", "tag": "photos"}],
        "via": ["matrix.org"]
      }
    ],
    "communities": [
      {
        "room_id": "!fediverse-news:matrix.org",
        "kind": "public_moderated",
        "topics": [{"namespace": "com.example.tags", "tag": "fediverse"}],
        "role": "poster",
        "via": ["matrix.org"]
      }
    ],
    "nostr_relays": [
      {"url": "wss://relay.damus.io", "markers": ["write"]},
      {"url": "wss://relay.example", "markers": ["read", "write"]}
    ],
    "space": "#alice-space:matrix.org",
    "reply_inbox": {
      "rooms": ["!my-mentions:matrix.org"],
      "nostr_relays": [{"url": "wss://relay.example", "markers": ["read"]}]
    }
  }
}
```

Field semantics:

- `broadcasts`: `public_broadcast` rooms the persona admins. Each entry
  includes the room ID, kind, topic tags, and `via` servers as Matrix
  federation join hints.
- `communities`: `public_moderated` rooms the persona participates in
  as poster or moderator. The `role` field indicates relationship.
- `nostr_relays`: NIP-65-compatible relay list with `read`/`write`
  markers. Followers using vanilla Nostr clients consume this list
  directly per NIP-65.
- `space`: OPTIONAL pointer to a Matrix Space (MSC2946) aggregating
  the persona's public broadcast rooms.
- `reply_inbox`: OPTIONAL hint to repliers indicating where the
  persona prefers to observe replies and mentions. Analogous to
  NIP-65's `read` marker. Repliers' clients SHOULD include these
  destinations in the fan-out per §6.5.

This state event is NOT encrypted — its container (the identity room)
is intentionally peekable, and public discovery requires that the
event be readable by anyone.

A persona MUST publish at most one `m.heterodyne.outbox.public.v1`
state event per identity room. Updates replace the previous version
via standard Matrix state semantics.

### 7.2 Audience-scoped outbox advertisement

Inside any `private_community` or community-like room, a persona MAY
publish an `m.heterodyne.outbox.scoped.v1` state event listing
additional feeds visible to members of that specific room:

```json
{
  "type": "m.heterodyne.outbox.scoped.v1",
  "state_key": "<persona npub hex>",
  "content": {
    "spec_version": "0.1",
    "scope_note": "Close friends — these are the private feeds I share with you.",
    "broadcasts": [
      {
        "room_id": "!private-photos:matrix.org",
        "kind": "private_community",
        "topics": [{"namespace": "com.example.tags", "tag": "photos"}],
        "via": ["matrix.org"]
      }
    ],
    "communities": [
      {
        "room_id": "!drafts-circle:matrix.org",
        "kind": "private_community",
        "topics": [{"namespace": "com.example.tags", "tag": "long-form"}],
        "role": "owner",
        "via": ["matrix.org"]
      }
    ],
    "nostr_relays": []
  }
}
```

Rules:

- The state event lives in the **advertising room** (a friend-circle
  or community room), NOT in the identity room. Membership in the
  advertising room is the access gate.
- The advertising room MUST be E2EE; the state event MUST therefore be
  encrypted per §9 and MSC4362.
- `state_key` is the advertising persona's npub in hex. Different
  personas / co-administrators in the same room each get their own
  scoped advertisement, keyed by their own npub.
- Each listed `broadcasts` / `communities` entry SHOULD be joinable by
  the advertising room's current members. Heterodyne RECOMMENDS using
  Matrix's `restricted` join rule (MSC3083) with the advertising room
  (or a containing Space) as the gating room, which makes joinability
  automatic. If the listed feed uses `invite`-only join rules, the
  advertising persona accepts responsibility for issuing invites to
  advertising-room members on request.
- A persona SHOULD only advertise feeds whose topic tags are relevant
  to the advertising room's audience (e.g., do not advertise unrelated
  feeds just because the audience exists). This is a soft norm; the
  spec provides the topic-tag mechanism and trusts clients to curate.
- `nostr_relays` MAY list private or invite-only Nostr relay
  endpoints visible only to the advertising room's members.

### 7.3 Discovery flow

A follower discovering a persona executes the following:

1. **Resolve the persona's npub** from a Matrix MXID per §3.6, or from
   a vanilla Nostr `npub1...` reference.
2. **Find the identity room.** From the MXID's profile field
   `m.heterodyne.identity_room`, or from a Heterodyne-aware vanilla
   Nostr event tag (extraction tracked in
   [`extensions/nips/`](extensions/nips/)).
3. **Read the public outbox** (`m.heterodyne.outbox.public.v1`).
   Choose which advertised feeds (by topic) to subscribe to.
4. **Join chosen rooms.** For `public_broadcast` and
   `public_moderated`, `world_readable` permits peek without joining;
   full subscription is a join. For `private_community`, an invite is
   required.
5. **Once a member of a friend-circle or community room**, read any
   `m.heterodyne.outbox.scoped.v1` state events inside that room to
   discover further feeds gated behind this room's membership.
6. **Repeat step 5 transitively.** Inner circles MAY advertise even
   deeper circles; the discovery walk is finite (no cycles) because
   joining each inner room requires prior membership in its
   advertising room.

A follower's client SHOULD cache discovered outbox state and
revalidate on a TTL; it MUST revalidate on receipt of new outbox state
events via Matrix `/sync`.

### 7.4 Following semantics

"Following" a persona in Heterodyne is not a single act; it is a
collection of room subscriptions and (optionally) Nostr relay
subscriptions:

- Following a persona's public tech feed = joining their topic-tagged
  `public_broadcast` room.
- Following a persona across all public topics = joining their Space
  (if advertised) or each topic-tagged room individually.
- Following a persona privately = being invited to one of their
  `private_community` rooms.
- Following the persona via vanilla Nostr = subscribing to the
  `write`-marked relays in their public outbox per NIP-65.

A follower MAY express their following preferences in a private,
local-only data structure; the spec does NOT require a NIP-02-style
public follow list. Clients MAY OPTIONALLY emit a NIP-02 `kind:3`
event to vanilla Nostr relays for interop with non-Heterodyne Nostr
clients.

### 7.5 Cross-persona advertisement

A persona MAY advertise a relationship to another persona,
double-signed by both npubs:

```json
{
  "type": "m.heterodyne.related_persona.v1",
  "state_key": "<other persona npub hex>",
  "content": {
    "spec_version": "0.1",
    "relation": "same_holder",
    "this_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<this npub hex>",
      "created_at": 0,
      "kind": 31004,
      "tags": [
        ["heterodyne", "related_persona"],
        ["other_npub", "<other npub hex>"],
        ["relation", "same_holder"]
      ],
      "content": "",
      "sig": "<sig from this npub>"
    },
    "other_attestation": {
      "id": "<32-byte hex>",
      "pubkey": "<other npub hex>",
      "created_at": 0,
      "kind": 31004,
      "tags": [
        ["heterodyne", "related_persona"],
        ["other_npub", "<this npub hex>"],
        ["relation", "same_holder"]
      ],
      "content": "",
      "sig": "<sig from other npub>"
    }
  }
}
```

Rules:

- `relation` is one of: `same_holder` (both personas are operated by
  the same human), `endorses` (this persona vouches for the other),
  `endorsed_by` (this persona is vouched for by the other), or
  `linked` (some other declared relationship spelled out in
  `scope_note`).
- The attestation is valid only if BOTH `this_attestation` and
  `other_attestation` validate against their respective npubs. A
  single-signed cross-persona claim MUST be rejected.
- Cross-persona advertisements MAY live in the public outbox
  context (publicly linking the personas) OR in a scoped outbox
  context (revealing the link only to a chosen audience). The
  containing room's privacy determines the audience.
- A client MUST NOT infer persona relationships from any signal other
  than an explicit, valid, double-signed
  `m.heterodyne.related_persona.v1`.

## 8. Moderation

*Stub.* Two layers:

- **Matrix layer**: power levels, kicks/bans, `m.room.server_acl`,
  subscribable policy rooms (MSC2313). Determines who is in the room.
- **Heterodyne layer**: optional NIP-72-style approval signatures by
  appointed moderators determine which posts surface in the feed view.
  Matrix membership is the floor; Heterodyne approval is the editorial
  ceiling.

The two layers do not conflict; they answer different questions ("who is
in the room" vs. "whose posts surface in the feed").

## 9. Encryption guarantees

*Stub.* For private rooms: every Matrix event including state events MUST
be end-to-end encrypted. This inherits the `mxdx` invariant; encrypted
state events use MSC4362. Megolm is used today; MLS migration is tracked
separately and will be reflected here when ready.

## 10. Bridge and client model

### 10.1 Pure client-side

The Heterodyne "bridge" is not a separate process. Every Heterodyne
client is simultaneously a Matrix client and a Nostr client; the
cross-protocol translation happens entirely on the user's device. No
appservice, no homeserver modifications, no third-party trust required.

This is a hard requirement, not a recommendation. Any homeserver-side
bridging component would, by virtue of receiving plaintext before Matrix
encryption, defeat the blind-server property that makes Heterodyne's
privacy story coherent.

### 10.2 `heterodyne-core`

The reference implementation MUST be packaged as a single Rust crate,
`heterodyne-core`, encompassing:

- Nostr event creation, validation, signing.
- Matrix event composition with proper wrap-mode handling per §4.
- Identity-room state management (§3).
- Outbox advertisement and discovery (§7).
- Optional fan-out to vanilla Nostr relays.

The crate MUST compile to WASM for use in browser and mobile clients, and
MUST also be usable as a native Rust dependency for desktop and headless
deployments. This mirrors the `mxdx` shared-core pattern.

### 10.3 Personal headless bridge (optional)

A user MAY run a long-running headless instance of `heterodyne-core` on
hardware they control (laptop, VPS, home server). This is useful for:

- Publishing from non-interactive sources (e.g., a Hugo blog hook emitting
  long-form Nostr `kind:30023` events).
- Maintaining a continuous Nostr-relay presence even when no interactive
  client is online.

A personal bridge is functionally identical to an interactive client in
every protocol respect. It is *within the user's trust boundary by
construction* and the spec does not distinguish it from any other client.

### 10.4 What homeservers MUST and MUST NOT do

- A homeserver hosting a Heterodyne user's identity room or outbox rooms
  needs no Heterodyne-specific software. Vanilla Synapse, Dendrite,
  Conduit, Tuwunel, etc. all suffice.
- A homeserver MUST NOT be expected to parse or validate Heterodyne event
  payloads. All such logic is client-side.
- A homeserver operator MAY refuse to host Heterodyne content per their
  acceptable-use policy; if so, the user moves to another homeserver and
  updates their identity-room delegations.

### 10.5 Vanilla Nostr relay interop

The same client that publishes a wrapped `m.heterodyne.note.v1` to a
Matrix outbox room MAY simultaneously publish the *unwrapped* Nostr event
to one or more vanilla Nostr relays configured in the identity-room
`m.heterodyne.outbox.v1` state. Because the wrapped envelope contains the
verbatim Nostr event with its signature intact, the two publications are
byte-identical at the Nostr layer; vanilla Nostr clients see them as
duplicates and deduplicate by Nostr event `id` per NIP-01.

Symmetric inbound interop: a Heterodyne client MAY subscribe to vanilla
Nostr relays directly. Inbound events from vanilla relays are presented
in the UI exactly as wrapped events from Matrix, with the same signature
check. The delegation check from §3.3 is N/A in this case (there is no
Matrix MXID to bind to); the npub identity stands on its own Nostr
signature.

## 11. Interoperability

*Stub.* Graceful degradation paths for vanilla Matrix clients (render
`fallback` for `m.heterodyne.note.v1`; render normally for bare
`m.room.message`) and for vanilla Nostr clients (same Nostr event, no
Matrix-specific behavior).

## 12. Versioning and capability negotiation

*Stub.* Every Heterodyne event content carries `spec_version` as
semver-formatted string. Clients advertise the spec versions they
implement via an `m.heterodyne.capabilities.v1` state event in their
identity room. Receivers SHOULD downgrade gracefully when interacting
with an older spec version; SHOULD warn (not silently ignore) on a newer
version they don't understand.

## 13. Security model

*Stub.* The threat model lives in
[`../security/threat-model.md`](../security/threat-model.md). Inherited
invariants:

- **Blind server**: a homeserver MUST NOT see plaintext for any E2EE room.
- **Identity integrity**: the npub is the authoritative author; Matrix
  MXIDs are merely delegated publishers and never the source of truth
  for identity.
- **No central directory**: discovery is relationship-mediated and
  consent-driven.

## 14. Conformance and test vectors

*Stub.* Conformance MUST be demonstrable against the test vectors in
[`vectors/`](vectors/). Initial vectors will cover:

- A minimal `kind:1` wrapped event (`m.heterodyne.note.v1`).
- A bare DM with `heterodyne_nostr_sig` (signed-attachment validation).
- An identity-room state sequence: root → delegation → outbox
  advertisement.
- A successor chain across two identity rooms.
- A revocation rejecting events post-`revoked_at`.

See [`vectors/README.md`](vectors/README.md) for the vector file format.
