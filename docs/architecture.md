# Architecture overview

This document is a non-normative introduction to Heterodyne for new
contributors. The normative specification is at
[`spec/heterodyne.md`](spec/heterodyne.md).

## What we're building

Heterodyne is a decentralized social network protocol. A user's identity
is a Nostr `secp256k1` keypair. The user's content is carried over Matrix
rooms. The combination gives:

| Property | Comes from |
|---|---|
| Cryptographic authenticity; key portability across homeservers; forwardability to vanilla Nostr | Nostr |
| End-to-end group encryption (Megolm today, MLS in flight); stateful access control; federated transport; censorship resistance at the server layer; native moderation primitives | Matrix |
| Multi-homing, persona-preserving key rotation, deniability-on-demand | Heterodyne's composition |

## The six load-bearing decisions

The design rests on six choices recorded with rationale so future
contributors understand why we picked what we picked.

### 1. Event envelope: verbatim Nostr inside Matrix; wrap optional in E2EE

Wrapped Heterodyne events carry the full signed Nostr event verbatim
inside the Matrix event content. Matrix is "just transport." This gives:

- A wrapped event can be lifted into vanilla Nostr 1:1 with no
  transformation. Same `id`, same signature, same kind.
- Authenticity survives transport: if the event leaks past the Matrix
  layer, the Nostr signature still proves origin.

Wrap is **optional in E2EE rooms** — senders can choose deniability per
event. In public rooms wrap is mandatory; authenticity is the whole point
of broadcasting publicly. In private communities wrap is the sensible
default but the sender can opt out for any individual message. In DMs the
default flips: bare by default, with an opt-in
`heterodyne_nostr_sig` field for explicit authenticity.

See spec §4.

### 2. Identity: npub canonical, Matrix accounts are delegated publishers

The npub is the authoritative identity. Matrix accounts are
*delegated publishers* bound by double-signed attestations in a
per-persona **identity room**. Multiple personas are first-class. Vanilla
Nostr's key-rotation pain (rotating means abandoning your followers) is
solved by an explicit identity-chain mechanism: an outgoing npub points
to its successor; the successor points back; followers walk the chain
transparently.

See spec §3.

### 3. Outbox model: every author admins their own rooms

A Heterodyne user broadcasts via Matrix rooms they own. Each circle —
friends, close friends, work, public — is a separate room with different
membership. The client surfaces "distribution lists" and "friend
circles"; Matrix power levels are the implementation detail and stay
hidden from the user.

This places the censorship-resistance burden on Matrix federation rather
than on Nostr relays. The user gains stateful, fine-grained membership
control. The cost is that "follow" becomes "join the broadcaster's
room," which is heavier than Nostr's pure follow-list approach but
unlocks the moderation and encryption story.

See spec §7 (stub).

### 4. Bridge: pure client-side, any homeserver works unmodified

There is no Heterodyne appservice and no homeserver modification. Every
client is a full Matrix + Nostr client. The cross-protocol logic lives
in a Rust crate, `heterodyne-core`, compiled to WASM for browser/mobile
clients and usable natively for desktop and headless deployments. This
mirrors the `mxdx` shared-core pattern.

This is the design choice that protects the blind-server property: a
homeserver-side bridge would see plaintext before Matrix encryption and
break the privacy story.

Per-MXID portability is provided by a dedicated **encrypted client
configuration room** (§3.8) that holds user preferences, per-persona
private state including mute lists, and Heterodyne-specific key
backups. A new device of the same MXID joins this room and re-syncs
configuration immediately.

See spec §10 (bridge model) and §3.8 (config room).

### 5. DMs: pure Matrix with optional Nostr wrap

Direct messages reuse Matrix DM rooms with `m.room.message` semantics. A
Heterodyne client adds an OPTIONAL `heterodyne_nostr_sig` field for
senders who want explicit authenticity on a specific message. By default
DMs are deniable in the same way encrypted Matrix DMs already are.

This makes vanilla Matrix clients render Heterodyne DMs natively, with
zero special handling — a substantial UX win for cross-network
conversations.

See spec §4.3, §4.4.

### 6. Moderation: Matrix is the floor, Heterodyne is the editorial ceiling

Matrix room-level ACLs (power levels, kicks, bans, server ACLs, MSC2313
policy rooms) decide who is in a room. NIP-72-style moderator approval
signatures, when used, decide whose posts surface in the feed view of a
public moderated community.

The two systems answer different questions and don't conflict. A user
banned from a room never publishes there. A user in the room whose posts
aren't moderator-approved is invisible in the curated feed but still
visible to anyone subscribed to the raw room.

See spec §8 (stub).

## High-level diagram

```
                       ┌─────────────────────────────────┐
                       │      Heterodyne client          │
                       │  (browser, desktop, mobile)     │
                       │                                 │
                       │   ┌───────────────────────┐     │
                       │   │   heterodyne-core     │     │
                       │   │   (Rust → WASM/native)│     │
                       │   └───┬────────────────┬──┘     │
                       │       │                │        │
                       │  Matrix SDK       Nostr SDK     │
                       └───────┼────────────────┼────────┘
                               │                │
                               ▼                ▼
                  ┌────────────────────┐   ┌───────────────────┐
                  │   Matrix           │   │   Vanilla Nostr   │
                  │   homeserver       │   │   relay           │
                  │   (any vendor —    │   │   (optional       │
                  │   blind to E2EE)   │   │   fan-out)        │
                  └─────────┬──────────┘   └───────────────────┘
                            │
                            │  Matrix federation
                            ▼
                  Other Heterodyne clients on
                  their own homeservers
```

The Matrix homeserver routes encrypted events between participants in
private rooms but cannot read their contents. The vanilla Nostr relay
optionally receives identical, unwrapped Nostr events for redundant
publication or vanilla-client interop.

## Where `mxdx` fits

Heterodyne and `mxdx` are sibling projects that share architectural DNA:

- Rust core compiled to WASM for portable client surfaces.
- Hard invariant that every Matrix event in a private context is E2EE,
  including state events (MSC4362).
- OS keychain integration for sensitive material at rest.
- Single implementation, multiple surfaces (CLI, browser, mobile,
  headless).

Heterodyne is **not** a fork of `mxdx` and does not depend on its code.
The protocols are different (one is fleet-management with PTYs and
WebRTC; the other is social with Nostr events and pub/sub). The
overlap is in engineering pattern, not implementation.

## Open design questions

All v0.1 spec sections are drafted. The remaining open questions are
follow-up work that does not block v0.1:

- **Cross-MXID persona-private state synchronization.** A persona
  with multiple delegated MXIDs has separate config rooms (§3.8) per
  MXID; persona-scoped private state (mutes, prefs) does not auto-sync
  across them in v0.1. A future spec version may define a
  persona-private encrypted room joined by all the persona's MXIDs.
  Defer until usage demand is clear.
- **`matrix:` URI refactor of §7 outbox schemas.** New constructs in
  v0.1 (§3.8 config-room pointer, §3.5 successor URI, §11.3 identity
  pointer) use `matrix:` URIs. The §7 outbox schemas still use the
  legacy `{room_id, via}` structured form for backward source
  compatibility. A minor-version bump can migrate them; not urgent.
- **MLS migration procedure.** §9.2 reserves
  `m.heterodyne.encryption_version.v1` and the `algorithm` field, but
  the actual migration procedure (re-key, member re-acknowledgement,
  atomic flip) is deferred to a future spec version when upstream
  `matrix-rust-sdk` MLS lands.
- **Conformance reporting formalization.** §14.4 leaves the
  conformance-claim mechanism informal. A future spec version may
  define a conformance manifest format consumable by a registry.
- **Canonical topic taxonomy.** The spec lets clients pick reverse-DNS
  namespaces (§5.1), but a recommended common set (under
  `org.heterodyne.topics`) would improve discoverability. Defer until
  there's actual usage to draw from.
- **Transitive join-rule consistency.** §7.2 recommends `restricted`
  join rules (MSC3083) for advertised inner rooms; should the spec
  formalize a check that inner rooms are at least as restrictive as
  their advertiser?
- **Megolm session establishment under robust batched delivery.**
  §6.4's "robust batched delivery" semantics interact with the latency
  of Megolm session setup for fresh members. Worth a worked example
  in the test vectors.
- **Persona switching UX.** Multiple personas (§3.4) are a first-class
  feature, but the spec is silent on how clients SHOULD present
  switching. UX-only — defer to client implementation.
- **Out-of-scope security threats.** Compromised user devices, traffic
  analysis under Tor-routed Matrix federation, and post-quantum
  adversaries are explicitly out of scope for v0.1 (see threat model).
  Each is a future-spec-version question.
