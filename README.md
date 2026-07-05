<p align="center">
  <img src="docs/assets/heterodyne-logo.png" width="320" alt="Heterodyne Protocol">
</p>

<p align="center">
  <strong>Social media that nobody owns — censorship-resistant, portable, with encrypted private messaging.</strong>
</p>

<p align="center">
  Nostr identity · Radicle + Nostr substrate · Matrix optional · one open network for any conformant client
</p>

---

> **Status:** Specification stage. The protocol is **fully specified** at
> [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) (**v0.4.0 DRAFT**). It is
> in its **0.x phase - in flux until 1.0**: wire formats and requirements may
> still change between releases (v0.4.0 breaks v0.3.0 - see the substrate pivot
> in ADR-026..029). A first-party reference client is the next milestone.
> **Contributions are welcome.**

## What Heterodyne means to you

Heterodyne is a decentralized social network protocol built around a simple
promise: **your identity is yours, and no platform owns or gatekeeps it.**

- **You own your identity, not a platform.** Your identity is a cryptographic
  keypair you hold — not a username inside someone else's database. No company
  can sell it, rename it, or lock you out of it. Your posts are portable across
  open relays and can be backed by archives you control, so no single provider
  is the gatekeeper of your presence.
- **Not tied to one provider or account.** Your public identity is decoupled
  from the server you happen to publish through. You can be *multi-homed* across
  several servers at once and still present **one cohesive identity** to your
  followers. If a server turns hostile, you point your followers elsewhere and
  carry your identity — and your audience — with you.
- **Highly censorship-resistant and hard to shut down.** There is no central
  server to seize and no single chokepoint. Content rides over two co-equal
  backends - open Nostr relays and **Radicle-backed repo relays** that replicate
  content peer-to-peer among the people who choose to seed it - and, optionally,
  federated Matrix homeservers; anyone can run any of them. Individual relays or
  nodes can still refuse or drop traffic, but because none of them is essential,
  clients publish to and read from many, and interest-driven Radicle seeding
  mirrors a persona's content across the peers who follow it.
- **You stay findable.** Decentralization usually makes people hard to discover.
  Heterodyne keeps a cryptographically-signed, authoritative pointer from your
  public identity to where you publish, so followers can verify your current
  location whenever that signed pointer is reachable — even after you've moved
  servers.
- **Messages are attributable to you.** Broadcast posts are signed by your key,
  so followers can verify a post genuinely came from your identity and was not
  forged. In the optional group-chat layer, messages default to "bare"
  messages - attributable to their author's identity through a verified
  delegation, with an opt-in per-message signature for transferable proof. A
  signature proves an *authorized key* signed the message, which is exactly why
  keys can be rotated and revoked if one is ever compromised.
- **Private content, with honest boundaries.** Broadcast content comes in three
  privacy tiers, each with a plainly-stated trust boundary: **public** (readable
  by anyone), **private-but-not-discoverable** (a Radicle private repo - visible
  only to the audience you allow, though those allowed nodes hold it in the
  clear), and **encrypted** (NIP-44 ciphertext committed to the repo - readable
  only by key-holders, so even the nodes that store it cannot open it). For
  real-time group chat and DMs, the OPTIONAL Matrix layer adds end-to-end
  encryption with Matrix's ratchet (Megolm today, MLS ahead), where the
  homeserver routes ciphertext it can never read.
- **Light on resources.** No proof-of-work mining, no blockchain, no heavy
  consensus. Confidential broadcast encrypts **once for the audience** - instead
  of re-encrypting a message separately for every recipient - and the OPTIONAL
  Matrix layer does the same per room. The protocol is designed to run on modest
  hardware; browsers and phones participate as light clients over ordinary
  websockets, never needing to run a full peer-to-peer node.
- **Anyone can build a client.** The specification is open and
  implementation-agnostic. Build your own client in any language or runtime; as
  long as it follows the spec, it is designed to interoperate with every other
  conformant Heterodyne client — that shared conformance is what makes one
  network out of many independent clients.

## How it works

Heterodyne runs **[Nostr](https://github.com/nostr-protocol/nips) signed
events** over a core substrate of **ordinary Nostr relays plus
[Radicle](https://radicle.xyz)-backed repo relays**, with
**[Matrix](https://spec.matrix.org/latest/) as an OPTIONAL layer** for
real-time discussion. Each system does what it does best:

- **Nostr provides identity, authenticity, and the canonical content unit.** A
  user's [`secp256k1`](https://www.secg.org/sec2-v2.pdf) keypair is portable,
  censorship-resistant, and not bound to any server. Every post is a signed
  Nostr event; that signature is what followers verify, wherever the event came
  from.
- **Radicle provides durable, peer-to-peer content storage.** A "repo relay" is
  an ordinary NIP-01 websocket endpoint whose event store is a Radicle git
  repository, replicated peer-to-peer among full nodes. To a browser or phone it
  looks like any other Nostr relay; the Radicle machinery lives entirely behind
  it. Content is mirrored by the peers who choose to seed a persona, so
  redundancy scales with interest.
- **Matrix (OPTIONAL) provides real-time encrypted discussion.**
  [Megolm](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md)/[MLS](https://www.rfc-editor.org/rfc/rfc9420.html)
  group end-to-end encryption, native room state, and federation for group chat,
  DMs, and calls. A client that omits Matrix is still fully conformant.

The key insight: the user's identity (their Nostr keypair) is **decoupled** from
the infrastructure that carries any given event. **Broadcast** content (you
publishing as yourself) is a signed Nostr event written to both core backends,
under one of three privacy tiers (public repo, private repo, or
encrypted-blobs-in-repo). **Replies and reactions** use the Nostr **outbox
model**: each author writes into their own outbox and clients assemble threads
scatter-gather. **Real-time group chat and DMs** flow through the OPTIONAL Matrix
layer, whose homeserver acts as a blind relay for the ciphertext it routes.

Confidential broadcast encrypts **once for the audience** and commits the
ciphertext to the repo, sidestepping the *N-encryptions-for-N-recipients*
scaling problem - and the storing nodes never see the plaintext. A private
(unencrypted-but-not-discoverable) repo instead gates *who can fetch* the content
without encrypting it, so the boundary is stated honestly: allowed seeders hold
it in the clear.

Identity is anchored by a
**[KERI](https://arxiv.org/abs/1907.02143) cold-root key**
(your public identity), with a
rotating **epoch key** that signs day-to-day attestations — so the root key
stays cold and a compromised signing key can be rotated out without losing your
identity. Each device that runs a Radicle full node also carries an Ed25519 Node
ID, bound to the persona by the same KERI-anchored delegation.

```
                     your device (holds your keys)
       broadcasts    │            │ replies/reactions    │ group chat / DMs
    signed Nostr     │            │ (outbox model)        │ (OPTIONAL)
    events           ▼            ▼                       ▼
        ┌─────────────────────┬──────────────────┐   Matrix homeserver
        │ open Nostr relays   │ Radicle repo      │   (blind relay: routes
        │ (public fan-out)    │ relays (P2P seed  │    ciphertext it can't
        │                     │  replication)     │    read; federates)
        └─────────────────────┴──────────────────┘
              two co-equal core backends
```

## Content taxonomy

Broadcast content is organized by **repo-visibility privacy tier**, each with
an explicitly stated trust boundary:

| Tier | What it is | Confidential against whom |
|---|---|---|
| **Public repo** | World-readable plaintext, mirrored to Nostr relays and any seeder. | No one (public by design). |
| **Private repo** ("unencrypted-but-not-discoverable") | A Radicle private repo: invisible/unfetchable to non-allowed nodes. | Not confidential against allowed seeders - they hold it in the clear. |
| **Encrypted-blobs-in-repo** | NIP-44 ciphertext committed under an audience key. | Everyone who is not a key-holder, including the nodes that store it. |

Real-time **discussion** - communities, topic rooms, forums, group chat, and
DMs - lives in the **OPTIONAL Matrix layer** as `public_discussion` and
`private_discussion` rooms (bare Matrix by default, with an optional per-message
signature badge). When Matrix is absent, replies and reactions fall back to the
Nostr outbox model. **No tier or discussion kind claims deniability** - every
post and message is attributable to its author's identity via the protocol's
delegation, though bare messages carry no *transferable* third-party proof.

## Project status & roadmap

The specification is **fully drafted with diagrams**. All load-bearing protocol
decisions — identity, envelope, rooms, publishing, discovery, moderation,
encryption, bridging, interop, versioning, security, and conformance — are
written down. See [`CHANGELOG.md`](CHANGELOG.md) for per-version history and
[`docs/adr/`](docs/adr/) for the decision records behind each revision.

The current release is **v0.4.0**, which pivots the core substrate to Radicle +
Nostr with Matrix as an optional layer (ADR-026 through ADR-029) and breaks
v0.3.0. Per the semver 0.x rule (spec §12.1), everything is subject to change
until **1.0.0**.

**Next milestones:**

1. Expand and complete the conformance test vectors in
   [`docs/spec/vectors/`](docs/spec/vectors/) (coverage is underway) and validate
   them against the first reference client.
2. Build a first-party reference client to validate the protocol end-to-end
   (language and runtime to be chosen separately — the spec is agnostic).
3. Iterate the spec based on implementation feedback toward 1.0.

## Build your own client

Heterodyne is **specification-first and implementation-agnostic** — no language
or runtime is prescribed. Interoperability is the goal that conformance serves:
any client that follows [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) and
passes the conformance vectors should interoperate with every other Heterodyne
client. The bridge is **purely client-side**: vanilla Nostr relays, Radicle
repo relays, and (optionally) Matrix homeservers carry Heterodyne traffic
without any protocol-specific modifications. A Matrix-free client is fully
conformant - Matrix support is SHOULD-level.

To start implementing, read the spec, then check the conformance vector format
in [`docs/spec/vectors/`](docs/spec/vectors/) to validate your wire output
byte-for-byte.

## Navigate this repository

| Path | What it is |
|---|---|
| [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) | The normative specification (single living document, 0.x). |
| [`docs/architecture.md`](docs/architecture.md) | Non-normative architecture overview and design rationale. |
| [`docs/glossary.md`](docs/glossary.md) | Term definitions referenced from the spec. |
| [`docs/security/threat-model.md`](docs/security/threat-model.md) | Companion analysis to the spec's security model. |
| [`docs/spec/vectors/`](docs/spec/vectors/) | Conformance test vectors (format defined; vectors authored incrementally). |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records behind each revision. |
| [`research/INDEX.md`](research/INDEX.md) | Topic-keyed index into the background research. |
| [`CLAUDE.md`](CLAUDE.md) | Project mission and full repository map. |

When you need to look something up, **start at
[`research/INDEX.md`](research/INDEX.md)** — it maps topics (outbox routing,
NIP-72 communities, MLS group cryptography, …) to exact source locations.

## References & standards

Heterodyne does not reinvent its cryptography or transport — it composes
existing open standards. These are the authoritative specifications for the
protocols referenced above.

**Nostr** (identity & canonical content layer)

- [Nostr NIPs](https://github.com/nostr-protocol/nips) — the canonical set of
  Nostr Implementation Possibilities (the protocol specification itself).
- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) — basic
  protocol flow, the event format, and `secp256k1` Schnorr signatures.
- [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) — bech32
  identifiers (`npub` / `nsec` and related entities).
- [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) — relay
  list metadata (the "outbox" model) for discovering where a user publishes.
- [NIP-72](https://github.com/nostr-protocol/nips/blob/master/72.md) — moderated
  communities, the model behind Heterodyne's moderated discussion rooms.
- [NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md) — MLS-based
  end-to-end encryption for Nostr.

**Radicle** (peer-to-peer content substrate)

- [Radicle](https://radicle.xyz) — the peer-to-peer code-collaboration network
  (Heartwood 1.x stack) whose signed, git-replicated repositories back
  Heterodyne's repo relays. Its identity documents (Ed25519 delegates +
  threshold), signed refs, and Collaborative Objects are the storage layer
  behind the NIP-01 wire.

**Matrix** (OPTIONAL real-time discussion, state & encryption layer)

- [Matrix specification](https://spec.matrix.org/latest/) — the full protocol:
  rooms, room state, power levels, and federation.
- [End-to-end encryption](https://spec.matrix.org/latest/client-server-api/#end-to-end-encryption)
  — the Client-Server API E2EE module, including the `m.megolm.v1` scheme.
- [Megolm ratchet](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md)
  — the cryptographic design of the group ratchet Heterodyne encrypts with today.

**Cryptography & identity**

- [MLS — RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) — the IETF
  Messaging Layer Security standard; the group-encryption target ahead of Megolm.
- [secp256k1 — SEC 2](https://www.secg.org/sec2-v2.pdf) — the SECG standard
  defining the elliptic curve behind every Heterodyne identity keypair.
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) —
  Schnorr signatures over secp256k1, the signature scheme Nostr events use.
- [KERI](https://arxiv.org/abs/1907.02143) — *Key Event Receipt Infrastructure*
  by Samuel M. Smith (arXiv); the foundational paper for the cold-root /
  epoch-key identity model. Active specification:
  [ToIP KSWG KERI spec](https://trustoverip.github.io/kswg-keri-specification/)
  ([repo](https://github.com/trustoverip/kswg-keri-specification)); project
  home: [keri.one](https://keri.one/).

## Contributing

Heterodyne is in active 0.x design. The most valuable contributions right now
are:

- **Spec review** — adversarial reading of [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md)
  and the [threat model](docs/security/threat-model.md).
- **Test vectors** — authoring conformance vectors in [`docs/spec/vectors/`](docs/spec/vectors/).
- **Client prototypes** — implementations that exercise the spec and feed back
  into it.

Architectural decisions are recorded as ADRs in [`docs/adr/`](docs/adr/); open a
discussion or proposal before large changes so the rationale is captured.

## License

The Heterodyne specification and documentation in this repository are licensed
under the **Creative Commons Attribution 4.0 International** license
([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)) — see
[`LICENSE`](LICENSE). You are free to share and adapt the material for any
purpose, including building clients and derivative specs, as long as you give
appropriate credit to the Heterodyne Protocol authors.

This is an interim choice for the 0.x phase and may be revisited (for example,
adding a separate software license) once a reference client lands.
