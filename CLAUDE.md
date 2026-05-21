# Heterodyne

A decentralized social network protocol that runs **Nostr events over Matrix
rooms** to combine the strengths of both:

- **Nostr** provides the identity and authenticity layer — a user's
  cryptographic `secp256k1` keypair is portable, censorship-resistant, and
  not tied to any specific homeserver or relay.
- **Matrix** provides the transport, state, encryption, and access control
  layer — Megolm/MLS for group E2EE, native room state for membership and
  power levels, federation for resilience.

The user's identity (their Nostr keypair) is decoupled from the Matrix account
used to publish a given event. A single user can be multi-homed across
multiple Matrix accounts and homeservers while still presenting one cohesive
Nostr identity to followers.

## Core design intuition

> By offloading group cryptography to Megolm (and eventually MLS) and routing
> Nostr events into encrypted Matrix rooms, we outsource group privacy to
> Matrix's ratchet. The bridge ingests the raw, unencrypted Nostr event; the
> Matrix client SDK encrypts it client-side and pushes ciphertext to the
> homeserver. The homeserver becomes a blind state manager — it routes
> messages but cannot read payloads or metadata.

This solves the **N-encryption-per-N-recipients** scaling problem of standard
Nostr DMs/groups: Megolm and MLS create a shared session for the room, so the
bridge encrypts once and Matrix handles key distribution to authorized
members.

## Room taxonomy (v0.1.5)

| Room kind | Purpose | Encryption | Default wrap mode | Moderation |
|---|---|---|---|---|
| `public_broadcast` | Open broadcast (Twitter-style public feed). Content + index on Nostr. | None | N/A — no timeline | Server ACLs + community lists |
| `public_moderated` | Communities, topic rooms, forums. Content + approvals on Nostr. | None | N/A — no timeline | NIP-72 moderator approvals + policy rooms |
| `private_verifiable` | Group rooms where authorship is part of the contract (work, records) | Megolm/MLS | wrapped (Nostr-signed) | Single or small admin set |
| `private_deniable` | Friend circles, casual planning, day-to-day groups | Megolm/MLS | bare (Megolm-deniable) | Single or small admin set |
| `dm_verifiable` | Notarized two-party DMs (agreements, tickets) | Megolm/MLS | wrapped | Participants only |
| `dm_deniable` | Standard two-party DM | Megolm/MLS | bare | Participants only |

## Project status

The v0.1 specification is **fully drafted with diagrams** at
[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md). All
load-bearing protocol decisions (identity, envelope, rooms,
publishing, discovery, moderation, encryption, bridge, interop,
versioning, security, conformance) are written down. v0.1.5
makes substantive structural changes after external review:
(a) feed indexes are migrated off Matrix state events to
Nostr-native `kind:31007` replaceable events, npub-signed and
gift-wrapped for private rooms; (b) the identity room is reframed
as a disposable Matrix container with the `kind:31005` identity
pointer as the authoritative npub→room mapping; (c) delegation
acknowledgement no longer requires a Matrix MSK signature;
(d) Heterodyne commits unconditionally to **KERI** for root
inception and rotation, retiring the v0.1.4 single-key chain;
(e) the room taxonomy now has six explicit kinds —
`public_broadcast`, `public_moderated`, `private_verifiable`,
`private_deniable`, `dm_verifiable`, `dm_deniable` — with the
default wrap mode encoded in the kind name; (f) Matrix-DM
retrieval backfill is forbidden (Nostr relays + user-hosted
archives only); (g) moderator post-hoc removal uses Nostr
`kind:5` deletions rather than Matrix redactions; (h) hardening
— strict ±5 minute clock skew, mandatory SSRF prevention on
ATProto DID resolution, mandatory `nip01_raw` canonical
serialization on every signed event to prevent parser-reordering
attacks. v0.1.4 added the OPTIONAL ATProto attached outbox
(§11.6) and KERI social witnesses; v0.1.3 introduced the
Nostr-relays-for-public-content pivot. The Cold Root + Epoch
Keys design at
`docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md`
specifies the v0.2 identity rewrite that v0.1.5's KERI commitment
anticipates. The spec is implementation-agnostic — no particular
language or runtime is prescribed. Not yet final until v0.2 freeze.

The next milestones are:

1. Author test vectors in `docs/spec/vectors/` (one per spec section).
2. Build a first-party client implementation (language and runtime
   to be chosen separately; the spec is agnostic) to validate the
   protocol end-to-end.
3. Iterate the spec based on implementation feedback toward v0.2.

## How to navigate this repo

| Path | What it is |
|---|---|
| `docs/spec/heterodyne.md` | The normative spec. Single living document, v0.1.1. |
| `docs/architecture.md` | Non-normative architecture overview + design rationale for each load-bearing decision. |
| `docs/glossary.md` | Term definitions referenced from the spec. |
| `docs/security/threat-model.md` | Companion analysis to spec §13 (security model). |
| `docs/spec/vectors/` | Test vectors (format defined; vectors authored incrementally). |
| `docs/spec/extensions/nips/` | Forward-reference index for future NIP extractions. |
| `docs/spec/extensions/mscs/` | Forward-reference index for future MSC extractions. |
| `research/sources/` | Raw Gemini deep-research output, stored verbatim with citations. Do not edit. |
| `research/INDEX.md` | Topic-keyed classification of the research. |
| `CLAUDE.md` | This file. Project mission + repo map. |

When you need to look something up, **start at `research/INDEX.md`** — it maps
topics like "Outbox routing", "NIP-72 communities", or "MSC3639 social media"
to the exact file and line range in `research/sources/`.

## Research index — quick links by topic

The full topic table lives in [`research/INDEX.md`](research/INDEX.md). The
high-level groupings:

- **Architecture comparison** (Matrix DAG vs Nostr broadcast): source 01,
  §"Architectural Foundations".
- **Existing Matrix↔Nostr bridges and prior art**: source 01, §"Technical
  Mechanisms of Matrix-Nostr Interoperability".
- **Matrix as a social-media substrate (MSCs)**: source 01, §"Matrix as a
  Substrate for Decentralized Social Media" (MSC3089, MSC2313, MSC1769,
  MSC2946, MSC3639, Cerulean).
- **Nostr identity, NIP-05, machine identity, app handlers**: source 02, §1.
- **Anti-spam friction (NIP-13 PoW, NIP-43, NIP-86, NIP-57 fees)**: source 02,
  §2.
- **Relay-side heuristics (rate limit, anomaly detection)**: source 02, §3.
- **Outbox routing (NIP-65)**: source 02 §4 + source 03 §"Outbox Model".
- **Distributed moderation (NIP-56 reports, NIP-32 labels)**: source 02, §5.
- **Mute lists & curation (NIP-51, starter packs kind:39089)**: source 02 §6
  + source 03 §"Static Curation".
- **Moderated communities (NIP-72 reddit-style, NIP-29 closed groups)**:
  source 02, §7.
- **Web of Trust & reputation (NIP-85)**: source 02 §8 + source 03 §"Web of
  Trust".
- **Data Vending Machines (NIP-90 — algorithmic feeds, AI moderation)**:
  source 02 §9 + source 03 §"Data Vending Machines".
- **Social graph & threading (NIP-02 follows, NIP-10 threads)**: source 03,
  §"Cryptographic Social Graph".
- **Infrastructure discovery (NIP-11, NIP-66)**: source 03, §"Infrastructure
  Discovery".
- **Search (NIP-50)**: source 03, §"Global Search Capabilities".
- **Economic signaling for feeds (NIP-57 zaps, NIP-75 zap goals)**: source
  03, §"Economic Signaling".
- **Long-form & calendar (NIP-23, NIP-52)**: source 03, §"Long-Form
  Publishing".
- **MLS / group cryptography (NIP-EE, Marmot, Matrix MLS migration)**: source
  01 §"Cryptographic Evolution" + source 02 §10.
- **Security research & vulnerability taxonomy**: source 01, §"Security
  Vulnerability Taxonomies".
- **Strategic implications / convergence**: source 01, §"Strategic Industry
  Implications".

## Inspiration: `mxdx`

The sibling project `mxdx` (Matrix-native fleet management) is the source
of several security-first habits we inherit:

- Every Matrix event in a private context is end-to-end encrypted,
  including state events (MSC4362 encrypted state).
- All sensitive material is stored encrypted at rest; OS keystore
  integration where available.
- Pure client-side bridge — vanilla homeservers handle Heterodyne
  traffic without protocol-specific modifications.

mxdx is **not** a dependency, and Heterodyne does not prescribe
mxdx's specific implementation choices (language, runtime, packaging).
The overlap is in security invariants and the client-side bridge
model, not implementation.
