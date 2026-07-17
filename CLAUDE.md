# Heterodyne

A decentralized social network protocol that runs **Nostr signed events over a
Radicle + Nostr core substrate, with Matrix as an OPTIONAL layer** (substrate
pivot, ADR-026 through ADR-029):

- **Nostr** provides the identity and authenticity layer and the canonical
  content unit - a user's cryptographic `secp256k1` keypair is portable,
  censorship-resistant, and not tied to any specific server. Every post is a
  signed Nostr event carried over two co-equal MUST backends: ordinary Nostr
  relays and **repo relays**.
- **Radicle** (the Heartwood 1.x peer-to-peer git stack) provides durable,
  censorship-resistant content storage behind repo relays - a repo relay is a
  NIP-01 websocket endpoint whose event store is a Radicle git repository,
  replicated peer-to-peer among full nodes. Radicle's Noise XK / TCP transport
  lives entirely behind full nodes and never in front of a browser/mobile
  client.
- **Matrix** is an OPTIONAL (SHOULD-level) layer for real-time discussion
  groups, DMs, calls, and encrypted rooms - Megolm/MLS for group E2EE, native
  room state, federation. No identity, publishing, discovery, or privacy
  requirement depends on it; a Matrix-free client is fully conformant.

The user's identity (their Nostr keypair) is decoupled from the infrastructure
that carries a given event. A single user can be multi-homed across multiple
full nodes (and, optionally, Matrix accounts) while still presenting one
cohesive Nostr identity to followers.

## Core design intuition

> Nostr signed events are the canonical content unit; Radicle git repos give
> them durable, peer-to-peer replication behind an ordinary NIP-01 wire, so
> browsers and phones participate as light clients that verify every event's
> signature locally. Confidentiality is a property of repo visibility plus
> app-layer encryption, not of a homeserver: content is either public, gated by
> selective replication (a private repo - plaintext on allowed seeders), or
> NIP-44-encrypted before it is committed (confidential against everyone
> including the nodes that store it).

Confidential broadcast still solves the **N-encryption-per-N-recipients**
scaling problem: the audience key encrypts content once and is distributed
per-recipient via `kind:31011` wraps, and the storing nodes never see the
plaintext. The OPTIONAL Matrix layer applies the same encrypt-once-per-room
model via Megolm/MLS for real-time discussion, where the homeserver is a blind
relay.

## Content taxonomy (current 0.x draft)

Broadcast content is organized by **repo-visibility privacy tier**, each with
an explicitly stated trust boundary; two-party DMs are a CORE double-ratchet
mechanism (§5.7) and multi-party discussion lives in the OPTIONAL Matrix layer:

| Tier / kind | Purpose | Trust boundary | Moderation |
|---|---|---|---|
| **Tier 1 - public repo** | Open broadcast (Twitter-style public feed). Plaintext Nostr events on both backends. | Confidential against no one. | Server ACLs + community lists; NIP-72 or the Radicle delegate-threshold canonical-branch editorial gate |
| **Tier 2 - private repo** ("unencrypted-but-not-discoverable") | Persona broadcasts to a closed audience via a Radicle private repo (`visibility: private` + allow list). | NOT confidential against members - plaintext on every allowed seeder. Client MUST warn and MUST NOT call it "encrypted." | Owner controls the allow list |
| **Tier 3 - encrypted-blobs-in-repo** | Confidential broadcast: NIP-44 ciphertext under an audience key committed to a repo. | Confidential against everyone incl. seeders; only key-holders read it. | Owner controls the audience-key roster |
| `direct_messages` (CORE) | Two-party DMs over the core substrate: nostr-double-ratchet wire (`kind:1060` relay-carried, never repo-committed), NIP-17 fallback for vanilla recipients. | Double Ratchet session - forward secrecy + post-compromise security. | Participants (§5.7.4 acceptance gating) |
| `public_discussion` (OPTIONAL Matrix) | Communities, topic rooms, forums, group chat. | Unencrypted Matrix room. | NIP-72 moderator approvals (when moderated) |
| `private_discussion` (OPTIONAL Matrix) | Friend circles, casual planning, day-to-day groups; the OPTIONAL Matrix layer's additional DM surface. | Megolm/MLS session boundary. | Participants / small admin set |

Moderation offers **two parallel editorial-gating mechanisms** (§8): the NIP-72
`kind:4550` approval flow (relay-hosted / interoperating communities) and a
native Radicle editorial-gating mode where a post is approved iff it is
reachable from the delegate-threshold-approved canonical feed branch (the finer
per-ref `xyz.radicle.crefs` refinement is OPTIONAL, verified against Heartwood
1.9.1; baseline canonicity MUST NOT depend on it, a scoping choice rather than
a verification hedge). No tier or discussion kind
claims deniability: every post/message is attributable to its author's npub via
the §3.3 delegation (bare messages carry no *transferable* third-party proof,
but are not anonymous).

## Project status

The specification is **fully drafted with diagrams** at
[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md). All
load-bearing protocol decisions (identity, envelope, rooms,
publishing, discovery, moderation, encryption, bridge, interop,
versioning, security, conformance) are written down.

The spec is in its **0.x phase — in flux until 1.0**. Per the semver
0.x rule (spec §12.1), everything is subject to change and any `0.x`
release MAY break the prior one; the strict PATCH/MINOR/MAJOR
compatibility contract takes effect only at `1.0.0`. Versions advance
by milestone - the current release is **v0.4.0**, which pivots the
core substrate to Radicle + Nostr with Matrix optional (ADR-026 through
ADR-029) and breaks v0.3.0 under the semver-0.x rule - but prose should
refer to the spec as **0.x** rather than pinning to a single point
version. See [`CHANGELOG.md`](CHANGELOG.md) for the per-version
history and [`docs/adr/`](docs/adr/) for the decision records behind
each revision.

Current shape (0.x):

- **Substrate.** Nostr signed events over two co-equal MUST backends -
  ordinary Nostr relays and Radicle-backed **repo relays** - with three
  node roles: **full node** (runs a Radicle node + NIP-01 repo-relay
  adapter; the only node type that holds content), **routing node**
  (edge-runtime; answers repo-location queries from `kind:31005`/
  `kind:31010` ads only; holds no content), and **light node** (fetches
  directly and verifies every event's Nostr signature locally). Matrix
  is OPTIONAL.
- **Identity** is anchored by a KERI cold-root key - the persona's
  npub; a rotating epoch key signs routine attestations (root
  attestation, delegations, outbox, feed index, posts, approvals). The
  KEL is authoritative over the Radicle identity document on any
  divergence (§3.9.10). `kind:31001` delegations now target Ed25519
  Radicle NIDs (bidirectionally bound, two keys per device, §3.3.1);
  organizations are first-class personas governed by repo delegates +
  threshold (with optional per-ref `crefs`). (See the Cold Root + Epoch
  Keys design at
  `docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md`.)
- **Feed indexes** are Nostr-native `kind:31007` replaceable events,
  epoch-key-signed, published to both backends, and audience-key-wrapped
  for the encrypted tier, so the canonical feed list cannot be silently
  mutated nor read by non-members. For org personas, canonicity requires
  reachability from the delegate-threshold-approved canonical feed branch
  (§6.7.0).
- **Privacy** is a repo-visibility taxonomy of three tiers (public
  repo; private "unencrypted-but-not-discoverable" repo; encrypted-
  blobs-in-repo), each with an honest trust boundary (§9.0). The
  `kind:31005` pointer is the authoritative npub→RID mapping; a
  compromised container is abandoned by re-anchoring to a fresh RID.
- **Lists.** Mute lists and every other NIP-51 list/set are core
  constructs: `kind:10000` mutes plus the sets file
  (`kind:30000`-`39092`, incl. kind-mute sets `kind:30007`), published
  to BOTH backends (repo relays MUST accept them), with private items
  NIP-44-encrypted to self under the epoch key. Community policy lists
  ride the same carrier via `kind:34550` tags (§8.5/§8.6).
- **Backups.** Non-key state is encrypted blobs in a per-persona
  unadvertised **config repository** (private repo, RID never
  published); key material lives in a local-only **keys repository**
  (NIP-49-wrapped nsec, epoch/NID secrets, audience keys, config-repo
  RID, followed-repositories list) synced device-to-device only via a
  §5.7 DM or backup restore. A RECOMMENDED removable-media (USB) backup
  covers all produced AND followed repos + config/keys repos, with a
  UI-chip freshness indicator (§3.8.6-§3.8.8, §9.6).
- **Other invariants:** CORE DMs are a nostr-double-ratchet mechanism
  (relay-carried, never repo-committed, no backfill; forward secrecy +
  post-compromise security; §5.7); replies/reactions use the Nostr
  outbox model (scatter-gather threading, no write access to another
  persona's repo); moderation approvals anchor per hosting (repo anchor
  in the delegate-threshold canonical history, OPTIONAL Matrix anchor,
  or a reduced-assurance relay-only `created_at` fallback), NIP-32
  `kind:1985` labels are advisory-only, and post-hoc removal uses Nostr
  `kind:5` deletions; encrypted blobs live on `enc/<key_id>` branches
  whose rotation force-deletes the retired branch (cooperative scrub,
  not erasure; §6.10.4); Tier 3 has no forward secrecy - a compromised
  audience key reads all past posts under its `key_id` (§9.5); hardening
  includes scoped ±5-minute clock skew on root attestations, mandatory
  SSRF prevention on ATProto DID resolution, and a mandatory `nip01_raw`
  canonical-serialization field on signed events. The OPTIONAL ATProto
  attached outbox (§11.6) and KERI social witnesses are available.

The spec is implementation-agnostic — no particular language or
runtime is prescribed.

The next milestones are:

1. Expand the authored v0.4.0 test-vector suite in `docs/spec/vectors/`
   (all §14.3 coverage-map categories authored; edge cases grow with the
   0.x draft).
2. Build a first-party client implementation (language and runtime
   to be chosen separately; the spec is agnostic) to validate the
   protocol end-to-end. Scheduled alongside this node work (ADR-032):
   compromised-key content revocation - tooling that identifies and
   revokes/quarantines repo commits authored inside a declared
   `compromise_since` window (spec §3.5.2), interacting with `kind:5`
   deletions and §6.10.4 branch-scrub semantics.
3. Iterate the spec based on implementation feedback toward 1.0.

## How to navigate this repo

| Path | What it is |
|---|---|
| `docs/spec/heterodyne.md` | The normative spec. Single living document (currently 0.x, in flux until 1.0). |
| `docs/architecture.md` | Non-normative architecture overview + design rationale for each load-bearing decision. |
| `docs/glossary.md` | Term definitions referenced from the spec. |
| `docs/security/threat-model.md` | Companion analysis to spec §13 (security model). |
| `docs/spec/vectors/` | Conformance test vectors (authored v0.4.0 suite covering the §14.3 map; generator tooling included). |
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
