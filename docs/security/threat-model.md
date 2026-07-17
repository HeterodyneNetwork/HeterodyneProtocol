# Threat model

**Status:** DRAFT stub. Will graduate as spec sections mature.

This document enumerates the actors, assets, and threats that the
Heterodyne specification must defend against. It is non-normative; the
normative spec ([`../spec/heterodyne.md`](../spec/heterodyne.md)) flows
from the analysis here, in particular its §13 security model.

As of v0.4.0 (ADR-026 through ADR-029), Heterodyne's **core substrate** is
Nostr signed events carried over two co-equal MUST backends - ordinary
Nostr relays and Radicle-backed repo relays - with **Matrix** demoted to an
OPTIONAL SHOULD-level layer for real-time discussion, DMs, and calls. CORE
actors and invariants below apply to every deployment, including
Matrix-free ones; items marked **OPTIONAL Matrix layer** apply only when
that layer is in use.

## Inherited invariants

Heterodyne inherits the following invariants from sibling project `mxdx`:

- **When the OPTIONAL Matrix layer is in use, every Matrix event in a
  private context is end-to-end encrypted**, including state events
  (MSC4362). No exceptions.
- **Sensitive material at rest is encrypted.** The persona's `nsec`, its
  Ed25519 Radicle NID secret where a device holds one, and any Matrix
  device keys use OS keystore / keychain integration where available.
- **No backend-side parsing of payload.** Bridging logic is purely
  client-side; every backend - Nostr relay, repo relay, routing node, and,
  when the OPTIONAL Matrix layer is in use, homeserver - is a blind
  transport.

## Heterodyne-specific invariants

These correspond directly to spec §13.2's I1-I7 normative invariants;
this section restates them in the threat model's own voice.

- **I1 - Blind carrier and honest tiers.** Tier 3
  (encrypted-blobs-in-repo) content is NIP-44-encrypted under an audience
  key before it reaches any repo, relay, or seed node, so no full node,
  seed, or relay ever sees Tier 3 plaintext. Tier 2 (private repo) is a
  selective-replication boundary, NOT encryption: content is plaintext on
  every allowed seeder, and a client MUST present that honestly and MUST
  NOT describe it as "encrypted." When the OPTIONAL Matrix layer is in
  use, no homeserver sees plaintext for any event in a `private_discussion`
  room or config room, including state events.
- **I2 - Identity integrity.** The npub is the authoritative author of
  every event. Matrix MXIDs are delegated publishers, never identities in
  their own right.
- **I3 - Dual-authenticated delegations.** A delegation is active only
  when both the persona's epoch key and the delegation target
  cryptographically attest to the binding. In CORE, the target is an
  Ed25519 Radicle NID and the binding MUST carry both the epoch key's
  BIP-340 signature and the NID's own Ed25519 signature (`nid_proof`) over
  the same payload. In the OPTIONAL Matrix layer, the target is an MXID
  and the binding is the epoch-key signature plus the MXID self-publishing
  the delegation via normal homeserver `/send/state` authorization.
  Either side alone cannot create a binding.
- **I4 - Verification before render.** Every event MUST be
  signature-verified (and delegation-checked) before rendering, regardless
  of which backend served it. `kind:31005`/`kind:31010` routing hints are
  never a substitute for verification.
- **I5 - No central directory.** Discovery is relationship-mediated; there
  is no global registry of users, personas, RIDs, or follow graphs to
  compromise.
- **I6 - At-rest encryption.** The persona's `nsec`, its Ed25519 NID
  secret where held, cached identity state, and private mute lists MUST
  be stored encrypted at rest. Concretely, key material lives in the
  local-only **keys repository** (spec §3.8.7) with the `nsec` NIP-49-wrapped
  under a user-controlled secret; non-key private state lives as encrypted
  blobs in the unadvertised **config repository** (§3.8.6); and private
  NIP-51 list items are NIP-44-encrypted to self under the epoch key (§8.5).
  OS keystore SHOULD protect the store where available.
- **I7 - Client-side bridging only.** The cross-backend/cross-protocol
  bridge runs on the user's device. No full node, repo relay, routing
  node, Nostr relay, or (OPTIONAL Matrix) homeserver may be a bridging
  component that sees Tier 3 or Matrix-E2EE plaintext.

## Privacy tiers and trust boundaries

Broadcast confidentiality is a property of repo visibility plus app-layer
encryption, not of a server (spec §9.0, §5.2). Each tier's trust boundary,
stated honestly:

- **Tier 1 - Public repo.** World-readable plaintext, mirrored to ordinary
  Nostr relays. Confidential against no one.
- **Tier 2 - Private repo ("unencrypted-but-not-discoverable").**
  Invisible and unfetchable to non-allowed nodes, but **plaintext git
  objects on every allowed seeder**. NOT confidential against members or
  any allowed node. The `visibility.allow` list itself is a metadata
  exposure distinct from content confidentiality: it reveals the
  audience/membership graph to any node that can see the repo's identity
  document.
- **Tier 3 - Encrypted-blobs-in-repo.** NIP-44 v2 ciphertext under an
  audience key, generated before commit. Confidential against everyone who
  is not a key-holder, including seeders and rented full nodes. The wire
  exposes only an opaque `key_id` - room/RID identity does not leak - but
  an external observer can still enumerate published `kind:31007` page
  identifiers and infer per-persona posting cadence from event timestamps.
  **No forward secrecy:** the audience key is static, so a compromise of it
  decrypts every past post under its `key_id` (from relays, repo history,
  and backups). Rotation on member removal limits *future* exposure only,
  and the §6.10.4 key-ID branch scrub is cooperative hygiene, not protection
  (see the forward-secrecy threats below and spec §9.5).

**Forward secrecy differs by mechanism** (spec §9.5) and one mechanism's
guarantee MUST NOT be inferred for another: Tier 3 broadcast has none;
**CORE DMs** (§5.7 double ratchet) have forward secrecy plus post-compromise
security; NIP-17 gift-wrap DMs to vanilla recipients have none; and the
OPTIONAL Matrix layer's Megolm/MLS has forward secrecy within its session
rotation, scoped to Matrix rooms only.

Metadata exposure is not confined to one tier: full nodes and ordinary
Nostr relays see fetch/read timing regardless of tier, and a routing node
sees which repos/npubs a client asks about (never content, at any tier).
See spec §13.1.1 for the full attacker-capability enumeration.

## Actors

| Actor | Capability assumption |
|---|---|
| **Trusted client** | A conformant Heterodyne client implementation; honest. Holds the user's nsec, Ed25519 NID secret, and Matrix device keys where applicable. |
| **Hostile full node / seeder** | Serves a persona's repo relay and/or seeds its RID. Reads plaintext for any Tier 1/2 content it seeds; can drop, delay, or selectively withhold events; sees read/fetch metadata (who asked for what, when). Cannot forge npub-signed, client-verified events and never sees Tier 3 plaintext (no audience key). A light node routes around a withholding node using other hosts and the ordinary-Nostr-relay fallback. |
| **Hostile routing node** | Answers "which full nodes serve this npub/RID?" from `kind:31005`/`kind:31010` ads. Sees only query metadata - which repos/npubs a client asks about - never content, and cannot proxy or tamper with content it never holds. Its answers are hints only; clients verify content independently regardless of source. |
| **Hostile homeserver (OPTIONAL Matrix layer)** | Can drop, delay, reorder events. Can lie about state to clients that don't verify. Cannot decrypt E2EE traffic. May correlate metadata (room IDs, timing, participant MXIDs). Only relevant when a persona runs the OPTIONAL Matrix layer. |
| **Hostile relay (ordinary Nostr)** | Can drop, delay events. Cannot forge signatures. Can correlate by npub. |
| **Passive network observer** | TLS-bounded. Sees connection metadata (peers, timing, volume); cannot read content. *Mitigation (per ADR-019, extended by ADR-026/029):* clients ship embedded Tor and offer opt-in egress-over-Tor (§7.7 of the spec) covering Nostr relays, repo relays, routing nodes, full nodes, and (OPTIONAL) homeservers alike; with egress enabled, the observer no longer sees the user's real peer set or location - only a Tor entry guard. Residual: Tor-level timing/volume traffic analysis (below). |
| **Federation peer (OPTIONAL Matrix layer, per ADR-016)** | A Matrix homeserver participating in a room's server-server federation that is neither the persona's own homeserver nor an adversary. Sees: all unencrypted state in public rooms; Megolm ciphertexts as opaque blobs; full `m.room.member` events; sender MXIDs + `origin_server_ts`; the federation join event graph. Cannot see: Megolm-encrypted content in private rooms; identity/config-room content for personas hosted on homeservers it is not federated with. Mitigation: personas concerned about membership-graph exposure SHOULD host their identity room on a homeserver whose federation peer set they trust. |
| **Colluding co-delegated MXID (OPTIONAL Matrix layer, per ADR-009)** | A peer MXID under the same npub that turns hostile. Has Megolm access to all config rooms via §3.9 mutual membership. Can: observe coordination state; attempt to plant lease conflicts during partition windows; race the single-MXID revocation procedure between `effective_at` and observation. Cannot: forge events signed under the persona's epoch key; evade the §3.9.6 partition-window void-and-requeue rule once the partition heals. Mitigations: §3.9.7 `effective_at` clamping; embedded Nostr-signed revocation attestations defend against forged peer revocations. |
| **Old-homeserver-during-overlap (OPTIONAL Matrix layer, per ADR-015)** | The source homeserver `H1` during the 7-day voluntary homeserver-exit window (§3.10, Matrix-layer only). Retains write access to the old identity room; can attempt to forge state events after the migration. Mitigation: the §3.10.3 migration-pointer-precedence rule makes the migration announcement in the OLD room authoritative regardless of subsequent `H1`-side activity. |
| **Compromised delegation** | Attacker controls a previously-authorized device: an Ed25519 NID/publishing-key pair in CORE, or a Matrix account in the OPTIONAL layer. Can publish NID-signed or MXID-published events claiming the npub *until revoked*. Cannot retroactively forge older events because each one is Nostr-signed at publication time. |
| **Compromised cold root** | Catastrophic for the persona. Recovery requires §3.5 KERI rotation/recovery from a clean device with sufficient witness support; the KEL preserves persona continuity where possible, but events the attacker published before revocation are valid. |
| **SHA-1 RID / git-object collision (structural, re-scoped)** | Not an active attacker but a structural property, verified against Heartwood 1.9.1: Radicle RIDs and git objects are SHA-1-based (no SHA-256 repository mode exists). A SHA-1 collision against a genesis identity document's canonical-JSON blob could yield two genesis documents sharing one `rad:` RID string - RID-genesis-binding confusion. It cannot forge a valid alternate identity document, post, or event stream: git refs/COBs carry independent delegate Ed25519 signatures, and every Nostr event carries an independent BIP-340 signature over its own SHA-256 NIP-01 id, none of which derives integrity from the RID's hash. Clients resolve any observed genesis divergence via the KEL and the cold-root-signed `kind:31005` binding, both SHA-1-independent. |

## Threats and mitigations (initial list)

### Impersonation via friendly homeserver (OPTIONAL Matrix layer)

A homeserver could insert events claiming to be from MXID X.

*Mitigation:* every wrapped event carries an independent Nostr signature;
receivers reject if signature fails or if `nostr.pubkey` is not the
KERI-authoritative epoch key for the persona delegated to the sender
MXID. Bare Matrix events are attributed only when the event's
`heterodyne_persona` (or an unambiguous room context) resolves to an
active delegation for the sender at the event's Matrix timestamp;
otherwise they render as vanilla Matrix. The CORE-substrate analogue - a
full node fabricating an NID delegation - is foreclosed by the
bidirectional `nid_proof` requirement (I3): a full node cannot produce the
NID's own Ed25519 signature over the binding payload.

### Phantom delegation (OPTIONAL Matrix layer)

A homeserver inserts a fake `m.heterodyne.delegation.v1` state event into
an identity room it hosts.

*Mitigation:* delegations are dual-authenticated. The Nostr attestation
must validate against the persona's current epoch key, whose authority
chains to the cold-root npub through the KEL. The Matrix state event's
`sender` must equal the delegation `state_key`, proving the named MXID
self-published it through normal homeserver `/send/state` authorization.
The CORE NID delegation has no equivalent single point of insertion: both
the epoch-key signature and the NID's own `nid_proof` are required (I3),
and no full node can supply the latter.

### Stale revocation

A compromised key is rotated, but a victim's client hasn't seen the
revocation yet and is still accepting events signed by the revoked key.

*Mitigation:* the persona's KEL, and, when the OPTIONAL Matrix layer is in
use, identity-room state, are re-validated on a configurable TTL and on
every repo re-fetch or Matrix `/sync` cycle. Clients SHOULD display
staleness indicators when verification cache exceeds the configured age.
KERI sequence numbers, witness first-seen ordering, and the cold-root
`kind:31005` identity pointer let verifiers distinguish the current
identity state from stale copies served by an attacker.

### Cross-persona linking via metadata

Even when content is encrypted, an observer can note that the same
device or client fetches from multiple personas' repos, or participates in
multiple identity rooms.

*Mitigation (incomplete):* personas SHOULD use separate devices, full
nodes, and/or (when applicable) homeservers per persona. Per ADR-019,
extended by ADR-026/029, clients ship embedded Tor and offer opt-in
egress-over-Tor (§7.7 of the spec) across every endpoint type - Nostr
relays, repo relays, routing nodes, full nodes, and OPTIONAL homeservers;
when enabled, any on-path observer sees only a Tor entry guard rather than
the user's IP, removing the *network-level* correlator across personas.
It remains *incomplete*: a full node, relay, or (in the OPTIONAL Matrix
layer) homeserver can still observe the same client/device fetching or
publishing across multiple personas at the application layer regardless of
network path. Reducing that still relies on separate accounts/full
nodes/homeservers per persona, and a mixnet-grade defense against
Tor-level traffic analysis remains future work.

### Bridge-side plaintext leak

A traditional appservice bridge, or a server-side component on any
backend, would see plaintext before it is encrypted or before it reaches
the user.

*Mitigation:* spec §10 and I7 forbid server-side bridges entirely on any
full node, repo relay, routing node, Nostr relay, or (OPTIONAL Matrix)
homeserver. A user-owned personal bridge is within the user's trust
boundary by construction and is not considered a third-party component.

### Replay across forks of the identity room (OPTIONAL Matrix layer)

An attacker mirrors an outdated identity room and presents it to
verifiers to mislead them about current delegations.

*Mitigation:* receivers resolve to the latest Matrix room state per
standard state resolution. Signed Heterodyne state events have
monotonically increasing `created_at` and stale attestations lose to
fresh ones via combined Matrix state resolution and Nostr signature
timestamp comparison. On the CORE substrate the equivalent divergence
(identity document vs. KEL) is resolved by KEL precedence (§3.9.10), not
Matrix state resolution.

### Backdating attacks

An attacker holding a recently-revoked key signs events with a
`created_at` predating the revocation.

*Mitigation:* a defense in depth, not a guarantee. Clients SHOULD
display "signed by previously-revoked key" warnings for events whose
`created_at` is within a configurable suspicion window before
`revoked_at`. Definitive resolution requires future work on signed
timestamping (e.g., Nostr relay receipts or Bitcoin OpenTimestamps as
auxiliary witnesses).

### Hostile relay refusing to deliver

A vanilla Nostr relay deliberately drops a user's events.

*Mitigation:* the user fans out to multiple relays per their NIP-65
write-relay list, and separately commits the same event to its repo
relay(s), held by every full node seeding the persona's RID - so
relay-level censorship does not remove the event from the two-backend
surface. Censoring the event requires colluding with all subscribed
relays *and* all full nodes seeding the repo, a materially higher bar than
either backend alone (§6.4; ADR-010 asymmetric-delivery contract).

### Full node withholding or selective censorship

A full node serving a persona's repo relay learns who fetched what and
when, and may drop, delay, refuse, or selectively withhold events it
holds.

*Mitigation:* a full node cannot forge npub-signed, client-verified events
(I2, I4) and can only withhold. A light node routes around a withholding
node using other hosts from the routing node's list and the
ordinary-Nostr-relay fallback backend (§10.1.1, §13.3).

### Routing-node query-metadata leak

A routing node sees *which* repos/npubs a light node asks about - a
metadata leak about the reader's interests - but never content, and
cannot tamper with what it never holds.

*Mitigation:* clients treat routing-node answers as unverified hints,
verify content independently regardless of source, and MAY rotate or
self-host routing nodes to avoid concentrating query metadata with a
single operator (§10.1.1).

### Malicious allowed seeder reads Tier 2 plaintext

A node the persona adds to a Tier 2 repo's `visibility.allow` set holds
the content as plaintext git objects and can read everything; the allow
list itself also reveals the audience/membership graph to any node that
can see the repo's identity document.

*Mitigation:* this is inherent to Radicle private repos, not a bug -
mitigated only by keeping the allow list minimal, the private-tier
honesty requirement (a client MUST NOT describe Tier 2 as "encrypted"),
and moving content that must be confidential against seeders to Tier 3
encrypt-before-commit (§6.10, §9.0).

### Org rogue-epoch-key relay-bypass

A lone holder of an organization persona's epoch key signs a `kind:31007`
index or post and publishes it to ordinary relays, attempting to pass it
off as the org's canonical feed.

*Mitigation:* an org's posts and index MUST be reachable from the
delegate-threshold-approved canonical feed branch to be treated as
canonical (§6.7.0, §8.8); a single signature published off that branch
does not satisfy M-of-N governance. FROST-style threshold epoch-key
signing is deferred future work (ADR-027).

### Audience-key compromise exposes Tier 3 history (no forward secrecy)

Tier 3 broadcast encrypts under a **static** per-generation audience key,
so an attacker who obtains that key reads every past post committed under
its `key_id` - from ordinary Nostr relays, from repo git history, and from
any backup - not just messages from the moment of compromise forward.

*Mitigation (honest, not a guarantee):* the spec never presents Tier 3 as
forward-secret (§9.5). Mandatory audience-key rotation on member removal
(§6.7.4) bounds *future* exposure to a removed member, and the §6.10.4
key-ID branch scrub shrinks the long-tail footprint of retired ciphertext
on cooperating seeds. The scrub is **cooperative hygiene, not cryptographic
erasure**: a hostile, offline, or non-conforming seed MAY retain a retired
`enc/<key_id>` branch forever, per-seed object reclamation timing is neither
immediate nor observable (source-verified for Heartwood 1.9.1: reclamation
is a post-fetch `git gc --prune=1.hours.ago --auto`, gated by git's auto
thresholds, so a low-churn repo can retain unreachable ciphertext
indefinitely even on a conforming seed - spec §6.10.4 verification note),
and ciphertext already published to ordinary Nostr
relays (the other MUST backend) is untouched by any branch deletion and
persists per relay policy. Confidentiality against a *removed member* rests
on the rotation (they already held the old key; the old ciphertext was never
secret from them); confidentiality against *non-members* rests on the
encryption, never on deletion. At-rest protection of held audience keys is
the keys repository (§3.8.7, I6). A no-history sender-key ratchet for Tier 3
is a possible future 0.x direction, not a current property.

### DM conversation metadata at relays

Two personas DM over the core substrate; a relay that carries the traffic
could otherwise link a conversation's messages to each other and to the
participants.

*Mitigation:* CORE DMs (§5.7) run a Signal-style Double Ratchet carried in
Nostr events, giving **forward secrecy plus post-compromise security** -
per-message keys are deleted as the ratchet advances, so compromising
current state does not decrypt past messages and a fresh DH step re-secures
the session afterward. Each `kind:1060` outer message is signed by the
sender's current DH ratchet key - a fresh key per ratchet step, NOT the
sender's epoch key - so a relay cannot correlate outer events to either
persona; messages sent within the same ratchet epoch share an outer signer
and are linkable to each other until the next DH step rotates it; §5.7.4
message-request gating sends no receipt or typing
signal to unaccepted senders. Ratchet ciphertext MUST NOT be committed to a
repo or stored by a repo relay, and there is no DM backfill, so no permanent
traffic record accrues on the durable backend. The residual is the
forward-secrecy corollary: lost ratchet state = unrecoverable history
(§3.8.7). DMs to vanilla-Nostr-only recipients fall back to NIP-17
gift-wrap, which has **no** forward secrecy (static ECDH conversation key);
clients SHOULD surface that on fallback.

### Stale-list rollback (relay serves an old mute or moderator list)

Mute lists (`kind:10000`), sets, and the `kind:34550` moderator declaration
are NIP-51/NIP-72 replaceable/addressable events; a hostile ordinary Nostr
relay could serve an older revision than the one the persona has since
published, silently reinstating a blocked account or a removed moderator.

*Mitigation:* because a repo relay's event store is git, the full revision
history of a list is retained and tamper-evident. A client MAY detect a
rollback (a relay serving a revision older than one reachable in the repo's
canonical history) and MUST prefer the newest verifiable revision (§8.5).
Moderator-set integrity in particular is resolved **as-of the approval's
anchor** against canonical ancestor history rather than a relay's current
view (§8.2.1).

### Keys repository loss or compromise

The keys repository (§3.8.7) is the single local-only home for a device's
`nsec`, epoch/NID secrets, held audience keys, the config-repository RID and
its key, and OPTIONALLY ratchet state. It is never Radicle-replicated,
seeded, or published.

*Mitigation and honest loss semantics:* the store MUST be encrypted at rest
(I6) with the `nsec` NIP-49-wrapped under a user-controlled memory-hard
secret, and the OS keystore SHOULD protect it. Sync between a user's own
devices happens only over an encrypted §5.7 DM session (authenticated by the
peer device's `kind:31001` delegation - a client MUST refuse a sync from a
revoked or unverifiable device) or an offline backup restore (§3.8.8).
Losing every copy and backup loses the audience keys (Tier 3 history becomes
unreadable), ratchet state (DM history is unrecoverable - a forward-secrecy
consequence), and the config-repository pointer; identity-level recovery of
the persona remains the §3.5 KERI path. A compromise of the store is a
compromised-device event (out of scope, below) but is bounded by the cold
root being held offline (§3.5.0). Removable-media backups carry the
encrypted keys repository and are as sensitive as the keys themselves; the
keys portion MUST stay encrypted in backups.

### Config repository de-anonymization

The config repository (§3.8.6) is a private Radicle repo of encrypted blobs;
an observer who could associate it with a persona would learn that the
persona keeps private config and (from its allow list) which device NIDs it
runs.

*Mitigation:* the config repository's RID is **unadvertised (MUST)** - it
appears in no `kind:31005`, `kind:31010`, NIP-65 list, `kind:0` profile,
NIP-51 list/set, feed index, or Matrix state - and knowledge of it travels
only through the keys repository, a §5.7 device-to-device DM, or a backup
restore. Combined with `visibility: private`, a non-allowed node cannot
fetch it and an outside observer cannot link it to the npub. One config
repository per persona (a shared repo would link personas through their
common seeders, §3.4), and the config audience key is distributed
off-substrate rather than via a published `kind:31011` wrap (publishing a
wrap would advertise the repo's existence and audience). The allow list
names only the persona's own device NIDs, so a party on it is already one of
the persona's devices.

### Moderation as-of integrity and the relay-only fallback

A moderated-feed view depends on resolving "who were the authorized
moderators when this approval was made?" An attacker who could rewrite that
history, or backdate an approval, could smuggle in or retroactively
legitimize approvals.

*Mitigation and residual trust:* for a repo-hosted (CORE) community the
as-of moderator set is the newest `kind:34550` revision reachable in the
approval's introducing commit's ancestor history on the delegate-threshold
canonical branch (§8.2.1). Integrity rests on the **same delegate-threshold
sigrefs machinery** that anchors everything else in the repo - which means
the only parties who could rewrite this history are the same delegates who
already control the moderator list itself, so the rewrite grants no
authority they lack. A removed moderator cannot obtain a new anchor
positioned before their removal, and later removal does not retroactively
invalidate earlier anchored approvals. The **relay-only fallback** (a
community with neither a repo nor a Matrix room) instead places approvals by
author-forgeable `created_at`, trusting listed-then-removed moderators not
to backdate; verifiers MUST treat relay-only communities as carrying this
weaker property, and communities SHOULD host in a repo (or Matrix room) when
moderation-history integrity matters (§8.1).

### Sybil vouching for a hostile key (per ADR-021)

An attacker mints many cheap "friend" identities and floods a persona's
recovery with informal `kind:31008` vouches, hoping to push a key the
persona never authorized over the rotation threshold.

*Mitigation:* informal `kind:31008` vouches are **advisory only** - by
the §3.5.5 / §3.5.3 invariant they are NEVER counted toward the rotation
threshold, so no number of fake friends can move a rotation toward
acceptance. Rotation acceptance rests entirely on declared-witness
weight (or the cold root). Informal vouches only feed a UI confidence
display and *manual* promotion suggestions; promotion into the declared
set is always an explicit user action (clients MUST NOT auto-promote).
The attack therefore has no purchase on acceptance at all. The §3.5.6
witness-hygiene SHOULDs (≥3 declared witnesses, ≥5 for personas with
>1000 mutuals, periodic re-verification) ensure the declared set - the
only thing that *does* gate acceptance - stays live and adequately
sized.

### Hostile mirror homeserver (OPTIONAL Matrix layer, per ADR-020)

A homeserver hosting a non-primary Matrix mirror replica (§3.11.2)
withholds state, serves stale state, or lies about room contents. The
CORE-substrate analogue - a hostile full node holding a repo replica - is
covered above under "Full node withholding or selective censorship."

*Mitigation:* the primary is the room named by the cold-root-signed
`kind:31005` pointer, and every signed event is verified by its Nostr
signature regardless of which replica served it. A hostile replica cannot
forge persona-signed content, and followers deduplicate by Nostr event id.
The blast radius of any one replica is bounded to availability, not
authenticity.

### Friend-cache poisoning (per ADR-021)

A follower caching a persona's identity and feed state (whether carried
on relays/repo or, when the OPTIONAL Matrix layer is in use, in a Matrix
identity room, §3.12.1) attempts to serve poisoned or fabricated state to
other followers during an outage.

*Mitigation:* the cache content filter admits ONLY events signed by the
persona's own Nostr identity (plus KERI events, which carry their own
signatures/attestations); a cacher cannot inject arbitrary state.
Cache-served state MUST be marked stale and cache-sourced, and the
authoritative re-anchor signal remains the fresh cold-root `kind:31005`
on relays (§3.12.2), which a poisoning cacher cannot forge.

### Lying or stale `kel_head` (per ADR-032)

An attacker (or an honestly stale client) stamps a `kel_head` that
does not match the persona's accepted KEL - stale, fabricated, or
pointing at a fork - hoping a verifier shortcuts to the wrong key
state, or a stolen epoch key emits backdated events naming a
still-valid old head.

*Mitigation:* spec §4.5.1 - `kel_head` is advisory and can never
substitute for KEL replay; the accelerator runs only under
decision-equivalence conditions (a)-(d), whose condition (c) applies
the §3.5.2 `effective_compromise_since` retroactive cutoff (also
enforced under full replay), closing the backdating hole; a head off
the accepted KEL MUST yield the `equivocation-flagged` outcome and be
surfaced.

### Relay suppression, replica lag, and repo rollback of key material (per ADR-032)

Relays drop or withhold key-material events (`kind:31002`/`31003`/
`31001`); a stale repo replica makes a valid event look revoked; or a
compromised repo host serves a rolled-back key history.

*Mitigation:* spec §3.9.10.1 - dual publication is mandatory and the
repo-carried set is canonical, so relay loss cannot regress key
state; §4.5.2 - relay-only events are provisional (never silently
final), absence-based withdrawal is convergence-gated (KEL `seq`
watermark; for `kind:31001`, conflict, revocation, or the §10.1.2
ingestion checkpoint - never bare absence); regressing repo heads are
rejected absent an authenticated re-anchor, and GC must not drop
finalized key material.

### Export-AID misuse (per ADR-032)

A verifier or downstream system treats a persona's derived did:webs
export AID as an authoritative identity, or an operator mints export
identities for personas without consent.

*Mitigation:* spec §11.8 - the export AID is derived and never
authoritative; substituting it for the npub anywhere the spec
requires one is non-conformant; enabling an export AID requires
operator consent; unmappable security-relevant state fails loudly
(fixed taxonomy) rather than exporting degraded security state.

## Out of scope (for now)

- Defenses against compromised user devices (key extraction via OS-level
  malware). The npub holder is assumed to be in control of their device.
  Heterodyne secures its own application surface, not the host OS or
  device. The **cold root** is the relevant in-scope mitigation for the
  application layer: because it is held offline and signs only rare
  identity-anchoring events (§3.5.0), routine app-layer compromise of a
  warm device does not expose it, and recovery from epoch-key loss is
  possible via KERI rotation (§3.5) plus social vouching (§3.12). What
  remains out of scope is an attacker who has fully compromised the OS
  of the device that *holds* the cold root during a ceremony - that is a
  platform-security problem Heterodyne cannot solve from inside its app.
- Tor-level traffic analysis (timing/volume correlation against the Tor
  network itself). As of ADR-019, extended by ADR-026/029, `.onion`
  reachability and opt-in egress-over-Tor are *in scope* (clients ship
  embedded Tor, §7.7 of the spec) and mitigate the clearnet passive
  observer and the IP-level cross-persona correlator, across Nostr
  relays, repo relays, routing nodes, full nodes, and OPTIONAL
  homeservers alike. What remains out of scope is correlation performed
  against the Tor circuit itself: traffic patterns are fingerprintable,
  and a global passive adversary observing Tor entry/exit can still
  attempt timing/volume correlation. A mixnet-grade defense is future
  work.
- Quantum-adversary resistance. `secp256k1` and `Ed25519` are not
  post-quantum. Mitigation strategy will follow Nostr's and Radicle's
  upstream when they have one.
- The repo-relay SERVER/STORAGE conformance target (ref namespace, COB
  type registry, retention/GC/quota rules) is a named pre-1.0 spec work
  item (§10.1.2); storage-exhaustion defenses that depend on it are not
  yet fixed and are out of scope until that contract lands.

## Open questions to address before v1.0

The three open questions previously tracked here are now resolved:

1. **Identity rotation x Megolm session keys - RESOLVED.** They are
   independent. Spec §9.4 establishes that KERI epoch rotation changes
   the persona's Nostr signing key but not the Matrix device or its
   Megolm sessions: rotation is invisible to Megolm, no session
   invalidation is required, and the new epoch key co-signs subsequent
   attestations through the same MXIDs. Delegation revocation is a
   verification-layer concern, not a Megolm-session concern.
2. **Warning vs. suppression on verification failure - RESOLVED as
   intentionally loose.** Clients choose contextually how to surface or
   suppress verification-failure signals; the spec deliberately does
   not tighten this into a single normative rule. (Strict mode, §11.7,
   tightens the broadcast-signature subset for clients that opt into the
   high-assurance profile.)
3. **Permanent identity-room homeserver loss - RESOLVED (per ADR-020,
   ADR-021, reframed by ADR-026).** A persona's primary redundancy engine
   is now opt-in Radicle seeding (§3.11): any peer that chooses to seed
   the persona's RID holds a full replica, and losing one full node
   degrades to another host plus the ordinary-Nostr-relay backend. When
   the OPTIONAL Matrix layer is also in use, a persona running
   identity-room mirrors additionally survives a single-homeserver outage
   by promoting a replica. When every persona-run full node (and, if
   applicable, every Matrix mirror) is permanently gone, the involuntary
   re-anchor procedure (§3.12) applies: the persona republishes a
   cold-root `kind:31005` to relays, and follower-cached identity state
   bridges verification until it propagates. Two-tier vouching (declared
   §3.5 witnesses + capped informal `kind:31008` vouchers) re-establishes
   key continuity.

No open questions remain blocking v1.0 from the items previously listed
here; new ones will be added as the spec matures.
