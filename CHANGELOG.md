# Changelog

All notable changes to the Heterodyne protocol family are recorded here.
Each document is in its **0.x phase**: under Core's version rules, any `0.x`
document release may break its predecessor. The strict PATCH/MINOR/MAJOR
compatibility contract takes effect independently when a document reaches
`1.0.0`.

## [Unreleased]

ADR-033 split the 0.4.0 monolith and prepared four independently versioned
0.5.0 documents. Their contents are current normative authority at their
repository paths, but the versions remain untagged and unreleased pending
explicit release approval.
[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is now the non-normative
family map. Prepared release combinations and the exact registry digest are
recorded in [machine-readable manifests](docs/spec/releases/).
The Marmot/Radicle integration is recorded historically in
[ADR-040](docs/adr/archive/2026-08-06-040-marmot-radicle-group-messaging.md)
and was integrated by [PR #19](https://github.com/HeterodyneNetwork/HeterodyneProtocol/pull/19).

### Core 0.5.0

- Prepared [Core](docs/spec/heterodyne-core.md) `core/0.5.0`, owning identity,
  KEL verification, canonical bytes, Radicle delegation and repository
  substrate, registry, versioning, and base conformance.
- Added the Core-owned, separately revisioned registry for kind allocations,
  immutable profile discriminators, reason codes, and namespaced security
  invariants.
- Added ADR-035 role-scoped transport: persistent v3 onion full nodes with
  Tor-default backend egress, outbound-Tor light clients, and explicit
  reduced-assurance browser operation through shared clearnet relays.
- Added KERI attribution for stable Marmot human-messaging, group-admin, host,
  and agent roles without changing Marmot validity or MLS convergence.

### Comms 0.5.0

- Prepared [Comms](docs/spec/heterodyne-comms.md) `comms/0.5.0`, depending on
  `core/0.5.0` and owning privacy tiers, publishing, feeds, Marmot
  conversations and media, Radicle-backed group storage, credential sync, and
  generic subprotocol carriage.
- Added ADR-034 atomic `kind:31013` typed-key claims and irreversible
  `kind:31014` revocations, strict attenuation and native possession proofs,
  and an encrypted private multi-writer claim ledger as the authority for
  persona-issued device claims.
- Added the one-persona OIDC/OAuth issuer, interoperable RS256 ID Tokens and
  RFC 9068 access tokens, consent-gated pairwise release, the public Radicle
  continuity mirror, and the exactly pinned
  `draft-ietf-oauth-status-list-21` profile. These JWTs are projections, not
  canonical Heterodyne authorization.
- Added the fragment-only universal public launcher and local Tier-1 reader,
  including bounded relay hints, SSRF defenses, and in-place transition to an
  authenticated light-client session.
- Added ADR-036 automated authorship: stable full-node-held agent role keys,
  scoped temporary sender-constrained OIDC workload tokens, canonical
  automation attribution, and fail-closed refusal of user-key or unlabeled
  fallback.
- Adopted pinned Marmot as the sole user-facing direct/group conversation
  engine, with standard-compatible and Heterodyne-private group profiles,
  exact-byte Radicle-backed relays, routing generations, persona inboxes,
  retention/non-erasure, and `radicle-v1` media locators. Double Ratchet is
  now limited to bootstrap and Control.

### Control 0.5.0

- Prepared [Control](docs/spec/heterodyne-control.md) `control/0.5.0` as an
  incomplete Comms profile requiring Core, Comms, and `double-ratchet`.
  Control remains non-claimable until its integration and vector gates close.
- Control consumes only `active` Comms claim decisions for enrollment and RPC;
  it defines no independent claim wire profile and gives NID-less session
  devices neither ledger access nor ledger keys.
- Integrated the relay-affine restart-safe request subset and the bounded
  agent token/publication/audit subset with normative partial vectors. Control
  remains non-claimable until the remaining ADR-030 enrollment/session gates
  close.
- Added grant-filtered node-mediated Marmot operations and group-scoped agent
  operations while keeping all Marmot account, leaf, epoch, and repository
  secrets on the designated node.

### Social 0.5.0

- Prepared [Social](docs/spec/heterodyne-social.md) `social/0.5.0`, depending
  on Core and Comms and owning public social behavior, moderation, durable
  assets, and optional ATProto attachment.
- Added public agent-policy receipts, subscriber-local canonical policy lists,
  visible/removable default subscriptions, and remediation scoped to the
  offending role device key. No moderator or policy list has global power.
- Removed the former optional group-communication layer; private replies and
  reactions now start or reuse Marmot conversations through Comms.

### Family migration and conformance

- Established the family's only normative dependency edges as
  `Core <- Comms <- Control` and `Core <- Comms <- Social`.
- Advanced all four untagged 0.5.0 release manifests to registry revision 4.
  Only Comms advertises `key-claims`, `private-claim-ledger`,
  `oidc-jwt-projection`, and `token-status-list-draft-21`; Core and Social add
  no claims/OIDC feature, and Control retains its exact Comms dependency.
- Added immutable strict-v2 Comms and Social profiles for the ADR-035/036
  invariants while leaving every strict-v1 membership unchanged.
- Replaced the historical monolith strict mode with composable profile IDs
  for Core, Comms, Control, and Social. The Control strict identifier is
  reserved-inactive with its baseline conformance gate.
- Preserved all pre-split normative bytes in
  [`docs/spec/archive/heterodyne-0.4.0.md`](docs/spec/archive/heterodyne-0.4.0.md)
  unchanged and added the complete
  [old-section anchor map](docs/spec/archive/heterodyne-0.4.0-anchor-map.md).
  The 0.4.0 notes below are historical archive descriptions, not current
  ownership guidance.

### Historical 0.4.0 work recorded before the family split

Empirical verification pass against `rad`/`radicle-node` 1.9.1 and the
Heartwood source at tag `releases/1.9.1`, closing several items the
v0.4.0 spec had left open pending verification (ADR-026/ADR-027).

### Verified - Heartwood 1.9.1 empirical verification
- Identity document confirmed stored as a `xyz.radicle.id` COB;
  `refs/rad/id` is a local, per-node convenience pointer to the COB's
  tip - not a second, independent storage form (§3.9.10).
- `rad id update` confirmed as a propose/accept mechanism: identity-doc
  revisions (delegate, threshold, or payload changes) are adopted once
  a **majority** of the live delegate set signs via `rad id accept` -
  the document's own `threshold` field does NOT govern its own
  revisions (it governs `defaultBranch`/`crefs` canonical-ref
  acceptance instead). Split into two named mechanisms so the two are
  never conflated (§3.9.10). A newly added delegate must already carry
  `rad/sigrefs` in storage; Heartwood 1.9.1 has no force/override/
  emergency path, confirming the spec's fresh-RID + cold-root
  `kind:31005` re-anchor rule as the only deadlock escape.
- `xyz.radicle.crefs` per-ref canonical rules confirmed fully
  implemented and CLI-documented (`rad id update --payload
  xyz.radicle.crefs rules '{...}'`, clash validation against
  `defaultBranch` works as specified). Promoted from "OPTIONAL and
  EXPERIMENTAL, pending Heartwood-release verification" to "verified
  against Heartwood 1.9.1, still OPTIONAL" - baseline org canonicity
  intentionally does not depend on it, a scoping choice rather than a
  verification hedge (§6.7.0).
- Custom reverse-DNS COB types (e.g. `xyz.heterodyne.thread`) need no
  protocol or wire change, but `rad` tooling drives any non-built-in
  COB type through an external helper binary `rad-cob-<suffix>` (JSON
  Lines protocol) that must be on PATH; an implementation manipulating
  custom COBs via `rad` tooling must ship one (§10.1.2).
- Radicle's per-fetch size limits confirmed hardcoded in 1.9.1 with no
  CLI or node-config override: 5 MiB for special refs (`rad/id`,
  `rad/sigrefs`), 5 GiB for data refs. The storage contract treats
  these as fixed Heartwood limits, not Heterodyne-tunable parameters
  (§10.1.2).
- SHA-1 threat re-scoped: Heartwood 1.9.1 has no SHA-256 repository
  mode (the RID/git-object identifier type is structurally SHA-1-only).
  A SHA-1 collision now yields RID-genesis-binding confusion only (two
  genesis identity documents sharing one `rad:` RID string) - not
  content or event forgery, since git refs/COBs carry Ed25519 delegate
  signatures and every Nostr event carries a BIP-340 signature over its
  SHA-256 NIP-01 `id`, neither deriving integrity from the RID's hash.
  Divergence resolves via the KEL + cold-root `kind:31005`, both
  SHA-1-independent (§13.1.1).
- Per-seed unreachable-object reclamation (the §6.10.4 rotation
  scrub's disk-level effect) source-verified against the Heartwood
  source at tag `releases/1.9.1`: `radicle-node` runs
  `git gc --prune=1.hours.ago --auto` after every completed fetch of
  a repo (fetch-driven, not timer-driven; the expiry is hardcoded and
  not node-configurable). The `--auto` gate means the run is a no-op
  below git's auto thresholds, so retired ciphertext on a low-churn
  repo can persist indefinitely even on a conforming seed; storage
  repos are plain bare repos with no reflogs, so nothing else pins
  deleted-branch objects. Closes the "open empirical item" hedge in
  the §6.10.4 verification note without changing the stated trust
  boundary (cooperative hygiene, not erasure).
- The repo-relay SERVER/STORAGE contract (ref namespace, COB type
  registry, NIP-01-filter-to-git-read mapping, retention/GC/quota)
  remains the one open Heartwood-related TBD - a named pre-1.0 spec
  work item, deliberately still unresolved (§10.1.2).

A second work stream in this Unreleased window pulls mutes, backups,
DMs, and moderation anchoring onto the core substrate. It adopts NIP-51
lists/sets, NIP-49 key wrapping, NIP-32 labels, and the
NIP-78/nostr-double-ratchet DM wire as core constructs, and demotes the
prior Matrix-carried forms to OPTIONAL mirrors. The NIP-51/NIP-49/
NIP-32/NIP-78 adoption and the double-ratchet DM plus web-of-trust
patterns were informed by a survey of the iris-client Nostr
implementation.

### Added - NIP-51 as the core list carrier (§3.0, §8.5, §8.6)
- Mute lists (`kind:10000`) and the full NIP-51 "sets file" (sets
  `kind:30000`-`39092`, including kind-mute sets `kind:30007`) are now
  core-substrate constructs, publishable to and served by BOTH backends;
  a repo relay MUST accept them like any other replaceable/addressable
  event and MUST NOT special-case NIP-51 kinds.
- Private list items use the NIP-51 private-item mechanism: entries
  NIP-44-encrypted to self under the persona's current epoch key,
  re-encrypted on KERI epoch rotation.
- Community policy lists (blocklists / allowlists) ride the same carrier,
  adopted via `["a", ...]` / `["p", ..., "policy"]` tags on the
  `kind:34550` community definition.
- The pre-pivot Matrix carriers (`m.heterodyne.mutes.public.v1` and the
  config room `private_mutes` field) are demoted to OPTIONAL mirrors; the
  NIP-51 events are authoritative on divergence.

### Added - CORE direct messages over a Nostr double ratchet (§5.7)
- DMs are now a core mechanism: the nostr-double-ratchet wire
  (Signal-style Double Ratchet with NIP-44 v2 payloads) carried in Nostr
  events - `kind:30078` device invites, `kind:1059` invite responses,
  `kind:1060` outer messages signed by the sender's current ratchet key
  (rotated per DH ratchet step, so relays cannot link messages to a
  persona; same-epoch messages share a signer), wrapping unsigned
  `kind:14` inner rumors. It gives forward secrecy and post-compromise
  security (§9.5) with no Matrix dependency.
- Full five-message double-ratchet transcript vector (`dm/006`, two DH
  ratchet steps, pinned session-setup secrets plus a pinned ratchet-key
  injection seam) generated by driving the exact-pinned upstream wire
  library `nostr-double-ratchet@0.0.138` (irislib, MIT) under a
  deterministic RNG and clock; receive-side replay and skipped-key
  recovery are asserted in the generator test suite. This replaces the
  earlier "transcripts deferred until wire-spec extraction" hedge.
- Sessions are delegation-bound to the persona via `kind:31001` (§3.3.1);
  a client MUST verify the peer device chains to the peer's cold root
  before establishing a session.
- Transport rules: `kind:1060`/`kind:1059` are relay-carried only and
  MUST NOT be committed to a repo; there is no DM backfill (history lives
  only in the device's local store); NIP-17 gift-wrap remains the fallback
  for vanilla-Nostr recipients (no forward secrecy).
- The two-member Matrix `private_discussion` room is demoted to the
  OPTIONAL Matrix layer's additional DM surface, not the DM mechanism.

### Changed - Backups redesigned around a config repository and a keys repository (§3.8.6-§3.8.8, §9.6)
- Non-key state is backed up as encrypted blobs in a per-persona **config
  repository**: a Radicle private repo whose RID is unadvertised (MUST NOT
  appear in any published event or profile surface) and whose contents are
  Tier 3-encrypted under a dedicated config audience key.
- Key material lives in a strictly local **keys repository** (never
  seeded or published): the NIP-49-wrapped `nsec`, epoch/NID secrets,
  Tier 3 audience keys, the config-repo RID, and the followed-repositories
  list. It syncs between the user's own devices over exactly two paths -
  an encrypted §5.7 device-to-device DM or an offline backup restore.
- Adds a RECOMMENDED periodic removable-media (USB) backup covering every
  repo the user produces AND follows, config repositories, and the
  encrypted keys repository, with a client freshness indicator (e.g. a UI
  chip) for un-backed-up changes.

### Changed - Key-ID branch layout for encrypted-blob repos (§6.10.4)
- All encrypted blobs (Tier 3 content repos and config repositories) live
  on per-generation `enc/<key_id>` branches; the `defaultBranch` carries
  no ciphertext.
- The RECOMMENDED `key_id` is a domain-separated, truncated SHA-256 of the
  audience key (self-verifying by any key-holder); publishers MAY use an
  opaque random id, and verifiers MUST treat `key_id` as opaque.
- Audience-key rotation creates a fresh branch and force-deletes the
  retired one via updated signed refs (`rad/sigrefs`), so cooperating
  seeds converge to a ref tree without the old ciphertext. The trust
  boundary is honest: cooperative hygiene, not cryptographic erasure
  (hostile or offline seeds and prior relay copies may retain ciphertext).

### Changed - NIP-72 moderation de-Matrixed; approvals anchored by hosting (§8.1, §8.2, §8.2.1)
- The core moderator declaration is the NIP-72 `kind:34550` community
  definition (epoch-key-signed on both backends), carrying moderator
  npubs and an `["approvals_required", "N"]` extension tag.
- A counted `kind:4550` approval MUST carry an anchor that fixes the
  moderator set as-of the approval, chosen by hosting: a **repo anchor**
  (a commit reachable from the delegate-threshold canonical history;
  moderator set read from the newest `kind:34550` in the commit's ancestor
  history), an OPTIONAL **Matrix anchor** (`m.heterodyne.approval.v1`), or
  a **relay-only `created_at` fallback** flagged as reduced-assurance.

### Added - NIP-32 labels and web-of-trust filtering guidance (§8.9, §8.10)
- NIP-32 `kind:1985` labels are a RECOMMENDED graded, advisory moderation
  signal; they gate nothing and MUST NOT be treated as an editorial-gating
  mechanism.
- Non-normative client guidance for web-of-trust filtering: follow-distance
  trust radius, overmuted-ratio crowd-moderation from subscribable mutes,
  a cold-start graph snapshot, and DM-acceptance gating.

### Changed - Forward-secrecy posture stated per mechanism; honesty fixes (§9.5, §13.1.2, §13.3, §14.3)
- New per-mechanism forward-secrecy table: Tier 3 audience-key broadcast
  has **no** forward secrecy (a compromised audience key decrypts all past
  posts under its `key_id`; rotation limits future exposure only); CORE
  DMs have forward secrecy plus post-compromise security; the NIP-17
  fallback has none; Megolm/MLS applies only within the OPTIONAL Matrix
  layer. Clients MUST NOT let one mechanism's guarantee be inferred for
  another.
- §13.1.2 pseudonymity-not-deniability wording reconciled with the CORE DM
  and Tier 3 boundaries; §13.3 gains threat rows for DM conversation
  metadata at relays, stale-list rollback, and malicious allowed-seeder
  plaintext reads.
- §14.3 coverage map gains CORE categories `lists/`, `dm/`, and
  `config-backup/`; the Matrix-shaped `broadcast/` (with `bridge/` and
  `index/`) categories are marked OPTIONAL, outside the CORE Matrix-free
  baseline.

## [0.4.0] - 2026-07-01

Substrate pivot: the core moves from Matrix-as-transport to a **Radicle +
Nostr core substrate**, with Matrix demoted to an OPTIONAL layer. This is
a 0.x breaking change (semver 0.x rule, §12.1): v0.4.0 breaks v0.3.0.
Decisions recorded in ADR-026 through ADR-029.

### Changed - Radicle + Nostr core substrate (ADR-026)
- Nostr signed events remain the canonical content unit, now carried over
  **two co-equal MUST backends**: ordinary Nostr relays AND **repo relays**
  (NIP-01 websocket endpoints backed by a Radicle git repository). Radicle's
  Noise XK / TCP peer-to-peer replication lives entirely behind full nodes,
  never in front of a browser/mobile client.
- Three node roles defined (§10.1.1): **full node** (runs a Radicle node +
  NIP-01 repo-relay adapter; the only node type that holds content),
  **routing node** (edge-runtime, answers repo-location queries from
  `kind:31005`/`kind:31010` ads only, holds no content), **light node**
  (fetches directly from full-node repo relays or relays; verifies every
  event's Nostr signature locally).
- `kind:31005` identity pointer repurposed from npub→Matrix room to
  **npub → Radicle RID + optional full-node host hints** (§11.3).
- New `kind:31010` node/repo advertisement - an outer BIP-340 Nostr event
  (valid on the NIP-01 wire) carrying an inner Ed25519 NID possession proof
  (an Ed25519 signature by the NID over the advertisement payload, including
  the current canonical repo head), the RID, endpoints, and an expiry (§7.0).

### Changed - KERI to Radicle identity and organizations (ADR-027)
- The KEL stays the single authority for key lifecycle; the Radicle identity
  document's `delegates` set is a derived projection, and clients trust the
  KEL on any divergence (§3.9.10).
- `kind:31001` delegation extended to authorize an **Ed25519 Radicle NID**;
  NID binding is **bidirectional** (epoch-key Schnorr signature + NID Ed25519
  `nid_proof`), two keys per device (§3.3.1).
- Organizations are first-class personas whose repo delegates + threshold
  (with optional per-ref `crefs`) encode M-of-N governance; a plain user is
  the one-delegate case.
- Two parallel editorial-gating mechanisms (§8): the retained NIP-72
  `kind:4550` approval flow, and a native **Radicle editorial-gating mode**
  (§8.8) where a post is approved iff it is reachable from the
  **delegate-threshold-approved canonical feed branch** (the commit a
  threshold of delegates agree on); the finer per-ref `xyz.radicle.crefs`
  refinement is OPTIONAL and EXPERIMENTAL, pending Heartwood-release
  verification. A community MAY use either mechanism or both.

### Changed - three privacy tiers (ADR-028)
- Broadcast confidentiality recast as three repo-visibility tiers with honest
  trust boundaries (§5.2, §9.0): Tier 1 public repo; Tier 2 private repo
  ("unencrypted-but-not-discoverable" - plaintext on every allowed seeder);
  Tier 3 encrypted-blobs-in-repo (NIP-44 encrypt-before-commit, confidential
  against everyone including seeders).
- Private-tier honesty MUST: a client MUST warn that private-repo content is
  plaintext on every allowed seeder and MUST NOT call it "encrypted."
- New `kind:31011` per-recipient audience-key wrap distributes the Tier 3
  audience key over the repo/Nostr substrate, Matrix-free (§6.7.4).

### Changed - Matrix demoted to OPTIONAL; v0.4.0 (ADR-029)
- Matrix becomes a SHOULD-level layer for discussion groups, DMs, calls, and
  encrypted real-time rooms; no identity, publishing, discovery, or privacy
  requirement depends on it. A Matrix-free client is **fully conformant**
  (§14). Megolm/MLS scoped to the OPTIONAL Matrix layer (§9.2).
- Asynchronous public interaction uses the Nostr **outbox model**: replies /
  reactions are written into the author's own outbox and assembled
  scatter-gather (§6.5).
- Every v0.3.0 Matrix-mandatory MUST superseded per ADR-029's supersession
  table.

### Migration
- Existing v0.3.0 personas republish `kind:31005` in its RID-pointer form and
  stand up (or arrange reachability through) at least one durably-connected
  full node (§12.1).

## [0.3.0] — 2026-05-23

Structural revision of the room model and a full reconciliation of the
KERI/identity signing model. Builds on the tagged `v0.2.0`.

### Changed — room taxonomy (ADR-017)
- Replaced the six-kind, *verifiable-vs-deniable* taxonomy with four
  kinds on a **broadcast vs discussion × public vs private** axis:
  `public_broadcast`, `private_broadcast` (new), `public_discussion`,
  `private_discussion` (plus `identity_room` / `config_room`).
- `private_broadcast` posts are **room-key-wrapped** Nostr events
  (encrypt-once-for-the-room), retiring per-recipient NIP-59 gift-wrap
  for broadcast.
- Retired room-level **deniability** as an unsound claim: every in-room
  message is attributable to its author's npub via the §3.3 delegation.
  Bare messages carry no *transferable* proof but are not anonymous.
- Moderated NIP-72 communities fold into `public_discussion` +
  `m.heterodyne.moderators.v1`.
- Read-back compatibility: clients MAY accept retired kind names and
  SHOULD map them to the nearest current kind.

### Changed — KERI/identity reconciliation (ADR-018)
- Pinned one signing model: the persona's **npub is its KERI cold-root
  key**. Cold root signs only inception (`kind:31002`), `committed`
  rotation (`kind:31003`), and the `kind:31005` pointer; the **current
  epoch key** signs the root attestation (`kind:31000`), delegations
  (`kind:31001`), outbox, feed index (`kind:31007`), posts, and
  approvals (`kind:4550`).
- `kind:31000` and `kind:31001` now carry a `["cold_root", <npub>]`
  tag (wire-format addition).
- Delegation revocation: `m.heterodyne.delegation_revoked.v1` is
  authoritative; the Nostr `kind:5` deletion is a relay-side mirror.
- Identity discovery (§3.6) replays the KEL **before** verifying the
  root attestation and delegation.
- §4.5 verification rewritten: a signing key is accepted only when it
  was the KERI-authoritative epoch key at the event's `created_at`;
  all hashing is over `nip01_raw`; bare messages are attributed (at
  their Matrix position) and rendered, never hidden.
- Moderator approvals evaluated by cold-root identity and **Matrix
  state-at-event** via a new `m.heterodyne.approval.v1` anchor.
- Removed the retired Matrix MSK co-signature from KERI ceremonies.

### Fixed
- Canonical persona address is the npub, not the identity-room ID.
- Repointed stale `§3.5.1` revocation references to §3.5.3 / §3.9.7.

## [0.2.0] — prior

Nostr-native feed index (`kind:31007`), KERI commitment for root
inception/rotation, ATProto attached outbox, strict clock-skew and
`nip01_raw` canonicalization hardening. See `docs/adr/` (ADRs 001–016)
for the decisions that shaped it.

[0.4.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.4.0
[0.3.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.3.0
[0.2.0]: https://github.com/Epiphytic/Heterodyne/releases/tag/v0.2.0
