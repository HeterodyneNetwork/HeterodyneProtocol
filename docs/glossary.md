# Heterodyne glossary

This file is a **non-normative index**. It helps readers find terminology; it
does not define conformance.

Shared normative terminology lives in
[Heterodyne Core](spec/heterodyne-core.md), especially `core-terminology`, and
document-local terms are assigned to their owners:

- [Heterodyne Core](spec/heterodyne-core.md)
- [Heterodyne Comms](spec/heterodyne-comms.md)
- [Heterodyne Control](spec/heterodyne-control.md)
- [Heterodyne Social](spec/heterodyne-social.md)

The owning version-qualified family document controls any conflict with this
index. Historical terminology is preserved in the
[0.4.0 archive](spec/archive/heterodyne-0.4.0.md).

## Family and conformance

**Core.** The foundation document for persona identity, KEL
verification, canonical signed bytes, Radicle delegation and storage substrate,
registry, versioning, and base conformance. Every Heterodyne
implementation claims Core.

**Comms.** The document for Nostr-native application envelopes, repository
privacy tiers, publishing and retrieval, canonical feeds, direct messages,
credential-plane sync, and encrypted subprotocol carriers.

**Control.** A Comms profile for own-device enrollment, grants, RPC, audit, and
agentic sessions. Control 0.5.0 is incomplete and cannot be claimed.

**Social.** The document for following, interactions, moderation, lists,
social discovery, presentation, ATProto attachment, and optional Matrix.

**Qualified version.** A document ID plus semver, such as `core/0.5.0`. The
whole string is not itself semver. Each family document versions independently.

**Registry revision.** A monotonic snapshot of kind allocations, profile
discriminators, reason codes, and security-invariant IDs. It is pinned by
releases, capabilities, reports, and vectors.

**Conformance class.** One of Core, Core+Comms (a Heterodyne persona), Control
profile, Social, or Social+Matrix. Claims also name required features.

**Strict profile.** An additive, stable conformance profile with exact
invariant membership and prerequisite profiles. Unknown profile IDs confer no
capability. The current IDs are `heterodyne-core-strict-v1`,
`heterodyne-comms-strict-v1`, `heterodyne-control-strict-v1`,
`heterodyne-social-strict-v1`, and
`heterodyne-social-matrix-strict-v1`; the Control ID is reserved-inactive.

## Core terms

**Persona.** One canonical cold-root npub, accepted KEL, canonical Radicle RID,
and delegation set. See Core `core-terminology`.

**Cold root.** The normally offline secp256k1/BIP-340 key whose public key is
the persona npub and which performs rare identity ceremonies.

**Epoch key.** The rotating BIP-340 key authorized by the accepted KEL for
routine attestations during its authority window.

**KEL.** The accepted key-event log of Core inception and rotation events.

**npub / nsec.** Bech32 renderings of a Nostr public/secret key. The persona's
cold-root public key is its canonical npub; the nsec is sensitive local
material.

**NID.** A Radicle Ed25519 node identity encoded as `did:key`. An NID signs
Radicle refs and collaborative objects; it does not replace Nostr authorship.

**RID.** A Radicle repository identifier encoded as `rad:z...`.

**Identity document.** The `xyz.radicle.id` collaborative object containing
delegates, threshold, payload, and visibility.

**Root attestation.** A short-lived Core proof binding current epoch authority,
persona, and repository context for bootstrap consumers.

**Identity pointer.** Core `kind:31005`, the authoritative signed npub-to-RID
binding with optional host hints.

**Node advertisement.** Core `kind:31010`, signed evidence that a node serves a
RID at specified endpoints. It is a locator hint rather than authority.

**Delegate.** A KEL-authorized NID empowered in the Radicle identity document.
A private-repository allow-list member is not necessarily a delegate.

**Threshold authority.** The M-of-N Radicle delegate rule for canonical data
refs. Identity-document revisions use a distinct delegate-majority mechanism.

**Canonical reference.** A ref accepted under `defaultBranch` threshold or an
optional `xyz.radicle.crefs` rule. Canonical-ref acceptance does not replace
Nostr signature verification.

**COB.** A Radicle Collaborative Object stored under a typed, signed operation
history. Heterodyne may use reverse-DNS custom types.

**Full node.** A Radicle node plus NIP-01 repo-relay adapter. It stores and
replicates repositories.

**Routing node.** A content-free service that derives serving-node answers
from verified advertisements. Its answers are hints.

**Light node.** A client that fetches from full-node or ordinary relay
interfaces and verifies signed objects locally.

**Repo relay.** A NIP-01 websocket endpoint whose durable store is a Radicle
repository.

**Seeding.** A full node's explicit choice to replicate and serve a repository.
Multiple seeders improve availability but do not change content authority.

**Re-anchor.** A cold-root-authorized move to a fresh RID after compromise or
unrecoverable repository governance failure.

**Heterodyne-aware relay.** An optional NIP-01 superset that advertises useful
KEL-aware features. Base Core conformance never depends on one.

**Protected repository.** Core's generic authenticated-encryption container
whose concrete encryption profile is supplied by the owning document.

**Keys repository.** A local-only protected store for persona and device key
material, config-repository location, and Core metadata. It is never seeded or
advertised.

**Wrapping secret.** A user-controlled input to the keys-repository protection
profile, including NIP-49 wrapping where applicable.

**Materialized KEL.** Core's dual-ref git projection of accepted KEL log and
state, designed so readers can prove both tips represent one accepted head.

**Recovery peer / declared witness.** Social-neutral Core roles that can cache
or attest identity material. Social may bind them to relationships but cannot
replace KEL authority.

## Comms terms

**Canonical Comms envelope.** A signed Nostr event whose exact serialization,
owner stamp, KEL binding, and destination rules pass Core and Comms checks.

**Tier 1.** Public-repository plaintext. Confidential against no one.

**Tier 2.** A private Radicle repository that is unfetchable by non-members but
stores plaintext on every allowed seeder. It must not be called encrypted.

**Tier 3.** Content encrypted under an audience key before any repository,
seed, full node, or relay receives it.

**Audience key.** A symmetric key used once per Tier 3 content generation and
distributed through per-recipient wraps.

**Key-ID branch.** An `enc/<key_id>` branch for one encrypted generation.
Deleting a retired branch is cooperative scrubbing, not cryptographic erasure.

**Config repository.** A private, unadvertised repository for encrypted
non-key state. Comms owns its encryption profile; payload ownership remains
with Core, Comms, or Social.

**Feed index.** The Comms-owned `kind:31007` canonical ordering for one generic
outbox. Social may opt into a registered presentation profile.

**Outbox.** A persona-owned publication location. Authors write their own
outboxes; readers assemble cross-persona interactions by scatter-gather.

**Public outbox.** Publicly advertised Comms feeds and endpoints for a persona.

**Retrieval hint.** A relay, archive, or repository location carried in an
index entry. It is transport metadata and does not replace event verification.

**Archive endpoint.** An optional HTTPS retrieval target for signed content.
It is a convenience carrier, never canonical authority.

**Scoped outbox.** An audience-specific descriptor that locates restricted
Comms feed material without publishing a global audience map.

**Double-ratchet session.** A Comms direct-message session with forward secrecy
and post-compromise security, subject to message-key deletion. Outer events are
relay-only and have no backfill.

**Acceptance hook.** Comms' post-authentication policy boundary with
`accept`, `hold-as-message-request`, and `reject` outcomes. Higher policy can
tighten, never bypass, cryptographic checks.

**Credential plane.** Explicitly authorized key/recovery-state transfer
between durable NID-bearing devices. It is distinct from Control.

**Subprotocol negotiation.** The mutual Comms exchange that selects a protocol
ID, version, and required features before an encrypted generic payload is
interpreted.

## Control terms

**Session device.** A confined, NID-less Control principal. It is not a
credential-plane device and never receives persona, NID, audience,
repository-decryption, or ratchet secrets.

**Control audit record.** Encrypted local evidence binding a request and result
to the negotiated Control and Comms versions, peer, session, grant decision,
and side effects. Its protection has no Social dependency.

**Control profile gate.** The accepted-ADR, integrated-schema, and minimum
vector conditions that must be satisfied before Control conformance becomes
claimable.

## Social terms

**Following.** Social's signed relationship and local-policy semantics. It is
not part of Core identity discovery.

**Distribution list / friend circle.** Social UX for an audience category.
Its concrete confidentiality is still the chosen Comms tier or Matrix room.

**Reply inbox.** A Social destination where another persona may deliver a
reply reference without write access to the original author's repository.

**Approval anchor.** Evidence fixing the moderator declaration and authority
state used to count a NIP-72 approval: a repository anchor, optional Matrix
anchor, or reduced-assurance relay time fallback.

**Approval.** A NIP-72 `kind:4550` event by an authorized moderator, counted
only after signature, authority-at-anchor, indexing, and deletion checks.

**Moderator declaration.** The authoritative Social `kind:34550` statement of
moderator npubs and approval threshold.

**Moderator.** A persona authorized by the declaration in force at an
approval's anchor.

**Radicle editorial gate.** Social's alternative moderation mode in which
approval follows reachability from delegate-threshold canonical history.

**Advisory label.** A NIP-32 label used for local ranking or filtering. It is
not identity or editorial authority.

**Mute list.** A Social-profiled NIP-51 `kind:10000` list. Public and private
items retain NIP-51 semantics; the private form does not imply Tier 2.

**Sets file.** Social's collection of NIP-51 addressable set events used for
curation and policy.

**Policy persona.** A persona whose signed lists are adopted as community or
reader policy. Adoption remains local Social policy.

**Social mute profile.** The registered stamping profile on NIP-51
`kind:10000`. A plain upstream NIP-51 event remains unstamped.

**Organization feed profile.** Social's registered `kind:31007` presentation
profile. Comms retains the base feed schema and org-content authorization.

**Social recovery binding.** Advisory mapping from Core recovery roles to
followers, mutual follows, friends, or Matrix caches. It cannot mint identity
authority.

**Social vouch.** Social `kind:31008`, an advisory attestation about recovery
identity material. It is not a declared KERI witness receipt.

**Attached ATProto outbox.** An optional public Social mirror bound to a
persona. It is downstream of the npub/KEL and never authoritative over them.

**ATProto link / PDS.** A double-sided binding between a persona and a DID plus
the Personal Data Server hosting the attached records. DID resolution and PDS
content remain downstream of Core identity.

**MXID.** A Matrix user ID used only by the optional Social Matrix feature.

**MXID delegation.** Social's optional Matrix binding, requiring both an
epoch-key proof and successful authorized Matrix self-publication.

**Identity room.** An optional Matrix coordination/cache room for a persona.
It is disposable and never authoritative over the npub/KEL.

**Config room.** An optional encrypted Matrix mirror of Social configuration.
The owning repository profile wins on divergence.

**Mirror group.** A set of optional Matrix rooms coordinated for redundancy
and promotion. Mirroring never changes persona authority.

**`matrix:` URI.** The canonical Matrix reference syntax used by Social when a
Matrix location must be named independently of a homeserver URL.

**Bare Matrix message.** An attributable Matrix event without a transferable
Nostr signature attachment. A strict Social+Matrix client does not hide it
solely because it is bare.

**Wrapped Matrix event.** A Matrix carrier containing an exact signed Nostr
event plus `nip01_raw`, allowing transferable verification.

**Wrap mode.** The Social choice between a wrapped transferable proof and a
bare Matrix message with attribution-only semantics.

**Social+Matrix.** The conformance class that adds the complete optional Matrix
feature to a Social claim, including MXID delegation, encrypted private
content/state, downgrade handling, and client-side bridging.
