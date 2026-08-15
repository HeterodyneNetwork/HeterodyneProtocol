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
index.

## Family and conformance

**Core.** The foundation document for persona identity, KEL
verification, canonical signed bytes, Radicle delegation and storage substrate,
registry, versioning, and base conformance. Every Heterodyne
implementation claims Core.

**Comms.** The document for Nostr-native application envelopes, repository
privacy tiers, publishing and retrieval, Marmot conversations and media,
Radicle-backed group storage, credential-plane sync, and encrypted
subprotocol carriers.

**Control.** A Comms profile for own-device enrollment, grants, RPC, audit, and
agentic sessions. Baseline Control 0.5.0 is claimable; recovery features are
separately advertised and optional.

**Social.** The document for public following, interactions, moderation,
lists, social discovery, presentation, durable assets, and ATProto attachment.

**Family version.** `heterodyne/` plus semver, such as `heterodyne/0.5.0`. The
whole string is not itself semver. All five documents carry this one version.

**Registry revision.** A monotonic counter over the kind, profile,
reason-code, security-invariant, feature, and object allocations. It advances
independently of the family version and is pinned in exactly one place,
`docs/spec/registry/manifest.json`.

**Profile registry revision.** A fixed allocation snapshot embedded in a
versioned wire profile. In v1 claims the JSON member remains named
`registry_revision` and is exactly `2`; it does not float with the family
release registry revision.

**Feature catalog.** The registry-owned allocation of globally unique dotted
and versioned feature IDs, their document owners, first versions, status,
specification anchors, and acyclic prerequisites.

**Conformance class.** One of Core, Core+Comms (a Heterodyne persona), Control
profile, or Social. Claims also name required features.

**Strict profile.** An additive, stable conformance profile with exact
invariant membership and prerequisite profiles. Unknown profile IDs confer no
capability. The current IDs are `heterodyne-core-strict-v1`,
`heterodyne-comms-strict-v1`, `heterodyne-comms-strict-v2`,
`heterodyne-control-strict-v1`, `heterodyne-social-strict-v1`, and
`heterodyne-social-strict-v2`.

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

**Canonical persona profile.** The versioned record selected from a persona's
public Radicle profile repository. A single active delegated
`profile-publisher` key mirrors it as ordinary Nostr `kind:0`; relay mirrors
and optional NIP-05 never override the repository record.

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
replicates repositories, provides a persistent v3 onion service, and uses Tor
for backend egress by default.

**Routing node.** A content-free service that derives serving-node answers
from verified advertisements. Its answers are hints.

**Public reader.** A non-authenticated light-client role that resolves and
renders verified Tier 1 only. A browser reader may operate without Tor only in
explicit reduced-assurance mode.

**Universal public launcher.** A static browser-client URL whose persona,
event, address, and bounded relay hints appear only in the fragment. The web
origin receives no target path; the downloaded client validates and resolves
the target locally.

**Authenticated light client.** A light-client role authenticated to a full
node for granted non-public capabilities. It still verifies received signed
objects locally.

**Light node.** A public-reader or authenticated-light client that fetches
from full-node or ordinary relay interfaces and verifies signed objects
locally. Outbound Tor is recommended; strict light profiles require it.

**Outbound-only Tor client.** A Tor implementation that initiates circuits but
does not accept inbound service traffic. Suitable non-browser WASM clients
should embed one; a browser tab must instead use reachable clearnet relays or
an authenticated shared relay.

**Authenticated shared relay.** A provider-independent websocket or WebRTC
service that authenticates a light client and relays its traffic to a full
node's onion service. It is a carrier, not authority, and browser use is
reduced assurance.

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

**Atomic key claim.** A complete `kind:31013` signed assertion containing one
namespace, name, and atomic JSON value about one typed key. Releasing one claim
does not disclose or imply another.

**Claim state.** One of `invalid`, `untrusted`, `provisional`, `active`,
`expired`, `revoked`, or `conflicted`. Only `active` can authorize.

**Private claim ledger.** A persona's encrypted multi-writer Radicle
repository. Canonical `main` is authoritative for persona-issued device
claims, reductions, consent, issuance mappings, reader state, and separately
wrapped issuer-key distribution.

**Claim-ledger reader.** A durable NID with an active
`claim-ledger-reader` authorization. NID-less session devices can receive
filtered decisions but not repository access or ledger audience keys.

**OIDC issuer.** The persona's one exact HTTPS issuer at
`https://<host>/oidc/<cold-root-npub>`. Its JWTs are interoperable projections
of active claim state, not canonical Heterodyne authorization.

**Issuer continuity tree.** Public OIDC metadata, JWKS, manifest, and signed
status artifacts committed under `.well-known/<cold-root-npub>/` on canonical
public `main`. It contains no private claims, consent, issuance mappings,
membership, audience keys, or signing secrets.

**Token issuer.** A synchronized node with active `oidc-token-issuer`
authority and a separately wrapped signing key. Ordinary ledger-reader status
does not grant mint authority.

**Agent role.** A stable `agent:<role-id>` Core/Comms delegation whose
dedicated publishing private key stays on the full node. One node usually has
one generic role; separately governed automation may use additional roles.

**Workload token.** A temporary, sender-constrained OIDC access token for an AI
or programmatic principal. Its role, audience, scope, resource, kind, size,
rate, burst, and time bounds are intersected with current private-ledger
authority before every side effect.

**Agent attribution.** The canonical NIP-32 namespace/label and
`heterodyne_agent` identity block added by the full node to every
agent-authored application event. Human review does not turn automated
authorship into human authorship.

**Intent-level publication.** The only automated publishing interface. The
caller supplies content intent and authorization proof but no private key,
signature, authoritative pubkey, human profile, or attribution override.

**Status List Token.** The separate signed draft-21 JWT referenced by a
projected token. A fresh `VALID` bit is necessary but never overrides another
token validation failure.

## Control terms

**Private Control principal.** A confined, NID-less `human-light` or
`automated` Marmot account authorized only through private Control
entitlement. It is not a Core/KERI device and never receives persona, NID,
repository-decryption, MLS-leaf, or agent-role secrets.

**One-time invite.** A purpose-bound, signed fragment envelope for `dm`,
`control-enrollment`, or `device-enrollment`. Its origin is not authority; the
first valid authenticated responder reserves it before group establishment
spends it.

**Enrollment-only group.** A pairwise Marmot Control group with no durable
application authority. It permits only initialization and enrollment methods,
is resource-bounded, and expires after at most 30 minutes.

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
Its concrete confidentiality is still the chosen Comms tier or Marmot group.

**Reply inbox.** A public Social destination or Comms persona-repository inbox
where another persona may deliver a reply or first-contact bundle without
write access to the original author's canonical branch.

**Approval anchor.** Evidence fixing the moderator declaration and authority
state used to count a NIP-72 approval: a repository anchor or a
reduced-assurance relay time fallback.

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

**Agent-policy receipt.** A signed public NIP-32 record describing an
attribution or publication-path violation by one agent device key. It informs
but does not mute by itself and exposes no workload token or protected audit
material.

**Agent-policy list.** A signed NIP-51 list binding device-key mutes to verified
agent-policy receipts. It affects only clients explicitly subscribed to that
policy persona and only after current canonical repository history verifies.

**Agent-role remediation.** Replacement of the offending device-publishing key
at the same stable agent role address. It does not rotate the persona epoch key
or mute other persona, device, NID, or agent-role keys.

**Social mute profile.** The registered stamping profile on NIP-51
`kind:10000`. A plain upstream NIP-51 event remains unstamped.

**Organization feed profile.** Social's registered `kind:31007` presentation
profile. Comms retains the base feed schema and org-content authorization.

**Social recovery binding.** Advisory mapping from Core recovery roles to
followers, mutual follows, friends, or repository and relay caches. It cannot
mint identity authority.

**Social vouch.** Social `kind:31008`, an advisory attestation about recovery
identity material. It is not a declared KERI witness receipt.

**Attached ATProto outbox.** An optional public Social mirror bound to a
persona. It is downstream of the npub/KEL and never authoritative over them.

**ATProto link / PDS.** A double-sided binding between a persona and a DID plus
the Personal Data Server hosting the attached records. DID resolution and PDS
content remain downstream of Core identity.

## Marmot and Radicle conversation terms

**Marmot account.** A stable Nostr account used by Marmot credentials and
attributed to a Heterodyne persona role through KERI evidence.

**Direct-member client.** A client that owns an independent MLS leaf and
participates directly after group admission.

**Node-mediated client.** A client that invokes grant-filtered conversation
operations on a designated full or recovery node and receives no group secret.

**Standard-compatible group.** A group that uses ordinary Marmot Nostr
transport and may additionally use Heterodyne Radicle-backed storage without
changing event bytes.

**Heterodyne-private group.** A non-discoverable group whose private Radicle
repositories provide the required discovery and admission path. Its Marmot
cryptography and event formats remain standard.

**Static group directory.** The stable repository containing group identity,
policy, sealed invites, hosts, retention, and signed routing bindings.

**Routing generation.** The one-to-one binding among one Marmot `h` value, one
event-repository RID, and its verified genesis manifest.

**Event repository.** A logically append-only repository whose contents are
the deduplicated union of objects reachable from authorized per-writer and
integrated-relay refs.

**Radicle-backed Marmot relay.** An optional standard NIP-01 and media
interface that maps `h` to an event repository and serves exact stored event
and ciphertext bytes.

**Persona repository inbox.** A contributor-ref delivery binding for an
atomic Marmot Welcome and first-event bundle. Sender refs are quarantined and
never merged into the persona's canonical profile branch.
