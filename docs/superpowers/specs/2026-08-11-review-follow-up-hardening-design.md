# Review follow-up hardening design

Date: 2026-08-11

Status: Approved design; implementation pending

## Purpose

This change resolves the verified remainder of the protocol review following
the Marmot and one-time-invitation work. It closes small registry and wire
ambiguities immediately, narrows incomplete conformance claims, and specifies
the security behavior that was previously left implicit for Tier 3 device
delivery, persona-profile projection, key rotation, node-advertisement time,
and late retired-key content.

The protocol is pre-1.0. Existing 0.5.0 identifiers and vectors may be
corrected in place where necessary, but the completed patch must leave the
specification family and its normative artifacts self-contained and
canonical.

## Review disposition

### Accepted findings

The following findings require specification work:

- the generic repo-relay server/storage contract is incomplete and must not be
  presented as a claimable conformance surface;
- Tier 3 audience-key wraps currently target a persona identity key rather
  than online, individually revocable device recipients;
- canonical Heterodyne profile metadata, vanilla `kind:0` projection, NIP-05,
  publisher rotation, addressable-event migration, and author-set discovery
  need one coherent rule;
- the Marmot dependency needs locally preserved normative bytes and an
  independently verifiable SHA-256 manifest;
- `kind:31010` needs a maximum lifetime and verifier clock discipline;
- late content signed by a routinely retired epoch key needs an honest
  provisional state when pre-rotation existence cannot be established;
- the claim schemas' registry revision 2 pin needs an explicit immutable
  profile-allocation interpretation distinct from the release-wide registry
  revision 6 pin;
- upstream Nostr kinds `1059` and `22242` are used by the live specification
  but absent from the current kind catalog; and
- Nostr wire key encodings in `kind:31011` and `kind:31012` are described with
  the ambiguous term `npub` rather than the required lowercase hexadecimal
  representation.

### Rejected or already-covered findings

- The live family and release manifests pin registry revision 6, not revision
  5.
- Upstream Nostr `kind:13` remains allocated in the current registry.
- Current NIP-44 v2 does not have a 65,535-byte plaintext ceiling. Its extended
  length form supports larger plaintext; a 500-entry page is therefore not
  invalid solely because of the alleged ceiling. This review patch does not
  change the existing Heterodyne page limit.
- Compromise-declared retired-key backdating is already rejected through
  `compromise_since` and KEL replay. This change addresses the distinct case of
  routine retirement followed by late discovery.
- Cold-root loss and compromise intentionally have different outcomes. This
  design clarifies that boundary rather than adding another root authority.

## Design

### 1. Tier 3 recipients are active delegated devices

Tier 3 audience membership is persona-level by default. For each member
persona, the producer resolves its accepted KEL and current device delegation
state and emits one `kind:31011` audience-key wrap for every active delegated
human-device secp256k1 publishing key. An audience policy may narrow delivery
to an explicit subset of those active devices. It may never expand delivery
to an inactive, revoked, unverified, or non-device key.

The existing device secp256k1 publishing key is also the device's NIP-44
recipient key. The device retains that private key, so authenticated light
clients can decrypt directly. The cold-root key and persona epoch key must
never appear as audience-key recipients.

The dual publishing/decryption use is one compromise domain and must be named
in Core, Comms, and the threat model. Device revocation or removal from a
persona's effective audience-device set triggers the existing full audience
generation rotation: new audience key, new `key_id`, new roster, wraps only to
the remaining effective devices, and updated encrypted indexes and
descriptors. Adding an active device follows ordinary member addition and
does not rotate existing content by default.

`kind:31011` and `kind:31012` wire fields use exact 32-byte x-only Nostr public
keys encoded as 64 lowercase hexadecimal characters. `npub` is reserved for
the NIP-19 bech32 presentation encoding and never occurs in a NIP-01 `pubkey`,
`p` tag, or address coordinate.

Normative vectors must cover all-active-device delivery, selected-device
narrowing, light-device decryption, cold-root rejection, epoch-key rejection,
revoked-device rejection, and removal-driven generation rotation.

### 2. Repo-relay conformance is narrowed

Core 0.5.0 defines only `core.repo-relay-client.v1`: a client reads and writes
ordinary NIP-01 events through a websocket endpoint without speaking Git or
Radicle. Core must not make normative server/storage promises about a generic
repo relay and must not expose a generic server/storage feature or claim.

The incomplete discussion of a reserved ref namespace, generic append-log
layout, filter-to-Git mapping, retention, garbage collection, and quota is
removed from the live conformance surface. The specification states that no
generic repo-relay server/storage profile exists in this release and that an
implementation must not claim one.

The separately specified Radicle-backed Marmot relay remains the only
claimable relay server/storage profile. Its exact-byte event storage, `h`
routing, per-author/relay branches, repository rotation, retention, and
multi-interface behavior remain unchanged. A future generic storage profile
requires its own ADR, complete namespace and query mapping, authenticated
admission, finite quotas, retention, garbage collection, and conformance
vectors.

### 3. Canonical persona profile and vanilla projection

The canonical Heterodyne persona profile is a versioned record in the
persona's public Radicle profile repository. It is selected through the
repository's existing canonical-main and threshold rules and is bound to the
cold-root persona. The record owns the stable Heterodyne metadata fields and
the current vanilla projection coordinate.

Exactly one active KEL delegation is designated as the persona's
`profile-publisher` role. The delegated secp256k1 key publishes a vanilla,
unstamped Nostr `kind:0` mirror for ordinary Nostr clients. The delegation and
repository profile record bind the publisher key to the cold-root persona;
the mirror itself remains ordinary Nostr and does not become cold-root
authority.

NIP-05 is optional. If present, it belongs to and must validate for the
current vanilla publisher key. It is a discoverability/display identifier and
never overrides the cold-root persona, accepted KEL, delegation, or canonical
repository profile. The cold root does not sign routine `kind:0` updates.

Competing `kind:0` events from non-designated devices are ordinary Nostr data
and not Heterodyne profile projections. A newly designated publisher creates a
new mirror after its delegation and canonical profile update are accepted.

### 4. Publisher rotation and addressable-event migration

Vanilla relays retain normal NIP-01 semantics. Heterodyne does not redefine an
`authors` query so that multiple publisher keys become one relay author, and
does not treat `(old_pubkey, kind, d)` and `(new_pubkey, kind, d)` as one Nostr
address.

When a delegated publisher rotates, each still-live addressable semantic
object is republished under the successor key. The canonical Heterodyne
repository or feed index atomically changes its live coordinate to
`(successor_pubkey, kind, d)`. The former coordinate remains historical. A
NIP-09 deletion request may be sent as advisory cleanup but is not migration
authority and does not prove erasure.

Discovery derives a finite historical-and-current publisher-key set from the
accepted KEL and validated delegation history and issues ordinary exact-hex
NIP-01 author queries for those keys. Results are verified in their signing
key's authority window. Only the repo-confirmed canonical Heterodyne index
selects the live address; relay arrival order, maximum `created_at`, and an
aware relay's expanded author query cannot substitute for that selection.

Vectors must cover designated-profile selection, invalid NIP-05 override,
successor republication, old-coordinate history, exact author-set discovery,
and failure to treat relay-only replacement as canonical migration.

### 5. Retired-key late discovery

KEL authority windows continue to validate that an event's claimed
`created_at` falls within the signing epoch. That test alone cannot prove the
event existed before a routine rotation if the retired secret was later
compromised and used to backdate an event.

For an event signed by a routinely superseded epoch or delegated publisher key
and first observed after its retirement:

- it is repo-confirmed pre-retirement content only when the introducing commit
  is an ancestor of a trusted repository checkpoint bound into, or accepted
  before, the retiring rotation;
- a trusted local receipt or checkpoint recorded before retirement may also
  prove prior observation for the local verifier; and
- otherwise a valid relay-only event remains visible only as
  `provisional-retired-key`, even when its signature and claimed timestamp are
  valid.

Relay timestamps, relay presence at the time of a later query, and the event's
own `created_at` are not proof of pre-retirement existence. The provisional
state cannot authorize, replace canonical profile state, migrate an address,
or become a canonical feed entry without an accepted anchor.

Compromise-declaring rotations retain the stronger existing
`compromise_since` rejection rule. The new provisional state must not loosen
that rule.

### 6. Node-advertisement time contract

A `kind:31010` node advertisement is valid only when:

- its `created_at` is within plus or minus 300 seconds of the verifier's clock
  when first accepted;
- `expiry` is a canonical decimal Unix timestamp strictly greater than
  `created_at`;
- `expiry - created_at` is at most 86,400 seconds; and
- the verifier clock is strictly before `expiry`.

The producer must refresh a continuing advertisement before 43,200 seconds
have elapsed from `created_at`. Refresh failure is an availability problem;
clients discard the old advertisement at expiry and do not extend it locally.
Verifier clocks must be synchronized to a secure platform time source where
available. A client detecting more than 300 seconds of known clock
uncertainty must fail closed for fresh advertisement acceptance and report a
clock error rather than silently expanding the window.

Vectors must cover maximum valid lifetime, excessive lifetime, future and
past clock skew, `expiry <= created_at`, refresh timing, expiry, and uncertain
clock failure.

### 7. Cold-root loss and compromise boundary

Cold-root loss is recoverable only from redundant encrypted backups that are
decryptable under an already authorized recovery path. Implementations should
recommend multiple independently stored encrypted copies using platform secure
storage, hardware or removable storage where available, and the portable
backup format. A backup does not itself grant a new device public authority;
the normal restore and activation checks still apply.

An already configured positive witness threshold and `strategy:none` may
preserve epoch continuity without using the cold root, but it does not recover
or replace the cold-root secret and cannot authorize an operation reserved to
the cold root.

Suspected cold-root compromise is terminal for the persona identity. When a
trustworthy controller remains, it should publish the existing migration
breadcrumbs and move users to a new cold-root persona. The protocol must not
describe same-persona cold-root reset, secret reconstruction by new social
trustees, or witness substitution as recovery from compromise.

### 8. Marmot normative archive

Heterodyne preserves the exact adopted Marmot specification bytes from
upstream commit
`4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`, whose tree is
`10d941f358de5d9fe4ee1db75581f3e5363f5e92`.

The archive contains this closed set:

- the upstream MIT `LICENSE` and root `README.md`;
- top-level `layout.md` and `principles.md`; and
- every Markdown file beneath `foundation/`, `protocol-core/`,
  `app-components/`, `transports/`, and `features/` whose first status field is
  exactly `Status: adopted.`, including the adopted section README files.

The archive excludes `AGENTS.md`, `CLAUDE.md`, `implementation-model.md`,
`mip-coverage.md`, and every surface document marked experimental, deprecated,
superseded, or branch draft, as well as MIP material, implementation source,
build artifacts, and other explicitly non-normative or historical content.

A closed manifest records the upstream repository URL, commit ID, tree ID,
verified upstream commit-signature result, each relative path, byte length,
Git blob ID, and SHA-256 digest. It also records a deterministic aggregate
SHA-256 over the ordered file records. A verifier must use the local archived
bytes and manifest for Heterodyne conformance; the GitHub URL is provenance
and a convenience, not a runtime or validation dependency.

Updating Marmot requires a newly reviewed archive and digest, corresponding
specification changes, registry/release updates where applicable, and new or
changed Heterodyne vectors for every affected integration rule. Upstream code
is never made normative by this archive.

### 9. Registry and claim revision corrections

The current kind catalog adds upstream-owned, unstamped entries for Nostr
`kind:1059` (NIP-59 Gift Wrap) and `kind:22242` (NIP-42 Client
Authentication). Existing upstream `kind:13` remains unchanged. Historical
registry snapshots are immutable; the correction is allocated in the next
registry revision and all active release manifests and vectors are repinned to
that revision and digest.

Claim and claim-revocation schema member `registry_revision: 2` is retained.
The specification must name it `profile_registry_revision`: the immutable
registry entry-set revision at which the v1 claim wire profile, discriminators,
and reason-code vocabulary were allocated. It is signed semantic content and
does not float when unrelated registry entries are added.

The family release manifest and conformance envelope independently pin the
current complete registry revision and digest. A verifier therefore checks
both: the artifact's fixed profile revision 2 and the implementation/release's
current registry revision. The schema property name remains
`registry_revision` for the v1 wire format; changing that member requires a new
claim profile version.

Vectors and documentation must distinguish these two meanings and reject an
artifact that substitutes the current family revision for the fixed v1
profile revision.

## Normative artifacts and testing

The implementation patch includes one new proposed ADR. After acceptance it
is archived in the same patch; only the specification and normative artifacts
remain implementation authority.

The patch updates, as applicable:

- Core, Comms, Social, glossary, architecture, and threat model;
- kind, feature, reason-code, and invariant registries plus immutable history;
- release manifests and registry digests;
- Tier 3, profile, rotation, node-advertisement, claims, and registry
  schemas or evaluators;
- deterministic generators and all affected normative vectors; and
- the local Marmot normative archive and closed digest manifest.

The generator must verify the Marmot archive manifest byte-for-byte and reject
missing, extra, changed, or path-traversing entries. Documentation lint must
reject a claimable generic repo-relay server/storage feature, ambiguous `npub`
wire descriptions, a live NIP-59/NIP-42 use without catalog allocation, and a
claim-revision explanation that conflates the artifact profile revision with
the release registry revision.

Completion requires both family checks, all vector checks, archive-manifest
verification, and `git diff --check` to pass. Conformance vectors are changed
because this design intentionally changes wire-level and validation behavior.

## Non-goals

This change does not:

- define generic repo-relay server/storage conformance;
- introduce a distinct Tier 3 encryption key or distribute any cold-root or
  epoch private key;
- redefine vanilla Nostr relay `authors` semantics;
- make NIP-05 identity authority;
- provide in-place cold-root compromise recovery;
- archive or prescribe a Marmot implementation; or
- impose the obsolete 65,535-byte NIP-44 plaintext limit.
