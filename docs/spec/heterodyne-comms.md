# Heterodyne Comms Protocol Specification

Document ID: `comms`

Comms is a section of the Heterodyne specification and is governed by
[`heterodyne:0.5.0#core-document-conventions`](heterodyne-core.md#core-document-conventions), which fixes the family version,
the registry pin, release status, BCP 14 usage, and the anchor and reference
forms.

<a id="comms-scope"></a>
## 1. Scope

Comms defines secure persona speech over the Core substrate: a Nostr-native
event envelope, public/private/encrypted repository tiers, publishing and
fan-out, standard NIP-65 outbox retrieval, Marmot conversations and media,
Radicle-backed group storage and relays, Marmot-carried Control integration,
credential-plane synchronization, private Control authorization state, and a
receive-only public-reader profile with a provider-independent fragment
launcher.

Comms does not define following as a social relationship, public feed
presentation, moderation, personal lists, community policy, social-graph
discovery, or command semantics. Application documents may select payloads
and tighten acceptance, but cannot weaken this document's cryptographic
checks.

An implementation claiming Core+Comms is a **Heterodyne persona**. A client
that offers Heterodyne private conversation MUST implement the applicable
Marmot client mode in §7.

`comms.public-reader.v1` is a narrower receive-only feature claim. It does not
require a persona key, publishing, private tiers, claims, OIDC, direct
conversation, or a Control implementation.

<a id="comms-envelope"></a>
## 2. Nostr-native event envelope and verification


The canonical Comms content unit is one NIP-01 signed event. Ordinary Nostr
relays and Core repo relays carry the same event bytes; the event `id` is the
deduplication key across both backends. Repo visibility and application-layer
encryption change confidentiality, not the NIP-01 envelope.

Before rendering, storing, indexing, or authorizing a received event, a client
MUST apply the Core NIP-01 verification rules. In order, it MUST:

1. require a well-formed event and the exact `nip01_raw` signing bytes;
2. hash `nip01_raw`, match `id` and every parsed field, and verify BIP-340;
3. when persona authorship is required, require `event.pubkey` to equal that
   persona's active key; and
4. apply the Comms schema, tier, and authorization rules for the event.

A failure MUST be surfaced as a rejection or explicit security indicator;
clients MUST NOT silently treat an invalid event as verified. A cold root,
KERI log, repository ref, storage signer, relay identity, or optional
Assurance claim MUST NOT substitute for the event's actual NIP-01 author.

Under [`heterodyne:0.5.0#core-version-stamps`](heterodyne-core.md#core-version-stamps), Comms-allocated
JSON-content kinds carry `"spec_version":"heterodyne/0.5.0"`.
Comms-allocated empty-content kinds carry
`["spec_version","heterodyne/0.5.0"]`. Adopted upstream events remain unstamped
unless the pinned registry names a stamping profile. Marmot transport and
unsigned inner application events remain governed by the pinned upstream
profile and their registered Heterodyne application discriminator.

<a id="comms-privacy-tiers"></a>
## 3. Repository privacy tiers


Every repository-carried publication declares one of three trust boundaries,
which clients MUST present without ambiguity:

| Tier | Stored form | Trust boundary |
|---|---|---|
| Tier 1 | plaintext in a public repository and on ordinary relays | confidential against no one |
| Tier 2 | plaintext in a private repository | hidden from non-allowed nodes, but readable by every allowed seeder |
| Tier 3 | NIP-44-v2-profile ciphertext in a public or private repository | confidential against everyone without the audience key, including seeders and full nodes |

Before a user relies on a Tier 3 audience, the client MUST disclose that Tier
3 protects content but not sender identity, recipient identity, audience
membership or membership changes, audience-generation linkage, timing, or
volume. A client MUST NOT label Tier 3 membership-private.

A client MUST NOT describe Tier 2 as encrypted, end-to-end encrypted, or
confidential against members. Adding an NID to `visibility.allow` grants that
node plaintext read and replication access and SHOULD require explicit user
confirmation. `visibility.allow` MUST NOT be conflated with the repository
`delegates` governance set.

Tier 3 content MUST be encrypted before it reaches any repository, full node,
seed, or relay. Plaintext Tier 3 content MUST NOT be committed or published.
An individual Tier 3 post outer event exposes only its registered
profile marker, opaque `key_id`, required Core integrity/identity tags, and
Comms profile stamp; semantic content and tags, RID, audience association, and
retrieval hints are encrypted. The surrounding distribution graph is not
membership-private: `kind:31011` and `kind:31012` expose clear recipient
`p`/`d` tags and roster changes, the shared `key_id` links wraps, rosters,
posts, descriptors, and rotations, and carrier observers retain
timing, size, count, publication, and fetch-cadence metadata.

<a id="comms-audience-keys"></a>
### 3.1 Audience key distribution and roster


An audience key is one
[`heterodyne:0.5.0#core-key-envelope`](heterodyne-core.md#core-key-envelope)
key generation. Comms supplies the five instantiation choices that primitive
requires and adds nothing else to its distribution and rotation rules:

| Choice | Comms value |
|---|---|
| Recipient set | every active Marmot account key selected for the audience, or an explicit policy-narrowed subset of those accounts |
| Reference and wrapping | `nostr-secp256k1`, NIP-44 wrapped to the active account key |
| Carrier | one `kind:31011` per recipient, with the replaceable `kind:31012` roster |
| Generation identifier | opaque `key_id` |
| Extra rotation triggers | `none` |

An audience key is 32 uniformly random bytes. A narrowing policy MUST NOT add
an inactive, superseded, or unverified account key. Local custody, a standard
NIP-46 signer, or a full node may perform the account-key operation; the wire
recipient remains the active account key and never an MLS leaf, Radicle NID,
repository RID, cold root, or KERI key.

The event MUST be signed by the publishing persona's active key and contain
exactly the addressing fields represented here:

```json
{
  "kind": 31011,
  "tags": [
    ["d", "<key_id>:<recipient pubkey-hex>"],
    ["heterodyne", "audience_key_wrap"],
    ["key_id", "<opaque id with at least 128 bits>"],
    ["p", "<recipient active account pubkey-hex>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": "<NIP-44 wrap of the audience key>"
}
```

The replaceable `kind:31012` roster uses `d = key_id`, the
`audience_roster` discriminator, the same `key_id`, and one `p` tag per
recipient active account key. It MUST be signed by the publishing persona's
active key. A sensitive roster MAY instead be carried inside a Tier 3
encrypted object.

Encrypting the roster does not create complete membership privacy.
Recipient-addressed `kind:31011` events on public carriers still expose the
clear recipient and generation linkage Core warns of. This release defines no
membership-private audience-key distribution profile.

Every addition and removal follows the Core key-envelope rotation rules.
Removing or superseding an account removes it from the effective recipient
set. Comms re-protects retained current objects and supersedes the
in-audience descriptor under the fresh generation. The producer MUST initiate
every required descriptor, roster, wrap, and retained-object action within
60 seconds of the triggering change
and retry until success, explicit expiry, user cancellation, a superseding
state transition, or the profile's terminal retry-budget outcome. A carrier
partition is an availability failure, not automatic producer nonconformance.

<a id="comms-tier-three-profile"></a>
### 3.2 Tier 3 encryption profile


Comms profiles the symmetric ChaCha20/HMAC-SHA256 layer of NIP-44 v2. It does
not perform NIP-44 ECDH for a post body; the per-recipient ECDH occurs
only in `kind:31011`. Keys are domain-separated:

```text
post_key = HKDF-SHA256(
  IKM=audience_key,
  salt=UTF8(key_id),
  info=UTF8("heterodyne-post-key-v1"),
  L=32
)
```

`audience_key` is the raw 32-byte key, not its hexadecimal text; `key_id` and
the domain label are encoded exactly as UTF-8. The resulting raw 32 bytes are
passed directly as the NIP-44 v2 symmetric layer's `conversation_key`; no
ECDH or additional KDF is applied. Every encryption under a derived key MUST
use a fresh 32-byte NIP-44 nonce, and a producer MUST NOT reuse a nonce with
the same derived key.

The registry permits Tier 3 wrapping only for this closed stamping
profile set:

| Nostr kind | Profile ID |
|---|---|
| `1` | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` |
| `6` | `heterodyne-comms-tier3-wrapped-content-kind-6-v1` |
| `16` | `heterodyne-comms-tier3-wrapped-content-kind-16-v1` |
| `1063` | `heterodyne-comms-tier3-wrapped-content-kind-1063-v1` |
| `30023` | `heterodyne-comms-tier3-wrapped-content-kind-30023-v1` |
| `30402` | `heterodyne-comms-tier3-wrapped-content-kind-30402-v1` |

Every profile uses discriminator `tag:heterodyne_wrap=room_key.v2` and is
stamping. Another upstream kind MUST NOT use `room_key.v2` until a later
registry revision allocates its own immutable profile.

A Tier 3 post has this outer shape (kind `1` shown):

```json
{
  "id": "<SHA-256 of canonical NIP-01 serialization>",
  "pubkey": "<publishing persona active key>",
  "created_at": 0,
  "kind": 1,
  "tags": [
    ["heterodyne_wrap", "room_key.v2"],
    ["key_id", "<opaque audience-key generation id>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": "<NIP-44-v2 symmetric ciphertext of the inner payload>",
  "sig": "<BIP-340 signature by the active key>"
}
```

The clear tags of every Tier 3 post MUST include the two wrap tags and
`spec_version` equal to `heterodyne/0.5.0` as required by its stamping
profile. For addressable kinds
`30023` and `30402`, an additional outer `d` tag is REQUIRED and MUST be an
opaque value derived from at least 128 bits of randomness or a keyed digest;
the semantic address remains encrypted. No other clear tag is permitted.
In particular, `room`, `matrix_room`, `rid`, `megolm_session_id`, semantic
`e`/`p`/`t` tags, and retrieval hints MUST remain encrypted.

The encrypted inner JSON is exactly a `content` string and `tags` array.
Encryption happens before signing, so re-encryption is a new intent and event
id.

A receiver MUST select the audience key named by `key_id`, derive `post_key`,
decrypt and parse the closed inner object, reconstruct the logical event, and
then verify the outer signature by its actual NIP-01 author. Possession of the
key, not current membership metadata, is the cryptographic access test.
`room_key.v1` and the withdrawn NIP-59 broadcast path MUST be rejected.

<a id="comms-config-repository"></a>
### 3.3 Config-repository protection profile


The `heterodyne-comms-config-repository-v1` protection profile instantiates
[`heterodyne:0.5.0#core-protected-repository`](heterodyne-core.md#core-protected-repository) with the Tier 3 profile
above. There is exactly one private,
unadvertised config repository per persona; its allow list contains only the
persona's durable authorized writer NIDs. The RID MUST NOT appear on any
published profile, event, relay list, or node advertisement. It travels only
through authorized credential sync, the Core keys repository, or backup
restore.

The dedicated config audience key MUST NOT be distributed by published
`kind:31011`; that would reveal the repository and audience. The repository
MUST contain no nsec, NID secret, audience key, or MLS state.
Comms owns its encryption profile and audience payload types; private
social preferences and followed-repository payloads are outside Comms.
The private persona claim ledger in §11 is an allowed Comms-owned non-key
configuration payload.

Writer authorization comes only from the active persona key's authenticated
repository policy and each writer NID's proof over the same exact RID, ref,
and operations under
[`heterodyne:0.5.0#core-nid-delegation`](heterodyne-core.md#core-nid-delegation).
A local device inventory is bookkeeping and MUST NOT authorize a writer.

<a id="comms-encrypted-branches"></a>
### 3.4 Encrypted branches, deletion, and residue


Ciphertext for each generation MUST live only at
`refs/heads/enc/<key_id>`; the default branch carries no ciphertext. The
RECOMMENDED self-verifying id is the first 16 bytes, lowercase hex, of
`SHA-256("heterodyne-key-id-v1" || audience_key)`, though verifiers MUST treat
all valid ids as opaque.

On rotation the publisher MUST create the new branch and force-delete the
retired ref from its signed refs. It MAY re-encrypt retained history, producing
new events and ids. Cooperating seeds SHOULD reclaim unreachable objects.
This scrub is cooperative hygiene, not erasure, under
[`heterodyne:0.5.0#core-non-erasure`](heterodyne-core.md#core-non-erasure).

Individual deletion uses ordinary Nostr `kind:5`. It signals intent, not
erasure. Live history MUST NOT be rewritten; deletion of a whole
retired `enc/<key_id>` ref is the sole sanctioned ref-deletion path.
Clients MUST warn that Tier 1 and Tier 2 plaintext may persist on every node
that fetched or seeded it. Tier 3 ciphertext may persist on relays and
non-cooperating seeds and remains readable to holders of its retired key.

<a id="comms-publishing"></a>
## 4. Publishing and delivery


One publication intent MUST produce exactly one signed Nostr event, computed
once and fanned out unchanged. Implementations MUST NOT re-sign the same
intent. Tier 3 encryption precedes signing. The event `id` is the idempotency
token across ordinary relays, repo relays, and native repository ingestion;
receivers MUST deduplicate on it.

The public destination set is the union of the author's selected NIP-65 write
relays, applicable read relays of tagged recipients, a repo relay already
listed in the author's kind `10002`, and other explicitly selected ordinary
relays. Tier 1 plaintext MAY use every public destination. Tier 2 plaintext
MUST be published only to private-repository allowed writers and interfaces.
Tier 3 ciphertext MAY use its configured ordinary and repository-backed
relays. A repository-backed relay receives the same standard NIP-01 `EVENT`
message and exact event bytes as any ordinary relay; it adds no envelope or
storage signature to the event.

A Nostr write is permanently failed when a relay returns NIP-01 `OK=false`
with `invalid:`, `blocked:`, or `restricted:`, when `rate-limited:` exceeds
one hour, after three consecutive retry windows, or on application close code
4000-4999. Other failures are transient. An AUTH-required rejection is
transient before NIP-42 authentication and permanent if repeated afterward
(`auth_rejected_permanent`). A NIP-13 proof-of-work rejection is PERMANENT
when the client cannot meet the relay's target.

Partial delivery succeeds when at least one intended destination accepts the
event. Every failed destination remains eligible for retry with the original
bytes, `created_at`, tags, content, signature, and event ID. If no destination
accepts, the event remains locally pending. A client MUST surface
destination-specific partial or total failure and MUST NOT create or commit a
custom public feed-index entry as a substitute for delivery.

An automated-principal publication additionally MUST satisfy §15 before this
ordinary fan-out begins. The full node constructs and signs one canonical
attributed event; an idempotent retry reuses those exact bytes and event id.

<a id="comms-feed-index"></a>
## 5. Standard outbox state and filtering


Public Comms history is the set of valid Nostr events returned by ordinary
NIP-01 filters, not a Heterodyne ordering object. A client requests the active
persona key in the filter's `authors` field and selects the application kinds,
tags, and time or limit bounds appropriate to its view. Event `pubkey` remains
the actual author and event `created_at` remains the ordinary ordering input.

Required kind `31005` identity pointers and kind `31007` feed indexes are
retired. A current Comms producer MUST NOT publish either as required
discovery or ordering authority, and a consumer MUST NOT require one for
outbox location, retrieval, completeness, current-state selection, repository
use, or public presentation. Historical events of those kinds remain
signature-verifiable Nostr events but grant no current authority.

The candidate set is the union of locally verified results from every
reachable ordinary relay, repo relay, and authorized native repository path.
Clients deduplicate by event ID before applying the selection rules in §5.2.
A carrier may omit, delay, replay, or reorder a result; it cannot make its copy
win merely because that carrier is preferred or durable.

<a id="comms-org-authorization"></a>
### 5.1 Organization authorship


An organization uses the same active-key wire model as a human persona. An
organization-owned Comms event is an ordinary NIP-01 event whose `pubkey` is
the organization's active key. Several custodians MAY jointly produce that
one BIP-340 signature, but delegate policy, repository branches, writer refs,
and optional Assurance do not replace it or create an alternate author.

<a id="comms-feed-paging"></a>
### 5.2 Candidate union and replaceable selection


Ordinary events coexist by event ID. Replaceable events select by
`(pubkey, kind)`, and parameterized replaceable events select by
`(pubkey, kind, d)`. Within one replaceable coordinate, the event with the
greatest `created_at` wins; the lowest lexicographic event ID wins a tie.
Invalid signatures, mismatched IDs or `nip01_raw`, and wrong-author candidates
never enter the union.

When reachable, a repository is the preferred durable source and
reconciliation target. It is not a source-priority override. A newer valid
relay event missing from the repository wins immediately and makes the
repository stale until an authorized writer ingests those exact bytes.
Repository unavailability leaves relay-derived state fully usable.

<a id="comms-private-index"></a>
### 5.3 Tier-specific carrier boundaries


Tier 1 filters may query ordinary public relays and public repo relays. Tier 2
filters may query only authorized private-repository interfaces. Tier 3
filters retrieve the signed ciphertext events from their configured ordinary
or repository-backed relays and decrypt only after exact-event verification.
The filter and selected carrier MUST NOT weaken the tier's disclosure rule.

Private audience bootstrap MAY carry an encrypted descriptor that names its
current `key_id`, authorized interfaces, and RID inside the audience boundary.
That descriptor is configuration, not a public feed index and not an ordering
authority. Rotation MUST supersede it under the fresh audience generation.

<a id="comms-retrieval"></a>
## 6. Retrieval, reconciliation, and NIP-65 outbox location


Public outbox discovery starts from the active persona key, obtained directly
or through NIP-05. A client fetches valid kind `0` and kind `10002` candidates
from known relays, selects current replaceable state under §5.2, and queries
the selected NIP-65 write relays with ordinary NIP-01 filters. An unmarked
kind-`10002` relay is both read and write; an explicitly marked relay has only
the upstream NIP-65 role that its marker grants.

The retrieval candidate set is the normalized, deduplicated union of selected
write relays, useful read relays, accepted event or NIP-19 hints, and every
repo relay already listed as an ordinary endpoint in kind `10002`. Clients
verify all returned events locally, union the valid candidates, deduplicate by
event ID, and apply §5.2. An unavailable repository, missing profile extension,
or absent optional Assurance chain MUST NOT make valid relay results unusable.

When native repository access is available, reconciliation compares the same
exact event IDs and `nip01_raw` bytes. An authorized writer fills repository
gaps without re-signing, normalizing, or replacing newer relay state. Writer
and carrier preference affects durability and retry order only; it never
changes which candidate wins.

Heterodyne publishing clients MUST refresh kind `0` and kind `10002` at least
once every seven days, even when their content is unchanged. Passing that
boundary produces a visible staleness or liveness warning, not invalidity of
the last correctly signed events. Relay-only retrieval remains a complete and
conforming public path.

Tier 3 retrieval obtains ciphertext before decryption. Tier 2 retrieval uses
only an authorized private interface. Marmot history follows the group's
declared retention and join-epoch rules. Comms defines no mandatory archive
service, centralized delivery directory, subscriber graph, or social-feed
presentation.

<a id="comms-public-reader"></a>
### 6.1 Public-reader feature

`comms.public-reader.v1` consumes only verified Tier 1 Nostr events and
source-neutral retrieval state. It MUST implement
`core.nostr-relay-read.v1`, local NIP-01 identifier and BIP-340 verification,
§5 candidate selection, §6 retrieval, and
`COMMS-I-PUBLIC-READER-TIER1-ONLY`. It MUST NOT require a Heterodyne account,
persona key, repository write path, publishing feature, claim ledger, OIDC
issuer, DM session, or Control session merely to render public content.

A public reader without `core.outbound-tor.v1` MAY contact accepted clearnet
`wss://` relays and remains conforming for this declared feature. It MUST
report reduced assurance and MUST NOT claim onion reachability or network
anonymity. It is account-anonymous because it presents no Heterodyne persona;
the launcher host sees the application download, and relays and external media
hosts may still observe its network address.

<a id="comms-public-launcher"></a>
### 6.2 Universal public launcher

The provider-independent version-1 fragment grammar is exactly:

```text
#/v1/p/<nprofile>
#/v1/p/<nprofile>/e/<nevent>
#/v1/p/<nprofile>/a/<naddr>
```

The first form selects a persona, the second an immutable event, and the third
an addressable or replaceable event. `nprofile` MUST decode under NIP-19 and
its public key MUST be the persona's active key. An `nevent` author, when
present, and an `naddr` public key MUST equal that active key. A cold root,
`did:key`, Radicle NID, repository RID, OIDC subject, optional Assurance key,
or launcher origin MUST NOT substitute for the active Nostr identity.

A compatible static host appends the complete fragment to its application
origin. The reference form is:

```text
https://heterodyne.network/client/#/v1/p/<nprofile>[/e/<nevent>|/a/<naddr>]
```

The origin and HTTP request path are not semantic inputs. A launcher MUST
download the same static application for every target, parse only the fragment
locally, and MUST NOT transmit the persona, asset, or relay identifiers in the
application request path. `heterodyne.network` is a reference host, never
identity, content, repository, or delivery authority. The identical artifact
and grammar MUST remain self-hostable.

Before any network activity, the client MUST parse the complete fragment,
reject an unknown route version or entity type, reject a fragment longer than
16,384 characters, and reject any individual NIP-19 entity longer than 5,000
characters. A parse failure returns `public-reader-route-invalid` and yields no
network plan.

NIP-19 relay entries are untrusted bootstrap hints. Across all route entities,
the client MUST use at most the first eight distinct normalized accepted hints
and ignore later hints. A public clearnet hint MUST use `wss://`; it MUST NOT
contain credentials, query, or fragment components. The client MUST reject
localhost, single-label, `.localhost`, `.local`, `.internal`, and any literal
or resolved private, link-local, loopback, unspecified, documentation,
benchmarking, multicast, or other special-use address with
`public-reader-relay-hint-invalid`. A `.onion` hint MUST be a v3 onion hostname
and MUST be used only through Tor. When a browser does not expose DNS results,
the client MUST rely on platform private-network protections and minimize the
connection to the NIP-01 exchange; successful connection is never authority.

<a id="comms-public-resolution"></a>
### 6.3 Local public resolution

After complete local parsing, the client:

1. contacts accepted usable hints;
2. resolves the active key directly from `nprofile` and verifies current kind
   `0` and kind `10002` candidates source-neutrally;
3. queries the selected NIP-65 write relays, usable read relays, and accepted
   route hints with an ordinary author, ID, or addressable-event filter;
4. verifies exact NIP-01 bytes, identifier, signature, author, kind, and `d`
   coordinate where applicable;
5. unions and deduplicates valid relay and optional repository candidates; and
6. applies ordinary NIP-01 replaceable selection without source priority.

Resolution MUST terminate in exactly one visible state:

- `verified` when the selected Tier 1 event passes every required check;
- `conflicted` when applicable NIP-01 or addressable-event rules
  identify a conflict;
- `unavailable` when no queried carrier returns the requested valid event; or
- `private` for Tier 2 plaintext or Tier 3 ciphertext.

The client MUST NOT turn a failed fetch into an authoritative empty outbox. It
MUST NOT render Tier 2 plaintext in public-reader mode and MUST NOT interpret,
probe, or label Tier 3 ciphertext as public content. Repository confirmation
MAY report durability, but its absence MUST NOT demote a relay-verified event.

<a id="comms-public-transition"></a>
### 6.4 Anonymous-to-authenticated transition

The static application starts with no identity or device key. At explicit user
request it MAY, without reloading the application or creating a hosted server
session, generate a local non-delegated Control key, locate a full-node Marmot
KeyPackage on accepted relays, establish a two-member group, and invoke the
Control enrollment profile. The transition MUST NOT change already verified
public-reader identity or content results.

The Control principal receives no persona active-key secret, NID secret,
audience key, repository-decryption key, credential-ledger key, device key, or
MLS leaf
belonging to another member. Logout MUST attempt self-revocation when
available, delete the local Control key and group state, clear private
configuration and decrypted caches, and return to public-reader mode without
a reload. Local deletion MUST proceed when revocation delivery fails; short
token expiry and the node's authorization-freshness policy are the backstop.

<a id="comms-public-reader-security"></a>
### 6.5 Launcher and content security

Fetched content is data, never application code. A launcher MUST sanitize
markup and MUST NOT execute publication-provided scripts, event handlers,
frames, or active content. External media requests MUST omit credentials and
referrer information. Without Tor, the client MUST warn before loading
external media that the request reveals its network address to the media host.

The reference client MUST load no third-party executable script, MUST apply a
restrictive Content Security Policy, and SHOULD publish reproducible signed
artifacts and a public release-transparency record. Hosted JavaScript remains
inside the authenticated browser's trusted computing base. Reproducibility
improves detection; it does not make mutable web delivery equivalent to an
independently installed client. Centrally hosted authenticated sessions SHOULD
receive short-lived constrained grants by default.

<a id="comms-marmot"></a>
## 7. Marmot conversations and Control application carriage

Comms adopts Marmot at exact commit
`4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` as the normative conversation
dependency for this release, with Git tree
`10d941f358de5d9fe4ee1db75581f3e5363f5e92`. The normative adopted
specification bytes are preserved under
`external/marmot/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/` and closed by
`external/marmot/manifest.json`. A conforming verifier MUST use that local
archive and verify every recorded path, byte length, Git blob ID, SHA-256,
and aggregate SHA-256; the upstream URL is provenance, not a runtime
dependency. Missing, extra, changed, or path-traversing archive entries are
rejected.

The archive contains the upstream MIT license, root README, `layout.md`,
`principles.md`, and every adopted Markdown document in `foundation/`,
`protocol-core/`, `app-components/`, `transports/`, and `features/`, including
adopted section READMEs. It excludes implementation, build, MIP, agent-guide,
experimental, deprecated, superseded, branch-draft, and historical material.
Updating the pin requires a reviewed replacement archive and manifest plus
all affected Heterodyne specification, registry, release, and vector changes.
Upstream implementation code is never normative.

Marmot is authoritative for MLS group creation, membership, proposals,
commits, Welcomes, retained state, and convergence; account credentials and
account-to-leaf proofs; unsigned Nostr-shaped application events; group
messages, edits, replies, reactions, and group-scoped long-form content;
encrypted-media v2; and its Nostr KeyPackage, Welcome, and signed `kind:445`
transport envelopes. Heterodyne MUST NOT fork, reinterpret, or add a required
application component to those surfaces.

Heterodyne is authoritative only for Control authorization, node-mediated
operation, agent policy, and Radicle repository and relay profiles around
those standard surfaces. Heterodyne metadata MUST NOT select an MLS branch,
alter convergence, replace an account proof, or introduce an identity alias
inside Marmot.

Ordinary user-facing one-to-one conversations and routine own-device Control
channels are two-member Marmot groups. Marmot also owns private group content,
replies, reactions, attachments, edits, group-scoped long-form messages, and
the authenticated encrypted application carriage on which Control relies.

<a id="comms-marmot-participation"></a>
### 7.1 Identity, leaf ownership, and client modes

The persona's active Nostr key is its Marmot account identity for ordinary and
administrative account-scoped privilege. There is no separate
`marmot:human-messaging` key, `marmot:group-admin` key, or Heterodyne account
alias. An agent key that participates is a separate standard Marmot account.
Local custody, NIP-46, and full-node signing are implementation choices and do
not change the account key carried by Marmot.

Devices use independent Marmot MLS leaf keys. Heterodyne does not adopt
Marmot's draft multi-device External Commit profile. A new device uses
standard Marmot KeyPackages, Add commits, account-to-leaf proofs, and
Welcomes. A leaf backup or transfer is permitted only as the exclusive
takeover allowed by Marmot; concurrent use of one leaf by multiple devices MUST
be rejected.

Active-key succession creates a new Marmot account. Every affected group MUST
explicitly remove all leaves bound to the old account, publish fresh
KeyPackages, add new independent leaves bound by standard account proofs to
the successor account, and advance the group under Marmot's rules. Optional
Assurance continuity MAY explain the transition to Heterodyne clients but
MUST NOT alias the accounts, preserve old leaf membership, or transfer group
administration inside MLS.

Comms defines two client modes:

- A `direct-member` owns an independent MLS leaf and communicates directly
  through an authorized Marmot transport after admission. Its ordinary
  retained history begins at its join epoch.
- A `node-mediated` client owns no group leaf. A designated full or recovery
  node participates in the group and exposes only grant-filtered conversation
  operations and retained history through Control. MLS secrets MUST NOT leave
  that node.

Browser and other light clients MAY use either mode when capable. Automated
principals MUST use `node-mediated`. An exclusive leaf restore MAY restore
retained history and epoch secrets contained in the encrypted backup.
Heterodyne MUST NOT export old epoch secrets to a new independent leaf merely
because both leaves are attributable to the same persona.

<a id="comms-marmot-groups"></a>
### 7.2 Group profiles and delivery policy

A `standard-compatible` group uses Marmot's unmodified Nostr transport.
Unmodified Marmot clients can join and communicate through the group's
advertised Nostr relays. Heterodyne clients MAY additionally use native
Radicle or a Radicle-backed relay, but those paths MUST expose the same Marmot
event and media bytes.

A `heterodyne-private` group is non-discoverable and Radicle-only. Its static
directory and routing-generation repositories are private Radicle
repositories. An administrator MUST authorize a member persona's active
Radicle NID and privately deliver repository and group bootstrap information.
The group still uses valid Marmot MLS state, application events, media, and
transport-envelope bytes. Ordinary Marmot clients cannot discover, join, or
synchronize it because they do not implement the private Radicle admission
profile; the incompatibility ends at that boundary.

A private group MUST fail closed when no authorized Radicle route is
available and MUST NOT fall back to an undeclared public relay.

Delivery configuration is per group and client:

- `failover` submits to one preferred target and tries another authorized
  target after rejection, timeout, or unavailability;
- `redundant` submits the exact same signed Marmot event to all configured
  targets immediately.

The first valid durable acknowledgement satisfies Marmot's
publish-before-apply requirement. Outstanding redundant attempts MAY
continue. Receivers MUST deduplicate by Nostr event ID so a second carriage
does not become a second logical message.

<a id="comms-marmot-directory"></a>
### 7.3 Static group directory repository

Each Heterodyne-backed group has one stable directory repository and a
sequence of event repositories. The directory manifest MUST validate against
`docs/spec/schemas/comms/marmot-group-directory-v1.schema.json`.

The manifest's `account_key` is the active Marmot administrator account that
authored the current standard routing commit. `current_routing` binds that
commit's exact event ID and `h` to one event RID and routing-binding digest.
Every `authorized_writer_refs` entry binds one Radicle NID to one exact ref;
the NID is storage provenance and never the Marmot account. Those members MUST
agree with the current routing binding and repository genesis before the
directory state is accepted.

The static repository carries stable group identification, public profile and
policy fields, host announcements, sealed invitations, encrypted routing
bindings, retention policy, membership administration, mute lists, and
moderation metadata. It MUST NOT be used as the message log.

A discoverable group has a public static repository. Public fields are
plaintext. Event-repository locators, membership, administrative records, and
other sensitive fields MUST be encrypted for current members. Invitations
MUST be individually sealed to their recipients. A declared public-group
policy MAY explicitly expose a normally private field.

A non-discoverable group has a private static repository. Its Radicle
allowlist is an admission boundary, not encryption at rest. Sensitive records
MUST remain application-encrypted for defense in depth. After removal, hosts
MUST exclude the removed NID from future replication and encrypt new directory
records only for the remaining membership.

<a id="comms-marmot-routing-generation"></a>
### 7.4 Routing generations and bindings

Marmot's `h` tag is the current random `nostr_group_id`; it is not an MLS epoch
number. One Heterodyne routing generation maps one-to-one to one `h` and one
event-repository RID.

A new routing generation rotates both `h` and the active event repository:

- whenever a member is added or removed;
- when the active repository reaches the 5 GB logical soft cap; or
- when an administrator explicitly rotates after compromise or operational
  failure.

Other MLS commits MUST NOT rotate the event repository. A routing update
itself creates an MLS epoch, so implementations MUST NOT describe this profile
as rotating after every MLS epoch.

For an addition, the administrator MUST prepare the repository and new `h`
before the Add transition so the Welcome delivers the resulting routing state
to the new member. For a removal, the removal commit MUST become canonical
first. A remaining administrator then publishes a separate Marmot routing
update from the post-removal state. An implementation MUST NOT combine those
steps in a way that reveals the replacement `h` to the removed member.

A routing binding MUST validate against
`docs/spec/schemas/comms/marmot-routing-binding-v1.schema.json` and MUST bind
the stable group identifier, new `h`, event RID, genesis-manifest digest,
prior generation, exact authorized writer NIDs and refs, authorized host set,
advertised interfaces, retention metadata, signing administrator
`account_key`, and accompanying standard Marmot routing-commit event ID. The
binding's `account_key` MUST equal the account that authored that canonical
commit, and the commit's `h` MUST equal the binding's `h`.

<a id="comms-marmot-event-repository"></a>
### 7.5 Event repository and logical union

An event repository genesis manifest MUST validate against
`docs/spec/schemas/comms/marmot-event-repository-genesis-v1.schema.json`.
The repository is append-only at the logical protocol layer and has no merged
canonical message branch.

The genesis `account_key`, `marmot_routing_event_id`, `h`, and `event_rid`
MUST exactly match the accepted routing binding. Its
`authorized_writer_refs` is the initial accepted writer set and MUST match
the binding. Later writer changes require the same group-owner authorization
and NID proof required by Core; they do not change Marmot authorship or group
administration.

Each native writer MUST publish to its own NID ref. An integrated relay MUST
publish relay-ingested objects to its own authorized NID ref under the relay
ref prefix. No two writer NIDs may share an accepted ref, and no accepted ref
may name two writer NIDs. Hosts replicate
valid authorized refs. The logical contents are the union of valid objects
reachable from authorized refs, deduplicated by Nostr event ID for events and
ciphertext hash for media. An unauthorized, malformed, or equivocated ref MUST
NOT contribute to the union.

Routing-generation event repositories are private by default for both
discoverable and non-discoverable groups. A group MAY explicitly authorize
public Radicle replication, but the client MUST present that choice as
metadata disclosure. Ordinary Marmot clients use an advertised Nostr relay
and do not need repository access.

The 5 GB cap measures the logical unique encoded bytes of stored event objects
plus encrypted media objects, not Git object, packfile, or filesystem size.
After the threshold is crossed, hosts MUST stop admitting new application and
media objects and MUST initiate rotation. They MUST continue admitting bounded
proposals, commits, routing updates, and other control traffic required to
repair or rotate the group.

Radicle ref identity proves storage provenance only. Marmot authenticates the
sender from the decrypted MLS message. A client MUST NOT infer sender identity
from the fresh ephemeral public key of an outer `kind:445`.

<a id="comms-marmot-exact-bytes"></a>
### 7.6 Exact event and media bytes

Every event object is the exact serialized signed Marmot Nostr event. A native
writer creates the standard event before committing it. A relay commits the
received bytes unchanged. An event is indexed by exact event ID and `h`; a
reader or NIP-01 endpoint returns the same bytes.

Radicle commits, indexes, relay adapters, and host replicas MUST NOT re-sign,
wrap, translate, normalize, or reconstruct the event. For every accepted
`kind:445`, the exact bytes hashed and signed by Marmot MUST be byte-identical
through native Radicle, onion NIP-01, and optional clearnet NIP-01 access. The
only permitted adaptation is between repository lookup and the standard
NIP-01 request/response interface.

Encrypted media objects are indexed by ciphertext hash. The ciphertext served
through native Radicle, onion media access, optional clearnet media access,
and any repeated locator MUST be byte-identical.

<a id="comms-marmot-relay"></a>
### 7.7 Radicle-backed Marmot relay and hosts

The OPTIONAL feature `comms.radicle-backed-marmot-relay.v1` is a standard
NIP-01 relay backed by routing-generation event repositories. It may expose
onion, clearnet, or both interfaces. It is not required of every full node.

The relay maps `h` directly to an event repository. It MUST NOT require or
infer the stable group identifier, MLS epoch, member list, administrator
policy, or static repository. It verifies the visible NIP-01 envelope and
commits exact accepted bytes to its relay ref.

Because `kind:445` uses a fresh ephemeral event key, a restricted relay MUST
NOT use that key as member identity. A write allowlist may use NIP-42
connection authentication by an authorized stable Marmot account key. This is
anti-abuse admission only; it MUST NOT be presented as Marmot sender
authentication. A relay claiming the private trusted-seed profile additionally
implements [§7.7.1](#comms-trusted-seed-private-relay); NIP-42 alone grants no
read, write, routing, or repository authority.

A group has one or more hosts, and administrators are hosts by default. Hosts
replicate the static, active, and retained archive repositories; advertise
authorized Radicle, onion, and clearnet interfaces; enforce repository
admission and retention; prepare repositories and bindings; and initiate only
authorized membership and routing commits. A host or Radicle delegate MUST
NOT acquire group-admin authority merely by hosting.

Light clients do not need Radicle NIDs unless they use native Radicle
membership. A standard-compatible client may remain Nostr-only.

<a id="comms-trusted-seed-private-relay"></a>
#### 7.7.1 Trusted-seed private relay

The OPTIONAL feature `comms.trusted-seed-private-relay.v1` lets an explicitly
trusted seed serve one private Marmot routing generation. Trust is anchored to
the seed's canonical Radicle NID under
[`heterodyne:0.5.0#core-seed-nid-trust`](heterodyne-core.md#core-seed-nid-trust),
not to its relay key, DNS name, TLS certificate, URL, repository head, or mere
availability. Several seed NIDs MAY be active concurrently. Each has its own
relay endpoint, Radicle endpoint, grant, permissions, and relay-ingest writer
ref. There is no primary seed and no shared ref between seed NIDs.

Private relay access requires successful NIP-42 authentication by the stable
Marmot account being authorized. The selected seed consequently learns that
account key, the presented `h`, the target private RID, timing and traffic
volume, and whether the request is a read or write. A client MUST present this
metadata disclosure before enabling the seed. The seed MUST NOT receive a
Marmot leaf, epoch secret, application plaintext, content-decryption key,
stable group identifier, or private administrative record.

The seed enforces one current private ACL projection validating against
`schemas/comms/trusted-seed-acl-v1.schema.json`. The closed object contains:

- profile `heterodyne.trusted-seed-acl.v1` and `spec_version`;
- the signing `administrator_account`;
- allowed stable Marmot `accounts`, each with a non-empty set of `read` and/or
  `write` roles;
- the exact current `h` and private event-repository RID;
- one or more independent `seed_grants`, each binding a seed NID, relay and
  Radicle endpoints, its own relay ref, roles, and `active` or `revoked` state;
- safe-integer `sequence`, nullable predecessor digest, and the exact Marmot
  group transition's generation, routing-event ID, and routing-binding digest;
- safe-integer `issued_at` and `expires_at`; and
- the administrator's BIP-340 signature.

The signature uses domain `heterodyne-trusted-seed-acl-v1` over the complete
ACL except `signature`. The signer MUST be the active Marmot administrator
that authored the bound canonical routing transition. A genesis ACL has
sequence zero and a null predecessor. Every later ACL increments sequence by
exactly one and names the SHA-256 JCS digest of the complete prior signed ACL.
Distinct otherwise valid heads at the same greatest sequence conflict. A
non-genesis head without the exact accepted predecessor is ambiguous. Neither
wall-clock order, seed preference, repository default branch, nor Radicle
delegate order selects among conflicting or ambiguous state.

For every read or write, the seed MUST recheck NIP-42 identity, account role,
its own active seed grant and operation, the exact `h` and private RID, the
current Marmot transition, predecessor continuity, issue time, expiry, and
administrator signature. Missing, malformed, future-issued, expired, stale,
conflicting, ambiguous, revoked, unauthorized, or route-mismatched state fails
closed using the registered `trusted-seed-*` reason. A removed seed grant takes
effect as soon as the newer authenticated ACL is available; an explicitly
`revoked` grant MUST NOT be used even if the endpoint or old ref remains
reachable.

The admission request is closed before any authorization decision. Its exact
required metadata members are `acl_candidates`,
`expected_administrator_account`, `authenticated_account`,
`nip42_authenticated`, `operation`, `seed_nid`, `h`, `private_rid`,
`group_transition`, and `now`; only `previous_acl`, `writer_ref`, and
`nip01_raw` are optional across the union of operations. A read request MUST
omit `writer_ref` and `nip01_raw`; a write request MUST carry both as non-empty
strings. When present, `previous_acl` MUST be an object for subsequent ACL
validation. `group_transition` is itself closed to the three ACL members named
above. The seed validates every optional member's type and operation-specific
presence or absence during closure, before NIP-42 or ACL authorization. Any
missing, alternate, wrongly typed, nested-extra, or top-level-extra metadata
member fails with `trusted-seed-request-invalid`. A read admission result MUST
NOT return either write-only member. The seed treats the accepted kind-445
event `content` as opaque ciphertext; request closure MUST NOT scan or
interpret that encrypted content as plaintext.

A candidate whose `administrator_account` differs from the current expected
administrator is unauthorized. A candidate naming the expected administrator
but carrying an invalid BIP-340 signature is instead an invalid ACL. Account,
grant, operation, or writer-ref mismatch remains unauthorized.

An accepted write is one exact serialized signed Marmot Nostr event. The seed
parses the complete closed NIP-01 event object, requires kind `445`, requires
exactly one two-member `h` tag equal to the admitted route, recomputes the event
ID from the six NIP-01 signing fields, and verifies its BIP-340 signature.
Malformed JSON, missing or additional event members, wrong kind, bad ID, or bad
signature fails with `trusted-seed-event-invalid`; a missing, duplicate, or
mismatched `h` fails with `trusted-seed-route-mismatch`. After verification the
seed commits the original received bytes unchanged only to the writer ref
bound to its own NID, and acknowledges only after the durability boundary in
§7.9. The accepted repository view unions all current authorized native and
seed refs under §7.5. A seed MUST NOT write another seed's ref, merge refs,
re-sign or reserialize an event, infer the MLS sender from the outer event key,
or turn storage provenance into group authority.

A seed, full node, persona, repository owner, and Marmot administrator are
distinct roles. A combined deployment MAY hold several roles, but each grant
and conformance claim remains independent. Private relay service alone grants
no persona signing, repository ownership, full-node policy, group
administration, membership, or MLS authority.

<a id="comms-marmot-host-authority"></a>
### 7.8 Host authority, convergence, and equivocation

Static-repository changes are signed announcements. A client accepts a routing
binding only when:

1. `account_key` was an active Marmot administrator account;
2. that exact account authored the canonical standard Marmot routing commit
   named by `marmot_routing_event_id` and establishing the same `h`;
3. the binding, directory state, and genesis agree on the exact event RID,
   `h`, routing event ID, and authorized writer refs; and
4. the event repository's genesis manifest matches the bound digest.

Other authorized hosts may advertise replicas and endpoints for the bound
RID; they MUST NOT substitute another repository. Neither a Radicle default
branch nor delegate threshold selects Marmot group state.

Concurrent routing commits are resolved only by Marmot convergence. Prepared
repositories attached to losing commits are abandoned and eventually
garbage-collected. Two different validly signed bindings for the canonical
`h` are administrator equivocation. Native Radicle transition MUST fail
closed, retain the last valid generation or an already authorized standard
Nostr path, surface the conflict, and require a new administrator routing
rotation.

<a id="comms-marmot-rotation"></a>
### 7.9 Rotation transaction and durable acknowledgement

Preparation occurs off-path: create the new repository, random `h`, genesis
manifest, routing binding, and required host replicas. The new generation MUST
NOT become authoritative until the Marmot routing commit is durably published
through the old `h`. A failed publication leaves the old generation active;
the prepared repository is retried or abandoned.

For native Radicle publication, durable acknowledgement requires the exact
event and referenced objects committed to the writer's ref, durable local
storage, and acceptance of the ref announcement by at least one configured
host. For an integrated relay, NIP-01 `OK` MUST NOT be returned until event
ID, signature, tag cardinality, `h`, and local limits validate and the exact
bytes are durably committed to the relay ref.

Only after durable acknowledgement may the sender apply the new Marmot epoch
and `h` and publish the encrypted directory entry. A standard-compatible
group MAY try another authorized host, a direct Radicle peer, or an ordinary
Nostr relay. A Heterodyne-private group queues locally and fails closed when
no authorized route exists.

<a id="comms-marmot-retention"></a>
### 7.10 Retention and non-erasure

Clients and hosts MUST retain the current generation and the prior routing IDs
required by Marmot's retained-history and rollback horizon. Additional
archives remain advertised for the signed group retention period.

When an archive expires, conforming hosts remove it from the encrypted active
directory, stop advertising and seeding its refs, and remove local refs.
Conforming clients stop requesting or serving it and garbage-collect local
objects where supported. NIP-40 expiration inside an exact Marmot event
remains unchanged; repository retention complements it.

Expiration is not erasure, under [`heterodyne:0.5.0#core-non-erasure`](heterodyne-core.md#core-non-erasure).

<a id="comms-marmot-persona-inbox"></a>
### 7.11 Persona repository inbox and first contact

A persona repository MAY publish Marmot KeyPackages and expose a
contributor-ref inbox. Sender refs MUST NOT be merged into the recipient's
canonical profile branch.

When no suitable two-member group exists, a sender MUST consume one recipient
KeyPackage, create a standard two-member Marmot group, produce Marmot's exact
Welcome transport artifact and first exact `kind:445`, and commit both
atomically in a contact bundle conforming to
`docs/spec/schemas/comms/marmot-persona-inbox-bundle-v1.schema.json` on its
sender-specific ref. The bundle's `account_key` is the sender's actual Marmot
account and `writer_nid` is only the Radicle identity that wrote that ref; both
values MUST match its manifest. The Welcome and first event MUST establish the
same account through Marmot's standard account-to-leaf proof. The first
application event may be a direct message,
private reply, or private reaction referencing a public or privately shared
Social asset. Heterodyne defines no one-shot encrypted contact payload.
Subsequent messages use the group's routing-generation repository, and a later
reaction reuses an existing suitable group.

The recipient MUST validate the Welcome and first event before joining or
presenting an accepted conversation. Ignoring or rejecting the request does
not mutate the sender ref and grants no global moderation power.

A private persona inbox accepts only NIDs already authorized to replicate the
repository. Unknown first contact uses a public inbox or another authorized
bootstrap path.

For a public inbox, an unknown ref enters pull-based quarantine. The client
MUST fetch and validate a bounded manifest conforming to
`docs/spec/schemas/comms/marmot-persona-inbox-manifest-v1.schema.json` before
larger objects. The manifest identifies the sender account key separately
from its writer NID, consumed KeyPackage, event IDs, object sizes, and
automation status. The automation flag is quarantine metadata, not an account
alias or authorization grant. Unknown bundles MUST NOT
trigger automatic media retrieval. Clients discard duplicate KeyPackage use,
malformed artifacts, muted senders, objects over local limits, excess rate,
and unsupported capabilities. Hosts MAY impose stricter quotas without making
otherwise valid Marmot bytes invalid. Inbox publication never forces local
visibility, acceptance, or replication.

<a id="comms-marmot-media"></a>
### 7.12 Encrypted media and locators

Marmot encrypted-media v2 is the media format and cryptographic authority.
Heterodyne retains `radicle-v1` only as a locator and storage profile. A
Marmot message MAY carry repeated locators including both `radicle-v1` and a
standard Marmot or Blossom locator. Unsupported locators are skipped under
Marmot's rules and MUST NOT invalidate the message.

A Radicle reader locates media by ciphertext hash from the event repository
and its advertised object stores. Onion and clearnet media endpoints serve the
same ciphertext. Heterodyne MUST NOT define a second group-media encryption
format.

<a id="comms-direct-messages"></a>
### 7.13 Direct messages and pairwise Control groups

Person-to-person direct messages use standard two-member Marmot groups and
ordinary Marmot application events. Heterodyne adds no competing DM cipher,
invitation format, or outer event kind.

Routine light-client, human RPC, and agent RPC use ordinary two-member Marmot
groups under [`heterodyne:0.5.0#control-frame`](heterodyne-control.md#control-frame). Each participant uses the
exact Marmot account selected by Control and an independent leaf bound through
the standard account proof. A standard Welcome and valid MLS membership
authenticate transport identity but grant no application authority.

The registry profile `heterodyne-control-marmot-frame-v1` allocates unsigned
inner application `kind:31017`. The event is valid only inside Marmot MLS. It
has empty tags and JCS-canonical content conforming to the Control frame
schema. Comms owns no competing negotiation carrier or outer envelope.

A Tor-capable light client SHOULD use outbound Tor. A browser without Tor MAY
use configured shared clearnet relays in visibly labeled reduced-assurance
mode. Neither mode requires a direct client-to-node address.

Control applies bounded Marmot retention. Raw Control events, tokens, device
codes, MLS state, and replayable transcripts MUST NOT be committed to Radicle
or portable backups. Loss of group state creates a new group; it never restores
old application messages or authorization from transport state.

<a id="comms-one-time-invites"></a>
### 7.14 Provider-independent one-time invites

Heterodyne defines one closed invitation format with three non-convertible
purposes: `dm`, `control-enrollment`, and `device-enrollment`. A compatible
HTTPS client URL carries the envelope only in its fragment:

```text
#v1.<base64url-no-pad(JCS(envelope))>
```

The envelope has exactly `descriptor`, `signature`, and `secret`. The web
origin loads a client but is not authority and, under normal browser URL
processing, does not receive the fragment. A user MAY substitute any
compatible client origin without changing the descriptor or invite identity.

The JCS-canonical `descriptor` binds version `1`, exact purpose, inviter
Marmot account, random 256-bit `invite_id`, a fresh ephemeral Nostr
`rendezvous_pubkey`, one or more normalized `wss://` relay hints, issue and
expiry times, `SHA-256(secret)` for a uniformly random 256-bit secret,
`interactive` or `preauthorized` approval mode, and any exact expected client
key or preauthorization template. The inviter Marmot account is the actual
active persona or agent key that signs the descriptor. A higher-layer
`device-enrollment` profile MAY bind additional Control authorization, but
Comms requires no KERI, cold-root, or epoch-key evidence. Unknown descriptor,
envelope, authority, or preauthorization members are invalid.

The inviter account produces the BIP-340 `signature` over the SHA-256 digest
of the [`heterodyne:0.5.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes) bytes for domain
`heterodyne-one-time-invite-v1`, whose sole bound member `descriptor` is the
complete descriptor object.

The secret itself occurs only in the fragment and protected issuer state; it
MUST NOT occur in the descriptor, logs, relay metadata, or a repository.
DM invites default to 24 hours and a configured value MUST NOT exceed seven
days. Control and device-enrollment invites default to ten minutes and MUST
NOT exceed one hour. Processing at or after `expires_at` fails with
`invite-expired`.

The responder generates and retains its own Marmot account and fresh
serialized `mls_key_package` MLSMessage. It sends a NIP-59 gift wrap to the
ephemeral rendezvous key whose unsigned rumor is `kind:31018`, has the
responder account as `pubkey`, and carries JCS content conforming exactly to
`docs/spec/schemas/comms/one-time-invite-response-v1.schema.json`. The NIP-59
seal signer MUST equal that rumor `pubkey`. The response binds the exact
purpose, descriptor digest, responder account, KeyPackage bytes, requested
class, capabilities, and:

```text
HMAC-SHA-256(secret, <heterodyne-one-time-invite-response-v1 proof bytes>)
```

whose sole bound member `response` is the response without its proof member.

It MUST NOT carry a persona, device, epoch, NID, MLS-leaf, repository, or
agent-role private key. A purpose mismatch fails with
`invite-purpose-mismatch`; invalid descriptor signature, seal binding, proof,
KeyPackage, or capability binding fails with
`invite-authentication-invalid`.

Issuer state is restart-safe and moves `active -> reserved -> spent`. Only the
first completely valid responder account and canonical response digest may
reserve it. That exact responder and response MAY retry; any other response
fails with `invite-already-reserved`. Successful standard Marmot group
establishment spends it. Malformed, expired, revoked, purpose-mismatched,
capability-incompatible, or unauthenticated traffic MUST NOT reserve or spend
it.

A valid `dm` redemption creates an ordinary two-member Marmot group and makes
the Comms-native admission result `accept` for its issuer, subject to an
absorbing local mute or block. Higher-layer Control profiles define Control
device effects; the Comms rendezvous alone grants no application or persona
authority.

<a id="comms-acceptance-hook"></a>
## 8. Authenticated Marmot admission and synchronization policy

Marmot cryptographic and group validation always precedes Heterodyne local
acceptance policy. Neither hook below runs on an invalid KeyPackage, Welcome,
account-to-leaf proof, group state, membership, or application event. A valid
Marmot object never grants Control, claim-ledger, repository, or persona
authority.

<a id="comms-ordinary-conversation-admission"></a>
### 8.1 Ordinary-conversation hook

For a proposed ordinary two-member conversation, the hook consumes the
authenticated inviter and recipient Marmot accounts, exact group identifier
and KeyPackage reference, supported capabilities, prior local acceptance, a
valid purpose-bound one-time DM invite if present, and an explicit local
decision if one exists. It returns exactly `accept`,
`hold-as-message-request`, or `reject`.

An unknown but otherwise valid Welcome defaults to
`hold-as-message-request`. Before local acceptance a held conversation MUST
emit no receipt, retry hint, typing signal, read marker, presence update, or
other sender-observable acceptance signal. Prior local acceptance, an
explicit local acceptance, or a valid `dm` invite issued for that inviter
returns `accept`. An explicit rejection returns `reject`.

A higher-layer Social policy MAY only preserve or tighten this result. A mute
or block is absorbing. Transport acceptance and the Control hook are not
Social policy inputs.

<a id="comms-control-admission"></a>
### 8.2 Control-group hook

For a proposed pairwise Control group, the separate hook consumes the
authenticated Marmot accounts and leaves, exact group identifier and
KeyPackage slot, selected Control version and profile, node invitation mode,
resource-limit state, private entitlement state, a valid purpose-bound
Control invite if present, and an explicit local decision if one exists. It
returns exactly `accept-enrollment-only`, `accept-authorized`, or `reject`.

`accept-enrollment-only` permits only the methods named by
[`heterodyne:0.5.0#control-invitation-policy`](heterodyne-control.md#control-invitation-policy) and grants no durable
authority. `accept-authorized` requires active, non-conflicted private
entitlement for the authenticated client account. `reject` ends application
processing without revealing whether another entitlement or private object
exists. Resource and KeyPackage decisions occur during tentative Welcome
validation, before durable group creation or KeyPackage-state mutation.

<a id="comms-credential-sync"></a>
### 8.3 Credential and configuration synchronization

Durable NID-bearing full nodes synchronize canonical credential and
configuration repositories through private Radicle. Small live records,
progress, grant-filtered configuration, and completion receipts MAY travel
over an authorized pairwise Control group. A transport message never becomes
canonical state until the corresponding signed record is reachable from the
applicable canonical repository head.

A joining full node receives temporary private-repository access only through
the optional recovery grants at
[`heterodyne:0.5.0#control-radicle-recovery`](heterodyne-control.md#control-radicle-recovery). An ordinary light client
receives filtered decisions and configuration, never claim-ledger reader
authority, repository credentials, audience keys, issuer keys, or unfiltered
private records.

Credential and configuration state machines remain append-only,
generation-bound, rollback-resistant, and fail closed on unresolved forks.
Valid reductions and revocations take effect immediately when authenticated
and later become repository-final. No live Comms profile defines an additional
encrypted point-to-point carrier.

<a id="comms-credential-continuity"></a>
### 8.4 Transport-independent credential continuity drafts

The closed schemas under `schemas/comms/` for repository retention,
governed decrypt-key obligations, checkpoint receipts, secret-source and
exposure records, reset records, lost-generation handling, and exact Git
projection are transport-independent draft building blocks. They do not
define a live wire profile, are not required by baseline Control, and are not
required by either optional recovery profile. Implementations MAY experiment
with them only as encrypted repository records and MUST report them as
non-claimable drafts.

<a id="comms-control-registry"></a>
## 9. Private Control registry integration

Each persona has an encrypted private Radicle Control registry shared by
authorized full nodes. It is logically separate from public device metadata
and MAY share a protected repository with the private claim ledger only when
namespaces, keys, and access policy preserve both schemas.

The registry contains:

- signed Control client authorization and absorbing revocation records;
- authorized full-node issuer public state;
- minimal operation reservations, results, and commit evidence;
- encrypted audit records;
- optional prepared recovery activation, finite recovery grants, and
  completion receipts; and
- no raw Control frame, access token, device code, MLS state, epoch secret, or
  replayable transcript.

Comms stores Control client-authorization records as opaque encrypted objects;
their authority and merge semantics belong to the Control document. Repository
writers still authenticate against current Core/KERI state, and Comms MUST NOT
interpret transport arrival order as authorization.

The approving node may act on its own record only after durably committing
and validating that commit. Another node acts only after fetching and
validating the record and approving authority. The repository is evidence
replication, not distributed consensus or a cross-node execution lock.

<a id="comms-control-bootstrap"></a>
### 9.1 Locked epoch inbox and recovery records

The epoch-key NIP-59 inbox exists only for prospective full/recovery-node
registration when no authorized device Control channel is available. Public
Core metadata provides the epoch recipient key and relay hints. The gift-wrap
rumor, prepared activation, recovery grant, and completion records are defined
at [`heterodyne:0.5.0#control-epoch-bootstrap`](heterodyne-control.md#control-epoch-bootstrap).

The epoch key stays encrypted and absent from memory except during an explicit
local approval ceremony. Prepared public and private authority remains
inactive, and the wrapped epoch envelope remains unreleased, until exact
repository heads, manifest identity, and required object digests satisfy the
signed completion condition. Epoch plaintext MUST be erased and relocked
before any Radicle synchronization, onion-service startup, SFTP process, or
bulk transfer.

Private-Radicle recovery and SFTP overflow are optional Control profiles.
Neither is a prerequisite for Comms or baseline Control conformance.

<a id="comms-authorization-freshness"></a>
### 9.2 Authorization-view freshness

This bound governs every Comms-derived authorization decision and every
document that composes one; no other document restates it.

Token minting and every privileged use require an authenticated,
non-conflicted private authorization view no more than 300 seconds old. A
mutation additionally performs an immediate synchronization attempt against
the canonical private ledger before authorizing, and fails closed unless it
establishes that fresh view. A fresh token cannot extend a stale authorization
view. A composing document or a local policy MAY shorten the window and MUST
NOT lengthen it.

<a id="comms-key-claims"></a>
## 10. Atomic typed-key claims

Comms defines an atomic assertion about one typed key. The registry assigns
`kind:31013` to `heterodyne-comms-key-claim-v1` and `kind:31014` to
`heterodyne-comms-key-claim-revocation-v1`. Both are addressable events. Their
sole `d` tag is the lowercase 64-hex claim identifier, and their JSON content
uses the single `heterodyne/0.5.0` owner stamp. The outer Nostr signer MUST be the
`nostr-secp256k1` issuer named by the claim. A verifier MUST reject missing,
duplicate, unknown, or misordered members and tags, an event/content mismatch,
an unknown profile discriminator, or an event whose BIP-340 signature fails.

The registered non-stamping production profiles and discriminators are exact:

| Use | Profile | Discriminator |
|---|---|---|
| claim Nostr proof | `heterodyne-comms-key-claim-nostr-bip340-v1` | `production-rule:claim-subject-pop;proof=nostr-bip340-v1` |
| claim Radicle proof | `heterodyne-comms-key-claim-radicle-ed25519-v1` | `production-rule:claim-subject-pop;proof=radicle-ed25519-v1` |
| claim JWK proof | `heterodyne-comms-key-claim-jwk-jws-v1` | `production-rule:claim-subject-pop;proof=jwk-jws-v1` |
| revocation Nostr proof | `heterodyne-comms-claim-revocation-nostr-bip340-v1` | `production-rule:claim-revoker;proof=nostr-bip340-v1` |
| revocation Radicle proof | `heterodyne-comms-claim-revocation-radicle-ed25519-v1` | `production-rule:claim-revoker;proof=radicle-ed25519-v1` |
| revocation JWK proof | `heterodyne-comms-claim-revocation-jwk-jws-v1` | `production-rule:claim-revoker;proof=jwk-jws-v1` |

These profiles change no signed event bytes and add no second version stamp.

For both v1 content schemas, the signed wire member `profile_revision` is
exactly `2`: the registry entry set that allocated the v1 profile
discriminators and reason-code vocabulary. It is frozen semantic content and
does not float when unrelated registry entries are added, which is why it is
named distinctly from the specification's registry pin in
[`registry/manifest.json`](registry/manifest.json). A verifier MUST reject a
v1 claim or revocation whose `profile_revision` is not `2`. Changing the
member requires a new claim profile version.

The `heterodyne-comms-key-claim-v1` content is the exact closed object defined
by `schemas/comms/key-claim-v1.schema.json`. Its required members are
`claim_id`, `issuer`, `subject`, `claim_class`,
`credential_ledger_persona`, `credential_ledger_generation`, `namespace`,
`name`, `value`, `issued_at`, `not_before`, `visibility`, `spec_version`, and
`profile_revision`. Optional members are `expires_at`, `audience`, `resources`,
`parent_claim_id`, `constraints`, and `revokers`. For an `authorization`
claim the credential-ledger persona is 64 lowercase hex and the generation is
a JSON-safe nonnegative integer; for a `descriptive` claim both are exactly
JSON `null`. `claim_class` is `descriptive` or `authorization`; `visibility` is `public`,
`pairwise-private`, `repository-private`, or `local-only`. `issuer`, `subject`,
and every explicit revoker use Core's canonical `nostr-secp256k1`,
`radicle-ed25519-nid`, or `jwk-thumbprint` reference. Sets are duplicate-free,
lexicographically sorted arrays.

Every claim contains exactly one `(namespace, name, value)` assertion, where
`value` is one atomic JSON value. `claim_id` is lowercase hexadecimal SHA-256
over RFC 8785 JCS bytes of the complete semantic object with only `claim_id`
omitted. Tags, transport, event id, and signatures are excluded. Reusing an
address is permitted only for a byte-identical canonical semantic object.
Selective release selects whole atomic signed claims. Comms 0.5.0 MUST NOT
perform SD-JWT disclosure. It MUST NOT automatically bundle multiple claim names
into one signed claim.

Visibility selects one exact carrier for the complete atomic object; a claim is
never split between carriers:

- `public` claims are complete signed events published through ordinary relays
  and, when the persona republishes them, its public profile repository.
- `pairwise-private` claims carry the full atomic signed claim only as a
  protected application event in an authenticated two-member Marmot group.
  The outer event exposes no claim ID, namespace, name, value, or visibility
  metadata. Retention follows the group's declared policy.
- `repository-private` claims appear only in the encrypted private claim ledger
  described by §11; repository paths, commit metadata, and object
  sizes MUST NOT reveal their semantics.
- `local-only` claims produce no protocol artifact: no Nostr or Marmot event,
  repository object, OIDC release, or other network carrier.

An implementation MUST NOT perform cross-visibility fallback or downgrade when
the selected carrier is unavailable. An unknown visibility value MUST cause the
whole claim to be rejected. Acceptance, storage, forwarding, and release are
atomic for the whole signed claim; partial member delivery is prohibited.

<a id="comms-claim-verification"></a>
### 10.1 Verification, trust, proof of possession, and state

Verification is ordered and fail-closed:

1. validate the closed JSON schema, owner version, profile revision, typed
   references, canonical claim ID, address, exact NIP-01 bytes, event ID, and
   outer signature;
2. require a `valid` Core/KEL authority result for the issuer at `issued_at`;
3. resolve and validate the complete chain in §10.2;
4. enforce time, audience, resource, namespace, operation, and subject-type
   constraints;
5. replay repository-confirmed canonical private-ledger state, revocations,
   and all reductions in §§10.3 and 11;
6. for authorization, verify a fresh native subject proof;
7. only after those checks, apply local trusted-issuer, trusted-namespace, and
   release policy; and
8. return exactly one state: `invalid`, `untrusted`, `provisional`, `active`,
   `expired`, `revoked`, or `conflicted`.

Cryptographic validity is not trust. `untrusted` content MAY be displayed with
its provenance but MUST NOT authorize. A delivered persona-issued device grant
is `provisional` until repository-confirmed. Only `active` authorizes.

The proof-of-possession challenge is the
[`heterodyne:0.5.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes) construction for domain
`heterodyne-claim-pop-v1`, whose claim binds `claim_id`, `nonce`, `audience`,
`resource`, `operation`, `issued_at`, and `expires_at`. It MUST be fresh, single-use, audience- and
operation-bound, and verified by Core's native suite for the subject type:
BIP-340, Ed25519 with exact NID binding, or JWS with an RFC 7638-matching JWK.
An authorization claim without valid fresh subject proof is inactive. An
event signature or an earlier possession proof MUST NOT substitute for it.

<a id="comms-claim-chain"></a>
### 10.2 Issuance chains and attenuation

A non-root claim names exactly one `parent_claim_id`. Its parent MUST be an
active authorization claim giving the child issuer explicit claim-issuance
authority. Resolution proceeds to an unparented trusted root, detects cycles,
and permits at most eight issuance edges. An eighth-edge claim may authorize
within its scope but its `remaining_depth` is zero and it cannot issue a ninth.

At every edge the child MUST preserve or narrow all of: namespace prefixes,
claim name, audiences, resources, purpose/operation, `not_before`,
`expires_at`, subject type, and visibility. `remaining_depth` MUST equal its
parent's value minus one. It MUST NOT start earlier, expire later, add an
audience or resource, broaden a namespace or purpose, change a descriptive
assertion into authorization, or gain redelegation implicitly. A child MAY
preserve both temporal bounds when every other authority dimension is
preserved or narrowed and the required depth decrement occurs; strict change
to a time bound is not independently required. Missing ancestors, ambiguity,
cycles, depth overflow, broadening, or an incorrect depth transition makes the
leaf `invalid`.

<a id="comms-claim-revocation"></a>
### 10.3 Irreversible revocation and reductions

The revocation content is the exact closed object in
`schemas/comms/key-claim-revocation-v1.schema.json`: `claim_id`, `revoked_at`,
registered `reason_code`, typed `revoker`, required `spec_version` equal to
`heterodyne/0.5.0`, required `profile_revision` equal to `2`, and an optional native
`proof`. `revoked_at` equals the event `created_at`. For both `kind:31013` and
`kind:31014`, the complete tag array MUST be exactly
`[["d","<claim_id>"]]`; an extra, duplicate, malformed, or differently ordered
tag is invalid. A Nostr revoker signs the outer event. A Radicle or JWK revoker
also supplies its matching [`heterodyne:0.5.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes) proof for
domain `heterodyne-claim-revocation-v1`, whose claim binds `claim_id`,
`profile_revision`, `reason_code`, `revoked_at`, and `spec_version`. Thus the
native proof binds the owning Comms profile revision as well as the
revocation.

An authorization claim may be revoked by its issuer, an active superior issuer
in its verified chain, current persona epoch or cold-root authority, or its
subject. Subject revocation is self-reduction only. A descriptive claim may be
revoked only by its issuer, an explicitly listed revoker, or a superior issuer;
its subject may separately reject the assertion but cannot erase it.

Valid direct revocation, ancestor or issuer-authority revocation, KEL/key
revocation, reader or token-issuer reduction, signing-key compromise, and
derived-token invalidation are cumulative. A valid reduction is permanent,
takes effect immediately when authenticated, and is later made repository-
final. Revocation wins concurrent merges. Renewal or correction creates a new
claim ID; no later grant or `VALID` token bit resurrects the old authority.

<a id="comms-claim-ledger"></a>
## 11. Authoritative private persona claim ledger

Each persona has one private Radicle repository shared by all authorized
devices and nodes. Its canonical `main` is authoritative for persona-issued
device claims, revocations, reader and issuer authority, consent, issuance
reservations, status invalidations, and separately wrapped signing-key state.
The repository is encrypted under the Comms repository-encryption profile and
MUST NOT expose claim type, subject, or revocation count through path names or
object sizes. Fixed-size encrypted entries and padded snapshots are used; keys,
plaintext claims, consent, issuance mappings, and membership never appear in
the public persona repository.

The append-only plaintext record schema is
`schemas/comms/claim-ledger-record-v1.schema.json`. It has exactly
`record_id`, `record_type`, `persona`, `credential_ledger_generation`,
`writer_nid`, `created_at`, `parents`, `payload`, `payload_digest`, and
Ed25519 `signature`. `persona` and `credential_ledger_generation` bind every
record, including retained prior-generation audit records, to one exact
ledger generation. Record types are `claim`, `revocation`,
`authority-reduction`, `reader-change`, `audience-key-epoch`,
`issuer-authority`, `issuance-reservation`, and `status-invalidation`.
`payload_digest` and `record_id` are domain-separated JCS SHA-256 digests. The
writer signature and current Core NID delegation MUST verify before replay.

Canonical replay verifies commits and parents from genesis, rejects rollback
or missing history, validates each embedded event and issuance object, and
derives a checkpoint `(repository_rid, main, commit_oid, observed_at)`. Claims
and reservations merge by immutable ID. Revocation and authority reduction are
monotonic and win. Concurrent incompatible policy changes remain `conflicted`
and fail closed; wall-clock or writer order MUST NOT resolve them.

Direct fetch, replication, and decryption require an `active`, durable,
NID-bearing `claim-ledger-reader` authorization. Onboarding uses private
Radicle plus an authorized pairwise Control group for small wrapped records.
It binds the claim record, repository RID, canonical checkpoint, current
audience-key epoch and wrap, compact-state digest, and Radicle fetch-and-seed
access. The recipient verifies all bindings before use. A delivered claim not
reachable from canonical state remains provisional.

The dedicated ledger audience key is a second
[`heterodyne:0.5.0#core-key-envelope`](heterodyne-core.md#core-key-envelope)
instantiation. Its five choices are: the recipient set is the `active`
`claim-ledger-reader` authorizations; the reference and wrapping profile are
`radicle-ed25519-nid` and `heterodyne-claim-ledger-key-wrap-v1`; the carrier is
the private repository; the generation identifier is a `key_id`; and the
extra rotation trigger is `none`. Reader removal is the Core removal rotation
with three Comms additions performed in order: record the authority reduction,
remove Radicle access, and, after the rotation, advance the checkpoint and
retire prior ciphertext under the cooperative scrub profile.

<a id="comms-multiwriter-minting"></a>
### 11.1 Multi-writer minting and issuer-key confinement

The repository is multi-writer. An online node is not excluded because another
authorized writer can mint. A node may mint for the persona only when it has
all three of: a separately envelope-encrypted usable signing JWK, an `active`
`oidc-token-issuer` claim, and a canonical checkpoint whose age is within the
continuity manifest bound. That bound MUST NOT exceed the window in
[§9.2](#comms-authorization-freshness). Loss or reduction of any condition
stops minting immediately.

The signing key MUST NOT be encrypted by or released merely with the ledger
audience key. It is a third
[`heterodyne:0.5.0#core-key-envelope`](heterodyne-core.md#core-key-envelope)
instantiation. Its five choices are: the recipient set is the NIDs holding
active `oidc-token-issuer` authority; the reference and wrapping profile are
`radicle-ed25519-nid` and `heterodyne-oidc-issuer-key-wrap-v1`; the carrier is
the private repository; the generation identifier is a monotonic `key_epoch`
scoped to the stable `credential_ledger_persona` identifier; and the extra
rotation triggers are routine issuer-signing-key rotation and shared-key
compromise. Beyond the members Core requires, its envelope binds the
credential-ledger generation, the JWK thumbprint, and the exact active
issuer-authority record set. Removing an issuer is the Core removal rotation.
A node MUST unwrap only after replaying the exact bound authority set,
generation, and checkpoint.

Before returning a JWT, a writer durably commits an issuance reservation with
credential-ledger generation, `jti`, client and request/release digests,
signing-key ID, source claim IDs, checkpoint, expiration, and the status
allocation defined in §14. The enclosing claim-ledger record supplies the
exact persona binding. Returning a token before that reservation is canonical
is prohibited. Shared-key compromise invalidates outstanding tokens, rotates
signing material, updates the public key set, and advances affected status
lists.

<a id="comms-oidc-endpoints"></a>
## 12. OIDC/OAuth issuer and endpoints

Sections 12 through 14 are `comms.oidc-jwt-projection.v1` and its dependent
`comms.token-status-list-draft-21.v1`. They are optional: they exist so an
ordinary third-party relying party can verify a persona's assertions through
standard discovery, and an implementation that projects nothing to third
parties omits them entirely. The prerequisite chain in
[`registry/features.json`](registry/features.json) fixes who must ship them.

A persona has one exact HTTPS issuer:

```text
https://<host>/oidc/<persona-npub>
```

The final path component is the canonical NIP-19 encoding of the persona's
active Nostr key. No cold root, KEL, or optional Assurance state is required.
A host may serve many isolated personas at disjoint active-key paths. Every
trusted serving node exposes current and retiring public keys for each persona
it serves, including keys minted elsewhere.

The OIDC configuration is at `<issuer>/.well-known/openid-configuration`, the
RFC 8414 alias is
`https://<host>/.well-known/oauth-authorization-server/oidc/<persona-npub>`,
and JWKS is at `<issuer>/.well-known/jwks.json`. Metadata uses that exact issuer
and advertises `<issuer>/authorize`, `<issuer>/token`, and
`<issuer>/device_authorization`. Issuer comparison is exact. Redirects,
aliases, case folding, a host change, or a different persona-key path do not silently
change issuer identity.

The closed metadata schema is
`schemas/comms/oidc-issuer-metadata-v1.schema.json`: response type `code`, grant
types `authorization_code` and the RFC 8628 device-code URN, PKCE method `S256`,
pairwise subjects, and mandatory `RS256`. JWKS contains public JWKs only; each
`kid` is its RFC 7638 thumbprint. Unknown required metadata or a mismatch with
the canonical Radicle mirror fails closed.

<a id="comms-oidc-authorization"></a>
### 12.1 Authorization, clients, consent, and release

Authorization Code with PKCE S256 and OAuth Device Authorization are REQUIRED.
Clients MUST be explicitly registered with exact redirect URIs, allowed
audiences, scopes, assertion profiles, and pairwise sector. Implicit,
Resource Owner Password Credentials, and Client Credentials grants are
prohibited. Client Credentials is reserved for a future sender-constrained
workload profile and never authenticates a persona.

Registration and consent are active authorization claims in the private
ledger, not mutable server-local records. A registration uses namespace
`heterodyne.oidc`, name `client-registration` (the combined claim name is
`heterodyne.oidc/client-registration`), visibility `repository-private`, and a
closed object value with exactly `client_id`, `redirect_uris`, `grant_types`,
`scopes`, `audiences`, `claims`, `assertion_profiles`, and `sector_identifier`.
Every array is a duplicate-free array of non-empty strings. Every redirect URI
and audience is an exact HTTPS resource with no query or fragment. The
`sector_identifier` is an exact serialized HTTPS origin: it has no credentials,
path, query, fragment, case-folded alias, or alternate default-port spelling.

A consent claim uses namespace `heterodyne.oidc`, name `consent` (the combined
claim name is `heterodyne.oidc/consent`), visibility `repository-private`, and a
closed object value with exactly `client_id`, `scopes`, `audiences`, `claims`,
and `source_claim_ids`. Its arrays are duplicate-free and contain non-empty
strings; each source claim ID is lowercase 64-hex. Registration, consent, and
every released source claim MUST use the same exact typed-key subject and be
repository-private. Registration and consent are keyed for replay by the exact
typed-key subject plus `client_id`; their immutable claim IDs and signed ledger
record IDs provide canonical identity. In the multi-writer repository,
concurrent non-identical registration or consent values for that key conflict
and fail closed. Neither wall-clock order nor writer preference selects one;
only canonical state containing one compatible active value authorizes.

Authorization codes are short-lived, single-use, client- and redirect-bound,
and require an exact PKCE verifier. Both the authorization-code transaction
and its redemption bind the exact `credential_ledger_persona` and
`credential_ledger_generation`. Device codes are client-bound, bind the same
exact ledger tuple, expire, enforce polling intervals and `slow_down`, require
an explicit approve/deny decision, and are single-use. Authentication,
consent, generation, and repository state MUST be rechecked before token
return; a reduction or generation change observed after initial approval
wins. An accepted emergency reset purges every prior-generation pending code
transaction rather than treating it as generation zero.

Release is the intersection of requested scope and audience, registered client
policy, explicit consent, trusted namespaces, active canonical repository
state, and current proof requirements. Any absent input denies the claim. `sub`
is pairwise by default. Stable key release additionally requires scope
`heterodyne:key-ref` and explicit consent, and appears only as
`https://heterodyne.network/jwt/key-ref`. A client MUST NOT infer unreleased
claims, correlate pairwise subjects across sectors, or treat a descriptive
claim as authority.

`local-subject` is exactly 64 lowercase hexadecimal characters encoding
SHA-256 over the RFC 8785 JCS bytes of the exact typed-key subject. The
pairwise identifier uses HMAC-SHA-256 under the persona's repository-private
pairwise secret over the UTF-8 string
`heterodyne-oidc-pairwise-sub-v1\0<exact-sector-origin>\0<local-subject>`, where
each `\0` is one NUL octet and `<local-subject>` is those exact 64 UTF-8 hex
characters between the separators. The 32-byte HMAC output is encoded as
unpadded base64url. The sector is the registration's exact HTTPS origin under
the rules above. Nodes sharing the same authoritative private repository state
and pairwise secret therefore produce an identifier stable across nodes
for the same subject and sector, while different sectors remain unlinkable by
the relying parties.

<a id="comms-jwt-projection"></a>
### 12.2 Interoperable JWT projection

Authorized nodes may issue OIDC ID Tokens, RFC 9068 JWT access tokens, and
separately registered signed JWT assertions. RS256 support is REQUIRED so an
ordinary third party can validate through HTTPS discovery and JWKS; ES256 or
EdDSA MAY be separately advertised in a later compatible profile. The issuer,
key, type, audience, signature, time, nonce when applicable, client, and sender
constraint MUST all be checked before claim use.

Every protected header in this profile has exactly `alg`, `kid`, and `typ`.
`alg` is `RS256`; `kid` is the canonical RFC 7638 thumbprint of exactly one
public RSA signing JWK in the issuer JWKS; and the RSA modulus is at least 2048
bits. An ID Token has `typ` equal to `JWT`, requires a non-empty nonce from the
signed authorization request, returns that exact `nonce` claim, and is valid
only when both the presented claim and the verifier's expected nonce are
non-empty and exactly equal. An absent or empty request nonce MUST prevent ID
Token issuance rather than producing a token without one. A signed JWT
assertion has `typ` equal to `heterodyne-assertion+jwt` and an
`assertion_profile` claim whose exact non-empty value was allowed by the
client's signed canonical registration and equals the verifier-selected
registered profile. An unregistered profile, absent or empty nonce, or
type/profile/nonce confusion is rejected.

An access-token protected header has `typ` equal to `at+jwt` and `alg` equal to
`RS256`. Its claims include `iss`, pairwise `sub`, `aud`, `exp`, `iat`, `jti`,
`client_id`, normalized `scope`, `credential_ledger_persona`, and
`credential_ledger_generation`, plus:

- `https://heterodyne.network/jwt/ledger-checkpoint`, binding the canonical
  private RID, `main`, commit and observation time;
- `https://heterodyne.network/jwt/status-mirror`, binding the public Radicle
  RID, `main`, manifest path and SHA-256 digest; and
- the draft-21 `status.status_list` reference from §14.

ID Tokens and registered signed JWT assertions carry the same exact
credential-ledger tuple. An ID Token additionally enforces OIDC token-type and
nonce rules and MUST NOT be accepted where an access token is required. A
projected JWT is an assertion derived from current active claims, not a
canonical encoding of the source event. DPoP under RFC 9449 or mutual-TLS under
RFC 8705 SHOULD bind access tokens when supported. A DPoP-bound token's `cnf`
is an exact one-member object containing only canonical 32-byte base64url
`jkt`; a mutual-TLS-bound token's `cnf` is an exact one-member object containing
only canonical 32-byte base64url `x5t#S256`. A bearer token has no `cnf`. The
verifier requires exact equality with its expected confirmation and rejects
missing, extra, mixed, or method-confused members. A `cnf` claim MUST NOT be
ignored by a bearer-only consumer.

<a id="comms-issuer-continuity"></a>
## 13. Radicle issuer continuity

Canonical `main` in the public persona profile repository simultaneously
publishes:

```text
.well-known/<persona-npub>/
  issuer.json
  openid-configuration
  jwks.json
  manifest.json
  status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

The exact manifest schema is
`schemas/comms/oidc-continuity-manifest-v1.schema.json`. It binds profile,
public RID, `main`, the active persona npub and raw key, exact issuer, monotonic
sequence and predecessor digest, checkpoint-age bound, current and retiring
key IDs/JWK digests, all status paths/URIs/digests, optional successor, and an
active NID writer/checkpoint. `persona_npub` MUST be the canonical NIP-19
encoding of `persona_key`, and the issuer's final component MUST equal that
npub. Its Ed25519 authority proof and that writer's current ledger authority
for the same active persona MUST verify. HTTPS and repository metadata, JWKS,
and Status List Token bytes MUST be identical. Optional Assurance state is not
an input to baseline manifest validity.

The manifest authority proof `issued_at` MUST be greater than or equal to its
exact canonical ledger checkpoint's `observed_at` and MUST NOT be later than
the verification time. The named writer authorization and its current Core NID
proof are evaluated at that `issued_at`, not at fetch time. The verifier
requires the exact active persona, writer NID, ledger generation, canonical
checkpoint, sequence, and predecessor digest. A change of active persona key
creates a different issuer identity; it cannot be accepted as a same-issuer
manifest update or justified by a KEL alias.

The `jwks.json` input is hashed as raw closed JWKS bytes, and that SHA-256 MUST
equal `current_jwks_sha256`; parsing or reserialization does not substitute for
the raw-byte check. The object has exactly `keys`. Each member is a closed
public RS256 signing JWK whose `kid` is its RFC 7638 thumbprint and whose role is
bound exactly by the manifest: one `current_signing_key_id` and the complete
duplicate-free `retiring_signing_key_ids` set, with matching current and
retiring JWK digests. Extra keys, missing keys, role swaps, or digest mismatch
fail closed.

Every confirmed unexpired issuance in canonical private-ledger state requires
transitive retention through the continuity chain of its uncompromised signing
key and status path. The current manifest MUST name that key as current or
retiring and MUST name the status path; the current public tree MUST contain
digest-matching, signature-valid, currently usable bytes for that path. Each
retained entry in a predecessor chain preserves its original issuer and URI;
changing either destroys provenance. Once a predecessor announces and binds a
successor, the old issuer MUST NOT make a new issuance or publish a later
same-issuer candidate. The successor is accepted only through the exact
sequence, predecessor digest, successor issuer, successor manifest commitment,
and persona-authority proof.

Routine rotation promotes a new current key while retaining the old public key
and its status bytes until every token it signed expires. Compromise handling
is different: the compromised key is removed from current and retiring trust,
all outstanding affected tokens receive `INVALID` status, and each affected
list is published as an INVALID replacement signed by the new current key.
Retention MUST NOT keep a compromised key trusted merely to verify the old
list.

The Radicle manifest is authoritative for Heterodyne continuity when the HTTPS
node is unavailable. A successor requires an unbroken predecessor chain plus
explicit authorization in current private persona state and an exact binding
to the new manifest. Optional Assurance MAY provide additional continuity
evidence but cannot alias the issuers. Heterodyne-aware resolution may then
find the new URL through canonical `main`; ordinary OIDC clients still require
normal trust or registration for the new issuer. A fork, rollback, persona-key
mismatch, unauthorized successor, digest mismatch, or disagreement between
HTTPS and Radicle fails closed. Public continuity contains no private claim,
consent, reader, issuance mapping, or secret key.

<a id="comms-token-status"></a>
## 14. Token status profile

Comms 0.5.0 freezes the complete behavior used from
`draft-ietf-oauth-status-list-21`; later drafts do not change this profile.
Each projected JWT contains `status.status_list` with an HTTPS `uri` and
non-negative `idx`. That URI returns a distinct compact Status List Token with
media type `application/statuslist+jwt`, protected `typ` `statuslist+jwt`,
`alg` `RS256`, and an authenticated `kid`. Claims are `sub` equal to the URI, `iat`,
`exp`, positive finite `ttl`, `credential_ledger_persona`,
`credential_ledger_generation`, and `status_list` with `bits: 1` and `lst`.

`lst` is the unpadded base64url encoding of a valid zlib-wrapped DEFLATE
representation of the bit array. Producers SHOULD use deterministic level-9
compression as the stable recommended encoding. Consumers MUST accept any
valid signed zlib-wrapped DEFLATE representation that inflates to the
authenticated bit array and MUST NOT require local recompression to reproduce
the received bytes. The inflated bit array MUST NOT exceed 1,048,576 bytes
(8,388,608 statuses); a larger result MUST be rejected. Bits are little-endian
within each byte. Initial values are `0` (`VALID`) and `1` (`INVALID`). Indices
are contiguous within a list, never reused, and allocated only in a durable
issuance reservation at:

```text
status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

The fingerprint is the first 16 bytes of the writer NID's SHA-256 digest as 32
lowercase hexadecimal characters. Writer namespaces avoid central allocation;
concurrent writers cannot share a namespace. Canonical replay rejects duplicate
`(uri, idx)` or `jti` allocation. Authorized writers regenerate merged lists
with invalidation-wins semantics.

A verifier validates the referenced JWT first, resolves the continuity chain,
checks byte digest and URI against the current manifest, verifies the Status
List Token with current/retiring JWKS, enforces `iat`, `exp`, `ttl`, checkpoint,
media type, valid bounded zlib decompression, bit width, and index bounds, then
reads the bit. Stale, missing, malformed, unverifiable, or mismatched status is
failure, not evidence of validity. `VALID` cannot override expiration,
audience/type failure, source-claim reduction, issuer compromise, or any other
invalid state.

Status `iat` MUST be a safe integer no earlier than the current manifest checkpoint's
`observed_at` and no later than `now`. The verifier records a
trusted `resolved_at` for the authenticated fetch; it rejects a future
resolution time and defines staleness exactly as `resolved_at + ttl < now`, so
equality is fresh. `ttl` is a finite positive JSON number. `exp` is a separate
safe-integer token-lifetime condition and MUST be later than `now`; satisfying
one freshness condition never satisfies the other.

A retained Status List Token may authenticate with an exact retiring key from
the raw JWKS bound by the current manifest. Newly generated Status List Tokens
MUST use the current canonical issuer key from validated private-ledger state.
This permits routine historical verification without allowing a retired writer
to produce new status bytes.

<a id="comms-agent-authorship"></a>
## 15. Agent authorship and workload authorization

An **automated principal** is an AI or other programmatic workload acting
through an agentic authenticated session. Every publication requested by that
principal is agent-authored, including output that a human reviews or approves
before publication. Automated principals MUST use the scoped workload-token
and intent-publication path below. They MUST refuse instructions to obtain a
private key, request raw signing, remove or falsify attribution, impersonate a
human author, or bypass token, proof, signer, scope, resource, rate, or size
enforcement.

This is a conformance rule for the execution path. It does not make a valid
Nostr signature invalid merely because a non-conforming private implementation
misclassified its source, and it cannot detect agent text manually copied into
a human client.

<a id="comms-agent-signer-selection"></a>
### 15.1 Signer selection and Nostr authorship

An independent agent key is the preferred default signer. It is an ordinary
Nostr author and its public key appears unchanged in the event's `pubkey`.
Separately governed automation MAY use different agent keys or public role
names. A private agent key MUST remain inside its selected signer and MUST NOT
be released to the workload, token, tool result, configuration export, audit
record, or public event.

A persona key MAY sign an automated publication only when the exact active
OIDC authorization contains scope `heterodyne:agent:sign:persona`. General
publication authority, a NIP-46 connection, client metadata, a human approval,
or an agent-publication scope without that exact additional scope is
insufficient. Implementations SHOULD present the agent-key mode first and MUST
NOT silently fall back from an unavailable agent key to the persona key.

Nostr authorship is never virtualized. The selected signing key is the
event's actual `pubkey`, and normal NIP-01 ID and BIP-340 verification are
authoritative. A Heterodyne association can explain that an agent key or role
is related to a persona-signed event; it cannot replace, alias, or override the
signer.

<a id="comms-agent-workload"></a>
### 15.2 Private workload registration and stable identity

The canonical private claim ledger MUST carry an active
`heterodyne.agent` / `workload-registration` authorization claim. Its value
MUST validate against
`docs/spec/schemas/comms/agent-workload-registration-v1.schema.json` and is
closed. It binds the exact active `persona_key`, `client_id`, subject JWK
thumbprint and DPoP proof method, `ai` or `programmatic` class, one
`selected_signer`, its `agent` or `persona` key class, one audience, non-empty
OIDC scopes, allowed event kinds, feeds and resources, maximum content bytes,
finite positive rate window/count/burst, validity interval, and an optional
descriptive software-claim reference. It MAY bind exactly one closed public
`agent_association` object whose `kind` is `key` or `role` and whose `value` is
respectively one 32-byte lowercase-hex Nostr key or a non-empty public role of
at most 128 characters. For key class `persona`,
`selected_signer` MUST equal `persona_key` and the exact persona-signing scope
is required. Empty or unlimited kind, resource, size, rate, or burst authority
is invalid.

The OIDC client registration, explicit consent, and workload registration MUST
all be active, repository-confirmed, subject-identical, and mutually
compatible. The workload proves possession of the registered JWK. Its
mandatory public identity is the tuple:

```text
(exact issuer, persona-scoped pairwise sub, client_id)
```

The `sub` MUST use the §12.1 pairwise-subject derivation with the exact sector
origin and persona-private pairwise secret. The tuple remains stable across
temporary-token renewals for one registration; distinct persona secrets
prevent the same workload JWK from producing a correlatable subject across
personas. An optional software, vendor, model, or pipeline claim is descriptive
only and grants no authority. The tuple, subject proof, client ID, token ID,
and private registration are authorization inputs and are not public
attribution fields.

<a id="comms-agent-token"></a>
### 15.3 Third-party OIDC workload projection

When `comms.oidc-jwt-projection.v1` is enabled, an authorized issuer MAY
project an active workload registration to an ordinary third-party resource
server as the RFC 9068 access token defined by §12.2. This is an interoperable
projection of private-ledger authority, not a node-local command credential.
In addition to the generic §12.2 claims, it carries
private Heterodyne claims for the exact selected signer, signer key class, and
optional association kind and value. Its exact `aud` and normalized `scope`
MUST be allowed by that workload registration and the compatible client
registration and consent. A persona-key token MUST contain the exact
`heterodyne:agent:sign:persona` scope; the verifier MUST NOT infer it from the
selected signer or any other claim.

If the client registration selects sender constraint, the token uses only the
standard DPoP or mutual-TLS confirmation form defined by §12.2. Its validity
MUST NOT outlive the workload registration, consent, source authorization, or
the issuer's applicable third-party token policy. Before claim use, a resource
server validates the complete §12.2 type, issuer, audience, signature, time,
client, scope, confirmation, checkpoint, status, and source-claim contract,
plus exact equality between the projected signer, key class, optional public
association kind/value, and current registration. Absence is also exact: a
token and registration MUST either both omit the association or both carry the
same kind and value. A null, scalar, array, partial object, or otherwise
malformed association claim fails closed with `agent-signer-mismatch` before
its fields are used; a verifier MUST NOT coerce or partially accept it.
A projected JWT never replaces canonical private-ledger state. Client
Credentials remains prohibited; a separately integrated sender-constrained
HTTPS workload profile is required before that grant can be added.

An internal Social publication boundary MUST atomically validate, attribute,
sign, and verify; it MUST NOT split those actions across caller-consumable
pre-sign and post-sign capability producers. The embedding supplies a trusted
clock and a durable execute-once signer capability. Comms samples that clock
once, then validates the represented persona, actual signer and optional
association, event kind and time, publication scope, exact requested feed and
resource, every immutable registration and token/grant identity or version
member, current ledger/status state, and all validity bounds. Trusted current
time is distinct from event `created_at`: both MUST satisfy their applicable
bounds, but they need not be equal. The registration audience MUST equal the
token's sole audience, its subject thumbprint/proof MUST equal both token
confirmation and validated sender proof, and each destination MUST occur in
its matching registration allow list.

The embedding constructs one publication-authority instance and captures the
trusted-clock function and a bound `executeOnce` function at that moment.
Later replacement of a method on the caller's signer object has no effect.
Every signed-publication proof is branded to the exact authority instance that
issued it. A Social consumer MUST be constructed with its expected authority
and MUST reject a proof from every other instance, including an attacker-
created instance using a backdated clock. There is no authority-agnostic proof
consumer.

Only after that final current-state check may Comms remove caller attribution,
inject the canonical block below, deep-copy and freeze the resulting unsigned
event, and pass those exact bytes to the embedding-owned `executeOnce`
boundary. It MUST strict-verify the returned NIP-01 id/signature and exact
equality with that immutable snapshot before returning the event and a
module-authenticated one-use signed-publication proof. No API may accept an
already signed event, strip `id`/`sig`, and mint that proof. Social burns the
proof against the exact signed event, persona, signer, association, and
destination without rechecking mutable grant state. Thus stale or revoked
state at the final pre-sign check prevents signing, while revocation after an
event was genuinely signed does not retroactively invalidate it. A plain or
reconstructed object grants no authority. The proof is not a wire object and
MUST NOT be serialized into the event.

The execute-once result is untrusted input. Comms reads each source node's own
property descriptors once, requires a closed ordinary object/array tree made
only of data descriptors, and rejects accessors, symbols, sparse arrays, and
unexpected members. A runtime that cannot generally prove proxy absence MUST
not claim that it did; any proxy may participate only in that single descriptor
capture. Comms then constructs and freezes one independent plain-data snapshot
and never reads the source again. Strict validation, equality comparison,
proof storage, and the returned event MUST all use that same snapshot. A result
cannot expose one event for validation and another for return.

<a id="comms-agent-attribution"></a>
### 15.4 Mandatory pre-sign attribution

An agent supplies intent content, kind, destination/feed, and permitted
options. It does not supply a signature or authoritative attribution identity.
The full node removes every caller-supplied reserved agent-attribution field,
then inserts this NIP-32-compatible block in exact relative order:

```text
["L", "network.heterodyne.agent"]
["l", "ai" | "programmatic", "network.heterodyne.agent"]
```

When the exact token/registration association carries a public kind and value,
the signer MUST append exactly one corresponding Heterodyne tag after the
NIP-32 block:

```text
["heterodyne_agent", "v1", "key", "<agent-key>"]
["heterodyne_agent", "v1", "role", "<public-role>"]
```

The association is optional and descriptive. It MUST NOT contain an issuer,
OIDC subject, client ID, token ID, claim ID, audit ID, private role record, or
other non-public authorization identifier. The closed registration carries at
most one association; it cannot publish both key and role forms.

Before injection, the signer MUST compare both presence and exact
`agent_association.kind`/`agent_association.value` equality between verified
token identity and current registration. A mismatch fails with
`agent-signer-mismatch`; the signer MUST NOT select one source, coerce a role
to a key, or infer an association from the selected signer.

The signer then appends `["agent_action","publish"]` immediately after the
association, or immediately after the NIP-32 block when no association is
present. Thus association-bearing events retain the registry's existing
`L`, `l`, `heterodyne_agent`, `agent_action` relative order while the
association itself remains optional.

It MAY append `["agent_review","<verified-review-reference>"]` only after
independent verification. Review never changes the automated classification.
All injection and validation MUST finish while the event is unsigned. The
signer then constructs the final NIP-01 ID and signs exactly once with the
selected key before applying ordinary §4 publication and §5 indexing. A
caller-supplied event ID or signature at the injection boundary is invalid.

The registry activates the mandatory automation label for these non-stamping
profiles:

- `heterodyne-comms-agent-attribution-kind-1-v1`;
- `heterodyne-comms-agent-attribution-kind-6-v1`;
- `heterodyne-comms-agent-attribution-kind-7-v1`;
- `heterodyne-comms-agent-attribution-kind-16-v1`;
- `heterodyne-comms-agent-attribution-kind-1063-v1`;
- `heterodyne-comms-agent-attribution-kind-1985-v1`;
- `heterodyne-comms-agent-attribution-kind-4550-v1`; and
- `heterodyne-comms-agent-attribution-kind-30023-v1`.

These cover notes, articles, replies, reactions, reposts, media, and
moderation actions represented by those kinds. A kind without an active
profile MUST fail with `agent-attribution-profile-unavailable`; it MUST NOT
fall back to an unlabeled or human event. Deterministic Assurance,
token-status, relay-metadata, and equivalent maintenance events are
not agent-authored application publications.

All eight entries use discriminator
`production-rule:agent-attribution-v1`. That rule admits exactly the canonical
NIP-32 block followed directly by `agent_action`, or the same block with one
canonical `heterodyne_agent` association immediately before `agent_action`.
Neither form makes the association mandatory or permits it in another order.

Tier 1 carries the block publicly. Tier 2 carries it inside the private
repository trust boundary. Tier 3 carries the same block only inside the
encrypted logical event and adds no agent marker to the clear wrapper. A
verifier MUST require the event `pubkey` to equal the exact selected signer and
MUST require the label namespace, class, action, ordering, and any optional
association to be canonical. Heterodyne clients always render the event as
automated, including a persona-key-signed event. Vanilla clients ignore the
unknown label and display the actual Nostr author normally. Public
verification establishes a signed automation assertion; it does not reveal or
prove the private token ceremony.

Human organization delegates remain private authorization and audit subjects
by default. They do not receive automation attribution merely because they use
a shared organization signer. An organization policy MAY require a public
human byline for a particular event class; that policy is separate from the
mandatory automation label and MUST NOT expose private OIDC or audit identity.

<a id="comms-agent-fail-closed"></a>
### 15.5 Fail-closed authorization and privacy

The full node MUST refuse before signing for a missing, invalid, expired,
revoked, stale, wrong-audience, or wrong-scope token; sender-proof or
`cnf.jkt` failure; session, client, subject, persona, selected-signer,
key-class, or current-key mismatch; missing persona-signing scope; non-active
or unavailable ledger/status state; a disallowed kind, feed,
resource, size, rate, or burst; unavailable attribution profile; raw signing,
key access, human-profile selection, or attribution bypass. There is no
fallback to an unlabeled event, persona key, bearer-only token, stale decision,
or agent-provided signature.

The raw token, `jti`, unused scopes, source claim IDs, sender proof, and private
workload registration MUST NOT appear in a public event, public repository,
attribution tag, or moderation receipt. A protected audit MAY retain their
identifiers and validation results but MUST NOT retain the raw token except
under a separately bounded encrypted diagnostic policy.

<a id="comms-security"></a>
## 16. Security invariants and forward-secrecy posture


The registry defines these Comms invariants. An entry the registry binds to a feature is owed only by an implementation
claiming that feature, under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).
The list below is descriptive:

- **COMMS-I-TIER3-BLIND-CARRIER:** Tier 3 content is audience-key encrypted before reaching any repository, seed, full node, or relay.
- **COMMS-I-TIER2-HONESTY:** Tier 2 private repositories are selective-replication boundaries, not encryption, and clients present that trust boundary honestly.
- **COMMS-I-CONFIG-AT-REST:** Comms-owned non-key private state and audience or group material are encrypted under the Comms repository-encryption profile.
- **COMMS-I-CLIENT-SIDE-DELIVERY:** Cross-backend Comms processing runs on user-controlled clients; full nodes, repository relays, routing nodes, and Nostr relays are blind carriers for protected plaintext.
- **COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY:** Feed, outbox, and delivery discovery do not depend on a centralized delivery directory.
- **COMMS-I-CLAIM-AUTHENTICITY:** Claim IDs, event signatures, issuer authority, typed references, and native proofs are verified before trust or authorization policy is applied.
- **COMMS-I-CLAIM-ATTENUATION:** Every delegated claim strictly preserves or narrows all authority dimensions and issuance chains contain at most eight edges.
- **COMMS-I-CLAIM-REPOSITORY-AUTHORITY:** Persona-issued device authorization is final only in canonical private claim-repository state, while authenticated reductions take effect immediately.
- **COMMS-I-CLAIM-REVOCATION:** A valid revocation or authority reduction is irreversible, monotonic, and wins concurrent repository merges.
- **COMMS-I-LEDGER-CONFINEMENT:** Private claim-ledger contents and decryption material are available only to active durable NID-bearing ledger readers.
- **COMMS-I-ISSUER-KEY-CONFINEMENT:** Shared OIDC signing keys are separately encrypted and released only to nodes with active oidc-token-issuer authority.
- **COMMS-I-MINT-FRESHNESS:** A node mints only from a synchronized canonical checkpoint no older than the manifest bound, which cannot exceed 300 seconds.
- **COMMS-I-ISSUER-CONTINUITY:** HTTPS issuer metadata and the active-persona-key-scoped Radicle continuity tree agree on the exact active issuer, keys, status digests, and authorized succession.
- **COMMS-I-CLAIM-RELEASE:** OIDC projection releases only claims allowed by scope, audience, client policy, consent, active repository state, issuer trust, and proof requirements.
- **COMMS-I-JWT-TYPE-AUDIENCE:** JWT consumers enforce exact issuer, intended audience, time, signature, nonce when applicable, and token-type separation including typ at+jwt for access tokens.
- **COMMS-I-STATUS-INTEGRITY:** Draft-21 status lists are signed, fresh, digest-bound across HTTPS and Radicle mirrors, writer-namespaced without index reuse, and never let VALID override other token failures.
- **COMMS-I-PUBLIC-READER-TIER1-ONLY:** A public-reader implementation consumes only verified Tier 1 content and never renders Tier 2 plaintext or interprets Tier 3 ciphertext as public content.
- **COMMS-I-AGENT-SIGNER-BINDING:** Every automated event uses the exact registered signer, key class, and optional association kind/value; an agent key is preferred, while a persona key requires the explicit OIDC persona-signing scope, and the event pubkey remains authoritative.
- **COMMS-I-AGENT-ATTRIBUTION:** Every agent-authored application event carries the canonical automation attribution block at its tier-appropriate protected location.
- **COMMS-I-WORKLOAD-TOKEN-CONFINEMENT:** Workload tokens, token identifiers, private source claims, and sender proofs remain confined to the protected authorization and audit boundary.
- **COMMS-I-MARMOT-UPSTREAM-AUTHORITY:** The pinned Marmot dependency remains authoritative for MLS, conversation events, encrypted media, and Nostr transport semantics.
- **COMMS-I-MARMOT-ACCOUNT-IDENTITY:** The active persona key is the Marmot account identity, every device leaf remains independent, and neither Heterodyne continuity nor storage provenance aliases another account or leaf inside MLS.
- **COMMS-I-MARMOT-EXACT-BYTES:** Radicle storage and every Nostr or media interface preserve exact signed Marmot event bytes and encrypted media ciphertext.
- **COMMS-I-MARMOT-SECRET-CONFINEMENT:** Independent device leaves do not share secrets by default, and node-mediated clients receive no MLS, account, leaf, or repository secret.
- **COMMS-I-RADICLE-ROUTING-AUTHORITY:** Only a canonical Marmot routing commit by its active account-key administrator can authorize a routing binding and repository genesis with the same `h`, RID, routing-event ID, and authorized writer refs.
- **COMMS-I-RADICLE-NON-ERASURE:** Retention expiry stops conforming advertisement and replication but never claims erasure of independent Git objects, clones, exports, or backups.
- **COMMS-I-TRUSTED-SEED-CONFINEMENT:** A trusted seed receives only routing metadata and exact encrypted event bytes, writes only its own active authorized NID ref, and gains no persona, repository-owner, group-admin, full-node, or MLS authority.
- **COMMS-I-PRIVATE-RELAY-ACL:** Every private seed read or write requires NIP-42 account authentication plus one unique current unexpired administrator-signed ACL head matching the account role, seed grant, `h`, private RID, and Marmot group transition.

Mechanism guarantees MUST remain distinct. Tier 3 has no forward secrecy: a
compromised audience key decrypts every retained post under its
`key_id`; rotation protects only later generations. Marmot conversation and
Control-channel guarantees come only from the pinned Marmot/MLS profile and
its retention behavior. Clients MUST NOT infer one mechanism's guarantee for
another.

<a id="comms-strict-profile"></a>
### 16.1 Comms strict profiles

The stable Comms strict profile composes the Core strict profile and adds the
baseline Comms invariants. Under
[`heterodyne:0.5.0#core-strict-profile`](heterodyne-core.md#core-strict-profile) it does not add or
require a feature-bound invariant, so claiming it does not oblige an
implementation to ship claims, the OIDC issuer, token status, or agent
authorship:

<!-- fixture:comms-strict-profile -->
```json
{
  "profile_id": "heterodyne-comms-strict-v1",
  "conformance_class": "Core+Comms",
  "state": "active",
  "requires_profiles": [
    "heterodyne-core-strict-v1"
  ],
  "adds_invariants": [
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY"
  ]
}
```

A `heterodyne-comms-strict-v1` implementation MUST meet every inherited Core
obligation, MUST present the Tier 2 plaintext-on-allowed-seeds warning before
publication, and MUST retain no retired message keys after the Comms deletion
points. Its capability advertisement MUST name both profile IDs. An
implementation missing any condition MUST omit the Comms profile. The
invariants bound to `comms.public-reader.v1` and
[`heterodyne:0.5.0#comms-agent-authorship`](#comms-agent-authorship) are owed
by every implementation claiming those features, strict or not.

<a id="comms-conformance"></a>
## 17. Conformance


A Comms conformance report follows the family requirements in
[`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance) and claims Core+Comms. A base
implementation MUST implement the envelope, tiers, one-event exact-byte
publishing and retry, NIP-65 outbox retrieval, source-neutral selection, and
every baseline Comms invariant. It MUST NOT require Assurance, a cold root,
KERI state, an epoch key, kind `31005`, or kind `31007`. One that advertises
DMs MUST implement all applicable Marmot rules in §7.
Transport-independent credential-continuity definitions remain non-claimable
at the pinned registry revision.

Typed key claims, the private claim ledger, the OIDC issuer, token status, the
public reader, Marmot conversations, Radicle Marmot storage and relays, and
trusted-seed private relay and agent authorship are each a separately claimed feature, not an entry
requirement. A base Comms implementation therefore does not need an RFC 9068
issuer, JWKS discovery, a continuity manifest, or status lists. The
invariant scoping in
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope) governs what each
claim owes. `comms.oidc-jwt-projection.v1` becomes mandatory exactly when an
implementation claims a feature that requires it, which for Comms means
`comms.agent-authorship.v1`: an automated principal's registration, consent,
and pairwise subject are OIDC objects, so a client that works with agents
ships the issuer and a client that does not, does not.

A report claiming `comms.trusted-seed-private-relay.v1` MUST identify every
seed by its Radicle NID, demonstrate independent endpoints and writer refs,
exercise NIP-42 plus the current ACL for both reads and writes, and fail closed
for every invalid-state class in §7.7.1. It MUST demonstrate that accepted
write bytes enter only the selected seed's authorized ref and that no MLS leaf,
plaintext, content-decryption key, persona authority, or group-administrator
authority reaches the seed.

A report claiming `comms.public-reader.v1` MAY omit every send-side and private
feature, but MUST name the `public-reader` Core role, implement
`core.nostr-relay-read.v1`, list whether `core.outbound-tor.v1` is present,
pass every public-reader and applicable Core vector, and report reduced
assurance when Tor is unavailable. Repository unavailability does not demote
valid relay-derived state. It MUST NOT claim this
feature after rendering Tier 2 or Tier 3 as public content.

A report claiming `heterodyne-comms-strict-v1` MUST include the computed
closure, the Core prerequisite result, the Tier 2 warning result, every
applicable strict vector result, and the vector results for every feature it
also claims. It MUST NOT claim the profile if any item is missing. An
implementation that exposes an automated publication path outside §15 MUST NOT
claim Comms conformance or the Comms strict profile.

No conforming report may list a §8.4 credential-continuity draft schema as an
active wire profile, feature, requirement, or strict-profile obligation. The
unprofiled credential-continuity draft vectors exercise schema and pure state-machine
definitions only; their normalized `conformance_claimable:false` result is
part of the case and they do not establish Control or recovery conformance.

Byte-exact wire conformance and unknown-version handling are family-wide
rules stated once by [`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance) and
[`heterodyne:0.5.0#core-versioning`](heterodyne-core.md#core-versioning); an unknown registry profile is an unknown
stamped version for that purpose.
