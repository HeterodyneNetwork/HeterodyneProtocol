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
fan-out, generic feed ordering and location, Marmot conversations and media,
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
MUST invoke [`heterodyne:0.5.0#core-verification`](heterodyne-core.md#core-verification). In order, it MUST:

1. require a well-formed event and the exact `nip01_raw` signing bytes;
2. hash `nip01_raw`, match `id` and every parsed field, and verify BIP-340;
3. resolve the signer through the persona KEL and require epoch-key authority
   at `created_at`, including compromise cutoffs;
4. apply Core `kel_head`, provisional-finality, and equivocation rules; and
5. apply the Comms schema, tier, and authorization rules for the event.

A failure MUST be surfaced as a rejection or explicit security indicator;
clients MUST NOT silently treat an invalid event as verified. A provisional
Core verdict MUST NOT be reported or persisted as final.

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
An individual Tier 3 post or index outer event exposes only its registered
profile marker, opaque `key_id`, required Core integrity/identity tags, and
Comms profile stamp; semantic content and tags, RID, audience association, and
retrieval hints are encrypted. The surrounding distribution graph is not
membership-private: `kind:31011` and `kind:31012` expose clear recipient
`p`/`d` tags and roster changes, the shared `key_id` links wraps, rosters,
posts, indexes, descriptors, and rotations, and carrier observers retain
timing, size, count, publication, and fetch-cadence metadata.

<a id="comms-audience-keys"></a>
### 3.1 Audience key distribution and roster


An audience key is 32 uniformly random bytes. Persona membership expands by
default to every active KEL-delegated human-device secp256k1 publishing key for
that persona. A policy MAY narrow delivery to an explicit subset of those
active devices, but MUST NOT add an inactive, revoked, unverified, non-device,
cold-root, or epoch key. `kind:31011` distributes the key once per effective
device recipient using NIP-44 to that device publishing key. The same device
private key signs Nostr events and decrypts its wraps; this is one compromise
domain. An authenticated light device therefore decrypts directly without
bringing a persona authority key online.

The event MUST be epoch-key signed and contain exactly the addressing fields
represented here:

```json
{
  "kind": 31011,
  "tags": [
    ["d", "<key_id>:<recipient pubkey-hex>"],
    ["heterodyne", "audience_key_wrap"],
    ["key_id", "<opaque id with at least 128 bits>"],
    ["p", "<recipient pubkey-hex>"],
    ["cold_root", "<persona cold root>"],
    ["kel_head", "<accepted KEL event id>", "<seq>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": "<NIP-44 wrap of the audience key>"
}
```

The replaceable `kind:31012` roster uses `d = key_id`, the
`audience_roster` discriminator, the same `key_id` and cold root, and one `p`
tag per recipient. It MUST be epoch-key signed and KEL-validated. A sensitive
roster MAY instead be carried inside a Tier 3 encrypted object.

Encrypting the roster does not create complete membership privacy.
Recipient-addressed `kind:31011` events on public carriers still expose clear
recipient and generation linkage. This release defines no membership-private
audience-key distribution profile.

A member addition MUST publish a replacing `kind:31012` under the same
`key_id` containing the new member and MUST publish that member's
`kind:31011` wrap. Addition SHOULD NOT rotate: the new member receives the
current generation.

A member or effective device removal MUST generate a fresh audience key and `key_id`, publish the
new roster, redistribute `kind:31011` wraps only to remaining members,
republish the current encrypted index under the newly derived `index_key`, and
supersede the in-audience descriptor. The producer MUST initiate every
required index, descriptor, roster, and wrap action within 60 seconds and
retry until success, explicit expiry, user cancellation, a superseding state
transition, or the profile's terminal retry-budget outcome. A carrier
partition is an availability failure, not automatic producer nonconformance.
Rotation excludes the removed member from future
content only; it cannot revoke old ciphertext encrypted under a key the member
already possessed.
Adding an active device follows ordinary member addition and does not rotate
existing content by default. Removing or revoking a device excludes it from
the effective set and triggers the complete removal rotation above.
After that removal, every subsequent post, index, and descriptor MUST use the
fresh audience generation and its fresh `key_id`; reuse of the retired
generation for any new object MUST be rejected.

<a id="comms-tier-three-profile"></a>
### 3.2 Tier 3 encryption profile


Comms profiles the symmetric ChaCha20/HMAC-SHA256 layer of NIP-44 v2. It does
not perform NIP-44 ECDH for a post or index body; the per-recipient ECDH occurs
only in `kind:31011`. Keys are domain-separated:

```text
post_key = HKDF-SHA256(
  IKM=audience_key,
  salt=UTF8(key_id),
  info=UTF8("heterodyne-post-key-v1"),
  L=32
)
index_key = HKDF-SHA256(
  IKM=audience_key,
  salt=UTF8(key_id),
  info=UTF8("heterodyne-index-key-v1"),
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
  "pubkey": "<current epoch key>",
  "created_at": 0,
  "kind": 1,
  "tags": [
    ["heterodyne_wrap", "room_key.v2"],
    ["key_id", "<opaque audience-key generation id>"],
    ["kel_head", "<accepted KEL event id>", "<decimal seq>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": "<NIP-44-v2 symmetric ciphertext of the inner payload>",
  "sig": "<BIP-340 signature by current epoch key>"
}
```

The clear tags of every Tier 3 post MUST include the two wrap tags,
`spec_version` equal to `heterodyne/0.5.0` as required by its stamping profile, and `kel_head`
exactly as Core requires for an epoch-signed event. For addressable kinds
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
then verify the outer signature and Core key authority. Possession of the key,
not current membership metadata, is the cryptographic access test.
`room_key.v1` and the withdrawn NIP-59 broadcast path MUST be rejected.

<a id="comms-config-repository"></a>
### 3.3 Config-repository protection profile


The `heterodyne-comms-config-repository-v1` protection profile instantiates
[`heterodyne:0.5.0#core-protected-repository`](heterodyne-core.md#core-protected-repository) with the Tier 3 profile
above. There is exactly one private,
unadvertised config repository per persona; its allow list contains only the
persona's durable delegated NIDs. The RID MUST NOT appear on any published
profile, event, relay list, feed index, or node advertisement. It travels only
through authorized credential sync, the Core keys repository, or backup
restore.

The dedicated config audience key MUST NOT be distributed by published
`kind:31011`; that would reveal the repository and audience. The repository
MUST contain no nsec, epoch secret, NID secret, audience key, or MLS state.
Comms owns its encryption profile and audience payload types; private
social preferences and followed-repository payloads are outside Comms.
The private persona claim ledger in §11 is an allowed Comms-owned non-key
configuration payload.

Authorization comes only from the KEL and active delegations defined by
[`heterodyne:0.5.0#core-nid-delegation`](heterodyne-core.md#core-nid-delegation). A device
inventory is bookkeeping and MUST NOT authorize a device; a stale inventory
MUST NOT remove a device except through an explicit marked revocation record.

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

Individual deletion uses Nostr `kind:5` plus an updated feed index. It signals
intent, not erasure. Live history MUST NOT be rewritten; deletion of a whole
retired `enc/<key_id>` ref is the sole sanctioned ref-deletion path.
Clients MUST warn that Tier 1 and Tier 2 plaintext may persist on every node
that fetched or seeded it. Tier 3 ciphertext may persist on relays and
non-cooperating seeds and remains readable to holders of its retired key.

<a id="comms-publishing"></a>
## 4. Publishing and delivery


One publication intent MUST produce exactly one signed Nostr event, computed
once and fanned out unchanged. Implementations MUST NOT re-sign the same
intent. Tier 3 encryption precedes signing. The event `id` is the idempotency
token across ordinary and repo relays, and receivers SHOULD deduplicate on it.

The destination set contains the persona's configured ordinary write relays
and the appropriate repo relay. Tier 1 plaintext MUST be published to ordinary
relays and the public repo relay. Tier 2 plaintext MUST be published only to
private-repo allowed seeders and MUST NOT be sent to a public relay. Tier 3
ciphertext MUST be published to both its configured ordinary relays and its
repo relay. The feed index follows the same tier-specific
publication boundary. Scheduling, batching, and retry are implementation
choices, but partial failure MUST be shown with destination and reason; a
generic unexplained partial-failure message is insufficient.

A Nostr write is permanently failed when a relay returns NIP-01 `OK=false`
with `invalid:`, `blocked:`, or `restricted:`, when `rate-limited:` exceeds
one hour, after three consecutive retry windows, or on application close code
4000-4999. Other failures are transient. An AUTH-required rejection is
transient before NIP-42 authentication and permanent if repeated afterward
(`auth_rejected_permanent`). A NIP-13 proof-of-work rejection is PERMANENT
when the client cannot meet the relay's target.

An indexed event MUST NOT enter `kind:31007` until at least one configured
Comms destination has accepted it. If every configured write destination
permanently fails, the index MUST NOT include it, automatic republication MUST
NOT occur, and user action is required. Retries MUST reuse the original event
without changing its id.

An automated-principal publication additionally MUST satisfy §15 before this
ordinary fan-out begins. The full node constructs and signs one canonical
attributed event; an idempotent retry reuses those exact bytes and event id.

<a id="comms-feed-index"></a>
## 5. Generic feed index


`kind:31007` is a persona's canonical ordering authority independent of which
backend served an event. It is an addressable, epoch-key-signed Comms event,
with a `["spec_version","heterodyne/0.5.0"]` tag unless a registered stamping
profile assigns the event's sole owner stamp elsewhere.
Tier 1 and Tier 2 ordinary indexes MUST have empty `content`.
Tier 3 index `content` MUST be ciphertext as defined by §5.3.
Publication is likewise tier-qualified by
§5.3: there is no common destination set for all indexes. The example below
is the ordinary plaintext metadata form used within the Tier 1 or Tier 2 trust
boundary.

```json
{
  "kind": 31007,
  "tags": [
    ["d", "<feed_id>:<page_id>"],
    ["heterodyne", "feed_index"],
    ["cold_root", "<persona cold root>"],
    ["rid", "<feed RID>"],
    ["feed_label", "<optional human-readable label>"],
    ["retrieval_hints", "{\"archive_url\":\"https://archive.example/<nostr_event_id>\"}"],
    ["e", "<event id>", "<relay hint>"],
    ["kel_head", "<accepted KEL event id>", "<seq>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": ""
}
```

The public `d` tag MUST be exactly `["d", "<feed_id>:<page_id>"]`.
`heterodyne` and `cold_root` are REQUIRED. `rid` SHOULD appear for a
repo-backed feed; `feed_label` and `retrieval_hints` are OPTIONAL feed
metadata. When present, `retrieval_hints` contains
[`heterodyne:0.5.0#core-canonical-json`](heterodyne-core.md#core-canonical-json) and its `archive_url` is interpreted by
§6. Ordered `e` tags define the display
order. A profile above
Comms declares which application events are indexed; absent such a profile,
persistent authored content SHOULD be indexed and ephemeral metadata SHOULD
not. An explicit `heterodyne_index=true|false` tag overrides that default.

Comms permits exactly one class of exception to the empty-content and
Comms-version-tag rules: a registered stamping profile on `kind:31007`. The
[`registry/kinds.json`](registry/kinds.json) entry names each such profile,
its owner, and its immutable `content.profile=` discriminator; the owning
document defines the exact content object. A stamped event carries that object
as its sole owner stamp, in `content` only, and MUST NOT carry a Comms or
owner `spec_version` tag. Every other Comms tag, paging, size, publication,
retrieval, signature, KEL, and organization-threshold rule remains unchanged.
No stamping profile may be used for Tier 3, contain Tier 3 ciphertext, or
carry `heterodyne_wrap` or `key_id` tags. A profile absent from the registry
entry MUST be rejected rather than treated as ordinary content.

<a id="comms-org-authorization"></a>
### 5.1 Organization threshold authorization


Applying [`heterodyne:0.5.0#core-threshold-authority`](heterodyne-core.md#core-threshold-authority), all posts and feed
indexes owned by an org persona MUST be reachable
from the delegate-threshold-approved canonical `defaultBranch` before being
canonical. A lone org epoch-key holder MUST NOT bypass threshold governance by
publishing a valid signature only to relays; failure is
`not_canonical_branch_reachable`. For a single-delegate persona this reduces
to ordinary signature verification, under
[`heterodyne:0.5.0#core-threshold-authority`](heterodyne-core.md#core-threshold-authority).

This rule applies uniformly to org-owned Comms posts and feed indexes; their
threshold authorization is not a presentation-layer option.

<a id="comms-feed-paging"></a>
### 5.2 Paging and integrity


A page MUST contain at most 500 entries and SHOULD contain 256. A chained
public page uses exactly `["previous_index", "<event_id>"]` and MUST also use
`["prev_page_hash", "<hex-sha256>"]`, where the hash is SHA-256 of the
prior page's canonical NIP-01 bytes. The first page MUST omit both tags. A
verifier MUST check every page signature and hash; mismatch breaks the chain
with `page_chain_broken` and a visible feed-integrity error. A page missing
the hash MAY be rendered only with an unverifiable-chain warning.

After a complete fetch attempt cannot resolve a predecessor, the newest
resolvable page containing that missing predecessor link is the referring
page. The client MUST surface a
[`heterodyne:0.5.0#core-structured-outcome`](heterodyne-core.md#core-structured-outcome)
with `outcome_class` `missing-predecessor`, a `subject` binding the
unavailable predecessor event id and the referring page's event id,
`created_at`, and `d`, and `allowed_actions` drawn from `retry` and
`continue-incomplete`. For example, an English UI may render “feed truncated
after `<created_at>` / `<d>`; missing `<event_id>`”; that sentence is not
normative.
The client MUST continue from the newest resolvable page and MUST NOT call the
result complete. It MUST persist the unresolved predecessor event id and the
referring-page locator (its event id, `created_at`, and `d`) across process
restart, and retry when a new relay becomes reachable or the user revisits the
feed. Equal `(pubkey, kind, d, created_at)` conflicts select the
lexicographically smallest event id.

<a id="comms-private-index"></a>
### 5.3 Tier-specific indexes and descriptors


Tier 1 indexes are plaintext and MUST be published to ordinary relays and the
public repo relay. Tier 2 indexes are plaintext only on private-repo allowed
seeders and MUST NOT be published to a public relay. A Tier 3 index MUST
encrypt its closed payload with `index_key` and MUST be published as
ciphertext to both its configured ordinary relays and its repo relay.
Clear tags are limited to opaque `d`, `heterodyne=feed_index`, `cold_root`,
`heterodyne_wrap=room_key.v2`, `key_id`, `kel_head`, and the Comms version
tag. Relay-visible tags MUST NOT contain `retrieval_hints`, RID, entries,
hints, or previous-page data; all of them MUST be inside ciphertext.

The Tier 3 outer `d` MUST be opaque and generated from at least 128 bits of
randomness or from a keyed digest whose secret input is known only to the
audience. It MUST NOT contain a literal RID, room identifier, feed label, or
semantic page name.

The closed decrypted payload contains, in order, `spec_version`, `rid`,
`page_id`, optional `feed_label`, optional `retrieval_hints`, ordered
`entries[{event_id,relay_hint}]`, and optional
`previous_index{event_id,prev_page_hash}`. `retrieval_hints`, when present,
MUST be an object with exactly one string `archive_url` member. Missing,
duplicate, unknown, misordered, or wrongly typed members MUST be rejected. A
receiver MUST select and derive the matching `index_key`, decrypt, require the
expected RID, verify signature and KEL authority, then traverse the decrypted
chain.

Every audience-scoped feed MUST publish an in-audience descriptor. Tier 2
carries it in the private repository; Tier 3 carries an epoch-key-authenticated
object encrypted under `index_key`, addressable from clear `key_id` plus Core
RID/host routing. Its payload MUST locate the publisher, kind 31007, latest
opaque `d`, `key_id`, RID, and relay/repo set. This non-circular bootstrap MUST
work without a higher-layer service. Removal and rotation MUST supersede the
descriptor under the fresh generation. The producer MUST initiate that
supersession within 60 seconds and retry until success, explicit expiry, user
cancellation, a superseding state transition, or the terminal retry-budget
outcome.

<a id="comms-retrieval"></a>
## 6. Retrieval, backfill, and outbox location


A missing indexed event is queried by NIP-01 id from its hint, then the
persona's NIP-65 write and read relays, and eligible repo relays. For this
calculation, `known_relays` is exactly the set union of the persona's current
NIP-65 `read` and `write` relays and all relay hints accompanying the feed
entry or page, after URL normalization and deduplication. A complete fetch
attempt queries `max(3, ceil(len(known_relays) * 0.5))` relays, subject to the
available set (when fewer are known, it queries every known relay), uses a default
10-second timeout, makes at most three retries (1/4/16 seconds RECOMMENDED),
and orders hints, write relays, then read relays. Clients MUST refresh changed
`kind:10002` relay lists before declaring the attempt complete.

Tier 3 fetches ciphertext then decrypts it. Tier 2 fetches only from an
allowed full node. A persona MAY advertise its own HTTPS archive in the
`retrieval_hints.archive_url` field of feed-index metadata. If the URL
contains the literal `<nostr_event_id>`, a client substitutes the requested
event id. Otherwise it appends or sets `?id=<nostr_event_id>`. The publisher
is entirely responsible for the endpoint; archive failure is not a protocol
error. If relay, repo, and explicitly advertised archive channels fail, the
object is permanently lost to the network and SHOULD be shown as missing.

Automated historical retrieval requests, responses, or pushes over any DM
transport are forbidden. Marmot history follows the group's declared
retention and join-epoch rules. Comms defines no relay-style bulk-fetch service
or mandatory archive service.

The generic public outbox location is the verified `kind:31005` npub-to-RID
pointer from [`heterodyne:0.5.0#core-identity-pointer`](heterodyne-core.md#core-identity-pointer) plus the NIP-65
relay list; clients use it to locate the persona's
`kind:31007` indexes. Audience-scoped location is the descriptor in §5.3.
Comms discovery ends at generic feed/outbox location and does not define who
subscribes or a social-graph traversal. No centralized delivery directory may
be required.

<a id="comms-public-reader"></a>
### 6.1 Public-reader feature

`comms.public-reader.v1` consumes only verified Tier 1 Comms envelopes, public
feed indexes, and retrieval state. It MUST implement
`core.nostr-relay-read.v1`, local NIP-01/BIP-340 and KEL verification, §5
receive-side feed integrity, §6 retrieval, and
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
its public key MUST be the persona's canonical cold-root npub. An `nevent`
author, when present, and an `naddr` public key MUST equal that cold root.
`did:key`, Radicle NID, derived export AID, OIDC subject, or launcher origin
MUST NOT substitute for the cold-root identity.

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
2. resolves and verifies the cold-root identity pointer and available KEL;
3. refreshes the persona's current NIP-65 relay list;
4. locates public `kind:31007` feed indexes;
5. fetches the target from entry hints and the refreshed relay set;
6. verifies its NIP-01 bytes, signature, KEL authority, page integrity, and
   complete-fetch state; and
7. requires reachability from the persona's canonical Tier 1 feed before
   calling the result canonical.

Resolution MUST terminate in exactly one visible state:

- `canonical` when every check succeeds and repository confirmation is final;
- `provisional-canonical` when the same checks succeed but repository
  confirmation is unavailable;
- `unindexed-signed-event` for a valid Tier 1 signed event absent from the
  canonical public index;
- `conflicted` when the applicable Core, page, or addressable-event rules
  identify a conflict;
- `unavailable` when the complete-fetch, NIP-65 refresh, predecessor, or
  required relay evidence cannot be completed; or
- `private` for Tier 2 plaintext or Tier 3 ciphertext.

The client MUST NOT turn a failed complete fetch into an empty feed. It MUST
NOT render Tier 2 plaintext in public-reader mode and MUST NOT interpret,
probe, or label Tier 3 ciphertext as public content. An unindexed signed event
MUST carry that exact visible qualification and MUST NOT be presented as a
canonical Heterodyne publication.

<a id="comms-public-transition"></a>
### 6.4 Anonymous-to-authenticated transition

The static application starts with no identity or device key. At explicit user
request it MAY, without reloading the application or creating a hosted server
session, generate a local non-delegated Control key, locate a full-node Marmot
KeyPackage on accepted relays, establish a two-member group, and invoke the
Control enrollment profile. The transition MUST NOT change already verified
public-reader identity or content results.

The Control principal receives no persona epoch secret, NID secret, audience
key, repository-decryption key, credential-ledger key, device key, or MLS leaf
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

Heterodyne is authoritative only for KERI attribution, Control authorization,
node-mediated operation, agent policy, Radicle repository and relay profiles,
and public Social assets. A Marmot-valid event without current KERI evidence
remains part of Marmot history. It loses verified Heterodyne attribution or
authorization, but Heterodyne MUST NOT use KERI to select an MLS branch or
alter convergence.

Ordinary user-facing one-to-one conversations and routine own-device Control
channels are two-member Marmot groups. Marmot also owns private group content,
replies, reactions, attachments, edits, group-scoped long-form messages, and
the authenticated encrypted application carriage on which Control relies.

<a id="comms-marmot-participation"></a>
### 7.1 Identity, leaf ownership, and client modes

Each persona uses the Core-bound `marmot:human-messaging` account for ordinary
account-scoped privilege and a separate `marmot:group-admin` account for
administration. Automated roles use `agent:<role-id>`. The account private
keys remain on authorized full or recovery nodes.

Devices use independent Marmot MLS leaf keys. Heterodyne does not adopt
Marmot's draft multi-device External Commit profile. A new device uses
standard Marmot KeyPackages, Add commits, account-to-leaf proofs, and
Welcomes. A leaf backup or transfer is permitted only as the exclusive
takeover defined by Core; concurrent use of one leaf by multiple devices MUST
be rejected.

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
prior generation, authorized host set, advertised interfaces, retention
metadata, signing administrator, and accompanying Marmot routing-commit event
ID.

<a id="comms-marmot-event-repository"></a>
### 7.5 Event repository and logical union

An event repository genesis manifest MUST validate against
`docs/spec/schemas/comms/marmot-event-repository-genesis-v1.schema.json`.
The repository is append-only at the logical protocol layer and has no merged
canonical message branch.

Each native writer MUST publish to its own NID ref. An integrated relay MUST
publish relay-ingested objects to its designated relay ref. Hosts replicate
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
NOT use that key as member identity. A write allowlist uses NIP-42 connection
authentication by an authorized stable Marmot account or active
KERI-delegated device or agent key. This is anti-abuse admission only; it MUST
NOT be presented as Marmot sender authentication.

A group has one or more hosts, and administrators are hosts by default. Hosts
replicate the static, active, and retained archive repositories; advertise
authorized Radicle, onion, and clearnet interfaces; enforce repository
admission and retention; prepare repositories and bindings; and initiate only
authorized membership and routing commits. A host or Radicle delegate MUST
NOT acquire group-admin authority merely by hosting.

Light clients do not need Radicle NIDs unless they use native Radicle
membership. A standard-compatible client may remain Nostr-only.

<a id="comms-marmot-host-authority"></a>
### 7.8 Host authority, convergence, and equivocation

Static-repository changes are signed announcements. A client accepts a routing
binding only when:

1. the signer was an active Marmot administrator;
2. that signer authored the canonical Marmot routing commit establishing the
   same `h`; and
3. the event repository's genesis manifest matches the bound digest.

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
sender-specific ref. The first application event may be a direct message,
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
larger objects. The manifest identifies sender NID, consumed KeyPackage,
event IDs, object sizes, and automation status. Unknown bundles MUST NOT
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
groups under [`heterodyne:0.5.0#control-frame`](heterodyne-control.md#control-frame). The full node uses its
Core-authorized device account and a dedicated leaf; the light client uses its
private non-delegated Control account and its own leaf. A standard Welcome and
valid MLS membership authenticate transport identity but grant no application
authority.

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
key or preauthorization template. A `device-enrollment` descriptor also binds
current Core/KERI inviter-authority evidence. Unknown descriptor, envelope,
authority, or preauthorization members are invalid.

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
and KERI device effects; the Comms rendezvous alone grants no application or
persona authority.

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
## 9. Private Control registry and token projection

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

<a id="comms-control-token"></a>
### 9.1 Node-scoped JWT projection

Each full node is an independent RFC 9068 issuer for its exact Control
resource. Issuer signing keys MUST remain node-local. Authenticated issuer
public state in the private Control registry binds the issuer URL, current
JWKs, node device key, exact resource audience, validity interval, and
predecessor.

A Control token has protected `typ` exactly `at+jwt`, all mandatory RFC
9068 claims, `cnf.jkt`, the exact Marmot group, client class, authorization
record, private-registry checkpoint, methods, objects, finite limits, and
optional agent role. Its audience names only the issuing node. Another full
node MUST reject it and issue a new token after independently validating the
same persona-wide entitlement.

For Marmot carriage the authenticated sender account and MLS sender leaf are
the proof bound to `cnf.jkt`; Comms MUST NOT invent HTTP method or URI values.
A separately exposed HTTPS endpoint may apply RFC 9449. The default lifetime
is five minutes. A separately consented `control.token.extended` grant may
increase it, but no token may exceed sixty minutes. No refresh token is
issued.

Every request rechecks current entitlement. A projected token never replaces
private repository authority. Once revocation is observed, every associated
token fails regardless of its remaining `exp`.

<a id="comms-control-bootstrap"></a>
### 9.2 Locked epoch inbox and recovery records

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
### 9.3 Authorization-view freshness

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

Reader removal first records the reduction, removes Radicle access, rotates the
dedicated ledger audience key, wraps the new key only for remaining active
readers, advances the checkpoint, and retires prior ciphertext under the
cooperative scrub profile. Old Git objects may remain observable to a former
reader; rotation protects new state and the UI MUST describe this limit.

<a id="comms-multiwriter-minting"></a>
### 11.1 Multi-writer minting and issuer-key confinement

The repository is multi-writer. An online node is not excluded because another
authorized writer can mint. A node may mint for the persona only when it has
all three of: a separately envelope-encrypted usable signing JWK, an `active`
`oidc-token-issuer` claim, and a canonical checkpoint whose age is within the
continuity manifest bound. That bound MUST NOT exceed the window in
[§9.3](#comms-authorization-freshness). Loss or reduction of any condition
stops minting immediately.

The signing key MUST NOT be encrypted by or released merely with the ledger
audience key. Its envelope binds persona, repository, checkpoint, key epoch,
credential-ledger generation, JWK thumbprint, ciphertext digest, active
issuer-authority record set, and per-recipient NID wraps. Removing an issuer
rotates the envelope/key epoch and excludes that NID. A node MUST unwrap only
after replaying the exact bound authority set, generation, and checkpoint.

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

A persona has one exact HTTPS issuer:

```text
https://<host>/oidc/<cold-root-npub>
```

The final path component is the canonical NIP-19 encoding of the persona's raw
cold-root key, not an epoch key. A host may serve many personas at disjoint
cold-root paths. Every trusted serving node exposes current and retiring public
keys for each persona it serves, including keys minted elsewhere.

The OIDC configuration is at `<issuer>/.well-known/openid-configuration`, the
RFC 8414 alias is
`https://<host>/.well-known/oauth-authorization-server/oidc/<cold-root-npub>`,
and JWKS is at `<issuer>/.well-known/jwks.json`. Metadata uses that exact issuer
and advertises `<issuer>/authorize`, `<issuer>/token`, and
`<issuer>/device_authorization`. Issuer comparison is exact. Redirects,
aliases, case folding, a host change, or an epoch-key path do not silently
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
.well-known/<cold-root-npub>/
  issuer.json
  openid-configuration
  jwks.json
  manifest.json
  status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

The exact manifest schema is
`schemas/comms/oidc-continuity-manifest-v1.schema.json`. It binds profile,
public RID, `main`, cold-root npub and raw key, accepted KEL head, exact issuer,
monotonic sequence and predecessor digest, checkpoint-age bound, current and
retiring key IDs/JWK digests, all status paths/URIs/digests, optional successor,
and an active NID writer/checkpoint. Its Ed25519 authority proof and that
writer's current ledger authority MUST verify. HTTPS and repository metadata,
JWKS, and Status List Token bytes MUST be identical.

The manifest authority proof `issued_at` MUST be greater than or equal to its
exact canonical ledger checkpoint's `observed_at` and MUST NOT be later than
the verification time. The named writer authorization and its Core KEL
authority are evaluated at that `issued_at`, not at fetch time. The verifier
requires Core-authenticated previous-to-current KEL transition evidence that
binds the same persona cold-root npub, the exact predecessor manifest's
previous head (or null at genesis), the candidate's current head, and a half-open
`valid_from <= issued_at < valid_until` interval. The candidate manifest MUST
also carry the exact current KEL head expected by the verifier.

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
current persona epoch authority or cold-root recovery and an exact binding to
the new manifest. Heterodyne-aware resolution may then find the new URL through
canonical `main`; ordinary OIDC clients still require normal trust or
registration for the new issuer. A fork, rollback, stale KEL head, digest
mismatch, unauthorized successor, or disagreement between HTTPS and Radicle
fails closed. Public continuity contains no private claim, consent, reader,
issuance mapping, or secret key.

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
and intent-publication path below. They MUST refuse instructions to obtain or
exercise a persona, epoch, NID, human-device, or role private key; request raw
signing; select a human publication profile; remove or falsify attribution;
impersonate a human author; or bypass token, proof, scope, resource, rate, or
size enforcement.

This is a conformance rule for the execution path. It does not make a valid
Nostr signature invalid merely because a non-conforming private implementation
misclassified its source, and it cannot detect agent text manually copied into
a human client.

<a id="comms-agent-delegation"></a>
### 15.1 Dedicated role key and delegation

A full node accepting automated commands MUST generate at least one dedicated
secp256k1 agent-signing key locally. The private key MUST remain protected on
the full node and MUST NOT be released through an agent session, OIDC,
configuration sync, credential sync, backup export to the workload, tool
result, or diagnostic interface. One generic role is normal; separate stable
roles MAY isolate a newsletter, aggregator, moderator, or other automation
pipeline.

The registry defines the non-stamping
`heterodyne-comms-agent-signing-delegation-v1` profile on the Core
role-addressed delegation extension at [`heterodyne:0.5.0#core-nid-delegation`](heterodyne-core.md#core-nid-delegation).
Its discriminator is
`tag:d=agent:<role-id>;tags:key_proof,radicle_nid,nid_proof`. Comms supplies
only the four items that extension requires.

**Namespace.** `agent`. `role-id` is exactly 32 random bytes encoded as 64
lowercase hexadecimal characters.

**Proof domain.** Domain `heterodyne-agent-signing-binding-v1`, whose claim binds
`cold_root`, `nid`, `publishing_key`, and `role_id`. The hosting NID and the
agent key each sign those bytes independently.

**Additional tags.** `radicle_nid` carrying the hosting full-node NID, and
`nid_proof` carrying that NID's Ed25519 proof, inserted after `heterodyne` and
before `publishing_key`. Each appears exactly once. Both proofs are REQUIRED;
the Core extension's `key_proof` is the agent key's BIP-340 proof over the
same bytes.

**Semantics.** The role authorizes automated publication for the persona under
[`heterodyne:0.5.0#comms-agent-attribution`](#comms-agent-attribution) and nothing else. Acceptance
additionally requires ordinary Core repo finality, returning
`provisional_not_final` while unmet.

Replacing the delegation at the same `agent:<role-id>` address rotates only
that role's device key. The prior key remains historically attributable but
MUST NOT authorize a new event after the replacement becomes effective. Other
roles, human devices, and the epoch key are unchanged.

<a id="comms-agent-workload"></a>
### 15.2 Private workload registration and stable identity

The canonical private claim ledger MUST carry an active
`heterodyne.agent` / `workload-registration` authorization claim. Its value
MUST validate against
`docs/spec/schemas/comms/agent-workload-registration-v1.schema.json` and is
closed. It binds exact `client_id`, subject JWK thumbprint, `ai` or
`programmatic` class, exactly one role ID, exactly one audience, non-empty
scopes, allowed kinds, feeds and resources, maximum content bytes, finite
positive rate window/count/burst, validity interval, and an optional
descriptive software-claim reference. Empty or unlimited kind, resource, size,
rate, or burst authority is invalid.

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
only and grants no authority.

<a id="comms-agent-token"></a>
### 15.3 Sender-constrained workload token

Marmot Control is the standard issuance carrier, but token construction,
validation, and private-ledger authority remain Comms semantics and create no
Comms dependency on Control. After an initialized agent profile and validated
Marmot account binding, an authorized built-in issuer returns the node-scoped
RFC 9068 access token defined by §9.1 with:

- protected `typ` exactly `at+jwt`;
- `iss`, pairwise `sub`, one exact `aud`, `exp`, `iat`, collision-resistant
  `jti`, `client_id`, normalized `scope`, `credential_ledger_persona`, and
  `credential_ledger_generation`;
- mandatory `cnf.jkt`;
- the existing ledger-checkpoint and status-mirror bindings; and
- `https://heterodyne.network/jwt/agent-role-id` equal to the one registered
  role.

The default lifetime is five minutes; an explicitly consented
`control.token.extended` capability may permit up to sixty minutes. The token
MUST issue no refresh token and MUST NOT outlive its Control group binding,
workload registration, consent, or source authorization. It authorizes only
registered scopes and resources. Every side effect authenticates the Marmot
sender whose JWK thumbprint equals `cnf.jkt` and binds the token `jti`, group,
request and operation IDs, method, and canonical payload digest.

Before authorizing an intent, the full node MUST validate exact issuer,
subject, audience, client, scope, role, time, signature, Control-group binding,
ledger checkpoint, status binding, source claims, and authenticated sender. A
projected JWT never replaces canonical private-ledger state. Client
Credentials remains prohibited; a separately integrated sender-constrained
HTTPS workload profile is required before that grant can be added.

<a id="comms-agent-attribution"></a>
### 15.4 Canonical public attribution

An agent supplies intent content, kind, destination/feed, and permitted
options. It does not supply a signature or authoritative attribution identity.
The full node removes every caller-supplied reserved agent-attribution field,
then inserts these tags in exact relative order:

```text
["L", "network.heterodyne.agent"]
["l", "ai" | "programmatic", "network.heterodyne.agent"]
["heterodyne_agent", "v1", "<issuer>", "<sub>", "<client_id>", "<role-id>"]
["agent_action", "publish"]
```

It MAY append `["agent_review","<verified-review-reference>"]` only after
independent verification. Review never changes the automated classification.
The full node signs exactly once with the current key at the named role
address, then applies ordinary §4 publication and §5 indexing.

The registry makes the attribution discriminator
`tags:L=network.heterodyne.agent,l=<class>@network.heterodyne.agent,heterodyne_agent=v1,agent_action=publish;order=v1`
active through these non-stamping profiles:

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
fall back to an unlabeled or human event. Deterministic KEL, delegation,
feed-index, token-status, relay-metadata, and equivalent maintenance events are
not agent-authored application publications.

Tier 1 carries the block publicly. Tier 2 carries it inside the private
repository trust boundary. Tier 3 carries the same block only inside the
encrypted logical event and adds no agent marker to the clear wrapper. A
verifier MUST require the signer to equal the current publishing key at the
named role address and MUST require the class, issuer, subject, client, and
role fields to be canonical. Public verification establishes a signed
agent-service assertion; it does not reveal or prove the private token
ceremony.

<a id="comms-agent-fail-closed"></a>
### 15.5 Fail-closed authorization and privacy

The full node MUST refuse before signing for a missing, invalid, expired,
revoked, stale, wrong-audience, or wrong-scope token; sender-proof or
`cnf.jkt` failure; session, client, subject, role, or current-key mismatch;
non-active or unavailable ledger/status state; a disallowed kind, feed,
resource, size, rate, or burst; unavailable attribution profile; raw signing,
key access, human-profile selection, or attribution bypass. There is no
fallback to an unlabeled event, human key, bearer-only token, stale decision,
or agent-provided signature.

The raw token, `jti`, unused scopes, source claim IDs, sender proof, and private
workload registration MUST NOT appear in a public event, public repository,
attribution tag, or moderation receipt. A protected audit MAY retain their
identifiers and validation results but MUST NOT retain the raw token except
under a separately bounded encrypted diagnostic policy.

<a id="comms-security"></a>
## 16. Security invariants and forward-secrecy posture


The registry defines these Comms invariants:

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
- **COMMS-I-ISSUER-CONTINUITY:** HTTPS issuer metadata and the root-key-scoped Radicle continuity tree agree on the exact active issuer, keys, status digests, and authorized succession.
- **COMMS-I-CLAIM-RELEASE:** OIDC projection releases only claims allowed by scope, audience, client policy, consent, active repository state, issuer trust, and proof requirements.
- **COMMS-I-JWT-TYPE-AUDIENCE:** JWT consumers enforce exact issuer, intended audience, time, signature, nonce when applicable, and token-type separation including typ at+jwt for access tokens.
- **COMMS-I-STATUS-INTEGRITY:** Draft-21 status lists are signed, fresh, digest-bound across HTTPS and Radicle mirrors, writer-namespaced without index reuse, and never let VALID override other token failures.
- **COMMS-I-PUBLIC-READER-TIER1-ONLY:** A public-reader implementation consumes only verified Tier 1 content and never renders Tier 2 plaintext or interprets Tier 3 ciphertext as public content.
- **COMMS-I-AGENT-ROLE-BINDING:** Every agent-authored event signer, workload registration, token role claim, and active role-addressed delegation identify the same dedicated full-node-held role key.
- **COMMS-I-AGENT-ATTRIBUTION:** Every agent-authored application event carries the canonical automation attribution block at its tier-appropriate protected location.
- **COMMS-I-WORKLOAD-TOKEN-CONFINEMENT:** Workload tokens, token identifiers, private source claims, and sender proofs remain confined to the protected authorization and audit boundary.
- **COMMS-I-MARMOT-UPSTREAM-AUTHORITY:** The pinned Marmot dependency remains authoritative for MLS, conversation events, encrypted media, and Nostr transport semantics.
- **COMMS-I-MARMOT-EXACT-BYTES:** Radicle storage and every Nostr or media interface preserve exact signed Marmot event bytes and encrypted media ciphertext.
- **COMMS-I-MARMOT-SECRET-CONFINEMENT:** Independent device leaves do not share secrets by default, and node-mediated clients receive no MLS, account, leaf, or repository secret.
- **COMMS-I-RADICLE-ROUTING-AUTHORITY:** Only a canonical Marmot routing commit by an active administrator can authorize a matching Radicle routing binding and repository genesis.
- **COMMS-I-RADICLE-NON-ERASURE:** Retention expiry stops conforming advertisement and replication but never claims erasure of independent Git objects, clones, exports, or backups.

Mechanism guarantees MUST remain distinct. Tier 3 has no forward secrecy: a
compromised audience key decrypts every retained post and index under its
`key_id`; rotation protects only later generations. Marmot conversation and
Control-channel guarantees come only from the pinned Marmot/MLS profile and
its retention behavior. Clients MUST NOT infer one mechanism's guarantee for
another.

<a id="comms-strict-profile"></a>
### 16.1 Comms strict profiles

The stable Comms strict profile composes the Core strict profile. Its flattened
invariant membership is exact:

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
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "COMMS-I-PUBLIC-READER-TIER1-ONLY",
    "COMMS-I-AGENT-ROLE-BINDING",
    "COMMS-I-AGENT-ATTRIBUTION",
    "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
  ]
}
```

A `heterodyne-comms-strict-v1` implementation MUST meet every inherited Core
obligation, MUST present the Tier 2 plaintext-on-allowed-seeds warning before
publication, MUST retain no retired message keys after the Comms deletion
points, MUST hold the public-reader Tier boundary, and MUST meet all
[`heterodyne:0.5.0#comms-agent-authorship`](#comms-agent-authorship) role, token, attribution,
no-fallback, and confinement obligations. Its capability advertisement MUST
name both profile IDs. An implementation missing any condition MUST omit the
Comms profile.

<a id="comms-conformance"></a>
## 17. Conformance


A Comms conformance report follows the family requirements in
[`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance) and claims Core+Comms. A base
implementation MUST implement the envelope, tiers, publishing, feed,
retrieval, Marmot invitation hook, private Control-registry integration, and
all registered Comms invariants. One that advertises DMs MUST implement all
applicable Marmot rules in §7. Transport-independent credential-continuity
definitions remain non-claimable at the pinned registry revision.

A report claiming `comms.public-reader.v1` MAY omit every send-side and private
feature, but MUST name the `public-reader` Core role, implement
`core.nostr-relay-read.v1`, list whether `core.outbound-tor.v1` is present,
pass every public-reader and applicable Core vector, and report reduced
assurance when Tor or repo confirmation is unavailable. It MUST NOT claim this
feature after rendering Tier 2 or Tier 3 as public content.

A report claiming `heterodyne-comms-strict-v1` MUST include the computed
closure, the Core prerequisite result, the Tier 2 warning result, and every
applicable strict, public-reader, and agent-authorship vector result. It MUST
NOT claim the profile if any item is missing. An implementation that exposes
an automated publication path outside §15 MUST NOT claim Comms conformance or
the Comms strict profile.

No conforming report may list a §8.4 credential-continuity draft schema as an
active wire profile, feature, requirement, or strict-profile obligation. The
unprofiled credential-continuity draft vectors exercise schema and pure state-machine
definitions only; their normalized `conformance_claimable:false` result is
part of the case and they do not establish Control or recovery conformance.

Byte-exact wire conformance and unknown-version handling are family-wide
rules stated once by [`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance) and
[`heterodyne:0.5.0#core-versioning`](heterodyne-core.md#core-versioning); an unknown registry profile is an unknown
stamped version for that purpose.
