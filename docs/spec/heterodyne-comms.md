# Heterodyne Comms Protocol Specification

Document ID: `comms`<br>
Version: `comms/0.5.0`<br>
Registry revision: `2`

Normative dependencies: `heterodyne:core/0.5.0#core-conformance`.

This document prepares Comms' first 0.5.0 release, descended from the
Heterodyne 0.4.x monolith. It is current normative authority at this repository
path but remains unreleased pending claims/OIDC completion and explicit
release approval.
`comms/0.5.0` is not a synchronized family version. While Comms is 0.x, exact
version matching is required. The key words MUST, MUST NOT, REQUIRED, SHALL,
SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL
are to be interpreted as described by BCP 14 when, and only when, they appear
in all capitals.

Permanent anchors use the literal `comms-` prefix and lowercase ASCII
kebab-case. Generated heading IDs are not stable protocol references.

<a id="comms-scope"></a>
## 1. Scope

<!-- Monolith provenance: §4.1/§4.5, §5.2, §5.7, §6.1-§6.4,
§6.7-§6.10, §7.1-§7.2, §9.0-§9.1, §9.5; split allocation: ADR-033. -->

Comms defines secure persona speech over the Core substrate: a Nostr-native
event envelope, public/private/encrypted repository tiers, publishing and
fan-out, generic feed ordering and location, Double Ratchet direct messages,
credential-plane synchronization, an authenticated acceptance-policy hook,
and an encrypted generic subprotocol carrier.

Comms does not define following, replies or reactions as social relationships,
threading, moderation, personal lists, community policy, social-graph
discovery, Matrix rooms, or command semantics. Application documents may
select payloads and tighten acceptance, but cannot weaken this document's
cryptographic checks.

An implementation claiming Core+Comms is a **Heterodyne persona**. DM support
is a RECOMMENDED feature; a client that offers Heterodyne-to-Heterodyne DMs
MUST implement the complete DM feature in §7.

<a id="comms-envelope"></a>
## 2. Nostr-native event envelope and verification

<!-- Monolith provenance: §4.1 and primary `verify_nostr` entry point in §4.5. -->

The canonical Comms content unit is one NIP-01 signed event. Ordinary Nostr
relays and Core repo relays carry the same event bytes; the event `id` is the
deduplication key across both backends. Repo visibility and application-layer
encryption change confidentiality, not the NIP-01 envelope.

Before rendering, storing, indexing, or authorizing a received event, a client
MUST invoke `heterodyne:core/0.5.0#core-verification`. In order, it MUST:

1. require a well-formed event and the exact `nip01_raw` signing bytes;
2. hash `nip01_raw`, match `id` and every parsed field, and verify BIP-340;
3. resolve the signer through the persona KEL and require epoch-key authority
   at `created_at`, including compromise cutoffs;
4. apply Core `kel_head`, provisional-finality, and equivocation rules; and
5. apply the Comms schema, tier, and authorization rules for the event.

A failure MUST be surfaced as a rejection or explicit security indicator;
clients MUST NOT silently treat an invalid event as verified. A provisional
Core verdict MUST NOT be reported or persisted as final.

Under `heterodyne:core/0.5.0#core-version-stamps`, Comms-allocated
JSON-content kinds carry `"spec_version":"comms/0.5.0"`.
Comms-allocated empty-content kinds carry
`["spec_version","comms/0.5.0"]`. Adopted upstream events remain unstamped
unless the pinned registry names a stamping profile. Double-ratchet outer
events are the explicit exception described in §7.2.

<a id="comms-privacy-tiers"></a>
## 3. Repository privacy tiers

<!-- Monolith provenance: §5.2, §6.10, §9.0-§9.1. -->

Every repository-carried publication declares one of three trust boundaries,
which clients MUST present without ambiguity:

| Tier | Stored form | Trust boundary |
|---|---|---|
| Tier 1 | plaintext in a public repository and on ordinary relays | confidential against no one |
| Tier 2 | plaintext in a private repository | hidden from non-allowed nodes, but readable by every allowed seeder |
| Tier 3 | NIP-44-v2-profile ciphertext in a public or private repository | confidential against everyone without the audience key, including seeders and full nodes |

A client MUST NOT describe Tier 2 as encrypted, end-to-end encrypted, or
confidential against members. Adding an NID to `visibility.allow` grants that
node plaintext read and replication access and SHOULD require explicit user
confirmation. `visibility.allow` MUST NOT be conflated with the repository
`delegates` governance set.

Tier 3 content MUST be encrypted before it reaches any repository, full node,
seed, or relay. Plaintext Tier 3 content MUST NOT be committed or published.
The outer event exposes only its registered profile marker, opaque `key_id`,
required Core integrity/identity tags, and Comms profile stamp; semantic
content and tags, RID, audience association, and retrieval hints are encrypted.

<a id="comms-audience-keys"></a>
### 3.1 Audience key distribution and roster

<!-- Monolith provenance: §6.7.4 and §6.10.1. -->

An audience key is 32 uniformly random bytes. `kind:31011` distributes it once
per recipient using NIP-44 to that recipient's npub. The event MUST be
epoch-key signed and contain exactly the addressing fields represented here:

```json
{
  "kind": 31011,
  "tags": [
    ["d", "<key_id>:<recipient npub>"],
    ["heterodyne", "audience_key_wrap"],
    ["key_id", "<opaque id with at least 128 bits>"],
    ["p", "<recipient npub>"],
    ["cold_root", "<persona cold root>"],
    ["kel_head", "<accepted KEL event id>", "<seq>"],
    ["spec_version", "comms/0.5.0"]
  ],
  "content": "<NIP-44 wrap of the audience key>"
}
```

The replaceable `kind:31012` roster uses `d = key_id`, the
`audience_roster` discriminator, the same `key_id` and cold root, and one `p`
tag per recipient. It MUST be epoch-key signed and KEL-validated. A sensitive
roster MAY instead be carried inside a Tier 3 encrypted object.

A member addition MUST publish a replacing `kind:31012` under the same
`key_id` containing the new member and MUST publish that member's
`kind:31011` wrap. Addition SHOULD NOT rotate: the new member receives the
current generation.

A member removal MUST generate a fresh audience key and `key_id`, publish the
new roster, redistribute `kind:31011` wraps only to remaining members,
republish the current encrypted index under the newly derived `index_key`, and
supersede the in-audience descriptor. The index and descriptor updates MUST
complete within 60 seconds. Rotation excludes the removed member from future
content only; it cannot revoke old ciphertext encrypted under a key the member
already possessed.
After that removal, every subsequent post, index, and descriptor MUST use the
fresh audience generation and its fresh `key_id`; reuse of the retired
generation for any new object MUST be rejected.

<a id="comms-tier-three-profile"></a>
### 3.2 Tier 3 encryption profile

<!-- Monolith provenance: §6.7.4 and §6.10.1. -->

Comms profiles the symmetric ChaCha20/HMAC-SHA256 layer of NIP-44 v2. It does
not perform NIP-44 ECDH for a post or index body; the per-recipient ECDH occurs
only in `kind:31011`. Keys are domain-separated:

```text
post_key  = HKDF-SHA256(audience_key, UTF8(key_id),
                        "heterodyne-post-key-v1", 32)
index_key = HKDF-SHA256(audience_key, UTF8(key_id),
                        "heterodyne-index-key-v1", 32)
```

Registry revision 2 permits Tier 3 wrapping only for this closed stamping
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
    ["spec_version", "comms/0.5.0"]
  ],
  "content": "<NIP-44-v2 symmetric ciphertext of the inner payload>",
  "sig": "<BIP-340 signature by current epoch key>"
}
```

The clear tags of every Tier 3 post MUST include the two wrap tags,
`spec_version` equal to `comms/0.5.0` as required by its stamping profile, and `kel_head`
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

<!-- Monolith provenance: §3.8.6; payload ownership rewritten by ADR-033 req 6. -->

The `heterodyne-comms-config-repository-v1` protection profile instantiates
`heterodyne:core/0.5.0#core-protected-repository` with the Tier 3 profile
above. There is exactly one private,
unadvertised config repository per persona; its allow list contains only the
persona's durable delegated NIDs. The RID MUST NOT appear on any published
profile, event, relay list, feed index, or node advertisement. It travels only
through authorized credential sync, the Core keys repository, or backup
restore.

The dedicated config audience key MUST NOT be distributed by published
`kind:31011`; that would reveal the repository and audience. The repository
MUST contain no nsec, epoch secret, NID secret, audience key, or ratchet state.
Comms owns its encryption profile and audience/ratchet payload types; private
social preferences and followed-repository payloads are outside Comms.
The credential authorization ledger in §8.1 is an allowed Comms-owned non-key
configuration payload.

Authorization comes only from the KEL and active delegations defined by
`heterodyne:core/0.5.0#core-nid-delegation`. A device
inventory is bookkeeping and MUST NOT authorize a device; a stale inventory
MUST NOT remove a device except through an explicit marked revocation record.

<a id="comms-encrypted-branches"></a>
### 3.4 Encrypted branches, deletion, and residue

<!-- Monolith provenance: §6.10.3-§6.10.4. -->

Ciphertext for each generation MUST live only at
`refs/heads/enc/<key_id>`; the default branch carries no ciphertext. The
RECOMMENDED self-verifying id is the first 16 bytes, lowercase hex, of
`SHA-256("heterodyne-key-id-v1" || audience_key)`, though verifiers MUST treat
all valid ids as opaque.

On rotation the publisher MUST create the new branch and force-delete the
retired ref from its signed refs. It MAY re-encrypt retained history, producing
new events and ids. Cooperating seeds SHOULD reclaim unreachable objects.
This scrub is cooperative hygiene, not erasure: offline or hostile seeds and
ordinary relays may retain ciphertext indefinitely, and clients MUST NOT claim
otherwise.

Individual deletion uses Nostr `kind:5` plus an updated feed index. It signals
intent, not erasure. Live history MUST NOT be rewritten; deletion of a whole
retired `enc/<key_id>` ref is the sole sanctioned ref-deletion path.
Clients MUST warn that Tier 1 and Tier 2 plaintext may persist on every node
that fetched or seeded it. Tier 3 ciphertext may persist on relays and
non-cooperating seeds and remains readable to holders of its retired key.

<a id="comms-publishing"></a>
## 4. Publishing and delivery

<!-- Monolith provenance: §6.1-§6.4.1. -->

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

<a id="comms-feed-index"></a>
## 5. Generic feed index

<!-- Monolith provenance: §6.7-§6.8; moderator and Social kind policy removed. -->

`kind:31007` is a persona's canonical ordering authority independent of which
backend served an event. It is an addressable, epoch-key-signed Comms event,
with a `["spec_version","comms/0.5.0"]` tag unless a registered stamping
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
    ["spec_version", "comms/0.5.0"]
  ],
  "content": ""
}
```

The public `d` tag MUST be exactly `["d", "<feed_id>:<page_id>"]`.
`heterodyne` and `cold_root` are REQUIRED. `rid` SHOULD appear for a
repo-backed feed; `feed_label` and `retrieval_hints` are OPTIONAL feed
metadata. When present, `retrieval_hints` contains canonical compact JSON and
its `archive_url` is interpreted by §6. Ordered `e` tags define the display
order. A profile above
Comms declares which application events are indexed; absent such a profile,
persistent authored content SHOULD be indexed and ephemeral metadata SHOULD
not. An explicit `heterodyne_index=true|false` tag overrides that default.

Registry revision 2 defines one narrow exception to the empty-content and
Comms-version-tag rules: the Social stamping profile whose immutable
discriminator is
`content.profile=heterodyne.social.org-feed.v1`. That profile is valid only
for Tier 1 or Tier 2 and replaces the ordinary empty content with the exact
canonical compact JSON string
`{"profile":"heterodyne.social.org-feed.v1","spec_version":"social/0.5.0"}`.
Its object is closed and ordered: `profile` then `spec_version`, with no other
members. The Social stamp occurs only in `content`; the event MUST NOT carry a
Comms or Social `spec_version` tag. Every other Comms tag, paging, size,
publication, retrieval, signature, KEL, and organization-threshold rule
remains unchanged. The profile MUST NOT be used for Tier 3, MUST NOT contain
Tier 3 ciphertext, and MUST NOT carry `heterodyne_wrap` or `key_id` tags.

<a id="comms-org-authorization"></a>
### 5.1 Organization threshold authorization

<!-- Monolith provenance: §6.7.0; authority supplied by Core, presentation removed. -->

Applying `heterodyne:core/0.5.0#core-threshold-authority`, all posts and feed
indexes owned by an org persona MUST be reachable
from the delegate-threshold-approved canonical `defaultBranch` before being
canonical. A lone org epoch-key holder MUST NOT bypass threshold governance by
publishing a valid signature only to relays; failure is
`not_canonical_branch_reachable`. For a single-delegate persona this reduces
to ordinary signature verification. Per-ref `xyz.radicle.crefs` MAY refine
authorization, but baseline canonicity MUST NOT depend on it.

This rule applies uniformly to org-owned Comms posts and feed indexes; their
threshold authorization is not a presentation-layer option.

<a id="comms-feed-paging"></a>
### 5.2 Paging and integrity

<!-- Monolith provenance: §6.7.2. -->

A page MUST contain at most 500 entries and SHOULD contain 256. A chained
public page uses exactly `["previous_index", "<event_id>"]` and MUST also use
`["prev_page_hash", "<hex-sha256>"]`, where the hash is SHA-256 of the
prior page's canonical NIP-01 bytes. The first page MUST omit both tags. A
verifier MUST check every page signature and hash; mismatch breaks the chain
with `page_chain_broken` and a visible feed-integrity error. A legacy missing
hash MAY be rendered only with an unverifiable-chain warning.

After a complete fetch attempt cannot resolve a predecessor, the newest
resolvable page containing that missing predecessor link is the referring
page. The client MUST surface exactly "feed truncated after `<created_at-of-referring-page>` / `<d-tag-of-referring-page>`; missing `<event_id>`",
substituting the referring page's own `created_at` and `d` and
the exact unavailable predecessor event id from its `previous_index` link.
The client MUST continue from the newest resolvable page and MUST NOT call the
result complete. It MUST persist the unresolved predecessor event id and the
referring-page locator (its event id, `created_at`, and `d`) across process
restart, and retry when a new relay becomes reachable or the user revisits the
feed. Equal `(pubkey, kind, d, created_at)` conflicts select the
lexicographically smallest event id.

<a id="comms-private-index"></a>
### 5.3 Tier-specific indexes and descriptors

<!-- Monolith provenance: §6.7.3-§6.7.5 and §7.2. -->

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
descriptor under the fresh generation within 60 seconds.

<a id="comms-retrieval"></a>
## 6. Retrieval, backfill, and outbox location

<!-- Monolith provenance: §6.9 and §7.1-§7.2; follower/community surfaces removed. -->

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
transport are forbidden. Double-ratchet history has no backfill. Comms defines
no relay-style bulk-fetch service or mandatory archive service.

The generic public outbox location is the verified `kind:31005` npub-to-RID
pointer from `heterodyne:core/0.5.0#core-identity-pointer` plus the NIP-65
relay list; clients use it to locate the persona's
`kind:31007` indexes. Audience-scoped location is the descriptor in §5.3.
Comms discovery ends at generic feed/outbox location and does not define who
subscribes or a social-graph traversal. No centralized delivery directory may
be required.

<a id="comms-direct-messages"></a>
## 7. Double-ratchet direct messages

<!-- Monolith provenance: §5.7 and §9.5. -->

Comms adopts nostr-double-ratchet version `0.0.138` as its 0.x normative wire
reference. It provides forward secrecy and post-compromise security. The wire
MUST be extracted and frozen before Comms can claim 1.0.

<a id="comms-dm-wire"></a>
### 7.1 Invite, response, and message profiles

Registry revision 2 binds these immutable, non-stamping profiles:

- `heterodyne-comms-double-ratchet-invite-v1`: upstream `kind:30078`,
  discriminator `d-prefix:double-ratchet/invites/`;
- `heterodyne-comms-double-ratchet-invite-response-v1`: upstream
  `kind:1059`, discriminator `wire:nostr-double-ratchet@0.0.138;kind=1059`;
- `heterodyne-comms-double-ratchet-message-v1`: upstream `kind:1060`,
  discriminator `wire:nostr-double-ratchet@0.0.138;kind=1060`.

Each delegated device publishes its own addressable invite at
`double-ratchet/invites/<device>`. An invite is signed by that device's
secp256k1 publishing key and contains the upstream ephemeral bootstrap
material. Before session establishment, the recipient MUST validate the
device's active delegation under
`heterodyne:core/0.5.0#core-nid-delegation` and KEL authority; missing or revoked bindings
are `dm_invite_unbound_device` or `dm_invite_revoked_device`.

Publishing a newer invite with the same `(pubkey, kind, d)` replaces the old
invite; an empty-content replacement is its tombstone. An out-of-band invite
whose bootstrap bytes are encoded in a URL fragment is an equivalent
client-mediated bootstrap and MUST undergo the same delegation, KEL, expiry,
and acceptance checks.

An invite response is `kind:1059`. A `kind:1060` message is signed by the
current DH-ratchet key, not an epoch key, and carries the encrypted header and
NIP-44-v2 ciphertext. Current and next expected ratchet keys select a session.
Outer signers rotate at a DH step; messages within one ratchet epoch remain
linkable until that step.

Decrypted chat, reaction, receipt, and typing data are unsigned NIP-17-style
rumors. They are attributable through the authenticated session but provide no
transferable third-party authorship proof. Messages are sent to the recipient's
NIP-17 `kind:10050` DM relay list; a DM-capable persona SHOULD publish one.
When the authenticated recipient is a vanilla-Nostr recipient that does not
support this DR profile, a DM-capable client MUST offer the NIP-17 fallback
and MUST label that it lacks forward secrecy and post-compromise security.

<a id="comms-dm-retention"></a>
### 7.2 Retention and ratchet state

<!-- Monolith provenance: §5.7.3 and §9.5. -->

`kind:1060` messages and `kind:1059` responses MUST NOT be committed to any
repo and a repo relay MUST reject them with `dm_event_not_storable`. Invites
MAY use both backends. Double-ratchet traffic has no backfill and relay
retention is transient. Local history and ratchet state MUST be encrypted at
rest.

After successful decryption and ratchet advancement, a receiver MUST delete
the consumed message key. Lost ratchet state means unrecoverable history and
clients MUST say so. Compromise of current state does not reveal deleted past
keys; a fresh DH step restores security after compromise.

Every durable delegated device owns separate invites and sessions. A sender
SHOULD establish a session with each active recipient device. Self-DMs between
devices of the same persona carry authorized credential sync. Group sender-key
extensions are OPTIONAL and non-normative in this release.

When a peer device's delegation expires or is revoked, active peers MUST stop
sending on every session bound to that device and SHOULD surface the change;
other devices of the persona are unaffected.

Neither `kind:1059` nor `kind:1060` carries a Heterodyne version marker,
`kel_head`, or persona identifier. Only encrypted inner Comms carrier rumors
carry `comms/0.5.0`.

<a id="comms-acceptance-hook"></a>
## 8. Authenticated acceptance-policy hook

<!-- Monolith provenance: §5.7.4, rewritten by ADR-033 req 16. -->

All cryptographic checks MUST complete successfully before acceptance policy
runs. Policy MUST NOT bypass, replace, reinterpret, or loosen signature,
session, delegation, KEL, freshness, revocation, or context checks.

The hook has these closed inputs:

- authenticated peer persona cold-root npub;
- authenticated peer device publishing key and delegation identifier;
- local recipient persona and target device NID, when one exists;
- context: exactly `ordinary-dm`, `credential-sync`, or
  `control-enrollment`;
- verified session identifier and transcript binding;
- message/negotiated protocol identifier and requested features;
- active-delegation, finality, and revocation result; and
- local prior-session state plus an explicit user decision, if any.

It returns exactly `accept`, `hold-as-message-request`, or `reject` plus a
local reason. `accept` permits interpretation and ordinary response behavior.
`reject` ends processing without interpreting application payload.
`hold-as-message-request` stores only the minimum encrypted local request
state and MUST NOT emit a receipt, typing signal, delivery acknowledgement,
automatic retry hint, or any other sender-observable signal until the user
accepts.

The Comms-native default is a total decision table applied only after
cryptographic authentication succeeds:

| Context and authenticated state | Outcome |
|---|---|
| `ordinary-dm`, established locally accepted session | `accept` |
| new `ordinary-dm` | `hold-as-message-request` |
| `credential-sync` | `accept` iff every §8.1 authoritative ledger and current-grant check passes |
| `credential-sync`, authoritative current state cannot be established | `hold-as-message-request`; no transfer and no sender-observable signal |
| `credential-sync`, invalid, revoked, expired, mismatched, or NID-less | `reject` |
| `control-enrollment` without a stricter composed profile decision | `hold-as-message-request` |

Cryptographically invalid input is rejected before the hook runs. A composed
profile MAY tighten the table but MUST NOT turn a Comms rejection into another
result or accept an unauthenticated input.

<a id="comms-credential-sync"></a>
### 8.1 Credential-plane synchronization

<!-- Monolith provenance: §3.8.7 self-DM path and §5.7.3; exact class: ADR-033 req 17. -->

A fully delegated trusted device is a cryptographic class: it has an active,
durable, NID-bearing Core `kind:31001` delegation and an explicit active
credential-sync authorization. A NID-less session device MUST always reject
credential-sync and MUST NOT receive a keys repository, audience key, NID
secret, epoch secret, or ratchet state.

Every credential-sync grant is bound to the target NID and credential-sync
purpose, validated against the KEL, and revocable as defined below.

The authorization record is canonical compact JSON:

```json
{
  "type": "heterodyne.credential-sync.authorization.v1",
  "authorization_id": "<32 lowercase hex characters>",
  "persona": "<64 lowercase hex cold-root npub>",
  "target_nid": "<canonical Ed25519 did:key NID>",
  "purpose": "credential-sync",
  "issued_at": 0,
  "valid_until": 9999999999,
  "kel_head": {"event_id": "<KEL event id>", "seq": 0},
  "action": "grant",
  "signature": "<128 lowercase hex BIP-340 signature>"
}
```

The signature covers SHA-256 of the UTF-8 bytes
`heterodyne-credential-sync-authorization-v1|` followed by compact JSON of
all members except `signature` in the displayed member order. The top-level
member sequence is closed and exactly the displayed sequence. Encodings are:

- `type` and `purpose` are the displayed literals;
- `authorization_id` is exactly 16 random bytes encoded as 32 lowercase hex;
- `persona` is exactly 32 bytes encoded as 64 lowercase hex;
- `target_nid` is the canonical `did:key` multibase encoding of an Ed25519
  Radicle NID; decoding and re-encoding MUST reproduce the input byte-for-byte;
- `issued_at`, `valid_until`, and `kel_head.seq` are JSON-safe nonnegative
  integers from 0 through 9007199254740991 inclusive;
- `kel_head` has exactly the ordered members `event_id`, `seq`, where
  `event_id` is 32 bytes encoded as 64 lowercase hex;
- `action` is exactly `grant` or `revoke`; and
- `signature` is exactly 64 bytes encoded as 128 lowercase hex.

A grant MUST have `valid_until > issued_at`. Its expiry is not an individual
record-validity failure and is evaluated only by the operational resolver
below. A revoke MUST use `valid_until` equal to `0`, the permanent sentinel. A
revoke tombstone MUST NOT expire and MUST never be discarded because of
`valid_until`. A missing, duplicate, unknown, misordered, or wrongly typed
member at either object level MUST be rejected.

A new grant MUST create an `authorization_id` not previously used for any
grant in this persona. A revoke MUST reuse that grant's ID and target NID. A
later grant MUST NOT reuse a previous or revoked ID; reauthorization requires
a fresh random `authorization_id`. Exact duplicate bytes are idempotent, but
records themselves are unique by their signed record digest/bytes, not by
`authorization_id`. Thus a conforming ID history contains exactly one distinct
grant record and zero or more distinct revoke records, all for the grant's
target. A revoke with no matching grant, a target mismatch, or a second
distinct grant makes that ID history invalid for credential transfer; those
individually valid signed records remain retained for audit and continuity.

For individual record eligibility, a verifier MUST validate the epoch
signature, epoch authority at `issued_at`, and `kel_head`. Requiring the target
to be the receiving device's own NID and requiring its currently active
NID-bearing delegation are operational checks below, not filters on the
canonical record set. Revoking or expiring the underlying Core delegation is
an independent immediate authorization failure even before ledger convergence.

**Durable authority.** The authoritative authorization ledger is a
Comms-owned non-key record set inside the encrypted private config repository,
where each record is identified by its signed bytes, as defined below.
Epoch-signed grant and revoke records have authority only when reachable from
the verified canonical config-repository state. A self-DM presents and
transports a signed grant or revoke record, but a self-DM MUST NOT become an
authorization authority.

The complete canonical signed-record set is the union of all individually
structurally, cryptographically, and KEL-valid authorization records reachable
from the active `enc/<key_id>` config branch in canonical signed-ref state
after a complete sync with every currently configured persona full node.
Individual validity requires the closed schema and encodings above, a valid
signature and persona/purpose binding, and an authoritative epoch key and
`kel_head` at `issued_at`. It also requires `valid_until > issued_at` for a
grant or the zero sentinel for a revoke. The set MUST include expired grants
and every revoke tombstone. Current evaluation time and current delegation
status MUST NOT remove an otherwise valid record from this set.

A record on an unmerged device branch has no authority. Authorized writers
MUST merge new records without deleting any record. If configured nodes expose
unresolved candidate canonical heads, or any configured node is unreachable,
the canonical record set cannot be established and credential sync is held.

Canonical record identity and ordering are exact:

```text
canonical_signed_record_bytes(record) = UTF8(canonical_compact_json(record))
record_digest(record) = lowercase-hex(SHA-256(canonical_signed_record_bytes(record)))
action_rank("grant") = 0
action_rank("revoke") = 1
```

Here `record` contains every member, including `signature`, in the displayed
top-level order. Byte-identical duplicates collapse to one record. Two
different byte strings with the same digest make canonical state invalid. Sort
the distinct records ascending by this fully specified tuple:

```text
(decoded authorization_id bytes,
 UTF8(target_nid) bytes,
 issued_at as an integer,
 action_rank(action),
 decoded record_digest bytes)
```

All byte comparisons are unsigned lexicographic comparisons. The canonical
digest input is the canonical compact JSON array of the ordered records'
`record_digest` strings, with no whitespace:

```text
canonical_authorization_record_digests =
  canonical_compact_json([record_digest(record_0), ..., record_digest(record_n)])
predecessor_ledger_digest = lowercase-hex(
  SHA-256(UTF8(canonical_authorization_record_digests))
)
```

This complete canonical set and its digest are independent of authorization
evaluation time: crossing a grant's `valid_until` MUST NOT change either one.

**Operational resolution.** Credential-transfer authority is evaluated
separately at an explicit evaluation time. The resolver first validates the
authorization-ID history rules above, the target match, and the target's
currently active NID-bearing delegation. An invalid history is rejected. If
any revoke exists for a valid history, revocation is absorbing and the result
is revoked regardless of issue or evaluation time; greatest `issued_at`
selects the representative revoke and the lexicographically smallest decoded
`record_digest` wins a tie. Otherwise the same ordering selects the
representative grant. Only after choosing that representative does the
resolver require `evaluation_time < valid_until`; an expired representative
is rejected and an older grant is not substituted. These operational outcomes
MUST NOT alter or filter the canonical signed-record set. An old grant replayed
after a tombstone remains revoked.

**Ledger continuity across config-key rotation.** Before a config audience-key
/ `enc/<key_id>` rotation retires the predecessor branch, the new branch MUST
atomically commit the complete canonical signed-record set: the exact signed
record bytes and digests for every predecessor record, including expired
grants and tombstones, plus metadata containing the old `key_id`,
`predecessor_ledger_digest`, and the new record-set digest. The verifier MUST
reconstruct the complete predecessor set, verify its digest, and verify that
the successor set equals the predecessor set union only individually valid,
signed authorization records included in the same atomic commit. No
predecessor record may disappear. Only after that commit is canonical may one
signed-ref transition publish the new branch and retire/delete the old branch.

An implementation MUST refuse rotation and credential transfer if the complete
predecessor signed-record set, predecessor digest continuity, successor-set
equality, or atomic publication cannot be established. These rules instantiate
Core's rollback-detection and atomic-rotation requirements for this profile.

Before any credential transfer, the source MUST sync and verify canonical
config-repository state from its configured persona full nodes, resolve any
multi-writer heads under the repository's canonical-ref rules, replay the KEL,
verify the active durable NID delegation, and apply revoke-wins resolution.
If the current canonical state cannot be established because synchronization
is incomplete, refs conflict, or key state is provisional, the hook MUST hold
the request and transfer nothing. Invalid, revoked, expired, mismatched, or
NID-less state MUST be rejected.

Every device MUST re-evaluate the ledger after config-repository sync, so an
offline device will discover a revocation before its next credential transfer.
Credential transfer MUST stop if either authorization or delegation becomes
provisional, expires, is revoked, or no longer matches the target NID.

Only after the `credential-sync` hook returns `accept` may a self-DM transfer
the encrypted keys repository and its integrity metadata. The receiving
device MUST verify the presented record against the same current ledger state
and MUST keep key material encrypted at rest. This permission does not
authorize remote actions, configuration mutations, or application payloads.

<a id="comms-subprotocol-negotiation"></a>
## 9. Encrypted subprotocol negotiation and carrier

<!-- Split provenance: ADR-033 reqs 15 and 23-26; no monolith wire existed. -->

Generic subprotocol traffic is carried only as encrypted inner rumors in an
accepted DR session. Each carrier is a complete unsigned Nostr rumor with
exactly these outer members in this order: `id`, `pubkey`, `created_at`,
`kind`, `tags`, `content`. It MUST NOT include `sig` or any additional member.
`pubkey` is the session-authenticated sending device's publishing key;
`created_at` is an integer Unix timestamp; `tags` is an array and MUST contain
exactly one `["p","<recipient device publishing key>"]` tag.

`content` MUST be a JSON string whose decoded bytes are the canonical compact
JSON frame defined below; object-valued `content` MUST be rejected. To produce
and validate `id`, serialize `[0,pubkey,created_at,kind,tags,content]` by
NIP-01 using the content *string*, hash that NIP-01 serialization with SHA-256,
and require the lowercase digest to equal `id`. Authenticity comes from the
accepted encrypted DR session and transcript, not a rumor signature.

A negotiation frame MUST be processed before any payload for that protocol is
interpreted. The complete kind `31015` unsigned Nostr rumor form is:

```json
{
  "id": "<SHA-256 of the NIP-01 serialization>",
  "pubkey": "<sender device publishing key>",
  "created_at": 0,
  "kind": 31015,
  "tags": [["p", "<recipient device publishing key>"]],
  "content": "{\"spec_version\":\"comms/0.5.0\",\"protocol_type\":\"negotiation\",\"phase\":\"offer\",\"negotiation_id\":\"<32 lowercase hex>\",\"protocol_id\":\"<stable protocol id>\",\"supported_versions\":[\"<qualified or profile version>\"],\"required_features\":[\"<feature id>\"]}"
}
```

This is registry profile `comms-subprotocol-negotiation-v1`, discriminator
`content.protocol_type=negotiation`, evaluated after decoding the string.
Negotiation is an authenticated initiator/responder exchange over kind `31015`
with three phases: offer, selection, and confirmation. Every phase uses a
fresh rumor id, the same 16-byte lowercase-hex `negotiation_id`, and the same
accepted DR session.

1. **Offer.** The initiator sends the exact decoded member sequence shown in
   the example: `spec_version`, `protocol_type`, `phase`, `negotiation_id`,
   `protocol_id`, `supported_versions`, `required_features`. `phase` is
   `offer`; the arrays contain unique non-empty strings. Initiator offer order
   is normative preference from most to least preferred version.
2. **Selection.** The responder validates the offer and selects the first
   offered exact version it supports while also supporting all
   `required_features`; it MUST NOT reorder preference, choose an unoffered
   version, or remove a required feature. Its decoded sequence is exactly
   `spec_version`, `protocol_type`, `phase`, `negotiation_id`, `protocol_id`,
   `selected_version`, `required_features`, `offer_hash`, where `phase` is
   `selection` and `offer_hash` is defined below. No match rejects the
   negotiation without a selection.
3. **Initiator confirmation.** The initiator validates the selected exact
   tuple and hashes, then sends exactly `spec_version`, `protocol_type`,
   `phase`, `role`, `negotiation_id`, `protocol_id`, `selected_version`,
   `required_features`, `offer_hash`, `selection_hash`, `tuple_hash`, with
   `phase=confirmation` and `role=initiator`.
4. **Responder confirmation.** After processing the initiator confirmation,
   the responder echoes the same tuple and hashes in that exact schema with
   `role=responder` and appends `initiator_confirmation_hash`. The initiator
   processes and validates this responder confirmation.

All phase strings are non-empty UTF-8, `negotiation_id` is 16 bytes encoded as
32 lowercase hex, every hash is 32 bytes encoded as 64 lowercase hex, and the
selection/confirmation `required_features` array MUST be byte-identical to the
offer's canonical array. Missing, duplicate, unknown, misordered, or wrongly
typed phase members MUST be rejected.

The transcript hashes are lowercase SHA-256 hex:

```text
offer_hash = H("heterodyne-comms-offer-v1" || session_id || offer_rumor.id)
selection_hash = H("heterodyne-comms-selection-v1" || offer_hash || selection_rumor.id)
tuple_hash = H("heterodyne-comms-tuple-v1" || canonical_compact_json(
  [protocol_id, selected_version, required_features]))
initiator_confirmation_hash = H("heterodyne-comms-confirmation-v1" ||
  selection_hash || initiator_confirmation_rumor.id)
responder_confirmation_hash = H("heterodyne-comms-responder-confirmation-v1" ||
  initiator_confirmation_hash || responder_confirmation_rumor.id)
```

`H` is SHA-256. Each hash input uses UTF-8 and the displayed ASCII `||` is
concatenation, not data. A phase with a wrong role, order, tuple, session,
prior hash, or member set MUST reject and erase the pending negotiation state.
A duplicate phase is idempotent only when its rumor id and canonical content
are identical.

Both peers MUST NOT accept a `kind:31016` payload until both have processed a
confirmation: the responder processes the initiator confirmation before
sending its confirmation, and the initiator processes the responder
confirmation before sending or accepting payload. Every payload binds
`responder_confirmation_hash`; this proves to the responder that an initiating
sender processed the responder confirmation and prevents reordering a payload
ahead of mutual confirmation. A receiver that has not processed the matching
confirmation MUST reject the payload without interpretation. The chosen
protocol id, version, required features, all five hashes, session id, peer
identity, and rumor ids MUST be retained in encrypted local audit records for
at least as long as any payload decision derived from them.

After agreement, payload uses `kind:31016`, registry profile
`comms-subprotocol-payload-v1`, discriminator
`content.protocol_type=payload`:

```json
{
  "id": "<SHA-256 of the NIP-01 serialization>",
  "pubkey": "<sender device publishing key>",
  "created_at": 0,
  "kind": 31016,
  "tags": [["p", "<recipient device publishing key>"]],
  "content": "{\"spec_version\":\"comms/0.5.0\",\"protocol_type\":\"payload\",\"negotiation_id\":\"<32 lowercase hex>\",\"protocol_id\":\"<negotiated id>\",\"protocol_version\":\"<negotiated version>\",\"responder_confirmation_hash\":\"<64 lowercase hex>\",\"payload\":{}}"
}
```

The decoded payload frame MUST have exactly these members in the displayed
order: string `spec_version` equal to `comms/0.5.0`, string `protocol_type`
equal to `payload`, `negotiation_id`, non-empty string `protocol_id`, non-empty
string `protocol_version`, `responder_confirmation_hash`, and JSON value
`payload`. The id and hash encodings are those defined above and MUST match the
locally confirmed tuple. For both rumor kinds, a missing,
duplicate, unknown, misordered, or wrongly typed outer or decoded member MUST
be rejected before application processing. A mismatch, payload before
negotiation, unnegotiated feature, or transcript change MUST also be rejected
before payload interpretation.

Comms owns both carrier kinds. The Comms stamp is inside the canonical content
string and is their sole encrypted wire stamp. A higher-layer protocol,
including Control, MUST NOT add or own a wire stamp; the Comms stamp identifies
only the carrier version and conveys no higher-layer conformance.

<a id="comms-key-claims"></a>
## 10. Atomic typed-key claims

Comms defines an atomic assertion about one typed key. Registry revision 2
assigns `kind:31013` to `heterodyne-comms-key-claim-v1` and `kind:31014` to
`heterodyne-comms-key-claim-revocation-v1`. Both are addressable events. Their
sole `d` tag is the lowercase 64-hex claim identifier, and their JSON content
uses the single `comms/0.5.0` owner stamp. The outer Nostr signer MUST be the
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

The `heterodyne-comms-key-claim-v1` content is the exact closed object defined
by `schemas/comms/key-claim-v1.schema.json`. Its required members are
`claim_id`, `issuer`, `subject`, `claim_class`, `namespace`, `name`, `value`,
`issued_at`, `not_before`, `visibility`, `comms_version`, and
`registry_revision`. Optional members are `expires_at`, `audience`,
`resources`, `parent_claim_id`, `constraints`, and `revokers`. `claim_class`
is `descriptive` or `authorization`; `visibility` is `public`,
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

<a id="comms-claim-verification"></a>
### 10.1 Verification, trust, proof of possession, and state

Verification is ordered and fail-closed:

1. validate the closed JSON schema, owner version, registry revision, typed
   references, canonical claim ID, address, exact NIP-01 bytes, event ID, and
   outer signature;
2. require a `valid` Core/KEL authority result for the issuer at `issued_at`;
3. resolve and validate the complete chain in §10.2;
4. enforce time, audience, resource, namespace, operation, and subject-type
   constraints;
5. apply local trusted-issuer and trusted-namespace policy;
6. replay canonical private-ledger state and all reductions in §§10.3 and 11;
7. for authorization, verify a fresh native subject proof; and
8. return exactly one state: `invalid`, `untrusted`, `provisional`, `active`,
   `expired`, `revoked`, or `conflicted`.

Cryptographic validity is not trust. `untrusted` content MAY be displayed with
its provenance but MUST NOT authorize. A delivered persona-issued device grant
is `provisional` until repository-confirmed. Only `active` authorizes.

The proof-of-possession challenge is the canonical object with domain
`heterodyne-claim-pop-v1`, claim ID, nonce, audience, resource, operation,
`issued_at`, and `expires_at`. It MUST be fresh, single-use, audience- and
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
`expires_at`, subject type, visibility, and redelegation depth. It MUST NOT
start earlier, expire later, add an audience or resource, broaden a namespace
or purpose, change a descriptive assertion into authorization, or gain
redelegation implicitly. Missing ancestors, ambiguity, cycles, depth overflow,
or any non-strict attenuation makes the leaf `invalid`.

<a id="comms-claim-revocation"></a>
### 10.3 Irreversible revocation and reductions

The revocation content is the exact closed object in
`schemas/comms/key-claim-revocation-v1.schema.json`: `claim_id`, `revoked_at`,
registered `reason_code`, typed `revoker`, and an optional native `proof`.
`revoked_at` equals the event `created_at`; the sole address tag equals the
claim ID. A Nostr revoker signs the outer event. A Radicle or JWK revoker also
supplies its matching domain-separated proof over the revocation body.

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
`record_id`, `record_type`, `persona`, `writer_nid`, `created_at`, `parents`,
`payload`, `payload_digest`, and Ed25519 `signature`. Record types are `claim`,
`revocation`, `authority-reduction`, `reader-change`, `audience-key-epoch`,
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
NID-bearing `claim-ledger-reader` authorization. Onboarding is delivered over
an authenticated Double Ratchet self-session and binds the claim record,
repository RID, canonical checkpoint, current audience-key epoch and wrap,
compact-state digest, and Radicle fetch-and-seed access. The recipient verifies
all bindings before use. A delivered claim not reachable from canonical state
remains provisional.

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
continuity manifest bound. That bound MUST be at most 300 seconds. Loss or
reduction of any condition stops minting immediately.

The signing key MUST NOT be encrypted by or released merely with the ledger
audience key. Its envelope binds persona, repository, checkpoint, key epoch,
JWK thumbprint, ciphertext digest, active issuer-authority record set, and
per-recipient NID wraps. Removing an issuer rotates the envelope/key epoch and
excludes that NID. A node MUST unwrap only after replaying the exact bound
authority set and checkpoint.

Before returning a JWT, a writer durably commits an issuance reservation with
`jti`, client and request/release digests, signing-key ID, source claim IDs,
checkpoint, expiration, and the status allocation defined in §14. Returning a
token before that reservation is canonical is prohibited. Shared-key
compromise invalidates outstanding tokens, rotates signing material, updates
the public key set, and advances affected status lists.

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
audiences, scopes, sender-constraint policy, and pairwise sector. Implicit,
Resource Owner Password Credentials, and Client Credentials grants are
prohibited. Client Credentials is reserved for a future sender-constrained
workload profile and never authenticates a persona.

Authorization codes are short-lived, single-use, client- and redirect-bound,
and require an exact PKCE verifier. Device codes are client-bound, expire,
enforce polling intervals and `slow_down`, require an explicit approve/deny
decision, and are single-use. Authentication, consent, and repository state
MUST be rechecked before token return; a reduction observed after initial
approval wins.

Release is the intersection of requested scope and audience, registered client
policy, explicit consent, trusted namespaces, active canonical repository
state, and current proof requirements. Any absent input denies the claim. `sub`
is pairwise by default. Stable key release additionally requires scope
`heterodyne:key-ref` and explicit consent, and appears only as
`https://heterodyne.network/jwt/key-ref`. A client MUST NOT infer unreleased
claims, correlate pairwise subjects across sectors, or treat a descriptive
claim as authority.

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
only when it matches the verifier's expected nonce. A signed JWT assertion has
`typ` equal to `heterodyne-assertion+jwt` and an `assertion_profile` claim whose
exact non-empty value was allowed by the client's signed canonical registration
and equals the verifier-selected registered profile. An unregistered profile,
missing nonce, or type/profile/nonce confusion is rejected.

An access-token protected header has `typ` equal to `at+jwt` and `alg` equal to
`RS256`. Its claims include `iss`, pairwise `sub`, `aud`, `exp`, `iat`, `jti`,
`client_id`, and normalized `scope`, plus:

- `https://heterodyne.network/jwt/ledger-checkpoint`, binding the canonical
  private RID, `main`, commit and observation time;
- `https://heterodyne.network/jwt/status-mirror`, binding the public Radicle
  RID, `main`, manifest path and SHA-256 digest; and
- the draft-21 `status.status_list` reference from §14.

An ID Token instead enforces OIDC token-type and nonce rules and MUST NOT be
accepted where an access token is required. A projected JWT is an assertion
derived from current active claims, not a canonical encoding of the source
event. DPoP under RFC 9449 or mutual-TLS under RFC 8705 SHOULD bind access
tokens when supported. A DPoP-bound token's `cnf` is an exact one-member object
containing only canonical 32-byte base64url `jkt`; a mutual-TLS-bound token's
`cnf` is an exact one-member object containing only canonical 32-byte base64url
`x5t#S256`. A bearer token has no `cnf`. The verifier requires exact equality
with its expected confirmation and rejects missing, extra, mixed, or method-
confused members. A `cnf` claim MUST NOT be ignored by a bearer-only consumer.

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
`alg` `RS256`, and current `kid`. Claims are `sub` equal to the URI, `iat`,
`exp`, positive finite `ttl`, and `status_list` with `bits: 1` and `lst`.

`lst` is the unpadded base64url encoding of the deterministic zlib-wrapped
DEFLATE level-9 compression of the bit array. Bits are little-endian within each byte. Initial
values are `0` (`VALID`) and `1` (`INVALID`). Indices are contiguous within a
list, never reused, and allocated only in a durable issuance reservation at:

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
media type, canonical compression, bit width, and index bounds, then reads the
bit. Stale, missing, malformed, unverifiable, or mismatched status is failure,
not evidence of validity. `VALID` cannot override expiration, audience/type
failure, source-claim reduction, issuer compromise, or any other invalid state.

<a id="comms-security"></a>
## 15. Security invariants and forward-secrecy posture

<!-- Monolith provenance: §9.0-§9.1 and §9.5; namespaced by ADR-033. -->

Registry revision 2 defines these Comms invariants:

- **COMMS-I-TIER3-BLIND-CARRIER:** Tier 3 content is audience-key encrypted before reaching any repository, seed, full node, or relay.
- **COMMS-I-TIER2-HONESTY:** Tier 2 private repositories are selective-replication boundaries, not encryption, and clients present that trust boundary honestly.
- **COMMS-I-CONFIG-AT-REST:** Comms-owned non-key private state and audience or ratchet material are encrypted under the Comms repository-encryption profile.
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

Mechanism guarantees MUST remain distinct. Tier 3 has no forward secrecy: a
compromised audience key decrypts every retained post and index under its
`key_id`; rotation protects only later generations. Double Ratchet has forward
secrecy and post-compromise security subject to prompt message-key deletion.
NIP-17 fallback to a vanilla recipient has neither guarantee because its
static conversation key exposes past and future wraps. Clients MUST label a
fallback and MUST NOT infer one mechanism's guarantee for another.

<a id="comms-strict-profile"></a>
### 15.1 Comms strict profile

The stable Comms strict profile composes the Core strict profile. Its flattened
invariant membership is exact:

<!-- fixture:comms-strict-profile -->
```json
{
  "profile_id": "heterodyne-comms-strict-v1",
  "conformance_class": "Core+Comms",
  "state": "active",
  "requires_profiles": ["heterodyne-core-strict-v1"],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
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
    "COMMS-I-STATUS-INTEGRITY"
  ]
}
```

A `heterodyne-comms-strict-v1` implementation MUST meet
`heterodyne-core-strict-v1`, MUST present the Tier 2 plaintext-on-allowed-seeds
warning before publication, and MUST retain no retired message keys after the
Comms deletion points. Its capability advertisement MUST contain both profile
IDs. An implementation missing either condition MUST omit the Comms profile.

<a id="comms-conformance"></a>
## 16. Conformance

<!-- Monolith provenance: §14; family conformance: ADR-033. -->

A Comms conformance report MUST claim Core+Comms, name `comms/0.5.0`, pin
`core/0.5.0`, registry revision 2 or its immutable digest, and enumerate
supported features and strict profiles. A base implementation MUST implement
the envelope, tiers, publishing, feed, retrieval, hook, negotiation carrier,
and all sixteen security invariants. It MAY omit the `double-ratchet` feature;
one that advertises DMs MUST implement all of §7 and §8.

A report claiming `heterodyne-comms-strict-v1` MUST include the flattened
membership above, the Core prerequisite result, the Tier 2 warning result,
message-key deletion evidence when double-ratchet is advertised, and every
applicable strict-vector result. It MUST NOT claim the profile if any item is
missing.

Wire conformance is byte-exact. Semantically similar encodings do not conform.
An unknown Comms version or registry profile MUST be rejected or explicitly
degraded under Core unknown-version handling, never silently interpreted as
this version.
