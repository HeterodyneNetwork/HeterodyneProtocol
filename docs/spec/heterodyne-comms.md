# Heterodyne Comms Protocol Specification

Document ID: `comms`<br>
Version: `comms/0.5.0`<br>
Registry revision: `1`

> Pre-release extraction draft. Until family cutover, the archived 0.4.0
> monolith remains normative.

Normative dependencies: `heterodyne:core/0.5.0#core-conformance`.

This is the first Comms release descended from the Heterodyne 0.4.x monolith.
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
The outer event exposes only the wrap marker and opaque `key_id`; sensitive
content, tags, RID, audience association, and retrieval hints are encrypted.

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

A removal MUST generate a fresh audience key and `key_id`, publish the new
roster, redistribute `kind:31011` wraps only to remaining members, and publish
subsequent content under the new key. Joining SHOULD NOT rotate: the new
member receives the current generation. Rotation limits future exposure; it
does not revoke ciphertext encrypted under a key already possessed.

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

A Tier 3 post uses its ordinary Nostr content kind. Clear tags MUST contain
`["heterodyne_wrap","room_key.v2"]` and `["key_id","<id>"]`; only a `d`
tag required by an addressable upstream kind may be added. It MUST NOT expose
`room`, `matrix_room`, `rid`, `megolm_session_id`, semantic `e`/`p`/`t` tags,
or retrieval hints. Its encrypted inner JSON is exactly a `content` string
and `tags` array. Encryption happens before signing, so re-encryption is a new
intent and event id.

A receiver MUST select the audience key named by `key_id`, derive `post_key`,
decrypt and parse the closed inner object, reconstruct the logical event, and
then verify the outer signature and Core key authority. Possession of the key,
not current membership metadata, is the cryptographic access test.
`room_key.v1` and the withdrawn NIP-59 broadcast path MUST be rejected.

<a id="comms-config-repository"></a>
### 3.3 Config-repository protection profile

<!-- Monolith provenance: §3.8.6; payload ownership rewritten by ADR-033 req 6. -->

The config repository instantiates
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

<a id="comms-publishing"></a>
## 4. Publishing and delivery

<!-- Monolith provenance: §6.1-§6.4.1. -->

One publication intent MUST produce exactly one signed Nostr event, computed
once and fanned out unchanged. Implementations MUST NOT re-sign the same
intent. Tier 3 encryption precedes signing. The event `id` is the idempotency
token across ordinary and repo relays, and receivers SHOULD deduplicate on it.

The destination set contains the persona's configured ordinary write relays
and the appropriate repo relay. Tier 1 is sent to both. Tier 2 plaintext MUST
remain on allowed private-repo seeders and MUST NOT be sent to public relays.
Tier 3 ciphertext may be sent to both. Scheduling, batching, and retry are
implementation choices, but partial failure MUST be shown with destination
and reason; a generic unexplained partial-failure message is insufficient.

A Nostr write is permanently failed when a relay returns NIP-01 `OK=false`
with `invalid:`, `blocked:`, or `restricted:`, when `rate-limited:` exceeds
one hour, after three consecutive retry windows, or on application close code
4000-4999. Other failures are transient. An AUTH-required rejection is
transient before NIP-42 authentication and permanent if repeated afterward
(`auth_rejected_permanent`).

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
published to ordinary relays and its repo relay, with an empty `content` and a
`["spec_version","comms/0.5.0"]` tag.

```json
{
  "kind": 31007,
  "tags": [
    ["d", "<feed_id>:<page_id>"],
    ["heterodyne", "feed_index"],
    ["cold_root", "<persona cold root>"],
    ["rid", "<feed RID>"],
    ["e", "<event id>", "<relay hint>"],
    ["kel_head", "<accepted KEL event id>", "<seq>"],
    ["spec_version", "comms/0.5.0"]
  ],
  "content": ""
}
```

`d`, `heterodyne`, and `cold_root` are REQUIRED. `rid` SHOULD appear for a
repo-backed feed. Ordered `e` tags define the display order. A profile above
Comms declares which application events are indexed; absent such a profile,
persistent authored content SHOULD be indexed and ephemeral metadata SHOULD
not. An explicit `heterodyne_index=true|false` tag overrides that default.

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

A page MUST contain at most 500 entries and SHOULD contain 256. A chained page
uses `previous_index` and MUST include `prev_page_hash`, the SHA-256 of the
prior page's canonical NIP-01 bytes. The first page MUST omit the hash. A
verifier MUST check every page signature and hash; mismatch breaks the chain
with `page_chain_broken` and a visible feed-integrity error. A legacy missing
hash MAY be rendered only with an unverifiable-chain warning.

After a complete fetch attempt cannot resolve a prior page, the client MUST
show where history was truncated, continue from the newest resolvable page,
and MUST NOT call the result complete. Equal `(pubkey, kind, d, created_at)`
conflicts select the lexicographically smallest event id.

<a id="comms-private-index"></a>
### 5.3 Tier-specific indexes and descriptors

<!-- Monolith provenance: §6.7.3-§6.7.5 and §7.2. -->

Tier 1 and Tier 2 indexes are plaintext within their respective trust
boundaries. A Tier 3 index MUST encrypt its closed payload with `index_key`.
Clear tags are limited to opaque `d`, `heterodyne=feed_index`, `cold_root`,
`heterodyne_wrap=room_key.v2`, `key_id`, `kel_head`, and the Comms version
tag. RID, entries, hints, and previous-page data MUST be inside ciphertext.

The decrypted payload contains `spec_version`, `rid`, `page_id`, optional
`feed_label`, ordered `entries[{event_id,relay_hint}]`, and optional
`previous_index{event_id,prev_page_hash}`. A receiver MUST select and derive
the matching `index_key`, decrypt, require the expected RID, verify signature
and KEL authority, then traverse the decrypted chain.

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
persona's NIP-65 write and read relays, and eligible repo relays. A complete
fetch attempt queries `max(3, ceil(known_relays * 0.5))`, uses a default
10-second timeout, makes at most three retries (1/4/16 seconds RECOMMENDED),
and orders hints, write relays, then read relays. Clients MUST refresh changed
`kind:10002` relay lists before declaring the attempt complete.

Tier 3 fetches ciphertext then decrypts it. Tier 2 fetches only from an
allowed full node. A persona MAY advertise its own HTTPS archive; failure is
not a protocol error. If relay, repo, and explicitly advertised archive
channels fail, the object is permanently lost to the network and SHOULD be
shown as missing.

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

Registry revision 1 binds these immutable, non-stamping profiles:

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

An invite response is `kind:1059`. A `kind:1060` message is signed by the
current DH-ratchet key, not an epoch key, and carries the encrypted header and
NIP-44-v2 ciphertext. Current and next expected ratchet keys select a session.
Outer signers rotate at a DH step; messages within one ratchet epoch remain
linkable until that step.

Decrypted chat, reaction, receipt, and typing data are unsigned NIP-17-style
rumors. They are attributable through the authenticated session but provide no
transferable third-party authorship proof. Messages are sent to the recipient's
NIP-17 `kind:10050` DM relay list; a DM-capable persona SHOULD publish one.

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

The Comms-native default is: an already established, locally accepted peer
session may `accept`; a cryptographically valid new `ordinary-dm` is
`hold-as-message-request`; a valid credential request proceeds only under
§8.1; and `control-enrollment` is held unless a composed profile supplies a
stricter explicit authorization. Everything cryptographically invalid is
`reject`. Higher profiles MAY tighten these outcomes but MUST NOT turn a
Comms rejection into another result.

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

The authorization is a canonical compact-JSON object carried inside an
authenticated self-DM:

```json
{
  "type": "heterodyne.credential-sync.authorization.v1",
  "authorization_id": "<128-bit-or-greater random id>",
  "persona": "<cold-root npub hex>",
  "target_nid": "<did:key NID>",
  "purpose": "credential-sync",
  "issued_at": 0,
  "valid_until": 9999999999,
  "kel_head": {"event_id": "<KEL event id>", "seq": 0},
  "action": "grant",
  "signature": "<BIP-340 signature by the authoritative epoch key>"
}
```

The signature covers SHA-256 of the UTF-8 bytes
`heterodyne-credential-sync-authorization-v1|` followed by compact JSON of
all members except `signature` in the displayed member order. A verifier MUST
require the exact type and
purpose, target its own NID, require a unique authorization id, validate the
epoch signature and epoch authority at `issued_at`, validate `kel_head`,
require the target's active NID-bearing delegation, and require `valid_until`
to be later than the evaluation time. Unknown or duplicate members MUST be
rejected.

Revocation is the same signed object with the same `authorization_id`, target,
persona, and purpose, a later `issued_at`, `action:"revoke"`, and a current
`kel_head`. The latest KEL-valid object wins; a revoke wins an exact-time tie.
Revoking/expiring the underlying delegation immediately revokes the grant.
Credential transfer MUST stop if either authorization becomes provisional,
expires, is revoked, or no longer matches the target NID.

Only after the `credential-sync` hook returns `accept` may a self-DM transfer
the encrypted keys repository and its integrity metadata. The receiving
device MUST verify the transfer against the authorization and MUST keep key
material encrypted at rest. This permission does not authorize remote
actions, configuration mutations, or application payloads.

<a id="comms-subprotocol-negotiation"></a>
## 9. Encrypted subprotocol negotiation and carrier

<!-- Split provenance: ADR-033 reqs 15 and 23-26; no monolith wire existed. -->

Generic subprotocol traffic is carried only as encrypted inner rumors in an
accepted DR session. A negotiation frame MUST be processed before any payload
for that protocol is interpreted:

```json
{
  "kind": 31015,
  "content": {
    "spec_version": "comms/0.5.0",
    "protocol_type": "negotiation",
    "protocol_id": "<stable protocol id>",
    "supported_versions": ["<qualified or profile version>"],
    "required_features": ["<feature id>"]
  }
}
```

This is registry profile `comms-subprotocol-negotiation-v1`, discriminator
`content.protocol_type=negotiation`. Both peers MUST choose one mutually
supported version and all required features or reject the subprotocol. The
chosen protocol id, version, required features, session id, peer identity,
and transcript binding MUST be retained in encrypted local audit records for
at least as long as any payload decision derived from them.

After agreement, payload uses `kind:31016`, registry profile
`comms-subprotocol-payload-v1`, discriminator
`content.protocol_type=payload`:

```json
{
  "kind": 31016,
  "content": {
    "spec_version": "comms/0.5.0",
    "protocol_type": "payload",
    "protocol_id": "<negotiated id>",
    "protocol_version": "<negotiated version>",
    "payload": {}
  }
}
```

A mismatch, payload before negotiation, unnegotiated feature, or transcript
change MUST be rejected before payload interpretation. Comms owns both
carrier kinds and their sole encrypted wire stamp. A higher-layer protocol,
including Control, MUST NOT add or own a wire stamp; the Comms stamp identifies
only the carrier version and conveys no higher-layer conformance.

<a id="comms-security"></a>
## 10. Security invariants and forward-secrecy posture

<!-- Monolith provenance: §9.0-§9.1 and §9.5; namespaced by ADR-033. -->

Registry revision 1 defines these Comms invariants:

- **COMMS-I-TIER3-BLIND-CARRIER:** Tier 3 is audience-key encrypted before
  any repository, seed, full node, or relay receives it.
- **COMMS-I-TIER2-HONESTY:** Tier 2 is selective replication, not encryption,
  and its plaintext trust boundary is presented honestly.
- **COMMS-I-CONFIG-AT-REST:** Comms-owned non-key private state and audience
  or ratchet material use the Comms repository-encryption profile.
- **COMMS-I-CLIENT-SIDE-DELIVERY:** cross-backend processing is client-side;
  carriers receive no protected plaintext.
- **COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY:** feed, outbox, and delivery
  discovery require no central directory.

Mechanism guarantees MUST remain distinct. Tier 3 has no forward secrecy: a
compromised audience key decrypts every retained post and index under its
`key_id`; rotation protects only later generations. Double Ratchet has forward
secrecy and post-compromise security subject to prompt message-key deletion.
NIP-17 fallback to a vanilla recipient has neither guarantee because its
static conversation key exposes past and future wraps. Clients MUST label a
fallback and MUST NOT infer one mechanism's guarantee for another.

<a id="comms-conformance"></a>
## 11. Conformance

<!-- Monolith provenance: §14; family conformance: ADR-033. -->

A Comms conformance report MUST claim Core+Comms, name `comms/0.5.0`, pin
`core/0.5.0`, registry revision 1 or its immutable digest, and enumerate
supported features and strict profiles. A base implementation MUST implement
the envelope, tiers, publishing, feed, retrieval, hook, negotiation carrier,
and all five security invariants. It MAY omit the `double-ratchet` feature;
one that advertises DMs MUST implement all of §7 and §8.

Wire conformance is byte-exact. Semantically similar encodings do not conform.
An unknown Comms version or registry profile MUST be rejected or explicitly
degraded under Core unknown-version handling, never silently interpreted as
this version.
