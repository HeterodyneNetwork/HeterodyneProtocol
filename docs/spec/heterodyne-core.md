# Heterodyne Core Protocol Specification

Document ID: `core`

Core defines the common Nostr identity, canonical-byte, discovery,
repository, and conformance rules used by the Heterodyne protocol family.

<a id="core-scope"></a>
## 1. Scope and non-goals

Core defines:

- one active Nostr public key as a complete human or organizational persona;
- ordinary NIP-01 event validity and authorship;
- standard kind `0`, NIP-05, and NIP-65 kind `10002` discovery;
- source-neutral current-state selection across relays and repositories;
- exact-event publication, retry, and Radicle-backed storage;
- authorized Radicle writer-ref unions, public repo relays, and seed-NID trust;
- generic canonical JSON, typed-key, proof-byte, protected-repository, and
  key-envelope primitives;
- versioning, capabilities, security invariants, and conformance methodology.

Core does not define a parallel identity namespace, a required identity
pointer, a public feed index, a cold-root or KERI prerequisite, an alternate
Nostr author, or a centralized directory. It does not define application
payloads, private-message semantics, social policy, workspace governance, or
remote-control semantics. Standard Nostr relays, Radicle nodes, and Marmot
implementations require no Heterodyne-specific changes.

<a id="core-document-conventions"></a>
### 1.1 Document conventions

These conventions govern every document in the family.

**Family version.** The live draft family uses the single qualified version
`heterodyne/0.6.0`. Core, Assurance, Comms, Control, Social, and Workspace are
sections of that family rather than independent version lineages. Assurance
is optional; its absence does not reduce baseline Core conformance.

**Registry pin.** [`registry/`](registry/) allocates kinds, profiles, reason
codes, invariants, features, object types, and proof domains. A conformance
claim MUST pin the current revision or immutable entry-set digest from
[`registry/manifest.json`](registry/manifest.json). Specification prose, not
an ADR, is normative authority for the current draft.

**BCP 14.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are interpreted as
described by BCP 14 only when they appear in all capitals.

**Anchors.** Every referenceable location has an explicit HTML ID beginning
with its owner prefix: `core-`, `assurance-`, `comms-`, `control-`, `social-`,
or `workspace-`. Generated heading IDs are not stable protocol references.

**Qualified references.** A normative cross-document reference is
`heterodyne:<semver>#<anchor>`, for example
[`heterodyne:0.6.0#core-active-key-persona`](#core-active-key-persona).

**Layering.** Core depends on nothing. Assurance and Comms depend on Core.
Control and Social depend on Core and Comms. Workspace depends on Core and
Comms and may optionally compose Control and Social. Assurance is an optional
Core extension; the active key remains sufficient for baseline behavior. The
graph MUST remain acyclic.

<a id="core-terminology"></a>
## 2. Shared terminology

- **Active persona key**: the exact 32-byte x-only secp256k1 public key that
  currently identifies one persona and signs that persona's Nostr events.
- **Persona**: one human or organization identified by one active persona key.
  An ordinary active key with no Heterodyne extension or Assurance state is a
  complete persona.
- **NID**: a Radicle Ed25519 node identity encoded as canonical `did:key`.
- **RID**: a Radicle repository identifier encoded as canonical `rad:z...`.
- **Repository owner**: the persona or higher-layer group whose authenticated
  policy authorizes writer NIDs for one logical repository.
- **Writer ref**: a Radicle ref signed by one authorized NID and containing
  exact signed Nostr events.
- **Repo relay**: a standard NIP-01 websocket endpoint whose durable event
  store is backed by a Radicle event repository.
- **Full node**: a policy and authority node that may manage isolated persona
  vaults and repositories.
- **Seed node**: an availability provider identified for Heterodyne trust by
  a configured Radicle NID. A seed may host repositories and relays without
  becoming a persona, repository owner, or group administrator.
- **Qualified version**: `<document-id>/<semver>` for document-qualified
  capabilities, distinct from the family version `heterodyne/<semver>`.

A Nostr public key that signs an event is its NIP-01 author. A client key,
agent key, delegate key, seed NID, repository RID, relay identity, optional
Assurance key, or local account correlation MUST NOT replace, rewrite, or
alias that author.

<a id="core-registry"></a>
## 3. Registry, allocation, and canonical bytes

The registry is separately revisioned from the specification. Adding or
promoting an entry does not change the family version. Implementations MUST
resolve an allocated kind or profile through the pinned registry and MUST NOT
infer ownership from a numeric range.

Every Heterodyne-defined addressable Nostr kind uses the ordinary NIP-01
coordinate `(pubkey, kind, d)`. A singleton uses `['d', '']`; a
multi-instance profile defines a non-empty `d`. This rule never changes the
meaning of `pubkey` as the actual signing key.

[`registry/features.json`](registry/features.json) is the allocation authority
for feature IDs. An unregistered feature string grants no capability.

<a id="core-canonical-serialization"></a>
### 3.1 NIP-01 serialization and `nip01_raw`

Every Nostr event MUST be hashed and signed over the UTF-8 bytes of the compact
RFC 8259 JSON array:

```text
[0,pubkey,created_at,kind,tags,content]
```

Tag order is producer-selected and MUST NOT be reordered. The event `id` is
SHA-256 of those exact bytes and `sig` is the BIP-340 signature over that
32-byte digest. Heterodyne defines no substitute canonicalization.

Whenever a Nostr event is embedded in another JSON object, the container MUST
include a sibling `nip01_raw` string containing the exact array bytes that
were hashed. A verifier MUST hash `nip01_raw`, verify `id` and `sig`, parse the
array, and require every exposed event field to match. Missing raw bytes,
reconstruction from parsed fields, normalization, or mismatch is rejection.

<a id="core-version-stamps"></a>
### 3.2 Owner stamps and upstream bytes

An event carries at most one Heterodyne version stamp. Ownership selects the
applicable registered schema or profile and its stamp placement; it never
selects a different Nostr signature or author.

1. Heterodyne-defined JSON `content` MUST carry the exact family
   `spec_version` required by its registered schema.
2. A Heterodyne-allocated kind with empty or non-JSON content MUST carry
   exactly `['spec_version', 'heterodyne/0.6.0']` when its registry entry
   requires stamping.
3. An adopted upstream kind is unstamped unless an immutable registered
   stamping profile opts it in.
4. Ordinary kind `0`, kind `10002`, NIP-42 AUTH, and adopted Marmot transport
   events retain their upstream wire shapes. A Heterodyne profile extension
   does not by itself add a version tag.
5. A registered non-stamping production profile changes no signed byte and
   cannot be inferred from relay bytes.

An unqualified or unsupported family stamp names no supported protocol
version. A consumer MUST reject a stamped Heterodyne object unless the stamp,
schema, and registered discriminator agree. Unknown data in an upstream-open
kind remains governed by that upstream kind's compatibility rules.

<a id="core-wire-keys"></a>
### 3.3 Canonical wire keys and identifiers

Every NIP-01 `pubkey`, `p` tag, address coordinate, and Heterodyne wire field
naming a Nostr key is exactly 64 lowercase hexadecimal characters encoding a
32-byte x-only secp256k1 public key. `npub` is a NIP-19 presentation encoding
for text and interfaces; it MUST NOT replace the hexadecimal wire value.
Uppercase, bech32 in a hex field, truncation, or normalization is rejection.

A Radicle NID uses canonical Ed25519 `did:key:z...`. A canonical RID is the
literal `rad:z` prefix followed by Base58BTC for exactly the 20 raw bytes of
its Git SHA-1 repository object identifier, without a multicodec prefix.
Decode and re-encode MUST reproduce the exact body and leading-zero markers.

A canonical NIP-19 `naddr` is lowercase Bech32 with HRP `naddr`, a valid
checksum, and valid NIP-19 TLV payload. A verifier MUST decode its identifier,
author public key, kind, and optional relay hints and MUST require re-encoding
those exact canonical TLVs to reproduce the input. Pattern matching alone is
not canonical-address validation.

<a id="core-canonical-json"></a>
### 3.4 Canonical JSON

Every JSON object defined by this family outside NIP-01 event serialization is
UTF-8 RFC 8785 JCS. Before signing, a producer MUST reject duplicate names,
non-integer numbers where integers are required, unknown members in a closed
schema, and values outside the schema. A consumer MUST validate the applicable
schema before evaluating authority or acting on the object.

<a id="core-typed-key-references"></a>
### 3.5 Typed-key references and native proof hooks

Core defines these initial typed-key references:

| Type | Canonical value | Native verifier |
|---|---|---|
| `nostr-secp256k1` | 64-lowercase-hex x-only public key | BIP-340 |
| `radicle-ed25519-nid` | canonical Ed25519 `did:key:z...` NID | strict RFC 8032 Ed25519 |
| `jwk-thumbprint` | unpadded base64url RFC 7638 SHA-256 thumbprint | JWS using a public JWK with the same recomputed thumbprint |
| `marmot-mls-leaf` | unpadded base64url SHA-256 of the exact TLS-serialized MLS `LeafNode` | MLS leaf signature, Marmot account proof, and membership in the bound group context |

A parser MUST reject an unknown type, non-canonical value, private JWK member,
remote JWK reference, or suite mismatch. The supported public-JWK profiles are
Ed25519/EdDSA, P-256/ES256, and RSA of at least 2048 bits/RS256. A protected
JWS header is the closed object containing only the matching `alg`. `none`,
HMAC/HS, `oct`, a wrong curve, weak RSA, private material, or extra protected
header data is invalid.

The caller supplies complete proof bytes and an expected reference. Core
returns `valid` or `invalid` plus the verified key reference and suite.
Freshness, replay, purpose, trust, and permission remain caller policy.

<a id="core-proof-bytes"></a>
### 3.6 Domain-separated proof bytes

Every Heterodyne proof that is not an ordinary NIP-01 event signature signs:

```text
<domain> || 0x00 || JCS(<claim>)
```

`<domain>` is an allocated US-ASCII proof-domain string with no zero byte.
`<claim>` contains exactly the registered bound members and no proof member.
When a construction signs a digest, it signs SHA-256 of these same bytes.

A proof domain is lowercase kebab-case, begins `heterodyne-`, ends `-v<N>`,
and is allocated in [`registry/proof-domains.json`](registry/proof-domains.json)
with its bound members and suites. A verifier MUST reject an unknown domain,
missing or extra bound member, non-JCS claim, or unregistered suite.
Positional and delimiter-joined proof inputs are forbidden.

<a id="core-structured-outcome"></a>
### 3.7 Structured client outcomes

A retry condition that is not a verdict on received bytes uses this shape:

```json
{
  "outcome_class": "<stable lowercase kebab-case class>",
  "subject": {},
  "attempted_at": 0,
  "deadline_at": 0,
  "last_attempt_at": 0,
  "retry_state": "retrying",
  "terminal_cause": null,
  "allowed_actions": []
}
```

`retry_state` is `retrying` or `terminal`; `terminal_cause` is non-null only
for `terminal`; `allowed_actions` is a non-empty array of stable identifiers.
The outcome is localizable and MUST NOT be substituted for a registered
reason code.

<a id="core-identity-model"></a>
## 4. Active-key persona identity

<a id="core-active-key-persona"></a>
### 4.1 Active-key persona

A Heterodyne human or organization persona is identified by exactly one active
Nostr public key. The active key is the persona's npub, NIP-01 author, and
Marmot account identity. It authors the persona's profile, relay list, public
events, lists, KeyPackages, and Marmot account-to-leaf proofs.

A bare active key is complete and first-class. Baseline validity MUST NOT
depend on a cold root, KERI state, succession authority, witness set,
threshold, epoch key, repository, Heterodyne profile extension, or Assurance
claim. A verifier resolves baseline persona authorship exactly when
`event.pubkey === active_persona_key` after NIP-01 identifier and BIP-340
verification.

An agent key is a distinct Nostr author. A client or delegated key that signs
directly is likewise the actual author. Association metadata can describe a
relationship but cannot replace the `pubkey`, merge address namespaces, or
make one key's signature an event by another.

<a id="core-full-node-control"></a>
### 4.2 Full-node persona isolation

A full node MAY manage zero or more persona vaults. Each vault MUST isolate
its active key, repositories, relay configuration, signer policy, optional
Assurance state, agents, and audit state. Every authorization binds one exact
persona, selected signing key, key class, and permission set. Cross-vault
lookup or fallback is forbidden. Operating a vault does not make the node the
persona, and hosting a repository does not authorize event signing.

Full-node Control and recovery metadata are owned by Control, not inferred
from Core identity or repository state. A light-only Control principal is
not a Core device and receives no active persona key, NID secret,
repository-owner authority, or seed trust merely by authenticating to a full
node.

<a id="core-assurance-composition"></a>
### 4.3 Optional Assurance composition and succession

Assurance is an optional document layered on Core. An existing active key MAY
attach Assurance later without changing its npub or historical events.
Assurance may prove enhanced continuity or recovery to clients that request
that claim, but it MUST NOT change NIP-01 signature, authorship, addressing,
filtering, replacement, or Marmot membership rules.

A successor active key is a new Nostr identity. Events and replaceable
coordinates remain under their original author keys. Follows, trust,
moderation, group state, financial authority, repositories, and subordinate
keys do not transfer silently. A client MAY present a verified Assurance
history while preserving those boundaries.

The optional kind-0 fields `identity_chain`, `cold_root`, and
`succession_authority` are signed discovery hints only. Their absence,
removal by a vanilla client, invalidity, or conflict MUST NOT invalidate the
active key or a baseline event.

<a id="core-kel-rotation"></a>
Historical rotation-breadcrumb producer checks retain the registered refusal
names `successor_persona_mismatch`, `retiring_key_nip05_invalid`, and
`compromise_rotation_breadcrumb_forbidden` for validation of already authored
pre-redesign material. Those codes do not define current active-key
succession, authorize a breadcrumb, or make legacy rotation state a Core
baseline prerequisite.

<a id="core-kel-verification"></a>
Cold-root inception, KERI event logs, pre-rotation, witnesses, epoch authority,
compromise windows, and continuity verification are not Core baseline
mechanisms. A composition that evaluates those claims MUST use Assurance and
MUST first complete Core active-key verification. Core does not allocate a KEL
authority window for ordinary Nostr events.

<a id="core-threshold-authority"></a>
### 4.4 Threshold custody and repository thresholds

Several custodians MAY jointly produce the ordinary BIP-340 signature of one
active persona key. Threshold custody is an implementation choice; the public
result remains one NIP-01 event by that key.

Radicle repository identity documents MAY separately use their native
delegate and ref thresholds. Those thresholds authorize Radicle state only.
They MUST NOT create or replace a Nostr persona, alter event authorship, or
make a storage ref authoritative over a valid newer Nostr event. A
higher-layer group MAY define its own authorization policy without weakening
these separations.

<a id="core-identity-discovery"></a>
## 5. Standard profile, NIP-05, and NIP-65 discovery

Core discovery starts with an active key directly or with a NIP-05 name and
uses ordinary Nostr state:

1. resolve the active key directly or through NIP-05;
2. fetch valid kind `0` and kind `10002` candidates from known relays;
3. select current state source-neutrally under [§6](#core-source-neutral-selection);
4. query the selected write relays with ordinary NIP-01 filters; and
5. optionally fetch the advertised profile repository or an Assurance chain.

Repository and Assurance steps are optional. Failure of either leaves valid
relay-derived Nostr state usable as ordinary upstream Nostr state. When the
selected kind `0` contains a valid `heterodyne.profile` RID, however, a client
MUST NOT mint a repository-bound canonical Heterodyne profile view until the
exact selected event is also observed on that RID through a currently
authorized writer ref. This does not invalidate the signed relay event; it
prevents an unauthenticated carrier from standing in for the advertised
repository state.

<a id="core-persona-profile"></a>
### 5.1 Kind `0` profile and the closed extension

Every persona SHOULD publish an ordinary replaceable kind `0` profile signed
by its active key. Standard and third-party fields remain upstream-open.

The content MAY contain one `heterodyne` object defined by
[`schemas/core/persona-profile-v1.schema.json`](schemas/core/persona-profile-v1.schema.json).
When the object is present, `profile` is required and no unknown member is
allowed:

| Member | Canonical value | Meaning |
|---|---|---|
| `profile` | canonical `rad:z` RID | Persona-owned profile and public event-repository root |
| `identity_chain` | canonical NIP-19 `naddr` | Current optional Assurance chain address |
| `cold_root` | 64-lowercase-hex x-only key | Optional attached-root discovery hint |
| `succession_authority` | 64-lowercase-hex x-only key | Optional succession-authority discovery hint |

An invalid `heterodyne` object is ignored as a whole. It MUST NOT invalidate
the surrounding correctly signed kind `0`, its upstream fields, the persona,
or previously pinned Assurance state. Every extension value is a hint signed
by the active key, not independent authority. A client MUST semantically
validate canonical RID and `naddr` encodings in addition to the schema's
structural boundary.

A canonical-profile selection authority MUST capture bounded, closed
candidate descriptors; verify every candidate's exact NIP-01 ID and signature;
authenticate every repository candidate against its exact RID and ref; union
relay and authenticated-repository candidates without carrier priority; and
apply the NIP-01 replacement rule to that union. It derives the repository
requirement solely from the selected signed profile's valid extension. A
request boolean, repository label, cache entry, clone, or object mutation MUST
NOT assert that requirement or satisfy it. If the selected profile advertises
a repository but its exact event lacks current authenticated repository
carriage, selection fails with `profile-repository-selection-required`.

<a id="core-nip05-discovery"></a>
### 5.2 NIP-05

NIP-05 is a DNS-based name-to-active-key mapping, not an event type. The
`/.well-known/nostr.json` response maps the selected name to the exact active
persona key. Optional relay entries are bootstrap hints and do not override
NIP-65. When an active key changes, the operator updates the mapping; vanilla
clients correctly observe a new npub.

NIP-05 does not authorize an event, repository, successor, or Assurance claim.
Those decisions require their own signed evidence.

<a id="core-nip65-discovery"></a>
### 5.3 NIP-65 outbox discovery

Every publishing persona SHOULD maintain a standard replaceable kind `10002`
relay list signed by its active key. `r` tags and optional `read` or `write`
markers retain NIP-65 semantics. A publicly reachable repo relay is listed as
an ordinary relay URL; vanilla clients need no repository awareness.

The list SHOULD remain small enough for conventional clients. Kind `0` and
kind `10002` MUST be spread to ordinary index relays and, when configured,
stored unchanged in the persona repository.

<a id="core-discovery-refresh"></a>
### 5.4 Seven-day refresh and warning

A Heterodyne publishing client MUST refresh kind `0` and kind `10002` at least
once every seven days, even when content is unchanged. A local signer,
standard NIP-46 service, or full node MAY schedule the refresh.

Passing the seven-day boundary produces a visible staleness or liveness
warning. It MUST NOT invalidate, demote, or hide the last correctly signed
profile or relay list. A refresh is a newly signed replaceable event; a client
MUST NOT alter `created_at` or replay an old signature as though it were new.

<a id="core-identity-pointer"></a>
### 5.5 Retired identity pointers and public feed indexes

Required kind `31005` identity pointers and kind `31007` public feed indexes
are retired from the current Core baseline. A conforming client MUST NOT
require either kind for persona resolution, profile discovery, outbox
discovery, event retrieval, current-state selection, or repository use.

Historical events of those kinds remain ordinary signature-verifiable Nostr
events. They do not override current kind `0`, NIP-05, kind `10002`, NIP-01
filters, or active-key authorship. A producer MAY preserve old bytes for
history but MUST NOT publish a required-current pointer or feed index as Core
authority.

<a id="core-source-neutral-selection"></a>
## 6. Source-neutral state selection

Relay and repository carriers expose candidates; they do not vote on current
state. A client MUST union every locally verified candidate from every
reachable carrier, deduplicate by event ID, and apply NIP-01 replacement rules
without source priority:

- ordinary events coexist by event ID;
- replaceable events use `(pubkey, kind)`;
- parameterized replaceable events use `(pubkey, kind, d)`; and
- within one replaceable coordinate, greatest `created_at` wins, with lowest
  lexicographic event ID winning a tie.

Only events with valid structure, identifier, and signature enter the union.
The rule is identical whether a candidate arrived from an ordinary relay, a
repo relay, or native repository access.

<a id="core-created-at-bound"></a>
Selection additionally applies a premature-candidate bound. A candidate whose
`created_at` exceeds the verifier's trusted current time by more than 900
seconds MUST NOT enter the selection union. The candidate is quarantined, not
invalidated: the verifier retains it, reports `core-created-at-premature`, and
the candidate re-enters selection automatically once its `created_at` is
within bound, if it is still a candidate then. A verifier whose known clock
uncertainty exceeds 900 seconds fails closed for selection that this bound
would decide. Quarantine changes candidate admission only; it does not alter
NIP-01 cryptographic validity, and the kind `0`/`10002` seven-day refresh duty
is unchanged and caps the residual effect of a later-activating quarantined
candidate at one refresh interval.

When reachable, a repository is the preferred durable reconciliation target,
not a priority override. A newer valid relay event missing from the repository
wins immediately and makes the repository stale until an authorized writer
ingests the exact event. Repository unavailability never makes valid relay
state unusable.

<a id="core-nip03-advisory"></a>
### 6.1 Advisory NIP-03 interoperability

An independent NIP-03 implementation MAY display evidence that a commitment
to an unsigned NIP-01 event existed no later than a confirmed block.
Heterodyne defines no timestamp-authority feature or kind `1040` profile and
assigns that evidence no protocol authority. It MUST NOT decide replaceable
selection, Assurance enrollment or continuity, permanent event rejection,
when an event was signed, published, or observed, whether its `created_at` is
truthful, whether competing events are complete, or a precise wall-clock time
derived from a block header. Heterodyne selection and Assurance ignore it.

The non-absorbing 900-second quarantine in
[`heterodyne:0.6.0#core-created-at-bound`](#core-created-at-bound) depends only
on the verifier's trusted current time and remains the sole Core
future-candidate bound.

<a id="core-publication-retry"></a>
## 7. Exact-byte publication, retrieval, and retry

One publication intent produces exactly one signed Nostr event. The producer
serializes it once and fans out the same event bytes, `id`, `sig`, and
`nip01_raw` to every destination without re-signing or normalizing.

Public destinations include the author's selected NIP-65 write relays,
applicable recipient read relays, a repo relay already present in kind
`10002`, and any other explicitly selected ordinary relay. A repository-backed
relay receives the same standard NIP-01 `EVENT` submission as another relay.

Partial delivery succeeds when at least one intended destination accepts the
event. Failed destinations remain eligible for retry using exactly the same
bytes and event ID. If no destination accepts, the event remains locally
pending. Retry MUST NOT change `created_at`, tags, content, signature, or ID.

Retrieval queries ordinary and repository relays with standard filters,
verifies every event locally, deduplicates by event ID, and applies
[§6](#core-source-neutral-selection). A relay acknowledgement or repository
ref proves storage only; it never proves authorship.

<a id="core-repository-union"></a>
## 8. Radicle event repositories

A logical Nostr event repository belongs to one persona or higher-layer
group. Its RID is a stable storage locator, not an identity. A persona holding
repository-owner policy authority SHOULD attach a window-complete Assurance
enrollment; a client MUST surface an unenrolled high-authority persona
distinctly. Its accepted
logical contents are the union of currently authorized Radicle writer refs:

- every native writer uses its own NID and signed ref;
- a relay-ingest seed uses its own NID and designated ingest ref;
- every ref contains exact signed Nostr event bytes and retained `nip01_raw`;
- events are deduplicated by Nostr event ID;
- replaceable state is derived under [§6](#core-source-neutral-selection);
- unauthorized, malformed, or revoked refs do not enter the union; and
- derived indexes are rebuildable and non-authoritative.

There is no merged event branch whose committer becomes the event author.
Writer authorization and repository ownership are distinct. The repository
owner's authenticated policy fixes the currently authorized writer NIDs and
refs. A persona-owned repository policy is authorized by the active persona
key; a group repository's owning document defines its administrator evidence.
Adding a writer does not grant persona signing, repository ownership, group
administration, or content-decryption authority.

Repository access controls replication. Nostr signatures establish public
event integrity, and higher-layer encryption establishes confidentiality.
Making a repository private does not by itself encrypt its Git objects.

<a id="core-nid-delegation"></a>
### 8.1 Writer-NID authorization

The authority-file object `heterodyne.core.repository-writer-binding.v1`
MUST validate against
[`schemas/core/repository-writer-binding-v1.schema.json`](schemas/core/repository-writer-binding-v1.schema.json).
It is the closed object with exactly these members:

```json
{
  "profile": "heterodyne.core.repository-writer-binding.v1",
  "spec_version": "heterodyne/0.6.0",
  "owner_active_key": "<64-lowercase-hex x-only key>",
  "repository_rid": "<canonical rad:z RID>",
  "writer_nid": "<canonical Ed25519 did:key NID>",
  "ref_namespace": "refs/<canonical permitted namespace>/",
  "operations": ["claim-ledger-write"],
  "issued_at": 0,
  "expires_at": 1,
  "owner_signature": "<128-lowercase-hex BIP-340 signature>",
  "nid_signature": "<128-lowercase-hex Ed25519 signature>"
}
```

`operations` MUST be non-empty, strictly lexicographically sorted, and unique.
Both times MUST be nonnegative safe integers and `expires_at` MUST be greater
than `issued_at`. `repository_rid` MUST use the `rad:z` prefix; its Base58btc
payload MUST decode to exactly 20 bytes and re-encode byte-for-byte to the
presented payload. Alphabet membership alone is insufficient.

`ref_namespace` is a canonical vanilla Git ref namespace prefix. It MUST begin
`refs/`, end in `/`, contain valid UTF-8, and contain at least one complete
component after `refs`. Every complete component is nonempty, is neither `.`
nor `..`, does not begin or end with `.`, and does not end with `.lock`.
The namespace MUST NOT contain `..`, `@{`, duplicate `/`, backslash, a control
or space character, or any of `~^:?*[`. A requested writer ref MUST satisfy
the same vanilla Git component rules without a trailing `/` and MUST be a
strict descendant of the namespace, not the namespace itself.

The unsigned body is the exact closed object above with
`owner_signature` and `nid_signature` deleted. The registered proof domain
`heterodyne-core-repository-writer-binding-v1` applies [§3.6](#core-proof-bytes)
to that body. The active repository owner makes `owner_signature` with
BIP-340 over SHA-256 of those proof bytes. The Ed25519 key that derives the
exact canonical `writer_nid` makes `nid_signature` over the identical proof
bytes. Both proofs are required before the ref enters the union; a proof over
a reserialized, partial, additional-member, differently ordered-operation, or
different-domain body grants nothing.

Resolution is repository-local. A verifier captures the presented object and
request once as closed ordinary data, verifies both proofs from that immutable
capture, and obtains the current authenticated repository-owner policy from a
locally configured resolver. The caller supplies only the exact active owner
key, RID, writer NID, writer ref, and requested operation. It MUST NOT supply
or assert policy activity, writer activity, conflict or revocation booleans,
policy revision, predecessor, or checkpoint.

The resolver result MUST bind the same active owner and RID, a non-revoked and
non-conflicted policy state, an exact revision, predecessor, and checkpoint,
and exactly one active inclusion of the writer NID, ref namespace, and
operation. The verifier's trusted current time MUST satisfy
`issued_at <= trusted_now < expires_at`. A successful resolution produces an
opaque, authority-instance-bound current binding that privately retains the
exact wire digest, request, and complete policy fingerprint. Before replay or
another authority effect, the same authority instance MUST recapture the
source, reload the current policy, and reject a changed source, owner, RID,
writer, ref, operation, revision, predecessor, checkpoint, inclusion,
revocation, conflict, or policy fingerprint. A clone or binding from another
authority instance is invalid.

Any closed-object, proof, NID derivation, time, request, current-policy, clone,
or revalidation failure returns the coarse registered reason
`repository-writer-binding-invalid`. Implementations MAY retain more specific
detail in a privileged local audit, but MUST NOT expose it as additional wire
authority.

This binding authorizes only the named writer NID, repository RID, ref
namespace, and operations while the exact current policy remains active. It
does not grant Nostr authorship, persona or repository ownership, Workspace or
group governance, content-decryption authority, Assurance authority, hosting
trust, or directory status. The resolver is not a network trust or discovery
service, and vanilla Nostr relays and standard Radicle nodes require no
Heterodyne-specific change.

Legacy epoch-authorized kind `31001` delegation is not a Core baseline
prerequisite. A higher-layer or Assurance profile MAY define additional
delegation semantics, but it cannot weaken the repository-owner and NID
proofs, change Nostr authorship, or make a seed an owner.

For byte-level compatibility, the allocated historical proof domain
`heterodyne-nid-binding-v1` remains defined as [§3.6](#core-proof-bytes) over
this exact closed claim:

```json
{
  "cold_root": "<64-lowercase-hex key>",
  "nid": "<canonical Radicle NID>"
}
```

This retained proof-byte definition permits historical validation and
optional Assurance composition. It does not authorize a baseline persona,
writer ref, repository, or event. Current writer authorization MUST bind the
RID, ref namespace, operations, and owner evidence as stated above; a profile
using the legacy two-member proof alone grants nothing.

<a id="core-repo-relay"></a>
### 8.2 Public repo relay

A public repo relay is a standard NIP-01 websocket relay backed by an event
repository. It MUST accept and return ordinary unmodified Nostr event objects,
support the ordinary filters it advertises through NIP-11, and preserve the
stored signing input. It MUST NOT require clients to speak Git, Radicle, or a
Heterodyne envelope protocol.

The relay persists accepted submissions through one authorized NID writer ref.
It MUST NOT add a storage signature to the Nostr object, substitute its NID or
relay key as author, or reconstruct a different event. When transport permits,
it SHOULD emit the stored event object byte-for-byte; any enclosing NIP-01
frame does not change the event fields or `nip01_raw`.

Public read access MAY be open. Write admission, retention, quota, and NIP-42
policy are relay policy and MUST be disclosed through normal NIP-11 or local
configuration. A persona selects a repo relay by listing it in kind `10002`;
the relay does not become authoritative merely by serving the RID.

<a id="core-node-advertisement"></a>
### 8.3 Seed NID trust and endpoint advertisements

<a id="core-seed-nid-trust"></a>
A Heterodyne trust decision for a seed is anchored to a locally configured or
owner-authorized canonical Radicle NID. A relay identity, DNS name, TLS
certificate, endpoint URL, repository head, or advertisement MUST NOT create
trusted-seed status. Several seed NIDs MAY be trusted concurrently and each
retains independent endpoints, grants, and writer refs.

A seed endpoint advertisement MAY use registered kind `31010`. Its NID proof
uses domain `heterodyne-node-advert-v1` over the exact JCS claim:

```json
{
  "endpoint": "<endpoint>",
  "expiry": "<canonical decimal unix second>",
  "nid": "<canonical Radicle NID>",
  "repo_head": "<40-lowercase-hex Git object id>",
  "rid": "<canonical RID>"
}
```

The outer Nostr event is a transport object and its signing key does not gain
seed or persona authority. A verifier MUST check the outer NIP-01 event, the
strict Ed25519 NID proof, equality of all bound fields, canonical encodings,
and that the NID is already trusted for the advertised RID. The expiry MUST be
strictly after `created_at`, no more than 86,400 seconds later, and verifier
time MUST be before expiry. First acceptance requires `created_at` within
plus or minus 300 seconds of verifier time; a verifier with greater known
clock uncertainty fails closed. `repo_head` is a possession snapshot, and the
endpoint MUST serve a graph containing it while the advertisement is valid.

An advertisement carries no `kel_head` and requires no cold-root or epoch
authority. It grants availability only. Invalid, expired, untrusted,
proof-mismatched, or unserved advertisements are ignored.

<a id="core-node-roles"></a>
### 8.4 Full nodes, seed nodes, and client roles

A full node may manage isolated persona vaults, signing policy, repositories,
and optional higher-layer services. A seed node hosts repositories and may
offer a public repo relay. One deployment may implement both roles, but their
grants and conformance claims remain independent.

Core's registered implementation roles remain:

| Role | Required behavior | Tor requirement |
|---|---|---|
| `public-reader` | Read and locally verify public Nostr events | outbound Tor recommended; omission is a visible downgrade |
| `authenticated-light` | Ordinary-relay read/write, local verification, and user-selected authenticated higher-layer sessions | outbound Tor recommended; omission is a visible downgrade |
| `full-node` | Store accepted repositories, use repo-relay clients, and provide its claimed services | outbound Tor and persistent onion hosting required by the registered features |

A role advertisement MUST claim only implemented registered features. A seed
capability not yet allocated by the registry is configuration, not a
conformance claim.

<a id="core-recovery"></a>
### 8.5 Availability recovery

Loss of one repository host is routed around through another authorized seed
or ordinary relay. After total repository loss, valid relay events remain
usable and MAY initialize a replacement persona-owned repository authorized by
the active key. This recovers availability, not secret material or identity
continuity. Recovery from active-key compromise is outside Core baseline and
requires explicit higher-layer reset plus optional Assurance continuity.

<a id="core-protected-repository"></a>
## 9. Protected repositories and key storage

Core defines a generic encrypted-repository primitive. An instantiating
profile MUST specify a unique profile ID, plaintext-schema owner,
authenticated-encryption byte format, key identifier, lifecycle, authorized
decryptors, ref layout, rollback detection, and atomic rotation. Plaintext
MUST be encrypted before commit; a storage node receives only authenticated
ciphertext. Core does not select an application encryption profile.

The repository identity, access controls, and ciphertext metadata MUST reveal
no more than the profile declares. A decryptor MUST authenticate ciphertext
before parsing. Rotation MUST prevent a retired generation from remaining
canonical.

<a id="core-non-erasure"></a>
Deletion, expiry, retraction, and rotation are cooperative hygiene, never
erasure. Git objects, relays, peers, exports, backups, and offline seeds may
retain bytes indefinitely. No family document may present a removal mechanism
as cryptographic or physical erasure.

<a id="core-keys-repository"></a>
### 9.1 Core keys-repository protection profile

The keys repository is a local versioned store. It MUST NOT be a Radicle
repository, be seeded, be relay-published, or be uploaded as plaintext. It
MUST be encrypted at rest. A git repository is RECOMMENDED for versioning but
does not itself provide encryption.

The active persona nsec MUST be wrapped with NIP-49 or an equivalent
memory-hard authenticated export under a user-controlled secret. The OS
keystore SHOULD protect the unlock secret. Backups MUST retain the same
encryption boundary.

The Core namespace owns only active persona keys, this node's NID secrets,
repository writer grants, sensitive discovery cache, protected-repository
location metadata, and protection parameters. Assurance keys and state are
Assurance-owned even when stored through this primitive. Other documents may
allocate namespaced records; Core treats unknown namespaces as opaque.

An unadvertised private configuration RID MUST NOT appear in kind `0`, kind
`10002`, kind `31010`, NIP-11, NIP-05, or another public descriptor. It MAY
leave the keys-repository boundary only in an encrypted backup or explicitly
authorized confidential transfer.

<a id="core-key-envelope"></a>
### 9.2 Key envelopes and generations

A **key generation** is one symmetric secret, one generation identifier, and
the exact recipient set entitled to hold it. The identifier is either an
opaque `key_id` with at least 128 bits of entropy or a monotonic `key_epoch`
scoped to one stable resource; a profile selects one form.

A **key envelope** delivers one generation to one recipient and binds at
least:

- the generation identifier;
- a [§3.5](#core-typed-key-references) recipient;
- the issuing authority and current signed or repository evidence; and
- wrapping profile, nonce, ciphertext, and ciphertext digest.

An envelope MUST NOT carry plaintext and MUST address exactly one recipient.
The recipient authenticates ciphertext and verifies issuing authority before
unwrapping. Adding a recipient publishes an envelope for the current
generation unless another rotation trigger applies. Removing a recipient MUST
derive a fresh generation and deliver it only to remaining recipients. New
objects MUST reject the retired generation. Rotation cannot revoke already
read plaintext and is not erasure.

An instantiating document supplies the recipient-set rule, reference and
wrapping profile, carrier, generation form, and additional rotation triggers.
It MAY tighten but MUST NOT weaken these rules.

<a id="core-verification"></a>
## 10. Baseline verification algorithm

Before rendering, storing, or using a Nostr event for authorization, a Core
implementation MUST perform these stages in order:

1. obtain every signed-event member exactly once into a new immutable snapshot
   and validate that snapshot's exact seven-member structure;
2. bind exact `nip01_raw` when the event is embedded;
3. serialize the NIP-01 six-member signing array from only that snapshot and
   recompute the SHA-256 event identifier;
4. verify the BIP-340 signature;
5. require `event.pubkey === active_persona_key` for a persona-scoped claim;
6. enforce the registered schema or profile for any Heterodyne extension; and
7. accept the baseline event or return a closed registered reason code.

NIP-01 event validity remains mandatory even when a repository, relay, NIP-05
mapping, profile extension, or Assurance claim is available. None may repair a
bad identifier, bad signature, raw mismatch, or author mismatch.

The structural step MUST reject without invoking any accessor, proxy trap, or
other user-controlled member operation. It rejects inherited members,
accessor-backed members, non-ordinary containers, symbol members, sparse tag
arrays, additional members, and cyclic structures. Successful verification
produces one independently owned, recursively immutable verified-event value.
Every later schema, authorship, routing, moderation, Assurance, Social, or
Control decision MUST use that exact value and MUST NOT reread the source
object. Repeating a boolean signature check does not establish this boundary.

The independent `core-signed-event-v1` checker exposes
`event_structure`, `nip01_raw`, `identifier`, `signature`,
`persona_resolution`, and `accept`. Its closed checker-only context requires
`active_persona_key`. Optional `assurance` evidence contains `requested` and
`verified`. The checker ignores absent or invalid Assurance evidence for a
baseline claim. Only when `requested` is explicitly `true` does it require a
closed valid object with `verified:true`. Assurance evaluation occurs after
baseline signature and active-key verification and cannot turn an unrequested
baseline claim into a failure.

Where exact raw input is required, absence or mismatch is
`nip01_raw_mismatch`. A malformed event, wrong identifier, or bad signature is
`bad_signature`. An active-key mismatch currently uses the registered
`delegation_mismatch` decision code; it does not imply that delegation could
make the event baseline-valid.

<a id="core-retired-key-observation"></a>
### 10.1 Retired-key observation is not baseline authority

Core has no epoch-authority or retired-key observation window. An event
remains attributable to the public key that signed it. Optional Assurance may
classify continuity or compromise for a caller that requests that separate
claim, but it cannot rewrite NIP-01 validity or source-neutral selection.

<a id="core-nostr-relay-interop"></a>
### 10.2 Vanilla relay interoperability and NIP-42

Core clients MUST implement NIP-01 and SHOULD implement NIP-42 AUTH when a
relay requests it. A persona-scoped AUTH event is standard kind `22242` signed
by the active persona key. A repository or higher-layer relay MAY instead
authenticate the exact Nostr account its disclosed policy authorizes. AUTH
uses ordinary NIP-42 challenge and relay tags and SHOULD be produced promptly.

NIP-42 requires no identity pointer, KEL, epoch key, `kel_head`, cold root, or
Heterodyne event shape. Authentication proves control of the AUTH event's
`pubkey`; relay policy decides what that key may access. Failure MUST surface
the relay URL and rejection reason.

A client SHOULD implement NIP-13 proof of work when a target relay advertises
`limitation.min_pow_difficulty` through NIP-11. All NIP-01 `NOTICE` messages
MUST be surfaced with relay URL and text.

<a id="core-tor-reachability"></a>
### 10.3 Onion reachability

An implementation claiming `core.outbound-tor.v1` MUST include self-contained
outbound capability for `.onion` relay, repo-relay, and Radicle endpoints. It
MUST NOT send onion hostnames to clearnet DNS or count an external proxy as
self-contained capability. An operator-selected external proxy is permitted
but is not that feature.

A browser that cannot open arbitrary Tor sockets MAY use configured clearnet
`wss://` relays in visible reduced-assurance mode. A full node claiming
`core.onion-service-host.v1` MUST persist a v3 onion identity and use Tor for
supported outbound backends by default. Explicit bypass disables strict
conformance while active.

<a id="core-versioning"></a>
## 11. Versioning, capabilities, and composition

The family version matches:

```text
^heterodyne/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$
```

During 0.x, any release may break an earlier 0.x release and implementations
MUST pin the exact version. At 1.0 and above, PATCH is clarification-only,
MINOR is additive, and MAJOR is breaking. A receiver MUST gate on MAJOR and
MUST NOT silently apply one major version's semantics to another.

Registry maturity is `draft < stable < frozen`, permits only adjacent forward
promotion, and forbids semantic change or reassignment of a frozen entry. A
1.0+ specification MUST NOT normatively require a non-frozen entry.

<a id="core-capabilities"></a>
### 11.1 Capability bootstrap

Every capability advertisement uses the Core-parsable descriptor registered
as `heterodyne-capabilities-v1` and binds the family version, pinned registry
digest, implementation role, supported documents, required features, and
strict profiles. `supported_documents` MUST include Core and be closed under
the family layering. Advertising Assurance is optional and MUST NOT be inferred
from Core support or profile hints.

Feature IDs MUST resolve through the pinned catalog, including transitive
prerequisites. Unknown optional profile IDs are retained or ignored safely and
grant nothing. Unknown claimed Core features fail capability negotiation. A
peer-bound session selects a mutually supported exact family version before
using a stamped Heterodyne profile; asynchronous input has no presumed
negotiation.

<a id="core-strict-profile"></a>
### 11.2 Strict-profile composition

The registered `heterodyne-core-strict-v1` profile is an additive claim. It
requires its declared invariant set, enabled outbound Tor for supported
network backends, local signature verification, and rejection rather than
warning for invalid signatures or repository-writer proofs. It never changes
wire parsing, active-key identity, or upstream Nostr compatibility.

<!-- fixture:core-strict-profile -->
```json
{
  "profile_id": "heterodyne-core-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST"
  ]
}
```

A strict profile's required invariant set is the transitive closure of its
prerequisite profiles plus `adds_invariants`. A duplicate ID with conflicting
membership is invalid. From 1.0, changing membership requires a new profile
ID.

<a id="core-security"></a>
## 12. Core security model

Relays, repositories, full nodes, and seeds may observe metadata, withhold,
reorder, replay, or discard events. They cannot forge a valid active-key
signature. Clients use multiple carriers, verify locally, and select state
source-neutrally. A compromised authorized seed can omit or add stored valid
events under its ref but cannot become their author or make its ref outrank a
newer valid relay event.

Core's current invariant meanings are:

- **CORE-I-IDENTITY-INTEGRITY:** The active persona key and its valid NIP-01
  signature are authoritative for baseline persona authorship; hints,
  repositories, caches, and optional Assurance cannot override them.
- **CORE-I-NID-DELEGATION-DUAL-PROOF:** A writer NID enters a repository union
  only after owner authorization and the NID's Ed25519 proof verify over the
  same exact binding.
- **CORE-I-VERIFY-BEFORE-USE:** Every signed object is captured once into an
  independently owned immutable value, locally signature-verified from that
  value, and never reread from attacker-controlled source state before
  rendering, storage, or authorization.
- **CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY:** Discovery uses active keys,
  NIP-05, kind `0`, kind `10002`, ordinary relays, and optional repositories;
  no centralized persona directory is required.
- **CORE-I-KEY-MATERIAL-AT-REST:** Active nsecs, NID secrets, repository
  grants, and sensitive cached state use the Core keys-repository protection
  profile, including NIP-49 wrapping where applicable.

<a id="core-operational-authority-views"></a>
### 12.1 Local operational authority views

Security-sensitive operational checks consume verifier-minted local views,
not caller-supplied booleans. A friend-cache candidate is usable only after
its captured NIP-01 event verifies and its author equals the expected persona;
otherwise the boundary returns `unauthorized_cache_content`. A relay profile
carrier is conforming only when bounded retained UTF-8 event bytes parse to
the exact same kind `0` fields, ID, author, and signature as the independently
captured event; otherwise it returns `relay_profile_mutation`.

The client captures its role, strict-profile selection, and effective route
once at the local authority boundary. A strict profile over clearnet returns
`strict_mode_tor_disabled`. Clearnet remains conforming for a disclosed
non-strict reduced-assurance role. These views are frozen, opaque, and bound
privately to the authority instance and captured evidence. Lookalikes, clones,
proxies, accessors, post-capture mutation, cross-authority use, and callback
substitution fail closed. This is client conformance over standard NIP-01 and
Tor behavior; it defines neither a relay extension nor a new transport.

<a id="core-retired-member-kel-and-role-delegation"></a>
### Retired member-KEL and role-delegation semantics

The pre-1.0 member-KEL organization-add rule and boolean role-delegation rules
are historical only. They grant no current Core authority, are not Workspace
roles, and MUST NOT be executed or counted as current conformance behavior.
Their retained reason-code registrations provide audit continuity only; Git
history, not the current evaluator graph, preserves the retired behavior.

<a id="core-sha1-bindings"></a>
SHA-1 appears in exactly three places, each analyzed individually rather than
dismissed wholesale. The Comms genesis-manifest digest is already SHA-256 and
is not in this list.

| Value | Where | Classification | Analysis |
|---|---|---|---|
| RID (20-byte Git object ID) | `rad:z…` repository identifier | locator | a collision yields two repositories claiming one name; neither gains event authorship (SHA-256/BIP-340) or ref authority (Ed25519) |
| `repo_head` | kind `31010` seed advert, Ed25519-bound | possession snapshot | signature-bound but grants nothing; advert expiry of at most 86,400 seconds limits exposure |
| `repository_head` | every signed Workspace object | carrier context | signature-bound but explicitly non-authority; a head not reachable from the accepted authority branch is rejected |

For each signature-bound SHA-1 value the concrete attack requires both a
chosen-prefix collision against repository state the attacker can influence
and a consumer that treats the digest as more than a locator; the rules above
remove the second half. Two requirements follow. No Heterodyne document may
bind authority, policy, or key material to a SHA-1 digest; authority bindings
require SHA-256 or stronger. Implementations SHOULD prefer the Radicle
`sha256` object format where the substrate supports it; the credential-ledger
schemas already accept both formats.

<a id="core-conformance"></a>
## 13. Conformance and validation

Every Heterodyne implementation claims Core. A claim states the exact family
version, registry revision or digest, claimed documents, supported feature
IDs, strict profiles, and implementation role. Protocol conformance and a
historical snapshot report are distinct.

Claimed features MUST resolve all prerequisites. A same-owner prerequisite
must also be claimed; a cross-document prerequisite requires the supplying
document. Missing IDs, cycles, or prerequisites supplied only by an unclaimed
document are rejection.

<a id="core-invariant-scope"></a>
An invariant without a `feature` member is baseline for every implementation
claiming its owner document. A feature-bound invariant applies whenever that
feature is claimed, including through transitive prerequisites. Exercising a
feature without claiming its invariants is nonconformance.

Wire conformance is byte-exact. Validation vectors compare canonical bytes,
verdicts, and reason codes but do not create requirements. A current-draft
checker MUST use specification anchors and normative registry or schema
artifacts, never an ADR, as authority.

Core minimum coverage includes NIP-01 structure, raw bytes, identifiers,
BIP-340 signatures, active-key persona matching, kind-0 extension isolation,
NIP-05 and NIP-65 discovery, seven-day warnings, source-neutral replacement,
exact-byte retry, authorized-ref union, public repo relay behavior, seed-NID
trust, NIP-42, protected storage, version negotiation, and Core invariants.

<a id="core-rolling-snapshot"></a>
### 13.1 Rolling pre-1.0 validation snapshot

Vector JSON under `docs/spec/vectors/` is the single non-normative rolling
pre-1.0 validation snapshot. The closed `snapshot.json` pins an exact
path/digest inventory. The current historical bootstrap remains bound to
source commit `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`; it contains 482 vectors
among 493 manifest-listed artifacts and declares zero reference-checker cases.

The snapshot lane derives its snapshot commit from the last commit that
changed `snapshot.json`; it does not trust uncommitted metadata. Its historical
source root contains the five documents that existed at that pinned commit.
The current-draft lane independently validates the live six-document family.
Optional Assurance discovery MUST NOT rewrite or add authority to the
historical snapshot.

Ordinary 0.x authoring does not update snapshot payloads, fixtures, coverage,
topics, or metadata. A dedicated reconciliation selects a stable full source
commit, authors and reviews one complete replacement, commits it, and only
then runs the read-only history check. Vector immutability, compatibility, and
release-manifest policy begin with a future 1.0 policy; this 0.x draft creates
no pre-1.0 release manifest.

<a id="core-reason-codes"></a>
### 13.2 Reason-code granularity

Reason codes are registry vocabulary, not a wire API. A code names a verifier
decision rather than an internal condition. Where a requester is not
authorized to distinguish causes, one coarse code MUST cover the refusal and
privileged detail stays only in the owning encrypted audit record. A document
MUST NOT allocate a finer code when an existing code intentionally covers the
same indistinguishable refusal. The registry marks such codes
`intentionally_coarse`; a document MUST NOT allocate a finer code where a
flagged code covers the refusal.

<a id="core-marmot-role-attribution"></a>
### 13.3 Superseded Core role attribution

Core no longer defines KERI attribution of Marmot account roles. The active
persona key is the baseline Marmot account identity. Agent keys are separate
accounts, device leaves remain independent, and higher documents define their
own explicit grants without changing Marmot account or MLS semantics.

<a id="core-retired-semantics"></a>
### 13.4 Retired diagnostic semantics

`retired-key-authority-window-invalid` is retained as non-wire history, not
current executable authority. It MUST NOT provide normative executable
evidence or a current protocol refusal. This retirement does not relax the
live Core NIP-01 verification, active-key persona, or source-neutral
selection boundaries specified in this document.
