# Heterodyne Core Protocol Specification

Document ID: `core`<br>
Version: `core/0.5.0`<br>
Registry revision: `6`

Normative dependencies: None.

This document prepares Core's first 0.5.0 release, descended from the
Heterodyne 0.4.x monolith. It is current normative authority at this repository
path but remains unreleased pending explicit release approval.
`core/0.5.0` is not a synchronized family version. The key words MUST, MUST
NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described by BCP 14
when, and only when, they appear in all capitals.

Permanent anchors use explicit HTML IDs formed by the literal `core-` prefix
and a lowercase ASCII kebab-case topic. Generated heading IDs are not stable
protocol references.

<a id="core-scope"></a>
## 1. Scope and non-goals

Core defines the common identity and transport substrate beneath every
Heterodyne protocol-family implementation:

- a persona whose canonical identifier is a KERI-anchored Nostr npub;
- cold-root inception, epoch-key rotation, compromise windows, replay, and
  deterministic KEL verification;
- root attestations and dual-proof delegation of Radicle Node IDs (NIDs);
- canonical NIP-01 serialization and the `nip01_raw` preservation rule;
- npub to RID to serving-node bootstrap using `kind:31005` and `kind:31010`;
- full, routing, and light node roles, plus the NIP-01 repo-relay adapter;
- generic delegate-threshold authority and KERI/Radicle reconciliation;
- generic protected repositories and a complete local keys-repository
  protection profile;
- KERI attribution of Marmot account roles and Radicle group-host identities;
- local signature verification, provisional key-state finality, qualified
  versioning, capabilities, security invariants, and conformance methodology.

Core does not define application payloads, feed policy, one-to-one message
semantics, group interaction, moderation, or remote command semantics. It does
not define a new transport, relay protocol, peer-to-peer network, programming
language, runtime, or centralized directory. Radicle replication remains
full-node-to-full-node; browser and mobile clients use NIP-01 endpoints.

<a id="core-terminology"></a>
## 2. Shared terminology

- **Persona**: one canonical cold-root npub, one accepted KEL, one canonical
  Radicle RID, and one set of delegations. Core MUST NOT infer or publish a
  link between separate personas, and private local correlation data MUST NOT
  become Core identity state. A higher-layer document MAY define an explicit
  relationship only when its wire profile authenticates authorization by both
  personas; Core assigns no application meaning to that relationship.
- **Cold root**: the offline secp256k1/BIP-340 key whose public key is the
  persona npub. It performs rare identity ceremonies.
- **Epoch key**: the secp256k1/BIP-340 key authorized by the accepted KEL for
  routine attestations during a bounded authority window.
- **KEL**: the persona's accepted sequence of `kind:31002` inception and
  `kind:31003` rotation events.
- **NID**: a Radicle Ed25519 node identity encoded as `did:key`. It signs
  Radicle refs and collaborative objects, not Nostr authorship.
- **RID**: a stable Radicle repository identifier, encoded as `rad:z...`.
- **Identity document**: the Radicle `xyz.radicle.id` collaborative object
  containing `delegates`, `threshold`, `payload`, and `visibility`.
- **Delegate**: a KEL-authorized NID empowered in the Radicle identity
  document. A visibility allow-list member is not necessarily a delegate.
- **Full node**: a Radicle node plus a NIP-01 repo-relay adapter; the only Core
  node role that stores and replicates repositories.
- **Routing node**: a content-free locator that derives serving-node answers
  solely from verified bootstrap advertisements.
- **Light node**: a client that locates a full node, fetches directly from a
  repo relay or ordinary relay, and verifies signed objects locally.
- **Repo relay**: a NIP-01 websocket endpoint whose durable event store is a
  Radicle repository.
- **Key-material event**: exactly `kind:31001`, `kind:31002`, or `kind:31003`.
  This class is closed in this release.
- **Qualified version**: `<document-id>/<semver>`, distinct from bare semver.
- **Marmot account**: the stable 32-byte Nostr account credential used by
  Marmot for account-scoped group privilege and account-to-leaf proofs.
- **Group host**: a full or recovery node authorized to replicate and serve a
  group's Radicle repositories. Hosting is operational authority, not MLS
  administration authority.

The Radicle identity document uses two different quorums. Its `threshold`
governs canonical data refs. A revision of the identity document itself is
accepted by more than half of the delegate set that revision replaces.
Implementations MUST NOT conflate these mechanisms.

<a id="core-registry"></a>
<!-- Monolith provenance: §3.0. -->
## 3. Registry, allocation, and canonical bytes

The separately revisioned Core-owned registry at `docs/spec/registry/` is the
allocation authority for kind numbers, profile discriminators, reason codes,
security-invariant IDs, and feature IDs. This release pins registry revision
`6`; changing a
non-Core-owned registry entry does not change Core semver. A conformance claim
MUST pin the registry revision or immutable entry-set digest.

Core owns the base schemas for `kind:31000` root attestations, `kind:31001`
delegations, `kind:31002` KERI inception, `kind:31003` KERI rotation,
`kind:31005` identity pointers, and `kind:31010` node advertisements. The
registry also records non-stamping Core production profiles on upstream kinds
`0` and `1`. Implementations MUST NOT infer ownership from the numeric range;
they MUST consult the pinned registry entry and any immutable profile
discriminator. Implementations MUST NOT allocate a new Heterodyne kind outside
the registry process.

All signed standalone Heterodyne-allocated kinds in the NIP-01 addressable range use the
`(pubkey, kind, d)` address. A singleton uses `['d', '']`; a multi-instance
schema defines a non-empty `d`. Examples MUST show the tag explicitly.

`features.json` is the allocation authority for globally unique dotted and
versioned feature IDs. Each entry binds its owner document, first version,
status, description, permanent specification reference, and duplicate-free
acyclic prerequisites. Capability advertisements and release manifests MUST
use catalog IDs exactly; a string absent from the pinned catalog grants no
feature capability.

<a id="core-canonical-serialization"></a>
<!-- Monolith provenance: §3.0.1-§3.0.1.1. -->
### 3.1 NIP-01 serialization and `nip01_raw`

Every Nostr event MUST be hashed and signed over the UTF-8 bytes of the compact
JSON array:

```text
[0,pubkey,created_at,kind,tags,content]
```

Strings use RFC 8259 escaping. Tag order is producer-selected and MUST NOT be
reordered in transport. The event `id` is SHA-256 of those bytes; `sig` is the
BIP-340 signature over that 32-byte digest. No Heterodyne-specific substitute
canonicalization is permitted.

Whenever a Nostr event is embedded inside another JSON object, the container
MUST include a sibling `nip01_raw` string containing the exact array bytes that
were hashed. A verifier MUST hash `nip01_raw`, verify `id` and `sig`, parse the
array, and require every exposed parsed field to match. A missing value or any
mismatch is rejection. A transport MUST NOT reconstruct the signing input from
the parsed object.

<a id="core-version-stamps"></a>
<!-- Monolith provenance: §3.0 and §12. -->
### 3.2 Owner stamps and historical bytes

An event carries at most one Heterodyne version stamp. The registry defines
these exhaustive classes:

1. Heterodyne-defined JSON `content` MUST contain the qualified
   `spec_version` of the base-schema owner.
2. A Heterodyne-allocated kind whose `content` is empty or non-JSON MUST carry
   `['spec_version', '<owner>/<semver>']`. The registry base-schema owner
   supplies `<owner>`.
3. An adopted upstream kind is unstamped unless an immutable registered
   stamping profile opts it in. A stamping profile uses its in-band
   discriminator and carries the profile owner's qualified version in the
   version tag without changing the upstream content shape.
4. A registered non-stamping profile changes no signed byte and adds no
   marker. The Core breadcrumb profiles
   `heterodyne-core-rotation-breadcrumb-profile-v1` and
   `heterodyne-core-rotation-breadcrumb-note-v1`, with discriminators
   `production-rule:rotation-breadcrumb-kind0-v1` and
   `production-rule:rotation-breadcrumb-kind1-v1`, are non-stamping. Those discriminators
   select trusted local producer rules only; they are not wire values, and a
   consumer MUST NOT infer either profile from relay bytes.
5. Adopted Marmot transport kinds `444`, `445`, and `30443` carry no
   Heterodyne marker. Their signed bytes remain upstream-owned.
6. Control inner application `kind:31017` exists only inside Marmot MLS. Its
   canonical JSON frame carries `control/0.5.0`; it has no outer Control stamp
   and MUST NOT be interpreted as a standalone event.
7. One-time-invite response rumor `kind:31018` exists only as unsigned inner
   NIP-59 content. Its JCS content carries `comms/0.5.0`; the authenticated
   NIP-59 seal supplies responder authentication and it MUST NOT be
   interpreted as a signed standalone addressable event.

The unqualified stamp `0.4.0` denotes the archived monolith. Missing-stamp
legacy inference is permitted only for a Heterodyne-allocated kind whose 0.4.0
schema required that monolith stamp. Adopted upstream kinds and post-split
non-stamping profiles MUST NOT receive legacy inference. Existing signed
events MUST NOT be restamped, re-signed merely for migration, or represented
as having different historical bytes.

**Closed legacy owner-inference table.** This table is exhaustive; numeric
range membership alone never makes an event eligible.

| Post-split owner | Monolith-stamped eligible kinds |
|---|---|
| Core | `31000`, `31001`, `31002`, `31003`, `31005`, `31010` |
| Comms | `31007`, `31011`, `31012` |
| Social | `31004`, `31008`, `31009` |

No legacy kind maps to Control. `31006` was only reserved and is not eligible.
For a kind in the table, an explicit unqualified `0.4.0` stamp selects the
archived monolith schema. An absent stamp MAY select that schema only when the
event otherwise validates as that kind's archived monolith form. Owner
inference then routes parsing and migration diagnostics to the named post-split
owner; it does not convert the event to that owner's 0.5.0 schema or stamp.
Unknown Heterodyne kinds, adopted upstream kinds, profile-only events, and any
event carrying a post-split discriminator MUST NOT receive this inference.

<a id="core-kel-head"></a>
<!-- Monolith provenance: §3.0 and §4.5.1. -->
### 3.3 Registered integrity tags

`['kel_head', '<64-lowercase-hex event id>', '<decimal seq>']` names the latest
accepted KEL event known to the signer. It is advisory and never replaces KEL
replay. When required it MUST occur exactly once and be well formed; the named
event's `s` MUST equal `seq`. Applicability is:

- every epoch-key-signed Heterodyne event MUST carry it;
- KEL events `31002` and `31003` MUST NOT carry it;
- an epoch-key-signed `31005` or `31010` MUST carry it, while a genuinely
  cold-root-signed instance MAY carry it;
- ephemeral NIP-42 AUTH and a device-key-signed invite MAY carry it;
- device- or MLS-leaf wire events and non-stamping breadcrumb profiles MUST
  NOT carry it.

`['compromise_since', '<unix-seconds>']` occurs exactly once on a
compromise-declaring rotation and MUST NOT occur on a routine rotation.

<a id="core-typed-key-references"></a>
### 3.4 Typed-key references and native proof hooks

Core provides a closed syntax and registration hook for higher documents to
name cryptographic keys without assigning policy meaning to those names. The
initial reference types are:

| Type | Canonical value | Native verifier |
|---|---|---|
| `nostr-secp256k1` | 32-byte x-only secp256k1 public key as 64 lowercase hexadecimal characters | BIP-340 |
| `radicle-ed25519-nid` | canonical Ed25519 `did:key:z...` Radicle NID | Ed25519 |
| `jwk-thumbprint` | unpadded base64url SHA-256 RFC 7638 thumbprint | JWS with a public JWK whose recomputed thumbprint is identical |

A parser MUST reject an unknown type, a non-canonical value, private JWK
members, remote JWK key references, or a proof whose suite does not match the
reference type. A future type or proof suite requires a registry allocation;
an implementation MUST NOT reinterpret an unknown discriminator.

The public JWK supplied for a `jwk-thumbprint` proof is one of these three
closed profiles:

- Ed25519 has `kty:"OKP"`, `crv:"Ed25519"`, and canonical `x`, and uses
  `alg:"EdDSA"`;
- P-256 has `kty:"EC"`, `crv:"P-256"`, and canonical `x` and `y`, and uses
  `alg:"ES256"`; or
- RSA has `kty:"RSA"`, canonical `n` and `e`, an unsigned modulus of at least
  2048 bits, and uses `alg:"RS256"`.

Each profile permits only its RFC 7638 thumbprint members plus optional
`alg`, `use`, `key_ops`, and `kid`. When present, those four members MUST
equal the profile algorithm, `"sig"`, `["verify"]`, and the recomputed
RFC 7638 thumbprint respectively. The protected JWS header is the exact
closed object `{"alg":"<profile algorithm>"}`: `alg` is required and is its
sole member. Unknown, private, or remote-reference JWK members, an extra
protected-header member, `none`, an HMAC/HS or `oct` key, a wrong curve, a
weak RSA modulus, or any algorithm/key-type mismatch MUST be rejected.

The generic native-proof input is a domain-separated canonical byte string
binding the referenced key, purpose, fresh challenge, audience, resource,
operation, verifier context, issue time, and expiry. The caller supplies the
complete bytes and expected reference. Core returns only `valid` or `invalid`
plus the verified key reference and suite. Freshness, replay, purpose, trust,
and permission decisions remain the caller's responsibility. For a Radicle
NID, Core additionally verifies that the public key in the proof encodes to
the exact canonical NID. For a JWK proof it recomputes the RFC 7638 thumbprint
before verifying the protected JWS.

<a id="core-authority-interfaces"></a>
### 3.5 Authority and repository interfaces

Core exposes a point-in-time persona/KEL issuer-authority result containing:
the cold-root persona, accepted KEL head, candidate signing key, authority
interval, verification time, evidence source, and one state from `valid`,
`provisional`, or `invalid`. `valid` means the cryptographic KEL and delegation
rules authorize the key for the caller-supplied purpose at that instant;
`provisional` records locally verified but not repository-final KEL evidence;
`invalid` grants nothing. A higher document MUST preserve that distinction and
MUST NOT convert provisional evidence to final authority.

For NID-bearing callers Core also exposes the result of the dual-proof
delegation check in §6, including the exact NID, binding, authority interval,
and accepted KEL head. This interface verifies identity and possession only.

Higher documents may reuse Core's generic protected-repository primitives:
canonical `main` selection, commit/ref verification, encrypted private-tree
storage, recipient-key wrapping, reader removal, key rotation, rollback
detection, and cooperative ciphertext scrubbing. They may also reuse the
public identity repository's canonical-`main` publication and digest-binding
rules. Those primitives do not assign meaning to repository records or make a
repository state authoritative for a higher-layer decision.

Core does not define claims, trust policy, authorization state, OIDC, JWT, or
token status. Registry hooks identify the owning document and immutable
profile discriminator; they do not transfer semantic ownership into Core.

<a id="core-identity-model"></a>
<!-- Monolith provenance: §3.1 and §3.5. -->
## 4. Persona identity and KEL

The cold-root npub is the authoritative subject of every Core attestation. A
delegated identifier, repository, cache, export AID, or serving node MUST NOT
replace it as the persona identity. One operator MAY hold multiple unlinkable
personas; private local correlation data MUST NOT be published.

<a id="core-kel-primitives"></a>
<!-- Monolith provenance: §3.5.0. -->
### 4.1 KEL primitives and witness keys

The cold root signs inception, committed-strategy rotation, and a changed-RID
identity pointer. The current epoch key signs routine attestations. A witness
is an identifier and weight declared in the KEL state in force before a
rotation. Supported witness identifiers are a Nostr public key, `did:key`, or
a DID profile explicitly defined by a compatible extension.

The cold root MUST NOT sign routine root attestations, delegations, node ads,
or application events. Its secret SHOULD remain offline outside an inception,
committed rotation, or changed-RID pointer ceremony.

A `did:key` witness is self-certifying. A verifier MUST decode the
multicodec key material, select the implied signature algorithm, and verify
locally. It MUST NOT perform network resolution for `did:key`.

<a id="core-kel-inception"></a>
<!-- Monolith provenance: §3.5.1. -->
### 4.2 Inception (`kind:31002`)

```json
{
  "pubkey": "<cold-root hex>",
  "created_at": "<ceremony unix seconds>",
  "kind": 31002,
  "tags": [
    ["d", ""],
    ["heterodyne", "keri_inception"],
    ["p", "<cold-root hex>"],
    ["s", "0"],
    ["epoch_key", "<initial epoch key hex>"],
    ["witness", "<identifier>", "<positive integer weight>"],
    ["threshold", "<non-negative integer>"],
    ["spec_version", "core/0.5.0"]
  ],
  "content": "",
  "sig": "<BIP-340 signature by cold root>"
}
```

`pubkey` and `p` MUST equal the cold root, `s` MUST equal `0`, and `d`
MUST be empty. `threshold` MUST be present when witnesses exist and MUST NOT
exceed the sum of configured weights. `created_at` is the canonical ceremony
timestamp selected by the producer. Its exact integer is part of the signed
NIP-01 bytes and MUST be retained through storage, replay, and materialization;
a verifier MUST NOT replace it with zero, an ingestion time, a rounded value,
or another normalized timestamp. The event MUST NOT carry `kel_head`.

<a id="core-kel-rotation"></a>
<!-- Monolith provenance: §3.5.2. -->
### 4.3 Rotation (`kind:31003`)

```json
{
  "pubkey": "<cold root for committed; prior epoch key for none>",
  "created_at": 0,
  "kind": 31003,
  "tags": [
    ["d", "<decimal s>"],
    ["heterodyne", "keri_rotation"],
    ["p", "<cold-root hex>"],
    ["s", "<positive decimal>"],
    ["prior_digest", "<prior event id>"],
    ["strategy", "committed | none"],
    ["epoch_key", "<new epoch key hex>"],
    ["witness", "<identifier>", "<positive integer weight>"],
    ["threshold", "<non-negative integer>"]
  ],
  "content": "{\"spec_version\":\"core/0.5.0\",\"receipts\":[]}",
  "sig": "<controller BIP-340 signature>"
}
```

The rotation event `content` MUST be the compact UTF-8 JSON serialization of
exactly one object with exactly two members in this order:
`spec_version`, whose value is exactly `core/0.5.0`, and `receipts`, whose
value is an array of the receipt objects defined below. The byte form is
`{"spec_version":"core/0.5.0","receipts":[...]}` with no insignificant
whitespace; an empty receipt set is `[]`. Any missing, duplicate, or unknown
top-level member, a member in the wrong order, a wrong `spec_version`, or a
non-array `receipts` value MUST be rejected.

The `p` tag MUST equal the cold root. `s` MUST advance from the prior accepted
event and `d` MUST equal `s`. `prior_digest` MUST equal the prior accepted
event id. `committed` requires the cold-root signature; `none` requires the
prior epoch-key signature and witness threshold. The event MUST NOT carry
`kel_head`. Its exact signed `created_at` is the authority-window transition
timestamp and MUST be retained without normalization.

`strategy:none` additionally requires the threshold in the prior accepted
state to be at least one and enough distinct valid receipts to satisfy it. A
threshold-zero `none` candidate is invalid before candidate selection: it
cannot win, compete with, or stall a valid `committed` successor, though an
implementation MAY retain it as non-authoritative attempted-fork evidence. A
witness-free or threshold-zero persona therefore rotates only with
`strategy:committed`. A threshold-zero committed successor remains valid when
its other requirements hold. Two valid committed successors of the same prior
event are duplicity and stall continuity under §4.4.

Each receipt has exactly `witness_id`, `scheme`, and lowercase-hex `sig`.
`witness_id` MUST occur in the witness configuration from the prior accepted
event. `scheme` MUST be one of `bip340`, `did:key`, or `atproto` and MUST be
compatible with that identifier:

- `bip340` requires a lowercase 64-hex Nostr x-only public key and verifies a
  raw BIP-340 signature over the 32-byte `witness_digest`;
- `did:key` requires the exact configured `did:key` URI, decodes its
  multicodec public key, and verifies using the algorithm implied by that key;
  network resolution MUST NOT occur; and
- `atproto` requires the exact configured `did:web` or `did:plc` identifier and
  verifies with the signing key that the registered DID witness profile makes
  authoritative for that identifier at the ceremony time.

A scheme/identifier mismatch MUST be rejected as a receipt and contributes
zero weight. An unconfigured identifier, unavailable key, malformed raw
signature, or failed signature likewise contributes zero. `sig` MUST be the
lowercase-hex encoding of the raw signature bytes regardless of scheme.
Receipts MUST be ordered by ascending `witness_id`, compared bytewise as UTF-8;
only the first receipt per identifier is counted and duplicates beyond it MUST
be ignored.

Every receipt signs the same 32-byte `witness_digest`: SHA-256 of this
rotation's canonical NIP-01 serialization with `content` set to the empty
string `""`. The event id and the next `prior_digest` use the actual JSON
content, so the KEL commits to the receipt set. During replay a verifier MUST
parse the receipt array, apply the identifier-to-scheme mapping above, verify
each signature over exactly `witness_digest` against the prior accepted
witness configuration, and sum only distinct valid receipt weights.

A compromise declaration MUST satisfy
`compromise_since <= created_at`. Define
`effective_compromise_since = min(compromise_since, created_at)`. The
superseded epoch is non-authoritative for any event with
`created_at >= effective_compromise_since - 300`, under full replay and every
accelerator.

#### 4.3.1 Vanilla Nostr routine-rotation breadcrumbs

After accepting a routine, non-compromise rotation, a producer SHOULD emit the
rotation breadcrumb pair from the retiring epoch key before destroying that
secret:

1. an unstamped `kind:0` profile whose human-readable `about` and `website`
   fields point to the successor's canonical NIP-19 `npub`; and
2. an unstamped plain `kind:1` note announcing the same successor `npub`.

Both events MUST omit `kel_head` and every Heterodyne wire marker. Their
`pubkey` fields remain the retiring key's 32-byte lowercase hexadecimal Nostr
public key; only human-readable fields use bech32 `npub`. The retiring
profile MUST NOT carry a NIP-05 identifier that has already been repointed to
the successor, because it would no longer validate for the signing key. The
successor's `kind:0` SHOULD identify the predecessor, and a persona-controlled
NIP-05 identifier SHOULD be repointed to the successor.

The v1 profile classification exists only inside the producer's trusted
rotation workflow. Before producing either event, the implementation MUST bind
these inputs as one candidate:

- the prior accepted KEL state;
- the accepted routine rotation and its persona cold root;
- the retiring key named by the prior state and the successor key named by the
  accepted rotation;
- the persona's selected NIP-65 write-relay set; and
- the exact candidate `kind:0` and `kind:1` event bytes.

The cold root MUST be identical across the prior and successor state, and both
candidate events MUST be signed by the retiring key. A compromise-driven
rotation, an unrelated successor, a candidate substitution, publication
before KEL acceptance, or publication after retiring-secret destruction MUST
produce no v1 breadcrumb.

The producer SHOULD attempt the exact pair on every selected write relay after
KEL acceptance and record per-relay outcomes. A partial relay failure does not
undo the accepted rotation, confer authority on a delivered event, or justify
retaining the retiring secret indefinitely. The implementation MAY retry failed
destinations only within its bounded destruction ceremony, then SHOULD destroy
the retiring secret and report incomplete delivery.

On consumption, an unstamped `kind:0` or `kind:1` without `kel_head` is
ordinary upstream Nostr. A consumer verifies its NIP-01 signature but MUST NOT
infer a v1 profile, KEL succession, or persona authority. A caller-supplied
role, profile id, expected identity, or similar oracle MUST NOT change that
classification. Registry histories 1 through 3 and the two v1 discriminators
remain immutable. Any future machine-recognizable breadcrumb profile MUST
allocate a v2 discriminator and a signed in-band marker rather than reinterpret
v1 bytes.

<a id="core-kel-verification"></a>
<!-- Monolith provenance: §3.5.3. -->
### 4.4 KEL verification

A verifier MUST parse and replay independently from the exact raw NIP-01 event
bytes. It MUST parse the array shape and tag/content bytes, reproduce the exact
canonical serialization, recompute the event id, verify the controller
signature, and derive state from accepted events. Regenerating a candidate
with the producer's fixture helper is not a conformance oracle.

A verifier MUST:

1. Fetch repo-carried candidates first and query ordinary relays with
   `{"kinds":[31002,31003],"#p":["<cold-root hex>"]}`. Merge by event id.
   A verifier SHOULD also chain-discover: after accepting an event, query
   `authors` for its `epoch_key` to recover a `none` rotation omitted from a
   relay's `#p` result. Open-query events with the wrong `p`, invalid schema,
   invalid controller signature, or broken chain MUST be discarded.
2. Accept one inception only after its cold-root BIP-340 signature, `p`, `s`,
   and schema validate.
3. Process each sequence in ascending order. Verify controller signature,
   `prior_digest`, and any carried receipt schemes and signatures exactly as
   specified above. For `strategy:none`, require cumulative distinct valid
   witness weight against the threshold in force at the prior accepted event
   and reject threshold zero before candidate selection. A valid
   `strategy:committed` successor is authorized by its cold-root signature and
   does not require receipts, even when the prior state has a positive witness
   threshold. An unlisted or invalid receipt has zero weight.
4. On same-sequence forks, apply KERI first-seen witness behavior: each witness
   honors the first valid rotation it observed at that sequence. A branch is
   accepted only if attestations from witnesses that first saw that branch
   reach threshold. If none does, the KEL stalls and the implementation MUST
   expose stalled continuity. Competing valid committed successors always
   stall and surface duplicity; a verifier MUST NOT schema-reject the fork or
   select one merely because it arrived from the repository. Otherwise, after
   signature and threshold validation, a repo-carried candidate is canonical
   over a conflicting relay-only candidate; the relay-only branch remains
   provisional and MUST NOT displace it. Duplicity MUST be surfaced.
5. Return the current epoch key, witness configuration, and half-open authority
   windows derived from accepted event timestamps and compromise declarations.

Only declared witness weight counts. Unregistered advisory attestations MUST
NOT move a rotation toward acceptance. A cached or exported KEL projection
MUST NOT displace independent exact-byte replay of accepted source events.

<a id="core-pre-keri-migration"></a>
<!-- Monolith provenance: §3.5.4. -->
### 4.5 Pre-KERI identity history

The v0.1.4 successor/predecessor/revoke chain is deprecated. A persona using
that history MUST publish a cold-root-signed KERI inception before producing
post-migration identity state. Once a valid inception exists, a verifier MUST
ignore deprecated chain events for authority. If no inception exists, a reader
MAY retain archival read compatibility but MUST label the persona `pre-KERI`
and MUST NOT claim Core 0.5 identity conformance for that state.

<a id="core-threshold-authority"></a>
<!-- Monolith provenance: §3.3 and §3.9.10. -->
## 5. Generic threshold authority

A threshold persona is governed by KEL-authorized NIDs projected into its
Radicle identity document. A single-delegate persona is the one-of-one case.
For any Core operation requiring threshold authority:

1. resolve the accepted KEL and active NID delegations;
2. reject signatures from NIDs absent from or revoked by the KEL;
3. resolve the verified Radicle identity document at the relevant repo head;
4. count distinct authorized delegate signatures over the same canonical
   commit or operation; and
5. accept only when the identity document's applicable ref threshold is met.

An identity-document revision uses its separate more-than-half acceptance
rule. Delegate replacement MUST be add-before-remove. Adding a member NID to a
threshold persona MUST have both that NID holder's valid Core delegation
chain and authorization by the existing persona delegate quorum; either alone
is insufficient. A higher document instantiating threshold authority MUST use
this algorithm and MAY add policy checks, but MUST NOT weaken these checks.
The optional `xyz.radicle.crefs` threshold extension MAY be used only after
all participating implementations negotiate it explicitly; baseline Core
authority MUST NOT depend on that extension.

<a id="core-root-attestation"></a>
<!-- Monolith provenance: §3.2.1 and §3.3. -->
## 6. Root attestation and delegation

A `kind:31000` root attestation is signed by the current epoch key, carries an
empty `d`, `['heterodyne', 'root']`, the cold-root hex, exactly one `kel_head`,
and `['spec_version', 'core/0.5.0']`. If embedded in an external container, it
MAY carry a container-binding tag defined by that profile.

The verifier MUST validate `nip01_raw`, BIP-340 signature, current epoch-key
authority, cold-root equality, empty `d`, and `kel_head`. A container binding,
when present, MUST equal the actual container. Root-attestation `created_at`
MUST be within plus or minus 300 seconds of the verifier's clock. This
freshness rule applies only to `kind:31000`; it MUST NOT be generalized to
other kinds. A container profile MUST reject simultaneously asserted root
attestations naming different cold roots rather than selecting one silently.

<a id="core-nid-delegation"></a>
<!-- Monolith provenance: §3.3.1. -->
### 6.1 NID delegation (`kind:31001`)

```json
{
  "pubkey": "<current epoch key hex>",
  "created_at": 0,
  "kind": 31001,
  "tags": [
    ["d", "nid:<did:key NID>"],
    ["heterodyne", "delegation"],
    ["radicle_nid", "<did:key NID>"],
    ["publishing_key", "<device secp256k1 key hex>"],
    ["cold_root", "<persona cold-root hex>"],
    ["nid_proof", "<Ed25519 signature hex>"],
    ["kel_head", "<accepted KEL event id>", "<decimal seq>"],
    ["valid_until", ""],
    ["spec_version", "core/0.5.0"]
  ],
  "content": "",
  "sig": "<BIP-340 signature by current epoch key>"
}
```

The NID signs these exact UTF-8 bytes, with one ASCII `|` separator:

```text
heterodyne-nid-binding-v1|<cold-root-hex>|<nid>|radicle-nid-delegation
```

The outer event signature binds the same values. A verifier MUST require both
the epoch-key BIP-340 signature and NID Ed25519 `nid_proof`, require the
declared device publishing key, require exact `d` construction, validate
`valid_until`, validate `kel_head`, and establish epoch authority at the
evaluation time. A KEL revocation overrides a stale identity document.

An empty `valid_until` means no expiry. Otherwise its value MUST be a decimal
Unix timestamp strictly greater than the evaluation clock. A verifier MAY
apply an explicitly bounded local clock-skew allowance (300 seconds is
RECOMMENDED) by evaluating against `wall_clock - allowance`; an unbounded or
implicit grace period is forbidden. Invalid, non-decimal, or expired values
MUST deactivate the delegation.

A light-only Control principal is not a Core device and MUST NOT use
`kind:31001`. Its non-delegated Marmot account and private authorization are
defined exclusively by Control. It cannot sign Radicle refs, become a durable
claim-ledger reader, acquire NID authority, or publish for the persona.

<a id="core-full-node-control"></a>
#### 6.1.1 Full-node Control and recovery metadata

A durable NID delegation MAY describe its authorized device as a full node in
the persona's canonical public device metadata. The signed metadata binds the
device delegation address and current `kel_head` and contains a closed
`control` object with:

```json
{
  "full_node": true,
  "versions": ["control/0.5.0"],
  "marmot_account": "<same authorized device Nostr pubkey>",
  "keypackage_slots": ["<standard Marmot KeyPackage address>"],
  "relay_metadata": ["<NIP-65/NIP-17 reference>"],
  "reachability": ["outbound-tor", "onion-only"],
  "recovery_features": [
    "control.recovery.radicle.v1",
    "control.recovery.epoch-inbox.v1",
    "control.recovery.sftp.v1"
  ],
  "epoch_inbox_relays": ["wss://relay.example/"]
}
```

`marmot_account` MUST equal the delegated device `publishing_key`.
`versions`, `keypackage_slots`, `relay_metadata`, `reachability`, and
`recovery_features` are duplicate-free arrays. Unsupported members or feature
identifiers invalidate the Control metadata, not the underlying device
delegation. An implementation MUST NOT infer liveness, current invitation
acceptance, recovery custody, or authorization from this advertisement.

`epoch_inbox_relays` is permitted only when
`control.recovery.epoch-inbox.v1` is advertised. It locates the locked epoch
NIP-59 inbox for the new-full-node bootstrap defined by Control; it is not a
general-purpose RPC endpoint. A device that does not advertise `full_node`
MUST omit the entire Control object.

<a id="core-role-delegation"></a>
#### 6.1.2 Role-addressed delegation extension

Core also permits a registered higher-layer profile to address a durable role
at `kind:31001` without creating a Radicle NID. Such an extension MUST retain
the epoch-key outer signature, `["heterodyne", "delegation"]`,
`publishing_key`, `cold_root`, `kel_head`, `valid_until`, empty content, and
the Core version stamp. It MUST set `d` to a registered
`<namespace>:<role-id>` address and provide a `key_proof` made by the declared
`publishing_key`. The registered profile MUST define:

1. the namespace and closed syntax of `role-id`;
2. the exact proof-domain bytes signed by `publishing_key`;
3. any additional binding tags and their uniqueness rules; and
4. the higher-layer authority and lifecycle semantics of the role.

A verifier MUST resolve the registered profile before interpreting the role.
An unknown namespace, malformed address, or profile/discriminator mismatch
MUST return `role-delegation-address-invalid`. A missing, malformed, or invalid
proof MUST return `role-delegation-key-proof-invalid`. The outer epoch
signature and `key_proof` are both REQUIRED and MUST bind the same
`publishing_key`, persona, and role address. A role-addressed delegation is
non-stamping: it does not change the Core owner or base schema of `kind:31001`.
Core assigns no automation, publication, moderation, or other application
meaning to a role namespace.

<a id="core-marmot-role-binding"></a>
#### 6.1.3 KERI attribution of Marmot account roles

Comms registers three persona-scoped Marmot role classes over the
role-addressed delegation extension:

- `marmot:human-messaging` identifies the persona's stable human messaging
  account;
- `marmot:group-admin` identifies a separately governed account permitted to
  exercise Marmot group-administration privilege; and
- `agent:<role-id>` identifies an automated account under the existing
  Comms agent-delegation profile.

Each binding MUST name one 32-byte x-only secp256k1 Marmot account public key
as `publishing_key`, MUST satisfy §6.1.1, and MUST be repository-final before
a Heterodyne implementation treats it as current role authority. The private
key for `marmot:human-messaging`, `marmot:group-admin`, or `agent:<role-id>`
MUST remain on an authorized full or recovery node. A light client or
automated principal MUST NOT receive it.

Marmot remains the authority for its account credential, MLS leaf credential,
and standard account-to-leaf proof. Core verifies only that the account is
currently attributable to the named persona and role. Invalid, missing,
provisional, expired, revoked, or equivocated KERI evidence removes verified
Heterodyne attribution and role authorization; it MUST NOT rewrite Marmot
history, select an MLS branch, or alter Marmot convergence.

Device MLS leaves are independent credentials. A KERI-authorized full or
recovery node MAY use the bound account to produce Marmot's standard
account-to-leaf proof for an authorized device. It MUST NOT represent two
concurrently active devices as one leaf. An encrypted leaf transfer is valid
only as an exclusive takeover in which the prior instance is deactivated or
fenced before the restored instance becomes active.

<a id="core-radicle-group-admission"></a>
#### 6.1.3 Radicle group admission and host attribution

Comms may bind a Marmot routing identifier to a private Radicle repository.
Core's NID delegation and protected-repository primitives provide the
replication identity and admission substrate for that binding.

An administrator admitting a persona to native Radicle group transport MUST
authorize an active NID attributable to that persona and MUST privately
deliver every non-public repository locator and bootstrap capability. A
private repository allow list controls which NIDs may replicate; it does not
encrypt stored Git objects, prove Marmot membership, or authorize an MLS
operation. Sensitive directory and administrative records therefore remain
application-encrypted even in a private repository.

Removing a member MUST remove its NID from future repository admission before
the replacement routing generation is advertised to that member set. Removal
prevents future authorized replication and decryption only. Existing clones,
Git objects, exports, and backups may remain and MUST NOT be described as
erased.

Group hosts MUST use active KERI-attributed NIDs. A group administrator is a
host by default, but a host or Radicle delegate is only a replication
operator. Neither a Radicle default branch, delegate threshold, ref signature,
nor host announcement may create group membership, select Marmot group state,
or grant group-admin authority.

<a id="core-key-authority"></a>
<!-- Monolith provenance: §3.9.10.1 and §4.5.2. -->
### 6.2 Key-material authority and finality

Key-material events MUST be published to ordinary relays and the repo relay.
The valid set reachable from verified canonical event-storage refs is
authoritative. KEL conflicts are keyed by `(cold_root, s)`; delegation
conflicts use `(pubkey, 31001, d)`. Relay-only key material is provisional
under one declared policy:

- `provisional-accept` applies it while marking all dependent decisions
  provisional; it is the default.
- `deny-until-repo` gives it no effect until repo-carried.

A repo-carried event hardens the decision. Mere repo reachability never does.
For KEL sequence N, absence permits withdrawal only after a verified
repo-carried KEL head reaches at least N and carries a different or missing
event at N. For a delegation, absence alone never withdraws authority;
withdrawal requires a canonically included replacement, explicit revocation,
or a verified ingestion checkpoint causally beyond its acknowledgement.

A contradictory KEL update, full verification, or converged repo state MUST
withdraw the prior acceptance signal and re-evaluate dependent objects.
Bootstrap kinds `31005` and `31010` are outside the key-material class so
locating a repo never depends circularly on that repo.

A full node's retention and garbage collection MUST NOT drop key-material
events reachable from finalized canonical history. A light node without repo
access remains in reduced-assurance `provisional-accept` mode and MUST upgrade
its view from a repo relay when one becomes reachable.

<a id="core-identity-discovery"></a>
<!-- Monolith provenance: §3.6. -->
## 7. Identity discovery, reconciliation, and recovery

Core discovery ends at npub to RID to serving node to authoritative key
material. It does not define content-location or application-discovery policy.
A client MUST be able to resolve identity with these steps:

1. Start from the cold-root npub.
2. Fetch and verify `kind:31005` from ordinary write relays.
3. Obtain serving-node hints from that pointer or verified `kind:31010` ads.
4. Fetch KEL, delegations, and root attestation from a repo relay and ordinary
   relays.
5. Replay the KEL, reconcile repo authority, then verify attestations.

Cached identity state MAY avoid repeated network work. Its default TTL SHOULD
be at most 24 hours, and active sessions SHOULD use one hour or less. A newer
pointer, KEL event, delegation expiry, revocation, head-ahead `kel_head`, or
successful repo reconciliation MUST trigger immediate revalidation. Cache
entries derived from provisional state MUST remain marked provisional.
Sensitive cached identity state MUST use the Core at-rest protection profile.
Every accelerator cache MUST be rebuilt whenever the accepted KEL changes.

<a id="core-identity-failures"></a>
<!-- Monolith provenance: §3.7. -->
### 7.1 Identity failure handling

If all pointer, KEL, delegation, and root-attestation sources are unreachable,
fresh verification is unavailable. Cached state MAY be used only with a clear
stale-identity signal. If relays are reachable while the repo is not,
relay-only key material remains provisional and MUST NOT harden or be withdrawn
for absence; a client SHOULD expose prolonged reduced-assurance operation.
Loss of one full node is routed around through another seeder or ordinary
relay; permanent loss of every seeded copy invokes re-anchor.

A compromised delegation MUST be selectively revoked or superseded by epoch
rotation. A compromised epoch MUST be replaced using KEL rotation and, when
known, a compromise window. Container or identity-document deadlock invokes a
new-RID cold-root re-anchor. Implementations MUST expose stalled continuity,
duplicity, stale verification, and reduced-assurance operation.

<a id="core-identity-pointer"></a>
<!-- Monolith provenance: §3.2, §3.9.8, and §11.3. -->
### 7.2 Identity pointer (`kind:31005`)

```json
{
  "pubkey": "<cold root or current epoch key hex>",
  "created_at": 0,
  "kind": 31005,
  "tags": [
    ["d", ""],
    ["heterodyne", "identity_pointer"],
    ["rid", "rad:z..."],
    ["host_hint", "wss://node.example/relay"],
    ["spec_version", "core/0.5.0"]
  ],
  "content": "",
  "sig": "<BIP-340 signature>"
}
```

The canonical npub-to-RID binding MUST be cold-root-signed. A same-RID update
that changes only host hints MAY be current-epoch-signed, in which case it
MUST add `cold_root` and `kel_head`. A changed RID always requires the cold
root. Every pointer MUST carry exactly one `rid` tag. A `host_hint` is OPTIONAL
and is never identity authority. The canonical pointer uses empty `d` and MUST
be published to ordinary relays; it SHOULD also be stored in the identity
repo.

An implementation MAY publish non-canonical staging or migration pointer
events with a non-empty `d`, but MUST NOT treat them as the canonical empty-`d`
binding.

For conflicting RID bindings, discard invalid cold-root signatures, prefer a
binding consistent with an authenticated KEL re-anchor, then choose greatest
`created_at`, then lexicographically smallest event id. An epoch-signed hint
refresh is accepted only for the selected RID and only while that epoch is
authoritative.

<a id="core-node-advertisement"></a>
<!-- Monolith provenance: §7.0. -->
### 7.3 Node advertisement (`kind:31010`)

A node advertisement has `d` equal to RID and exactly one tag each for
`node_advert`, `rid`, Ed25519 `nid`, `endpoint`, `repo_head`, `expiry`, and
`nid_proof`, plus the appropriate Core version tag and `kel_head` when
epoch-signed. `repo_head` is exactly one canonical lowercase 40-hex Git object
ID. Multiple endpoints require separate advertisements so that each proof
binds one endpoint. Its outer event is BIP-340-signed by a dedicated node key
or a current epoch key.

A full node MUST publish at least one current advertisement whose `endpoint`
is its persistent v3 onion service. It MAY publish additional onion endpoints
and, when it claims browser compatibility, shared clearnet Nostr relay hints.
A clearnet hint is a transport rendezvous and never authorizes direct
clearnet access to the full node.

The NID proof signs these exact UTF-8 bytes:

```text
heterodyne-node-advert-v1|<rid>|<nid>|<endpoint>|<expiry>|<repo_head>
```

A verifier MUST validate the outer signature, inner Ed25519 proof, equality of
all bound fields, canonical tag cardinality and shapes, and expiry. The
`expiry` value MUST be a canonical decimal Unix timestamp strictly greater
than `created_at`, and `expiry - created_at` MUST NOT exceed 86,400 seconds.
On first acceptance, `created_at` MUST be within 300 seconds of verifier time.
The verifier clock MUST be strictly before `expiry`. A continuing producer
MUST refresh before `created_at + 43,200`; refresh failure never extends the
old advertisement locally.

Verifier time SHOULD come from a secure platform time source. A client that
knows its clock uncertainty exceeds 300 seconds MUST fail closed for fresh
advertisement acceptance and report a clock error. It MUST NOT widen the
acceptance window.

The advertised `repo_head` is the repository's canonical head at issuance: it is a
possession snapshot, not a promise that no later push occurs. Until expiry the
advertised endpoint MUST successfully serve an object graph that contains that
exact head. A missing, malformed, duplicate, proof-mismatched, or successfully
fetched-but-unserved head MUST be rejected. Transport unavailability is a
retryable provisional outcome, not proof that the endpoint does not serve the
head; an unserved rejection requires a successful graph fetch whose reachable
object set excludes it. Invalid or expired ads MUST be discarded.

<a id="core-persona-profile"></a>
### 7.4 Canonical persona profile and vanilla projection

The canonical Heterodyne persona profile is the closed
`heterodyne-core-persona-profile-v1` record defined by
`schemas/core/persona-profile-v1.schema.json` in the persona's public Radicle
profile repository. Canonical-main selection and the repository's configured
threshold choose exactly one record bound to the cold-root persona. Relay
state, NIP-05, and arrival time cannot override that selection.

Exactly one active KEL delegation MAY carry the `profile-publisher` role. Its
delegated secp256k1 device publishing key produces an ordinary, unstamped
Nostr `kind:0` mirror of the selected record's `vanilla_profile`. The cold
root MUST NOT sign routine profile updates. A `kind:0` from any other key is
ordinary Nostr data, not a Heterodyne profile projection.

Optional `nip05` MUST resolve to the current designated publisher key. It is a
display and discovery identifier only; it never becomes persona authority.
After publisher rotation, the successor publishes a fresh `kind:0` mirror
only after its delegation and the repository profile update are accepted.

For every still-live addressable semantic object, rotation republishes the
object under `(successor_pubkey, kind, d)` and atomically changes the canonical
repository or feed index to that coordinate. `(old_pubkey, kind, d)` remains
historical. A NIP-09 deletion request is optional advisory cleanup, not
migration authority or proof of erasure.

Historical discovery derives a finite set of old and current publisher keys
from accepted KEL and delegation history and sends ordinary NIP-01 `authors`
filters containing exact lowercase 64-hex keys. Heterodyne does not redefine
relay author semantics or merge address coordinates. Results are checked in
the signer's authority window, and only the repository-confirmed index selects
the live address.

<a id="core-radicle-reconciliation"></a>
<!-- Monolith provenance: §3.9.10. -->
### 7.5 KEL and Radicle reconciliation

The accepted KEL is authoritative over the Radicle identity document. A
revoked or absent NID MUST NOT be honored even if the document still lists it,
and refs signed by it MUST be rejected. Clients MUST tolerate the identity
document lagging the KEL and MUST resolve authority from the KEL. Device
changes are dual writes: update the Core delegation set and the identity
document. Replacement is add-before-remove.

If live delegates cannot reach the majority needed to revise the identity
document, the persona MUST incept a new RID with delegates matching the KEL
and publish a cold-root-signed `kind:31005` re-anchor. A verifier MUST reject a
repo head that regresses below a finalized canonical head unless such an
authenticated re-anchor authorizes the move.

Changed-RID re-anchor recovers serving-repository, identity-container,
hosting, or delegate-threshold deadlock only. It is authorized by the existing
cold root and therefore MUST NOT be presented as recovery from cold-root
compromise. Until Core standardizes a precommitted cold-root recovery policy,
a compromised cold root requires migration to a new persona and new root; the
old persona's trustworthy authority cannot be preserved by re-anchor.

<a id="core-recovery"></a>
<!-- Monolith provenance: §3.7 and §3.12.2. -->
### 7.6 Infrastructure-loss recovery

Recovery roles are protocol-neutral: recovery peers retain verified identity
material; declared witnesses attest KEL continuity; the persona uses the cold
root to re-anchor infrastructure. Application relationships do not affect
Core authorization.

A declared witness serving as a recovery peer MUST retain verified
persona-signed identity events and valid KEL events for at least 30 days. Other
recovery peers MAY do so. The cache MUST contain only persona-signed identity
material plus KEL events. KEL events are the sole exception to a current-owner
signature filter because a valid event may be signed by the prior epoch under
`none` or carry witness receipts. Cached material MUST exclude unrelated
application content, MUST be labeled cache-sourced and stale when served, and
MUST NOT be presented as live repo state.

After permanent serving-infrastructure loss, the persona creates a new RID and
publishes a fresh cold-root-signed `kind:31005`. That pointer is authoritative;
cached identity material is only a bridge while it propagates. Any disagreement
between the new pointer and cached state MUST be logged and surfaced. KEL
continuity uses the witness-threshold algorithm; a `none` rotation is used for
epoch recovery when its controller conditions apply. Human identity checks a
witness performs before signing are out of scope.

This procedure requires the existing cold root to remain available and
uncompromised. It does not repair or supersede cold-root compromise.

Cold-root loss is recoverable only from redundant encrypted backups already
decryptable through an authorized recovery path. Implementations SHOULD
recommend multiple independently stored copies using platform secure storage
and, where available, hardware or removable storage plus the portable backup
format. Restored bytes do not grant a new device authority; ordinary restore,
delegation, and activation checks still apply. A configured positive witness
threshold with `strategy:none` may preserve epoch continuity, but cannot
reconstruct or replace the cold-root secret or perform a root-only operation.

Suspected cold-root compromise is terminal for the persona. A trustworthy
remaining controller SHOULD publish the defined migration breadcrumbs and
move to a new cold-root persona. This protocol defines no same-persona root
reset, newly selected social-trustee reconstruction, or witness substitution.

<a id="core-multi-host-seeding"></a>
<!-- Monolith provenance: §3.11. -->
### 7.7 Multi-host seeding

Repository redundancy is opt-in Radicle seeding. A repository is replicated
by exactly the full nodes that elect to seed its RID; Core MUST NOT infer
replication from popularity or audience size. A persona needs at least one
durably connected full node for reliable propagation. A client MUST display
host count and durable-host status and SHOULD warn when no durable host is
advertised.

<a id="core-protected-repository"></a>
<!-- Monolith provenance: §3.8.6. -->
## 8. Protected repositories and key storage

Core defines a generic encrypted-repository primitive. An instantiating
profile MUST specify a unique profile ID, plaintext schema owner, authenticated
encryption algorithm and byte format, key identifier derivation, key lifecycle,
authorized decryptors, ref or branch layout, rollback detection, and atomic
rotation behavior. Plaintext MUST be encrypted before commit; storage nodes
MUST receive only authenticated ciphertext. Core does not select an
application encryption profile.

The repository identity, access controls, and ciphertext metadata MUST reveal
no more than the instantiating profile declares. A decryptor MUST authenticate
ciphertext before parsing. Rotation MUST prevent a retired generation from
remaining canonical, but deletion from cooperating replicas is not a promise
of erasure.

Protected-record ownership is closed for this release:

| Owner namespace | Records |
|---|---|
| Core | Root and epoch secrets, NID secrets, KEL/delegation state, protected-repository location metadata, and protection parameters |
| Comms | Audience keys, direct-session secrets, encrypted configuration payloads, and content-location records |
| Social | Mute data, feed-presentation preferences, and subscribed-repository preferences |

The owner names the plaintext schema and lifecycle. This allocation does not
create a Core dependency on a higher document.

<a id="core-keys-repository"></a>
<!-- Monolith provenance: §3.8.7-§3.8.8. -->
### 8.1 Core keys-repository protection profile

The keys repository is a local, versioned store. It MUST NOT be a Radicle
repository; MUST NOT be seeded, relay-published, or uploaded to a service; and
MUST be encrypted at rest. A git repository is RECOMMENDED for versioning but
does not satisfy encryption by itself.

The cold-root nsec MUST be wrapped with NIP-49 or an equivalent memory-hard,
authenticated export under a user-controlled secret. The OS keystore SHOULD
protect the store-unlock secret where available. Backups MUST preserve the
same encryption boundary.

The Core namespace owns only:

- NIP-49-wrapped cold-root material and epoch-key secrets;
- this device's Ed25519 NID secrets;
- Core delegation and cached KEL metadata;
- encrypted-repository location metadata, including an unadvertised config
  RID; and
- protection-profile parameters needed to unlock those Core records.

Application audience secrets, session secrets, preference data, content
location lists, and application payloads are not Core-owned records. A sibling
document may allocate namespaced records, but the keys repository MUST treat
unknown namespaces as opaque and MUST NOT grant authority based on them.

The unadvertised config RID MUST NOT appear in a `kind:31005`, a
`kind:31010`, or any other published Core descriptor or advertisement. It MAY
leave the keys-repository boundary only inside an encrypted backup or an
explicitly authorized higher-layer transfer that preserves confidentiality.

Offline restore is a Core path: unlock the keys repository first, use its
location metadata to restore protected repositories, then restore ordinary
repositories. Losing every keys-repository copy can destroy decryptability,
but it does not change KEL identity continuity. Clients SHOULD state these
loss consequences plainly before destructive reset or restore.

<a id="core-verification"></a>
<!-- Monolith provenance: §4.5 and §4.5.2. -->
## 9. Verification algorithm

Before rendering, storing, or using a signed object for authorization, a Core
implementation MUST:

1. validate event structure and exact `nip01_raw` where applicable;
2. recompute SHA-256 id and verify BIP-340 signature;
3. resolve the persona through the pointer, KEL, and delegation path;
4. enforce the per-kind version-stamp and `kel_head` classes;
5. establish epoch authority at the event's `created_at`, including any
   retroactive compromise window;
6. enforce subtype and NID proof rules; and
7. return `accept`, `accept_provisional`, `equivocation_flagged`, or a closed
   registry reason code.

An object whose identity inputs are provisional MUST NOT be reported final.
Failed verification MUST be exposed as a rejection or explicit security
warning; it MUST NOT silently become trusted content.

<a id="core-retired-key-observation"></a>
### 9.1 Retired-key late observation

An event signed by a routinely superseded epoch or delegated publisher key
and first observed after retirement is repo-confirmed pre-retirement content
only when its introducing commit is an ancestor of a trusted repository
checkpoint bound into, or accepted before, the retiring rotation. A trusted
local receipt or checkpoint recorded before retirement may establish the same
fact for that local verifier.

Without either proof, a signature-valid event whose claimed `created_at` is in
the key's authority window is `provisional-retired-key`. Relay timestamps,
later relay presence, and the event's own timestamp are not proof of prior
existence. Provisional retired-key content MAY be displayed with that state,
but MUST NOT authorize, replace canonical profile state, migrate an address,
or enter a canonical feed index without an accepted anchor.

The accepted `compromise_since` cutoff remains stronger: content at or after
that cutoff is rejected even if a later repository or local receipt purports
to anchor it. This provisional state never weakens compromise handling.

`kel_head` handling has three distinct non-success paths. A required tag that
is absent, duplicated, or malformed is rejection; a forbidden tag is
rejection; and an id/sequence mismatch is rejection. A well-formed but stale
head MUST NOT by itself reject an otherwise valid event. A head ahead of the
accepted KEL SHOULD trigger a repo-relay-first refresh; a pending or failed
refresh caps the result at provisional. A well-formed head naming an event off
the accepted KEL MUST produce `equivocation_flagged` and an explicit security
warning rather than silent deletion.

Head classification order is normative. The verifier MUST test
`seq_ahead_of_accepted_head` before `off_accepted_kel`; this rule is identified
as `seq_ahead_of_accepted_head-before-off_accepted_kel`. On the ahead case it
MUST refresh repo-relay-first, re-resolve identity from the refreshed candidate
set, and rerun every structural and head check. Only after that refresh may it
classify a still-off-chain head as `equivocation_flagged`. A failed or pending
refresh makes key state non-final and MUST cap a later successful verification
at `accept_provisional`.

The declared key-material policy is also part of every verification path. A
relay-only key-material input under `provisional-accept` may be applied only
with provisional status. Under `deny-until-repo`, it has no authority and the
path MUST return `reject` with reason `provisional_not_final`; it MUST NOT
return `accept_provisional`. This policy rejection holds the object unresolved
for re-evaluation after repo synchronization and is not a permanent validity
judgment. Verification of an embedded signature MUST apply the same head
ordering, refresh, re-resolution, and `provisional_not_final` rules.

<a id="core-verification-accelerator"></a>
<!-- Monolith provenance: §4.5.1. -->
### 9.2 `kel_head` accelerator

`kel_head` is never sufficient for acceptance. A verifier MAY use materialized
key state instead of full replay only when all conditions hold: the named event
is on the accepted KEL; event time is inside that head's authority window; no
later accepted compromise declaration covers the event time; and no KEL
refresh is pending or failed. Otherwise it MUST replay the authoritative
candidate set or hold the decision provisional.

Materialized state MUST be derived from the verifier's own completed replay.
The optional repo projection below may populate a cache only after it matches
the independently accepted KEL.

<a id="core-node-roles"></a>
<!-- Monolith provenance: §7.0 and §10.1.1. -->
## 10. Node and repo-relay substrate

A full node stores repositories, performs Radicle Noise XK/TCP replication,
serves NIP-01 websocket access through a persistent v3 onion service, and
routes outbound repository, relay, and application backend connections through
Tor by default. It is an onion service, not a public Tor relay, exit, or
general-purpose proxy. A routing node stores no content and answers only from
verified `31005`/`31010` advertisements. A light client fetches from the
returned endpoint or shared relay and verifies locally. Routing answers are
untrusted hints; no routing node or shared relay is on the integrity path.

A routing node MUST discard expired or unverifiable advertisements, MUST NOT
be required to proxy content, and MAY expose a cache only when that cache is
outside the integrity path. A light client MUST fetch content from a repo
relay or ordinary relay, MUST NOT be required to fetch it through a routing
node, and MUST verify every event locally before display or storage. A
browser-based client MAY use a shared clearnet relay because a browser tab
cannot open arbitrary Tor sockets. That path is reduced assurance and does
not expose the full node's onion service as a clearnet endpoint.

Core declares three implementation roles and five exact feature IDs:

| Role | Required behavior | Tor requirement |
|---|---|---|
| `public-reader` | Implement `core.nostr-relay-read.v1`; verify signed public events locally; hold no persona authority | `core.outbound-tor.v1` is RECOMMENDED; omission is reduced assurance and forbidden by strict mode |
| `authenticated-light` | Implement ordinary-relay read/write, local verification, and the authenticated higher-layer session selected by the user | `core.outbound-tor.v1` is RECOMMENDED; omission is reduced assurance and forbidden by strict mode |
| `full-node` | Implement `core.outbound-tor.v1`, `core.repo-relay-client.v1`, and `core.onion-service-host.v1`; store and serve the repositories it accepts | REQUIRED and MUST be the default for outbound backends |

`core.browser-shared-relay.v1` means that a full node has at least one
normalized clearnet `wss://` shared Nostr relay through which browser clients
can exchange protocol traffic. A full node claiming browser compatibility
MUST implement and advertise that feature and at least one such relay. A full
node not claiming browser compatibility MAY omit it.

Feature advertisements are exact capability claims. An implementation MUST
advertise only features it implements and MUST reject an unknown claimed Core
feature rather than silently inferring support. A non-strict public or
authenticated-light client without outbound Tor MUST display and report
reduced-assurance operation. Strict mode MUST reject that configuration.

A full node MUST keep one stable v3 onion service identity across ordinary
restarts, advertise it through verified node-advertisement state, and use Tor
for outbound repository, Nostr, and other network backends by default. It MUST
NOT silently replace the onion path with direct WebRTC, a direct clearnet
socket, or a provider-specific realtime path. Any future direct-connect mode
requires a separately negotiated expansion and an explicit security downgrade;
it is not part of Core 0.5.0.

<a id="core-repo-relay"></a>
<!-- Monolith provenance: §10.1.2. -->
### 10.1 Repo-relay adapter

`core.repo-relay-client.v1` requires a client to read and write ordinary,
unmodified NIP-01 events over a websocket endpoint without speaking Git or
Radicle. It is REQUIRED for a full node and OPTIONAL for public-reader and
authenticated-light roles. The client MUST verify event signatures locally;
event authorship rests on the Nostr signature rather than any storage ref.

Core 0.5.0 defines no generic repo-relay server/storage profile, feature, or
claim. It makes no normative promise about a generic ref namespace,
append-log representation, filter-to-Git mapping, admission, retention,
garbage collection, or quota. An implementation MUST NOT claim generic
repo-relay server/storage conformance. The separately defined Comms
Radicle-backed Marmot relay is the only claimable relay server/storage profile
in this family release.

<a id="core-client-responsibilities"></a>
<!-- Monolith provenance: §10.2. -->
### 10.2 Client responsibilities

A Core implementation MUST meet the requirements of every role and feature it
claims. Every role MUST verify NIP-01/BIP-340 events locally, enforce version
and registry pins, and reject capabilities it does not understand.
Authenticated-light and full-node roles MUST create signed events and manage
the root, KEL, delegation, repo-authority, provisional-finality, and protected
key state applicable to their authority. Only
`core.repo-relay-client.v1` requires direct repo-relay read/write.

An outbound-Tor implementation embedded in a non-browser WASM runtime SHOULD
be an outbound-only client and MUST NOT expose a listening proxy or relay
merely to satisfy Core. A browser tab MAY instead use its browser networking
APIs to a shared `wss://` relay and operate in reduced-assurance mode. It MUST
NOT claim embedded Tor merely because a host-local proxy, gateway, or relay is
available. A full-node build SHOULD provide the derived export-AID capability.
Internal language, runtime, and packaging are unrestricted.

A repo relay SHOULD expose a monotonic ingestion watermark over its canonical
event-storage head. The watermark MUST strictly increase as submissions are
processed and MUST be comparable with a submission acknowledgement before it
is used as an absence proof for a delegation.

<a id="core-materialized-kel"></a>
<!-- Monolith provenance: §10.1.2. -->
### 10.3 Materialized-KEL storage profile

This profile is a cache output of the independent exact-byte replay in §4.4.
An implementation MUST NOT populate either ref directly from generator
expectations, parsed convenience objects, or the refs' prior contents. Only
events accepted by that replay contribute log or state commits.

An implementation MAY derive two linear refs:

- `refs/xyz.heterodyne.keri/log`: one commit per accepted KEL event; the tree
  contains only mode `100644` `event.nip01` with exact `nip01_raw` bytes. Each
  log commit has the prior event's log commit as its sole parent; the inception
  log commit is parentless.
- `refs/xyz.heterodyne.keri/state`: one commit per resulting state; the tree
  contains only mode `100644` `state.json` encoded with RFC 8785 JCS. Parent
  order is prior state then producing log; inception has only its log parent.

`state.json` MUST validate before JCS canonicalization against this exact
closed schema:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["cold_root", "s", "epoch_key", "witnesses",
               "threshold", "producing_event_id"],
  "properties": {
    "cold_root": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "s": {"type": "integer", "minimum": 0},
    "epoch_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "witnesses": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "weight"],
        "properties": {
          "id": {"type": "string"},
          "weight": {"type": "integer", "minimum": 1}
        }
      }
    },
    "threshold": {"type": "integer", "minimum": 0},
    "producing_event_id": {
      "type": "string", "pattern": "^[0-9a-f]{64}$"
    }
  }
}
```

Witness IDs are exact configured strings, sorted ascending by Unicode code
point. An empty witness set is `[]`, never omitted or null. Hex is lowercase;
numeric fields are JSON integers. Authors and committers are exactly
`Heterodyne KERI <keri@heterodyne.invalid>`; timestamps equal event
`created_at` with `+0000`; commit message is event id plus one LF; optional git
headers are forbidden. Conforming nodes MUST derive byte-identical chains from
the same accepted KEL.

Both refs MUST update atomically by compare-and-swap. Divergence requires a
full atomic rebuild, never an incremental patch. An empty accepted KEL MUST
delete both refs in the same transaction. A backend without atomic multi-ref
transactions MUST NOT claim this profile. Readers MUST verify that both tips
derive from the same accepted KEL head before using either. These refs are
derived and never authoritative; divergence from repo-carried KEL events
requires re-derivation, and neither ref is an input to acceptance.

<a id="core-nostr-relay-interop"></a>
<!-- Monolith provenance: §10.5-§10.6. -->
### 10.4 Vanilla relay interoperability

Core clients MUST implement NIP-01 and NIP-42 AUTH. An AUTH event uses the
current epoch key, never the cold root, and SHOULD be sent within 10 seconds.
On an `AUTH` challenge during a write session the client MUST answer with a
signed `kind:22242` event whose `pubkey` is the current KEL-authorized epoch
key. The cold root MUST remain offline and MUST NOT sign AUTH. AUTH failure
MUST be exposed with relay URL and rejection reason.

A client SHOULD implement NIP-13 proof of work. It MUST read the target from
NIP-11 `limitation.min_pow_difficulty`; absent or zero means no proof is
required for that relay. If computation is cancelled or exceeds the client's
budget, the client MUST expose the relay URL and required difficulty. All
NIP-01 `NOTICE` messages MUST be surfaced with relay URL and reason.

A Heterodyne-aware relay is an OPTIONAL strict superset of NIP-01. It MUST
preserve vanilla read/write behavior and advertise added features through
NIP-11. It MAY provide KEL-aware reputation continuity, KEL-aware author-query
convenience, or passive receipt storage. Such storage does not make the relay
a witness. A relay that changes `authors` query semantics through KEL expansion
MUST advertise that feature through NIP-11. A persona MUST NOT depend on an
aware relay being available. No Core conformance verdict depends on this
profile.

<a id="core-tor-reachability"></a>
<!-- Monolith provenance: §7.7. -->
### 10.5 Onion reachability

An implementation advertising `core.outbound-tor.v1` MUST include
self-contained outbound capability to reach `.onion` relay, repo-relay,
routing-node, and full-node endpoints. It MUST NOT require a separately
installed daemon or externally configured SOCKS proxy and MUST NOT send an
onion hostname to clearnet DNS. An external system proxy MAY be honored as an
operator choice but MUST NOT be counted as the self-contained feature.

A non-browser WASM implementation of this feature SHOULD embed an outbound-only
Tor client; it need not expose a local proxy or accept inbound connections. A
browser tab that cannot open arbitrary Tor sockets MAY omit the feature and use
accepted clearnet `wss://` relays in declared reduced-assurance mode. Core does
not require an experimental browser-to-Tor WebSocket bridge.

A full node MUST implement the feature, persist its v3 onion service, and start
supported outbound Heterodyne backends Tor-routed. An operator MAY explicitly
disable Tor for a backend only with a visible downgrade, and the node then MUST
NOT claim strict conformance while that bypass is active. Full-node Radicle
replication SHOULD support onion peers.

<a id="core-keri-export"></a>
<!-- Monolith provenance: §11.8. -->
## 11. Canonical-KERI export

NIP-01 plus `nip01_raw` is the Core wire and storage form. KERI10JSON or CESR
MUST NOT replace it. Signature-preserving conversion is impossible because the
signatures cover different serializations.

A full node SHOULD support an operator-enabled derived export AID whose own
KEL anchors, in order, digests of accepted Heterodyne KEL events and identifies
the persona npub as canonical subject. The export AID is never persona
authority and MUST NOT substitute for the npub.

A full node MUST NOT enable an export AID for a persona without operator
consent. Consent is per persona; merely configuring a web origin is not
consent.

Once enabled, the node SHOULD maintain an origin-independent CESR stream and
anchored-digest map. Origin-bound did:webs artifacts are produced only when an
operator origin and path exist. Security-relevant source state MUST NOT be
omitted. Failures are `UNMAPPABLE_FEATURE`, `UNSUPPORTED_CRYPTO_SUITE`, or
`INCOMPLETE_EXPORT`; an export with any non-security omission MUST be marked
degraded, MUST NOT be labeled complete, and MUST carry explicit warnings.

<a id="core-versioning"></a>
<!-- Monolith provenance: §12. -->
## 12. Versioning, dependencies, and capabilities

A qualified version matches:

```text
^(core|comms|control|social)/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$
```

The qualified string is not semver; only its suffix is passed to a semver
parser. Every document begins its independent lineage at 0.5.0. During 0.x,
any release may break an earlier 0.x release and implementations SHOULD pin
exact qualified versions. At 1.0 and above:

- PATCH is clarification-only and MUST NOT change wire format;
- MINOR is additive: optional fields, optional types, or loosened requirements;
  an earlier MINOR receiver MUST tolerate unknown fields and types safely; and
- MAJOR is breaking. A receiver MUST gate on MAJOR and MUST NOT silently apply
  one MAJOR version's semantics to another.

Implementations SHOULD increment MINOR for every optional field addition.

Document maturity is ordered `0.x < 1.0+`. A document MUST NOT normatively
depend on another document at a lower level. Registry maturity is ordered
`draft < stable < frozen`, permits only monotonic adjacent promotion, and
forbids semantic change, removal, or reassignment of a frozen entry. A 1.0+
document MUST NOT normatively require a non-frozen registry entry.

<a id="core-capabilities"></a>
<!-- Monolith provenance: §12.2-§12.3. -->
### 12.1 Stable capability bootstrap

Every capability advertisement uses this Core-parsable bootstrap object:

```json
{
  "descriptor": "heterodyne-capabilities-v1",
  "bootstrap_version": "core/0.5.0",
  "registry_revision": 7,
  "implementation_role": "public-reader",
  "supported_versions": {
    "core": ["core/0.5.0"],
    "comms": [],
    "control": [],
    "social": []
  },
  "required_features": [
    "core.nostr-relay-read.v1"
  ],
  "strict_profiles": []
}
```

`descriptor`, `bootstrap_version`, `registry_revision`,
`implementation_role`, and `core` support are REQUIRED.
`implementation_role` MUST be exactly `public-reader`, `authenticated-light`,
or `full-node`. Each supported-version set contains qualified versions for
that document only. `required_features` uses exact IDs from the pinned
`features.json`; document names alone do not establish feature conformance. A claimed
role and its required feature set MUST agree.

`strict_profiles` contains stable profile IDs. It MUST contain only profiles
whose complete invariant, obligation, feature, vector, and
prerequisite-profile sets are actually met by the advertiser. A composed profile
MUST advertise every prerequisite profile in the same object and MUST
advertise the document versions and required features on which those profiles
depend. An unknown strict-profile ID MUST be retained or ignored safely and
MUST NOT be used to infer conformance, grant a capability, or satisfy a known
profile. An unknown claimed Core feature MUST fail capability negotiation;
unknown optional fields use the ordinary fail-closed rule.

The descriptor SHOULD be committed to the identity repo so a peer can discover
it without a higher protocol. A Core-only implementation MUST use this carrier;
absence of any higher carrier MUST NOT imply non-conformance. A public reader
MUST advertise `core.nostr-relay-read.v1`. A full node MUST advertise
`core.outbound-tor.v1`, `core.repo-relay-client.v1`, and
`core.onion-service-host.v1`; it MUST additionally advertise
`core.browser-shared-relay.v1` when it claims browser compatibility.

A peer-bound session MUST exchange advertisements and select a mutually
supported qualified version before either peer sends an event stamped with
that version. A peer MUST NOT stamp a version the receiver did not negotiate.
For asynchronous input, no negotiation is presumed: an unsupported stamped
version MUST be rejected or processed only by an explicitly declared degraded
mode that does not apply unknown security semantics. An unknown MAJOR MUST NOT
be silently treated as compatible.

<a id="core-strict-profile"></a>
### 12.2 Strict-profile composition

Strict profiles are additive conformance claims, not negotiation shortcuts.
They never weaken baseline requirements and do not change wire parsing. The
stable Core strict profile is defined by this complete machine-readable
membership declaration:

<!-- fixture:core-strict-profile -->
```json
{
  "profile_id": "heterodyne-core-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": [],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST"
  ]
}
```

`heterodyne-core-strict-v1` additionally requires
`core.outbound-tor.v1`, requires egress over Tor to be enabled for every
supported network backend, and requires invalid signatures or delegations to
be rejected rather than rendered with a warning. Disabling or bypassing Tor
makes the strict profile unmet; it does not silently downgrade a strict claim.
A claim MUST satisfy every listed invariant at registry revision 7 and every
applicable strict vector.

Higher-document strict profiles compose by naming prerequisite profile IDs and
listing their complete flattened invariant membership. A conforming report
MUST reject a duplicate profile ID with conflicting membership. Profile IDs
are stable: changing membership or an obligation requires a new ID.

<a id="core-security"></a>
<!-- Monolith provenance: §9.1 and §13. -->
## 13. Core security model

Core assumes endpoint secrets and cryptographic primitives remain secure. Full
nodes, routing nodes, repo relays, and ordinary relays may observe metadata,
withhold, reorder, or discard data; none is trusted to establish authorship or
identity. Radicle RID and git-object identifiers are SHA-1-based in Heartwood
1.9.x, but event integrity independently uses SHA-256/BIP-340 and Radicle refs
use Ed25519. Genesis-RID collision risk therefore does not authorize a forged
KEL or event.

Core recognizes root-replay, JSON reserialization, KEL fork, stale-delegation,
serving-node withholding, routing-query metadata, rollback, and key-extraction
threats. Multiple serving nodes and ordinary-relay access improve availability;
they never replace local verification.

The registry binds these exact normative invariants:

- **CORE-I-IDENTITY-INTEGRITY:** The cold-root npub and accepted KEL are authoritative for persona identity; downstream caches and delegated identifiers cannot override them.
- **CORE-I-NID-DELEGATION-DUAL-PROOF:** A Radicle NID delegation is active only after both the persona epoch-key BIP-340 signature and the delegated NID Ed25519 proof verify over the same binding.
- **CORE-I-VERIFY-BEFORE-USE:** Every signed object is locally signature-verified and, where applicable, delegation-checked before rendering, storage, or authorization.
- **CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY:** Core discovery does not depend on a centralized persona, npub, RID, or serving-node directory.
- **CORE-I-KEY-MATERIAL-AT-REST:** Persona nsec, NID secrets, and sensitive cached identity material are protected by the Core keys-repository profile, including NIP-49 wrapping where applicable.
- **CORE-I-MARMOT-ROLE-ATTRIBUTION:** KERI role evidence attributes Marmot accounts and Radicle hosts without selecting MLS state or altering Marmot convergence.

<a id="core-conformance"></a>
<!-- Monolith provenance: §14. -->
## 14. Conformance and vectors

Every Heterodyne implementation claims Core conformance. A claim MUST state
the exact qualified version, registry revision or digest, supported feature
IDs, strict-profile IDs, implementation role, and every dependency version.
Core has no document dependencies. Protocol conformance and vector conformance
are distinct claims.

This document is pinned to registry revision 7 and its immutable digest.
History revision 7, the current entry files, release manifests, and vector
metadata MUST agree exactly. Optional Control recovery profiles remain
independently claimable and do not alter baseline Core conformance.

A release manifest lists disjoint `provided_features` and
`required_features`. Every provided ID MUST be owned by that manifest's
document. Every same-owner prerequisite of a provided feature MUST also be
provided; every external prerequisite MUST appear in `required_features`.
Every required ID MUST be owned and provided by the exact declared dependency
release. Validators MUST resolve the catalog prerequisite graph, reject cycles
or missing IDs, and reject a requirement supplied only by a different or
unpinned dependency release.

A conformance report MUST, for each strict-profile ID, list the profile's state,
conformance class, prerequisite profile IDs, required invariant IDs, required
features, applicable strict-vector results, and any gaps. It MUST NOT report a
profile as met while any required invariant, obligation, feature, prerequisite
profile, or vector is unmet. A partial report may describe an unknown or unmet
profile but MUST NOT advertise it in `strict_profiles`.

Normative vectors compare canonical bytes and exact verdicts; semantic
equivalence is insufficient. Each vector has an ID, owner document, owner
version, registry pin, qualified spec references, direction, input, and
expected output. Time-sensitive vectors use a simulated clock and production
vectors pin randomness. During 0.x, an accepted specification change MAY
change or retire an unreleased current vector in place. Released artifact sets
preserve their exact historical bytes. Vector-ID immutability begins at 1.0.

When this document declares a behavior conformant, an implementation MUST
produce or accept it as specified. NIP-01 events have only the canonical
serialization defined in Section 3.1. For a producer vector, the generated
canonical bytes MUST equal the expected bytes exactly. For a consumer vector,
the verdict and reason code MUST equal the expected values exactly. A
repo-relay round trip MUST preserve the accepted signed-event bytes exactly.

The Core minimum set covers NIP-01 bytes, KEL inception/rotation and authority
windows, root freshness, NID dual proof, pointer resolution, node ads,
repo-authority finality, materialized KEL derivation, routing/light roles,
repo-relay client behavior, Tor reachability, keys-repository protection,
version negotiation, and each Core invariant. A skipped REQUIRED vector bars
a full Core vector-conformance claim; partial reports MUST list every gap and
rationale.

Vector JSON under `docs/spec/vectors/` is normative for the behavior it covers.
Generator code is non-normative authoring and verification tooling. Diagnostic
reason codes are registry vocabulary, not a wire API.
