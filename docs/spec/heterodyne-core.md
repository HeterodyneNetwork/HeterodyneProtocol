# Heterodyne Core Protocol Specification

Document ID: `core`<br>
Version: `core/0.5.0`<br>
Registry revision: `1`

> Pre-release extraction draft. Until family cutover, the archived 0.4.0
> monolith remains normative.

Normative dependencies: None.

This is the first Core release descended from the Heterodyne 0.4.x monolith.
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
  Radicle RID, and one set of delegations. Separate personas MUST NOT be linked
  at the protocol layer.
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

The Radicle identity document uses two different quorums. Its `threshold`
governs canonical data refs. A revision of the identity document itself is
accepted by more than half of the delegate set that revision replaces.
Implementations MUST NOT conflate these mechanisms.

<a id="core-registry"></a>
<!-- Monolith provenance: §3.0; split allocation: ADR-033. -->
## 3. Registry, allocation, and canonical bytes

The separately revisioned Core-owned registry at `docs/spec/registry/` is the
allocation authority for kind numbers, profile discriminators, reason codes,
and security-invariant IDs. This release pins registry revision `1`; changing a
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

All Heterodyne-allocated kinds in the NIP-01 addressable range use the
`(pubkey, kind, d)` address. A singleton uses `['d', '']`; a multi-instance
schema defines a non-empty `d`. Examples MUST show the tag explicitly.

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
<!-- Monolith provenance: §3.0 and §12; split rules: ADR-033. -->
### 3.2 Owner stamps and historical bytes

An event carries at most one Heterodyne version stamp. Registry revision 1
defines these exhaustive classes:

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
   `production-rule:adr-031-kind0-v1` and
   `production-rule:adr-031-kind1-v1`, are non-stamping.
5. Double-ratchet outer kinds `1059` and `1060` carry no Heterodyne marker.
   An encrypted inner rumor carries only its Comms carrier stamp; it MUST NOT
   duplicate a Core or Control stamp.
6. Control never owns a wire stamp. A Control-profiled `kind:31001` retains the
   Core base-schema stamp, and its non-stamping profile changes no bytes.

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
- device-, session-, or ratchet-key wire events and non-stamping breadcrumb
  profiles MUST NOT carry it.

`['compromise_since', '<unix-seconds>']` occurs exactly once on a
compromise-declaring rotation and MUST NOT occur on a routine rotation.

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
  "created_at": 0,
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
exceed the sum of configured weights. The event MUST NOT carry `kel_head`.

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

The `p` tag MUST equal the cold root. `s` MUST advance from the prior accepted
event and `d` MUST equal `s`. `prior_digest` MUST equal the prior accepted
event id. `committed` requires the cold-root signature; `none` requires the
prior epoch-key signature and witness threshold. The event MUST NOT carry
`kel_head`.

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

<a id="core-kel-verification"></a>
<!-- Monolith provenance: §3.5.3. -->
### 4.4 KEL verification

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
   `prior_digest`, receipt schemes and signatures exactly as specified above,
   and cumulative distinct witness weight against the threshold in force at
   the prior accepted event. An unlisted or invalid receipt has zero weight.
4. On same-sequence forks, apply KERI first-seen witness behavior: each witness
   honors the first valid rotation it observed at that sequence. A branch is
   accepted only if attestations from witnesses that first saw that branch
   reach threshold. If none does, the KEL stalls and the implementation MUST
   expose stalled continuity. After signature and threshold validation, a
   repo-carried candidate is canonical over a conflicting relay-only candidate;
   the relay-only branch remains provisional and MUST NOT displace it.
   Duplicity MUST be surfaced.
5. Return the current epoch key, witness configuration, and half-open authority
   windows derived from accepted event timestamps and compromise declarations.

Only declared witness weight counts. Unregistered advisory attestations MUST
NOT move a rotation toward acceptance. A cached or exported KEL projection
MUST NOT displace replay of accepted source events.

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

A light-only device MAY have a publishing-key delegation without an NID. It
cannot sign Radicle refs and submits its Nostr event to an authorized full
node. Registry revision 1 reserves the non-stamping profile
`heterodyne-control-session-device-v1` with discriminator
`tags:heterodyne=delegation,binding_nonce,key_proof;radicle_nid=absent`. That
profile MUST NOT alter the Core base-schema stamp; its added semantics do not
change Core NID authority.

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

A node advertisement has `d` equal to RID and tags for `node_advert`, `rid`,
Ed25519 `nid`, one `endpoint`, `expiry`, `nid_proof`, the appropriate Core
version tag, and `kel_head` when epoch-signed. Its outer event is BIP-340-signed
by a dedicated node key or a current epoch key. The proof input also carries
the current canonical repo head as pinned by the conformance vectors.

The NID proof signs these exact UTF-8 bytes:

```text
heterodyne-node-advert-v1|<rid>|<nid>|<endpoint>|<expiry>|<repo_head>
```

A verifier MUST validate the outer signature, inner Ed25519 proof, equality of
all bound fields, and expiry. Invalid or expired ads MUST be discarded.

<a id="core-radicle-reconciliation"></a>
<!-- Monolith provenance: §3.9.10. -->
### 7.4 KEL and Radicle reconciliation

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

<a id="core-recovery"></a>
<!-- Monolith provenance: §3.7 and §3.12.2. -->
### 7.5 Infrastructure-loss recovery

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

<a id="core-multi-host-seeding"></a>
<!-- Monolith provenance: §3.11. -->
### 7.6 Multi-host seeding

Repository redundancy is opt-in Radicle seeding. A repository is replicated
by exactly the full nodes that elect to seed its RID; Core MUST NOT infer
replication from popularity or audience size. A persona needs at least one
durably connected full node for reliable propagation. A client MUST display
host count and durable-host status and SHOULD warn when no durable host is
advertised.

<a id="core-protected-repository"></a>
<!-- Monolith provenance: §3.8.6; split allocation: ADR-033. -->
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
path MUST return internal reason `provisional_not_final`; that reason maps to
the non-final `accept_provisional` outcome and MUST NOT become final acceptance
or a permanent rejection. Verification of an embedded signature MUST apply the
same head ordering, refresh, re-resolution, and `provisional_not_final` rules.

<a id="core-verification-accelerator"></a>
<!-- Monolith provenance: §4.5.1. -->
### 9.1 `kel_head` accelerator

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
and serves NIP-01 websocket access. A routing node stores no content and
answers only from verified `31005`/`31010` advertisements. A light node
connects directly to the returned full node and verifies locally. Routing
answers are untrusted hints; no routing node is on the integrity path.

A routing node MUST discard expired or unverifiable advertisements, MUST NOT
be required to proxy content, and MAY expose a cache only when that cache is
outside the integrity path. A light node MUST fetch content directly from a
repo relay or ordinary relay, MUST NOT be required to fetch it through a
routing node, and MUST verify every event locally before display or storage.

<a id="core-repo-relay"></a>
<!-- Monolith provenance: §10.1.2. -->
### 10.1 Repo-relay adapter

A repo relay MUST expose unmodified NIP-01, MUST NOT require a light client to
speak Radicle or git, MUST reject invalid Nostr signatures, and MUST persist
accepted events as signed objects in its backing repository. Before serving
canonical content, a full node MUST verify Radicle signed refs and the
identity-document threshold. It MUST namespace non-delegate contributions
under Radicle's signed-ref model.

Event authorship rests on the Nostr signature. The Ed25519 ref signature is a
storage attestation. A light device authors with its delegated secp256k1 key
and submits to an authorized full node for ref commitment.

The reserved event-storage namespace uses `refs/cobs/xyz.heterodyne.*` for
collaborative objects and an event-id-addressed append-log ref layout for
persona-owned events. Heartwood 1.9.x fixes fetch limits at 5 MiB for special
`rad/id` and `rad/sigrefs` refs and 5 GiB for data refs; an implementation MUST
NOT present these as Heterodyne-tunable limits.

Client conformance requires reading and writing NIP-01 events over a repo
relay. Server/storage conformance remains unavailable until the complete ref
namespace, filter-to-git mapping, retention, garbage-collection, and quota
contract is frozen. An implementation MUST NOT claim server/storage
conformance before that contract exists.

<a id="core-client-responsibilities"></a>
<!-- Monolith provenance: §10.2. -->
### 10.2 Client responsibilities

A Core client MUST create and verify NIP-01/BIP-340 events; read and write both
ordinary and repo relays; resolve the three node roles; manage root, KEL, and
delegation state; apply repo authority and provisional finality; enforce
version and registry pins; protect the keys repository; and provide onion
reachability. A full-node build SHOULD provide the derived export-AID
capability. Internal language, runtime, and packaging are unrestricted.

A repo relay SHOULD expose a monotonic ingestion watermark over its canonical
event-storage head. The watermark MUST strictly increase as submissions are
processed and MUST be comparable with a submission acknowledgement before it
is used as an absence proof for a delegation.

<a id="core-materialized-kel"></a>
<!-- Monolith provenance: §10.1.2. -->
### 10.3 Materialized-KEL storage profile

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

A conforming client MUST include self-contained capability to reach `.onion`
relay, repo-relay, routing-node, and full-node endpoints. It MUST NOT require a
separately installed daemon or externally configured SOCKS proxy, and MUST NOT
send an onion hostname to clearnet DNS. Browser/WASM clients MUST implement an
embedded-Tor WebSocket bridge path and visibly report when no bridge is usable.
A temporary bridge outage is an operational condition rather than a
conformance failure. Full-node Radicle replication SHOULD support onion peers.
An external system proxy MAY be honored but MUST NOT substitute for the
self-contained capability.

The client MUST also offer prominent user-controlled egress-over-Tor, default
OFF, with an active indicator. A selected strict profile MAY make it default
ON only when selection itself is explicit enablement and the behavior is
disclosed.

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
`INCOMPLETE_EXPORT`; non-security omissions require degraded status and
explicit warnings.

<a id="core-versioning"></a>
<!-- Monolith provenance: §12; split rules: ADR-033. -->
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
<!-- Monolith provenance: §12.2-§12.3; split rules: ADR-033. -->
### 12.1 Stable capability bootstrap

Every capability advertisement uses this Core-parsable bootstrap object:

```json
{
  "descriptor": "heterodyne-capabilities-v1",
  "bootstrap_version": "core/0.5.0",
  "registry_revision": 1,
  "supported_versions": {
    "core": ["core/0.5.0"],
    "comms": [],
    "control": [],
    "social": []
  },
  "required_features": [
    "core.identity.v1",
    "core.repo-relay-client.v1",
    "core.embedded-tor.v1"
  ],
  "strict_profiles": []
}
```

`descriptor`, `bootstrap_version`, `registry_revision`, and `core` support are
REQUIRED. Each supported-version set contains qualified versions for that
document only. `required_features` uses stable feature IDs; document names
alone do not establish feature conformance. `strict_profiles` contains stable
profile IDs and asserts only profiles actually implemented. Unknown fields and
unknown optional IDs MUST be retained or ignored safely, not reinterpreted.

The descriptor SHOULD be committed to the identity repo so a peer can discover
it without a higher protocol. A Core-only implementation MUST use this carrier;
absence of any higher carrier MUST NOT imply non-conformance. A read/write
client MUST advertise both `nostr_relay` and `repo_relay` features; a read-only
client MAY state a reduced set with rationale.

A peer-bound session MUST exchange advertisements and select a mutually
supported qualified version before either peer sends an event stamped with
that version. A peer MUST NOT stamp a version the receiver did not negotiate.
For asynchronous input, no negotiation is presumed: an unsupported stamped
version MUST be rejected or processed only by an explicitly declared degraded
mode that does not apply unknown security semantics. An unknown MAJOR MUST NOT
be silently treated as compatible.

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

Registry revision 1 binds these exact normative invariants:

- **CORE-I-IDENTITY-INTEGRITY**: The cold-root npub and accepted KEL are
  authoritative for persona identity; downstream caches and delegated
  identifiers cannot override them.
- **CORE-I-NID-DELEGATION-DUAL-PROOF**: A Radicle NID delegation is active only
  after both the persona epoch-key BIP-340 signature and the delegated NID
  Ed25519 proof verify over the same binding.
- **CORE-I-VERIFY-BEFORE-USE**: Every signed object is locally
  signature-verified and, where applicable, delegation-checked before
  rendering, storage, or authorization.
- **CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY**: Core discovery does not depend on a
  centralized persona, npub, RID, or serving-node directory.
- **CORE-I-KEY-MATERIAL-AT-REST**: Persona nsec, NID secrets, and sensitive
  cached identity material are protected by the Core keys-repository profile,
  including NIP-49 wrapping where applicable.

<a id="core-conformance"></a>
<!-- Monolith provenance: §14; split rules: ADR-033. -->
## 14. Conformance and vectors

Every Heterodyne implementation claims Core conformance. A claim MUST state
the exact qualified version, registry revision or digest, supported feature
IDs, strict-profile IDs, implementation role, and every dependency version.
Core has no document dependencies. Protocol conformance and vector conformance
are distinct claims.

Normative vectors compare canonical bytes and exact verdicts; semantic
equivalence is insufficient. Each vector has an immutable ID, owner document,
owner version, registry pin, qualified spec references, direction, input, and
expected output. Time-sensitive vectors use a simulated clock and production
vectors pin randomness. An incompatible behavior change MUST allocate a new
vector ID.

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
