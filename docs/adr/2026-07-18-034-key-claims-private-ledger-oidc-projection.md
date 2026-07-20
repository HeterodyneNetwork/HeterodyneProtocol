# ADR-034: Key claims, private persona ledger, and OIDC projection

**Date:** 2026-07-18
**Status:** Accepted
**Decision makers:** user (design questionnaire and approval); Codex implementation

## Context

Heterodyne devices need a general way to make narrowly scoped assertions about
specific keys. Some assertions are descriptive; others authorize a key to read
a repository, synchronize credentials, issue further attenuated claims, mint a
token, or invoke a resource. Existing Core delegations identify persona and
device authority, but do not provide an atomic, selectively releasable claim
plane or ordinary OAuth/OIDC interoperability.

The same persona may have several online nodes. Those nodes need one shared
authorization view and must not become independent issuers merely because they
serve different HTTPS origins. A node can disappear or its hostname can change,
so the persona also needs a continuity mechanism anchored in its Radicle
profile. At the same time, an ordinary relying party must be able to validate a
JWT with standard HTTPS discovery and JWKS without implementing Heterodyne.

ADR-033 established the four-document family and its downward-only dependency
graph. Core owns persona/KEL, typed authority, NID delegation, repository, and
registry primitives. Comms owns private delivery and synchronization. Control
is a Comms profile and needs to consume authorization decisions without
defining another claim protocol.

The applicable interoperability references are OpenID Connect Core and
Discovery, RFC 7517 (JWK), RFC 7519 (JWT), RFC 7636 (PKCE), RFC 7638 (JWK
thumbprints), RFC 8414 (authorization-server metadata), RFC 8628 (Device
Authorization), RFC 8705 (OAuth mutual TLS), RFC 9068 (JWT access tokens), RFC
9449 (DPoP), and exactly `draft-ietf-oauth-status-list-21`. The status-list
draft is not followed by floating reference: Comms 0.5 freezes the complete
draft-21 behavior it uses.

## Decision

Heterodyne adopts Comms-owned atomic typed-key claims, an encrypted private
multi-writer persona claim ledger as the canonical device-authorization state,
and an OIDC/OAuth projection whose public HTTPS material has a simultaneous
Radicle continuity mirror.

### Ownership and allocations

Core remains unaware of claim or OIDC policy. It supplies only generic typed-key
parsing and native proof-verification hooks, KEL authority results, NID
delegation, and repository/canonical-branch primitives. Comms owns claim and
revocation objects, trust and attenuation, ledger convergence, OIDC/OAuth,
issuer continuity, JWT projection, and token status. Control consumes Comms'
active/inactive authorization result for enrollment, RPC, agent, and filtered
session-device views; it does not redefine claim transport or status.

Registry revision 2 allocates the following draft Comms base kinds beginning in
`comms/0.5.0`:

- `kind:31013`: atomic key claim;
- `kind:31014`: irreversible claim revocation/status.

Each kind registers separate, immutable, non-stamping proof-profile
discriminators for `nostr-bip340-v1`, `radicle-ed25519-v1`, and `jwk-jws-v1`.
Their profile identifiers distinguish claim use from revocation use. A future
semantic change allocates a new profile identifier or discriminator rather than
reinterpreting old events. Because the base schemas are Comms-owned, their
single wire stamp is `comms/<semver>` under ADR-033.

### Atomic claims and native subject proof

A claim carries exactly one `(namespace, name, atomic JSON value)` assertion.
Its semantic body includes a canonical `claim_id`, typed issuer and subject,
claim class (`descriptive` or `authorization`), issue and validity times,
audience and visibility, qualified Comms version and registry revision, plus an
optional parent and delegation constraints. Initial key references are:

- Nostr `secp256k1` x-only public keys;
- Radicle Ed25519 node IDs;
- RFC 7638 JWK thumbprints.

The first native possession suites are BIP-340 for a Nostr key, Ed25519 for a
Radicle NID, and JWS verification against a JWK whose RFC 7638 thumbprint equals
the subject reference. The proof binds a fresh challenge, purpose, audience,
claim identifier, and verifier context. An authorization claim is unusable
without fresh proof of possession; signature validity alone is not possession.
The outer Nostr event remains independently signature-verified.

`claim_id` is lowercase hexadecimal SHA-256 over RFC 8785 JCS bytes of the
complete semantic body with only `claim_id` omitted. Transport, Nostr event ID,
outer signature, and tags are excluded. Any semantic change creates a new ID.
A second event at the same address is acceptable only when its canonical
semantic body is byte-identical.

Atomicity makes selective release a choice among independent signed claims.
SD-JWT disclosure is deliberately not part of this first profile.

### Delegation and strict attenuation

Cryptographic validity is separate from issuer trust. Relying-party policy
chooses trusted issuers and namespaces only after canonical bytes, signatures,
Core/KEL authority, the issuance chain, time, audience, subject type,
repository state, revocation, and subject proof have passed.

Redelegation requires an explicit scoped claim-issuance capability. A child
must preserve or narrow every namespace, audience, resource, validity, and
purpose dimension, name its parent, and decrement `remaining_depth`. It cannot
implicitly gain redelegation. The complete chain is acyclic and has a strict
maximum of eight issuance edges; an eighth child may authorize within its
scope but cannot create a ninth edge.

### Layered and irreversible revocation

A valid `kind:31014` revocation names one `claim_id`, a `revoked_at` instant,
and a registered reason. It is permanent. Renewal or correction always creates
a new claim ID.

Authorization claims can be revoked by the issuing key, an active superior
issuer in the verified chain, the authoritative persona epoch/cold-root
authority, or the subject key itself. Subject revocation is self-reduction and
can never increase authority. A descriptive claim can be revoked only by its
issuer, an explicitly named revoker, or a superior issuer; its subject may
publish a separate rejection but cannot erase the issuer's assertion.

Revocation is layered. A verifier applies direct claim revocation, ancestor or
issuer-authority revocation, subject-key/KEL revocation, ledger-reader and token-
issuer authority reduction, issuer signing-key compromise, and derived-token
status. Any valid reduction at any layer wins. It takes effect immediately when
authenticated, even before the next repository merge, and later becomes
repository-final. No `VALID` token-status bit can restore an expired, invalid,
or otherwise revoked authorization.

### Authoritative private multi-writer ledger

Each persona has one encrypted private Radicle claim repository, shared by its
authorized devices and nodes. It is the authoritative record for persona-issued
device authorization, revocation, consent, OIDC issuance mappings, and signing-
key distribution. Radicle synchronization is multi-writer: an online writer is
not excluded merely because another authorized writer can mint.

A delivered grant is provisional and cannot authorize until it is reachable
from canonical repository state. Conversely, an authenticated revocation or
authority reduction stops affected operations immediately and is committed for
repository finality. Claims and issuance records merge append-only;
revocation-wins and authority-reduction-wins are monotonic. Concurrent
non-monotonic policy changes remain conflicted and fail closed.

Direct repository replication and decryption require an active, durable,
NID-bearing `claim-ledger-reader` authorization. NID-less session devices may
receive filtered views over Comms or Control but never repository access or
decryption keys. Reader removal commits the revocation, rotates the dedicated
ledger audience key, distributes the new key only to remaining readers, removes
Radicle access, and retires old ciphertext under Comms scrub rules. Encrypted
paths are keyed so repository metadata does not reveal claim type, subject, or
revocation count.

### One issuer and simultaneous Radicle continuity

A persona has exactly one active HTTPS issuer string:

```text
https://<node>/oidc/<cold-root-npub>
```

OIDC discovery is served below that issuer and the RFC 8414 alias is served at
the corresponding host-level well-known path. Metadata and every JWT use the
same exact issuer string. One node may host several personas by serving a
separate immutable cold-root path for each. A hosting node exposes the current
and retiring public issuer keys for every persona issuer it is trusted to
serve, not merely keys generated by that node.

At the same time, canonical `main` in the persona's public Radicle profile
repository contains:

```text
.well-known/<cold-root-npub>/
  issuer.json
  openid-configuration
  jwks.json
  manifest.json
  status-lists/<list-id>.jwt
```

The root-key identifier in the path prevents issuer collisions on a shared
node. The signed manifest binds the raw lowercase cold-root key, exact current
HTTPS issuer, sequence and predecessor, all current and retiring public-key
digests, status-list paths and digests, and an optional successor issuer.
Public material is committed on canonical `main`; HTTPS and repository
JWKS/status-token copies are byte-identical. The Radicle manifest is
authoritative for Heterodyne continuity and can publish a successor URL after
the current node is unavailable. Ordinary OIDC validation remains rooted in
the exact HTTPS issuer and normal trust/registration for any successor. A
mismatch fails closed.

Private claims, reader membership, consent, issuance mappings, and decryption
or signing secrets never enter this public tree. Status data is a separate
signed Status List Token, not embedded in `jwks.json`; JWKS may carry a
collision-resistant pointer which ordinary JWK processors ignore.

### Shared issuer keys and mint authority

OIDC signing keys synchronize through the private claim repository but are
separately envelope-encrypted from the ledger audience key. Only a node with
all three of the following may mint for the persona's one active issuer:

1. the usable signing key;
2. active `oidc-token-issuer` authority;
3. a synchronized canonical ledger checkpoint within the issuer manifest's
   age bound, which MUST NOT exceed 300 seconds.

Thus any synchronized online node holding the key may mint; authority is not
reserved to a single server. The node stops immediately when its authority is
reduced or it cannot meet the freshness bound. Each private issuance record
binds `jti`, writer namespace, status allocation, ledger checkpoint, and all
source claim IDs. Shared-key compromise invalidates outstanding tokens, rotates
key material, updates JWKS, and publishes replacement status lists.

### OAuth/OIDC and interoperable JWT profile

The required human/device flows are Authorization Code with PKCE and OAuth
Device Authorization. Clients are explicitly registered. Implicit, Resource
Owner Password Credentials, and Client Credentials grants are prohibited.
Client Credentials is reserved for a future sender-constrained workload
profile and never represents persona authentication.

Claim release is the intersection of requested scopes and audience, client
policy, explicit consent, active repository state, trusted namespaces, and
subject-proof requirements. `sub` is pairwise by default. Stable key release
requires scope `heterodyne:key-ref`, explicit consent, and uses claim
`https://heterodyne.network/jwt/key-ref`. JWTs also use
`https://heterodyne.network/jwt/ledger-checkpoint` and
`https://heterodyne.network/jwt/status-mirror` for the private checkpoint and
public Radicle mirror binding.

Authorized nodes may issue OIDC ID Tokens, RFC 9068 JWT access tokens, and
signed JWT assertions under separately registered profiles. RS256 support is
mandatory so third parties can validate with ordinary discovery and JWKS; ES256
and EdDSA may also be advertised. Access tokens carry `typ: at+jwt` and the RFC
9068 claims including `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`,
and `scope`. ID-token nonce and token-type separation are enforced. DPoP or
mutual-TLS `cnf` sender constraints are used when the relying party supports
them. These JWTs are projections of current claim state, never canonical
encodings of `kind:31013`.

### Draft-21 token status and writer allocation

Comms 0.5 normatively pins `draft-ietf-oauth-status-list-21`. Projected JWTs
carry the draft's `status.status_list` object with `uri` and `idx`, while the
top-level collision-resistant Heterodyne status-mirror claim binds Radicle RID,
canonical branch, path, and digest. The HTTPS URI returns a separately signed
`application/statuslist+jwt` Status List Token with the pinned compressed bit-
array encoding and signed `iat`, `exp`, and `ttl`. Initial values are only
`VALID` and `INVALID`; stale or unverifiable status is never evidence of valid
authorization.

Writers allocate without central serialization in durable NID-derived paths:

```text
status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

Within that namespace the writer durably commits the issuance record and index
before returning the JWT. It never reuses `(uri, idx)`. Authorized nodes can
regenerate merged revocation-wins lists, and Heterodyne-aware verifiers can use
the digest-bound Radicle copy when HTTPS is unavailable.

## Security and privacy consequences

The design adds explicit invariants for claim authenticity, attenuation,
repository authority, irreversible revocation, ledger and issuer-key
confinement, mint freshness, issuer continuity, minimized release, JWT type and
audience separation, and status integrity. Authorization fails closed for
invalid, untrusted, provisional, expired, revoked, or conflicted state; only
`active` authorizes. Descriptive UIs may show untrusted or provisional claims
only with provenance and assurance labels.

Compromise of a ledger reader no longer automatically yields the issuer key,
but compromise of an authorized issuer node can mint until reduction is seen;
the 300-second maximum checkpoint age bounds stale minting and immediate
reduction stops synchronized nodes sooner. Public continuity reveals issuer
URLs, public key rotation, and coarse status-list activity, but no private
claim, subject, consent, issuance mapping, repository membership, or plaintext
revocation reason.

Because draft 21 is not yet an RFC, Comms cannot claim 1.0 while depending on
it unless the resulting RFC is adopted through a versioned migration or Comms
freezes the complete required profile locally.

Registry revision 2 allocates these exact Comms security invariants. They are
the accepted ADR evidence until the claims threat-model integration task moves
their exact text into the family threat model:

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

## Migration

Registry revision 1 remains immutable. Revision 2 is the complete revision-1
entry set plus the new kinds, profiles, reason codes, and invariants. Existing
vectors and historical event interpretations do not change. New claims,
revocations, claim repositories, issuer trees, JWTs, and status lists pin
registry revision 2 and `comms/0.5.0`; they receive new conformance vector IDs.

Deployments create the private encrypted claim repository, issue NID-bearing
reader claims, synchronize its canonical checkpoint, provision issuer keys only
to separately authorized nodes, and then publish the root-key-scoped public
continuity tree. An existing ad hoc token or device grant is not imported as
active merely because it predates this ADR: it must be reissued, proven,
committed, and confirmed under the new profile.

## Rejected alternatives

- **One compound credential per device.** Rejected because changing or
  selectively releasing one assertion would replace unrelated authority.
- **SD-JWT as the canonical claim format.** Deferred; atomic signed claims
  provide selective release without a second disclosure protocol.
- **HTTPS or an individual node as authorization authority.** Rejected because
  it fragments a persona across nodes and fails over poorly.
- **A public claims repository.** Rejected because subjects, consent,
  membership, and authorization history are sensitive even when content is
  signed.
- **Single-writer token minting or leader exclusion.** Rejected because the
  private Radicle repository is already multi-writer and synchronized nodes
  with the same scoped key can safely allocate in disjoint namespaces.
- **One issuer per node.** Rejected because a persona needs one stable issuer;
  node changes are handled by root-key-scoped Radicle succession.
- **Only Heterodyne-native tokens.** Rejected by the requirement that ordinary
  third parties validate JWTs using standard OIDC discovery, RS256, and JWKS.
- **Embedding status data in JWKS.** Rejected because draft 21 defines a
  separate signed Status List Token; only an ignorable pointer belongs in JWKS.
- **A floating status-list draft reference.** Rejected because later drafts may
  change bytes or validation behavior silently.
- **Client Credentials for persona authentication.** Rejected because it does
  not establish interactive persona or device possession and consent.
- **Grant-before-commit.** Rejected because delivery alone is neither merged
  canonical state nor reliable revocation visibility.
- **Revocation that can be undone.** Rejected because rollback and concurrent
  writers could resurrect authority; renewal gets a new claim ID instead.

## Conformance obligations

Normative vectors must cover canonical IDs, typed references, all native proof
profiles, persona/delegated/third-party issuance, untrusted and invalid issuers,
strict attenuation and eight-edge rejection, fresh proof of possession,
provisional and repository-final states, each authorized and unauthorized
revocation path, encryption/path privacy, reader rotation and NID-less denial,
multi-writer merge/conflict/revocation-wins, discovery and exact issuer,
required/prohibited grants, pairwise and consent-gated stable subjects, RFC
9068/token-type confusion, shared-key multi-node minting and freshness, draft-21
encoding/allocation/freshness/invalidation, byte-identical public mirrors,
digest mismatch, key compromise, and issuer succession.

Those vectors model bytes, state transitions, and authorization decisions.
They do not prescribe an HTTP server, programming language, or modified Nostr,
Radicle, or Matrix infrastructure.
