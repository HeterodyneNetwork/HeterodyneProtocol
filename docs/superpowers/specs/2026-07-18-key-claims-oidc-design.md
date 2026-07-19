# Key Claims and OIDC Projection Design

**Date:** 2026-07-18
**Status:** Approved for planning after the ADR-033 split
**Protocol owner:** Heterodyne Comms, with bounded Core and Control integration

## Goal

Add a general key-claim plane to Heterodyne Comms. Claims can describe or
authorize any registered key type, can be issued by a persona or trusted third
party, and can be delivered publicly, pairwise privately, repository
privately, or retained locally. Persona-issued device authorization and
revocation state is anchored in a shared encrypted multi-writer Radicle
repository.

Expose selected validated claims through a standards-compatible OIDC/OAuth
projection. Third parties can validate signed ID Tokens, JWT access tokens,
and registered JWT assertions using ordinary HTTPS discovery and JWKS. A
public Radicle mirror supplies Heterodyne-native continuity, issuer recovery,
and token-status availability.

## Ownership and dependency placement

Core supplies canonical persona identity, KEL validation, typed authority
anchors, NID delegation, repository and canonical-branch primitives, and the
registry mechanism. Core does not depend on claims or OIDC.

Comms owns claim objects, claim validation, delegation/attenuation, private
delivery, repository synchronization, authoritative device-claim status,
public claim publication, JWT projection, issuer continuity, and token status.

Control consumes Comms claims for enrollment, RPC grants, agent/subagent
authority, and filtered claim views. Control does not redefine claim transport
or canonical status.

## Canonical claim object

Comms allocates:

- `kind:31013` for an atomic key claim;
- `kind:31014` for irreversible claim revocation/status.

A claim is a complete signed Nostr event even when it appears only inside DR
or repository ciphertext. Its canonical JSON content contains:

- `claim_id`, derived from the canonical semantic body;
- typed `issuer` and `subject` key references;
- `claim_class`, exactly `descriptive` or `authorization`;
- one namespace, name, and atomic JSON value;
- `issued_at`, `not_before`, and optional `expires_at`;
- optional relying-party audience restriction;
- visibility profile;
- optional parent claim and delegation constraints;
- qualified Comms version and registry revision.

Initial subject types are Nostr secp256k1, Radicle Ed25519 NID, and RFC 7638
JWK thumbprint. Initial issuers are Core-verifiable Heterodyne personas or
delegated secp256k1 claim issuers. Other proof suites require registered
profiles.

`claim_id` is lowercase hex SHA-256 over RFC 8785 JCS bytes of the complete
content object with the `claim_id` member omitted. The outer Nostr event ID,
signature, tags, and transport metadata are not inputs. Verifiers reject a
non-lowercase ID or a mismatch.

Changing a semantic field therefore produces a new claim ID. A second event at the old
`(issuer, kind:31013, d=claim_id)` address is valid only when its canonical
semantic body is identical. A valid `kind:31014` revocation is irreversible;
renewal or correction issues a new claim.

`kind:31014` content names the target `claim_id`, `revoked_at`, and a registered
reason code. For an authorization claim, a revocation is valid when signed by
the claim issuer, an active ancestor issuer in its issuance chain, the
authoritative persona epoch/cold-root authority, or the subject key itself.
Subject-signed revocation is self-revocation and can only reduce the subject's
authority. For a descriptive claim, only its issuer, an explicitly named
revoker, or a superior issuer in the issuance chain can revoke the assertion;
the subject may issue a separate rejection claim but cannot erase what the
third-party issuer asserted.

Claims are deliberately atomic. Selective release chooses individual signed
claims rather than introducing SD-JWT disclosure into the first profile.

## Trust, authorization, and delegation

Cryptographic validity does not imply issuer trust. A verifier or OIDC release
policy selects trusted issuers and namespaces. Third-party descriptive claims
use the same object and retain their external provenance when cached.

Authorization use requires:

- a bounded expiry;
- fresh proof of possession of the subject key;
- live Core/KEL issuer and delegation authority;
- active repository-confirmed state;
- exact namespace, audience, and resource matching.

A holder may redelegate only with an explicit scoped claim-issuance
capability. A child must preserve or narrow every scope dimension, shorten the
validity window, name its parent, and decrement the remaining depth. The first
profile permits at most eight issuance edges. Claims never imply automatic
redelegation.

## Processing states and order

Implementations expose `invalid`, `untrusted`, `provisional`, `active`,
`expired`, `revoked`, and `conflicted` states. Authorization fails closed for
every state except `active`. Descriptive interfaces may show untrusted or
provisional claims only with provenance and assurance labels.

The verification pipeline is:

1. Parse canonical bytes and recompute `claim_id`.
2. Verify the event signature and Core/KEL issuer authority.
3. Resolve the claim-issuance chain.
4. Prove attenuation and enforce the depth bound.
5. Check time, audience, namespace, and subject type.
6. Resolve repository confirmation and revocation.
7. Require fresh subject proof for authorization.
8. Apply local trust and release policy.

Authentication precedes policy. Policy can reject a valid claim but cannot
accept an invalid, unconfirmed, expired, revoked, or conflicted one.

## Private claim repository

Each persona has one encrypted private multi-writer claim repository. Direct
replication and decryption require a durable NID-bearing
`claim-ledger-reader` authorization. NID-less session devices receive filtered
views over Comms/Control and never receive repository key material.

The repository is authoritative for persona-issued device authorization claims
and revocations. A DR-delivered grant cannot authorize until it is reachable
from canonical repository state. A valid revocation or authority reduction
takes effect immediately when authenticated and later becomes repository
final. Third-party claims may be cached without becoming trusted.

Sensitive objects are encrypted with a dedicated ledger audience key. Paths
use keyed derivation and commits reveal no claim type, subject, or revocation
count. Removing a reader commits the revocation, rotates the audience key,
distributes it only to remaining readers, removes Radicle access, and retires
the old encrypted branch under Comms scrub rules.

Repository merge semantics are append-only for claims and issuance records,
irreversible revocation-wins for status, and authority-reduction-wins for
concurrent authorization changes. Conflicting non-monotonic policy changes
remain unresolved and cannot authorize operations or token minting.

Credential-plane onboarding sends the reader authorization, repository
location, canonical checkpoint, current audience key, compact state, and
Radicle access over a DR self-DM.

## Public issuer continuity tree

Private claim contents never enter the persona's public repository. The
canonical `main` branch exposes only public OIDC material beneath the immutable
cold-root NIP-19 npub:

```text
.well-known/<cold-root-npub>/
  issuer.json
  openid-configuration
  jwks.json
  manifest.json
  status-lists/<list-id>.jwt
```

The manifest includes the root key in raw lowercase hex, the current HTTPS
issuer, sequence and predecessor, current and retiring key digests, status-list
digests, and any successor declaration. Web and repository JWKS/status-token
copies are byte-identical.

The repository manifest is authoritative for Heterodyne issuer continuity.
HTTPS discovery remains authoritative for ordinary OIDC validation under its
exact current issuer. A mismatch fails closed. The repository may authorize a
successor URL; vanilla OIDC clients still register or trust that new exact
issuer normally.

## OIDC issuer and endpoints

Each persona has one active issuer URL:

```text
https://<node>/oidc/<cold-root-npub>
```

OIDC Discovery is served at:

```text
https://<node>/oidc/<cold-root-npub>/.well-known/openid-configuration
```

The RFC 8414 metadata alias is:

```text
https://<node>/.well-known/oauth-authorization-server/oidc/<cold-root-npub>
```

Issuer metadata, ID Tokens, and access tokens use the exact same `issuer`/`iss`
string.

The initial profile requires Authorization Code with PKCE and OAuth Device
Authorization. It prohibits implicit, password, and Client Credentials grants.
Client Credentials is reserved for a future sender-constrained workload
profile and never represents persona authentication.

Clients are explicitly registered. Claim release is the intersection of
requested scopes/audience, client policy, user consent, active repository
state, trusted namespaces, and subject proof requirements. OIDC `sub` is
pairwise by default. Stable Heterodyne key references require a dedicated
scope and explicit consent.

## Shared issuer keys and multi-writer minting

OIDC signing keys synchronize through the private repository. A signing key is
separately envelope-encrypted to devices with an active
`oidc-token-issuer` claim; ordinary ledger readers cannot decrypt it.

Any node holding the key, active issuer authorization, and sufficiently fresh
repository state may mint for the persona's one active `iss`. The issuer
manifest declares the maximum acceptable checkpoint age, which MUST NOT exceed
300 seconds in the initial profile. A node synchronizes before minting and
stops minting if it cannot meet that bound. Each private issuance record and
Heterodyne JWT extension identify the repository checkpoint used. The private
record also maps the JWT `jti` and status-list allocation to every source
`claim_id`, so revoking any source authorization deterministically invalidates
all derived tokens.

Removing issuer authority stops minting immediately. Suspected signing-key
compromise revokes the key, invalidates its outstanding tokens, rotates the
shared key material, updates JWKS, and publishes new status lists.

## JWT interoperability profile

Authorized nodes can issue:

- OIDC Core ID Tokens;
- RFC 9068 JWT access tokens;
- signed JWT assertions under separately registered profiles.

These JWTs are projections, not canonical encodings of `kind:31013` claims.
Third parties validate them using standard HTTPS discovery, exact issuer,
JWKS/JWS signature, audience, time, nonce where applicable, and token-type
rules.

RS256 support is required for interoperability. ES256 and EdDSA may be
advertised. Access tokens use `typ: at+jwt` and contain `iss`, `sub`, `aud`,
`exp`, `iat`, `jti`, `client_id`, `scope`, and token status. Authorization
tokens use `cnf` sender constraints when the relying party supports DPoP or
mutual TLS.

## Token Status Lists

Comms 0.5 pins `draft-ietf-oauth-status-list-21`. A projected JWT contains the
draft-standard `status.status_list` object with `uri` and `idx`, plus a
top-level collision-resistant Heterodyne JWT claim identifying the Radicle RID,
branch, path, and digest of the byte-identical mirror. The Heterodyne member is
outside the draft's `status` object, so an ordinary draft-21 verifier processes
only the registered `status_list` mechanism.

The standard HTTPS status URI returns a separate signed Status List Token as
`application/statuslist+jwt`; status data is not embedded in `jwks.json`.
JWKS may contain a collision-resistant pointer to the status manifest that
ordinary JWK consumers ignore.

Status values in the first profile are only `VALID` and `INVALID`. Status List
Tokens carry signed `iat`, `exp`, and `ttl`. A valid status never overrides an
expired or otherwise invalid JWT. A stale or unverifiable list is not valid
evidence of `VALID`.

Concurrent writers avoid `(uri, idx)` reuse by allocating in NID-derived
namespaces:

```text
status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

The writer durably commits its issuance record and index before returning the
JWT. Multiple writers' records merge through Radicle; revocation-wins state
allows any authorized node to regenerate the same lists. Heterodyne-aware
validators may use the digest-bound Radicle mirror if HTTPS is unavailable.

Because draft 21 is work in progress, Comms cannot claim 1.0 while depending
on it unless the final RFC is frozen or Comms locally freezes the complete
profile it requires.

## Operational flows

Claim issuance is: validate issuer authority, commit, synchronize, deliver,
and confirm repository inclusion.

Revocation is: authenticate, stop affected operations, commit, merge with
revocation-wins, rotate repository or issuer keys when required, and regenerate
affected status lists.

JWT minting is: synchronize, resolve active claims, obtain consent, allocate a
writer-namespaced status entry, commit the issuance record, sign, and publish
the updated status token.

Issuer failover is: commit a signed successor manifest, serve the new exact
issuer and JWKS, stop old issuance, and retain old JWKS/status tokens until all
old JWTs expire.

## Security invariants

The Comms threat model adds namespaced invariants for:

- claim authenticity and canonical IDs;
- strict attenuation and bounded issuance chains;
- repository authority and rollback rejection;
- immediate authority reduction and monotonic revocation;
- ledger and issuer-key confinement;
- pre-mint repository freshness;
- exact issuer continuity;
- consent and claim-release minimization;
- JWT type separation and audience binding;
- status-list integrity, freshness, collision avoidance, and privacy.

Public discovery never contains private claims, consent records, issuance
mappings, or repository decryption material.

## Conformance vectors

The normative corpus covers:

- canonical claim IDs and typed key references;
- persona, delegated, and third-party issuance;
- untrusted issuers and invalid KEL authority;
- valid attenuation and rejection of widening, extension, and excess depth;
- proof of possession and copied-token rejection;
- provisional grants, immediate revocation, and repository confirmation;
- encrypted path/content privacy and reader-key rotation;
- NID-less repository denial;
- multi-writer merge, conflicts, and revocation-wins;
- OIDC discovery, exact issuer, PKCE, and Device Authorization;
- pairwise subject and consent-gated stable-key release;
- RFC 9068 tokens and ID/access-token confusion rejection;
- draft-21 encoding, expiry, TTL, invalidation, and double-allocation checks;
- byte-identical HTTPS/Radicle mirrors and digest mismatch rejection;
- shared-key minting by multiple authorized nodes;
- stale/revoked issuer authority and issuer succession.

Changed semantics always receive new vector IDs.

## Acceptance criteria

The feature is ready for normative integration when:

1. A new accepted ADR records the kind allocations, ownership, draft-21 pin,
   repository authority, and OIDC projection.
2. The ADR-033 split is complete and the design integrates into Comms with
   bounded Core/Control amendments only.
3. Claim verification and merge behavior are deterministic and vectorized.
4. Private metadata is absent from public repos and outer transport metadata.
5. Multiple authorized nodes can mint without index collisions or stale-state
   authorization.
6. Vanilla OIDC/OAuth parties can validate JWTs without Heterodyne software.
7. Heterodyne-aware parties can recover issuer keys and token status from the
   canonical public Radicle mirror.
8. Registry, schema, generator, threat model, and companion documentation all
   pass the family conformance checks.

## Standards profile

- OpenID Connect Core 1.0 and Discovery 1.0
- OAuth 2.0 Authorization Server Metadata, RFC 8414
- JSON Web Token, RFC 7519
- JSON Web Key, RFC 7517; JWK thumbprint, RFC 7638
- JWT Profile for OAuth 2.0 Access Tokens, RFC 9068
- OAuth Device Authorization Grant, RFC 8628
- PKCE, RFC 7636
- DPoP, RFC 9449; OAuth mutual TLS, RFC 8705
- Token Status List, `draft-ietf-oauth-status-list-21` (exact 0.5 pin)
