# Heterodyne protocol-family threat model

**Status:** Draft, non-normative security analysis for the 0.5.x family.

[`docs/spec/heterodyne.md`](../spec/heterodyne.md) is the non-normative family
map. Security requirements are owned by the four versioned documents below.

This document analyzes the four independently versioned documents:

- [Heterodyne Core](../spec/heterodyne-core.md) — identity, verification,
  registry, node roles, and repository substrate;
- [Heterodyne Comms](../spec/heterodyne-comms.md) — publishing, privacy tiers,
  retrieval, direct messages, atomic claims, private-ledger authority, OIDC/JWT
  projection, and encrypted subprotocol carriage;
- [Heterodyne Control](../spec/heterodyne-control.md) — the currently inactive
  own-device command profile over Comms; and
- [Heterodyne Social](../spec/heterodyne-social.md) — social behavior,
  moderation, and the optional Matrix feature.

The owner sections below reproduce registry revision 3 and security boundaries
without creating or relaxing requirements. The family's only normative
dependency edges are:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Social has no dependency on Control. A client may implement both as separate
conformance claims.

## 1. Security assumptions

The family assumes that endpoint secrets and the selected cryptographic
primitives remain secure. A compromised endpoint can act with every key it
holds until the applicable rotation or revocation becomes effective. Network
services are not assumed honest: relays, repositories, routing nodes, full
nodes, and Matrix homeservers may observe metadata, omit, delay, reorder, or
replay traffic.

Authentication always precedes policy. Routing advertisements, repository
location, social relationships, moderation labels, and Matrix state never
substitute for local signature, KEL, delegation, or schema verification.
Availability from multiple carriers reduces withholding risk but does not make
any carrier authoritative for persona identity.

## 2. Registry-bound invariants

The descriptions below reproduce registry revision 3 exactly.
Registry-bound rows cite an invariant where that invariant directly governs
the mitigation. Metadata residuals, operational consequences, out-of-scope
limitations, and open work may instead be cross-cutting and are not assigned a
false invariant merely for uniformity.

### 2.1 Core

- **CORE-I-IDENTITY-INTEGRITY:** The cold-root npub and accepted KEL are authoritative for persona identity; downstream caches and delegated identifiers cannot override them.
- **CORE-I-NID-DELEGATION-DUAL-PROOF:** A Radicle NID delegation is active only after both the persona epoch-key BIP-340 signature and the delegated NID Ed25519 proof verify over the same binding.
- **CORE-I-VERIFY-BEFORE-USE:** Every signed object is locally signature-verified and, where applicable, delegation-checked before rendering, storage, or authorization.
- **CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY:** Core discovery does not depend on a centralized persona, npub, RID, or serving-node directory.
- **CORE-I-KEY-MATERIAL-AT-REST:** Persona nsec, NID secrets, and sensitive cached identity material are protected by the Core keys-repository profile, including NIP-49 wrapping where applicable.

### 2.2 Comms

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
- **COMMS-I-PUBLIC-READER-TIER1-ONLY:** A public-reader implementation consumes only verified Tier 1 content and never renders Tier 2 plaintext or interprets Tier 3 ciphertext as public content.
- **COMMS-I-AGENT-ROLE-BINDING:** Every agent-authored event signer, workload registration, token role claim, and active role-addressed delegation identify the same dedicated full-node-held role key.
- **COMMS-I-AGENT-ATTRIBUTION:** Every agent-authored application event carries the canonical automation attribution block at its tier-appropriate protected location.
- **COMMS-I-WORKLOAD-TOKEN-CONFINEMENT:** Workload tokens, token identifiers, private source claims, and sender proofs remain confined to the protected authorization and audit boundary.

### 2.3 Control

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests, grants, tokens, or side effects are encrypted at rest under Core, Comms, and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never receives persona epoch, NID, audience, repository-decryption, or ratchet secrets.
- **CONTROL-I-INGRESS-RELAY-AFFINITY:** A Control response is published first and only to the authenticated request ingress relay, while identical cross-relay retries reuse one restart-safe execution result.
- **CONTROL-I-AGENT-NO-KEY-RELEASE:** An automated principal never receives or directly exercises a persona, epoch, NID, human-device, or agent-role private key.
- **CONTROL-I-AGENT-INTENT-ONLY:** An automated principal publishes only through the intent-level agent method, and raw signing, human-profile fallback, and attribution bypass fail closed.
- **CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS:** Every automated side effect requires a current scoped token, sender proof, canonical authorization state, and finite kind, resource, size, rate, and burst limits.

Control 0.5.0 is incomplete. These identifiers reserve its boundary but do not
make Control or `heterodyne-control-strict-v1` claimable. In particular,
CONTROL-I-AUDIT-AT-REST depends only on Core, Comms, and Control protections;
Social and Matrix are outside that dependency.

### 2.4 Social

- **SOCIAL-I-MATRIX-E2EE:** Private Matrix discussion and configuration content, including protected state, remains end-to-end encrypted and downgrade-resistant from the homeserver.
- **SOCIAL-I-MXID-DELEGATION-DUAL-PROOF:** A Matrix MXID delegation requires both the persona epoch-key signature and successful MXID self-publication through Matrix state authorization.
- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE:** Matrix and cross-protocol Social bridging runs on user-controlled clients; no homeserver or relay bridge receives protected plaintext.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-REMEDIATION-SCOPED:** Agent-policy enforcement and remediation target only the offending role device key; replacement at the same role address never requires epoch-key rotation.

The three Matrix-specific invariants apply only to the optional Matrix feature.
A Matrix-free Social implementation still applies the private-state and
social-graph invariants.

## 3. Assets and trust boundaries

| Asset | Owner and boundary | Principal invariant |
|---|---|---|
| Cold-root and epoch secrets | User endpoint; cold root normally offline | CORE-I-IDENTITY-INTEGRITY, CORE-I-KEY-MATERIAL-AT-REST |
| Accepted KEL and `nip01_raw` | Verified locally from signed bytes | CORE-I-VERIFY-BEFORE-USE |
| Radicle NID secret and delegation | Authorized full device | CORE-I-NID-DELEGATION-DUAL-PROOF |
| Tier 1 content | Public by design | COMMS-I-CLIENT-SIDE-DELIVERY |
| Tier 2 content | Plaintext on every allowed seeder | COMMS-I-TIER2-HONESTY |
| Tier 3 content and audience keys | Ciphertext outside key-holding endpoints | COMMS-I-TIER3-BLIND-CARRIER, COMMS-I-CONFIG-AT-REST |
| Double-ratchet state | Accepted participant devices only | COMMS-I-CLIENT-SIDE-DELIVERY |
| Atomic key claims and native proofs | Locally verified signed objects; trust follows cryptographic validity | COMMS-I-CLAIM-AUTHENTICITY, COMMS-I-CLAIM-ATTENUATION |
| Private claim ledger and audience key | Active durable NID-bearing readers only | COMMS-I-CLAIM-REPOSITORY-AUTHORITY, COMMS-I-CLAIM-REVOCATION, COMMS-I-LEDGER-CONFINEMENT |
| OIDC signing keys and mint authority | Separately authorized, fresh synchronized issuer nodes | COMMS-I-ISSUER-KEY-CONFINEMENT, COMMS-I-MINT-FRESHNESS |
| Public OIDC metadata, JWKS, and status | HTTPS plus byte-identical public Radicle continuity tree | COMMS-I-ISSUER-CONTINUITY, COMMS-I-JWT-TYPE-AUDIENCE, COMMS-I-STATUS-INTEGRITY |
| Consent and projected claim release | Canonical private ledger plus explicit relying-party policy | COMMS-I-CLAIM-RELEASE |
| Public-reader target and resolved content | Fragment-local target; verified Tier 1 rendering only | COMMS-I-PUBLIC-READER-TIER1-ONLY, CORE-I-VERIFY-BEFORE-USE |
| Agent role key | Full-node key store; never released to the automated principal | COMMS-I-AGENT-ROLE-BINDING, CONTROL-I-AGENT-NO-KEY-RELEASE |
| Workload token, sender proof, and agent audit | Protected authorization/audit boundary; never public event content | COMMS-I-WORKLOAD-TOKEN-CONFINEMENT, CONTROL-I-AUDIT-AT-REST |
| Control audit and session authority | User-controlled Control endpoint | CONTROL-I-AUDIT-AT-REST, CONTROL-I-SESSION-KEY-CONFINEMENT |
| Social private configuration | Protected local/config storage | SOCIAL-I-PRIVATE-STATE-AT-REST |
| Agent-policy receipts and subscribed lists | Public signed evidence; subscriber-local effect from verified canonical history | SOCIAL-I-AGENT-POLICY-LOCAL, SOCIAL-I-AGENT-REMEDIATION-SCOPED |
| Private Matrix content and state | Matrix participant endpoints | SOCIAL-I-MATRIX-E2EE, SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE |

Tier 3 broadcast has no forward secrecy: compromise of an audience key exposes
retained ciphertext for that `key_id`; rotation protects later generations.
Double Ratchet provides forward secrecy and post-compromise security when
message keys are promptly deleted. NIP-17 fallback has neither property.
Megolm/MLS guarantees are scoped to Matrix sessions. A client must not present
one mechanism's guarantee as another's.

## 4. Actors

| Actor | Capabilities and limits |
|---|---|
| Trusted client | Holds authorized secrets and performs all verification. Malware or key extraction is outside the honest-client assumption but addressed by rotation, confinement, and at-rest protection. |
| Hostile full node or seeder | Reads Tier 1 and allowed Tier 2 plaintext, observes repository metadata, and may withhold or replay. It cannot forge accepted signed objects and receives no Tier 3 plaintext. |
| Hostile routing node | Observes location queries and can return false or stale hints. It holds no content and cannot replace signed pointers or local verification. |
| Hostile Nostr relay | Correlates public keys, timing, and traffic and may drop, delay, reorder, or replay events. It cannot forge valid signatures. |
| Passive network observer | Observes endpoints, timing, and volume outside encrypted transports. Optional Tor egress hides direct destinations but leaves timing and volume leakage. |
| Hostile Matrix homeserver | Applies only to Social+Matrix. It sees room and federation metadata and may manipulate delivery or visible state, but must not receive private plaintext. |
| Federation peer | A non-hosting Matrix server participating in a Social+Matrix room sees unencrypted public state, `m.room.member` events, opaque Megolm/MLS ciphertext, sender MXIDs, `origin_server_ts`, and the federation join graph. The membership graph is exposed to every participating server. A persona concerned about that exposure should host identity/config rooms on a homeserver whose federation peer set it trusts; residual metadata still includes sender and timing information. |
| Compromised durable device | Uses its NID, epoch, audience, or ratchet authority until effective revocation; compromise windows and key rotation bound later trust. |
| Compromised ledger reader | Reads ledger state and ciphertext already available to it; removal, access withdrawal, and audience-key rotation protect later generations but cannot erase old Git objects. |
| Compromised token issuer | Can mint while it holds both the separately wrapped signing key and active issuer authority; immediate reduction and the at-most-300-second checkpoint-age bound limit continued minting. |
| Ordinary OIDC relying party | Validates HTTPS discovery, JWKS, JWT, and draft-21 status without Heterodyne software. It receives only consented projections and has no authority over the private claim ledger. |
| Public browser reader | Runs downloaded client code without authentication, resolves a fragment-local target, and may lack outbound Tor. It can consume verified Tier 1 only and must show reduced assurance when using clearnet/shared relays. |
| Automated principal | Supplies publication intent and sender proof under a scoped temporary token. It receives no persona, device, NID, or agent-role private key and cannot select a human profile or suppress attribution. |
| Control session device | Has only negotiated, granted Control authority. It is never a credential-plane device and receives none of the secrets prohibited by CONTROL-I-SESSION-KEY-CONFINEMENT. |
| Colluding delegated MXID | Applies only to Social+Matrix. It can read rooms it legitimately joined, race coordination state, and exploit a partition window, but cannot forge the persona's epoch-key proof. |
| Old or mirror homeserver | Applies only to Social+Matrix. It may retain stale room state, equivocate, or continue writing during a migration overlap; signed migration and delegation state wins over server location. |
| Compromised cold root | Catastrophic persona authority until KERI recovery/re-anchor; already valid attacker events remain attributable history. |

## 5. Threats and mitigations by owner

### 5.1 Core threats

| Threat | Mitigation |
|---|---|
| Forged or stale persona authority | Replay the accepted KEL and authority window; reject downstream identity overrides (CORE-I-IDENTITY-INTEGRITY). |
| One-sided NID binding | Require the epoch-key and NID proofs over the same payload (CORE-I-NID-DELEGATION-DUAL-PROOF). |
| JSON reserialization or signature confusion | Verify exact NIP-01 canonical bytes and preserve `nip01_raw` for embedded events (CORE-I-VERIFY-BEFORE-USE). |
| Malicious directory or serving-node response | Treat location data as hints, use multiple verified sources, and retain decentralized bootstrap (CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY). |
| Relay suppression, replica lag, or repository rollback hides current key state | Merge independent candidate sources, replay before use, and keep decisions provisional until repository authority is established (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Stale revocation or backdated event is accepted | Resolve the event time inside the accepted KEL authority window and apply `compromise_since` before authorization (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Lying or stale `kel_head` accelerates verification | Treat it only as a checked cache hint; replay whenever its event, sequence, authority window, or compromise state is not already accepted (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Hostile full node selectively withholds a persona | Try other advertised serving nodes and ordinary relays, then verify every result identically (CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY, CORE-I-VERIFY-BEFORE-USE). |
| Browser claims Tor assurance it cannot provide | Treat missing outbound Tor as explicit reduced-assurance operation, disclose the shared/clearnet carrier, and never advertise a strict light-client profile without `core.outbound-tor.v1`. |
| Direct WebRTC reveals a full node's network location | Keep direct client-to-node WebRTC/TURN outside the base profile; reach the persistent v3 onion service through Tor or an authenticated shared relay so the node does not expose a clearnet candidate. |
| Shared relay forges content or authority | Treat it only as a transport carrier, verify every signed object locally, and route around it when other relays are available (CORE-I-VERIFY-BEFORE-USE, CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY). |
| Local key-store theft | Use the keys-repository protection profile, NIP-49 wrapping, and OS-keystore integration where available (CORE-I-KEY-MATERIAL-AT-REST). |
| Keys repository is lost or copied | Offline backup limits loss; wrapping and local-only storage limit disclosure. Rotation and re-anchor address compromised authority but cannot recover an unavailable secret (CORE-I-KEY-MATERIAL-AT-REST, CORE-I-IDENTITY-INTEGRITY). |
| Derived export AID is mistaken for persona authority | Label it derived/degraded as applicable and always resolve the npub/KEL on divergence (CORE-I-IDENTITY-INTEGRITY). |
| Separate personas are linked by local metadata | Keep local correlation and recovery bookkeeping private; never publish it as Core identity state (CORE-I-KEY-MATERIAL-AT-REST, CORE-I-IDENTITY-INTEGRITY). |
| SHA-1 RID or git-object collision | Never let repository identity replace event SHA-256/BIP-340 or Radicle Ed25519 verification (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |

### 5.2 Comms threats

| Threat | Mitigation |
|---|---|
| Carrier reads Tier 3 plaintext | Encrypt before repository, seed, node, or relay access (COMMS-I-TIER3-BLIND-CARRIER). |
| Tier 2 mislabeled as encrypted | Warn that every allowed seeder holds plaintext (COMMS-I-TIER2-HONESTY). |
| Audience, ratchet, or config-state theft | Apply the Comms repository-encryption profile and generation rotation (COMMS-I-CONFIG-AT-REST). |
| Audience-key compromise exposes retained history | State that Tier 3 has no forward secrecy, rotate to a fresh generation, and never describe cooperative branch scrubbing as erasure (COMMS-I-TIER3-BLIND-CARRIER, COMMS-I-CONFIG-AT-REST). |
| Config-repository traffic reveals its existence or owner | Keep its RID unadvertised, use encrypted blobs, and recognize that traffic analysis remains residual metadata (COMMS-I-CONFIG-AT-REST, COMMS-I-CLIENT-SIDE-DELIVERY). |
| Backend bridge becomes a decryption oracle | Keep delivery, deduplication, and decryption on user-controlled clients (COMMS-I-CLIENT-SIDE-DELIVERY). |
| Central feed directory blocks discovery | Resolve signed feed/outbox hints over multiple carriers (COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY). |
| DM replay, ratchet-state loss, or metadata correlation | Enforce session replay checks and key deletion; keep outer DR events out of repositories and provide no backfill. Within a ratchet epoch, messages share an outer signer and are linkable to each other until the next DH step. Lost or corrupted ratchet state makes local history unrecoverable because Comms intentionally provides no backfill. |
| Org epoch-key holder bypasses delegate threshold through a relay | Require threshold-authorized canonical history for every org-owned Comms post and feed index, regardless of carrier (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE, COMMS-I-CLIENT-SIDE-DELIVERY). |
| Policy bypasses cryptography | Run the authenticated acceptance hook only after cryptographic checks; policy can tighten but never loosen a rejection. |
| Launcher origin learns the public target | Keep persona/event/address and relay hints in the URL fragment, serve target-independent static bytes, and perform parsing and resolution locally. |
| Malicious launcher relay hint reaches local or credentialed resources | Reject credentials, localhost, link-local, private/special resolved addresses, excessive hints, and onion hints without a Tor-capable path before any network request. |
| Public reader crosses a privacy tier | Render only verified Tier 1; refuse Tier 2 and treat Tier 3 ciphertext as unavailable rather than public content (COMMS-I-PUBLIC-READER-TIER1-ONLY). |
| Automated principal impersonates a human or signs directly | Require the full-node intent path, dedicated role-key delegation, current sender-constrained workload token, and canonical automation attribution. Human-device keys and raw signing are never fallback paths (COMMS-I-AGENT-ROLE-BINDING, COMMS-I-AGENT-ATTRIBUTION). |
| Caller forges or strips agent attribution | Remove caller-controlled attribution fields, inject the exact canonical block at the tier-appropriate protected location, and fail closed when that profile cannot be emitted (COMMS-I-AGENT-ATTRIBUTION). |
| Stolen, replayed, stale, or overbroad workload token | Enforce exact issuer, audience, client, role, sender proof, time, status, canonical source authority, and finite kind/resource/size/rate/burst bounds for every operation (COMMS-I-AGENT-ROLE-BINDING, COMMS-I-WORKLOAD-TOKEN-CONFINEMENT). |
| Agent token or private claim leaks into public evidence | Keep raw tokens, `jti` mappings, sender proofs, private claims, and protected audit records inside the authorization/audit boundary; public events carry only the canonical attribution identity (COMMS-I-WORKLOAD-TOKEN-CONFINEMENT). |
| Agent role key compromise contaminates human authority | Give each automation role a dedicated full-node-held key and stable role address; replace only that key, leaving persona epoch and human-device keys untouched (COMMS-I-AGENT-ROLE-BINDING). |
| Claim forgery or semantic malleation | Recompute the RFC 8785/JCS `claim_id`, verify the exact event, issuer authority, typed key and native proof, and reject address reuse unless the semantic object is byte-identical. A `kind:31014` reduction additionally requires `comms/0.5.0`, registry revision 2, the exact single `[["d","<claim_id>"]]` tag, and a native proof that binds the owning Comms profile and registry revision. See `heterodyne:comms/0.5.0#comms-key-claims`, `claims/004-claim-id-mismatch`, and `claims/015-authorization-self-revocation`; COMMS-I-CLAIM-AUTHENTICITY. |
| Compromised or stale claim issuer | Evaluate the issuer's Core/KEL authority at the claim's `issued_at`, apply compromise and revocation state, and keep a cryptographically valid but untrusted third-party issuer non-authorizing; compromised OIDC signing keys invalidate affected tokens and status. See `heterodyne:comms/0.5.0#comms-claim-verification`, `claims/007-third-party-issuer-untrusted`, and `token-status/009-signing-key-compromise`; COMMS-I-CLAIM-AUTHENTICITY and COMMS-I-STATUS-INTEGRITY. |
| Delegation-chain amplification | Require explicit issuance authority, strict narrowing of every scope dimension, cycle detection, and no more than eight issuance edges. See `heterodyne:comms/0.5.0#comms-claim-chain` and `claims/010-chain-depth-exceeded`; COMMS-I-CLAIM-ATTENUATION. |
| Subject-proof replay | Bind a fresh single-use challenge to claim, purpose, audience, resource, operation, nonce, and verifier context; an event signature or earlier proof cannot substitute. See `heterodyne:comms/0.5.0#comms-claim-verification` and `claims/012-copied-proof-rejected`; COMMS-I-CLAIM-AUTHENTICITY. |
| Provisional authorization use | Treat delivery as `provisional`; only a claim reachable from canonical private-ledger state can become `active`, and only `active` authorizes. See `heterodyne:comms/0.5.0#comms-claim-ledger` and `claims/013-provisional-authorization-denied`; COMMS-I-CLAIM-REPOSITORY-AUTHORITY. |
| Private-ledger rollback | Replay canonical `main` from genesis, verify record signatures and parents, reject a missing or older checkpoint, and apply every authenticated reduction immediately. See `heterodyne:comms/0.5.0#comms-claim-ledger` and `claim-ledger/008-checkpoint-rollback-rejected`; COMMS-I-CLAIM-REPOSITORY-AUTHORITY. |
| Private-ledger metadata leakage | Encrypt fixed-size padded entries under keyed paths so claim type, subject, and revocation count are absent from paths, commits, and object sizes. See `heterodyne:comms/0.5.0#comms-claim-ledger` and `claim-ledger/009-keyed-path-metadata-private`; COMMS-I-LEDGER-CONFINEMENT. |
| Removed ledger reader retains access | Commit the reduction, remove Radicle access, rotate the ledger audience key, wrap it only to remaining active NID readers, and scrub retired ciphertext cooperatively; disclose that old Git objects may remain readable. See `heterodyne:comms/0.5.0#comms-claim-ledger` and `claim-ledger/010-reader-removal-key-rotation`; COMMS-I-LEDGER-CONFINEMENT and COMMS-I-CLAIM-REVOCATION. |
| Multi-writer policy conflict | Merge claims and reservations by immutable ID, make revocation and authority reduction win, and leave incompatible non-monotonic policy `conflicted` and unable to authorize or mint. See `heterodyne:comms/0.5.0#comms-claim-ledger` and `claim-ledger/007-nonmonotonic-conflict-blocks`; COMMS-I-CLAIM-REVOCATION. |
| OIDC signing-key overdistribution | Keep signing JWKs in recipient-specific envelopes separate from the ledger audience key and release them only to active `oidc-token-issuer` NIDs at the exact replayed checkpoint. See `heterodyne:comms/0.5.0#comms-multiwriter-minting` and `claim-ledger/012-stale-minter-denied`; COMMS-I-ISSUER-KEY-CONFINEMENT. |
| Stale token minter | Synchronize before minting and stop when the canonical checkpoint exceeds the manifest bound, which is at most 300 seconds, or issuer authority is reduced. See `heterodyne:comms/0.5.0#comms-multiwriter-minting` and `claim-ledger/012-stale-minter-denied`; COMMS-I-MINT-FRESHNESS. |
| Confused deputy or JWT type/audience confusion | Enforce exact client, issuer, intended audience, resource, sender constraint, nonce where applicable, and protected type; access tokens require `typ: at+jwt` and cannot be accepted as ID Tokens or assertions. See `heterodyne:comms/0.5.0#comms-jwt-projection` and `oidc/010-token-type-confusion-rejected`; COMMS-I-JWT-TYPE-AUDIENCE. |
| OIDC issuer mix-up | Require one exact HTTPS issuer in discovery, metadata, token `iss`, continuity manifest, and status provenance; redirects, aliases, and host/path rewriting do not change it. See `heterodyne:comms/0.5.0#comms-oidc-endpoints` and `oidc/002-issuer-mismatch-rejected`; COMMS-I-ISSUER-CONTINUITY and COMMS-I-JWT-TYPE-AUDIENCE. |
| Consent overrelease | Intersect requested scope/audience, registration, explicit consent, active source claims, trust, and proof. Pairwise `sub` uses the exact 64-lowercase-hex SHA-256 digest of the JCS typed-key subject; stable key release needs its dedicated scope and consent. See `heterodyne:comms/0.5.0#comms-oidc-authorization` and `oidc/007-stable-key-consent-gated`; COMMS-I-CLAIM-RELEASE. |
| Status collision, staleness, or downgrade | Allocate `(uri, idx)` durably in NID-derived writer namespaces without reuse; verify signed draft-21 bytes, digest, `iat`, `exp`, and finite positive `ttl`; with trusted fetch time, reject exactly when `resolved_at + ttl < now` and never let `VALID` override another failure. See `heterodyne:comms/0.5.0#comms-token-status`, `token-status/004-writer-index-collision-rejected`, and `token-status/003-stale-status-list-rejected`; COMMS-I-STATUS-INTEGRITY. |
| Radicle/HTTPS equivocation | Require byte-identical discovery, raw closed JWKS, and Status List Token bytes plus manifest digests; any disagreement fails closed. See `heterodyne:comms/0.5.0#comms-issuer-continuity` and `token-status/006-radicle-digest-mismatch`; COMMS-I-ISSUER-CONTINUITY and COMMS-I-STATUS-INTEGRITY. |
| Issuer-successor hijack | Authenticate the continuity proof at its `issued_at` against the exact proof-time KEL transition and current KEL head, then require sequence, predecessor digest, the predecessor's retained status issuer/URI provenance, old-issuer cessation, successor URL, and successor-manifest commitment. See `heterodyne:comms/0.5.0#comms-issuer-continuity` and `token-status/008-issuer-successor`; COMMS-I-ISSUER-CONTINUITY. |
| Status-correlation privacy leakage | Keep source claims, `jti` mappings, consent, membership, and reasons in the private ledger; expose only public list paths/digests and coarse update activity. Writer buckets and fetch timing remain correlatable residuals. See `heterodyne:comms/0.5.0#comms-token-status` and `token-status/005-https-radicle-byte-identity`; COMMS-I-LEDGER-CONFINEMENT and COMMS-I-STATUS-INTEGRITY. |

### 5.3 Control threats

| Threat | Mitigation |
|---|---|
| Audit disclosure or tampering | Encrypt durable audit records and bind them to negotiated Core/Comms/Control context (CONTROL-I-AUDIT-AT-REST). |
| Session device escalates into persona or credential authority | Never deliver epoch, NID, audience, repository-decryption, or ratchet secrets; require explicit object-level grants (CONTROL-I-SESSION-KEY-CONFINEMENT). |
| Cross-relay retry executes twice or leaks a response | Reserve one request digest restart-safely, join identical retries to that result, reject changed method/payload, and publish the response first and only to the authenticated ingress relay (CONTROL-I-INGRESS-RELAY-AFFINITY). |
| Automated caller requests a private key, raw signature, human profile, or attribution bypass | Expose only bounded token and intent-level publish methods; refuse every key-access and bypass shape without fallback (CONTROL-I-AGENT-NO-KEY-RELEASE, CONTROL-I-AGENT-INTENT-ONLY). |
| Automated side effect outlives or exceeds its grant | Revalidate the scoped token, sender proof, canonical authority, and finite kind/resource/size/rate/burst bounds for each operation (CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS). |
| Experimental implementation claims conformance | Keep baseline and strict Control claims inactive until the remaining ADR-030 enrollment/session blockers and vector gate are complete. |

### 5.4 Social threats

| Threat | Mitigation |
|---|---|
| Centralized follow-graph censorship or poisoning | Evaluate signed relationship data client-side and retain plural discovery sources (SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH). |
| Private mute/feed/followed-repository state leaks | Store it under the owning Social or bound Comms protection profile (SOCIAL-I-PRIVATE-STATE-AT-REST). |
| Hostile homeserver reads or downgrades private state | Encrypt private content and protected state and surface downgrade failures (SOCIAL-I-MATRIX-E2EE). |
| Forged MXID delegation | Require both the epoch-key signature and authorized Matrix self-publication (SOCIAL-I-MXID-DELEGATION-DUAL-PROOF). |
| Homeserver forks or replays identity-room state | Revalidate embedded Core authority, Matrix authorization, and current delegation instead of trusting room history alone (SOCIAL-I-MXID-DELEGATION-DUAL-PROOF, CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Old or mirror homeserver races migration state | Apply signed migration precedence and lease/partition rules; a server location never becomes persona authority (SOCIAL-I-MXID-DELEGATION-DUAL-PROOF, SOCIAL-I-MATRIX-E2EE). |
| Server-side bridge sees protected plaintext | Run Matrix and cross-protocol bridging only on user-controlled clients (SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE). |
| Relay serves a stale mute, moderator, or policy list | Compare replaceable-event authority and timestamps, use anchored history where required, and retain encrypted local state (SOCIAL-I-PRIVATE-STATE-AT-REST, SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH, CORE-I-VERIFY-BEFORE-USE). |
| Listed-then-removed moderator backdates an approval | A relay-only anchor relies on author-controlled `created_at`, so a listed-then-removed moderator can attempt backdating and the residual cannot be eliminated there. A repository anchor binds the approval to an introducing commit and resolves the moderator declaration from canonical ancestor history; communities needing strong as-of integrity should use that repo anchor. |
| Advisory label becomes authority | Treat NIP-32 labels and web-of-trust scoring as local policy, never identity or editorial authority. |
| Agent-policy receipt silently becomes a global mute | Show the receipt as public evidence only; change visibility solely when the reader explicitly subscribes to a verified current canonical policy list, and disclose the policy source for each decision (SOCIAL-I-AGENT-POLICY-LOCAL). |
| Default moderator persona gains undeclared global power | Keep a default subscription visible, inspectable, disableable, and replaceable. A relay event or unmerged policy-repository PR has no filtering effect (SOCIAL-I-AGENT-POLICY-LOCAL). |
| Agent violation mutes the persona or forces epoch rotation | Bind enforcement to the exact offending device-publishing key. Replacement at the same stable role is evaluated independently; persona, epoch, human-device, NID, and other role keys remain unaffected (SOCIAL-I-AGENT-REMEDIATION-SCOPED). |
| False receipt remains effective after correction | Require both a valid signed correction and removal of the receipt binding from the current canonical policy list before restoring local visibility (SOCIAL-I-AGENT-POLICY-LOCAL, SOCIAL-I-AGENT-REMEDIATION-SCOPED). |
| Sybil vouchers or poisoned friend caches drive recovery | Treat Social recovery bindings as advisory inputs only; accepted KEL and declared Core witness rules retain authority (SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH, CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |

## 6. Metadata, availability, and residual risk

Encryption does not hide all metadata. Relays and repository hosts can observe
timing, volume, public keys, branch changes, and fetch patterns; allowed Tier 2
seeders also see the membership allow list. Routing nodes see lookup targets.
Matrix federation exposes the membership graph, sender MXIDs, timestamps, and
event-graph metadata to relevant servers and their federation peer set. Hosting
identity/config rooms with a deliberately trusted peer set limits, but cannot
eliminate, this exposure. Tor reduces direct network-linkability but does not
prevent global timing analysis.

A browser in reduced-assurance mode exposes its relay or shared-gateway
destination to the network and that carrier observes timing, volume, and
lookup patterns. Fragment-only launcher targets stay out of the static
origin's HTTP request, but relay queries can still reveal the target to the
selected relays. An authenticated shared relay can correlate a session with
its onion destination even though it cannot forge verified content.

Canonical agent attribution is intentionally linkable within a stable role:
issuer, pairwise subject, client ID, role ID, and signing key let recipients
filter and audit that automation. Pairwise subjects limit cross-persona
correlation, but role continuity is not an anonymity mechanism. Raw workload
tokens, token identifiers, sender proofs, source claims, and audit contents
must not be used as additional public correlation handles.

Within a ratchet epoch, multiple Comms DM messages use the same outer signer
and are linkable to one another until the next DH ratchet step, even though the
signer is not the persona epoch key. Lost or corrupted ratchet state makes the
affected local history unrecoverable: no backfill exists by design, and a fresh
session restores future communication rather than old message keys.

The config repository has a distinct linkage boundary. Its Radicle identity
document exposes its private `visibility.allow` allow-list to nodes that know
the repository, revealing the device NIDs allowed to seed it. A keys-repository
compromise, backup disclosure, access-log correlation, or accidental public
reference can reveal its RID and location; subsequent traffic can link the
otherwise unadvertised config repository to a persona or device set. Mitigation
is one dedicated unadvertised RID per persona, no public pointer or
`kind:31011` wrap, the smallest own-device allow-list, encrypted blobs before
commit, private replication, and rotation to a fresh RID/key after a location
compromise. These measures do not erase traffic already observed.

The OIDC continuity tree has an equally strict public/private boundary. A
private claim MUST NOT appear in public issuer discovery. A consent record
MUST NOT appear in public issuer discovery. An issuance mapping MUST NOT appear
in public issuer discovery. An audience key MUST NOT appear in public issuer discovery.
The same prohibition covers reader membership, `jti`-to-source
mapping, plaintext revocation reasons, signing secrets, and pairwise secrets.
The public tree contains only issuer metadata, public JWKs, continuity
commitments, and signed status artifacts; those artifacts still reveal coarse
key-rotation and status-list activity.

Keys repository and backup loss have irreversible consequences. Losing every
copy of an audience key permanently loses decryptability of retained Tier 3
history; losing ratchet state permanently loses that device's DM history; and
losing every cold-root/recovery copy can permanently prevent identity recovery
or re-anchor. Operationally, clients should maintain periodic encrypted
removable-media backups covering all produced and followed repositories plus
config and keys repositories, show a freshness indicator for unbacked changes,
keep backup media offline when not in use, and test restore procedures. Backup
copies are as sensitive as the live keys repository.

No deletion mechanism guarantees erasure from hostile relays, old git objects,
backups, screenshots, or offline seeds. `kind:5`, canonical-index removal, and
encrypted-branch scrubbing are cooperative visibility and retention controls.
Clients must describe them accordingly.

Multi-source retrieval improves availability against withholding but does not
guarantee it. A persona can be unavailable if all serving nodes and relays are
offline. Recovery peers and witnesses can help restore verified identity
material but cannot mint authority outside the KEL.

## 7. ADR-034 acceptance evidence

The approved design contains exactly eight acceptance criteria. The table is
an audit index, not a second source of requirements; ADR-034 and the permanent
Comms anchors remain authoritative, registry revision 2 names the allocation,
and the cited vector file or group supplies executable evidence.

| Criterion | Approved criterion | ADR evidence | Permanent Comms anchors | Registry evidence | Vector evidence | Threat invariants |
|---:|---|---|---|---|---|---|
| 1 | A new accepted ADR records the kind allocations, ownership, draft-21 pin, repository authority, and OIDC projection. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#ownership-and-allocations`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#authoritative-private-multi-writer-ledger`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#oauthoidc-and-interoperable-jwt-profile`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#draft-21-token-status-and-writer-allocation` | `heterodyne:comms/0.5.0#comms-key-claims`<br>`heterodyne:comms/0.5.0#comms-claim-ledger`<br>`heterodyne:comms/0.5.0#comms-jwt-projection`<br>`heterodyne:comms/0.5.0#comms-token-status` | `kind:31013`<br>`kind:31014`<br>`registry revision 2` | `claims/001-canonical-nostr-subject`<br>`claim-ledger/001-reader-nid-authorized`<br>`oidc/009-rfc9068-access-token-valid`<br>`token-status/001-valid-status-list` | `COMMS-I-CLAIM-AUTHENTICITY`<br>`COMMS-I-CLAIM-REPOSITORY-AUTHORITY`<br>`COMMS-I-JWT-TYPE-AUDIENCE`<br>`COMMS-I-STATUS-INTEGRITY` |
| 2 | The ADR-033 split is complete and the design integrates into Comms with bounded Core/Control amendments only. | `docs/adr/2026-07-16-033-four-document-protocol-family-split.md#a-document-set-and-dependency-direction`<br>`docs/adr/2026-07-16-033-four-document-protocol-family-split.md#b-document-boundaries`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#ownership-and-allocations` | `heterodyne:comms/0.5.0#comms-scope`<br>`heterodyne:comms/0.5.0#comms-conformance` | `registry revision 2` | `versioning/008-per-document-negotiation`<br>`stamping/008-control-carrier-comms-owner` | `COMMS-I-CLAIM-AUTHENTICITY` |
| 3 | Claim verification and merge behavior are deterministic and vectorized. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#atomic-claims-and-native-subject-proof`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#layered-and-irreversible-revocation`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#authoritative-private-multi-writer-ledger` | `heterodyne:comms/0.5.0#comms-claim-verification`<br>`heterodyne:comms/0.5.0#comms-claim-revocation`<br>`heterodyne:comms/0.5.0#comms-claim-ledger` | `kind:31013`<br>`kind:31014`<br>`COMMS-I-CLAIM-AUTHENTICITY`<br>`COMMS-I-CLAIM-REPOSITORY-AUTHORITY`<br>`COMMS-I-CLAIM-REVOCATION` | `claims/004-claim-id-mismatch`<br>`claims/005-persona-issuance-active`<br>`claim-ledger/005-multiwriter-revocation-wins`<br>`claim-ledger/007-nonmonotonic-conflict-blocks` | `COMMS-I-CLAIM-AUTHENTICITY`<br>`COMMS-I-CLAIM-REPOSITORY-AUTHORITY`<br>`COMMS-I-CLAIM-REVOCATION` |
| 4 | Private metadata is absent from public repos and outer transport metadata. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#atomic-claims-and-native-subject-proof`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#authoritative-private-multi-writer-ledger`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#one-issuer-and-simultaneous-radicle-continuity` | `heterodyne:comms/0.5.0#comms-key-claims`<br>`heterodyne:comms/0.5.0#comms-claim-ledger`<br>`heterodyne:comms/0.5.0#comms-issuer-continuity` | `kind:31013`<br>`COMMS-I-LEDGER-CONFINEMENT` | `claims/018-pairwise-private-dr-delivery`<br>`claim-ledger/009-keyed-path-metadata-private` | `COMMS-I-LEDGER-CONFINEMENT` |
| 5 | Multiple authorized nodes can mint without index collisions or stale-state authorization. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#shared-issuer-keys-and-mint-authority`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#draft-21-token-status-and-writer-allocation` | `heterodyne:comms/0.5.0#comms-multiwriter-minting`<br>`heterodyne:comms/0.5.0#comms-token-status` | `COMMS-I-ISSUER-KEY-CONFINEMENT`<br>`COMMS-I-MINT-FRESHNESS`<br>`COMMS-I-STATUS-INTEGRITY` | `claim-ledger/011-multiwriter-status-allocation`<br>`claim-ledger/012-stale-minter-denied` | `COMMS-I-ISSUER-KEY-CONFINEMENT`<br>`COMMS-I-MINT-FRESHNESS`<br>`COMMS-I-STATUS-INTEGRITY` |
| 6 | Vanilla OIDC/OAuth parties can validate JWTs without Heterodyne software. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#oauthoidc-and-interoperable-jwt-profile`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#draft-21-token-status-and-writer-allocation` | `heterodyne:comms/0.5.0#comms-oidc-endpoints`<br>`heterodyne:comms/0.5.0#comms-jwt-projection`<br>`heterodyne:comms/0.5.0#comms-token-status` | `COMMS-I-JWT-TYPE-AUDIENCE`<br>`COMMS-I-STATUS-INTEGRITY` | `oidc/001-discovery-exact-issuer`<br>`oidc/008-id-token-valid`<br>`oidc/009-rfc9068-access-token-valid`<br>`token-status/001-valid-status-list` | `COMMS-I-JWT-TYPE-AUDIENCE`<br>`COMMS-I-STATUS-INTEGRITY` |
| 7 | Heterodyne-aware parties can recover issuer keys and token status from the canonical public Radicle mirror. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#one-issuer-and-simultaneous-radicle-continuity`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#draft-21-token-status-and-writer-allocation` | `heterodyne:comms/0.5.0#comms-issuer-continuity`<br>`heterodyne:comms/0.5.0#comms-token-status` | `COMMS-I-ISSUER-CONTINUITY`<br>`COMMS-I-STATUS-INTEGRITY` | `token-status/005-https-radicle-byte-identity`<br>`token-status/007-https-outage-radicle-fallback`<br>`token-status/008-issuer-successor` | `COMMS-I-ISSUER-CONTINUITY`<br>`COMMS-I-STATUS-INTEGRITY` |
| 8 | Registry, schema, generator, threat model, and companion documentation all pass the family conformance checks. | `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#security-and-privacy-consequences`<br>`docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md#conformance-obligations` | `heterodyne:comms/0.5.0#comms-security`<br>`heterodyne:comms/0.5.0#comms-conformance` | `registry revision 2`<br>`registry digest b52c0a6f99fdb8a34fa761a74c8374a5a55bd3b0e0494e9d973589e00febccf9` | `claims/*`<br>`claim-ledger/*`<br>`oidc/*`<br>`token-status/*`<br>`registry/002-frozen-entry-immutable`<br>`versioning/008-per-document-negotiation`<br>`stamping/008-control-carrier-comms-owner` | `COMMS-I-CLAIM-AUTHENTICITY`<br>`COMMS-I-CLAIM-ATTENUATION`<br>`COMMS-I-CLAIM-REPOSITORY-AUTHORITY`<br>`COMMS-I-CLAIM-REVOCATION`<br>`COMMS-I-LEDGER-CONFINEMENT`<br>`COMMS-I-ISSUER-KEY-CONFINEMENT`<br>`COMMS-I-MINT-FRESHNESS`<br>`COMMS-I-ISSUER-CONTINUITY`<br>`COMMS-I-CLAIM-RELEASE`<br>`COMMS-I-JWT-TYPE-AUDIENCE`<br>`COMMS-I-STATUS-INTEGRITY` |

## 8. Strict-profile posture

Strict profiles are additive and composable:

- `heterodyne-core-strict-v1` covers the Core invariant set and strict Core
  obligations;
- `heterodyne-comms-strict-v1` composes Core strict plus Comms invariants;
- `heterodyne-comms-strict-v2` adds public-reader and automated-authorship
  invariants without changing v1;
- `heterodyne-control-strict-v1` is reserved-inactive with Control;
- `heterodyne-social-strict-v1` composes Core, Comms, and Matrix-free Social
  obligations; and
- `heterodyne-social-matrix-strict-v1` adds the Matrix-specific Social
  invariants and exact `Social+Matrix` conformance class;
- `heterodyne-social-strict-v2` adds subscriber-local agent-policy and
  device-key-scoped remediation invariants; and
- `heterodyne-social-matrix-strict-v2` composes that v2 Social profile with
  the Matrix-specific invariant set.

A capability advertisement lists only profiles actually met. Unknown profile
IDs confer no authority or compatibility. Conformance reports reproduce exact
membership and prerequisite results; incomplete Control cannot advertise its
reserved strict profile.

## 9. Out of scope and pre-1.0 work

The family does not attempt to prevent a compromised honest endpoint from
reading data already available to that endpoint, a recipient from copying
plaintext, global traffic analysis, denial of service by every available
carrier at once, or erasure of bytes retained by hostile third parties. Legal
and operational moderation obligations are deployment concerns; the protocol
defines authenticity and policy carriers, not universal content policy.

Host-OS malware on a device during a key ceremony remains outside the
application security boundary; keeping the cold root offline reduces exposure
but cannot protect a secret while the operating system that handles it is
fully compromised. Tor-level timing/volume correlation by a global observer
also remains outside the delivered anonymity guarantee.

The current cryptographic suites are **not post-quantum**. A quantum adversary
capable of breaking secp256k1, Ed25519, or the deployed symmetric assumptions
falls outside this threat model. A migration strategy is pre-1.0/open work and
must coordinate with Nostr, Radicle, Matrix, KERI, and stored historical
signature semantics rather than claiming present quantum resistance.

Before relevant 1.0 claims, work remains to freeze the Comms double-ratchet
wire profile, finish the repo-relay server/storage contract, exercise KERI fork
and recovery behavior across independent implementations, validate Matrix MLS
migration, complete the remaining Control enrollment/session vector corpus,
and expand
negative vectors for rollback, metadata, and recovery-policy attacks. Each
item belongs to its named document and must not create a forbidden dependency.
The repo-relay server/storage contract must also close storage-exhaustion,
retention, garbage-collection, and quota behavior before that conformance class
can reach 1.0.
