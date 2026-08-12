# Heterodyne protocol-family threat model

**Status:** Draft, non-normative security analysis for the 0.5.x family.

[`docs/spec/heterodyne.md`](../spec/heterodyne.md) is the non-normative family
map. Security requirements are owned by the four versioned documents below.

This document analyzes the four independently versioned documents:

- [Heterodyne Core](../spec/heterodyne-core.md) — identity, verification,
  registry, node roles, and repository substrate;
- [Heterodyne Comms](../spec/heterodyne-comms.md) — publishing, privacy tiers,
  Marmot conversations and media, Radicle-backed group storage, atomic claims,
  private-ledger authority, OIDC/JWT projection, and Marmot application
  carriage;
- [Heterodyne Control](../spec/heterodyne-control.md) — the active baseline
  own-device command profile and optional recovery capabilities; and
- [Heterodyne Social](../spec/heterodyne-social.md) — public social behavior,
  durable assets, and moderation.

The owner sections below reproduce registry revision 7 and security boundaries
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
nodes, and group hosts may observe metadata, omit, delay, reorder, or replay
traffic.

Authentication always precedes policy. Routing advertisements, repository
location, social relationships, moderation labels, and repository state never
substitute for local signature, KEL, delegation, or schema verification.
Availability from multiple carriers reduces withholding risk but does not make
any carrier authoritative for persona identity.

## 2. Registry-bound invariants

The descriptions below reproduce registry revision 7 exactly.
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
- **CORE-I-MARMOT-ROLE-ATTRIBUTION:** KERI role evidence attributes Marmot accounts and Radicle hosts without selecting MLS state or altering Marmot convergence.

### 2.2 Comms

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

### 2.3 Control

- **CONTROL-I-AUDIT-AT-REST:** Authorization and side-effect audit is encrypted and contains no replayable token or transcript.
- **CONTROL-I-CLIENT-KEY-CONFINEMENT:** A light client receives no persona, device, epoch, NID, repository, MLS-leaf, or agent-role private key.
- **CONTROL-I-MARMOT-SENDER-BINDING:** Every privileged token is bound to the authenticated Marmot account and exact group.
- **CONTROL-I-ENTITLEMENT-FRESHNESS:** Every privileged request uses current, non-conflicted private entitlement state and absorbing revocation.
- **CONTROL-I-NODE-AUDIENCE:** A node-issued Control token is accepted only by its exact issuing-node audience.
- **CONTROL-I-OPERATION-AT-MOST-ONCE:** Mutation reservation precedes effects and cross-node retry is limited to provably safe cases.
- **CONTROL-I-AGENT-NO-KEY-RELEASE:** An automated principal never receives or directly exercises a persona, epoch, NID, human-device, or agent-role private key.
- **CONTROL-I-AGENT-INTENT-ONLY:** An automated principal publishes only through the intent-level agent method, and raw signing, human-profile fallback, and attribution bypass fail closed.
- **CONTROL-I-MARMOT-GRANT-CONFINEMENT:** Node-mediated Marmot operations expose only grant-filtered content and actions while all account, MLS leaf, epoch, and repository secrets remain on the designated node.
- **CONTROL-I-EPOCH-LOCKED-DURING-TRANSFER:** Epoch plaintext is erased and relocked before network or bulk-transfer activity.
- **CONTROL-I-RECOVERY-GRANT-CONFINEMENT:** Recovery access is finite and bound to exact identities, resources, direction, bytes, time, and completion.
- **CONTROL-I-SFTP-PROCESS-SEPARATION:** Overflow SFTP uses a per-grant onion and isolated rooted process with Tor and SSH authentication.

Baseline Control 0.5.0 is claimable independently of the three optional
recovery invariants. `CONTROL-I-AUDIT-AT-REST` depends only on Core, Comms,
and Control protections; Social is outside that dependency.

### 2.4 Social

- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-REMEDIATION-SCOPED:** Agent-policy enforcement and remediation target only the offending role device key; replacement at the same role address never requires epoch-key rotation.

## 3. Assets and trust boundaries

| Asset | Owner and boundary | Principal invariant |
|---|---|---|
| Cold-root and epoch secrets | User endpoint; cold root normally offline | CORE-I-IDENTITY-INTEGRITY, CORE-I-KEY-MATERIAL-AT-REST |
| Accepted KEL and `nip01_raw` | Verified locally from signed bytes | CORE-I-VERIFY-BEFORE-USE |
| Radicle NID secret and delegation | Authorized full device | CORE-I-NID-DELEGATION-DUAL-PROOF |
| Tier 1 content | Public by design | COMMS-I-CLIENT-SIDE-DELIVERY |
| Tier 2 content | Plaintext on every allowed seeder | COMMS-I-TIER2-HONESTY |
| Tier 3 content and audience keys | Ciphertext outside key-holding endpoints | COMMS-I-TIER3-BLIND-CARRIER, COMMS-I-CONFIG-AT-REST |
| Control group state and token | The light client and one full node; bounded and never backed up | CONTROL-I-MARMOT-SENDER-BINDING, CONTROL-I-NODE-AUDIENCE |
| Marmot account and MLS leaf secrets | Authorized full/recovery nodes and direct-member devices | CORE-I-MARMOT-ROLE-ATTRIBUTION, COMMS-I-MARMOT-SECRET-CONFINEMENT |
| Marmot events and encrypted media | Exact bytes across authorized Radicle and Nostr interfaces | COMMS-I-MARMOT-UPSTREAM-AUTHORITY, COMMS-I-MARMOT-EXACT-BYTES |
| Group directory and routing bindings | Active administrators authorize; hosts replicate | COMMS-I-RADICLE-ROUTING-AUTHORITY |
| Atomic key claims and native proofs | Locally verified signed objects; trust follows cryptographic validity | COMMS-I-CLAIM-AUTHENTICITY, COMMS-I-CLAIM-ATTENUATION |
| Private claim ledger and audience key | Active durable NID-bearing readers only | COMMS-I-CLAIM-REPOSITORY-AUTHORITY, COMMS-I-CLAIM-REVOCATION, COMMS-I-LEDGER-CONFINEMENT |
| OIDC signing keys and mint authority | Separately authorized, fresh synchronized issuer nodes | COMMS-I-ISSUER-KEY-CONFINEMENT, COMMS-I-MINT-FRESHNESS |
| Public OIDC metadata, JWKS, and status | HTTPS plus byte-identical public Radicle continuity tree | COMMS-I-ISSUER-CONTINUITY, COMMS-I-JWT-TYPE-AUDIENCE, COMMS-I-STATUS-INTEGRITY |
| Consent and projected claim release | Canonical private ledger plus explicit relying-party policy | COMMS-I-CLAIM-RELEASE |
| Public-reader target and resolved content | Fragment-local target; verified Tier 1 rendering only | COMMS-I-PUBLIC-READER-TIER1-ONLY, CORE-I-VERIFY-BEFORE-USE |
| Agent role key | Full-node key store; never released to the automated principal | COMMS-I-AGENT-ROLE-BINDING, CONTROL-I-AGENT-NO-KEY-RELEASE |
| Workload token, sender proof, and agent audit | Protected authorization/audit boundary; never public event content | COMMS-I-WORKLOAD-TOKEN-CONFINEMENT, CONTROL-I-AUDIT-AT-REST |
| Control audit and session authority | User-controlled Control endpoint | CONTROL-I-AUDIT-AT-REST, CONTROL-I-CLIENT-KEY-CONFINEMENT |
| Node-mediated group access | Grant-filtered results; all group secrets remain on the designated node | CONTROL-I-MARMOT-GRANT-CONFINEMENT |
| Social private configuration | Protected local/config storage | SOCIAL-I-PRIVATE-STATE-AT-REST |
| Agent-policy receipts and subscribed lists | Public signed evidence; subscriber-local effect from verified canonical history | SOCIAL-I-AGENT-POLICY-LOCAL, SOCIAL-I-AGENT-REMEDIATION-SCOPED |

Tier 3 broadcast has no forward secrecy: compromise of an audience key exposes
retained ciphertext for that `key_id`; rotation protects later generations.
Marmot MLS provides its pinned upstream group confidentiality and
post-compromise properties for both conversations and Control groups. Bounded
Control retention and non-backup reduce replayable state but do not create a
different cryptographic guarantee. A client must not present one mechanism's
guarantee as another's.

## 4. Actors

| Actor | Capabilities and limits |
|---|---|
| Trusted client | Holds authorized secrets and performs all verification. Malware or key extraction is outside the honest-client assumption but addressed by rotation, confinement, and at-rest protection. |
| Hostile full node or seeder | Reads Tier 1 and allowed Tier 2 plaintext, observes repository metadata, and may withhold or replay. It cannot forge accepted signed objects and receives no Tier 3 plaintext. |
| Hostile routing node | Observes location queries and can return false or stale hints. It holds no content and cannot replace signed pointers or local verification. |
| Hostile Nostr relay | Correlates public keys, timing, and traffic and may drop, delay, reorder, or replay events. It cannot forge valid signatures. |
| Hostile group host or Radicle delegate | Observes repository metadata and may withhold refs or advertise stale endpoints. It cannot select Marmot state, forge an administrator routing commit, or substitute a mismatched repository genesis. |
| Hostile integrated Marmot relay | Observes connection metadata and kind-445 envelopes, may reject or delay writes, and can publish only to its designated relay ref. It does not learn the MLS sender from the fresh envelope key. |
| Passive network observer | Observes endpoints, timing, and volume outside encrypted transports. Optional Tor egress hides direct destinations but leaves timing and volume leakage. |
| Compromised durable device | Uses its NID, epoch, audience, issuer, or MLS authority until effective revocation; compromise windows and key rotation bound later trust. |
| Compromised ledger reader | Reads ledger state and ciphertext already available to it; removal, access withdrawal, and audience-key rotation protect later generations but cannot erase old Git objects. |
| Compromised token issuer | Can mint while it holds both the separately wrapped signing key and active issuer authority; immediate reduction and the at-most-300-second checkpoint-age bound limit continued minting. |
| Ordinary OIDC relying party | Validates HTTPS discovery, JWKS, JWT, and draft-21 status without Heterodyne software. It receives only consented projections and has no authority over the private claim ledger. |
| Public browser reader | Runs downloaded client code without authentication, resolves a fragment-local target, and may lack outbound Tor. It can consume verified Tier 1 only and must show reduced assurance when using clearnet/shared relays. |
| Automated principal | Supplies publication intent and sender proof under a scoped temporary token. It receives no persona, device, NID, or agent-role private key and cannot select a human profile or suppress attribution. |
| Light Control client | Has only private entitled Control authority. It is not a Core/KERI device and receives none of the secrets prohibited by CONTROL-I-CLIENT-KEY-CONFINEMENT. |
| Compromised cold root | Catastrophic persona authority. Changed-RID re-anchor cannot repair it because the same root authorizes re-anchor; absent a standardized precommitted recovery policy, migrate to a new persona/root. |

## 5. Threats and mitigations by owner

### 5.1 Core threats

| Threat | Mitigation |
|---|---|
| Forged or stale persona authority | Replay the accepted KEL and authority window; reject downstream identity overrides (CORE-I-IDENTITY-INTEGRITY). |
| One-sided NID binding | Require the epoch-key and NID proofs over the same payload (CORE-I-NID-DELEGATION-DUAL-PROOF). |
| JSON reserialization or signature confusion | Verify exact NIP-01 canonical bytes and preserve `nip01_raw` for embedded events (CORE-I-VERIFY-BEFORE-USE). |
| Malicious directory or serving-node response | Treat location data as hints, use multiple verified sources, and retain decentralized bootstrap (CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY). |
| Relay suppression, replica lag, or repository rollback hides current key state | Merge independent candidate sources, replay before use, and keep decisions provisional until repository authority is established (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Stale revocation or backdated event is accepted | Resolve the event time inside the accepted KEL authority window, apply `compromise_since`, and treat first-seen-after-routine-retirement content as provisional unless a pre-retirement repository or local checkpoint proves prior existence (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Relay profile or NIP-05 overrides canonical persona metadata | Select the profile from canonical public-repository history, require the one active `profile-publisher` delegation, and treat `kind:0` and NIP-05 only as interoperability projections (CORE-I-IDENTITY-INTEGRITY). |
| Long-lived or future-dated node advert persists stale reachability | Enforce ±300-second initial skew, 24-hour maximum lifetime, strict expiry, 12-hour refresh, and fail closed when known clock uncertainty exceeds 300 seconds (CORE-I-VERIFY-BEFORE-USE). |
| Lying or stale `kel_head` accelerates verification | Treat it only as a checked cache hint; replay whenever its event, sequence, authority window, or compromise state is not already accepted (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Retired-key breadcrumb overwrites or redirects vanilla followers | Treat unstamped `kind:0`/`kind:1` bytes as NIP-01-authenticated advisory content only, never infer the producer-only v1 profile or KEL succession, emit a pair only from a trusted same-persona routine-rotation workflow, and destroy the retiring secret after bounded publication attempts. A compromise rotation has no trustworthy breadcrumb (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Hostile full node selectively withholds a persona | Try other advertised serving nodes and ordinary relays, then verify every result identically (CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY, CORE-I-VERIFY-BEFORE-USE). |
| Browser claims Tor assurance it cannot provide | Treat missing outbound Tor as explicit reduced-assurance operation, disclose the shared/clearnet carrier, and never advertise a strict light-client profile without `core.outbound-tor.v1`. |
| Direct WebRTC reveals a full node's network location | Keep direct client-to-node WebRTC/TURN outside the base profile; reach the persistent v3 onion service through Tor or an authenticated shared relay so the node does not expose a clearnet candidate. |
| Shared relay forges content or authority | Treat it only as a transport carrier, verify every signed object locally, and route around it when other relays are available (CORE-I-VERIFY-BEFORE-USE, CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY). |
| Local key-store theft | Use the keys-repository protection profile, NIP-49 wrapping, and OS-keystore integration where available (CORE-I-KEY-MATERIAL-AT-REST). |
| Keys repository is lost or copied | Redundant independently stored encrypted backups limit loss; wrapping and local-only storage limit disclosure. Witness continuity does not reconstruct the root. Suspected root compromise requires persona migration rather than same-persona reset (CORE-I-KEY-MATERIAL-AT-REST, CORE-I-IDENTITY-INTEGRITY). |
| Derived export AID is mistaken for persona authority | Label it derived/degraded as applicable and always resolve the npub/KEL on divergence (CORE-I-IDENTITY-INTEGRITY). |
| Separate personas are linked by local metadata | Keep local correlation and recovery bookkeeping private; never publish it as Core identity state (CORE-I-KEY-MATERIAL-AT-REST, CORE-I-IDENTITY-INTEGRITY). |
| SHA-1 RID or git-object collision | Never let repository identity replace event SHA-256/BIP-340 or Radicle Ed25519 verification (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |

### 5.2 Comms threats

| Threat | Mitigation |
|---|---|
| Carrier reads Tier 3 plaintext | Encrypt before repository, seed, node, or relay access (COMMS-I-TIER3-BLIND-CARRIER). |
| Tier 3 audience membership is inferred | Treat Tier 3 as content-confidential, not membership-private. Clear `kind:31011`/`kind:31012` recipient `p`/`d` tags, roster generations, shared `key_id` correlation, timing, count, size, publication, and fetch cadence remain observable; disclose these residuals before use. |
| Tier 2 mislabeled as encrypted | Warn that every allowed seeder holds plaintext (COMMS-I-TIER2-HONESTY). |
| Audience or config-state theft | Apply the Comms repository-encryption profile and generation rotation (COMMS-I-CONFIG-AT-REST). |
| Tier 3 wrap targets a persona authority or revoked device | Resolve active KEL-delegated human-device publishing keys, permit only narrowing, reject cold-root/epoch/inactive recipients, and rotate the audience generation when a device leaves. Publishing and NIP-44 decryption share one explicitly disclosed device-key compromise domain. |
| Audience-key compromise exposes retained history | State that Tier 3 has no forward secrecy, rotate to a fresh generation, and never describe cooperative branch scrubbing as erasure (COMMS-I-TIER3-BLIND-CARRIER, COMMS-I-CONFIG-AT-REST). |
| Config-repository traffic reveals its existence or owner | Keep its RID unadvertised, use encrypted blobs, and recognize that traffic analysis remains residual metadata (COMMS-I-CONFIG-AT-REST, COMMS-I-CLIENT-SIDE-DELIVERY). |
| Backend bridge becomes a decryption oracle | Keep delivery, deduplication, and decryption on user-controlled clients (COMMS-I-CLIENT-SIDE-DELIVERY). |
| Central feed directory blocks discovery | Resolve signed feed/outbox hints over multiple carriers (COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY). |
| Control replay, group-state loss, or metadata correlation | Authenticate the Marmot sender and exact group, enforce request and operation identifiers, apply bounded NIP-40 retention, and never back up raw frames or MLS state. Group loss establishes a fresh group and token rather than restoring an executable transcript. |
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
| Heterodyne adapter changes or loses Marmot semantics | Validate the closed local archive's paths, exact bytes, Git blobs, per-file SHA-256 values, and aggregate digest; treat those adopted MLS, application-event, media, and transport rules as authoritative (COMMS-I-MARMOT-UPSTREAM-AUTHORITY). |
| Repository or relay rewrites a Marmot event or media object | Index and serve the exact signed kind-445 bytes and exact encrypted-media ciphertext; never re-sign, wrap, or translate the object (COMMS-I-MARMOT-EXACT-BYTES). |
| Shared leaf or node-mediated secret export enables impersonation | Use independent leaves by default, permit only exclusive leaf takeover, and keep all account, leaf, epoch, and repository secrets on the designated node for mediated clients (COMMS-I-MARMOT-SECRET-CONFINEMENT). |
| Radicle delegate substitutes group state or repository | Require an active Marmot administrator's canonical routing commit, matching `h`, binding, RID, and genesis manifest; delegates replicate but do not authorize (COMMS-I-RADICLE-ROUTING-AUTHORITY). |
| Removed member receives future private repository data | Remove its NID from future replication, rotate membership and routing in the required two-stage sequence, and encrypt new directory records to remaining members (COMMS-I-RADICLE-ROUTING-AUTHORITY). |
| Retention UI promises erasure | Stop advertising and serving expired archives and garbage-collect locally where possible, while explicitly disclosing that clones, Git objects, exports, and backups can survive (COMMS-I-RADICLE-NON-ERASURE). |
| Public persona inbox causes unbounded fetch or media download | Fetch a bounded manifest into quarantine, reject replayed KeyPackages and invalid artifacts, and require policy or user action before media retrieval. |
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
| Light client escalates into persona or credential authority | Treat its key as a private Control principal only and never deliver persona, device, epoch, NID, repository, MLS-leaf, or role secrets (CONTROL-I-CLIENT-KEY-CONFINEMENT). |
| Token is replayed by another account, group, or node | Bind `cnf.jkt` to the authenticated Marmot account, bind the exact group, and require the issuing node's exact audience (CONTROL-I-MARMOT-SENDER-BINDING, CONTROL-I-NODE-AUDIENCE). |
| Unsolicited Welcome traffic exhausts Control KeyPackages or group state | Default invitations to off; enforce one pending group per account, a finite global cap, a 30-minute lifetime, finite Welcome/replenishment rates, paused public replenishment at capacity, and a reserved entitled/approved slot before durable Welcome mutation. |
| One-time invite is converted, raced, or replayed | Sign and domain-separate the exact purpose and descriptor, authenticate the NIP-59 responder and secret proof, and persist the first-valid `active -> reserved -> spent` transition. |
| Device Authorization user code is guessed | Require at least 34.5 bits of user-code entropy, no more than five failures, per-code and node-wide throttles, constant-time normalized comparison, and identical code/fingerprint displays. Device codes contain at least 128 random bits. |
| A stale full node keeps minting fresh authority | Require an authenticated, non-conflicted authorization view at most 300 seconds old for mint and every privileged request, and an immediate successful synchronization before mutation. |
| Cross-node retry executes a mutation twice | Reserve the operation before effects and retry only an inherently idempotent operation or one with a provable committed result; otherwise return `indeterminate` (CONTROL-I-OPERATION-AT-MOST-ONCE). |
| Automated caller requests a private key, raw signature, human profile, or attribution bypass | Expose only bounded token and intent-level publish methods; refuse every key-access and bypass shape without fallback (CONTROL-I-AGENT-NO-KEY-RELEASE, CONTROL-I-AGENT-INTENT-ONLY). |
| Automated side effect outlives or exceeds its grant | Revalidate the scoped Control token, authenticated sender, current entitlement, role, and finite kind/resource/size/rate/burst bounds for each operation (CONTROL-I-ENTITLEMENT-FRESHNESS, CONTROL-I-AGENT-INTENT-ONLY). |
| Node-mediated client escapes its group grant or obtains secrets | Filter every method, object, history range, and result by current authority and retain all Marmot and repository secrets on the designated node (CONTROL-I-MARMOT-GRANT-CONFINEMENT). |
| Recovery capability is confused with baseline Control | Require separate feature advertisement and recovery vectors; baseline Control conveys no epoch custody, repository grant, or SFTP authority. |
| Epoch key remains live during network transfer | Prepare and wrap activation during an explicit unlock, then erase and relock before any group, Radicle, onion, or SFTP activity (CONTROL-I-EPOCH-LOCKED-DURING-TRANSFER). |
| Epoch scalar reuse crosses signing and decryption boundaries | The same scalar is intentionally used for BIP-340 epoch authority and Nostr-compatible NIP-59 recipient ECDH, so compromise of either use compromises both. Domain-separate every protocol input, bound work before decryption, reject malformed ciphertext without invoking signing, never sign while processing untrusted epoch-inbox ciphertext, and keep the scalar encrypted and absent from memory outside the explicit short unlock ceremony. |
| Recovery service exposes other files or network channels | Use an exact finite grant, fresh client-authorized onion, independent SSH authentication and host pinning, rooted SFTP-only process, byte ceiling, expiry, and prohibited forwarding (CONTROL-I-RECOVERY-GRANT-CONFINEMENT, CONTROL-I-SFTP-PROCESS-SEPARATION). |

### 5.4 Social threats

| Threat | Mitigation |
|---|---|
| Centralized follow-graph censorship or poisoning | Evaluate signed relationship data client-side and retain plural discovery sources (SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH). |
| ATProto DNS validation is bypassed by rebinding or connection substitution | Resolve explicitly, reject any non-public answer, dial one validated address directly, preserve the original hostname for TLS and HTTP authority, inspect the connected peer, and repeat manually for each redirect. If the runtime cannot bind and inspect, expose the feature as unavailable and do not claim resolver conformance. |
| Breadcrumb-like prose silently rewrites a follow target | Show it only as reduced-assurance external content and require an explicit user action to follow, refollow, or switch. Never project KEL continuity or automatically follow a claimed successor (SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH, CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |
| Private mute/feed/followed-repository state leaks | Store it under the owning Social or bound Comms protection profile (SOCIAL-I-PRIVATE-STATE-AT-REST). |
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
seeders also see the membership allow list. Tier 3 provides content
confidentiality, not membership privacy: recipient tags, roster events,
`key_id` linkage, timing, count, size, publication, and fetch cadence remain
observable. Routing nodes see lookup targets.
Marmot and Radicle group paths still expose timing, object size, ref activity,
host topology, and fetch behavior to participating carriers. Private event
repositories reduce public discovery but do not encrypt Git storage. Tor
reduces direct network-linkability but does not prevent global timing analysis.

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

Marmot Control outer events retain the metadata properties of standard Marmot
transport. Relays can observe timing, volume, routing hints, and the current
ephemeral transport signer even though MLS protects application content.
Losing Control-group state ends that channel; a fresh group and node-scoped
token restore future operation but do not restore raw Control transcripts.

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
history; losing every cold-root/recovery copy can permanently prevent identity recovery
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

## 7. Claims and OIDC assurance coverage

Claims and OIDC requirements are defined entirely by the permanent Comms
anchors, pinned registry entries, schemas, security invariants, and normative
vector groups. The threat table above maps each risk directly to those current
artifacts. Historical decision records are not required to interpret or
validate this coverage.

The authoritative surfaces are
`heterodyne:comms/0.5.0#comms-key-claims`,
`heterodyne:comms/0.5.0#comms-claim-ledger`,
`heterodyne:comms/0.5.0#comms-oidc-endpoints`,
`heterodyne:comms/0.5.0#comms-jwt-projection`,
`heterodyne:comms/0.5.0#comms-token-status`, and the `claims/`,
`claim-ledger/`, `oidc/`, and `token-status/` vector groups.

## 8. Strict-profile posture

Strict profiles are additive and composable:

- `heterodyne-core-strict-v1` covers the Core invariant set and strict Core
  obligations;
- `heterodyne-comms-strict-v1` composes Core strict plus Comms invariants;
- `heterodyne-comms-strict-v2` adds public-reader and automated-authorship
  invariants without changing v1;
- `heterodyne-control-strict-v1` composes Core, Comms, and active Control
  invariants;
- `heterodyne-social-strict-v1` composes Core, Comms, and Social obligations;
  and
- `heterodyne-social-strict-v2` adds subscriber-local agent-policy and
  device-key-scoped remediation invariants.

A capability advertisement lists only profiles actually met. Unknown profile
IDs confer no authority or compatibility. Conformance reports reproduce exact
membership and prerequisite results.

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
must coordinate with Nostr, Radicle, Marmot, KERI, and stored historical
signature semantics rather than claiming present quantum resistance.

Before relevant 1.0 claims, work remains to define any future generic
repo-relay server/storage profile, exercise KERI fork and recovery behavior across
independent implementations, expand Marmot, Control, and Radicle
interoperability testing, and expand negative vectors for rollback, metadata,
and recovery-policy attacks. Each
item belongs to its named document and must not create a forbidden dependency.
Any future generic repo-relay server/storage profile must close authenticated admission, storage-exhaustion,
retention, garbage-collection, and quota behavior before that conformance class
can reach 1.0.
