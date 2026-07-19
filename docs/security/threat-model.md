# Heterodyne protocol-family threat model

**Status:** Draft, non-normative security analysis for the 0.5.x family.

This document analyzes the four independently versioned normative documents:

- [Heterodyne Core](../spec/heterodyne-core.md) — identity, verification,
  registry, node roles, and repository substrate;
- [Heterodyne Comms](../spec/heterodyne-comms.md) — publishing, privacy tiers,
  retrieval, direct messages, and encrypted subprotocol carriage;
- [Heterodyne Control](../spec/heterodyne-control.md) — the currently inactive
  own-device command profile over Comms; and
- [Heterodyne Social](../spec/heterodyne-social.md) — social behavior,
  moderation, and the optional Matrix feature.

Normative security requirements live in their owning family document and in
registry revision 1. This analysis neither creates nor relaxes requirements.
The only normative dependency edges are:

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

The descriptions below reproduce registry revision 1 exactly. Each assumption,
threat, and mitigation in later sections cites its owning identifier.

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

### 2.3 Control

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests, grants, tokens, or side effects are encrypted at rest under Core, Comms, and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never receives persona epoch, NID, audience, repository-decryption, or ratchet secrets.

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
| Control audit and session authority | User-controlled Control endpoint | CONTROL-I-AUDIT-AT-REST, CONTROL-I-SESSION-KEY-CONFINEMENT |
| Social private configuration | Protected local/config storage | SOCIAL-I-PRIVATE-STATE-AT-REST |
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
| Compromised durable device | Uses its NID, epoch, audience, or ratchet authority until effective revocation; compromise windows and key rotation bound later trust. |
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
| DM replay, ratchet-state loss, or metadata correlation | Enforce session replay checks and key deletion; keep outer DR events out of repositories and provide no backfill. |
| Org epoch-key holder bypasses delegate threshold through a relay | Require threshold-authorized canonical history for every org-owned Comms post and feed index, regardless of carrier (CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE, COMMS-I-CLIENT-SIDE-DELIVERY). |
| Policy bypasses cryptography | Run the authenticated acceptance hook only after cryptographic checks; policy can tighten but never loosen a rejection. |

### 5.3 Control threats

| Threat | Mitigation |
|---|---|
| Audit disclosure or tampering | Encrypt durable audit records and bind them to negotiated Core/Comms/Control context (CONTROL-I-AUDIT-AT-REST). |
| Session device escalates into persona or credential authority | Never deliver epoch, NID, audience, repository-decryption, or ratchet secrets; require explicit object-level grants (CONTROL-I-SESSION-KEY-CONFINEMENT). |
| Experimental implementation claims conformance | Keep baseline and strict Control claims inactive until ADR-030 integration and the minimum vector gate. |

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
| Moderation authority changes after approval | Verify approval signatures and the moderator set at the required repository, Matrix, or reduced-assurance relay anchor. |
| Advisory label becomes authority | Treat NIP-32 labels and web-of-trust scoring as local policy, never identity or editorial authority. |
| Sybil vouchers or poisoned friend caches drive recovery | Treat Social recovery bindings as advisory inputs only; accepted KEL and declared Core witness rules retain authority (SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH, CORE-I-IDENTITY-INTEGRITY, CORE-I-VERIFY-BEFORE-USE). |

## 6. Metadata, availability, and residual risk

Encryption does not hide all metadata. Relays and repository hosts can observe
timing, volume, public keys, branch changes, and fetch patterns; allowed Tier 2
seeders also see the membership allow list. Routing nodes see lookup targets.
Matrix federation exposes room membership and event-graph metadata to relevant
servers. Tor reduces direct network-linkability but does not prevent global
timing analysis.

No deletion mechanism guarantees erasure from hostile relays, old git objects,
backups, screenshots, or offline seeds. `kind:5`, canonical-index removal, and
encrypted-branch scrubbing are cooperative visibility and retention controls.
Clients must describe them accordingly.

Multi-source retrieval improves availability against withholding but does not
guarantee it. A persona can be unavailable if all serving nodes and relays are
offline. Recovery peers and witnesses can help restore verified identity
material but cannot mint authority outside the KEL.

## 7. Strict-profile posture

Strict profiles are additive and composable:

- `heterodyne-core-strict-v1` covers the Core invariant set and strict Core
  obligations;
- `heterodyne-comms-strict-v1` composes Core strict plus Comms invariants;
- `heterodyne-control-strict-v1` is reserved-inactive with Control;
- `heterodyne-social-strict-v1` composes Core, Comms, and Matrix-free Social
  obligations; and
- `heterodyne-social-matrix-strict-v1` adds the Matrix-specific Social
  invariants and exact `Social+Matrix` conformance class.

A capability advertisement lists only profiles actually met. Unknown profile
IDs confer no authority or compatibility. Conformance reports reproduce exact
membership and prerequisite results; incomplete Control cannot advertise its
reserved strict profile.

## 8. Out of scope and pre-1.0 work

The family does not attempt to prevent a compromised honest endpoint from
reading data already available to that endpoint, a recipient from copying
plaintext, global traffic analysis, denial of service by every available
carrier at once, or erasure of bytes retained by hostile third parties. Legal
and operational moderation obligations are deployment concerns; the protocol
defines authenticity and policy carriers, not universal content policy.

Before relevant 1.0 claims, work remains to freeze the Comms double-ratchet
wire profile, finish the repo-relay server/storage contract, exercise KERI fork
and recovery behavior across independent implementations, validate Matrix MLS
migration, integrate Control with its required vector corpus, and expand
negative vectors for rollback, metadata, and recovery-policy attacks. Each
item belongs to its named document and must not create a forbidden dependency.
