# Heterodyne threat model

This is a defensive, non-normative analysis of the six-document current draft.
The specifications, live registry, and schemas remain authoritative.

## Security objective and scope

Heterodyne keeps baseline Nostr authorship simple: the active Nostr public key
identifies the persona, and the valid NIP-01 signature by that key establishes
authorship. A bare active key is a first-class identity. Optional Assurance can
add continuity and recovery evidence, but cannot change Core validity, NIP-01
authorship, or standard Marmot account semantics.

The model covers hostile relay and repository input, compromised carriers,
malicious or stale authenticated peers, confused-deputy authorization,
cross-persona state leakage, replay and concurrency failures, metadata
disclosure, and partial compromise. It assumes standard cryptographic
primitives are correctly implemented and does not treat end-user endpoint
compromise as solvable by a carrier protocol.

Defensive validation uses synthetic fixtures in the repository and local test
harness. It demonstrates rejection, unchanged protected state, bounded work,
and absence of disclosure. It does not need operational exploit payloads,
external targets, live credentials, destructive actions, persistence, evasion,
or weakened security controls.

## Trust boundaries

| Boundary | Untrusted or limited input | Required decision |
|---|---|---|
| Nostr event ingestion | Relay, repository, cache, or peer bytes | Verify exact ID and signature, then apply the owning kind/profile rule before use. |
| Identity discovery | kind `0`, NIP-05, NIP-65, repository and node hints | Preserve active-key authority; treat hints as source-neutral observations. |
| Repository union | Git objects and NID refs | Admit only authorized refs and locally verified exact objects. |
| Privacy tiers | Repository readers, relays, seeds, full nodes | Present private-repository plaintext honestly, encrypt Tier 2 and Tier 3 before every carrier, and confine Tier 3 to authorized private-repository interfaces. |
| Marmot boundary | Conversation events, routing commits, media | Preserve exact signed/ciphertext bytes and upstream account and device-leaf semantics. |
| Full-node API | Light-client request and caller metadata | Resolve one persona vault and exact current grant; fail closed on ambiguity. |
| Signer | Closed intent, grant, request identity, usage state | Attribute and reserve before signing; acquire the execute-once fence before effect. |
| Claims and OIDC | Claims, ledger heads, issuer/status metadata, JWTs | Revalidate authentic current state, audience, type, scope, proof, and freshness. |
| Workspace | Roles, relationships, invites, envelopes, host state | Reject ambient carrier or affiliation authority; consume current signed state. |

## Primary threats and controls

### Identity substitution and downgrade

A relay, repository, cache, continuity provider, or UI label may try to replace
the signed event author with another identity. Core therefore treats the event
public key as authoritative and validates all signed inputs before rendering or
authorization. Missing or invalid Assurance cannot downgrade a Core-valid
active-key persona. A pinned Assurance state cannot silently disappear.

Baseline discovery combines kind `0`, NIP-05, NIP-65, and signed repository or
node hints. Carrier selection is source-neutral. Repository location never
outvotes a newer valid relay event, and relay location never outvotes a valid
repository observation. Only a kind `0` profile or kind `10002` relay list
older than seven days raises a warning and refresh attempt rather than becoming
invalid solely due to age. Every other state retains its applicable freshness
and expiry rules and fails closed where those rules require.

Pre-enrollment key theft can no longer silently attach an attacker cold root:
enrollment requires a seven-day observably public, conflict-free window, and
contested enrollments fail closed to baseline.

### Confidentiality and topology leakage

A private plaintext repository is selective replication, not encryption. A UI
must not imply otherwise.
Tier 2 and Tier 3 encrypt before any repository, relay, trusted seed, or full
node. Tier 2 ciphertext on public carriers exposes the full distribution graph
by design. Tier 3 improves membership privacy against global observers but
concentrates audience metadata at the private repository's allowed nodes; a
compromised or compelled allowed node yields the audience graph. Private
workspace identifiers, counts, locators, and correlations remain inside the
protected boundary. Resource content uses independent keys; role MLS state is
an authorization channel rather than a universal content key.

### Carrier authority confusion

Git authorship, an authorized repository writer, a full-node operator, relay
acceptance, custody, a trusted seed, and Marmot membership are distinct roles.
None creates application authority without the exact signed grant owned by the
relevant family document. A full node can provide a signer without being a
Nostr relay. Multiple trusted seeds improve availability; no seed becomes a
canonical authority.

### Automation and confused deputies

Automation derives signer class, association, tier, and scopes from
authenticated policy rather than caller assertions. The exact attribution is
added before signing and remains protected at the content tier. A persona key
requires explicit narrow OIDC scope; the NIP-01 event public key remains the
author. Vault selection, grant selection, and signer selection fail closed and
cannot fall back across personas or key classes.

### Replay, races, and partial failure

Usage state and request reservation precede a key effect. The durable
signer-side execute-once fence is irreversibly acquired before invocation.
Exact completed retries can return isolated cached results; ambiguous terminal
persistence stays poisoned for reconciliation. Claim revocation and authority
reduction are monotonic, and every authorization effect rechecks current state.

### Compromise

Compromise of the active key also puts its bound device-local Marmot leaves at
risk. Baseline recovery is a complete reset: revoke NIP-46 and OIDC grants,
invalidate subordinate authorities and trusted seeds, remove old leaves,
advance every reachable group, publish fresh successor KeyPackages, and issue
fresh distinct authorization for every continuing subordinate capability.
Optional Assurance can prove continuity to a successor but does not alias the
new author or preserve subordinate authority implicitly. A workspace's hot key
can no longer authorize its own succession; recovery authority rests with the
cold root bound at inception.

## Registry-bound invariants

Each row below is copied exactly from the live security-invariant registry so
reviewers can trace the threat control to its owner and feature binding.

- **CORE-I-IDENTITY-INTEGRITY:** The active persona key and its valid NIP-01 signature are authoritative for baseline persona authorship; hints, repositories, caches, and optional Assurance cannot override them.
- **CORE-I-NID-DELEGATION-DUAL-PROOF:** A writer NID enters a repository union only after owner authorization and the NID's Ed25519 proof verify over the same exact binding.
- **CORE-I-VERIFY-BEFORE-USE:** Every signed object is captured once into an independently owned immutable value, locally signature-verified from that value, and never reread from attacker-controlled source state before rendering, storage, or authorization.
- **CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY:** Core discovery does not depend on a centralized persona, npub, RID, or serving-node directory.
- **CORE-I-KEY-MATERIAL-AT-REST:** Persona nsec, NID secrets, and sensitive cached identity material are protected by the Core keys-repository profile, including NIP-49 wrapping where applicable.
- **ASSURANCE-I-CORE-OPTIONALITY:** Absent, invalid, stale, or withdrawn Assurance cannot invalidate a Core-valid active-key persona or alter NIP-01 or Marmot identity semantics.
- **ASSURANCE-I-RECIPROCAL-ENROLLMENT:** Assurance attaches only when a cold-root inception and no-earlier active-key acceptance bind the same exact active key, inception event, and cold-root signature.
- **ASSURANCE-I-TRANSITION-PROOF-BINDING:** Every succession authority proof, new-key acceptance, and witness receipt binds one identical digest containing every closed transition member except the proof signature values themselves.
- **ASSURANCE-I-PIN-DOWNGRADE:** A pinned Assurance state survives disappearing or conflicting hints and can be downgraded only by the active key plus current recovery authority.
- **ASSURANCE-I-SUCCESSION-NON-ALIASING:** A verified successor proves continuity but remains a distinct Nostr author and Marmot account whose authority does not silently inherit.
- **ASSURANCE-I-COMPROMISE-CUTOFF:** A compromise succession rejects Assurance authority at or after its effective cutoff and carries no subordinate continuation.
- **ASSURANCE-I-NO-IMPLICIT-CONTINUATION:** Succession transfers no succession authority, associated-key issuance policy, subordinate key, repository, group, delegate, financial, or application authority unless the record explicitly reauthorizes it.
- **ASSURANCE-I-ASSOCIATED-KEY-BOUNDS:** Associated keys are accepted only for their exact head, active-key or epoch-threshold issuance ceiling, narrowed role and scope, issuer, subject, time bounds, active-grant proof requirements, and non-revoked state.
- **ASSURANCE-I-EXPORT-LOSSLESS:** KERI export either preserves every security-relevant accepted Assurance semantic or fails without emitting a misleading partial identity.
- **COMMS-I-TIER3-BLIND-CARRIER:** Tier 2 and Tier 3 content is audience-key encrypted before reaching any repository, seed, full node, or relay, and Tier 3 objects reach only authorized private-repository interfaces.
- **COMMS-I-TIER2-HONESTY:** Private plaintext repositories are selective-replication boundaries, not encryption, and clients present that trust boundary honestly.
- **COMMS-I-CONFIG-AT-REST:** Comms-owned non-key private state and audience or group material are encrypted under the Comms repository-encryption profile.
- **COMMS-I-CLIENT-SIDE-DELIVERY:** Cross-backend Comms processing runs on user-controlled clients; full nodes, repository relays, routing nodes, and Nostr relays are blind carriers for protected plaintext.
- **COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY:** Feed, outbox, and delivery discovery do not depend on a centralized delivery directory.
- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-NIP01-AUTHORSHIP:** Every ordinary Social event is authored by the public key that actually produced its valid NIP-01 signature; no persona, agent, moderator, repository, relay, KEL, or feed metadata can substitute another author.
- **SOCIAL-I-SOURCE-NEUTRAL-SELECTION:** Social state unions valid exact events from relays and repositories and applies NIP-01 replaceable selection without carrier priority; only kind `0` profiles and kind `10002` relay lists use the seven-day warning-only refresh age. Every other state remains subject to its applicable freshness and expiry rules and fails closed where those rules require.
- **CONTROL-I-AUDIT-AT-REST:** Signer authorization, attribution, refusal, and side-effect audit is encrypted and contains no replayable token, connection secret, or transcript.
- **CONTROL-I-BASELINE-ACTIVE-KEY:** Baseline enrollment and signing depend only on the persona active Nostr account; cold roots, KERI, epochs, succession, and Assurance remain optional additional protection.
- **CONTROL-I-CLIENT-KEY-CONFINEMENT:** A light client receives no persona, agent, NID, repository, Marmot-leaf, OIDC-issuer, or trusted-seed private key.
- **CONTROL-I-PERSONA-VAULT-ISOLATION:** Every request resolves exactly one persona vault and no authority, key, repository, audit context, or fallback crosses a vault boundary.
- **CONTROL-I-EXACT-SIGNER-GRANT:** A domain-separated BIP-340-authenticated signer grant exactly binds the persona, NIP-46 client, audience, selected signing key and class, methods, event kinds, finite limits, issuance, expiry, and revocation state, and only the unique authenticated predecessor/revocation head is current.
- **CONTROL-I-NIP46-OIDC-ACTIVATION:** OIDC activates standard NIP-46 only after the exact approved grant, OIDC authorization, persona, client, audience, signer, class, lifetime, and one-use secret are atomically consumed from authenticated current state; caller metadata cannot widen a grant.
- **CONTROL-I-NO-SIGNER-FALLBACK:** Vault lookup and signer selection fail closed without falling through to another persona, key class, local key, or broader grant.
- **CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING:** Every closed automated intent is digest-bound to its request and derives class, association, tier, and scopes from authenticated current policy, then passes through Comms attribution after durable reservation and before the selected signer can produce a verifiable NIP-01 signature.
- **CONTROL-I-MARMOT-GRANT-CONFINEMENT:** Node-mediated Marmot operations expose only active-account and exact device-leaf grant-filtered content while all leaf secrets remain device-local.
- **CONTROL-I-OPERATION-AT-MOST-ONCE:** An authoritative revisioned per-grant usage record and request reservation precede every effect, and only a durable cross-process signer-side execute-once token fence over an immutable event snapshot may invoke the key operation; acquisition irreversibly poisons the token before the effect, exact terminal retries return isolated cached copies, unresolved terminal persistence remains non-reacquirable reconciliation, different bindings conflict, and no post-signing compare-and-swap substitutes for that fence.
- **CONTROL-I-MARMOT-LEAF-COMPROMISE:** Compromise of the active Nostr account assumes every device-local Marmot leaf bound to that account may also be compromised.
- **CONTROL-I-COMPROMISE-RESET:** An authenticated reset grant binds the authoritative pre-reset inventory and a successor-authenticated completion binds consecutive authoritative evidence: all NIP-46 and OIDC grants are revoked, subordinate authorities and trusted seeds invalidated, old leaves removed, every reachable group advanced, fresh successor KeyPackages published, and every continuing subordinate authority receives a fresh distinct authorization.
- **COMMS-I-CLAIM-AUTHENTICITY:** Claim IDs, event signatures, issuer authority, typed references, and native proofs are verified before trust or authorization policy is applied.
- **COMMS-I-CLAIM-ATTENUATION:** Every delegated claim strictly preserves or narrows all authority dimensions and issuance chains contain at most eight edges.
- **COMMS-I-CLAIM-REPOSITORY-AUTHORITY:** Persona-issued device authorization is final only in canonical private claim-repository state, while authenticated reductions take effect immediately.
- **COMMS-I-CLAIM-REVOCATION:** A valid revocation or authority reduction is irreversible, monotonic, and wins concurrent repository merges.
- **COMMS-I-LEDGER-CONFINEMENT:** Private claim-ledger contents and decryption material are available only to active durable NID-bearing ledger readers.
- **COMMS-I-ISSUER-KEY-CONFINEMENT:** Shared OIDC signing keys are separately encrypted and released only to nodes with active oidc-token-issuer authority.
- **COMMS-I-MINT-FRESHNESS:** A node mints only from a synchronized canonical checkpoint no older than the declared authorization_view_max_age bound, which defaults to 300 seconds and cannot exceed 86400 seconds.
- **COMMS-I-ISSUER-CONTINUITY:** HTTPS issuer metadata and the active-persona-key-scoped Radicle continuity tree agree on the exact active issuer, keys, status digests, and authorized succession.
- **COMMS-I-CLAIM-RELEASE:** OIDC projection releases only claims allowed by scope, audience, client policy, consent, active repository state, issuer trust, and proof requirements.
- **COMMS-I-JWT-TYPE-AUDIENCE:** JWT consumers enforce exact issuer, intended audience, time, signature, nonce when applicable, and token-type separation including typ at+jwt for access tokens.
- **COMMS-I-STATUS-INTEGRITY:** Draft-21 status lists are signed, fresh, digest-bound across HTTPS and Radicle mirrors, writer-namespaced without index reuse, and never let VALID override other token failures.
- **COMMS-I-PUBLIC-READER-TIER1-ONLY:** A public-reader implementation consumes only verified Tier 1 content and never renders private-repository plaintext or interprets Tier 2 or Tier 3 ciphertext as public content.
- **COMMS-I-AGENT-SIGNER-BINDING:** Every automated event uses the exact registered signer, key class, and optional association kind/value; an agent key is preferred, while a persona key requires the explicit OIDC persona-signing scope, and the event pubkey remains authoritative.
- **COMMS-I-AGENT-ATTRIBUTION:** Every agent-authored application event carries the canonical automation attribution block at its tier-appropriate protected location.
- **COMMS-I-WORKLOAD-TOKEN-CONFINEMENT:** Workload tokens, token identifiers, private source claims, and sender proofs remain confined to the protected authorization and audit boundary.
- **COMMS-I-MARMOT-UPSTREAM-AUTHORITY:** The pinned Marmot dependency remains authoritative for MLS, conversation events, encrypted media, and Nostr transport semantics.
- **COMMS-I-MARMOT-ACCOUNT-IDENTITY:** The active persona key is the Marmot account identity, every device leaf remains independent, and neither Heterodyne continuity nor storage provenance aliases another account or leaf inside MLS.
- **COMMS-I-MARMOT-EXACT-BYTES:** Radicle storage and every Nostr or media interface preserve exact signed Marmot event bytes and encrypted media ciphertext.
- **COMMS-I-MARMOT-SECRET-CONFINEMENT:** Independent device leaves do not share secrets by default, and node-mediated clients receive no MLS, account, leaf, or repository secret.
- **COMMS-I-RADICLE-ROUTING-AUTHORITY:** Only a canonical Marmot routing commit by its active account-key administrator can authorize a routing binding and repository genesis with the same h, RID, routing-event ID, and authorized writer refs.
- **COMMS-I-RADICLE-NON-ERASURE:** Retention expiry stops conforming advertisement and replication but never claims erasure of independent Git objects, clones, exports, or backups.
- **COMMS-I-TRUSTED-SEED-CONFINEMENT:** A trusted seed receives only routing metadata and exact encrypted event bytes, writes only its own active authorized NID ref, and gains no persona, repository-owner, group-admin, full-node, or MLS authority.
- **COMMS-I-PRIVATE-RELAY-ACL:** Every private seed read or write uses embedding-configured seed and administrator trust roots, one-use authenticated request authority, trusted current state and time, and one unique current unexpired administrator-signed ACL head matching the account role, seed grant, h, private RID, and Marmot group transition.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-AUTHORSHIP-EXACT:** Agent-policy receipts, corrections, and subscriber-local enforcement bind the actual signed event author and verified Comms agent association; no moderator or associated agent becomes an event author without producing that event's signature.
- **WORKSPACE-I-NO-AMBIENT-AUTHORITY:** Workspace affiliation, optional Assurance continuity, or active-key succession alone grants no role, relationship, delegate, seed, or resource capability; each subordinate authority requires explicit current-key reauthorization.
- **WORKSPACE-I-INHERITANCE-NARROWS:** Exact role-policy-head sets, child roles, resource visibility/capabilities, grants, and bilateral allowances cannot widen an applicable workspace or parent-role ceiling.
- **WORKSPACE-I-PRIVATE-TOPOLOGY:** Public state reveals no stable identifier, digest, count, locator, or correlation for a concealed workspace, role, relationship, repository, or resource.
- **WORKSPACE-I-CARRIER-NOT-AUTHORITY:** Git authorship, Radicle repository-writer permission, trusted-seed or host status, relay acceptance, custody, and Marmot membership or group administration are never sufficient Workspace authorization evidence.
- **WORKSPACE-I-AUTHENTICATED-CURRENT-STATE:** Every Workspace authority effect consumes only its configured resolver instance's latest accepted generation and revalidates complete signed state, exact requested terms, transition times, role paths, exactly one semantic receiving relationship receipt, immutable envelope-ID ancestry, and revocations at effect time.
- **WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS:** Role MLS state authorizes delivery but never serves as one universal content key for subordinate resources.
- **WORKSPACE-I-REVOCATION-FUTURE-ONLY:** Revocation blocks future authorization and key delivery, including custody-host delivery from and including the exact effective time, without claiming erasure of data or keys already obtained.
- **WORKSPACE-I-FRESHNESS-BOUNDED:** Ordinary writes use checkpoints no older than 86400 seconds and authority mutations no older than the declared authorization-view bound (default 300 seconds, ceiling 86400 seconds), with policy able only to shorten those bounds; invitation commit samples trusted time itself, reruns complete activation validation at that time, and releases the reservation on any failure before its atomic transition.
- **WORKSPACE-I-HOST-AUTHORITY-SEPARATION:** Hosting or trusted-seed availability does not grant governance authority, while explicit key-custody hosts remain confidentiality trust boundaries.
- **WORKSPACE-I-RADICLE-BACKSTOP:** Every effective role retains an authorized Radicle locator and eligible Radicle-backed relay host independent of optional Nostr relays.
- **WORKSPACE-I-DEVICE-LEAF-SEPARATION:** Each active account device has an independently revocable Marmot MLS leaf and receives only uniquely identified envelopes bound to that exact grant, single path admission epoch, account, device, leaf, role, resource, checkpoint, and custody host.
- **WORKSPACE-I-GOVERNANCE-ASSURED:** Workspace authority mutations execute only under a window-complete verified Assurance enrollment bound at inception, compromise reset for a workspace uses only the assurance-recovery class, and ordinary writes continue under their own window when governance fails closed.
- **ASSURANCE-I-ENROLLMENT-WINDOWED:** No enrollment is pin-eligible before 604800 seconds of observably public, conflict-free existence; contests and competing enrollments fail closed to baseline, and a conflict resolves only to an enrollment with both materially earlier proven existence and witness receipts spanning the gap.
- **COMMS-I-TIER3-CONFINED:** Tier 3 posts, audience wraps, rosters, and rotation records are carried only via the private repository's authorized interfaces, never ordinary public relays, confining audience membership metadata to allowed nodes.
- **CORE-I-CREATED-AT-REFUTATION:** A matured OpenTimestamps attestation proving created_at materially exceeds true existence time permanently excludes the event from replaceable selection and every enhanced claim, and no proof requirement gates baseline interoperability.

## Current draft versus frozen validation history

The current-draft lane evaluates current specifications, registry entries,
schemas, and current reference code. It does not execute the frozen historical
topic projection. The rolling snapshot contains 482 non-normative vectors from
source commit `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, bound by snapshot
commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`.

The frozen claim schema member `profile_revision` has value `2`, distinct from the current family registry revision 14. Neither that historical wire value nor
the snapshot count is a substitute for current registry or specification
authority.
