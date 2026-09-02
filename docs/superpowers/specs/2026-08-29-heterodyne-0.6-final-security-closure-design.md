# Heterodyne 0.6 final security closure design

**Status:** Approved repair design. This document governs the Task-10 repair
wave but does not itself amend the live protocol; authority changes only when
the complete prose, registry, schema, proof-domain, reason, runtime, vector
source, and test patch is reviewed and merged.

**Approved:** 2026-08-29

**Reviewed HEAD:** `4cf1af9294c843138de3dc48939d4c94ab6c380e`

**Lifecycle constraint:** ADR-048 remains `Proposed` throughout this repair,
source stabilization, Task-9 regeneration, and the next independent review.

## 1. Verification result

The Task-10 candidate is not merge-ready. Direct inspection confirms the one
Critical and every Important finding in the two independent reviews. The two
reviews overlap on post-pin finality, leaving one Critical and eight distinct
Important defects. The static-graph finding is also accurate, although no
present hidden dynamic or CommonJS edge was reported.

| Finding | Verified implementation fact | Design disposition |
|---|---|---|
| Spec C1: backdateable witness chronology | The receipt binds self-declared first/last times and the inception tuple, but not `accepted_head`; the evaluator trusts those times and only consults witness keys selected by the candidate. | Replace plain evidence callbacks with a durable observation authority, independently configured witness trust, authority-owned ingestion times, and an exact-head receipt binding. |
| Spec I1 / Security I1: post-pin unpin | Every valid receipt contributes a future window end, even if immature, and conflicts are tested before a matching pin is returned. | Atomically close and persist the one pre-pin evidence revision; an exact verified pin is thereafter absorbing and later evidence is warning-only. |
| Spec I2: stale snapshot guidance | `snapshot.json` pins source `0dd150...`, vector schema 3, 275 vectors, and 287 artifacts, while normative Core, maintained guides, and docs-lint assert the superseded `2ef40...` / `5d4bb...` / 482 / 493 bootstrap. | Make the manifest and history-derived snapshot commit the sole exact identity; remove mutable literals from maintained prose and make docs-lint manifest-aware. |
| Spec I3: member-KEL case | `validateOrganizationMemberAddition`, its current case, and its reason coverage have no live specification or schema contract and contradict Core's active-key baseline. | Remove the current evaluator/case and quarantine the retained historical reason under an explicit retired-semantics anchor. Do not move member-KEL into Workspace. |
| Security I2: boolean downgrade | `evaluateAssurancePinPolicy` accepts two booleans; the event model omits `downgrade_consent`; the cryptographic enrollment evaluator rejects every downgrade. | Verify the actual active-key-signed kind `31000` record and current recovery signature, mint an opaque transition, and CAS it against the retained pin. |
| Security I3: fabricated claim authority | Authorization consumes plain semantic objects and public `envelope_valid` / `issuer_authorized` assertions; a shaped arbitrary event ID suffices. | Mint opaque claim and revocation artifacts only from immutable, cryptographically verified events; every chain and authorization API consumes those artifacts. |
| Security I4: non-consuming PoP | The public `Set` is only read. The caller mutates it after success; concurrent callers can both succeed and there is no effect fence. | Bind proof use and effect under one durable atomic acquire/terminal state machine. No authority-returning API may expose an uncommitted `allowed:true`. |
| Security I5: missing ledger writer authority | Replay verifies the Ed25519 self-signature derived from `writer_nid`, but never verifies current Core owner delegation, RID, ref, operation, revision, or checkpoint. | Add the current Core writer-binding proof/evaluator and an opaque current-writer resolver to every replay and effect-time revalidation. |
| Security I6: ungrounded semantic coverage | `semanticEvidenceForCase` emits labels from the static contract regardless of what the privately retained raw result proves. The Workspace signature case compares two strings. | Require a boundary-specific opaque semantic certificate before an invariant or security reason counts. Replace affected fixtures with actual signed objects and authority transitions. |
| Spec M1: partial import graph | The collector visits only top-level ES/import-equals syntax; acceptance is a count plus filename denylist. | Repair now with recursive import-like AST traversal and an exact reviewed repo-relative allowlist. |

The findings are not independent implementation accidents. They share a trust-
boundary error: an authority consumer accepts a caller's description of a
verified fact instead of a capability minted by the verifier that established
the fact.

## 2. Defensive validation scope

All threat analysis, hostile-boundary fixtures, and negative conformance work
specified here are blue-team validation exercises for protocol quality. They
must use only the smallest deterministic, synthetic invalid fixtures needed in
the repository and isolated local test processes. Their purpose is to prove
fail-closed rejection, no unauthorized state or effect, no disclosure,
bounded work, replay resistance, correct reconciliation, and interoperability.

This design does not authorize contacting or testing real relays, nodes,
deployments, identity providers, accounts, third-party systems, credentials, or
user data. It does not authorize exploit or offensive-payload development,
targeting, scanning, malware, shells, credential theft, persistence, evasion,
anti-forensics, destructive action, or weakening a control. Attacker-
precondition and trust-boundary descriptions are non-operational defensive
analysis only.

Every implementation test derived from a hostile boundary in this design must
identify itself as a defensive validation exercise and use a synthetic/local
fixture. If a proposed validation would require a live target, real credential,
destructive action, persistence, evasion, or functional exploit, implementation
stops at a non-operational finding and requests maintainer direction.

## 3. Normative constraints on the repair

The repair must preserve these existing meanings:

1. A bare active Nostr key remains a complete Core identity. Neither claim
   verification nor repository-writer verification may introduce a mandatory
   KEL, cold root, Assurance profile, directory, or Heterodyne-specific relay.
2. Event `created_at`, receipt timestamps, and NIP-03 remain non-authoritative
   for enrollment chronology. Comparing one author-controlled timestamp with
   another does not repair C1.
3. For an Assurance downgrade, the active key consents through the outer
   NIP-01 signature over the exact kind `31000` event. The current recovery
   authority signs the existing registered downgrade proof bytes. Requiring a
   second active-key signature over those proof bytes would change, not repair,
   the live contract.
4. A claim's exact outer issuer is the Nostr key that signed the verified
   event. Optional continuity, a repository identity, or a cache identity must
   not substitute for it. The Core result embedded in a verified claim artifact
   is therefore the immutable verified NIP-01 author result, not a new KEL gate.
5. Core writer authorization is repository authority only. It does not grant
   Nostr authorship, Workspace governance, decryption, or Assurance authority.
6. Generated snapshot bytes are never repaired by hand. Any live prose,
   registry, schema, evaluator, vector-source, test, or docs-lint change is
   source work and requires a new stable source commit followed by full Task-9
   regeneration.

## 4. Final decision and rejected alternatives

### Final decision — authority-capability closure

Use the repository's established opaque-authority and execution-fence pattern
at every affected boundary. Make only the wire additions needed to express an
already normative proof: `accepted_head` on the witness receipt and a closed
current Core repository-writer binding. Chronology, current-state resolution,
nonce consumption, and effect fencing remain local/repository-backed authority
interfaces; no network service is introduced.

This is the approved architecture. It is the broadest source refactor, but it
addresses the common root cause, supports deterministic defensive negative
conformance, and prevents a later caller-boolean variant of the same defect.

### Rejected alternative — remove witness acceleration

Delete witness receipts as an enrollment-eligibility alternative and require
each verifier to durably observe the exact candidate for `W`. The remaining
claim, downgrade, writer, and evidence-certificate repairs still apply.

This is the smallest and easiest chronology model to audit, but it gives up the
approved configured-witness alternative and any ability for a shared
observation authority to help multiple local clients. It is not selected for
the 0.6 repair.

### Rejected alternative — portable external chronology service

Define an independently trusted, replay-protected witness/timestamp log whose
checkpoints make old observation portable to a verifier that has never seen the
candidate. This can preserve immediate late-verifier eligibility, but it adds
a new network trust root, availability and privacy surface, deployment profile,
schemas, discovery, retention, fork handling, and interoperability work.

Nothing in 0.6 requires that portability, and the approved design rejects an
unnecessary central identity dependency. This approach is outside the Task-10
closure.

A surgical patch that merely checks receipt timestamps, moves the existing pin
branch, replaces booleans with new booleans, or inserts into the caller's `Set`
is not a viable fourth approach. It would leave the chronology, forgery, race,
and effect-failure findings intact.

## 5. Final architecture

### 5.1 Common boundary rule

Authority-bearing flows use four layers:

```text
hostile bytes/object
  -> capture once and verify exact closed form
  -> opaque verifier-minted artifact/view
  -> durable CAS or effect fence
  -> terminal result or explicit indeterminate reconciliation
```

Opaque values are empty/frozen public objects backed by private `WeakMap`
records. Every private record holds an independently owned immutable snapshot,
the authority instance that minted it, and the exact binding digest. A clone,
plain lookalike, proxy, accessor object, mutation after validation, or artifact
from another authority fails closed.

The in-repository reference stores may be process-local deterministic
conformance implementations, as the Control signing fence already is. Normative
prose must require production stores to be durable across restart and competing
workers. That is an implementation requirement, not a reason to invent a new
network service.

### 5.2 Non-backdateable enrollment chronology and absorbing finality

Introduce an opaque `EnrollmentObservationAuthority` created with:

- a trusted monotonic clock;
- a durable compare-and-swap journal;
- an independently configured witness trust policy containing keys, maximum
  weights, a minimum local threshold, and a stable policy digest; and
- a stable verifier/authority identity used only to bind its own retained state.

The public loader no longer returns authoritative `observed_at` fields in plain
objects. Candidate pairs, contests, competitors, and receipts are first
captured and cryptographically authenticated. The authority then records its
own ingestion time and monotonically advances one journal entry keyed by the
exact tuple:

```text
(active_key, inception_event_id, cold_root, accepted_head)
```

The journal contains a revision, the candidate's first ingestion time,
deduplicated evidence/event/receipt digests and their first ingestion times,
per-witness first and latest receipt state, all authenticated conflicts, an
absorbing contested marker, and an optional terminal pin. Caller timestamps
can be retained as signed audit assertions but never move an authoritative
start or conflict time backward.

Revise `enrollment-observation-receipt-v1` to add required `accepted_head` and
add it to `heterodyne-assurance-enrollment-observation-v1` proof-domain members.
All repeated candidate members must equal the exact verified pair. A receipt
key counts only if it appears both in the candidate inception and in the
authority's independent trust policy. Its effective weight is no greater than
either configuration permits, and both the inception threshold and the
authority's local minimum must be met.

A witness key matures only after the authority has ingested at least two
monotonic, distinct signed receipts for the same exact tuple and witness:

- the first receipt establishes an authority-owned `first_ingested_at`;
- a later receipt is ingested no earlier than `first_ingested_at + W`;
- `first_observed_at` is unchanged, `last_observed_at` does not regress and is
  non-future at ingestion, and the later receipt covers the completed interval;
- exact receipt replay is idempotent and cannot advance the journal; and
- no qualifying conflict was ingested on or before the closing revision.

The verifier-local path similarly uses the authority's durable first candidate
ingestion and trusted current time. Raw receipts imported into a second
authority begin a new chronology there; they cannot fast-forward it. A shared
already-configured durable authority can serve several local clients, but the
wire receipt by itself is not portable elapsed-time authority. This
authority-owned, non-portable chronology is the final 0.6 rule; a portable
chronology protocol or external service is neither implied nor introduced.

Pin creation is part of the same transaction. The closed retained pin keeps the
existing exact candidate fields and `observed_at`, and adds the complete closed
`eligibility_basis` plus its digest. The basis contains the closing journal
revision, start/close times, mode, qualifying receipt digests, trust-policy
digest, and conflict set. Pin backup/export preserves that basis and its
referenced journal evidence; a digest without its provenance is not a valid
pin. The authority commits it only if the journal revision is unchanged. A
conflict racing the close changes the revision, causes CAS failure, and is
evaluated before retry. `verified` is returned only after the pin commit
succeeds.

After an exact pin exists:

1. validate the retained pin and its stored eligibility basis;
2. authenticate newly presented evidence and journal it at the authority's
   current ingestion time;
3. return the exact retained `verified` state before constructing any new
   candidate-window boundary; and
4. report authenticated post-pin contests or competitors as warnings/audit
   facts only.

No evidence first ingested after the pin can become timely by claiming an old
time or by creating a future receipt window. A nonmatching retained pin returns
`assurance-pin-conflict`; it is not silently reclassified or replaced. A
pre-pin contest is absorbing. Only valid succession and the dual-consent
downgrade below transition an established pin.

Required chronology/finality defensive validation tests use only synthetic
local fixtures and include immediate backdating, declared time before candidate
ingestion, candidate-only witness trust, wrong accepted head, receipt replay,
second-authority replay, same-witness duplicate weight, nonmonotonic receipt
update, threshold/config substitution, pre-pin race/CAS failure, pre-pin
absorbing conflict, exact pin plus later immature receipt and contest, post-pin
local-start replacement, and pin-provenance mutation.

### 5.3 Real dual-signature Assurance downgrade

Keep the existing active-key-acceptance schema and
`heterodyne-assurance-downgrade-v1` proof domain: both already express the live
wire rule. Repair the TypeScript model and evaluator instead of inventing a
different consent object.

Add a dedicated `evaluateAssuranceDowngrade(retainedPin, sourceEvent)` boundary
that snapshots and verifies the actual kind `31000` event, canonical content,
exact tags, and exact current immutable pin. It requires:

- outer `pubkey === active_key` and a valid NIP-01 ID/signature;
- `state:"downgraded"` and the required closed `downgrade_consent`;
- `predecessor === assurance_head === retained accepted_head`;
- the original inception, active key, and cold root/recovery authority;
- the recovery signature over the exact registered five-member downgrade
  digest; and
- no field, byte, predecessor, authority, or pin mutation after capture.

Success mints an opaque `VerifiedAssuranceDowngrade`. Pin persistence consumes
only that artifact and CASes the exact retained head/revision to a terminal
`downgraded` pin. An exact completed retry returns the cached terminal state; a
different event or predecessor cannot replay against it. Remove the public
boolean downgrade branch from `evaluateAssurancePinPolicy` and retain that
function only for pin/head and duplicity selection. The downgrade transition
and persistence boundary consumes only `VerifiedAssuranceDowngrade`.

Use existing `assurance-downgrade-consent-required` when either signature is
absent or invalid, and the existing schema/head/pin reasons for their exact
conditions. Add synthetic/local defensive validation tests for valid
dual-signature acceptance, missing proof, wrong recovery key, wrong active
signer, exact-byte mutation, wrong inception/head/predecessor, artifact clone,
mutation-after-check, replay, and terminal CAS.

### 5.4 Opaque verified claims and atomic single use

`verifyClaimEnvelope` returns an opaque `VerifiedClaimArtifact`, not a plain
`ClaimSemanticBody`. Its private record contains the immutable exact NIP-01
event/signing bytes, verified event ID/signature/author, parsed closed semantic
body, claim ID, issued time, declared credential-ledger persona/generation, and
the Core verified-event result. Remove public `issuer_authorized` and
`envelope_valid` members. The exact outer Nostr author remains the claim issuer;
no KEL or Assurance lookup is added.

Update the retained `claim-issuer-authority-invalid` description accordingly:
it covers failure to establish the exact verified outer issuer or explicit
claim-chain authority, not a KEL identity substitution. Preserve its historical
`first_version`.

Chain resolution accepts only `VerifiedClaimArtifact` instances and uses their
private semantic snapshots. Any read-only accessor returns a clone for display,
and no authorization API accepts that clone back. Apply the same pattern to
signed revocations so a public `VerifiedRevocation` or
`RevocationAuthorityEvidence` lookalike cannot bypass the repaired claim path.
Ledger-embedded `{event, semantic}` artifacts remain valid wire data, but replay
must verify the event and byte-equivalence of the duplicate semantic value
before minting the opaque runtime artifact.

Create an opaque `ClaimAuthorizationAuthority` that owns the trusted clock,
trusted-issuer policy, current canonical ledger/revocation loader, exact request
binding, and a durable proof/effect store. It exposes two different concepts:

- inspection resolves display state without granting an effect capability;
- authorization prepares and executes an effect using a verified artifact
  chain, fresh subject proof, and current repository state.

The single-use key is a domain-separated digest of exactly:

```text
(issuer, subject, claim_id, audience, resource, operation, nonce)
```

The acquired binding additionally commits the complete artifact-chain digest,
proof/challenge digest, current ledger checkpoint/generation, request/effect
digest, authority identity, and idempotency key. After all fail-closed checks
and an immediate current-view reload, one atomic acquire irreversibly changes
`unused` to `executing` before the effect is invoked. Concurrent or substituted
bindings cannot both acquire it.

The effect capability is idempotent for the derived execution token. Terminal
states are `committed` with a cached result or `indeterminate` with a
reconciliation digest. If the effect throws, its exact outcome is unknown, or
terminal persistence fails after acquisition, the proof remains burned and the
record is never reopened. Exact retries return the cached terminal result or a
reconciliation outcome; a mismatched retry is replay/conflict.

Keep `heterodyne-claim-pop-v1` unchanged: its proof bytes already bind the
correct challenge. The defect is authoritative consumption, not signature
coverage. Add `claim-subject-proof-replayed` for an already acquired or
conflicting single-use key and `claim-authorization-effect-indeterminate` for
an acquired effect whose terminal result requires reconciliation. Invalid
cryptography remains `claim-subject-proof-invalid`.

Synthetic/local defensive validation tests cover a bare semantic object,
cloned/fabricated evidence, substituted event ID, changed exact event bytes,
wrong authority instance, opaque artifact mutation, sequential replay,
simultaneous acquire, binding substitution, CAS conflict, effect throw,
successful effect with terminal-write failure, exact cached retry, and
post-prepare repository/revocation change.

### 5.5 Current Core writer delegation in claim-ledger replay

Core already normatively requires owner and NID proofs over one exact writer
binding, but the current artifacts do not define or execute that binding. The
approved design closes that existing rule with a new registered, closed
`heterodyne.core.repository-writer-binding.v1` authority-file object and
`heterodyne-core-repository-writer-binding-v1` proof domain. The unsigned body
binds at least:

```text
(profile, spec_version, owner_active_key, repository_rid, writer_nid,
 ref_namespace, operations, issued_at, expires_at)
```

The active repository owner makes the BIP-340 `owner_signature`; the writer NID
makes the Ed25519 `nid_signature`; both verify over the identical domain-
separated closed body. The NID must derive from the Ed25519 key. Presence in the
owner's current authenticated repository policy supplies current inclusion,
revision, predecessor/checkpoint, and revocation state; those resolver facts
cannot be supplied as booleans by the caller.

Add an opaque `CoreRepositoryWriterAuthority` backed by a trusted clock and
current owner-policy loader. It mints `CurrentRepositoryWriterBinding` only
after schema closure, both signatures, active owner, time bounds, current policy
inclusion, exact RID/ref/operation, revision, and checkpoint all validate. This
is a repository-local resolver interface, not a directory or network service.

Extend canonical ledger evidence so every record is attributed to the exact
writer ref and commit that carried it. Before a record enters replay,
`mergeClaimLedger` must resolve and consume the current opaque binding and
require:

- `owner_active_key === record.persona`;
- exact claim-ledger RID, canonical writer ref, and ledger-write operation;
- exact `writer_nid === record.writer_nid` plus the existing record signature;
- current, nonexpired, nonrevoked, nonconflicted policy state; and
- the authoritative replay checkpoint/revision rather than `record.created_at`.

Store only private authority fingerprints with the validated merge result.
Immediately before a downstream authority effect, reload and revalidate every
distinct writer binding along with the canonical ledger view. A removed writer
makes the prepared view stale; repository membership and the record's
self-signature never substitute for current delegation.

Allocate `repository-writer-binding-invalid` in Core for closed-binding or
current-policy validation and use the intentionally coarse
`claim-ledger-writer-unauthorized` Comms translation at the ledger boundary,
with privileged Core detail retained in the local audit. Add positive
dual-proof and missing-owner-proof vectors plus synthetic/local defensive
validation negatives for stale/revoked writer, cross-persona, wrong RID, wrong
ref, wrong operation, checkpoint/revision substitution, mutation-after-check,
and effect-time revocation.

This new boundary becomes the real evidence for
`CORE-I-NID-DELEGATION-DUAL-PROOF`. A node advertisement proves NID possession
and availability, not repository-owner writer delegation, so its current
contract must stop claiming that invariant.

### 5.6 Boundary-specific semantic vector evidence

Replace the generic “executed result plus static labels” mechanism for every
security-sensitive allocation with an opaque `SemanticBoundaryCertificate`.
Each certificate is minted only by a boundary-specific predicate that examines
the immutable fixture input, exact invoked evaluator identity, raw result, and
the postcondition that corresponds to the claimed invariant/reason. The static
case contract remains the expected allocation; `bindExecutedCase` requires
exact equality between it and the independently minted certificate. Coverage
consumes the certificate, never labels copied directly from the contract.

Verdict-only diagnostic vectors remain permitted, but they do not count toward
a security invariant or security-sensitive reason without a certificate. Add
synthetic/local defensive validation tests proving an unrelated same-verdict
result, swapped invariant label, different boundary, plain certificate clone,
missing certificate, and mutated post-result cannot count.

At minimum, replace and certify these concrete surfaces:

- Workspace `signature-invalid`: sign an otherwise valid closed Workspace
  object, mutate its signature or signed binding, and invoke the real Workspace
  object/repository authenticator rather than `eventsAreByteIdentical`;
- Assurance enrollment backdating/finality and actual dual-signature downgrade;
- Comms claim-active and PoP replay through `VerifiedClaimArtifact` and the
  durable effect fence;
- claim-ledger replay with real current Core writer delegation; and
- Core writer dual-proof acceptance/rejection itself.

As part of this conversion, audit every contract currently carrying a security
invariant. The observed `node-advert-dual-proof-valid` mapping is already known
to overclaim Core writer delegation and must lose that invariant allocation.
The boolean `validateRoleDelegation` cases have no independent current live
contract and do not bind a repository owner, RID, writer NID, ref, operation,
or dual proof. Remove them from the current evaluator graph and vector catalog;
retain their reason allocations only as historical retired semantics, with an
explicit non-wire exclusion and anchor. Do not rebind their role-profile names
to the new repository-writer object. The new Core writer-binding boundary is
the sole current evidence for `CORE-I-NID-DELEGATION-DUAL-PROOF`.

### 5.7 Retired member-KEL quarantine

Remove `validateOrganizationMemberAddition` from the current evaluator graph,
remove the builder and case-contract entry, and let full regeneration remove
`core/org-member-add-unauthorized.json` from the schema-3 snapshot. Do not
manually delete or edit generated vector bytes before Task 9.

Retain the pre-1.0 `org_member_add_unauthorized` registry allocation for audit
continuity, preserve its historical `first_version`, point it to an explicit
Core retired-semantics anchor, and add it to `NON_WIRE_REASON_EXCLUSIONS` with a
justification. The anchor states that the member-KEL organization-add rule is
historical, grants no current Core authority, and is not a Workspace role rule.
Git history remains the source for executing the retired behavior.

Re-specifying it as current Workspace behavior is rejected: Workspace
already owns active-key/policy governance, and importing a member-KEL
prerequisite would violate optional Assurance and family direction. A future
organization-membership proposal can define a new Workspace object and effect
without reactivating this rule.

### 5.8 Snapshot guidance and docs-lint

Rewrite normative Core §13.1 and maintained current guidance so exact mutable
facts come only from `docs/spec/vectors/snapshot.json`:

- the manifest supplies `source_commit`, `vector_schema_version`,
  `vector_count`, artifact paths, and artifact digests;
- `snapshot-check` derives the snapshot commit from the last commit that changed
  the manifest;
- the source root supplies the family that exists at that source commit; and
- current-draft checks and history-bound snapshot checks remain independent.

Do not copy the new source commit, snapshot commit, vector count, or artifact
count into live prose. Such literals become stale immediately and a snapshot
commit in its own source would be self-referential. Update the maintained
README, family map, vector guide, architecture, glossary, threat model,
`AGENTS.md`, and the current/unreleased changelog wording. Preserve explicitly
historical, point-in-time design/review records rather than rewriting history.

Make docs-lint load the committed manifest, validate any intentionally retained
exact statement against it, require maintained guides to identify the manifest
as the exact source, and reject the superseded bootstrap hashes/counts or
unqualified “current 0.5 / five-document / schema-2 / zero executable cases”
language in a curated maintained-file set. The test must not require a mutable
hash literal. Scope changelog lint to assertions presented as current; dated
historical facts can remain historical.

### 5.9 Static graph gap

Repair M1 in this wave. Exact current-source confinement is an explicit Task-10
acceptance surface, and source/snapshot regeneration is already unavoidable.

Recursively visit the TypeScript AST and collect ES imports/re-exports,
import-equals, literal `import()` calls, and CommonJS `require()` calls. Reject
nonliteral import-like arguments. Resolve literal local edges through the same
TypeScript compiler options and retain the current external-library/builtin
handling. Compare the sorted repo-relative transitive graph with an explicit,
reviewable allowlist; a count or path digest may be reported but cannot replace
the paths. Keep the historical-module denylist as defense in depth.

Synthetic/local defensive validation tests cover literal dynamic import,
nonliteral dynamic import, literal and nonliteral `require`, same-count path
substitution, a historical module with an innocent filename,
re-export/import-equals resolution, aliases, and exact allowlist drift.
Implement the traversal tests early, but freeze the final allowlist only after
all repair-source imports have stabilized.

## 6. Artifact impact map

| Surface | Required impact |
|---|---|
| Assurance prose | Define authority-owned ingestion chronology, independent witness policy, exact-head receipt binding, CAS pin close, immutable post-pin boundary, warning-only late evidence, and the real downgrade transition. Resolve the current contradictory “any applicable boundary” language. |
| Core prose | Specify the closed current writer binding and resolver semantics; add the retired member-KEL anchor; make snapshot identity manifest-derived. Preserve bare-key identity and repository-only writer scope. |
| Comms prose | Require verifier-minted claim/revocation artifacts, durable atomic PoP/effect execution, explicit reconciliation, and current Core writer binding before replay/effect. |
| Workspace prose | No new authority semantics are required; only ensure the real signed-object boundary used by evidence matches existing prose. |
| Registry manifest | Increment revision and recompute the entry-set digest after all entry changes. Preserve every existing `first_version`. |
| Object registry | Add the Core repository-writer-binding object. Keep the revised Assurance observation-receipt object registration. |
| Proof-domain registry | Add `accepted_head` to enrollment observation; add the exact dual-suite Core writer-binding domain. Do not change claim PoP or Assurance downgrade domains. |
| Reason registry | Add the Core writer, Comms ledger-writer, PoP replay, and effect-indeterminate decisions; retarget/quarantine the historical member-KEL and role-delegation reasons. Reuse existing downgrade/pin/schema reasons rather than duplicating them. |
| Security invariants / strict profiles | Existing enrollment, pin-downgrade, claim-authenticity, claim-repository, and Core NID dual-proof meanings are already sufficient. Correct their executable/profile evidence rather than weakening descriptions. |
| Protocol schemas | Add `accepted_head` to the receipt; add a closed Core writer-binding schema. The current active-key-acceptance and claim/revocation schemas need runtime enforcement, not redesign. |
| Runtime source | Assurance observation authority/pin transaction and downgrade verifier; Core writer verifier/resolver; claim/revocation artifact layer and claim effect fence; ledger replay resolver; semantic certificates; retired-case removal; complete graph collector. |
| Vector source | Real signed positive/negative builders for every repaired boundary, corrected contracts, removed member-KEL and stale role-delegation cases, corrected node-advert invariant allocation, final exact graph allowlist. |
| Focused tests | Blue-team defensive validation with synthetic/local fixtures for hostile object capture, signatures/proof bytes, authority substitution, replay/CAS/concurrency, effect failure, chronology/finality, writer revocation, certificate misbinding, docs-lint, and graph traversal. |
| Generated vectors/conformance | One complete schema-3 replacement from the stable repair source, updated packaged registry/reason/coverage artifacts, and any conformance fixture expectations derived by Task 9. No manual payload edits. |
| Maintained documentation | Manifest-derived snapshot wording and removal of obsolete current-0.5 identities/counts. Historical point-in-time records remain clearly historical. |

## 7. TDD and integration order

Each numbered item begins with a focused failing defensive validation test
against the reviewed HEAD, using only a synthetic/local fixture, then changes
the smallest coherent prose/registry/schema/runtime/vector-source set until it
is green. Do not use the existing green matrix as proof for a missing boundary.

1. **Lock lifecycle:** keep a focused assertion that ADR-048 is present and
   `Proposed`; no archive/acceptance edit belongs to this wave.
2. **Enrollment chronology/finality RED:** reproduce immediate backdating,
   cross-head and second-authority replay, and exact pin + later immature
   receipt + late contest. Implement the observation authority, receipt/domain
   update, transactional pin, and corrected prose.
3. **Downgrade RED:** show boolean consent cannot authorize and a valid actual
   dual-signature event currently cannot pass. Implement the verifier, opaque
   transition, CAS persistence, and mutation/replay tests.
4. **Core writer-binding RED:** show self-signed NID material without current
   owner/RID/ref/operation authority fails. Add the Core schema, domain, reasons,
   verifier/resolver, strict-profile evidence, and positive/negative tests.
5. **Claim artifact RED:** show bare semantics, fabricated evidence, and cloned
   authority currently authorize. Introduce opaque claim/revocation artifacts
   and migrate chain/replay callers.
6. **PoP/effect RED:** show sequential and concurrent reuse plus terminal-write
   failure. Add the durable acquire/execution fence, new reasons, and exact
   retry/reconciliation behavior.
7. **Ledger replay RED:** use the Core resolver to reject stale/revoked,
   cross-persona, wrong RID/ref/op, and effect-time removed writers before merge
   or use. Migrate all claim-ledger test support; no default “authorized” stub.
8. **Retired semantics RED:** assert the current graph/catalog cannot execute or
   count member-KEL organization addition or boolean role-delegation. Remove
   those cases and quarantine their reasons under explicit retired-semantics
   anchors and non-wire exclusions.
9. **Semantic-certificate RED:** prove same-verdict substitution and invariant
   reassignment do not count. Replace Workspace and every repaired boundary
   fixture with real signed/opaque evidence and correct the Core node-advert
   allocation.
10. **Graph RED:** land recursive-loader unit tests; after all imports settle,
    record and verify the exact repo-relative allowlist.
11. **Snapshot-guidance RED:** replace docs-lint's old-hash requirement with
    manifest-aware maintained-doc checks, then update all maintained current
    prose and the current changelog section.
12. **Source closure:** run focused suites, registry/schema/profile/invariant/
    reason closure, `build:current`, `draft:check`, family checks, docs-lint,
    and `git diff --check`. Review the complete source diff and commit one stable
    repair source commit **without editing `snapshot.json`**.
13. **Full Task-9 regeneration:** author the entire rolling snapshot from that
    exact source commit, review the replacement, and commit it as the snapshot
    commit. Never edit a generated vector, manifest count, coverage projection,
    or digest manually.
14. **Read-only verification and re-review:** run `snapshot-check`, both package
    builds/tests, `scripts/conformance-ci.sh`, the complete Task-10 matrix, clean
    status/index/hidden-file audits, and new independent specification and
    security reviews over the full repaired range.

This design's implementation lifecycle stops there. ADR-048 remains `Proposed`.
Only a later lifecycle step, after zero Critical/Important findings on the
exact regenerated candidate, may perform the separate acceptance/archive
commit described by the Task-10 brief.

## 8. Final decisions and implementation concerns

### Final decisions

1. **Witness portability:** raw receipts do not carry portable elapsed-time
   authority into a verifier that did not durably ingest the start. Immediate
   late-verifier portability is outside this repair and cannot be inferred from
   signed timestamps.
2. **Core writer artifact:** the already normative Core writer rule is closed
   with the registered authority-file object and proof domain in section 5.5.
   An embedding-only opaque resolver is rejected because it leaves the exact
   “same binding” proof bytes non-interoperable.
3. **Retired member-KEL semantics:** remove and quarantine the stale current
   case; do not re-specify it as Workspace authority.
4. **Static graph gap:** repair M1 in this wave with recursive import-like
   traversal and an exact reviewed allowlist; do not defer it.

The member-KEL quarantine and M1 repair do not need new protocol semantics:
quarantine follows the existing retired-reason mechanism, and the graph change
only makes the claimed acceptance control exact.

### Concerns to carry into implementation review

- The current catalog overclaims `CORE-I-NID-DELEGATION-DUAL-PROOF`: node
  advertisement proves availability/NID possession, while the two stale role-
  delegation cases consume booleans and have no exact writer object.
  Implementation must remove those allocations/cases and count only the new
  Core writer-binding boundary as current evidence.
- Process-local conformance stores can prove state-machine semantics but cannot
  prove production crash durability. Prose and host interfaces must make the
  durability obligation explicit and tests must exercise injected CAS and
  terminal-persistence failures.
- Post-pin evidence still needs cryptographic authentication for warnings, but
  invalid or late evidence must never turn a valid retained pin into a reject or
  contested replacement. State disposition and audit disposition should be
  separate outputs.
- The new writer binding must be checked at replay/effect time as the live Comms
  text says, even though that means removing a writer can make its historical
  records non-authoritative in a freshly replayed current view. Using record
  `created_at` instead would be a normative change.
- Docs-lint must distinguish maintained current assertions from historical
  records. Rewriting archived design/review material would destroy provenance;
  ignoring unqualified current claims would preserve the defect.
- The source commit must be genuinely stable before Task 9. Any post-source
  tweak to prose, registries, schemas, evaluator code, vector builders, tests,
  allowlist, or docs-lint invalidates the snapshot source pin and requires a new
  full regeneration.
