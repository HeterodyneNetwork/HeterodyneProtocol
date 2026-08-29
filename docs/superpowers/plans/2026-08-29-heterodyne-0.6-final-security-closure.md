# Heterodyne 0.6 Final Security Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every Critical and Important Task-10 review finding with verifier-minted authority artifacts, durable state transitions, semantically grounded current vectors, exact current-source confinement, and one regenerated schema-3 snapshot while keeping ADR-048 Proposed.

**Architecture:** Repair the common trust-boundary error at four layers: capture hostile input once, mint an opaque verified artifact, consume it through a durable CAS/effect fence, and return only terminal or explicit reconciliation state. Stabilize all live prose, registry, schema, runtime, tests, and current-vector source in one source commit before regenerating the complete rolling snapshot from that exact commit. Hostile-boundary coverage is strictly local, deterministic blue-team defensive validation for protocol quality; it never targets a real system.

**Tech Stack:** TypeScript 5.9, Vitest 4, AJV/draft-07 JSON Schema, `@noble/curves` BIP-340 and Ed25519, JCS, CommonMark docs lint, TypeScript compiler AST/module resolution, the rolling-snapshot orchestrator, and the TypeScript conformance package.

**Spec:** `docs/superpowers/specs/2026-08-29-heterodyne-0.6-final-security-closure-design.md`

## Global Constraints

- Execute in `.worktrees/pr28-protocol-closure` on top of approved-design commit `4e893b3b136c541956a4ef68fb324bd65bda1034`; preserve unrelated and untracked files.
- Keep `docs/adr/2026-08-26-048-security-review-remediation.md` live and `Proposed` through every task in this plan. Do not accept, archive, merge, tag, release, or deploy.
- A bare active Nostr key remains a complete Core identity. Do not add mandatory KEL, cold-root, Assurance, directory, external chronology, or Heterodyne-specific relay dependencies.
- Receipt and NIP-01 timestamps are audit assertions only. Enrollment elapsed time comes exclusively from an authority-owned trusted monotonic clock and durable ingestion journal.
- New authority-bearing public values are frozen empty objects backed by module-private `WeakMap` state. Clones, accessors, proxies, cross-authority artifacts, and post-verification mutation fail closed.
- Reference stores may be deterministic process-local test implementations, but normative prose and host interfaces require durability across restart and competing workers.
- Preserve every existing registry `first_version`. New 0.6 entries use `heterodyne/0.6.0`. Task 9 applies all registry edits together and authors revision `16` exactly once.
- Do not hand-edit `docs/spec/vectors/snapshot.json`, generated vector JSON, packaged schema/reason/coverage projections, conformance baselines, reports, or debt artifacts. Task 14 regenerates the entire snapshot from the exact source commit.
- Every hostile-boundary test name and comment must say `BLUE TEAM VALIDATION` and use only deterministic synthetic/local fixtures. It must not contact a relay, node, identity provider, account, deployment, credential, third-party service, or user data, and must not create reusable exploit, scanning, persistence, evasion, destructive, or control-weakening functionality.
- Every task uses strict TDD: add the named focused RED, run it and record the expected failure, make the smallest coherent change, run focused GREEN, inspect the diff, obtain spec-compliance and code-quality reviews, then commit.
- Assign one fresh implementation subagent per task with ownership of only the listed files. Tell every worker they are not alone in the codebase, must preserve others' edits, and must not change generated snapshot artifacts before Task 14.
- A task may not weaken an invariant, reinterpret an existing proof domain, or add a network trust service to make a test pass. Stop and return to the approved design if that would be required.

## File and Responsibility Map

- `assurance.ts` and new `assurance-observation.ts`: immutable Assurance event verification, durable observation chronology, absorbing pins, and warning-only post-pin evidence.
- `assurance-policy.ts` and new `assurance-downgrade.ts`: pin/head selection, real dual-signature downgrade verification, and terminal pin transition.
- New `core-writer-binding.ts`: exact dual-proof repository-writer object verification and opaque current-policy authority.
- `claims.ts` and new `claim-authorization.ts`: opaque verified claim/revocation artifacts, chain inspection, proof consumption, effect fencing, and reconciliation.
- `claim-ledger.ts`: current Core writer authorization at replay and effect time; no default authorized stub.
- New `current-vectors/semantic-certificates.ts`: boundary-specific opaque vector evidence independent of static case labels.
- `current-import-graph.ts` and new `current-module-allowlist.ts`: recursive import-like traversal plus exact reviewed current graph.
- `docs-lint.ts`: manifest-derived maintained-document checks and lifecycle guard.
- `registry/*.json`, `schemas/**/*.json`, and live specification prose: complete normative contract; no ADR authority.
- Current-vector builders/contracts/runners: real signed fixtures, new authority boundaries, retired-case removal, and security-coverage closure.
- Task 14 alone owns generated vector, coverage, manifest, baseline, report, and debt replacement.

---

### Task 1: Lock lifecycle and blue-team validation policy

**Files:**
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `.superpowers/sdd/2026-08-27-heterodyne-0.6-pr28-closure/progress.md` (ignored execution ledger)

**Interfaces:**
- Consumes: the approved design status and ADR-048 live path.
- Produces: the focused ADR lifecycle assertion plus
  `lintDefensiveValidationText(text, path): DocsLintIssue[]`, reused by each
  new blue-team boundary-test review.

- [ ] **Step 1: Add lifecycle and validation-scope RED tests**

Add exact tests that expect the live ADR path, `Status: Proposed`, no archived copy, and reject an implementation brief that labels a hostile fixture without the required defensive scope:

```ts
it("keeps ADR-048 Proposed until exact repaired-candidate reviews pass", () => {
  expect(existsSync(resolve(root, "docs/adr/2026-08-26-048-security-review-remediation.md"))).toBe(true);
  expect(existsSync(resolve(root, "docs/adr/archive/2026-08-26-048-security-review-remediation.md"))).toBe(false);
  expect(read("docs/adr/2026-08-26-048-security-review-remediation.md"))
    .toMatch(/\*\*Status:\*\* Proposed/);
});

it("requires hostile-boundary fixtures to declare BLUE TEAM VALIDATION", () => {
  const issues = lintDefensiveValidationText(
    "hostile accessor mutation reaches the authority boundary",
    "synthetic-boundary.test.ts",
  );
  expect(issues.map(({ code }) => code)).toContain("defensive-validation-scope");
  expect(lintDefensiveValidationText(
    "BLUE TEAM VALIDATION: synthetic/local accessor mutation must fail closed",
    "synthetic-boundary.test.ts",
  )).toEqual([]);
});
```

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: lifecycle assertion passes; defensive-scope assertion fails because `lintDefensiveValidationText` does not exist.

- [ ] **Step 3: Add the narrow lint helper and ledger ruling**

Implement a literal, non-NLP helper used only for new test/brief prose:

```ts
export function lintDefensiveValidationText(text: string, path: string): DocsLintIssue[] {
  const hostile = /\b(hostile|adversarial|attacker|attack)\b/iu.test(text);
  const defensive = /\bBLUE TEAM VALIDATION\b/u.test(text)
    && /\b(synthetic|local)\b/iu.test(text);
  return hostile && !defensive ? [{
    path,
    line: 1,
    code: "defensive-validation-scope",
    message: "hostile-boundary validation must be framed as synthetic/local BLUE TEAM VALIDATION",
  }] : [];
}
```

Append a `Ruling:` ledger entry that quotes the scope constraint and prohibits live-target validation.

- [ ] **Step 4: Run focused GREEN and diff audit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: PASS, and `git diff -- docs/adr docs/spec/vectors/snapshot.json` is empty.

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/docs-lint.ts docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "test: lock final security closure lifecycle"
```

---

### Task 2: Make enrollment chronology authority-owned and pins absorbing

**Files:**
- Create: `docs/spec/vectors/generator/src/assurance-observation.ts`
- Create: `docs/spec/vectors/generator/src/assurance-observation.test.ts`
- Modify: `docs/spec/vectors/generator/src/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/assurance.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/profile-oracles.ts`
- Modify: `docs/spec/schemas/assurance/enrollment-observation-receipt-v1.schema.json`
- Modify: `docs/spec/heterodyne-assurance.md`
- Modify: `docs/security/threat-model.md`

**Interfaces:**
- Produces: `createAssuranceEnrollmentObservationAuthority(config)` and the
  repaired `evaluateEnrollmentEligibility(authority, { inception,
  acceptance, evidence })` boundary;
  evidence ingestion occurs inside that authority call before eligibility is
  evaluated.
- Produces opaque `EnrollmentObservationAuthority`; consumes exact verified inception/acceptance pairs from `assurance.ts`.
- Produces a committed `AssuranceEnrollmentAuthoritativePin` with closed `eligibility_basis` and warnings separate from state.

- [ ] **Step 1: Write chronology/finality RED matrix**

Use a heading and comments beginning `BLUE TEAM VALIDATION: synthetic/local`. Cover immediate backdating, candidate-selected witness trust, wrong `accepted_head`, receipt replay, second-authority replay, duplicate witness weight, nonmonotonic receipt update, policy substitution, pre-pin CAS race, absorbing pre-pin contest, retained pin plus late immature receipt/contest, and pin-provenance mutation.

Define the test journal explicitly:

```ts
type EnrollmentObservationJournal = {
  load(key: string): EnrollmentObservationJournalEntry | null;
  compareAndSwap(
    key: string,
    expectedRevision: number | null,
    next: EnrollmentObservationJournalEntry,
  ): "committed" | "conflict";
};
```

Assert that two authorities ingesting the same signed historical receipts get different local starts and neither is immediately eligible.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/assurance-observation.test.ts src/assurance.test.ts`

Expected: backdated and post-pin cases expose the reviewed failures; the new authority symbols are absent.

- [ ] **Step 3: Add exact-head wire closure**

Add required `accepted_head` to the JSON Schema and to `EnrollmentObservationReceipt`. Task 9 will change the proof-domain members to this exact order:

```json
["profile","spec_version","inception_event_id","active_key","cold_root",
 "accepted_head","first_observed_at","last_observed_at","conflict_free","witness_key"]
```

Keep signed times as audit members; do not use them as an authoritative elapsed-time start.

- [ ] **Step 4: Implement opaque authority and durable CAS journal**

Use these closed interfaces:

```ts
export type EnrollmentWitnessPolicy = Readonly<{
  policy_digest: string;
  minimum_weight: number;
  witnesses: ReadonlyMap<string, number>;
}>;

export type EnrollmentObservationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  witness_policy: EnrollmentWitnessPolicy;
  journal: EnrollmentObservationJournal;
}>;

export type EnrollmentEvidenceInput = Readonly<{
  witness_receipts: readonly EnrollmentObservationReceipt[];
  contests: readonly NostrSignedEvent[];
  competing_enrollments: readonly Readonly<{
    inception: NostrSignedEvent;
    acceptance: NostrSignedEvent;
  }>[];
}>;

export function createAssuranceEnrollmentObservationAuthority(
  config: EnrollmentObservationAuthorityConfig,
): AssuranceEnrollmentObservationAuthority;

export function evaluateEnrollmentEligibility(
  authority: AssuranceEnrollmentObservationAuthority,
  input: Readonly<{
    inception: NostrSignedEvent;
    acceptance: NostrSignedEvent;
    evidence: EnrollmentEvidenceInput;
  }>,
): Promise<AssuranceEnrollmentEligibility | AssuranceVerdict<never>>;
```

Capture callback descriptors once, reject proxies/accessors, snapshot every callback result, key journal state by `(active_key,inception_event_id,cold_root,accepted_head)`, deduplicate evidence digests, and compute maturity only from authority-owned first/latest ingestion times. Commit the complete eligibility basis and pin in one CAS.

- [ ] **Step 5: Make exact pins absorbing**

Order evaluation as: validate retained pin+basis, authenticate/journal new evidence, return retained `verified`, then attach warning-only late contests. A nonmatching pin returns `assurance-pin-conflict`; a pre-pin contest remains terminal contested.

- [ ] **Step 6: Update normative text**

In Assurance enrollment/pinning sections, specify nonportable authority chronology, independent witness policy, two distinct receipts over `W`, CAS close, complete pin provenance, and warning-only post-pin evidence. In the threat model, describe backdating and cross-authority replay as fail-closed blue-team validation surfaces, not operational attack instructions.

- [ ] **Step 7: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/assurance-observation.test.ts src/assurance.test.ts src/schema.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Expected: all focused cases pass; schema requires `accepted_head`; no generated snapshot files change.

Commit: `git commit -m "fix: make Assurance enrollment chronology authoritative"`

---

### Task 3: Replace boolean downgrade with real dual-signature transition

**Files:**
- Create: `docs/spec/vectors/generator/src/assurance-downgrade.ts`
- Create: `docs/spec/vectors/generator/src/assurance-downgrade.test.ts`
- Modify: `docs/spec/vectors/generator/src/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/assurance-policy.ts`
- Modify: `docs/spec/vectors/generator/src/assurance-policy.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/heterodyne-assurance.md`

**Interfaces:**
- Consumes: immutable retained pin/basis from Task 2 and existing `heterodyne-assurance-downgrade-v1` proof bytes.
- Produces: `evaluateAssuranceDowngrade(retainedPin, sourceEvent): AssuranceVerdict<VerifiedAssuranceDowngrade>` and `commitAssuranceDowngrade(artifact)`.

- [ ] **Step 1: Write real-signature RED tests**

Add `BLUE TEAM VALIDATION: synthetic/local` cases for a valid active-key-signed kind `31000` downgrade plus recovery proof, boolean lookalikes, missing proof, wrong recovery key, wrong active signer, byte mutation, wrong inception/head/predecessor, artifact clone, source mutation after verification, replay, and terminal CAS conflict.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/assurance-downgrade.test.ts src/assurance-policy.test.ts`

Expected: boolean consent currently accepts; actual signed event has no dedicated accepting boundary.

- [ ] **Step 3: Implement verified downgrade artifact**

Define:

```ts
export type VerifiedAssuranceDowngrade = Readonly<{
  readonly __verifiedAssuranceDowngrade: unique symbol;
}>;

export function evaluateAssuranceDowngrade(
  retainedPin: AssuranceEnrollmentAuthoritativePin,
  sourceEvent: unknown,
): AssuranceVerdict<VerifiedAssuranceDowngrade>;
```

Keep the brand only in a private `WeakMap`. Verify the outer NIP-01 event once, closed canonical content/tags, `state:"downgraded"`, exact inception/head/predecessor, and recovery signature over the existing five-member domain. Store an immutable source snapshot and binding digest privately.

Extend the private `ActiveKeyAcceptance` model to include the schema's
conditional `downgrade_consent`; do not add a second active-key proof because
the outer NIP-01 signature is that consent.

- [ ] **Step 4: Add CAS terminal transition and simplify pin policy**

`commitAssuranceDowngrade` accepts only the branded artifact, whose private
record retains the originating journal identity, and CASes exact retained
revision/head to terminal downgraded state. Exact completed retry returns
cached state; mismatched input rejects. Remove `downgrade.active_key_consent`
and `recovery_authority_proof` from `evaluateAssurancePinPolicy`; that function
handles pin/head/duplicity only.

- [ ] **Step 5: Update prose, verify, review, and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/assurance-downgrade.test.ts src/assurance-policy.test.ts src/assurance.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Expected: dual-signature acceptance passes; every boolean/clone/mutation/replay case fails closed.

Commit: `git commit -m "fix: verify dual-signature Assurance downgrade"`

---

### Task 4: Register and verify current Core repository-writer bindings

**Files:**
- Create: `docs/spec/schemas/core/repository-writer-binding-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/core-writer-binding.ts`
- Create: `docs/spec/vectors/generator/src/core-writer-binding.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/core-policy.ts`
- Modify: `docs/spec/heterodyne-core.md`

**Interfaces:**
- Produces closed `RepositoryWriterBindingV1`, opaque `CoreRepositoryWriterAuthority`, and opaque `CurrentRepositoryWriterBinding`.
- Produces `resolveCurrentRepositoryWriterBinding(authority, object, request)` and `revalidateCurrentRepositoryWriterBinding(authority, binding)` for Task 7.

- [ ] **Step 1: Write schema and dual-proof RED tests**

Create valid fixed-key fixtures and `BLUE TEAM VALIDATION: synthetic/local` mutations for missing owner proof, missing NID proof, wrong owner, cross-persona RID, wrong ref namespace, wrong operation, expiry, policy revision/checkpoint substitution, revoked/conflicted policy, clone, proxy/accessor, and mutation after verification.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/core-writer-binding.test.ts src/schema.test.ts`

Expected: schema/object/domain/reason and verifier are absent.

- [ ] **Step 3: Add exact closed wire object**

Use this body and signatures, with `additionalProperties:false` at every object:

```ts
export type RepositoryWriterBindingV1 = Readonly<{
  profile: "heterodyne.core.repository-writer-binding.v1";
  spec_version: "heterodyne/0.6.0";
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  ref_namespace: string;
  operations: readonly string[];
  issued_at: number;
  expires_at: number;
  owner_signature: string;
  nid_signature: string;
}>;
```

Both signatures cover the same unsigned closed body under `heterodyne-core-repository-writer-binding-v1`. Require canonical sorted unique operations and `expires_at > issued_at`.

- [ ] **Step 4: Implement opaque current-policy authority**

```ts
export type CoreRepositoryWriterAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  load_current_policy: (repositoryRid: string) => CurrentRepositoryPolicy;
}>;

export type RepositoryWriterRequest = Readonly<{
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  writer_ref: string;
  operation: "claim-ledger-write";
}>;
```

Snapshot callback/result descriptors, validate both signatures and NID derivation, then require exact owner/RID/ref/op plus active policy inclusion/revision/checkpoint. Private state retains binding and policy fingerprints.

- [ ] **Step 5: Specify the normative Core boundary**

Update Core prose to define object `heterodyne.core.repository-writer-binding.v1`, proof domain `heterodyne-core-repository-writer-binding-v1`, failure `repository-writer-binding-invalid`, repository-only scope, current policy resolution, and no authorship/Workspace/decryption/Assurance authority. Task 9 performs the matching registry allocations in one digest-consistent revision.

- [ ] **Step 6: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/core-writer-binding.test.ts src/core-policy.test.ts src/schema.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "feat: verify current Core repository writers"`

---

### Task 5: Mint opaque verified claim and revocation artifacts

**Files:**
- Modify: `docs/spec/vectors/generator/src/claims.ts`
- Modify: `docs/spec/vectors/generator/src/claims.test.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger-test-support.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/comms.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/revocation-profile-boundary.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/revocation-profile-fixtures.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/profiles.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces: `verifyClaimEnvelope(event, context): VerifiedClaimArtifact`, `verifyClaimRevocationEnvelope(event): VerifiedClaimRevocationArtifact`, `inspectVerifiedClaim(artifact): ClaimSemanticBody`, and `verifyClaimChain(leaf, artifactsById): VerifiedClaimArtifact[]`.
- Consumed by: Task 6 authorization authority, Task 7 ledger replay, and Task 10 semantic certificates.

- [ ] **Step 1: Write artifact-forgery RED tests**

Add `BLUE TEAM VALIDATION: synthetic/local` cases for bare semantics, public `issuer_authorized`/`envelope_valid`, cloned evidence, substituted event ID, changed raw bytes, proxy/accessor source, artifact lookalike, revocation lookalike, and semantic/event mismatch in ledger-embedded artifacts.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/claims.test.ts`

Expected: shaped `ClaimAuthorityEvidence` can authorize and `validateClaimEnvelope` returns reusable plain semantics.

- [ ] **Step 3: Replace public semantic authority with private records**

Define empty opaque types and private records:

```ts
export type VerifiedClaimArtifact = Readonly<{ readonly __verifiedClaim: unique symbol }>;
export type VerifiedClaimRevocationArtifact = Readonly<{ readonly __verifiedRevocation: unique symbol }>;

type VerifiedClaimRecord = Readonly<{
  event: VerifiedNostrEvent;
  nip01_raw: string;
  semantic: ClaimSemanticBody;
  claim_id: string;
  issuer_pubkey: string;
  event_id: string;
  chain_binding_digest: string;
}>;
```

Snapshot/verify event once, require outer pubkey equals typed issuer, validate canonical semantic bytes and credential-ledger binding, then mint. `inspectVerifiedClaim` returns a deep clone; no authority API accepts that clone.

- [ ] **Step 4: Migrate chain and revocation resolution**

Change chain inputs to opaque artifacts and read only private snapshots. Verify ledger duplicate semantics byte-equal the event content before minting. Remove `issuer_authorized`, `envelope_valid`, `ClaimAuthorityEvidence`, and `RevocationAuthorityEvidence` from public authorization inputs.

- [ ] **Step 5: Correct reason/prose and run GREEN**

Update Comms claim verification prose so `claim-issuer-authority-invalid` means exact verified outer issuer or explicit chain authority without KEL substitution. Task 9 changes the registry description while preserving its `first_version`.

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/claims.test.ts src/claim-ledger-remediation.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: mint opaque verified claim artifacts"`

---

### Task 6: Make claim proof use and effects atomic

**Files:**
- Create: `docs/spec/vectors/generator/src/claim-authorization.ts`
- Create: `docs/spec/vectors/generator/src/claim-authorization.test.ts`
- Modify: `docs/spec/vectors/generator/src/claims.ts`
- Modify: `docs/spec/vectors/generator/src/claims.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/comms.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Consumes: Task 5 opaque artifacts.
- Produces opaque `ClaimAuthorizationAuthority`, `inspectClaimState`, and `authorizeClaimEffect` with durable proof/effect terminal state.

- [ ] **Step 1: Write replay/effect RED matrix**

Add `BLUE TEAM VALIDATION: synthetic/local` cases for sequential reuse, simultaneous acquire, altered audience/resource/op/nonce, different chain digest, wrong authority instance, CAS conflict, effect throw, timeout/unknown result, successful effect plus terminal-write failure, exact committed retry, exact indeterminate retry, mismatched retry, and repository/revocation change after prepare.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/claim-authorization.test.ts`

Expected: caller-owned `used_nonces` is non-consuming and competing calls can both return allowed.

- [ ] **Step 3: Add durable store contract**

```ts
export type ClaimEffectRecord = Readonly<{
  state: "executing" | "committed" | "indeterminate";
  binding_digest: string;
  execution_token: string;
  result_digest?: string;
  reconciliation_digest?: string;
  cached_result?: unknown;
}>;

export type CurrentClaimAuthorizationView = Readonly<{
  credential_ledger: CredentialLedgerBinding;
  checkpoint_digest: string;
  repository_revision: number;
  claims: readonly VerifiedClaimArtifact[];
  revocations: readonly VerifiedClaimRevocationArtifact[];
  conflicted_claim_ids: readonly string[];
}>;

export type ClaimEffectStore = Readonly<{
  load(singleUseKey: string): ClaimEffectRecord | null;
  acquire(singleUseKey: string, bindingDigest: string, executionToken: string):
    "acquired" | "replay" | "conflict";
  commit(executionToken: string, resultDigest: string, cachedResult: unknown):
    "committed" | "conflict";
  markIndeterminate(executionToken: string, reconciliationDigest: string):
    "indeterminate" | "conflict";
}>;

export type ClaimAuthorizationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  trusted_issuers: readonly KeyRef[];
  load_current_view: () => CurrentClaimAuthorizationView;
  store: ClaimEffectStore;
}>;

export function createClaimAuthorizationAuthority(
  config: ClaimAuthorizationAuthorityConfig,
): ClaimAuthorizationAuthority;
```

The authority config owns trusted clock, trusted issuers, current ledger/revocation loader, request binding, and store. Derive the single-use key from exactly `(issuer,subject,claim_id,audience,resource,operation,nonce)` and the acquired binding from complete chain/proof/checkpoint/request/effect/authority/idempotency digests.

- [ ] **Step 4: Implement acquire-before-effect and terminal handling**

Reload current state immediately before acquire, transition `unused -> executing`, then invoke the idempotent effect. Commit a cached result or mark indeterminate. Never reopen after acquisition. Exact retries return cached committed/indeterminate state; substitutions return replay/conflict.

- [ ] **Step 5: Specify reasons and update prose**

Specify `claim-subject-proof-replayed` and `claim-authorization-effect-indeterminate`; Task 9 allocates them with new 0.6 `first_version`. Keep invalid signatures under `claim-subject-proof-invalid`. State the production durability/across-worker obligation in Comms.

- [ ] **Step 6: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/claim-authorization.test.ts src/claims.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: fence claim proof use and effects"`

---

### Task 7: Enforce current writer authority in claim-ledger replay and effects

**Files:**
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.test.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger-conformance.test.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger-remediation.test.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger-test-support.ts`
- Modify: `docs/spec/vectors/generator/src/claim-authorization.ts`
- Modify: `docs/spec/vectors/generator/src/claim-authorization.test.ts`
- Modify: `docs/spec/vectors/generator/src/authorization-freshness.ts`
- Modify: `docs/spec/vectors/generator/src/authorization-freshness.test.ts`
- Modify: `docs/spec/vectors/generator/src/authorization-freshness-test-support.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.test.ts`
- Modify: `docs/spec/vectors/generator/src/oidc-test-support.ts`
- Modify: `docs/spec/vectors/generator/src/token-status.test.ts`
- Modify: `docs/spec/vectors/generator/src/control-profile.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/comms.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/revocation-profile-boundary.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/revocation-profile-fixtures.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Consumes: `CoreRepositoryWriterAuthority`/`CurrentRepositoryWriterBinding` from Task 4 and opaque claim artifacts from Task 5.
- Produces: replay results privately bound to exact writer authority fingerprints and an effect-time `revalidateLedgerWriterAuthorities` boundary consumed by Task 6 loaders.

- [ ] **Step 1: Write writer-replay RED tests**

Add positive dual-proof replay and `BLUE TEAM VALIDATION: synthetic/local` negatives for self-signed writer without owner proof, stale/revoked/conflicted writer, cross-persona, wrong RID/ref/op, wrong commit/checkpoint/revision, mutation after resolution, and writer removal between prepare and effect.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/claim-ledger.test.ts src/claim-ledger-conformance.test.ts src/claim-ledger-remediation.test.ts`

Expected: a self-signed record with repository evidence passes without current Core owner delegation.

- [ ] **Step 3: Extend exact record-location evidence**

Add closed location evidence to the replay context rather than caller booleans:

```ts
export type LedgerRecordLocation = Readonly<{
  record_id: string;
  repository_rid: string;
  writer_ref: string;
  commit: string;
  checkpoint: string;
  revision: number;
  writer_binding: RepositoryWriterBindingV1;
}>;
```

Require location and artifact byte equality before authority resolution. Do not use `record.created_at` as current delegation evidence.

- [ ] **Step 4: Resolve before replay and revalidate before effect**

For each distinct writer, require exact persona/RID/ref/`claim-ledger-write`, record writer NID, current policy inclusion, checkpoint, and existing Ed25519 record signature. Store only private fingerprints in `LedgerMergeResult`. Expose a revalidation function that reloads every distinct current binding immediately before Task 6's effect acquire.

```ts
export function revalidateLedgerWriterAuthorities(
  state: LedgerMergeResult,
):
  | { verdict: "accept"; writer_fingerprints: readonly string[] }
  | { verdict: "reject"; reason_code: "claim-ledger-writer-unauthorized" };
```

- [ ] **Step 5: Add coarse boundary reason and prose**

Specify `claim-ledger-writer-unauthorized`; Task 9 allocates it with new 0.6 `first_version`. Translate Core detail to that reason at Comms boundary while retaining local audit detail. Update Comms replay/effect text.

- [ ] **Step 6: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/core-writer-binding.test.ts src/claim-ledger.test.ts src/claim-ledger-conformance.test.ts src/claim-ledger-remediation.test.ts src/claim-authorization.test.ts src/authorization-freshness.test.ts src/oidc.test.ts src/token-status.test.ts src/control-profile.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: authorize claim-ledger writers at replay"`

---

### Task 8: Quarantine retired member-KEL and boolean delegation semantics

**Files:**
- Modify: `docs/spec/vectors/generator/src/core-policy.ts`
- Modify: `docs/spec/vectors/generator/src/core-policy.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/core.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`
- Modify: `docs/spec/heterodyne-core.md`

**Interfaces:**
- Produces: no current callable `validateOrganizationMemberAddition` or `validateRoleDelegation`; retained reasons are explicit non-wire exclusions.
- Consumed by: Task 9 registry closure and Task 10 certificate closure.

- [ ] **Step 1: Write current-graph/catalog RED tests**

Assert the current compiler graph, boundary IDs, case IDs, and semantic coverage contain none of `validateOrganizationMemberAddition`, `org-member-add-unauthorized`, `validateRoleDelegation`, or boolean role-delegation cases. Assert `org_member_add_unauthorized` and the exact retired role reasons occur only in the explicit non-wire exclusion table.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/core-policy.test.ts src/current-vectors.test.ts src/coverage.test.ts`

Expected: current member-KEL and boolean delegation cases are still executable/countable.

- [ ] **Step 3: Remove current implementations and cases**

Delete only the live exports, builders, runners, contracts, and security allocations. Do not delete generated snapshot JSON. Remove `CORE-I-NID-DELEGATION-DUAL-PROOF` from node-advert and role-delegation contracts; Task 10 will bind it only to the real writer proof.

- [ ] **Step 4: Add retired-semantics anchor and exact exclusions**

Add `#core-retired-member-kel-and-role-delegation` stating these pre-1.0 rules grant no current authority and are not Workspace roles. Add sorted, per-reason justifications to `NON_WIRE_REASON_EXCLUSIONS`. Task 9 retargets the retained registry refs while preserving old `first_version`.

- [ ] **Step 5: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/core-policy.test.ts src/current-vectors.test.ts src/coverage.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: quarantine retired Core delegation semantics"`

---

### Task 9: Allocate registry revision 16 once

**Files:**
- Modify: `docs/spec/registry/objects.json`
- Modify: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`

**Interfaces:**
- Consumes: the complete object/domain/reason semantics from Tasks 2-8.
- Produces: one digest-consistent immutable registry revision `16` used by every current-vector and source-closure test.

- [ ] **Step 1: Write exact registry RED assertions**

Require revision `16`, the Core repository-writer object/domain/reason,
Comms ledger-writer/replay/indeterminate reasons, `accepted_head` in the
Assurance observation domain, the corrected claim-issuer description, and
retired member-KEL/role refs. Assert every existing entry retains the exact
`first_version` from revision 15 and only new entries use
`heterodyne/0.6.0`.

- [ ] **Step 2: Run focused RED before changing the registry**

Run: `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts`

Expected: revision/allocation assertions fail against revision 15.

- [ ] **Step 3: Apply the complete registry entry-set edit**

Use these exact new allocations:

```json
{
  "object": "heterodyne.core.repository-writer-binding.v1",
  "domain": "heterodyne-core-repository-writer-binding-v1",
  "core_reason": "repository-writer-binding-invalid",
  "comms_reasons": [
    "claim-ledger-writer-unauthorized",
    "claim-subject-proof-replayed",
    "claim-authorization-effect-indeterminate"
  ]
}
```

Add `accepted_head` to the existing observation domain in the order fixed by
Task 2. Retarget retired reasons to
`heterodyne:0.6.0#core-retired-member-kel-and-role-delegation`. Do not change
the claim PoP or Assurance downgrade domains and do not change any historical
`first_version`.

Register the writer object with owner `core`, carrier
`radicle-authority-file`, schema
`schemas/core/repository-writer-binding-v1.schema.json`, and new 0.6
`first_version`. Register the writer proof domain with suites
`["bip340","ed25519"]` and these exact unsigned members:

```json
["profile","spec_version","owner_active_key","repository_rid","writer_nid",
 "ref_namespace","operations","issued_at","expires_at"]
```

Use `heterodyne:0.6.0#core-nid-delegation` for the Core object/domain/reason,
`heterodyne:0.6.0#comms-claim-ledger` for the coarse writer failure, and
`heterodyne:0.6.0#comms-claim-verification` for proof replay and indeterminate
effect reconciliation.

- [ ] **Step 4: Author revision 16 exactly once**

Run: `npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 16`

Expected: `manifest.json` reports revision `16` and its digest equals a fresh
`computeRegistryDigest` over the final entry set.

- [ ] **Step 5: Run registry/schema/current GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts src/core-writer-binding.test.ts src/claims.test.ts src/claim-authorization.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "spec: allocate final 0.6 authority registry"`

---

### Task 10: Bind current-vector coverage to boundary-specific certificates

**Files:**
- Create: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.ts`
- Create: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/index.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/types.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/{core,assurance,comms,workspace}.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/profile-oracles.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/profiles.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`
- Modify: `docs/spec/vectors/generator/src/workspace-policy.ts`
- Modify: `docs/spec/vectors/generator/src/workspace-policy.test.ts`

**Interfaces:**
- Consumes: Tasks 2-9 authority artifacts, evaluators, and final registry entries.
- Produces opaque `SemanticBoundaryCertificate` and `certifyBoundaryExecution(contract, fixture, execution)`; `bindExecutedCase` and `buildSemanticCoverage` consume the certificate.

- [ ] **Step 1: Write certificate-forgery RED tests**

Add `BLUE TEAM VALIDATION: synthetic/local` cases for same-verdict/unrelated result, swapped invariant, swapped reason, different evaluator identity, plain certificate clone, missing certificate, result mutation, and static labels copied without a verified postcondition.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/current-vectors/semantic-certificates.test.ts src/current-vectors.test.ts src/coverage.test.ts`

Expected: `semanticEvidenceForCase` returns contract labels even where raw results do not prove them.

- [ ] **Step 3: Implement private certificate records**

```ts
export type SemanticBoundaryCertificate = Readonly<{
  readonly __semanticBoundaryCertificate: unique symbol;
}>;

type SemanticCertificateRecord = Readonly<{
  vector_id: string;
  boundary_id: string;
  fixture_digest: string;
  result_digest: string;
  verdict: "accept" | "reject" | "indeterminate";
  invariants: readonly string[];
  reasons: readonly string[];
  postcondition: string;
}>;
```

Mint only from a closed predicate registered to the exact boundary ID. `bindExecutedCase` requires equality between static contract and independently minted record; coverage reads only the record.

- [ ] **Step 4: Replace minimum security-sensitive fixtures**

Use real signed Workspace objects for `workspace_signature_invalid`; Task 2 chronology/pin state; Task 3 downgrade; Task 5/6 claim-active and PoP replay; Task 7 ledger writer replay; and Task 4 Core writer dual-proof. No string-equality or caller boolean may certify a security invariant.

- [ ] **Step 5: Audit every security-invariant contract**

Generate a table in the test from all current contracts and require every nonempty security invariant to have a boundary-specific predicate. Bind `CORE-I-NID-DELEGATION-DUAL-PROOF` only to Task 4 writer cases. Use `currentCaseIds().length` for current-source counts instead of a copied numeric constant.

- [ ] **Step 6: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/current-vectors/semantic-certificates.test.ts src/current-vectors.test.ts src/coverage.test.ts src/workspace-policy.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: certify current vector security semantics"`

---

### Task 11: Complete recursive current-source graph confinement

**Files:**
- Create: `docs/spec/vectors/generator/src/current-module-allowlist.ts`
- Modify: `docs/spec/vectors/generator/src/current-import-graph.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/current-lane-boundary.test.ts`

**Interfaces:**
- Produces `currentModuleDependencies(entry)` covering all approved literal import-like syntax and `assertExactCurrentModuleGraph(entry, allowlist)`.
- Consumed by current-lane tests and source-closure gate.

- [ ] **Step 1: Write recursive AST RED table**

Create local synthetic source trees labeled `BLUE TEAM VALIDATION: synthetic/local`. Cover nested literal `import()`, nonliteral `import()`, literal/nonliteral `require`, aliases that call literal/nonliteral require, re-export, import-equals, same-count path substitution, innocent-named historical file, and allowlist add/remove drift.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/current-vectors.test.ts src/current-lane-boundary.test.ts`

Expected: nested dynamic/CommonJS edges are missed and a same-count substitution passes.

- [ ] **Step 3: Recursively collect import-like syntax**

Walk every AST node. Follow ES imports/re-exports/import-equals plus literal `import()` and `require()`. Reject nonliteral import-like arguments. Track simple lexical aliases to ambient `require`; reject ambiguous or reassigned aliases instead of guessing. Resolve through the exact current tsconfig and preserve verified builtin/external leaves.

- [ ] **Step 4: Freeze exact reviewed allowlist**

After Tasks 2-9 imports are stable, write sorted repo-relative paths to `CURRENT_MODULE_ALLOWLIST`. Require deep equality, not count/hash alone, and retain historical denylist matching by path and retired export family.

- [ ] **Step 5: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/current-vectors.test.ts src/current-lane-boundary.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Commit: `git commit -m "fix: close the current source module graph"`

---

### Task 12: Make maintained snapshot guidance manifest-derived

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne.md`
- Modify: `README.md`
- Modify: `docs/spec/vectors/README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/glossary.md`
- Modify: `docs/security/threat-model.md`
- Modify: `AGENTS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Produces manifest-aware `lintMaintainedSnapshotGuidance(repositoryRoot)`; no maintained prose owns mutable source/snapshot hashes or corpus counts.

- [ ] **Step 1: Write manifest-guidance RED tests**

Copy a temporary maintained-document set plus a mutated manifest. Assert a guide that names a copied source SHA/count becomes stale, while wording that points readers to `docs/spec/vectors/snapshot.json` remains valid. Assert dated archived/design records are excluded, but current changelog bullets are checked.

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: current lint still requires obsolete `2ef40...`/`5d4bb...`/482/493 bootstrap facts.

- [ ] **Step 3: Parse and validate the committed manifest**

Load `snapshot.json` as closed data and validate `source_commit`, schema version, vector count, artifact paths, and digests. Require maintained guides to name the manifest as exact authority and `snapshot-check` as the history-derived snapshot-commit mechanism. Reject superseded literals and unqualified current-0.5/schema-2/five-document/zero-executable claims only in the curated current-file list.

- [ ] **Step 4: Rewrite maintained current prose**

State that the manifest supplies mutable facts, the last manifest-changing commit supplies snapshot identity, and draft/snapshot lanes are independent. Remove copied current hashes/counts from the listed files. Preserve clearly historical archived records.

- [ ] **Step 5: Run GREEN and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/snapshot-manifest.test.ts
npm --prefix docs/spec/vectors/generator run family:check
```

Commit: `git commit -m "docs: derive snapshot guidance from the manifest"`

---

### Task 13: Close the stable source commit

**Files:**
- Inspect: all source/prose/tests from Tasks 2-12
- Modify only when a review finding requires a focused repair in its owning task
- Do not modify: `docs/spec/vectors/snapshot.json` or generated snapshot-owned paths

**Interfaces:**
- Consumes: all source tasks, registry revision 16, and exact current allowlist.
- Produces: one stable source commit suitable for Task 14.

- [ ] **Step 1: Run complete source-closure assertions**

Assert revision `16`, exact new object/domain/reasons, preserved old `first_version`, retired-reason anchors/exclusions, no orphan schema/profile/invariant/reason, and exact current module allowlist.

- [ ] **Step 2: Run the focused closure gate before the full matrix**

Run: `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts src/coverage.test.ts`

Expected: PASS if Tasks 2-12 are coherent; any failure identifies the owning task and is repaired there with a focused RED/GREEN cycle.

- [ ] **Step 3: Run the complete source matrix serially**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/assurance-observation.test.ts src/assurance-downgrade.test.ts src/core-writer-binding.test.ts src/claims.test.ts src/claim-authorization.test.ts src/claim-ledger.test.ts src/current-vectors/semantic-certificates.test.ts src/current-vectors.test.ts src/coverage.test.ts src/docs-lint.test.ts src/registry.test.ts src/schema.test.ts
npm --prefix docs/spec/vectors/generator run build:current
npm --prefix docs/spec/vectors/generator run draft:check
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
git diff --check
```

Expected: all pass; `git diff --name-only -- docs/spec/vectors/snapshot.json docs/spec/vectors/{core,assurance,comms,control,social,workspace} docs/spec/vectors/coverage docs/spec/vectors/schema` is empty.

- [ ] **Step 4: Run two independent source reviews**

Dispatch one specification reviewer and one security reviewer over the full design-base-to-worktree diff. Require zero Critical/Important findings. Repair findings with focused RED/GREEN and rerun Step 3; do not waive them.

- [ ] **Step 5: Commit the stable source**

```bash
test -z "$(git status --porcelain=v1)"
git diff --name-only "4e893b3b136c541956a4ef68fb324bd65bda1034..HEAD" -- \
  docs/spec/vectors/snapshot.json \
  docs/spec/vectors/core docs/spec/vectors/assurance docs/spec/vectors/comms \
  docs/spec/vectors/control docs/spec/vectors/social docs/spec/vectors/workspace \
  docs/spec/vectors/coverage docs/spec/vectors/schema \
  docs/spec/vectors/fixtures.json
git commit --allow-empty -m "chore: mark heterodyne 0.6 security source closure"
git rev-parse HEAD
```

Expected: the protected generated-path command prints nothing. The empty
closure commit changes no bytes; it gives Task 14 one unambiguous source root
after all source commits, full checks, and independent reviews.

Record the resulting full SHA as `source_commit` in the ignored execution ledger. Any later source/prose/registry/schema/runtime/test/allowlist/docs-lint edit invalidates it and returns execution to this task.

---

### Task 14: Regenerate the complete schema-3 rolling snapshot

**Files:**
- Generated replacement: `docs/spec/vectors/snapshot.json`
- Generated replacement: `docs/spec/vectors/{core,assurance,comms,control,social,workspace}/`
- Generated replacement: `docs/spec/vectors/coverage/`
- Generated replacement: `docs/spec/vectors/schema/`
- Generated replacement: `docs/spec/vectors/fixtures.json`
- Generated replacement: conformance baselines/report/debt paths selected by `snapshot-author`
- Modify only if provenance RED requires it: `docs/spec/vectors/generator/src/snapshot-manifest.test.ts`

**Interfaces:**
- Consumes: exact stable `source_commit` from Task 13.
- Produces: one history-bound complete rolling snapshot commit; no parallel 0.5/current tree.

- [ ] **Step 1: Prove clean pre-author state and focused provenance RED**

Run:

```bash
test -z "$(git status --porcelain=v1)"
source_commit="$(git rev-parse HEAD)"
npm --prefix docs/spec/vectors/generator run draft:check
```

Add/update the manifest test to require `source_commit`, schema `3.0.0`, vector count equal to the source catalog count, unique/sorted IDs, six owners, complete certificate-derived invariants/reasons/profiles, and absence of retired member-KEL/role cases. Run it before authoring and record the expected old-manifest RED.

- [ ] **Step 2: Author transactionally from the exact source commit**

Run: `npm --prefix docs/spec/vectors/generator run snapshot-author -- "$PWD" "$source_commit"`

Expected: the tool materializes the committed source, authors/packages/verifies the complete corpus, updates all owned artifacts, and performs guarded cleanup.

- [ ] **Step 3: Audit generated replacement without editing it**

Verify manifest digests, artifact inventory, six owner counts, sorted/unique IDs, every reject's one registered reason, full invariant/profile closure, zero unresolved spec refs, no retired current cases, and exact source SHA. Inspect `git diff --name-status` and reject any path outside the generated ownership list plus the intentional provenance assertion.

- [ ] **Step 4: Commit snapshot and run history-bound verification**

```bash
git diff --name-only -z -- \
  docs/spec/vectors/snapshot.json \
  docs/spec/vectors/core docs/spec/vectors/assurance docs/spec/vectors/comms \
  docs/spec/vectors/control docs/spec/vectors/social docs/spec/vectors/workspace \
  docs/spec/vectors/coverage docs/spec/vectors/schema \
  docs/spec/vectors/fixtures.json docs/spec/conformance \
  docs/spec/vectors/generator/src/snapshot-manifest.test.ts \
  | xargs -0 git add --
git diff --cached --check
git commit -m "test: regenerate heterodyne 0.6 security snapshot"
npm --prefix docs/spec/vectors/generator run snapshot-check
```

Expected: snapshot-check derives this commit as the snapshot commit and reproduces byte-identical output from Task 13's source commit.

- [ ] **Step 5: Run final package matrix**

Run:

```bash
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
test -z "$(git status --porcelain=v1)"
```

Expected: all commands exit zero and tracked/index state is clean.

---

### Task 15: Independent exact-candidate review and handoff

**Files:**
- Create ignored report: `.superpowers/sdd/2026-08-27-heterodyne-0.6-pr28-closure/task-10-final-spec-review.md`
- Create ignored report: `.superpowers/sdd/2026-08-27-heterodyne-0.6-pr28-closure/task-10-final-security-review.md`
- Modify ignored report: `.superpowers/sdd/2026-08-27-heterodyne-0.6-pr28-closure/task-10-report.md`
- Modify ignored ledger: `.superpowers/sdd/2026-08-27-heterodyne-0.6-pr28-closure/progress.md`
- Do not modify: ADR-048 lifecycle or tracked source/snapshot artifacts

**Interfaces:**
- Consumes: exact source and snapshot commits from Tasks 13-14.
- Produces: evidence-backed merge-readiness report with every ledger `Ruling:` and explicit residual obligations; no merge or ADR acceptance.

- [ ] **Step 1: Dispatch fresh independent reviewers**

Give specification and security reviewers immutable commit SHAs, the approved design, this plan, and the two prior Task-10 reports. Require direct adversarial blue-team validation with synthetic/local fixtures only, and require separate counts for Critical, Important, and Minor findings.

- [ ] **Step 2: Run the exact serial verification matrix independently**

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
test -z "$(git status --porcelain=v1)"
```

Also verify registry revision/digest, source/snapshot provenance, manifest/artifact digests, no live normative ADR citations, no parallel current-0.5 snapshot tree, exact static allowlist, and no tracked `.DS_Store`.

- [ ] **Step 3: Resolve every Critical/Important finding**

Any Critical/Important finding reopens the owning source task, requires a focused RED/GREEN fix, invalidates Task 13's source SHA, and therefore requires a complete new Task 13 source commit and Task 14 snapshot regeneration. Minor findings are fixed unless the user explicitly accepts a documented residual.

- [ ] **Step 4: Produce handoff without accepting ADR-048**

Append exact commands/counts/SHAs, reviewer verdicts, audit findings, concerns, and every `Ruling:` line from the ledger to the Task-10 report. State that ADR-048 remains Proposed and that acceptance/archive is a separate later lifecycle commit requiring explicit user instruction.

- [ ] **Step 5: Offer branch integration choices**

Invoke `superpowers:finishing-a-development-branch`. Offer review/push options consistent with the user's authority. Do not merge PR #28, tag, release, or deploy without a new explicit instruction.
