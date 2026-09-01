# Final Security Evidence Prerequisites Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace caller-asserted security evidence with real opaque authority boundaries, retire obsolete diagnostics, author registry revision 17 once, and finish the paused Task 10 semantic-certificate closure.

**Architecture:** Each protocol family receives narrowly scoped verifier-minted authorities over exact captured bytes, authenticated current state, and durable consuming stores. Prerequisite tasks land runtime boundaries, normative prose, and focused tests without touching the five paused Task 10 files; after semantics stabilize, one registry task authors immutable revision 17, and one final Task 10 task performs all current-vector, dispatcher, predicate, and certificate wiring.

**Tech Stack:** TypeScript, Vitest, Node.js `crypto`, existing Nostr/NIP-44/OIDC/Workspace evaluators, JSON Schema, JCS-authored registry manifests.

**Spec:** `docs/superpowers/specs/2026-08-31-final-security-evidence-prerequisites-design.md`

## Global Constraints

- Work only in `.worktrees/pr28-protocol-closure` on `fix/pr28-protocol-closure`; preserve unrelated and untracked files.
- Preserve the uncommitted Task 10 work in `current-vectors/{boundary-runners.ts,case-contracts.ts,index.ts,semantic-certificates.test.ts,semantic-certificates.ts}`. Tasks 1–14 must neither modify nor stage these files; Task 15 owns their integration and commit.
- Every behavior change follows strict RED → observed expected failure → minimal GREEN → focused regression → `build:current`.
- Every hostile test is labeled `BLUE TEAM VALIDATION: synthetic/local`, uses deterministic non-deployable fixtures, and contacts no live relay, Radicle node, Marmot deployment, identity provider, account, credential, user data, third-party system, or external service.
- New authority modules use `type AuthorityDecision<R extends string = string, O = unknown> = Readonly<{ verdict: "accept"; output?: O } | { verdict: "reject"; reason_code: R } | { verdict: "indeterminate"; reason_code?: R }>` unless an existing protocol result type is stricter; `MarmotAdmissionDecision` is the alias `AuthorityDecision<"conversation-rejected">`.
- Opaque public handles are frozen empty objects backed by module-private `WeakMap` records. Plain objects, clones, proxies, accessors, cross-authority handles, stale views, and post-capture mutations fail closed.
- Consuming boundaries use caller-independent durable acquire/CAS state with `available`, `executing`, `committed`, and `indeterminate` behavior; exact committed retries return byte-identical cached output and unknown post-effect outcomes never repeat the effect.
- No public security input may be a caller assertion named `valid`, `authorized`, `canonical`, `current`, `unused`, `durable`, `subscribed`, or `effect_applied`.
- Agent publication authorization and signing are one exported atomic operation; no caller-consumable authorize-now/sign-later capability is permitted.
- The root Workspace role's `allowed_capabilities` is the workspace-wide ceiling.
- The six live invariant gaps are exactly `COMMS-I-MARMOT-ACCOUNT-IDENTITY`, `COMMS-I-MARMOT-SECRET-CONFINEMENT`, `COMMS-I-RADICLE-NON-ERASURE`, `WORKSPACE-I-CARRIER-NOT-AUTHORITY`, `WORKSPACE-I-INHERITANCE-NARROWS`, and `WORKSPACE-I-NO-AMBIENT-AUTHORITY`.
- The 11 retired reasons are exactly `revoked_key_post_compromise`, `retired-key-authority-window-invalid`, `dm_invite_revoked_device`, `dm_invite_unbound_device`, `agent-attribution-bypass-prohibited`, `agent-human-profile-prohibited`, `agent-key-access-prohibited`, `agent-method-prohibited`, `agent-resource-denied`, `control-request-id-conflict`, and `control-signed-event-invalid`.
- The one diagnostic-only reason is exactly `auth_rejected_permanent`.
- The 28 live reasons that require real evidence are exactly `agent-sender-proof-invalid`, `conversation-rejected`, `invite-authentication-invalid`, `marmot-agent-scope-denied`, `marmot-keypackage-replayed`, `marmot-premature-ack`, `marmot-private-inbox-nid-required`, `control-compromise-reset-evidence-invalid`, `control-compromise-reset-inventory-mismatch`, `control-compromise-reset-unauthenticated`, `control-subordinate-reauthorization-required`, `control-device-code-display-mismatch`, `control-device-code-invalid`, `control-device-code-rate-limited`, `control-enrollment-unavailable`, `control-frame-invalid`, `invite-preauthorization-invalid`, `control-keypackage-invalid`, `control-keypackage-replenishment-paused`, `control-signer-effect-indeterminate`, `control-token-invalid`, `capability_escalation`, `policy_denied`, `workspace_replay`, `profile-repository-selection-required`, `relay_profile_mutation`, `strict_mode_tor_disabled`, and `unauthorized_cache_content`.
- The five positive replacements are exactly `comms/agent-workload-token-accepted`, `comms/marmot-exact-bytes-durable`, `comms/marmot-expiration-not-erasure`, `comms/marmot-ordinary-welcome-held`, and `workspace/current-capability-intersection`.
- Registry revision 16 and older history remain byte-identical. Tasks 1–13 do not edit registry JSON; Task 14 authors immutable revision 17 exactly once after all semantics and anchors settle.
- Generated rolling snapshot files, `snapshot.json`, projections, counts, baselines, and digests remain untouched. Snapshot reconciliation is deferred.
- ADR-048 remains `Proposed`. Do not merge, push, create/update a PR, tag, publish, release, deploy, alter repository-host settings, or mutate live infrastructure.

---

### Task 1: Establish retired and diagnostic-only normative anchors

**Files:**
- Modify: `docs/spec/heterodyne-assurance.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: the exact 11 retired reasons and one diagnostic-only reason in design §§2.1–2.2.
- Produces: explicit owner-document anchors for revision 17 and a lint assertion that none are normative executable evidence.

- [ ] **Step 1: Add the focused RED**

Add a `BLUE TEAM VALIDATION: synthetic/local — retired diagnostics cannot claim live semantic authority` test that loads the four current documents and asserts exact anchors for Assurance, Core, Comms, and Control plus diagnostic-only wording for `auth_rejected_permanent`.

- [ ] **Step 2: Observe the expected failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts -t "retired diagnostics cannot claim live semantic authority"
```

Expected: FAIL because the explicit anchors and diagnostic-only wording do not exist.

- [ ] **Step 3: Add the minimum normative text**

Add one explicit retired-semantics section per owner. List the exact retained IDs, state that they are non-wire history and not current executable authority, and preserve the current invariants through their named real boundaries. In Comms, state that `auth_rejected_permanent` is a local relay-write diagnostic and proves no cryptographic or upstream authority.

- [ ] **Step 4: Run GREEN and current build**

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit only Task 1 paths**

```bash
git add docs/spec/heterodyne-assurance.md docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: classify retired security diagnostics"
```

### Task 2: Verify Marmot Welcome and admission authority

**Files:**
- Create: `docs/spec/vectors/generator/src/security-authority-support.ts`
- Create: `docs/spec/vectors/generator/src/security-authority-support.test.ts`
- Create: `docs/spec/vectors/generator/src/marmot-admission-authority.ts`
- Create: `docs/spec/vectors/generator/src/marmot-admission-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/marmot-admission.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces the shared durable contract used by Tasks 2–10:

```ts
export type AuthorityDecision<R extends string, O = undefined> = Readonly<
  | { verdict: "accept"; output: O }
  | { verdict: "reject"; reason_code: R }
  | { verdict: "indeterminate"; reason_code?: R }
>;
export interface DurableAuthorityStore<O = unknown> {
  load(key: string): Promise<unknown>;
  acquire(input: Readonly<{ key: string; binding_digest: string; execution_token: string }>): Promise<unknown>;
  commit(input: Readonly<{ key: string; binding_digest: string; execution_token: string; output: O }>): Promise<unknown>;
}
```

- Produces: `createMarmotAdmissionAuthority(config): MarmotAdmissionAuthority`, `verifyMarmotWelcome(authority, input): VerifiedMarmotWelcome | MarmotAdmissionDecision`, and `admitOrdinaryMarmotWelcome(authority, welcome, acceptance): MarmotAdmissionDecision`.
- `VerifiedMarmotWelcome` is an opaque handle binding exact Welcome/KeyPackage bytes, account, group, members, capabilities, and current conversation checkpoint.

- [ ] **Step 1: Write the authority RED**

Add deterministic signed Welcome/KeyPackage fixtures and tests for exact acceptance, account mismatch, leaf reuse, wrong group/member/capability, stale conversation state, clone/cross-authority handle, source mutation, accessor/proxy zero-trap rejection, and a restart-stable consuming admission. Prefix hostile cases with `BLUE TEAM VALIDATION: synthetic/local`.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-admission-authority.test.ts
```

Expected: FAIL because the module and opaque authority do not exist.

- [ ] **Step 3: Implement the closed API**

Implement frozen empty handles backed by private records. Capture callback identity once, descriptor-snapshot every input before semantic reads, verify exact account/group/member/keypackage bindings, reload current conversation state, and reserve admission before returning accept. Keep `cryptographic_valid` and `one_time_dm_invite_valid` outside the new API.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-admission-authority.test.ts src/marmot-admission.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/security-authority-support.ts docs/spec/vectors/generator/src/security-authority-support.test.ts docs/spec/vectors/generator/src/marmot-admission-authority.ts docs/spec/vectors/generator/src/marmot-admission-authority.test.ts docs/spec/vectors/generator/src/marmot-admission.ts docs/spec/heterodyne-comms.md
git commit -m "fix: verify Marmot admission authority"
```

### Task 3: Bind exact Marmot archive retention and acknowledgement

**Files:**
- Create: `docs/spec/vectors/generator/src/marmot-archive-retention-authority.ts`
- Create: `docs/spec/vectors/generator/src/marmot-archive-retention-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/marmot-routing-policy.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces: `createMarmotArchiveRetentionAuthority(config)`, `appendExactMarmotArchive(authority, input): MarmotArchiveAppendReceipt | AuthorityDecision`, `acknowledgeMarmotArchive(authority, receipt): AuthorityDecision`, and `expireMarmotPresentation(authority, receipt): AuthorityDecision`.
- The opaque receipt binds repository RID/ref, object digest, exact source-event/ciphertext digest, and durable commit identity.

- [ ] **Step 1: Write RED**

Test exact-byte append/ack, invalid signed-event ID/signature, unauthorized repository writer/ref, changed bytes/ref/RID, ciphertext without authenticated source-event/media authorization, acknowledgement before durable reachability, expiration preserving retained ciphertext/history, store conflict, unknown terminal write, exact committed retry, clone/cross-authority handle, and callback accessor/proxy zero-trap behavior. Use the mandated blue-team label on hostile cases.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-archive-retention-authority.test.ts
```

- [ ] **Step 3: Implement minimal durable boundary**

Capture exact bytes once, verify NIP-01 ID/signature for event inputs, authenticate the repository writer/RID/ref, bind ciphertext to an authenticated source-event or media authorization, then require durable repository reachability before receipt minting. Allow acknowledgement only from the genuine receipt and make terminal-write uncertainty absorbing `indeterminate`. Expiration changes current presentation/authorization only.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-archive-retention-authority.test.ts src/marmot-routing-policy.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/marmot-archive-retention-authority.ts docs/spec/vectors/generator/src/marmot-archive-retention-authority.test.ts docs/spec/vectors/generator/src/marmot-routing-policy.ts docs/spec/heterodyne-comms.md
git commit -m "fix: bind Marmot archival durability"
```

### Task 4: Authorize persona inbox admission and one-time invite redemption

**Files:**
- Create: `docs/spec/vectors/generator/src/persona-inbox-admission-authority.ts`
- Create: `docs/spec/vectors/generator/src/persona-inbox-admission-authority.test.ts`
- Create: `docs/spec/vectors/generator/src/one-time-invite-authority.ts`
- Create: `docs/spec/vectors/generator/src/one-time-invite-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/one-time-invite.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces: `createPersonaInboxAdmissionAuthority`, `admitPersonaInboxBundle`, `createOneTimeInviteAuthority`, and `redeemOneTimeInvite`.
- Inbox authority owns current NID authorization, sender scope, exact sender ref, selected KeyPackage, and group transition. Invite authority reuses real descriptor signature and `responseProof` validation but owns current revocation and durable reservation state.

- [ ] **Step 1: Write focused RED suites**

Cover exact accepts and the live reasons `marmot-agent-scope-denied`, `marmot-keypackage-replayed`, `marmot-private-inbox-nid-required`, and `invite-authentication-invalid`. Add wrong purpose/transcript/recipient/secret, expiry/revocation, replay, mismatched retry, unknown post-effect state, mutation, clone, proxy, and accessor cases using the blue-team label.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/persona-inbox-admission-authority.test.ts src/one-time-invite-authority.test.ts
```

- [ ] **Step 3: Implement the two opaque authorities**

Use separate module-private authority/handle records and separate durable store keys. Verify signed invite bytes with existing helpers, bind every security-relevant member into the reservation digest, cache exact committed outputs, and never recreate the retired DM device-state reasons.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/persona-inbox-admission-authority.test.ts src/one-time-invite-authority.test.ts src/one-time-invite.test.ts src/comms-policy.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/persona-inbox-admission-authority.ts docs/spec/vectors/generator/src/persona-inbox-admission-authority.test.ts docs/spec/vectors/generator/src/one-time-invite-authority.ts docs/spec/vectors/generator/src/one-time-invite-authority.test.ts docs/spec/vectors/generator/src/one-time-invite.ts docs/spec/heterodyne-comms.md
git commit -m "fix: authorize Marmot inbox and invite use"
```

### Task 5: Make workload publication authorization atomic with signing

**Files:**
- Create: `docs/spec/vectors/generator/src/agent-publication-authorization.ts`
- Create: `docs/spec/vectors/generator/src/agent-publication-authorization.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces only `createAgentPublicationAuthorizationAuthority(config)` and `authorizeAndSignAgentPublication(authority, request, signer): Promise<AuthorityDecision>`.
- The internal `VerifiedAgentPublicationAuthorization` is not exported. It binds verified JWT bytes, issuer/audience/subject/persona/agent/signer/scope/expiry/status/generation, DPoP or configured mTLS identity, current opaque claim view, exact publication, and attribution profile.

- [ ] **Step 1: Write RED**

Use real local JWT signing/verification, deterministic DPoP fixtures, and a synthetic constructor-captured mTLS peer identity. Test accepted DPoP and mTLS atomic publication, wrong/substituted mTLS peer, per-operation mTLS callback replacement, wrong signer/audience/scope/nonce/method/target, stale status/generation/claim view, proof replay, publication mutation, cross-authority/callback substitution, signer throw, terminal-write failure, exact retry, and the absence of any exported pre-sign capability. Label hostile cases as blue-team validation.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-publication-authorization.test.ts
```

- [ ] **Step 3: Implement atomic mint-and-consume**

Capture and verify the complete request before acquire, revalidate status/claim state immediately before the CAS, invoke the signer only from exact persisted `executing`, verify its returned NIP-01 event, and commit immutable output before returning accept. Do not export the internal authorization handle.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-publication-authorization.test.ts src/agent-authorship.test.ts src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/agent-publication-authorization.ts docs/spec/vectors/generator/src/agent-publication-authorization.test.ts docs/spec/vectors/generator/src/agent-authorship.ts docs/spec/heterodyne-comms.md
git commit -m "fix: authorize and sign agent publications atomically"
```

### Task 6: Prepare real Control reset, frame, and signer evidence

**Files:**
- Create: `docs/spec/vectors/generator/src/control-security-evidence.ts`
- Create: `docs/spec/vectors/generator/src/control-security-evidence.test.ts`
- Modify: `docs/spec/vectors/generator/src/control-signing.ts`
- Modify: `docs/spec/vectors/generator/src/profile-negotiation.ts`
- Create: `docs/spec/vectors/generator/src/profile-negotiation.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces deterministic fixture constructors and result adapters that invoke `validateCompromiseReset`, `executePersistedAutomatedSigning`, and a hardened `validateCurrentControlFrameProfile(frameBytes, requestBinding, verificationContext)` without boolean summaries. The frame function descriptor-captures the exact frame, verifies its signing event, binds request/profile/version/transport, and never supplies hard-coded validity booleans to `validateControlFrameBoundary`.
- Later Task 15 consumes these exact functions and fixtures through its dispatcher.

- [ ] **Step 1: Write RED over exact real paths**

Add signed reset/grant/completion fixtures for all four reset reasons, malformed closed frames for `control-frame-invalid`, and an executing signer reservation producing durable `control-signer-effect-indeterminate`. Assert exact function invocation and opaque terminal identity, not only reason strings.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-security-evidence.test.ts
```

- [ ] **Step 3: Add the minimal adapters**

Export narrowly typed fixture/result functions that retain signed bytes and opaque states. Do not create a new policy evaluator or accept boolean validity fields.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-security-evidence.test.ts src/control-signing.test.ts src/profile-negotiation.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/control-security-evidence.ts docs/spec/vectors/generator/src/control-security-evidence.test.ts docs/spec/vectors/generator/src/control-signing.ts docs/spec/vectors/generator/src/profile-negotiation.ts docs/spec/vectors/generator/src/profile-negotiation.test.ts docs/spec/heterodyne-control.md
git commit -m "test: bind Control evidence to real boundaries"
```

### Task 7: Implement durable Control device authorization

**Files:**
- Create: `docs/spec/vectors/generator/src/control-device-authorization.ts`
- Create: `docs/spec/vectors/generator/src/control-device-authorization.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlDeviceAuthorizationAuthority(config)`, `createControlDeviceTransaction(authority, request)`, and `pollControlDeviceAuthorization(authority, request)`.
- Authority owns high-entropy device/user codes, client/persona, display fingerprint, interval, rate buckets, failure budget, expiry, invalidation, and atomic transaction state.

- [ ] **Step 1: Write RED**

Cover generated device/user-code entropy and deterministic collision retry/exhaustion, a valid transaction, malformed/unknown code, display mismatch, poll-before-interval, rate limit/slow-down, fifth-failure atomic invalidation, expiry, concurrent poll/CAS conflict, exact committed retry, mutation, proxy/accessor, and cross-authority use. Use blue-team labels.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-device-authorization.test.ts
```

- [ ] **Step 3: Implement the authority**

Hash normalized codes internally, load authoritative transaction/rate state, perform all attempts and invalidation through one atomic store, and derive the three `control-device-code-*` reasons only from real state transitions.

- [ ] **Step 4: Verify GREEN and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-device-authorization.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-device-authorization.ts docs/spec/vectors/generator/src/control-device-authorization.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: authorize Control device transactions"
```

### Task 8: Implement Control enrollment admission

**Files:**
- Create: `docs/spec/vectors/generator/src/control-enrollment-admission.ts`
- Create: `docs/spec/vectors/generator/src/control-enrollment-admission.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlEnrollmentAdmissionAuthority(config)` and `admitControlEnrollment(authority, request)`.
- Authority owns pending-group capacity, slot reservation, invite purpose, exact KeyPackage validation, public replenishment state, current enrollment, expiry, and rate state.

- [ ] **Step 1: Write RED**

Test exact admission plus malformed/unbound/expired/replayed KeyPackage, independently expired invite, enrollment rate-limit state, already/currently enrolled account or device, unavailable capacity, replenishment pause, changed inventory between validation/acquire, concurrent reservation, effect uncertainty, exact retry, clone, mutation, proxy, and callback substitution with blue-team labels.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-enrollment-admission.test.ts
```

- [ ] **Step 3: Implement and verify GREEN**

Use exact descriptor capture and a caller-independent slot store; reload authoritative inventory immediately before acquire. Derive only `control-enrollment-unavailable`, `control-keypackage-invalid`, and `control-keypackage-replenishment-paused`.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-enrollment-admission.test.ts src/marmot-admission.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 4: Commit**

```bash
git add docs/spec/vectors/generator/src/control-enrollment-admission.ts docs/spec/vectors/generator/src/control-enrollment-admission.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: authorize Control enrollment admission"
```

### Task 9: Verify Control invite preauthorization

**Files:**
- Create: `docs/spec/vectors/generator/src/control-invite-preauthorization.ts`
- Create: `docs/spec/vectors/generator/src/control-invite-preauthorization.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlInvitePreauthorizationAuthority(config)` and `verifyControlInvitePreauthorization(authority, descriptor, template, request): VerifiedControlInvitePreauthorization | AuthorityDecision<"invite-preauthorization-invalid">`.
- The opaque result binds exact signed fragment, non-convertible purpose, client key, persona, audience, signer/class, methods, kinds, limits, expiry, and current revocation view.

- [ ] **Step 1: Write and observe RED**

Test exact accept; signature, purpose, client, signer, audience, methods/kinds/limits, expiry, revocation, KERI prompt-free device, mutation, clone, and proxy/accessor rejection.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-invite-preauthorization.test.ts
```

- [ ] **Step 2: Implement minimal composition**

Compose the real Comms signed invite verification with exact closed Control template equality and current revocation loading. Never accept a caller `valid` summary.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-invite-preauthorization.test.ts src/one-time-invite.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-invite-preauthorization.ts docs/spec/vectors/generator/src/control-invite-preauthorization.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: verify Control invite preauthorization"
```

### Task 10: Verify current Control tokens

**Files:**
- Create: `docs/spec/vectors/generator/src/control-token-verifier.ts`
- Create: `docs/spec/vectors/generator/src/control-token-verifier.test.ts`
- Modify: `docs/spec/vectors/generator/src/token-status.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlTokenVerifier(config)`, `verifyControlToken(verifier, compactJwt, use): VerifiedControlToken | AuthorityDecision<"control-token-invalid">`, and `consumeVerifiedControlToken(verifier, token, operation): Promise<AuthorityDecision<"control-token-invalid", Readonly<{ operation_id: string }>>>`.
- The opaque one-use result binds actual RS256 JWT verification, issuer/audience/token class, sender key, Marmot group, exact grant/checkpoint/generation/status, expiry, proof-of-possession, and current opaque grant view.

- [ ] **Step 1: Write and observe RED**

Use local deterministic signing keys. Test exact accept and consume; bad signature/type/issuer/audience/sender/time/group/grant/checkpoint/generation/status/proof; stale current view; replay; cross-authority consume; changed operation; exact committed retry; indeterminate terminal; mutation; clone; accessor/proxy; and cross-authority use.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-token-verifier.test.ts
```

- [ ] **Step 2: Implement real verification**

Reuse actual projected-JWT validation, then resolve and bind the current Control grant view before minting a one-use token handle. Map all public failures to `control-token-invalid` without leaking internal mismatch detail.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-token-verifier.test.ts src/token-status.test.ts src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-token-verifier.ts docs/spec/vectors/generator/src/control-token-verifier.test.ts docs/spec/vectors/generator/src/token-status.ts docs/spec/heterodyne-control.md
git commit -m "fix: verify current Control tokens"
```

### Task 11: Migrate Workspace authority to signed current state

**Files:**
- Create: `docs/spec/vectors/generator/src/workspace-security-evidence.ts`
- Create: `docs/spec/vectors/generator/src/workspace-security-evidence.test.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.test.ts`
- Modify: `docs/spec/heterodyne-workspace.md`

**Interfaces:**
- Produces signed deterministic fixture builders and exact calls through `createWorkspaceRepositoryResolverAuthority`, `authenticateWorkspaceRepositoryView`, `resolveWorkspaceEffectiveAuthorization`, `consumeWorkspaceInvitationAcceptance`, and `evaluateGrantActivation`.
- Root role `allowed_capabilities` is enforced as the ceiling at repository acceptance, resolution, activation, allowance, and key delivery.

- [ ] **Step 1: Write RED**

Test a carrier/host/repository writer with no signed grant, ambient affiliation without authority, child/grant capability widening, valid narrowing intersection, revoked future effect, first invitation acceptance, exact committed retry, changed/replayed invitation, effect-time state change, and proxy/accessor/mutation rejection. Label hostile tests as blue-team validation.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/workspace-security-evidence.test.ts src/workspace.test.ts -t "workspace-wide ceiling|signed current state|invitation replay"
```

- [ ] **Step 3: Implement the root ceiling and fixture harness**

Make complete-state validation reject any descendant widening beyond root `allowed_capabilities`. Preserve opaque resolver authority in private fixture state; serialize only signed objects and closed requests. Use the existing consuming invitation store for replay.

- [ ] **Step 4: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/workspace-security-evidence.test.ts src/workspace.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/workspace-security-evidence.ts docs/spec/vectors/generator/src/workspace-security-evidence.test.ts docs/spec/vectors/generator/src/workspace.ts docs/spec/vectors/generator/src/workspace.test.ts docs/spec/heterodyne-workspace.md
git commit -m "fix: enforce Workspace authority ceiling"
```

### Task 12: Compose signed subscriber-local Social policy

**Files:**
- Create: `docs/spec/vectors/generator/src/social-subscription-authority.ts`
- Create: `docs/spec/vectors/generator/src/social-subscription-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-moderation.ts`
- Modify: `docs/spec/vectors/generator/src/agent-moderation.test.ts`
- Modify: `docs/spec/heterodyne-social.md`

**Interfaces:**
- Produces: `createSocialSubscriptionAuthority(config)`, `resolveSubscribedAgentPolicy(authority, input): SubscribedAgentPolicyView | null`, and `applySubscribedAgentPolicy(view, event): AgentPolicyDecision`.
- Local subscription state is captured by the authority; the view binds source-neutral selected signed list, exact signed receipts/targets/authorship, and muted author/device keys.

- [ ] **Step 1: Write and observe RED**

Test signed current list/receipt accept, unsubscribed, stale/replaced/removed/corrected list, invalid receipt, wrong author/device, relay-current candidate, default subscription visible/removable, clone/cross-authority view, mutation, and zero-trap proxy/accessor cases.

```bash
npm --prefix docs/spec/vectors/generator test -- src/social-subscription-authority.test.ts
```

- [ ] **Step 2: Implement signed composition**

Reuse `validateAgentPolicyReceipt`, `validateAgentPolicyList`, source-neutral replaceable selection, and real Social/Comms authorship evidence. Remove caller-provided `subscribed`, `policy_event_selected`, and `muted_event_authors` from the secure path.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/social-subscription-authority.test.ts src/agent-moderation.test.ts src/social-events.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/social-subscription-authority.ts docs/spec/vectors/generator/src/social-subscription-authority.test.ts docs/spec/vectors/generator/src/agent-moderation.ts docs/spec/vectors/generator/src/agent-moderation.test.ts docs/spec/heterodyne-social.md
git commit -m "fix: verify subscribed Social policy"
```

### Task 13: Implement Core profile and operational authorities

**Files:**
- Create: `docs/spec/vectors/generator/src/canonical-profile-selection-authority.ts`
- Create: `docs/spec/vectors/generator/src/canonical-profile-selection-authority.test.ts`
- Create: `docs/spec/vectors/generator/src/core-operational-assurance-authority.ts`
- Create: `docs/spec/vectors/generator/src/core-operational-assurance-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/core-policy.ts`
- Modify: `docs/spec/vectors/generator/src/follow-up-hardening.ts`
- Modify: `docs/spec/heterodyne-core.md`

**Interfaces:**
- Produces: `createCanonicalProfileSelectionAuthority`, `selectCanonicalProfile`, `createCoreOperationalAssuranceAuthority`, `verifyCacheCandidate`, `verifyRelayProfileCarrier`, and `verifyStrictTransport`.
- Profile selection reuses source-neutral opaque replaceable selection and authenticates repository writers; operational views bind verified NIP-01 bytes/author or captured strict-role transport configuration.

- [ ] **Step 1: Write RED**

Test source-neutral signed selection, required repository state, bad writer, unsigned/wrong-author cache entry, raw relay mutation with recomputed field mismatch, strict role without Tor, reduced-assurance non-strict accept, mutation, clone, proxy/accessor, and callback substitution.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/canonical-profile-selection-authority.test.ts src/core-operational-assurance-authority.test.ts
```

- [ ] **Step 3: Implement opaque views**

Use `snapshotAndVerifyNostrEvent` and `ReplaceableSelectionAuthority`; authenticate repository candidates without carrier priority; remove boolean security inputs from the secure Core path. Derive the four live Core reasons from exact state only.

- [ ] **Step 4: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/canonical-profile-selection-authority.test.ts src/core-operational-assurance-authority.test.ts src/core-policy.test.ts src/follow-up-hardening.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/canonical-profile-selection-authority.ts docs/spec/vectors/generator/src/canonical-profile-selection-authority.test.ts docs/spec/vectors/generator/src/core-operational-assurance-authority.ts docs/spec/vectors/generator/src/core-operational-assurance-authority.test.ts docs/spec/vectors/generator/src/core-policy.ts docs/spec/vectors/generator/src/follow-up-hardening.ts docs/spec/heterodyne-core.md
git commit -m "fix: verify Core operational authority"
```

### Task 14: Author immutable registry revision 17 exactly once

**Files:**
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify only if concrete allocations require it: `docs/spec/registry/objects.json`
- Modify only if concrete allocations require it: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`

**Interfaces:**
- Consumes: settled anchors and authority contracts from Tasks 1–13.
- Produces: immutable revision 17, preserved revision-16 history, 11 exact retired exclusions, one exact diagnostic-only exclusion, and no exclusion for the 28 live reasons.

- [ ] **Step 1: Write registry-history RED**

Assert revision 17, the exact revision-16 baseline digest `5ff98ff2af3bcbb413918dc207dcfc5da7035e9751e9836680df9b56a2b2230f`, preserved entry IDs/owners/status/`first_version`, exact new anchors/descriptions, and exact sorted exclusions with individual justifications. Assert all 28 live reasons are absent from exclusions.

- [ ] **Step 2: Observe RED before any author call**

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/coverage.test.ts -t "revision 17|retired security diagnostics|live authority reasons"
```

Expected: FAIL on revision 16 and missing revised entries. Record author-call count as zero in the task report.

- [ ] **Step 3: Edit entry JSON and validate a synthetic no-write manifest**

Retarget the 11 retained reasons, classify `auth_rejected_permanent`, refine live descriptions/anchors only where required, and add only concrete object/proof allocations backed by completed Tasks 2–13. Preserve every prior identity and `first_version`. In `registry.test.ts`, load the edited entry set, compute `const digest = computeRegistryDigest(entrySet)`, construct a synthetic manifest `{ ...revision16Manifest, revision: 17, entry_set_sha256: digest }`, and call `validateRegistry({ manifest: syntheticManifest, ...entrySet })`. Assert the revision-16 baseline digest and every prior identity/`first_version` before permitting the author step. After this preflight passes, entry JSON is frozen for the task; any further entry edit aborts the task before authoring.

- [ ] **Step 4: Invoke the registry author exactly once**

```bash
npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 17
```

Do not invoke it again. Any failure after this call stops Task 14 for adjudication; no entry edit or second author invocation is permitted.

- [ ] **Step 5: Verify GREEN and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/coverage.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/registry/manifest.json docs/spec/registry/reason-codes.json docs/spec/registry/objects.json docs/spec/registry/proof-domains.json docs/spec/vectors/generator/src/registry.test.ts docs/spec/vectors/generator/src/coverage.ts docs/spec/vectors/generator/src/coverage.test.ts
git commit -m "spec: author security authority registry revision 17"
```

### Task 15: Resume Task 10 and close executable semantic certificates

**Files:**
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/index.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.test.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/comms.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/control.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/core.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/social.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/workspace.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`

**Interfaces:**
- Consumes: every authority/result from Tasks 2–13 and revision 17 from Task 14.
- Produces: exact ordered invocation plans, unbypassable `InvocationContext.call(stepId, exactArgs)`, opaque execution receipts, boundary-specific proof witnesses, and complete invariant/reason/profile/owner/spec-reference closure.

The exact replacement map is:

| Case | Ordered canonical boundary plan | Allocation | Required terminal postcondition |
|---|---|---|---|
| `comms/agent-sender-proof-invalid` | `agent-publication-authorization.authorizeAndSignAgentPublication` | `COMMS-I-WORKLOAD-TOKEN-CONFINEMENT`; `agent-sender-proof-invalid` | real JWT accepted, exact DPoP/mTLS sender proof rejected before signer/effect |
| `comms/conversation-rejected` | `verifyMarmotWelcome` → `admitOrdinaryMarmotWelcome` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `conversation-rejected` | verified Welcome exists, authenticated current admission rejects |
| `comms/invite-authentication-invalid` | `one-time-invite-authority.redeemOneTimeInvite` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `invite-authentication-invalid` | exact signed invite/response proof rejects with no reservation/effect |
| `comms/marmot-agent-scope-denied` | `persona-inbox-admission-authority.admitPersonaInboxBundle` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-agent-scope-denied` | current inbox scope excludes the captured sender/request |
| `comms/marmot-keypackage-replayed` | same inbox boundary | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-keypackage-replayed` | exact KeyPackage is already durably consumed |
| `comms/marmot-premature-ack` | `appendExactMarmotArchive` → `acknowledgeMarmotArchive` | `COMMS-I-MARMOT-EXACT-BYTES`; `marmot-premature-ack` | no genuine durable append receipt exists at acknowledgement time |
| `comms/marmot-private-inbox-nid-required` | `persona-inbox-admission-authority.admitPersonaInboxBundle` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-private-inbox-nid-required` | current authenticated recipient authorization lacks required NID binding |
| `control/compromise-reset-evidence-invalid` | `control-signing.validateCompromiseReset` | `CONTROL-I-COMPROMISE-RESET`; matching reason | signed grant/completion valid but exact consecutive reset evidence invalid |
| `control/compromise-reset-inventory-mismatch` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | authenticated required-reset inventory differs from completion |
| `control/compromise-reset-unauthenticated` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | grant/completion signature or Assurance binding rejects |
| `control/subordinate-reauthorization-required` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | a required subordinate fresh authorization is absent |
| `control/device-code-display-mismatch` | `control-device-authorization.pollControlDeviceAuthorization` | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | stored and authenticated display fingerprints differ |
| `control/device-code-invalid` | same device boundary | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | normalized code is absent/invalid/atomically invalidated |
| `control/device-code-rate-limited` | same device boundary | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | authoritative interval/rate state forbids this poll |
| `control/enrollment-unavailable` | `control-enrollment-admission.admitControlEnrollment` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | authenticated capacity/current enrollment forbids reservation |
| `control/frame-invalid` | `profile-negotiation.validateCurrentControlFrameProfile` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | exact captured signed frame/profile/request fails closed |
| `control/invite-preauthorization-invalid` | `control-invite-preauthorization.verifyControlInvitePreauthorization` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | signed invite/template/current revocation does not bind request |
| `control/keypackage-invalid` | `control-enrollment-admission.admitControlEnrollment` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | exact KeyPackage verification/binding fails |
| `control/keypackage-replenishment-paused` | same enrollment boundary | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | authoritative public-pool pending state pauses replenishment |
| `control/signer-effect-indeterminate` | `control-signing.executePersistedAutomatedSigning` | `CONTROL-I-OPERATION-AT-MOST-ONCE`; `control-signer-effect-indeterminate` | persisted execution becomes absorbing indeterminate and signer is not repeated |
| `control/token-invalid` | `verifyControlToken` → `consumeVerifiedControlToken` | `CONTROL-I-CLIENT-KEY-CONFINEMENT`; matching reason | actual JWT/current grant/per-use proof rejects before operation |
| `workspace/carrier-not-ambient-authority` | authenticate view → `resolveWorkspaceEffectiveAuthorization` | `WORKSPACE-I-CARRIER-NOT-AUTHORITY`, `WORKSPACE-I-NO-AMBIENT-AUTHORITY`; `policy_denied` | carrier/host/writer principal has no qualifying signed grant |
| `workspace/inheritance-escalation-rejected` | authenticate view → resolve → `evaluateGrantActivation` | `WORKSPACE-I-INHERITANCE-NARROWS`; `capability_escalation` | child/grant request exceeds root/ancestor intersection |
| `workspace/invitation-replay` | `consumeWorkspaceInvitationAcceptance` → activation → identical second consume | `WORKSPACE-I-NO-AMBIENT-AUTHORITY`; `workspace_replay` | first terminal is committed; replay performs no second activation |
| `workspace/revocation-blocks-future-effect` | authenticate view → resolve → activation | `WORKSPACE-I-REVOCATION-FUTURE-ONLY`; `policy_denied` | current signed revocation excludes the future effect |
| `core/friend-cache-unsigned` | `core-operational-assurance-authority.verifyCacheCandidate` | `CORE-I-IDENTITY-INTEGRITY`; `unauthorized_cache_content` | cache candidate lacks exact verified persona authorship |
| `core/profile-repository-selection-required` | `canonical-profile-selection-authority.selectCanonicalProfile` | `CORE-I-IDENTITY-INTEGRITY`; matching reason | selected profile requires authenticated repository state that is absent |
| `core/relay-profile-mutated` | `core-operational-assurance-authority.verifyRelayProfileCarrier` | `CORE-I-IDENTITY-INTEGRITY`; `relay_profile_mutation` | retained raw event ID/signature/exposed fields do not match |
| `core/strict-mode-without-tor` | `core-operational-assurance-authority.verifyStrictTransport` | `CORE-I-VERIFY-BEFORE-USE`; `strict_mode_tor_disabled` | captured strict role requires Tor and current transport lacks it |
| `comms/agent-workload-token-accepted` | `agent-publication-authorization.authorizeAndSignAgentPublication` | `COMMS-I-AGENT-SIGNER-BINDING`, `COMMS-I-WORKLOAD-TOKEN-CONFINEMENT` | one durable effect yields an exactly attributed signed NIP-01 event |
| `comms/marmot-exact-bytes-durable` | `marmot-archive-retention-authority.appendExactMarmotArchive` | `COMMS-I-MARMOT-EXACT-BYTES` | genuine receipt binds identical authorized bytes and durable ref/object commit |
| `comms/marmot-expiration-not-erasure` | append → `expireMarmotPresentation` → archive reload | `COMMS-I-RADICLE-NON-ERASURE` | presentation expires while ciphertext/history remains reachable |
| `comms/marmot-ordinary-welcome-held` | `verifyMarmotWelcome` → `admitOrdinaryMarmotWelcome` | `COMMS-I-MARMOT-ACCOUNT-IDENTITY`, `COMMS-I-MARMOT-SECRET-CONFINEMENT`, `COMMS-I-MARMOT-UPSTREAM-AUTHORITY` | exact account/group/member/leaf bindings accept once under local authority |
| `workspace/current-capability-intersection` | authenticate view → resolve → activation | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE`, `WORKSPACE-I-INHERITANCE-NARROWS`, `WORKSPACE-I-NO-AMBIENT-AUTHORITY` | output equals root ∩ ancestors ∩ current grant/relationship/resource constraints |

- [ ] **Step 1: Preserve and re-run the dispatcher RED/GREEN evidence**

Confirm the existing test proves a same-ID substituted evaluator is actually called/throws and the AST guard reports zero branch calls outside canonical plan construction. Do not weaken the paused assertions.

- [ ] **Step 2: Add prerequisite-boundary REDs**

For each replaced case, assert that a fabricated same-terminal result, copied reason/invariant, cloned fixture, alternate evaluator wrapper, or omitted composite step cannot mint a certificate. Assert the five positive cases prove their real postconditions. All hostile tests use the exact blue-team label.

- [ ] **Step 3: Replace cases and remove retired cases**

Delete exactly `assurance/retired-key-post-compromise`, `core/retired-key-authority-window-invalid`, `comms/dm-invite-revoked-device`, `comms/dm-invite-unbound-device`, `control/agent-attribution-bypass-prohibited`, `control/agent-human-profile-prohibited`, `control/agent-key-access-prohibited`, `control/agent-method-prohibited`, `control/agent-resource-denied`, `control/request-id-conflict`, and `control/signed-event-invalid`. Keep `comms/auth-rejected-permanent` terminal-only with no semantic certificate. Replace every other shim fixture with closed data consumed by the real authorities; keep function-bearing authorities in private fixture registries. Do not serialize opaque handles or callbacks.

- [ ] **Step 4: Finish canonical invocation plans**

Every branch calls only through ordered `InvocationContext.call`. The receipt binds exact runner/plan/function references, argument identities/digests, return/throw identities/digests, fixture identity/digest, raw/projected result identity, durable state, and terminal postcondition. `finish()` rejects skipped, extra, or reordered occurrences.

- [ ] **Step 5: Implement exact boundary-specific proof predicates**

Each predicate derives its owned invariants/reasons from exact fixture plus inspected trace/raw result/private artifacts; it never accepts caller labels or expected output as evidence. Registry/profile prerequisites and semantic evaluators both appear in composite plans. Remove `NON_CERTIFIABLE_CALLER_SHIM_CASES` when the last replacement lands.

- [ ] **Step 6: Run focused closure**

```bash
npm --prefix docs/spec/vectors/generator test -- src/current-vectors/semantic-certificates.test.ts src/current-vectors.test.ts src/coverage.test.ts src/current-traceability.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Expected: zero invariant, semantic-reason, profile, owner, case, graph, and specification-reference issues; dynamic counts are asserted from the catalog rather than copied historical literals.

- [ ] **Step 7: Run full source gates without snapshot mutation**

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run draft:check
npm --prefix docs/spec/vectors/generator run snapshot-check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
```

The history-bound snapshot gate must reproduce its checked-in source/snapshot; it must not regenerate rolling snapshot files from this source.

- [ ] **Step 8: Audit protected scope and commit**

Confirm no generated vector, snapshot, projection, baseline, report, DEBT, package/lock, ADR lifecycle, or release path changed. Stage the five preserved Task 10 files plus the exact current-vector family/test integrations and commit:

```bash
git add docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts docs/spec/vectors/generator/src/current-vectors/case-contracts.ts docs/spec/vectors/generator/src/current-vectors/index.ts docs/spec/vectors/generator/src/current-vectors/semantic-certificates.test.ts docs/spec/vectors/generator/src/current-vectors/semantic-certificates.ts docs/spec/vectors/generator/src/current-vectors/assurance.ts docs/spec/vectors/generator/src/current-vectors/comms.ts docs/spec/vectors/generator/src/current-vectors/control.ts docs/spec/vectors/generator/src/current-vectors/core.ts docs/spec/vectors/generator/src/current-vectors/social.ts docs/spec/vectors/generator/src/current-vectors/workspace.ts docs/spec/vectors/generator/src/current-vectors.test.ts docs/spec/vectors/generator/src/coverage.test.ts
git commit -m "fix: certify executable security authority"
```

- [ ] **Step 9: Request final independent review**

Review the complete addendum range for authority opacity, exact capture, cryptographic/state binding, durability/replay, no false semantic evidence, registry-history integrity, defensive-test framing, protected artifact scope, and all required gates. Fix every Critical/Important finding through the bounded review loop before returning to the parent plan's Task 11.
