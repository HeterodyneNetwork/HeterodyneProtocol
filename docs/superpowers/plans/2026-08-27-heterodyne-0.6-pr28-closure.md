# Heterodyne 0.6 PR 28 Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair PR #28 in place so `heterodyne/0.6.0` has coherent Nostr-first semantics, complete machine artifacts and evaluators, one reproducible latest-only vector snapshot, and green required checks.

**Architecture:** Preserve the useful PR #28 security and privacy work, but reopen ADR-048 until the release is complete. Implement optional Assurance through an opaque Workspace composition boundary, make enrollment finality observation-based, keep NIP-03 advisory, derive freshness from authenticated current state, and replace the quarantined 0.5 authoring catalog with current 0.6 vector modules before authoring the final snapshot.

**Tech Stack:** TypeScript 5.9, Vitest 4, AJV/draft-07 JSON Schema, `@noble/curves` BIP-340/Ed25519, JCS, CommonMark, the generator snapshot orchestrator, and the TypeScript conformance package.

**Spec:** `docs/superpowers/specs/2026-08-27-heterodyne-0.6-pr28-closure-design.md`

## Global Constraints

- Execute from an isolated worktree based on PR #28 head `447d34b68efb768748b138d7d1fac6c4e1fc4a2d`, with the approved design and this plan applied before Task 1.
- Keep ADR-048 Proposed and live until Task 10; no earlier task may archive or accept it.
- The active Nostr key is a complete baseline identity. Assurance is optional for Core, Comms, Control, Social, and Workspace.
- Preserve the family layering map: Core has no dependencies; Assurance and Comms depend on Core; Control and Social depend on Core+Comms; Workspace may depend on Core+Comms+Control+Social. Control never depends on Workspace.
- `first_version` means first introduction. Existing entries keep their prior value; only new 0.6 entries use `heterodyne/0.6.0`.
- NIP-03 is advisory only. It never determines enrollment, permanent rejection, signature time, publication time, completeness, or precise wall-clock time.
- `max_checkpoint_age_seconds` retains a 300-second ceiling. `authorization_view_max_age` is independently signed, defaults to 300 seconds, and accepts integers from 1 through 86400.
- Keep the committed 0.5 vector snapshot unchanged through Task 8. Replace it exactly once in Task 9; do not commit parallel 0.5 and 0.6 snapshot trees.
- Do not edit `research/sources/`, tag a release, merge the PR, or push during implementation tasks.
- Security tests are local defensive negative-conformance tests. They must not contact live relays, use real credentials, or emit reusable exploit tooling.
- Every task uses strict TDD: observe the named RED, implement the smallest coherent change, run focused GREEN, review the diff, then commit.

---

### Task 1: Reopen the release lifecycle and supersede the incomplete plan

**Files:**
- Rename: `docs/adr/archive/2026-08-26-048-security-review-remediation.md` -> `docs/adr/2026-08-26-048-security-review-remediation.md`
- Modify: `docs/adr/2026-08-26-048-security-review-remediation.md`
- Modify: `docs/superpowers/specs/2026-08-26-security-review-remediation-design.md`
- Modify: `docs/superpowers/plans/2026-08-26-security-review-remediation.md`
- Modify: `CHANGELOG.md`
- Test: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: the approved closure design.
- Produces: an honest Proposed lifecycle state that remains in force through Task 9.

- [ ] **Step 1: Add a failing lifecycle test**

Add beside the existing ADR lifecycle assertions:

```ts
it("keeps ADR-048 proposed while the 0.6 closure matrix is incomplete", () => {
  const live = resolve(repositoryRoot,
    "docs/adr/2026-08-26-048-security-review-remediation.md");
  const archived = resolve(repositoryRoot,
    "docs/adr/archive/2026-08-26-048-security-review-remediation.md");
  expect(existsSync(live)).toBe(true);
  expect(existsSync(archived)).toBe(false);
  expect(readFileSync(live, "utf8")).toMatch(/\*\*Status:\*\* Proposed/);
  expect(read("CHANGELOG.md")).toMatch(/heterodyne\/0\.6\.0 \(draft\)/);
});
```

- [ ] **Step 2: Run focused RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: FAIL because ADR-048 is archived and Accepted.

- [ ] **Step 3: Restore Proposed state**

Move ADR-048 to `docs/adr/`, set `**Status:** Proposed`, remove acceptance-only claims, and state that acceptance requires Task 10's exact matrix. Change the changelog heading to `heterodyne/0.6.0 (draft)` and remove language claiming vectors may remain deferred.

Add below the titles of the old design and plan:

```markdown
> **Superseded before merge:** The approved closure design and implementation
> plan dated 2026-08-27 replace this artifact where they differ. In particular,
> vectors are required, Workspace Assurance is optional, NIP-03 is advisory,
> and existing registry `first_version` values retain their history.
```

- [ ] **Step 4: Run focused GREEN and record remaining family failures**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: PASS.

Run: `npm --prefix docs/spec/vectors/generator run family:check`

Expected: still FAIL only on the known version/dependency mismatches; record them for Tasks 2 and 7.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md docs/adr docs/superpowers/specs/2026-08-26-security-review-remediation-design.md docs/superpowers/plans/2026-08-26-security-review-remediation.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "docs: reopen ADR 048 pending complete remediation"
```

---

### Task 2: Restore family layering and define the optional Workspace policy shape

**Files:**
- Modify: `docs/spec/heterodyne.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/schemas/workspace/workspace-policy-v1.schema.json`
- Modify: `docs/spec/vectors/generator/src/workspace-schemas.ts:92-123`
- Test: `docs/spec/vectors/generator/src/family.test.ts`
- Test: `docs/spec/vectors/generator/src/workspace-schema.test.ts`

**Interfaces:**
- Produces: optional closed `workspace-policy-v1.assurance` and dependency-clean prose.
- Consumed by: Task 3's Workspace composition evaluator and Task 8 vectors.

- [ ] **Step 1: Add family and schema RED tests**

```ts
it("keeps Assurance optional and forbids Control-to-Workspace authority", () => {
  expect(DOCUMENT_LAYERING.workspace).not.toContain("assurance");
  expect(DOCUMENT_LAYERING.control).not.toContain("workspace");
  expect(() => assertAllowedDependency("workspace", "assurance")).toThrow();
  expect(() => assertAllowedDependency("control", "workspace")).toThrow();
});
```

```ts
it("accepts bare-key policy and one exact optional Assurance profile", () => {
  const bare = values["workspace-policy-v1"];
  expect(validate("workspace-policy-v1", bare)).toBeNull();
  const assurance = {
    profile: "heterodyne.workspace.assurance.v1",
    inception_event_id: "a".repeat(64),
    required_state: "verified",
  };
  expect(validate("workspace-policy-v1", { ...bare, assurance })).toBeNull();
  expect(validate("workspace-policy-v1", {
    ...bare, assurance: { ...assurance, cold_root: "b".repeat(64) },
  })).toMatch(/additionalProperties/);
});
```

- [ ] **Step 2: Run RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/family.test.ts src/workspace-schema.test.ts`

Expected: optional schema acceptance fails; `family:check` still reports the PR's Workspace-to-Assurance and Control-to-Workspace references.

- [ ] **Step 3: Correct normative ownership**

Make the top-level and Core composition text say bare-key Workspace is baseline and Assurance is optional. Delete “enroll before you incorporate.” Control owns generic authorization/recovery; Workspace references only allowed Control anchors.

Workspace must say:

```markdown
A Workspace MAY be created and operated with its active Nostr persona key and
no Assurance claim. A Workspace policy MAY activate the closed
`heterodyne.workspace.assurance.v1` profile after the active key has a
window-complete verified enrollment. Absence of that profile is baseline, not
an error.
```

- [ ] **Step 4: Generate the optional schema**

Add this optional property without adding it to the required list:

```ts
assurance: closed(
  ["profile", "inception_event_id", "required_state"],
  {
    profile: { const: "heterodyne.workspace.assurance.v1" },
    inception_event_id: h64,
    required_state: { const: "verified" },
  },
),
```

Run: `npm --prefix docs/spec/vectors/generator run workspace-schemas -- "$PWD"`

Expected: the JSON schema changes and the source/JSON parity test passes.

- [ ] **Step 5: Run GREEN and commit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/family.test.ts src/workspace-schema.test.ts src/docs-lint.test.ts`

Expected: PASS.

Run: `npm --prefix docs/spec/vectors/generator run family:check`

Expected: no `forbidden-dependency` issue; only the Task 7 version mismatch remains.

```bash
git add docs/spec/heterodyne.md docs/spec/heterodyne-core.md docs/spec/heterodyne-control.md docs/spec/heterodyne-workspace.md docs/spec/schemas/workspace/workspace-policy-v1.schema.json docs/spec/vectors/generator/src/workspace-schemas.ts docs/spec/vectors/generator/src/family.test.ts docs/spec/vectors/generator/src/workspace-schema.test.ts
git commit -m "spec: keep Workspace Assurance optional"
```

---

### Task 3: Enforce optional Workspace Assurance without a downgrade path

**Files:**
- Create: `docs/spec/vectors/generator/src/workspace-assurance.ts`
- Create: `docs/spec/vectors/generator/src/workspace-assurance.test.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.ts:93-146,663-780`
- Modify: `docs/spec/vectors/generator/src/workspace.test.ts`
- Modify: `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/registry/reason-codes.json`

**Interfaces:**
- Produces `WorkspaceAssuranceAuthority`, `createWorkspaceAssuranceAuthority(config)`, and `evaluateWorkspaceAssuranceTransition(authority, input)`.
- Consumes embedding callbacks only; it does not import Assurance internals or create a normative document dependency.

- [ ] **Step 1: Write the failing table**

Define this constructor contract in the test:

```ts
type WorkspaceAssuranceConfig = Readonly<{
  trusted_now: () => number;
  resolve_verified_enrollment: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    evaluated_at: number;
  }>) => unknown;
  authorize_removal: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    transition_digest: string;
    evaluated_at: number;
  }>) => unknown;
}>;
```

Cover bare-to-bare, verified activation, pending activation, stale continued profile, active-key-only removal, dual-authorized removal, exact transition digest, callback identity capture, proxy/accessor results, and caller-supplied `{state:"verified"}`.

- [ ] **Step 2: Run RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/workspace-assurance.test.ts`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the opaque authority**

Use module-private `WeakMap` state. Capture all three callbacks from their own data descriptors once. Reject proxy/accessor/open callback results.

Enrollment succeeds only for:

```ts
{
  state: "verified",
  active_key: workspace_key,
  inception_event_id,
  evaluated_at,
}
```

Removal succeeds only for `{authorized:true, transition_digest, evaluated_at}` matching the same JCS transition digest and trusted clock sample. Return `workspace-assurance-state-required` for missing, stale, mismatched, or unilateral downgrade cases.

- [ ] **Step 4: Compose into current Workspace state**

Store the optional closed profile in `WorkspaceCurrentStateRecord`. Add an optional opaque authority to resolver configuration. Revalidate it at state resolution and immediately before every security-sensitive authority mutation. A bare policy never requires the authority. Public requests never carry a cold root, state label, proof boolean, or evaluation time.

- [ ] **Step 5: Register and specify the reason**

Replace `workspace-governance-assurance-required` with `workspace-assurance-state-required`, owned by Workspace, first introduced in 0.6, and anchored at `workspace-optional-assurance`. Specify the gated mutation class and exact dual-authority removal digest.

- [ ] **Step 6: Run GREEN and commit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/workspace-assurance.test.ts src/workspace.test.ts src/workspace-schema.test.ts src/registry.test.ts`

Expected: PASS.

Run: `npm --prefix docs/spec/vectors/generator run build:current`

Expected: PASS.

```bash
git add docs/spec/vectors/generator/src/workspace-assurance.ts docs/spec/vectors/generator/src/workspace-assurance.test.ts docs/spec/vectors/generator/src/workspace.ts docs/spec/vectors/generator/src/workspace.test.ts docs/spec/heterodyne-workspace.md docs/spec/registry/reason-codes.json
git commit -m "spec: enforce optional Workspace Assurance safely"
```

---

### Task 4: Keep future-date quarantine and make NIP-03 advisory only

**Files:**
- Create: `docs/spec/vectors/generator/src/replaceable-selection.ts`
- Create: `docs/spec/vectors/generator/src/replaceable-selection.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.ts:116-135`
- Modify: `docs/spec/vectors/generator/src/social-events.test.ts`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/spec/registry/{kinds,features,reason-codes,security-invariants}.json`
- Modify: `docs/spec/extensions/nips/README.md`
- Modify: `docs/security/threat-model.md`

**Interfaces:**
- Produces `createReplaceableSelectionAuthority({trusted_now})` and `selectCurrentReplaceableEvent(authority, candidates)`.
- Removes `core.ots-anchor.v1`, `CORE-I-CREATED-AT-REFUTATION`, and `core-created-at-refuted` from Heterodyne authority.

- [ ] **Step 1: Write defensive selection RED tests**

```ts
it("quarantines then reconsiders at the 900-second boundary", () => {
  let now = 1_000;
  const authority = createReplaceableSelectionAuthority({ trusted_now: () => now });
  const future = signedReplaceable({ created_at: 1_901 });
  expect(selectCurrentReplaceableEvent(authority, [future])).toEqual({
    selected: null,
    quarantined: [{ event_id: future.id, reason_code: "core-created-at-premature" }],
  });
  now = 1_001;
  expect(selectCurrentReplaceableEvent(authority, [future]).selected?.id).toBe(future.id);
});
```

Also prove advisory kind-1040 evidence cannot change selection, an uncertain/throwing clock fails closed, source events are immutable snapshots, and lowest ID wins equal `created_at`.

- [ ] **Step 2: Run RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/replaceable-selection.test.ts src/social-events.test.ts`

Expected: FAIL because future candidates currently enter Social selection and no shared authority exists.

- [ ] **Step 3: Implement shared current selection**

Capture the trusted clock callback once. Verify and snapshot each NIP-01 event before sorting. Quarantine `created_at > now + 900` with `core-created-at-premature`; quarantine is not absorbing and is reconsidered on the next call. Return only verified frozen events. Migrate Social replaceable selection to the helper.

- [ ] **Step 4: Remove NIP-03 protocol authority**

Delete the PR's permanent-refutation rule, enrollment tiebreak, Heterodyne OTS feature, invariant, reason, strict-profile membership, and kind-1040 Heterodyne profile. Replace them with a Core interoperability note: an independent NIP-03 implementation may display advisory “commitment existed no later than a confirmed block” evidence, but Heterodyne selection and Assurance ignore it.

Keep `core-created-at-premature` and its non-permanent 900-second quarantine.

- [ ] **Step 5: Run GREEN and commit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/replaceable-selection.test.ts src/social-events.test.ts src/registry.test.ts src/docs-lint.test.ts`

Expected: PASS and zero live occurrences of the removed OTS feature/invariant/reason outside superseded or historical documents.

```bash
git add docs/spec/vectors/generator/src/replaceable-selection.ts docs/spec/vectors/generator/src/replaceable-selection.test.ts docs/spec/vectors/generator/src/social-events.ts docs/spec/vectors/generator/src/social-events.test.ts docs/spec/heterodyne-core.md docs/spec/heterodyne-social.md docs/spec/registry docs/spec/extensions/nips/README.md docs/security/threat-model.md
git commit -m "spec: make timestamp evidence advisory only"
```

---

### Task 5: Implement authenticated enrollment-window and contest semantics

**Files:**
- Modify: `docs/spec/heterodyne-assurance.md`
- Modify: `docs/spec/schemas/assurance/enrollment-contest-v1.schema.json`
- Create: `docs/spec/schemas/assurance/enrollment-observation-receipt-v1.schema.json`
- Modify: `docs/spec/registry/{kinds,objects,proof-domains,reason-codes,security-invariants}.json`
- Modify: `docs/spec/vectors/generator/src/assurance.ts:31-228,503-620`
- Test: `docs/spec/vectors/generator/src/assurance.test.ts`
- Test: `docs/spec/vectors/generator/src/schema.test.ts`
- Test: `docs/spec/vectors/generator/src/registry.test.ts`

**Interfaces:**
- Produces `AssuranceEnrollmentObservationAuthority`, `createAssuranceEnrollmentObservationAuthority(config)`, and `evaluateEnrollmentEligibility(authority, {inception, acceptance})`.
- Produces `pending | verified | contested` without weakening reciprocal cryptographic validation.

- [ ] **Step 1: Add contest/schema RED tests**

Use this exact body:

```ts
const contestBody = {
  profile: "heterodyne.assurance.enrollment-contest.v1",
  spec_version: "heterodyne/0.6.0",
  inception_event_id: inception.id,
  cold_root: COLD_KEY,
};
```

Require kind 31006, outer active-key signature, exact tags `[["d", inception.id], ["p", COLD_KEY]]`, canonical JSON, and repeated-field equality. Reject generic stamping, extra tags/members, wrong active key, wrong cold root, and wrong inception.

- [ ] **Step 2: Add enrollment-state RED tests**

Cover window ages 604799/604800, timely contest, timely competing inception, late contest after authoritative pin, insufficient/duplicate/unconfigured witness weight, forged receipt, backdated `created_at`, caller time/state, callback proxy/accessor, and carrier replay of one event ID.

The core table is:

```ts
it.each([
  [604_799, [], "pending", "assurance-enrollment-pending-window"],
  [604_800, [], "verified", null],
  [604_800, [timelyContest], "contested", "assurance-enrollment-contested"],
  [604_800, [timelyCompetitor], "contested", "assurance-enrollment-contested"],
])("evaluates window age %i", async (age, conflicts, state, reason) => {
  const result = await evaluateEnrollmentEligibility(
    observationAuthorityAt({ age, conflicts }),
    validEnrollmentPair(),
  );
  expect(result).toMatchObject({ state, reason });
});
```

- [ ] **Step 3: Define signed witness observation receipts**

Create a closed schema with profile/spec version, inception ID, active key, cold root, first/last observation time, `conflict_free:true`, witness key, and signature. Register proof domain `heterodyne-assurance-enrollment-observation-v1`; BIP-340 signs the domain-separated JCS digest of every member except `signature`. Count each configured witness once using inception weight/threshold policy.

- [ ] **Step 4: Implement the opaque observation authority**

Capture `{trusted_now, load_evidence}` once in a module-private `WeakMap`. `load_evidence(inception_event_id)` returns one exact snapshotted structure containing local first observation, witness receipts, contests, competing inceptions, and optional authoritative pin. Verify every event and receipt. Never use event `created_at` to establish the window.

A verified pin is absorbing against later initial-enrollment evidence. Only existing succession/downgrade evaluators can change it.

- [ ] **Step 5: Align registry and prose**

Set kind 31006 discriminator to `content.profile=heterodyne.assurance.enrollment-contest.v1` and `stamping:false`. Register the receipt schema/object/domain, retain pending/contested reasons, and make `ASSURANCE-I-ENROLLMENT-WINDOWED` observation-based without OTS.

- [ ] **Step 6: Run GREEN and commit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/assurance.test.ts src/schema.test.ts src/registry.test.ts`

Expected: PASS.

Run: `npm --prefix docs/spec/vectors/generator run build:current`

Expected: PASS.

```bash
git add docs/spec/heterodyne-assurance.md docs/spec/schemas/assurance docs/spec/registry docs/spec/vectors/generator/src/assurance.ts docs/spec/vectors/generator/src/assurance.test.ts docs/spec/vectors/generator/src/schema.test.ts docs/spec/vectors/generator/src/registry.test.ts
git commit -m "spec: authenticate Assurance enrollment finality"
```

---

### Task 6: Bind checkpoint and authorization-view freshness independently

**Files:**
- Create: `docs/spec/vectors/generator/src/authorization-freshness.ts`
- Create: `docs/spec/vectors/generator/src/authorization-freshness.test.ts`
- Modify: `docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json`
- Modify: `docs/spec/vectors/generator/src/token-status.ts:57-90,336-390,532-553`
- Modify: `docs/spec/vectors/generator/src/token-status.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts:805-865`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.test.ts`
- Modify: `docs/spec/vectors/generator/src/control-profile.ts:180-205,320-445`
- Modify: `docs/spec/vectors/generator/src/control-profile.test.ts`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces opaque `CurrentAuthorizationView` from a verified manifest and authoritative ledger checkpoint.
- Control consumes the opaque view instead of caller-provided freshness booleans/ages.

- [ ] **Step 1: Add schema RED tests**

Add required `authorization_view_max_age:300`. Assert acceptance at 300 and 86400; reject 0, 86401, non-integer, missing, and extra members. Retain independent rejection above 300 for `max_checkpoint_age_seconds`.

Run: `npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts src/token-status.test.ts`

Expected: FAIL because the closed schema omits the new field.

- [ ] **Step 2: Add effect-time RED tests**

Test both exact boundaries, stale transition between prepare/effect, manifest substitution, caller `now`, caller success boolean, and conflicting current ledger view:

```ts
it.each([
  [300, 300, "accept"],
  [301, 300, "oidc-checkpoint-stale"],
  [86_400, 86_400, "accept"],
  [86_401, 86_400, "control-authorization-view-stale"],
])("enforces independent ages", async (age, max, expected) => {
  const result = await evaluateAuthorizationFreshness(
    freshnessAuthorityAtAge(age),
    signedManifest({ authorization_view_max_age: max }),
  );
  expect(result.reason ?? result.verdict).toBe(expected);
});
```

- [ ] **Step 3: Update the signed manifest**

Add `authorization_view_max_age` to the JSON schema and `ContinuityManifestBody`. `continuityProofPayload` already signs the complete unsigned object; add no exception. `validateManifestIntrinsic` independently enforces both numeric ranges.

- [ ] **Step 4: Implement the freshness authority**

Construct with `{trusted_now, load_current_view}`. The loader binding is `{repository_rid, persona_key, manifest_digest}` and its result contains exact manifest plus authoritative ledger state. Re-run `resolveIssuerContinuity`, enforce both ages from `authority.checkpoint.observed_at`, and mint a module-private branded view. `revalidateAuthorizationViewAtEffect` reloads and compares exact manifest/checkpoint immediately before effect.

- [ ] **Step 5: Remove caller-authored Control freshness**

Replace `authorization_view_authenticated`, `authorization_view_conflicted`, and `authorization_view_age_seconds` with the opaque view in token/enrollment inputs. Revalidate immediately before token issuance or durable enrollment effect.

- [ ] **Step 6: Align prose, run GREEN, and commit**

Run: `npm --prefix docs/spec/vectors/generator test -- src/authorization-freshness.test.ts src/token-status.test.ts src/claim-ledger.test.ts src/control-profile.test.ts src/schema.test.ts`

Expected: PASS.

Run: `npm --prefix docs/spec/vectors/generator run build:current`

Expected: PASS.

```bash
git add docs/spec/vectors/generator/src/authorization-freshness.ts docs/spec/vectors/generator/src/authorization-freshness.test.ts docs/spec/vectors/generator/src/token-status.ts docs/spec/vectors/generator/src/token-status.test.ts docs/spec/vectors/generator/src/claim-ledger.ts docs/spec/vectors/generator/src/claim-ledger.test.ts docs/spec/vectors/generator/src/control-profile.ts docs/spec/vectors/generator/src/control-profile.test.ts docs/spec/vectors/generator/src/schema.test.ts docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md
git commit -m "spec: bind authorization freshness to current state"
```

---

### Task 7: Close registry history, strict profiles, and the atomic 0.6 cutover

**Files:**
- Modify: `docs/spec/vectors/generator/src/family.ts:11`
- Modify: live current generator sources/tests containing current 0.5 stamps; exclude `snapshot-*`, `legacy-*`, retired KEL files, and historical negative fixtures
- Modify: live specifications, schemas, release metadata, README, glossary, and threat model
- Modify: `docs/spec/registry/{features,kinds,objects,proof-domains,reason-codes,security-invariants,manifest}.json`
- Modify: `docs/spec/conformance/src/subjects/types.ts` and current conformance fixtures
- Test: `docs/spec/vectors/generator/src/{family,registry,docs-lint}.test.ts`
- Test: `docs/spec/conformance/src/gates/invariant-completeness.test.ts`

**Interfaces:**
- Produces one current family version, registry revision/digest, and complete strict-profile closure for Task 8.

- [ ] **Step 1: Add registry-history and strict-profile RED tests**

Assert an existing profile retains `heterodyne/0.5.0`, the new contest profile uses 0.6, and strict closures contain:

```ts
expect(strict("heterodyne-assurance-strict-v1").adds_invariants)
  .toContain("ASSURANCE-I-ENROLLMENT-WINDOWED");
expect(strict("heterodyne-comms-strict-v1").adds_invariants)
  .toContain("COMMS-I-TIER3-CONFINED");
expect(strict("heterodyne-workspace-strict-v1").adds_invariants)
  .toContain("WORKSPACE-I-OPTIONAL-ASSURANCE");
```

`WORKSPACE-I-OPTIONAL-ASSURANCE` replaces `WORKSPACE-I-GOVERNANCE-ASSURED` and states that bare-key operation is valid while an activated profile cannot be downgraded unilaterally.

- [ ] **Step 2: Run RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/family.test.ts src/docs-lint.test.ts`

Expected: failures for bulk-rewritten history, missing Assurance strict profile, incomplete Comms/Workspace closures, and generator family 0.5.

- [ ] **Step 3: Restore historical `first_version` values**

Compare PR entries by stable ID against `origin/main`. Copy `first_version` from main for every pre-existing entry; retain 0.6 only for IDs absent from main. Check in a closed `NEW_0_6_REGISTRY_IDS` test table so another global rewrite fails.

- [ ] **Step 4: Add complete strict profiles**

Add `heterodyne-assurance-strict-v1` with `requires_profiles:["heterodyne-core-strict-v1"]` and every Assurance baseline invariant. Add tier-3 confinement to Comms strict and optional-Assurance downgrade resistance to Workspace strict. Update README, glossary, threat-model mirrors, and conformance fixtures.

- [ ] **Step 5: Cut live current semantics to 0.6**

Set `FAMILY_VERSION="0.6.0"`. Replace version strings only in current live sources, live schemas/specifications, current conformance fixtures, and release metadata. Do not alter snapshot adapters or intentional 0.5 rejection fixtures.

Audit with:

```bash
git grep -n 'heterodyne/0\.5\.0\|heterodyne:0\.5\.0#' -- \
  ':!docs/adr/archive/**' ':!docs/superpowers/**' \
  ':!docs/spec/vectors/generator/src/snapshot-*' \
  ':!docs/spec/vectors/generator/src/legacy-*'
```

Expected: only named negative-conformance fixtures, each documenting why 0.5 must reject.

- [ ] **Step 6: Author the registry digest once**

Run: `npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 15`

Expected: revision 15 is preserved and the canonical digest matches `computeRegistryDigest`.

- [ ] **Step 7: Run current GREEN and commit**

Run: `npm --prefix docs/spec/vectors/generator run draft:check`

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`

Expected: both PASS with no forbidden dependency or version mismatch.

```bash
git add docs CHANGELOG.md README.md
git commit -m "spec: close the heterodyne 0.6 family registry"
```

---

### Task 8: Replace historical authoring with a current 0.6 vector catalog

**Files:**
- Create: `docs/spec/vectors/generator/src/current-vectors/{types,core,assurance,comms,control,social,workspace,index}.ts`
- Create: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/author.ts:13-61`
- Modify: `docs/spec/vectors/generator/src/coverage.ts:7-125`
- Modify: `docs/spec/vectors/generator/src/types.ts:19-48`
- Modify: `docs/spec/vectors/generator/src/schema.ts:17-139`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`
- Modify: `docs/spec/conformance/src/artifacts.ts`
- Modify: `docs/spec/conformance/src/artifacts.test.ts`
- Modify: `docs/spec/vectors/generator/tsconfig.current.json`
- Modify: `docs/spec/vectors/generator/package.json`

**Interfaces:**
- Produces `buildCurrentVectors(): Promise<AuthoredVector[]>` with no dependency on `topics*`, `snapshot*`, `legacy*`, or retired KEL modules.
- Produces vector schema 3.0.0 with invariant and reason traceability.

- [ ] **Step 1: Add an import-boundary RED test**

Build the TypeScript dependency graph rooted at `current-vectors/index.ts` and reject:

```ts
const forbidden = [
  /\/topics[^/]*\.ts$/,
  /\/snapshot[^/]*\.ts$/,
  /\/legacy[^/]*\.ts$/,
  /\/kel(?:-replay)?\.ts$/,
  /\/keri-materialized\.ts$/,
];
```

Also assert `author.ts` imports `buildCurrentVectors`, not `buildSnapshotCompatibleVectors`.

Run: `npm --prefix docs/spec/vectors/generator test -- src/current-vectors.test.ts`

Expected: FAIL because the catalog is absent and author still uses the 0.5 adapter runtime.

- [ ] **Step 2: Add vector schema 3.0.0 traceability**

Every raw vector carries sorted unique arrays:

```ts
type VectorTraceability = {
  invariants: string[];
  reason_codes: string[];
};
```

Accept vectors may have no reasons; reject vectors contain the exact expected registered reason. `invariants` is non-empty. Update generator validation, snapshot packaging, conformance parsing, and coverage rendering together.

`schema.ts` is the current schema source. Do **not** edit the committed
`docs/spec/vectors/schema/vector.schema.json` in this task. `author.ts` writes
the 3.0.0 schema into temporary output, and Task 9 installs that generated
schema atomically with the rest of the replacement snapshot. Until then, the
conformance loader must discriminate the committed historical 2.x snapshot
from temporary 3.0.0 artifacts; 3.0.0 requires traceability, while historical
2.x parsing does not manufacture it.

- [ ] **Step 3: Create the catalog interface**

```ts
export type CurrentVectorCase = Readonly<{
  relativePath: string;
  vector_id: string;
  owner_document: DocumentId;
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
  description: string;
  direction: VectorDirection;
  input: Readonly<Record<string, unknown>>;
  expected_output: Readonly<Record<string, unknown>>;
}>;
```

The shared helper injects `vector_schema_version:"3.0.0"` and `spec_version:QUALIFIED_VERSION`; family modules cannot hard-code either.

- [ ] **Step 4: Author six current family modules**

Each module imports only live evaluators and deterministic fixtures. Mandatory new cases are:

- Core: future quarantine, exact 900-second acceptance, equal-time lowest ID, advisory NIP-03 ignored.
- Assurance: pending at `W-1`, verified at `W`, contest, competitor, forged contest, late warning/no unpin, witness threshold pass/fail.
- Comms: checkpoint boundary/stale, authorization-view 300/86400 boundaries, malformed maximum, tier-3 recipient confinement.
- Control: opaque view accepted, caller booleans rejected, view stale at effect.
- Social: source-neutral selection uses Core quarantine and preserves vanilla authorship.
- Workspace: bare-key baseline, verified/pending activation, unilateral removal reject, dual removal accept, mutation revalidation.

Port every remaining current strict invariant from live semantic fixtures; do not copy retired KEL or cold-root-primary cases.

- [ ] **Step 5: Make coverage mechanically complete**

Add and assert:

```ts
expect(findInvariantCoverageIssues(registry, coverage)).toEqual([]);
expect(findReasonCoverageIssues(registry, coverage)).toEqual([]);
expect(findProfileCoverageIssues(registry, coverage)).toEqual([]);
```

Every strict invariant needs a vector owned by its document. Every current baseline semantic rejection needs a negative vector. Non-wire administrative reasons may be omitted only through a closed audited exclusion array with a specific justification per code.

- [ ] **Step 6: Switch author and coverage to current catalog**

Replace snapshot adapter/runtime imports in current `author.ts` and `coverage.ts`. Leave old adapter files untouched until Task 9 replaces the 0.5 snapshot, but remove them from current authoring and coverage.

- [ ] **Step 7: Prove current authoring in a temporary directory**

```bash
tmp_vectors="$(mktemp -d /tmp/heterodyne-0.6-vectors.XXXXXX)"
npm --prefix docs/spec/vectors/generator run author -- "$tmp_vectors"
npm --prefix docs/spec/vectors/generator run verify -- "$tmp_vectors"
case "$tmp_vectors" in
  /tmp/heterodyne-0.6-vectors.*) find "$tmp_vectors" -depth -delete ;;
  *) echo "refusing to delete unexpected temporary path" >&2; exit 1 ;;
esac
```

Expected: PASS; all vectors are current 0.6 and the repository snapshot is unchanged.

Run: `npm --prefix docs/spec/vectors/generator run draft:check`

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add docs/spec/vectors/generator docs/spec/conformance/src
git commit -m "test: author current heterodyne 0.6 vectors"
```

---

### Task 9: Reconcile the latest-only 0.6 snapshot

**Files:**
- Replace generated snapshot-owned files under `docs/spec/vectors/`
- Replace generated `docs/spec/conformance/baselines/`
- Replace generated `docs/spec/conformance/report.json`
- Replace generated `docs/spec/conformance/DEBT.md` only if produced by authoring
- Modify snapshot tests only for intentional schema/count assertions; never hand-edit generated bytes

**Interfaces:**
- Consumes: exact clean Task 8 source commit.
- Produces: one manifest pinned to that commit with vector schema 3.0.0.

- [ ] **Step 1: Establish the clean source commit**

```bash
test -z "$(git status --porcelain=v1)"
source_commit="$(git rev-parse HEAD)"
npm --prefix docs/spec/vectors/generator run draft:check
```

Expected: clean status and PASS.

- [ ] **Step 2: Author the replacement snapshot**

Run: `npm --prefix docs/spec/vectors/generator run snapshot-author -- "$PWD" "$source_commit"`

Expected: transactional replacement; `snapshot.json.source_commit` equals `$source_commit`; no parallel 0.5 tree.

- [ ] **Step 3: Audit generated output**

```bash
jq -r '.source_commit, .vector_schema_version, .vector_count' docs/spec/vectors/snapshot.json
git diff --check
git status --short
```

Expected: exact source commit, schema 3.0.0, nonzero count, six owners including Assurance, and changes limited to generated snapshot/projection paths.

- [ ] **Step 4: Commit and verify from history**

```bash
git add docs/spec/vectors docs/spec/conformance/baselines docs/spec/conformance/report.json docs/spec/conformance/DEBT.md
git commit -m "test: reconcile the heterodyne 0.6 vector snapshot"
```

Run: `npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"`

Expected: PASS, reporting Task 8 source and Task 9 snapshot commits.

Run: `npm --prefix docs/spec/vectors/generator test -- src/snapshot-lifecycle.test.ts src/snapshot-orchestrator.test.ts src/snapshot-manifest.test.ts`

Expected: PASS.

---

### Task 10: Holistic review, final acceptance, and PR readiness

**Files:**
- Rename: `docs/adr/2026-08-26-048-security-review-remediation.md` -> `docs/adr/archive/2026-08-26-048-security-review-remediation.md`
- Modify: archived ADR-048, `CHANGELOG.md`, and `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify only files required by independently confirmed review findings

**Interfaces:**
- Consumes: complete source and committed 0.6 snapshot.
- Produces: accepted ADR and an exact PR candidate with green required checks.

- [ ] **Step 1: Run the complete pre-acceptance matrix serially**

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
test -z "$(git status --porcelain=v1)"
```

Expected: every command exits 0. Do not accept ADR-048 if any command fails or times out.

- [ ] **Step 2: Request independent specification and security reviews**

Review `origin/main...HEAD` against the approved design. Require explicit answers for active-key baseline identity, optional Workspace Assurance downgrade resistance, contest/witness replay and backdating, NIP-03 non-authority, independent freshness enforcement, strict invariant/reason coverage, `first_version` preservation, and exact snapshot provenance.

Expected: no unresolved Critical or Important findings. Confirm every finding with a focused defensive RED before changes, and re-review after each fix round.

- [ ] **Step 3: Add final lifecycle RED**

Change Task 1's test to require archived path, absent live path, `Status: Accepted`, and accepted changelog entry. Run it before moving the ADR.

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: exactly the lifecycle assertion fails.

- [ ] **Step 4: Accept ADR-048 and commit**

Move ADR-048 to the archive and record exact evidence: current test count, vector count, source commit, snapshot commit, conformance count, registry revision/digest, and review verdict. Change changelog draft to accepted. Keep the old 2026-08-26 design/plan marked superseded.

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`

Expected: PASS.

```bash
git add CHANGELOG.md docs/adr docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "docs: accept complete heterodyne 0.6 remediation"
```

- [ ] **Step 5: Run the exact post-acceptance matrix**

Repeat every Step 1 command on the acceptance commit. Record fresh hashes/counts; do not reuse pre-commit evidence.

Expected: all green, clean worktree, and no live normative ADR references.

- [ ] **Step 6: Update PR #28 and verify GitHub**

Push the repaired branch to the existing PR head, then run:

```bash
gh pr checks 28 --watch
gh pr view 28 --json headRefOid,mergeable,reviewDecision,statusCheckRollup
```

Expected: GitHub head equals local `HEAD`, required checks pass, requested changes are resolved, and the PR is mergeable. Report readiness; do not merge without a separate explicit merge instruction.
