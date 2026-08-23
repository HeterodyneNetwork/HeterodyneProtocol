# Independent Conformance Harness and CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independent, ratcheted conformance harness and make its read-only gate the shared GitHub and Radicle acceptance path.

**Architecture:** A standalone TypeScript package reads only committed protocol artifacts and never imports the vector generator. Corpus-wide gates, an explicitly scoped Core signed-event checker, deterministic debt projections, and one shell entry point keep both intake paths identical.

**Tech Stack:** Node.js 22, TypeScript 5.9, Vitest 4, AJV 8, `@noble/curves`, `@noble/hashes`, Bash, GitHub Actions, Radicle native YAML.

**Spec:** `docs/superpowers/specs/2026-08-15-conformance-harness-independence-design.md`

## Global Constraints

- Keep family version `heterodyne/0.5.0` and release status `unreleased`.
- Advance registry revision 12 to 13; keep registry schema `3.0.0`.
- Advance vector schema 1.0.0 to 1.1.0 and regenerate the unreleased corpus.
- The conformance and generator packages must not import each other in either direction.
- Conformance runtime dependencies are limited to Node built-ins, AJV, and required `@noble/*` packages.
- Gate keys are sorted and contain no line numbers, absolute paths, or unstable indexes.
- `check` and CI are read-only; only `baseline-author` and `report-author` write projections.
- Conformance tooling is excluded from the family release manifest; registry/schema/vector changes remain included.
- Use Node 22, no secrets, `contents: read`, no `pull_request_target`, publishing, deployment, push, tag, or remote configuration.

---

### Task 1: Record proposed ADR-045

**Files:**
- Create: `docs/adr/2026-08-15-045-conformance-harness-independence.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the approved design.
- Produces: a proposed non-canonical record and changelog link; no live requirement cites the ADR.

- [ ] **Step 1: Write the proposed ADR**

Use this exact header and decision core:

```markdown
# ADR-045: Independent conformance harness and shared CI gate

**Status:** Proposed
**Date:** 2026-08-15

## Decision

Add a standalone conformance package that imports no generator code, applies
corpus-wide gates, runs explicitly declared Core signed-event checks, and
ratchets measured debt. GitHub and Radicle invoke one read-only shell gate.
Registry revision 13 and vector schema 1.1.0 ship in the same patch; live
specifications and artifacts remain authoritative.
```

Add context, consequences, no-deployment scope, and the acceptance/archive condition.

- [ ] **Step 2: Add the changelog entry**

Under Unreleased, add `Proposed independent conformance CI` linking ADR-045, Core verification, the registry manifest, vector schema, and `docs/spec/conformance/` without duplicating normative rules.

- [ ] **Step 3: Verify and commit**

```bash
rg -n 'Status:.*Proposed|ADR-045' docs/adr/2026-08-15-045-conformance-harness-independence.md CHANGELOG.md
if rg -n 'ADR-045|2026-08-15-045-conformance' docs/spec docs/security AGENTS.md README.md; then exit 1; fi
npm --prefix docs/spec/vectors/generator run family:check
git diff --check
git add docs/adr/2026-08-15-045-conformance-harness-independence.md CHANGELOG.md
git commit -m "docs: propose independent conformance CI decision"
```

Expected: only the proposed record and changelog cite ADR-045; checks pass.

### Task 2: Allocate revision-13 reasons and close rejection schema

**Files:**
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/topics-split.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Regenerate: `docs/spec/vectors/schema/reason-codes.json`
- Regenerate: `docs/spec/vectors/schema/reason-codes.md`
- Regenerate: `docs/spec/vectors/schema/vector.schema.json`
- Regenerate: `docs/spec/vectors/breadcrumbs/002-compromise-rotation-not-produced.json`
- Regenerate: `docs/spec/vectors/**/*.json`
- Regenerate: `docs/spec/releases/family/0.5.0.json`

**Interfaces:**
- Consumes: `authorRegistryRevision(repositoryRoot, 13)` and Core anchors `core-verification`, `core-kel-rotation`.
- Produces: revision 13, four Core reasons, and reason closure for all vector directions.

- [ ] **Step 1: Write failing tests**

```ts
it("allocates independent-checker reasons at revision 13", () => {
  expect(registry.manifest.revision).toBe(13);
  const reasons = new Map(registry.reason_codes.map((entry) => [entry.code, entry]));
  for (const code of [
    "nip01_raw_mismatch", "successor_persona_mismatch",
    "retiring_key_nip05_invalid", "compromise_rotation_breadcrumb_forbidden",
  ]) {
    expect(reasons.get(code)).toMatchObject({
      owner: "core", status: "draft", first_version: "heterodyne/0.5.0",
    });
  }
});

it.each(["consume", "produce", "round-trip"] as const)(
  "requires reason_code on %s rejects",
  (direction) => expect(() => validateVectorOrThrow({
    ...valid("core"), direction, expected_output: { verdict: "reject" },
  })).toThrow(/reason_code/),
);
```

Add a docs-lint test requiring the four literal codes at their Core sections.

- [ ] **Step 2: Prove RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts src/docs-lint.test.ts
```

Expected: revision, allocation, prose, and produce-rejection assertions fail.

- [ ] **Step 3: Implement exact allocations and prose**

Add four `draft`, Core-owned, `heterodyne/0.5.0` entries. Use `core-verification` for `nip01_raw_mismatch`; use `core-kel-rotation` for the three breadcrumb codes. Their descriptions must match the design table exactly.

In Core §9 bind missing/mismatched raw input to `nip01_raw_mismatch`. In §4.3.1 bind unrelated successor, repointed NIP-05, and compromise rotation to their exact codes.

Remove the consume-direction condition from `VECTOR_SCHEMA`'s reject rule. Change the breadcrumb vector reason to `compromise_rotation_breadcrumb_forbidden`.

- [ ] **Step 4: Regenerate and verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 13
```

Replace Core's capability-example `registry_sha256` with the new manifest digest, then run:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts src/docs-lint.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/heterodyne-core.md docs/spec/registry docs/spec/vectors docs/spec/releases/family/0.5.0.json
git commit -m "spec: allocate independent conformance reasons"
```

### Task 3: Add vector-schema 1.1 checker declarations

**Files:**
- Modify: `docs/spec/vectors/generator/src/types.ts`
- Modify: `docs/spec/vectors/generator/src/vector-helpers.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/author.test.ts`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/vectors/README.md`
- Regenerate: `docs/spec/vectors/schema/vector.schema.json`
- Regenerate: `docs/spec/vectors/**/*.json`
- Regenerate: `docs/spec/vectors/fixtures.json`
- Regenerate: `docs/spec/releases/family/0.5.0.json`

**Interfaces:**
- Consumes: `baseVector(VectorBody)` and vector schema 1.0.0.
- Produces: `ExpectedTerminalStage`, `ConformanceCheck`, optional `Vector.conformance_checks`, schema 1.1.0.

- [ ] **Step 1: Write failing closed-shape tests**

```ts
const check = {
  profile: "core-signed-event-v1",
  event_pointer: "/input/event",
  nip01_raw_pointer: "/input/nip01_raw",
  expected_terminal_stage: "signature",
};
expect(() => validateVectorOrThrow({
  ...valid("core"), vector_schema_version: "1.1.0", conformance_checks: [check],
})).not.toThrow();
for (const invalid of [
  { ...check, profile: "generator-v1" },
  { ...check, event_pointer: "input/event" },
  { ...check, inferred: true },
]) {
  expect(() => validateVectorOrThrow({
    ...valid("core"), vector_schema_version: "1.1.0", conformance_checks: [invalid],
  })).toThrow();
}
```

- [ ] **Step 2: Prove RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts src/author.test.ts
```

- [ ] **Step 3: Implement types and schema**

```ts
export type ExpectedTerminalStage =
  | "event_structure" | "nip01_raw" | "identifier" | "signature"
  | "persona_resolution" | "version_stamp" | "kel_head"
  | "epoch_authority" | "subtype_nid" | "accept";
export type ConformanceCheck = {
  profile: "core-signed-event-v1";
  event_pointer: string;
  nip01_raw_pointer: string;
  context_pointer?: string;
  expected_terminal_stage: ExpectedTerminalStage;
};
```

Add the optional array to `Vector` and `VectorBody`; set `SCHEMA_VERSION = "1.1.0"`. The JSON Schema uses `uniqueItems`, closed objects, the exact stage enum, and RFC 6901 pattern `^(?:/(?:[^~/]|~[01])*)+$`.

- [ ] **Step 4: Document, regenerate, verify, and commit**

Document the optional non-wire checker metadata in Core §14 and the vector README. Then:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts src/author.test.ts
npm --prefix docs/spec/vectors/generator run check
git diff --check
git add docs/spec/heterodyne-core.md docs/spec/vectors docs/spec/releases/family/0.5.0.json
git commit -m "spec: add explicit conformance checker metadata"
```

Expected: all 498 current vectors use schema 1.1.0 and none declares a check yet.

### Task 4: Build standalone package and safe artifact intake

**Files:**
- Create: `docs/spec/conformance/package.json`, `package-lock.json`, `tsconfig.json`
- Create: `docs/spec/conformance/src/types.ts`
- Create: `docs/spec/conformance/src/json-pointer.ts`, `json-pointer.test.ts`
- Create: `docs/spec/conformance/src/artifacts.ts`, `artifacts.test.ts`, `test-support.ts`
- Modify: `docs/spec/vectors/generator/src/release.test.ts`

**Interfaces:**
- Consumes: family release manifest, registry revision 13, vector schema 1.1.0.
- Produces: `resolveJsonPointer`, `safeRepositoryPath`, `loadCorpus`, `ArtifactCorpus`, `CorpusIssue`.

- [ ] **Step 1: Create package metadata**

Use package name `@heterodyne/conformance`, `private: true`, ESM, and these exact scripts/dependencies; dev dependency ranges match the generator:

```json
{
  "scripts": {
    "build": "tsc --noEmit",
    "test": "vitest run",
    "check": "npm run build && npm test && tsx src/cli.ts check",
    "baseline-author": "tsx src/cli.ts baseline-author",
    "report-author": "tsx src/cli.ts report-author"
  },
  "dependencies": {
    "@noble/curves": "^1.9.7",
    "@noble/hashes": "^1.8.0",
    "ajv": "^8.17.1"
  }
}
```

Copy strict NodeNext compiler settings and run:

```bash
npm --prefix docs/spec/conformance install --package-lock-only
npm --prefix docs/spec/conformance ci
```

- [ ] **Step 2: Write failing pointer/path tests**

```ts
expect(resolveJsonPointer({ "a/b": { "~key": 7 } }, "/a~1b/~0key"))
  .toEqual({ found: true, value: 7 });
for (const pointer of ["", "input/event", "/__proto__/x", "/constructor/prototype"]) {
  expect(() => parseJsonPointer(pointer)).toThrow();
}
for (const path of ["/tmp/x", "../x", "docs//spec", "docs/./spec"]) {
  expect(() => safeRepositoryPath(repositoryRoot, path)).toThrow();
}
```

Write an artifact test whose temporary manifest has one unsafe path and one malformed vector; assert both sorted codes: `invalid-json`, `unsafe-artifact-path`.

- [ ] **Step 3: Prove RED, implement, and verify GREEN**

```bash
npm --prefix docs/spec/conformance test -- src/json-pointer.test.ts src/artifacts.test.ts
```

Implement:

```ts
export type CorpusIssue = { code: string; path: string; message: string };
export type ExpectedTerminalStage =
  | "event_structure"|"nip01_raw"|"identifier"|"signature"
  | "persona_resolution"|"version_stamp"|"kel_head"
  | "epoch_authority"|"subtype_nid"|"accept";
export type ConformanceCheckDocument = {
  profile: "core-signed-event-v1";
  event_pointer: string;
  nip01_raw_pointer: string;
  context_pointer?: string;
  expected_terminal_stage: ExpectedTerminalStage;
};
export type VectorDocument = {
  vector_id: string;
  vector_schema_version: "1.1.0";
  owner_document: "core"|"comms"|"control"|"social"|"workspace";
  spec_version: "heterodyne/0.5.0";
  spec_refs: string[];
  direction: "consume"|"produce"|"round-trip";
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
  conformance_checks?: ConformanceCheckDocument[];
};
export type RegistryDocument = {
  manifest: { revision: 13; schema_version: "3.0.0"; entry_set_sha256: string };
  reason_codes: readonly { code: string }[];
  security_invariants: readonly { id: string; owner: string; feature?: string }[];
};
export type ArtifactCorpus = {
  repositoryRoot: string;
  familyVersion: "heterodyne/0.5.0";
  registryRevision: 13;
  registryDigest: string;
  specifications: ReadonlyMap<string, string>;
  schemas: ReadonlyMap<string, unknown>;
  vectors: readonly { path: string; value: VectorDocument }[];
  fixtures: Record<string, unknown>;
  registry: RegistryDocument;
};
export function loadCorpus(repositoryRoot: string): {
  corpus?: ArtifactCorpus; issues: CorpusIssue[];
};
```

Use `realpathSync` containment, parse readable files independently, reject duplicate vector IDs, and sort issues by code/path/message. Add a release test asserting no artifact path begins `docs/spec/conformance/`.

```bash
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test -- src/json-pointer.test.ts src/artifacts.test.ts
npm --prefix docs/spec/vectors/generator test -- src/release.test.ts
git diff --check
```

- [ ] **Step 4: Commit**

```bash
git add docs/spec/conformance docs/spec/vectors/generator/src/release.test.ts
git commit -m "feat: add independent conformance artifact intake"
```

### Task 5: Implement gates G1-G3

**Files:**
- Create: `docs/spec/conformance/src/gates/types.ts`, `anchors.ts`, `index.ts`
- Create: `docs/spec/conformance/src/gates/anchor-resolution.ts`, `anchor-resolution.test.ts`
- Create: `docs/spec/conformance/src/gates/reason-code-closure.ts`, `reason-code-closure.test.ts`
- Create: `docs/spec/conformance/src/gates/invariant-completeness.ts`, `invariant-completeness.test.ts`

**Interfaces:**
- Consumes: `ArtifactCorpus`.
- Produces: `Gate`, `GateResult`, G1-G3, initial `STATIC_GATES`.

- [ ] **Step 1: Define interfaces and failing keys**

```ts
export type GateId = "G1"|"G2"|"G3"|"G4"|"G5"|"G6"|"G7"|"G8"|"G9"|"G10"|"G11";
export type GateResult = { id: GateId; name: string; failures: string[] };
export type Gate = { id: GateId; name: string; evaluate(corpus: ArtifactCorpus): string[] };
```

Synthetic tests assert exact keys:

```ts
expect(findAnchorResolutionFailures(corpus)).toEqual([
  "sample/missing :: heterodyne:0.5.0#core-missing",
]);
expect(findReasonCodeClosureFailures(corpus)).toEqual([
  "sample/unregistered :: not_registered",
]);
expect(findInvariantCompletenessFailures(corpus)).toEqual(["CORE-I-UNCLAIMED"]);
```

- [ ] **Step 2: Prove RED and implement**

```bash
npm --prefix docs/spec/conformance test -- src/gates/anchor-resolution.test.ts src/gates/reason-code-closure.test.ts src/gates/invariant-completeness.test.ts
```

Extract explicit `<a id>` anchors and map owner prefixes. G1 resolves every `spec_ref`; G2 checks every reject in every direction and uses `<missing>` when absent; G3 independently parses strict-profile fixture JSON, resolves prerequisites transitively, and reports invariants absent from all applicable closures. Return sorted unique keys; import no generator code.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/conformance test -- src/gates/anchor-resolution.test.ts src/gates/reason-code-closure.test.ts src/gates/invariant-completeness.test.ts
npm --prefix docs/spec/conformance run build
git add docs/spec/conformance/src/gates
git commit -m "feat: add structural conformance gates"
```

### Task 6: Implement gates G4-G7

**Files:**
- Create: `docs/spec/conformance/src/gates/anchor-coverage.ts`, `anchor-coverage.test.ts`
- Create: `docs/spec/conformance/src/gates/fixtures-consistency.ts`, `fixtures-consistency.test.ts`
- Create: `docs/spec/conformance/src/gates/dead-vocabulary.ts`, `dead-vocabulary.test.ts`
- Create: `docs/spec/conformance/src/gates/orphan-schemas.ts`, `orphan-schemas.test.ts`
- Modify: `docs/spec/conformance/src/gates/index.ts`

**Interfaces:**
- Consumes: Task-5 gate/anchor interfaces.
- Produces: G4-G7 and `STATIC_GATES = [G1,G2,G3,G4,G5,G6,G7]`.

- [ ] **Step 1: Write failing exact-key tests**

```ts
expect(findAnchorCoverageFailures(corpus)).toEqual(["heterodyne:0.5.0#core-uncovered"]);
expect(findFixturesConsistencyFailures(corpus)).toEqual(["/registry_sha256", "/unexpected"]);
expect(findDeadVocabularyFailures(corpus)).toEqual(["unused_reason"]);
expect(findOrphanSchemaFailures(corpus)).toEqual([
  "docs/spec/schemas/core/orphan-v1.schema.json",
]);
```

- [ ] **Step 2: Prove RED and implement**

G4 compares all explicit anchors with all vector refs. G5 allows exactly:

```ts
new Set([
  "audience_keys", "category_keysets", "device_publishing_keys", "ed25519_nids",
  "kel", "personas", "pinned_randomness", "radicle_rids", "registry_sha256",
  "spec_version", "test_epoch", "vector_schema_version",
]);
```

It also requires family 0.5.0, vector schema 1.1.0, and current registry digest. G6 subtracts all vector rejection reasons from registered reasons. G7 accepts only exact repository-relative schema paths appearing in normative prose or a vector value; basename matches do not count.

```bash
npm --prefix docs/spec/conformance test -- src/gates/anchor-coverage.test.ts src/gates/fixtures-consistency.test.ts src/gates/dead-vocabulary.test.ts src/gates/orphan-schemas.test.ts
npm --prefix docs/spec/conformance run build
```

- [ ] **Step 3: Commit**

```bash
git add docs/spec/conformance/src/gates
git commit -m "feat: add conformance coverage inventory gates"
```

### Task 7: Implement the independent Core checker

**Files:**
- Create: `docs/spec/conformance/schema/core-verification-context-v1.schema.json`
- Create: `docs/spec/conformance/src/subjects/types.ts`, `nip01.ts`
- Create: `docs/spec/conformance/src/subjects/reference-checker.ts`, `reference-checker.test.ts`
- Create: `docs/spec/conformance/src/subjects/import-boundary.test.ts`

**Interfaces:**
- Consumes: Core §9, checker metadata, RFC 6901 resolution, approved context schema.
- Produces: `checkCoreSignedEvent(vector, check): SubjectResult` and reciprocal import-boundary proof.

- [ ] **Step 1: Define result types and failing tests**

```ts
export type CheckerStage =
  | "event_structure"|"nip01_raw"|"identifier"|"signature"
  | "persona_resolution"|"version_stamp"|"kel_head"
  | "epoch_authority"|"subtype_nid"|"accept";
export type SubjectResult = {
  terminalStage: CheckerStage;
  verdict: "accept"|"reject";
  reasonCode?: string;
  stages: { stage: CheckerStage; verdict: "pass"|"reject"; reasonCode?: string }[];
};
```

Pin official BIP-340 vector 0: public key `F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9`, zero message, signature `E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0`. Build one valid local fixture and one isolated mutation per stage; assert the ten terminal stages in order.

- [ ] **Step 2: Prove RED and implement**

```bash
npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts
```

Parse exact raw `[0,pubkey,created_at,kind,tags,content]`, reject noncanonical reserialization, bind exposed fields, hash raw UTF-8, then verify Schnorr. Validate the closed context with AJV; enforce contiguous KEL links, pointer head membership, authority intervals, compromise truncation, signer/delegation binding, version/`kel_head` policy, and Ed25519 NID proof. Never reconstruct raw before raw binding.

- [ ] **Step 3: Prove package independence and commit**

Recursively resolve conformance relative imports and reject generator paths; scan generator imports and reject conformance paths.

```bash
npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts src/subjects/import-boundary.test.ts
npm --prefix docs/spec/conformance run build
git diff --check
git add docs/spec/conformance/schema docs/spec/conformance/src/subjects
git commit -m "feat: add independent Core reference checker"
```

### Task 8: Add gates G8-G11 and declared corpus cases

**Files:**
- Create: `docs/spec/conformance/src/gates/identifier-integrity.ts`
- Create: `docs/spec/conformance/src/gates/signature-integrity.ts`
- Create: `docs/spec/conformance/src/gates/nip01-raw.ts`
- Create: `docs/spec/conformance/src/gates/negative-hygiene.ts`
- Create: `docs/spec/conformance/src/gates/subject-gates.test.ts`
- Modify: `docs/spec/conformance/src/gates/index.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/topics-v04.ts`
- Modify: `docs/spec/vectors/generator/src/vector-metadata.ts`
- Modify: `docs/spec/vectors/generator/src/author.test.ts`
- Modify: `docs/spec/vectors/generator/src/release.test.ts`
- Create: `docs/spec/vectors/verification/005-valid-core-signed-event-accepts.json`
- Regenerate: `docs/spec/vectors/verification/001-bad-signature-rejects.json`
- Regenerate: `docs/spec/vectors/node-advert/002-outer-sig-invalid-rejected.json`
- Regenerate: `docs/spec/vectors/coverage/*`
- Modify: `docs/spec/vectors/README.md`
- Regenerate: `docs/spec/releases/family/0.5.0.json`

**Interfaces:**
- Consumes: `checkCoreSignedEvent`, `Gate`, generator authoring primitives.
- Produces: `ALL_GATES` G1-G11, three declarations, and a 499-vector corpus.

- [ ] **Step 1: Write failing gate tests**

```ts
expect(findIdentifierIntegrityFailures(identifierNegativeCorpus)).toEqual([]);
expect(findSignatureIntegrityFailures(signatureNegativeCorpus)).toEqual([]);
expect(findNegativeHygieneFailures(doubleBrokenCorpus)).toEqual([
  "verification/bad-signature-rejects :: /input/event",
]);
expect(findNip01RawFailures(missingRawCorpus)).toEqual([
  "docs/spec/vectors/sample.json :: /input/event",
]);
```

```bash
npm --prefix docs/spec/conformance test -- src/gates/subject-gates.test.ts
```

Expected: RED because G8-G11 do not exist.

- [ ] **Step 2: Implement G8-G11**

G8/G9/G11 dispatch only declared `core-signed-event-v1` checks. G10 recursively finds objects with the complete signed NIP-01 member set, records exact pointers, requires a sibling `nip01_raw`, and cross-checks declared raw pointers. Register:

```ts
export const ALL_GATES: readonly Gate[] = [
  G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11,
];
```

- [ ] **Step 3: Correct and declare signature cases**

For verification/001, create exact raw from the unsigned event, set `id` to its SHA-256, and retain only the bad signature. Add exact raw to node-advert/002. Both use:

```ts
conformance_checks: [{
  profile: "core-signed-event-v1",
  event_pointer: "/input/event",
  nip01_raw_pointer: "/input/nip01_raw",
  expected_terminal_stage: "signature",
}],
```

- [ ] **Step 4: Author one full accepted Core case**

Add verification/005 from a deterministic epoch-key event. Store exact raw and closed `CoreVerificationContextV1` at `/input/vector_context/core_verification`; declare that context pointer and terminal `accept`. Expected output is exactly `{ verdict: "accept" }`; sole spec ref is `heterodyne:0.5.0#core-verification`.

Add `verification/valid-core-signed-event-accepts` to `CORE_IDS` and its `core-verification` mapping. Change the release test's vector count from 498 to 499.

- [ ] **Step 5: Regenerate, verify, and commit**

Update README count to 499, then:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
npm --prefix docs/spec/conformance test -- src/gates/subject-gates.test.ts
npm --prefix docs/spec/vectors/generator test -- src/author.test.ts
npm --prefix docs/spec/vectors/generator run check
git diff --check
git add docs/spec/conformance/src/gates docs/spec/vectors docs/spec/releases/family/0.5.0.json
git commit -m "test: add independent signed-event conformance cases"
```

### Task 9: Add ratchets, reports, and CLI

**Files:**
- Create: `docs/spec/conformance/src/ratchet.ts`, `ratchet.test.ts`
- Create: `docs/spec/conformance/src/report.ts`, `report.test.ts`
- Create: `docs/spec/conformance/src/run.ts`, `cli.ts`, `integration.test.ts`
- Create: `docs/spec/conformance/baselines/G1-anchor-resolution.json` through `G11-negative-hygiene.json`
- Create: `docs/spec/conformance/report.json`, `DEBT.md`

**Interfaces:**
- Consumes: `ALL_GATES`, `loadCorpus`.
- Produces: `compareBaseline`, `runConformance`, read-only check, explicit authoring commands.

- [ ] **Step 1: Write failing ratchet/report tests**

```ts
expect(compareBaseline(["a"], ["a", "b"]))
  .toEqual({ newFailures: [], staleFailures: ["b"] });
expect(compareBaseline(["a", "b"], ["a"]))
  .toEqual({ newFailures: ["b"], staleFailures: [] });
expect(compareBaseline([], []))
  .toEqual({ newFailures: [], staleFailures: [] });
```

Assert report JSON uses two spaces plus one LF and DEBT has one row per G1-G11.

- [ ] **Step 2: Prove RED and implement**

```bash
npm --prefix docs/spec/conformance test -- src/ratchet.test.ts src/report.test.ts src/integration.test.ts
```

Implement:

```ts
export type ConformanceRun = {
  familyVersion: string;
  registryRevision: number;
  registryDigest: string;
  results: GateResult[];
  issues: CorpusIssue[];
};
export function runConformance(repositoryRoot: string): ConformanceRun;
export function compareBaseline(actual: readonly string[], baseline: readonly string[]): {
  newFailures: string[]; staleFailures: string[];
};
```

`check` only compares committed baselines/projections. `baseline-author` writes exactly 11 measured sets. `report-author` writes report/DEBT. Invalid invocation exits 2; validation exits 1.

Each baseline has exact shape `{ "gate": "G1", "failures": [] }`, substituting its own gate ID and measured sorted keys. `report.json` contains family version, registry revision/digest, per-gate counts/keys, and totals; `DEBT.md` is the deterministic table projection of the same run.

- [ ] **Step 3: Author current baselines and prove both directions**

```bash
npm --prefix docs/spec/conformance run baseline-author -- "$PWD"
npm --prefix docs/spec/conformance run report-author -- "$PWD"
```

In integration tests, inject one unregistered reason and expect new G2 debt; remove one measured debt instance and expect a stale key. Do not mutate the real corpus in tests.

- [ ] **Step 4: Verify and commit**

```bash
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
npm --prefix docs/spec/conformance run check -- "$PWD"
git diff --check
git add docs/spec/conformance
git commit -m "feat: add ratcheted conformance reports"
```

### Task 10: Wire the shared GitHub and Radicle gate

**Files:**
- Create: `scripts/conformance-ci.sh`
- Create: `.github/workflows/conformance.yml`
- Create: `.radicle/native.yaml`
- Create: `docs/spec/conformance/src/ci-config.test.ts`
- Modify: `AGENTS.md`, `README.md`, `docs/spec/vectors/README.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: generator/conformance checks.
- Produces: stable GitHub check `conformance`, Radicle wrapper, one shell job body.

- [ ] **Step 1: Write failing config and failure-propagation tests**

Assert script contains `set -euo pipefail`, two `npm ci` installs, family check, generator check, and conformance check in order. Assert workflow contains pull requests, pushes to main, `contents: read`, Node 22, and no `pull_request_target`. Assert Radicle invokes only the script. With a fake `npm` in temporary PATH, make the second check exit 23 and prove the script exits 23 without invoking the third.

```bash
npm --prefix docs/spec/conformance test -- src/ci-config.test.ts
```

- [ ] **Step 2: Create the shared script**

```bash
#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"
npm --prefix docs/spec/vectors/generator ci
npm --prefix docs/spec/conformance ci
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run check -- "$repository_root"
```

Mark executable.

- [ ] **Step 3: Create wrappers**

GitHub runs `pull_request` and push branches `[main]`, grants only `contents: read`, cancels concurrency by workflow/ref, names job `conformance`, uses checkout/setup-node v4 with Node 22 and both lockfiles, then invokes only `scripts/conformance-ci.sh`.

Radicle is exactly:

```yaml
shell: |
  scripts/conformance-ci.sh
```

- [ ] **Step 4: Document operational boundaries**

Add conformance package navigation and AGENTS third verification command. Require green isolated podman-adapter Radicle runs before merge; recommend GitHub required check `conformance` without changing remote settings. Document explicit author commands but exclude them from normal verification.

- [ ] **Step 5: Verify and commit**

```bash
bash -n scripts/conformance-ci.sh
npm --prefix docs/spec/conformance test -- src/ci-config.test.ts
scripts/conformance-ci.sh
git diff --check
git add scripts/conformance-ci.sh .github/workflows/conformance.yml .radicle/native.yaml docs/spec/conformance/src/ci-config.test.ts AGENTS.md README.md docs/spec/vectors/README.md CHANGELOG.md
git commit -m "ci: enforce independent conformance gate"
```

### Task 11: Verify closure and accept/archive ADR-045

**Files:**
- Move: `docs/adr/2026-08-15-045-conformance-harness-independence.md` to `docs/adr/archive/2026-08-15-045-conformance-harness-independence.md`
- Modify: `CHANGELOG.md`
- Regenerate if measured state changed: `docs/spec/conformance/baselines/*.json`, `report.json`, `DEBT.md`
- Regenerate: `docs/spec/releases/family/0.5.0.json`

**Interfaces:**
- Consumes: all prior tasks and design acceptance matrix.
- Produces: self-contained green patch with accepted archived ADR.

- [ ] **Step 1: Run pre-acceptance verification**

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run check
scripts/conformance-ci.sh
git diff --check
```

Expected: all exit 0; generator verifies 499 vectors; release and all G1-G11 ratchets validate.

- [ ] **Step 2: Audit hard boundaries**

```bash
if rg -n 'from .*vectors/generator|import\(.*vectors/generator' docs/spec/conformance; then exit 1; fi
if rg -n 'from .*spec/conformance|import\(.*spec/conformance' docs/spec/vectors/generator/src; then exit 1; fi
test "$(jq -r '.revision' docs/spec/registry/manifest.json)" = 13
test "$(jq -r '.schema_version' docs/spec/registry/manifest.json)" = 3.0.0
test "$(jq -r '.vector_schema_version' docs/spec/vectors/verification/005-valid-core-signed-event-accepts.json)" = 1.1.0
test "$(jq '[.artifacts[] | select(.path | startswith("docs/spec/conformance/"))] | length' docs/spec/releases/family/0.5.0.json)" = 0
```

- [ ] **Step 3: Request final review and fix verified findings**

Review unsafe path handling, generator leakage, false-clean gates, baseline laundering, stage order, registry/release drift, workflow privilege, and tracked writes during check. Critical or Important findings block acceptance and require a focused regression test plus Step 1 rerun.

- [ ] **Step 4: Accept/archive and post-verify**

Set `**Status:** Accepted`, add the standard non-canonical archive notice, move to the exact archive path, and change changelog heading/link from proposed to accepted/archive. Then:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run check
scripts/conformance-ci.sh
git diff --check
git status --short
```

- [ ] **Step 5: Commit and verify without publishing**

```bash
git add docs/adr CHANGELOG.md docs/spec/conformance docs/spec/releases/family/0.5.0.json
git commit -m "docs: accept independent conformance CI decision"
scripts/conformance-ci.sh
git diff --check HEAD^
git status --short --branch
```

Expected: final gate passes, worktree is clean, and nothing was pushed, tagged, published, deployed, or remotely configured.
