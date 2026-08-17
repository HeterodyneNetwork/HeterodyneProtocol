# Protocol Simplification Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the single-family-version simplification with coherent normative vectors, one implementable key-envelope primitive, Control-owned node tokens, one family release manifest, and no stale authoring terminology.

**Architecture:** Keep Core as the owner of family-wide version, typed-key, registry, and envelope rules; keep Comms free of Control-specific token semantics; make Control own its complete RFC 9068 node-token profile. Replace deleted per-document release records with one content-addressed family manifest generated and verified alongside the existing normative corpus.

**Tech Stack:** Markdown specifications and ADRs, JSON Schema draft-07, TypeScript, Vitest, AJV, deterministic JSON generation, SHA-256.

**Spec:** `docs/superpowers/specs/2026-08-17-protocol-simplification-stabilization-design.md`

## Global Constraints

- The only qualified family version is `heterodyne/0.5.0`.
- During `0.x`, peers accept only an exact supported family version unless an explicitly declared degraded mode refuses unknown security semantics.
- Documents remain layering and conformance boundaries, not independent version lineages.
- Core may depend on no higher document; Comms may depend only on Core; Control may depend on Core and Comms.
- Wire changes update specification prose, registry, schemas, and normative vectors in the same patch.
- The proposed ADR remains under `docs/adr/` until human acceptance.
- Preserve unrelated branch commits and generated artifacts.

---

### Task 1: Record the proposed protocol decision

**Files:**
- Create: `docs/adr/2026-08-17-046-stabilize-single-family-simplification.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: approved design at `docs/superpowers/specs/2026-08-17-protocol-simplification-stabilization-design.md`.
- Produces: ADR-046 in proposed state and a changelog entry linking the six changes to their live specification owners.

- [ ] **Step 1: Write ADR-046 in proposed state**

Use the repository ADR format and include these decisions verbatim in substance:

```markdown
**Status:** Proposed

1. One exact family version replaces every per-document negotiation artifact.
2. A key-envelope instantiation declares recipient set, typed reference and
   wrapping, carrier, generation form, and extra rotation triggers.
3. Workspace uses `marmot-mls-leaf` to bind the exact authorized MLS leaf.
4. Node-scoped Control JWTs are owned only by Control.
5. One family release manifest replaces per-document release manifests.
6. Authoring checks reject the retired models and terminology.
```

State that normative authority remains the live specification and machine-readable artifacts, not the ADR.

- [ ] **Step 2: Add a concise changelog entry**

Add links to ADR-046, `core-versioning`, `core-key-envelope`, `control-token`, and the family release manifest. Do not restate wire requirements in the changelog.

- [ ] **Step 3: Verify the record is proposed and the live specs do not cite it normatively**

Run:

```bash
rg -n "Status:.*Proposed|ADR-046" docs/adr/2026-08-17-046-stabilize-single-family-simplification.md CHANGELOG.md
npm --prefix docs/spec/vectors/generator run family:check
```

Expected: ADR status is Proposed; family check passes because normative documents do not depend on the ADR.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/2026-08-17-046-stabilize-single-family-simplification.md CHANGELOG.md
git commit -m "docs: propose single-family stabilization decision"
```

### Task 2: Replace the obsolete versioning model and vectors

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/vectors/generator/src/family.ts`
- Modify: `docs/spec/vectors/generator/src/family.test.ts`
- Create: `docs/spec/vectors/generator/src/versioning.test.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/topics-split.ts`
- Modify: `docs/spec/vectors/generator/src/vector-metadata.ts`
- Regenerate: `docs/spec/vectors/versioning/*.json`
- Regenerate: `docs/spec/vectors/registry/001-downref-nonfrozen-rejected.json`
- Regenerate: `docs/spec/vectors/coverage/*`

**Interfaces:**
- Consumes: `QUALIFIED_VERSION` and `parseFamilyVersion(value: string): string` from `family.ts`.
- Produces: `negotiateExactFamilyVersion(local: readonly string[], remote: readonly string[]): string | null` and nine normative version vectors using only family-qualified strings.

- [ ] **Step 1: Write failing exact-negotiation tests**

Add to `family.test.ts`:

```ts
it("negotiates only the exact current family version", () => {
  expect(negotiateExactFamilyVersion(
    ["heterodyne/0.5.0"],
    ["heterodyne/0.5.0"],
  )).toBe("heterodyne/0.5.0");
  expect(negotiateExactFamilyVersion(
    ["heterodyne/0.5.0"],
    ["heterodyne/0.4.0"],
  )).toBeNull();
  expect(negotiateExactFamilyVersion(
    ["core/0.5.0"],
    ["core/0.5.0"],
  )).toBeNull();
});
```

Add `versioning.test.ts` that builds authored vectors and asserts:

```ts
expect(byId("versioning/qualified-version-valid").expected_output)
  .toEqual({ valid: true, semver: "0.5.0" });
expect(byId("versioning/exact-family-version-negotiation").input)
  .toEqual({ local: ["heterodyne/0.5.0"], remote: ["heterodyne/0.5.0"] });
expect(JSON.stringify(versionVectors)).not.toMatch(
  /(?:core|comms|control|social|workspace)\/[0-9]/,
);
```

- [ ] **Step 2: Run the tests to verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/family.test.ts src/versioning.test.ts
```

Expected: failure because `negotiateExactFamilyVersion` and the new vector ID do not exist and old document-qualified strings remain.

- [ ] **Step 3: Implement exact family negotiation**

Add to `family.ts`:

```ts
export function negotiateExactFamilyVersion(
  local: readonly string[],
  remote: readonly string[],
): string | null {
  return local.includes(QUALIFIED_VERSION) && remote.includes(QUALIFIED_VERSION)
    ? QUALIFIED_VERSION
    : null;
}
```

In Core, replace “document versions” with singular “family version” in capability and strict-profile prose.

- [ ] **Step 4: Rewrite the version vectors at their authoring sources**

Use these semantics:

```text
001: heterodyne/1.0.0 is an unsupported future major and rejects.
002: heterodyne/0.4.0 versus exact heterodyne/0.5.0 rejects.
003: the complete heterodyne-capabilities-v1 object round-trips.
004: unknown optional room behavior is tolerated only at the same supported family version.
005: heterodyne/0.5.0 parses to semver 0.5.0, with no document result.
006: bare 0.5.0 and core/0.5.0 reject as invalid_family_version.
007: the complete Core bootstrap object is accepted.
008: rename to versioning/exact-family-version-negotiation and select one scalar version.
009: heterodyne/9.0.0 rejects asynchronously as unknown_major_version.
```

Change `registry/001-downref-nonfrozen-rejected` input to `heterodyne/1.0.0`.

- [ ] **Step 5: Regenerate and run targeted tests**

Run:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator test -- src/family.test.ts src/versioning.test.ts
```

Expected: targeted tests pass and the retired `008-per-document-negotiation.json` is removed.

- [ ] **Step 6: Commit**

```bash
git add docs/spec/heterodyne-core.md docs/spec/vectors
git commit -m "spec: finish single-family version cutover"
```

### Task 3: Make the shared key-envelope contract exact

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/schemas/workspace/resource-key-envelope-v1.schema.json`
- Modify: `docs/spec/vectors/generator/src/workspace-schemas.ts`
- Modify: `docs/spec/vectors/generator/src/workspace-schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.ts`
- Regenerate: affected `docs/spec/vectors/workspace-key/*.json`

**Interfaces:**
- Consumes: Core typed-key object shape `{ type: string; value: string }` and Workspace `resource-key-envelope-v1`.
- Produces: registered Core type `marmot-mls-leaf`, whose value is unpadded base64url SHA-256 of the exact TLS-serialized MLS `LeafNode` in the authenticated role-group epoch; Workspace envelope member `recipient` of that type.

- [ ] **Step 1: Write failing Workspace schema tests**

Extend the valid envelope fixture with:

```ts
recipient: {
  type: "marmot-mls-leaf",
  value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
},
```

Add rejection cases for a missing recipient, `type:"nostr-secp256k1"`, padded base64url, and a value other than 43 base64url characters.

- [ ] **Step 2: Run the schema test to verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/workspace-schema.test.ts
```

Expected: the valid fixture fails because `recipient` is currently an additional property.

- [ ] **Step 3: Define the Core typed reference and five-choice envelope contract**

Add the Core table row:

```markdown
| `marmot-mls-leaf` | unpadded base64url SHA-256 of the exact TLS-serialized MLS `LeafNode` in its authenticated group epoch | MLS leaf signature plus Marmot `marmot.member.account-identity-proof.v2` and membership in the bound group context |
```

Replace “exactly four” with five choices: recipient set; typed reference and wrapping; carrier; generation identifier; extra rotation triggers. State that the fifth value is `none` when removal is the only trigger and that adding a recipient alone does not rotate, without prohibiting rotation caused by a simultaneous independent trigger.

- [ ] **Step 4: Complete every instantiation table**

Comms audience keys use `nostr-secp256k1`, `key_id`, and extra trigger `none`; claim-ledger and issuer-key prose explicitly supply all five choices. Workspace uses `marmot-mls-leaf`, `key_epoch`, and extra trigger `none`. This preserves the current rotation semantics while making every required choice explicit.

- [ ] **Step 5: Add the typed recipient to the generated Workspace schema**

In `workspace-schemas.ts`, require `recipient` and define:

```ts
recipient: {
  type: "object",
  additionalProperties: false,
  required: ["type", "value"],
  properties: {
    type: { const: "marmot-mls-leaf" },
    value: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" },
  },
},
```

Retain `target_device` as the Workspace policy/device-registry identifier; `recipient` is the exact cryptographic delivery leaf.

- [ ] **Step 6: Regenerate and run targeted tests**

Run:

```bash
npm --prefix docs/spec/vectors/generator run workspace-schemas
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator test -- src/workspace-schema.test.ts src/workspace.test.ts
```

Expected: valid typed recipients pass and all malformed variants reject.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-workspace.md docs/spec/schemas/workspace docs/spec/vectors
git commit -m "spec: complete the shared key-envelope primitive"
```

### Task 4: Move node-scoped JWT ownership to Control

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/topics-oidc.ts`
- Create: `docs/spec/vectors/generator/src/topics-oidc.test.ts`
- Modify: `docs/spec/vectors/generator/src/control-profile.ts`
- Regenerate: affected Control, OIDC, coverage, and registry-derived vector artifacts

**Interfaces:**
- Consumes: `control.private-entitlement.v1`, which already closes over `control.marmot.v1` and `comms.private-claim-ledger.v1`.
- Produces: `control.node-scoped-token.v1` as sole owner of the Control `at+jwt` profile; no `comms.node-scoped-jwt.v1` entry or Comms token anchor.

- [ ] **Step 1: Write failing registry ownership tests**

Add assertions:

```ts
expect(featureIds).not.toContain("comms.node-scoped-jwt.v1");
expect(feature("comms.oidc-jwt-projection.v1").prerequisites)
  .toEqual(["comms.private-claim-ledger.v1"]);
expect(feature("control.node-scoped-token.v1").prerequisites)
  .toEqual(["control.private-entitlement.v1"]);
expect(feature("control.oauth-device-enrollment.v1").prerequisites)
  .toEqual(["comms.oidc-jwt-projection.v1", "control.node-scoped-token.v1"]);
expect(invariant("COMMS-I-JWT-TYPE-AUDIENCE").feature)
  .toBe("comms.oidc-jwt-projection.v1");
```

Add a docs-lint assertion that live Comms prose does not contain `comms.node-scoped-jwt.v1`, “A Control token has”, or a `comms-control-token` anchor.

- [ ] **Step 2: Run targeted tests to verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/docs-lint.test.ts
```

Expected: failures identify the current Comms feature, invariant, and token section.

- [ ] **Step 3: Move the complete token contract into Control**

Delete Comms §9.1 node-token semantics and renumber its remaining subsections without changing stable anchors. Expand Control `control-token` to own RFC 9068 `typ:at+jwt`, node-local issuer state, exact node audience, `cnf.jkt`, Marmot sender/group binding, client and entitlement IDs, methods, objects, limits, optional agent role, five-minute default, sixty-minute ceiling, no refresh token, and per-request entitlement revalidation.

- [ ] **Step 4: Simplify the registry closure and invariants**

Remove `comms.node-scoped-jwt.v1`. Make OIDC depend only on the private claim ledger. Make Control node tokens depend only on private entitlement, and OAuth enrollment depend on both OIDC and the Control token feature. Rebind `COMMS-I-JWT-TYPE-AUDIENCE` to the third-party OIDC projection and expand `CONTROL-I-NODE-AUDIENCE` to carry the corresponding Control-specific type, signature, time, and audience requirements.

Advance the current registry revision once, recompute `entry_set_sha256`, and do not create a pre-1.0 history snapshot.

- [ ] **Step 5: Update generators and vectors**

Move token validation vector ownership and spec references to `control-token`. Keep third-party discovery, JWKS, pairwise subject, RFC 9068 projection, and status-list vectors in Comms OIDC. Regenerate registry projections, vectors, and coverage.

- [ ] **Step 6: Run targeted checks**

Run:

```bash
npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 12
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/docs-lint.test.ts src/marmot-control-profile.test.ts src/topics-oidc.test.ts
```

Expected: feature closure and ownership tests pass; no Comms-only/OIDC-only claim requires Control semantics.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/registry docs/spec/vectors
git commit -m "spec: move node-scoped JWTs to Control"
```

### Task 5: Add one content-addressed family release manifest

**Files:**
- Create: `docs/spec/releases/family-release-manifest.schema.json`
- Create: `docs/spec/releases/family/0.5.0.json`
- Create: `docs/spec/vectors/generator/src/release.ts`
- Create: `docs/spec/vectors/generator/src/release.test.ts`
- Modify: `docs/spec/vectors/generator/src/cli.ts`
- Modify: `docs/spec/vectors/generator/package.json`
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/spec/heterodyne.md`

**Interfaces:**
- Produces: `buildFamilyReleaseManifest(repoRoot: string): FamilyReleaseManifest`, `writeFamilyReleaseManifest(repoRoot: string): string`, and `validateFamilyReleaseManifest(repoRoot: string): string[]`.
- Manifest shape: `{ schema_version, family_version, status, registry, artifacts }`, where `artifacts` is a path-sorted array of `{ path, role, sha256 }`.

- [ ] **Step 1: Write failing release tests**

Test that the built manifest has:

```ts
expect(manifest.family_version).toBe("heterodyne/0.5.0");
expect(manifest.status).toBe("unreleased");
expect(manifest.registry.path).toBe("docs/spec/registry/manifest.json");
expect(manifest.artifacts.filter(a => a.role === "specification")).toHaveLength(5);
expect(manifest.artifacts.map(a => a.path)).toEqual(
  [...manifest.artifacts.map(a => a.path)].sort(),
);
expect(validateFamilyReleaseManifest(repoRoot)).toEqual([]);
```

Mutation tests must detect one changed file, one missing artifact, one extra manifest entry, a wrong registry digest, and an unsafe path.

- [ ] **Step 2: Run the release test to verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/release.test.ts
```

Expected: module import failure because `release.ts` does not exist.

- [ ] **Step 3: Define the closed family manifest schema**

Use draft-07 with no additional properties. Roles are exactly `specification`, `registry`, `schema`, `vector`, and `normative-support`. Paths are repository-relative, contain no empty, `.` or `..` segment, and match `^[A-Za-z0-9._/-]+$`; digests are lowercase 64-hex SHA-256.

Exclude the release manifest itself, its schema, generator source, coverage Markdown, design files, plans, reviews, and ADRs from `artifacts` to avoid circular or non-normative pins. Include the five normative documents, registry JSON except registry history, all protocol schemas, committed normative vector JSON except coverage projections and generator metadata, and the pinned Marmot manifest as normative support.

- [ ] **Step 4: Implement deterministic authoring and validation**

Use `createHash("sha256")`, `readFileSync`, and the repository's existing file-walk conventions. `buildFamilyReleaseManifest` derives paths from the closed role rules; `writeFamilyReleaseManifest` writes stable two-space JSON plus one LF; validation rebuilds the manifest and reports path/digest/shape drift without trusting manifest paths before safety checks.

- [ ] **Step 5: Add CLI and package commands**

Add:

```json
"release-author": "tsx src/cli.ts release-author",
"release-check": "tsx src/cli.ts release-check",
"check": "npm run build && npm test && npm run verify && npm run release-check"
```

`release-author [root]` writes `docs/spec/releases/family/0.5.0.json`; `release-check [root]` exits nonzero and prints every issue when validation fails.

- [ ] **Step 6: Author the manifest and run mutation tests**

Run:

```bash
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
npm --prefix docs/spec/vectors/generator test -- src/release.test.ts
npm --prefix docs/spec/vectors/generator run release-check -- "$PWD"
```

Expected: tests and release check pass.

- [ ] **Step 7: Restore release metadata to the project workflow**

Add `docs/spec/releases/` back to AGENTS.md's normative artifacts and document the single family manifest in README and the family overview. Do not describe documents as independently released.

- [ ] **Step 8: Commit**

```bash
git add AGENTS.md README.md docs/spec/heterodyne.md docs/spec/releases docs/spec/vectors/generator
git commit -m "spec: add one family release manifest"
```

### Task 6: Remove stale authoring models and terminology

**Files:**
- Modify: `docs/spec/vectors/README.md`
- Modify: `docs/spec/extensions/nips/README.md`
- Modify: `docs/glossary.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: current vector schema, current family release command, and `profile_revision` claim schemas.
- Produces: maintained documentation that contains no retired document-qualified versions, per-document vector metadata, removed commands, or false `registry_revision` wire-member claims.

- [ ] **Step 1: Write failing documentation-cutover tests**

Add a lint check over the maintained guides with these forbidden patterns:

```ts
const retired = [
  /owner_version/,
  /dependency_versions/,
  /heterodyne:(?:core|comms|control|social|workspace)\//,
  /run release-manifests/,
  /JSON member remains named\s+`registry_revision`/,
];
```

Also assert that vector README metadata names `spec_version`, the documented count equals the built corpus count, and the documented release commands are `release-author` and `release-check`.

- [ ] **Step 2: Run the lint tests to verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts
```

Expected: failures identify vectors README, NIP extraction references, and glossary terminology.

- [ ] **Step 3: Update the maintained guides**

Document vector metadata as `owner_document`, `spec_version`, and one `spec_refs` entry. Remove registry-revision-8 and 497-vector claims; use the actual generated count. Replace all extraction references with `heterodyne:0.5.0#<anchor>`. Replace the glossary and threat-model claim wire member with `profile_revision`, explaining that its value remains frozen at `2` and is distinct from the release registry revision.

- [ ] **Step 4: Run targeted lint and reference sweeps**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts
rg -n --glob 'docs/spec/**' --glob '!docs/spec/external/**' \
  'owner_version|dependency_versions|heterodyne:(core|comms|control|social|workspace)/|run release-manifests'
rg -n 'JSON member remains named `registry_revision`' docs/glossary.md docs/security/threat-model.md
```

Expected: targeted test passes and both searches return no matches.

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/README.md docs/spec/extensions/nips/README.md docs/glossary.md docs/security/threat-model.md docs/spec/vectors/generator/src/docs-lint.ts docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "docs: remove retired protocol authoring models"
```

### Task 7: Regenerate the closed corpus and verify the complete patch

**Files:**
- Regenerate: `docs/spec/registry/manifest.json`
- Regenerate: `docs/spec/schemas/workspace/*.json`
- Regenerate: `docs/spec/vectors/**/*.json`
- Regenerate: `docs/spec/vectors/coverage/*`
- Regenerate: `docs/spec/releases/family/0.5.0.json`
- Modify only if required by generated drift: authoritative generator sources from Tasks 2-6

**Interfaces:**
- Consumes: every authoritative source changed in Tasks 1-6.
- Produces: one internally closed normative corpus with deterministic projections.

- [ ] **Step 1: Regenerate in dependency order**

Run:

```bash
npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 12
npm --prefix docs/spec/vectors/generator run workspace-schemas -- "$PWD"
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
```

Expected: each command exits zero and the family manifest is authored last so it pins final bytes.

- [ ] **Step 2: Run focused regression tests**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- \
  src/family.test.ts \
  src/versioning.test.ts \
  src/workspace-schema.test.ts \
  src/registry.test.ts \
  src/release.test.ts \
  src/docs-lint.test.ts
```

Expected: all focused suites pass.

- [ ] **Step 3: Run mandatory verification**

Run:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/vectors/generator run release-check -- "$PWD"
git diff --check
```

Expected: family check validates the document graph; build and all Vitest suites pass; every committed vector verifies; release manifest validation passes; diff check emits no output.

- [ ] **Step 4: Audit the six original gaps**

Run:

```bash
test -f docs/adr/2026-08-17-046-stabilize-single-family-simplification.md
test -f docs/spec/releases/family/0.5.0.json
test ! -e docs/spec/vectors/versioning/008-per-document-negotiation.json
! rg -n 'comms\.node-scoped-jwt\.v1|comms-control-token' docs/spec docs/security README.md
! rg -n 'owner_version|dependency_versions|heterodyne:(core|comms|control|social|workspace)/' docs/spec/vectors/README.md docs/spec/extensions/nips/README.md
! rg -n 'JSON member remains named `registry_revision`' docs/glossary.md docs/security/threat-model.md
```

Expected: every command exits zero.

- [ ] **Step 5: Commit final generated closure**

```bash
git add AGENTS.md CHANGELOG.md README.md docs
git commit -m "test: close stabilized protocol corpus"
```
