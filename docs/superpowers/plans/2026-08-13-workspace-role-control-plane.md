# Workspace Role Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a canonical, independently versioned Workspace protocol document and every normative artifact needed to implement and test workspace identity, role authorization, private discovery, cross-workspace allowances, hosting, and resource-key delivery.

**Architecture:** Workspace is a higher-layer family document whose base role control plane composes Core identity and Comms Marmot/Radicle transport. Stable workspace and role repositories hold signed, closed-schema authority objects; rotating Marmot event repositories carry live encrypted control traffic; native resources keep independent state and key epochs. Optional Control and Social compositions add device-mediated operations and affiliation presentation without moving their authority into Workspace.

**Tech Stack:** Markdown/BCP 14 protocol prose, JSON Schema draft-07, canonical JSON registry and release manifests, TypeScript/Vitest conformance-vector generator.

**Spec:** `docs/adr/archive/2026-08-13-044-workspace-role-control-plane.md` (the approved design is moved to this historical ADR during Task 1)

## Global Constraints

- The canonical result is the specification family plus registries, schemas, releases, and vectors; the archived ADR is historical only.
- Add `workspace/0.1.0` without changing the prepared `0.5.0` versions of Core, Comms, Control, or Social.
- Preserve an acyclic dependency graph: Core → Comms → Control/Social → Workspace; Workspace base requirements remain Core/Comms-only.
- Public is a role, workspace membership grants no ambient resource access, inheritance can only narrow, and every denial/revocation wins.
- Private topology must not be projected into public objects, including hashes, counts, encrypted placeholders, or stable correlations.
- Radicle remains the mandatory transport backstop; standard Nostr relays are optional and byte-identical carriers.
- Marmot/MLS mechanics and Radicle replication remain upstream responsibilities; no new messaging engine, Matrix dependency, or modified vanilla server is introduced.
- Resource keys are independent; role MLS controls delivery but does not become a universal role content key.
- Ordinary-write freshness defaults to 86,400 seconds and authority-mutation freshness defaults to 300 seconds; policy may only shorten either default.
- Do not edit `research/sources/` or the untracked `docs/reviews/` tree.

---

### Task 1: Record the decision and establish the Workspace family boundary

**Files:**
- Move: `docs/superpowers/specs/2026-08-13-workspace-role-control-plane-design.md` → `docs/adr/archive/2026-08-13-044-workspace-role-control-plane.md`
- Create: `docs/spec/heterodyne-workspace.md`
- Modify: `AGENTS.md`
- Modify: `docs/spec/heterodyne.md`

**Interfaces:**
- Consumes: the approved design and existing qualified-reference grammar.
- Produces: `workspace/0.1.0`, permanent `workspace-*` anchors, and the family dependency map used by release and vector tooling.

- [ ] **Step 1: Write family tests that expect Workspace**

Extend `family.test.ts` so `parseQualifiedVersion("workspace/0.1.0")` succeeds, Workspace may depend on Core, Comms, Control, and Social, and no existing document may depend on Workspace.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/family.test.ts`
Expected: FAIL because `workspace` is not a `DocumentId` or qualified version.

- [ ] **Step 3: Add the Workspace document boundary**

Write `heterodyne-workspace.md` with normative dependencies, scope/non-goals, terminology, conformance classes, and permanent anchors. Move the approved design to ADR-044, mark it Accepted, and state that it has no normative authority. Update the family map and agent guide with the fifth document and dependency edge.

- [ ] **Step 4: Extend family types and rerun the focused test**

Add `workspace` to `DocumentId`, `DOCUMENT_VERSIONS`, `DOCUMENT_DEPENDENCIES`, and qualified-version regexes. Run the focused test and expect PASS.

- [ ] **Step 5: Commit**

Commit message: `feat: establish workspace protocol family`

### Task 2: Specify the complete role control plane and closed object schemas

**Files:**
- Modify: `docs/spec/heterodyne-workspace.md`
- Create: `docs/spec/schemas/workspace/workspace-manifest-v1.schema.json`
- Create: `docs/spec/schemas/workspace/workspace-policy-v1.schema.json`
- Create: `docs/spec/schemas/workspace/role-manifest-v1.schema.json`
- Create: `docs/spec/schemas/workspace/role-grant-v1.schema.json`
- Create: `docs/spec/schemas/workspace/role-revocation-v1.schema.json`
- Create: `docs/spec/schemas/workspace/role-checkpoint-v1.schema.json`
- Create: `docs/spec/schemas/workspace/resource-advertisement-v1.schema.json`
- Create: `docs/spec/schemas/workspace/host-advertisement-v1.schema.json`
- Create: `docs/spec/schemas/workspace/service-advertisement-v1.schema.json`
- Create: `docs/spec/schemas/workspace/workspace-relationship-v1.schema.json`
- Create: `docs/spec/schemas/workspace/joint-workspace-relationship-v1.schema.json`
- Create: `docs/spec/schemas/workspace/resource-key-envelope-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/workspace-schema.test.ts`

**Interfaces:**
- Consumes: Core KERI authority/checkpoint identifiers and Comms Marmot/Radicle locators.
- Produces: twelve exact closed-schema object types with `spec_version`, `object_type`, authority bindings, and type-specific fields.

- [ ] **Step 1: Write table-driven schema tests**

For each schema, provide one valid object and assertions that an unknown member, missing required member, wrong `object_type`, malformed 64-hex digest, and invalid visibility/capability/history enum are rejected.

- [ ] **Step 2: Run the schema test and verify RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/workspace-schema.test.ts`
Expected: FAIL because the Workspace schemas do not exist.

- [ ] **Step 3: Author the schemas and normative object rules**

Use draft-07, `additionalProperties:false` at every object boundary, exact `$id` paths under `https://heterodyne.network/schemas/workspace/`, integer seconds, lowercase 64-hex digests, `rad:` locators, and closed enums. Define deterministic JCS encoding, signature input, KERI/checkpoint validation, replay identity, activation ordering, and conflict handling in the Workspace spec.

- [ ] **Step 4: Run the schema test and verify GREEN**

Run the focused schema test and expect all cases PASS.

- [ ] **Step 5: Commit**

Commit message: `feat: define workspace authority objects`

### Task 3: Allocate Workspace registry entries and release metadata

**Files:**
- Modify: `docs/spec/registry/registry.schema.json`
- Create: `docs/spec/registry/objects.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/vectors/generator/src/registry.ts`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/releases/release-manifest.schema.json`
- Create: `docs/spec/releases/workspace/0.1.0.json`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Create: `docs/spec/registry/history/8.json`
- Modify: `docs/spec/registry/manifest.json`

**Interfaces:**
- Consumes: twelve object schemas and permanent Workspace spec anchors.
- Produces: registry revision 8, Workspace feature/invariant/reason/object allocations, and a canonical Workspace release manifest.

- [ ] **Step 1: Write registry and release tests for revision 8**

Expect `objects` in the registry entry set, the twelve unique Workspace object IDs, Workspace-owned features and invariants, `workspace/0.1.0`, complete exact dependencies, and release-manifest feature resolution.

- [ ] **Step 2: Run focused registry/docs-lint tests and verify RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/docs-lint.test.ts`
Expected: FAIL because revision 8 and Workspace release metadata are absent.

- [ ] **Step 3: Add allocations and generalized release paths**

Add registry object support, allocate the twelve objects, Workspace reason codes, security invariants, and features. Generalize manifest writers/readers to use `DOCUMENT_VERSIONS[document]` instead of hard-coded `0.5.0`. Add Workspace to schema enums and dependency maps.

- [ ] **Step 4: Author revision 8 and all release manifests**

Run:
`npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 8`
`npm --prefix docs/spec/vectors/generator run release-manifests -- "$PWD"`

Expected: revision 8 history/digest and five canonical manifests are generated.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run registry and docs-lint tests; expect PASS.

- [ ] **Step 6: Commit**

Commit message: `feat: register workspace protocol artifacts`

### Task 4: Implement policy, grant, federation, freshness, and key-delivery conformance semantics

**Files:**
- Create: `docs/spec/vectors/generator/src/workspace.ts`
- Create: `docs/spec/vectors/generator/src/workspace.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-workspace.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/vector-metadata.ts`
- Modify: `docs/spec/vectors/schema/vector.schema.json`

**Interfaces:**
- Consumes: normalized Workspace object shapes and signed/checkpoint-valid booleans supplied by vector fixtures.
- Produces: deterministic evaluators for effective authorization, grant activation, relationship allowances, host/key recovery, freshness, privacy, and event-repository selection.

- [ ] **Step 1: Write behavioral unit tests**

Cover: capability intersection; denial/revocation precedence; admin not implying governance; invitation authority; multi-approval activation; continuously current bilateral affiliation plus grace; private topology leakage rejection; inherited and overridden host sets retaining Radicle backstop; per-device leaves; full/from-admission/selected-snapshot key eligibility; host authorization; rollback/incomparable heads; 86,400-second ordinary and 300-second authority boundaries; epoch/size event-repo rotation; and exact-byte event identity.

- [ ] **Step 2: Run the Workspace unit test and verify RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/workspace.test.ts`
Expected: FAIL because Workspace evaluators are absent.

- [ ] **Step 3: Implement minimal deterministic evaluators**

Return `{verdict:"accept", normalized:{...}}` for valid cases and `{verdict:"reject", reason_code:<registered-code>}` for failures. Never accept from carrier write permission, MLS membership, hosting status, or self-declared timestamps alone.

- [ ] **Step 4: Run unit tests and verify GREEN**

Run the focused Workspace unit test and expect PASS.

- [ ] **Step 5: Author positive and negative vectors**

Add Workspace-owned vectors whose IDs cover object validation, policy narrowing, grants/revocations, invitations, bilateral allowances, privacy, hosting/failover, device leaves, key push/pull/history, freshness, joint governance, repository rotation, and exact-byte carrier equivalence. Add every ID to the exhaustive metadata inventory with Workspace ownership and dependencies.

- [ ] **Step 6: Run author tests**

Run: `npm --prefix docs/spec/vectors/generator test -- src/author.test.ts src/workspace.test.ts`
Expected: PASS with every Workspace topic authored and schema-valid.

- [ ] **Step 7: Commit**

Commit message: `test: add workspace conformance corpus`

### Task 5: Complete profiles, architecture, security evidence, and changelog integration

**Files:**
- Modify: `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security/threat-model.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: registered Workspace invariants/features and complete vector coverage.
- Produces: claimable base/strict Workspace profiles, optional Control/Social composition rules, integration references, and exact threat-model evidence.

- [ ] **Step 1: Write docs-lint assertions for integration**

Require the Workspace document in the family, all permanent qualified anchors to resolve, strict-profile flattened invariant membership to be complete, every registry invariant description to appear exactly in the threat-model table, and no live normative citation to ADR-044.

- [ ] **Step 2: Run docs-lint and verify RED**

Run: `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`
Expected: FAIL until integration and evidence are complete.

- [ ] **Step 3: Finish the canonical spec and supporting documents**

Specify base and strict profiles; optional Control and Social compositions; object processing; repository layout; privacy; inheritance; federation; invitations; host custody; key recovery; lifecycle; freshness; errors; security; and conformance. Update Core/Comms/Control/Social only where they need to recognize Workspace as a consumer/composition. Update architecture, threat model, README map, and Unreleased changelog; cite ADR-044 only from the changelog.

- [ ] **Step 4: Run docs-lint and verify GREEN**

Run the focused docs-lint test and expect PASS.

- [ ] **Step 5: Commit**

Commit message: `docs: integrate workspace control plane`

### Task 6: Generate canonical projections and verify the whole patch

**Files:**
- Modify: `docs/spec/vectors/**/*.json`
- Modify: `docs/spec/vectors/coverage/*.md`
- Modify: `docs/spec/vectors/coverage/manifest.json`
- Modify: `docs/spec/vectors/fixtures.json`
- Modify: `docs/spec/vectors/schema/reason-codes.json`
- Modify: `docs/spec/vectors/schema/reason-codes.md`

**Interfaces:**
- Consumes: all authored Workspace vectors and registry revision 8.
- Produces: byte-reproducible canonical vector corpus and coverage projections.

- [ ] **Step 1: Author the vector tree**

Run: `npm --prefix docs/spec/vectors/generator run author`
Expected: Workspace vector files and generated projections are written.

- [ ] **Step 2: Run full family and vector verification**

Run:
`npm --prefix docs/spec/vectors/generator run family:check`
`npm --prefix docs/spec/vectors/generator run check`

Expected: both exit 0 with no stale generated artifacts, schema failures, dependency errors, or coverage gaps.

- [ ] **Step 3: Audit the patch against the design**

Check every design success criterion against a normative Workspace anchor and one or more vectors; confirm there are no references from live normative documents to the design or ADR; confirm `docs/reviews/` and `research/sources/` are untouched.

- [ ] **Step 4: Verify repository hygiene**

Run:
`git diff --check`
`git status --short`
`git diff --stat main...HEAD`

Expected: no whitespace errors; only intended protocol, generator, generated-vector, ADR, and documentation files differ.

- [ ] **Step 5: Commit**

Commit message: `chore: generate workspace conformance artifacts`
