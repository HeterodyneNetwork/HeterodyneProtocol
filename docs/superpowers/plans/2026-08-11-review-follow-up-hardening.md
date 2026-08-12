# Review Follow-up Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the approved review-follow-up design into the canonical Heterodyne specification, registry, releases, schemas, deterministic vectors, and locally verifiable Marmot archive.

**Architecture:** Extend the existing TypeScript vector generator with small pure validators for Tier 3 device resolution, persona-profile migration, retired-key observation, and node-advertisement time. Keep Core responsible for identity/profile/time and generic client capability, Comms responsible for Tier 3 and Marmot storage, and Social responsible only for how canonical profile state is presented socially. Advance the immutable registry history to revision 7 and regenerate all revision-bound artifacts.

**Tech Stack:** Markdown specifications, JSON Schema draft 2020-12, canonical JSON registry/release artifacts, TypeScript, Vitest, Nostr event vectors, Git/Radicle.

## Global Constraints

- The approved design at `docs/superpowers/specs/2026-08-11-review-follow-up-hardening-design.md` is the complete behavior source for this patch.
- The specification and normative artifacts must stand alone at merge; the accepted ADR is historical and the design file is removed.
- `registry_revision: 2` in v1 claim wire objects remains fixed profile-allocation content while release/conformance metadata advances to revision 7.
- Nostr wire public keys are lowercase 64-character hexadecimal strings; `npub` is presentation only.
- Core exposes only generic repo-relay client conformance; Radicle-backed Marmot storage remains the sole relay server/storage profile.
- Generated vectors are edited through their deterministic TypeScript authors, not by hand.

---

### Task 1: Test and implement validation primitives

**Files:**
- Create: `docs/spec/vectors/generator/src/follow-up-hardening.ts`
- Create: `docs/spec/vectors/generator/src/follow-up-hardening.test.ts`

**Interfaces:**
- Produces: `resolveTier3Recipients`, `validateCanonicalProfile`, `classifyRetiredKeyObservation`, and `validateNodeAdvertisementTime` for deterministic vector generation.

- [ ] **Step 1: Write failing tests** for active-device expansion and narrowing, cold-root/epoch/revoked-key rejection, canonical publisher and NIP-05 validation, successor-coordinate migration, relay-only provisional retired-key classification, and every 300-second/86,400-second node-advert boundary.
- [ ] **Step 2: Run** `npm --prefix docs/spec/vectors/generator test -- follow-up-hardening.test.ts` **and confirm failures are caused by the missing module.**
- [ ] **Step 3: Implement the minimal pure typed validators** with stable reason codes and normalized results matching the approved design.
- [ ] **Step 4: Re-run the focused test and confirm it passes.**

### Task 2: Author the new normative vectors

**Files:**
- Create: `docs/spec/vectors/generator/src/topics-follow-up-hardening.ts`
- Modify: `docs/spec/vectors/generator/src/author.ts`
- Modify: `docs/spec/vectors/generator/src/vector-metadata.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Generated: `docs/spec/vectors/privacy-tiers/*.json`, `docs/spec/vectors/persona-profile/*.json`, `docs/spec/vectors/key-retirement/*.json`, `docs/spec/vectors/node-advert/*.json`

**Interfaces:**
- Consumes: Task 1 validators.
- Produces: deterministic consume vectors for each changed validation rule and coverage references to canonical spec anchors.

- [ ] **Step 1: Add generator tests** asserting the new vector IDs, owners, anchors, and expected verdict/reason-code vocabulary.
- [ ] **Step 2: Run the focused generator tests and confirm the missing vectors fail.**
- [ ] **Step 3: Add the topic author** and register it with the author and coverage machinery.
- [ ] **Step 4: Run** `npm --prefix docs/spec/vectors/generator run author` **and the focused tests.**

### Task 3: Integrate the canonical protocol documents and schemas

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/spec/heterodyne.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security/threat-model.md`
- Create: `docs/spec/schemas/core/persona-profile-v1.schema.json`
- Modify: `docs/spec/schemas/comms/key-claim-v1.schema.json`
- Modify: `docs/spec/schemas/comms/key-claim-revocation-v1.schema.json`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Produces: self-contained normative anchors for Tier 3 device delivery, persona profiles and migration, provisional retired-key content, node-advertisement time, cold-root failure, fixed claim profile revision, and narrowed repo-relay conformance.

- [ ] **Step 1: Add failing documentation-lint assertions** for forbidden generic server/storage claims, ambiguous wire `npub`, absent claim revision semantics, and absent current NIP allocations.
- [ ] **Step 2: Run the lint tests and confirm the new assertions fail.**
- [ ] **Step 3: Update the family documents, threat model, architecture, and persona-profile schema** so every approved rule is normative without relying on the ADR.
- [ ] **Step 4: Re-run the documentation and schema tests.**

### Task 4: Freeze Marmot bytes and advance the registry

**Files:**
- Create: `docs/spec/external/marmot/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/**`
- Create: `docs/spec/external/marmot/manifest.json`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/registry/kinds.json`
- Modify: `docs/spec/registry/manifest.json`
- Create: `docs/spec/registry/history/7.json`
- Modify: `docs/spec/releases/*/0.5.0.json`
- Modify: registry-bound generated vectors and coverage manifests.

**Interfaces:**
- Produces: a closed byte-for-byte Marmot archive manifest and immutable registry revision 7 containing upstream kinds 1059 and 22242.

- [ ] **Step 1: Add failing archive tests** for missing, extra, changed, and traversal entries plus registry tests for both upstream kinds.
- [ ] **Step 2: Run the focused tests and confirm the archive/allocation failures.**
- [ ] **Step 3: Materialize the approved upstream file set, generate byte length/Git blob/SHA-256 records and aggregate digest, add the two kind entries, and author registry revision 7.**
- [ ] **Step 4: Regenerate registry-bound release manifests and vectors; run archive, registry, family, and vector tests.**

### Task 5: Archive the decision and integrate the reviewed branch

**Files:**
- Create: `docs/adr/archive/2026-08-11-043-review-follow-up-hardening.md`
- Modify: changelog entry that records PR #22
- Delete: `docs/superpowers/specs/2026-08-11-review-follow-up-hardening-design.md`
- Delete: `docs/superpowers/plans/2026-08-11-review-follow-up-hardening.md`

**Interfaces:**
- Produces: historical auditability while leaving live protocol authority entirely in the specification and normative artifacts.

- [ ] **Step 1: Convert the approved design into accepted ADR 043 and add the PR #22 changelog reference.**
- [ ] **Step 2: Remove the noncanonical design and implementation plan from the merge tree.**
- [ ] **Step 3: Run** `npm --prefix docs/spec/vectors/generator run family:check`, `npm --prefix docs/spec/vectors/generator run check`, **and** `git diff --check`.
- [ ] **Step 4: Review the complete diff, commit intentionally, and push with an explicit branch refspec.**
- [ ] **Step 5: Mark PR #22 ready, merge it, fast-forward local `main`, rerun the full checks on merged `main`, and push that exact main commit to Radicle with an explicit refspec.**
