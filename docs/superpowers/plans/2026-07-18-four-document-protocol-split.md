# Four-Document Protocol Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute ADR-033 by replacing the 0.4.0 monolith with independently versioned Core, Comms, Control, and Social specifications, plus executable registry, reference, security, and vector ownership checks.

**Architecture:** Keep the monolith normative while the four documents are extracted and validated. Introduce one Core-owned registry and one generator-emitted coverage manifest before cutover; all per-document views derive from those sources. Archive and replace the monolith only after document-DAG, anchor, registry, schema, generator, and companion-document checks are green.

**Tech Stack:** Markdown; JSON and JSON Schema; TypeScript 5.9; AJV 8; Vitest 4; existing Nostr/Radicle vector generator.

## Global Constraints

- ADR-033 is normative for the split; the approved design is `docs/superpowers/specs/2026-07-18-four-document-protocol-split-design.md`.
- Preserve the final 0.4.0 monolith byte-for-byte and never restamp existing signed events.
- Document dependencies are exactly `Core <- Comms <- Control` and `Core <- Comms <- Social`.
- All four documents begin at 0.5.0 as independent descendants of monolith 0.4.x.
- The split cutover is a pre-release checkpoint: do not create 0.5.0 tags while the approved claims/OIDC phase remains queued, because that phase is also targeted at Comms 0.5.0 and registry revision 2.
- A lower document must not normatively reference a higher document; Social must not normatively depend on Control.
- Existing vector IDs are immutable; changed behavior receives a new vector ID.
- `research/sources/` is read-only.
- The specification remains implementation-agnostic.
- Run every command from the repository root unless a step explicitly says otherwise.
- Existing untracked `.claude-flow/` and `.repowise/` directories are user/tool state and must not be staged.

---

## File Structure

### New normative and migration files

- `docs/spec/heterodyne-core.md` — Core 0.5.0 normative specification.
- `docs/spec/heterodyne-comms.md` — Comms 0.5.0 normative specification.
- `docs/spec/heterodyne-control.md` — Control 0.5.0 incomplete draft/profile until ADR-030 acceptance and coverage.
- `docs/spec/heterodyne-social.md` — Social 0.5.0 normative draft with optional Matrix feature.
- `docs/spec/archive/heterodyne-0.4.0.md` — byte-identical frozen monolith.
- `docs/spec/archive/heterodyne-0.4.0-anchor-map.md` — every old heading to permanent new anchor.
- `docs/spec/heterodyne.md` — non-normative family overview after cutover.

### Registry and releases

- `docs/spec/registry/manifest.json` — registry revision, schema version, and entry-set digest.
- `docs/spec/registry/registry.schema.json` — registry JSON Schema.
- `docs/spec/registry/kinds.json` — kind ownership, stability, and immutable profiles.
- `docs/spec/registry/reason-codes.json` — reason-code ownership and first-version metadata.
- `docs/spec/registry/security-invariants.json` — namespaced invariant allocation.
- `docs/spec/registry/history/1.json` — immutable canonical snapshot of registry revision 1.
- `docs/spec/releases/release-manifest.schema.json` — exact document/dependency/registry combination schema.
- `docs/spec/releases/core/0.5.0.json` — Core first-release manifest.
- `docs/spec/releases/comms/0.5.0.json` — Comms first-release manifest.
- `docs/spec/releases/control/0.5.0.json` — incomplete Control draft manifest.
- `docs/spec/releases/social/0.5.0.json` — Social first-release manifest.

### Generator and validation

- `docs/spec/vectors/generator/src/family.ts` — document IDs, qualified versions, dependencies, and reference parsing.
- `docs/spec/vectors/generator/src/family.test.ts` — DAG, version, and reference tests.
- `docs/spec/vectors/generator/src/registry.ts` — registry loading, digesting, and validation.
- `docs/spec/vectors/generator/src/registry.test.ts` — registry invariants.
- `docs/spec/vectors/generator/src/coverage.ts` — authoritative coverage manifest and derived views.
- `docs/spec/vectors/generator/src/coverage.test.ts` — ownership and deterministic-output tests.
- `docs/spec/vectors/generator/src/docs-lint.ts` — permanent-anchor and normative-reference audit.
- `docs/spec/vectors/generator/src/docs-lint.test.ts` — archive map and DAG regression tests.
- `docs/spec/vectors/coverage/manifest.json` — generated family coverage data.
- `docs/spec/vectors/coverage/core.md` — generated Core view.
- `docs/spec/vectors/coverage/comms.md` — generated Comms view.
- `docs/spec/vectors/coverage/control.md` — generated Control view.
- `docs/spec/vectors/coverage/social.md` — generated Social view.
- `docs/spec/vectors/coverage/family.md` — generated family view.

---

### Task 1: Freeze the baseline and add family-validation interfaces

**Files:**
- Create: `docs/spec/archive/heterodyne-0.4.0.md`
- Create: `docs/spec/vectors/generator/src/family.ts`
- Create: `docs/spec/vectors/generator/src/family.test.ts`
- Modify: `docs/spec/vectors/generator/src/types.ts`
- Modify: `docs/spec/vectors/generator/src/cli.ts`
- Modify: `docs/spec/vectors/generator/package.json`

**Interfaces:**
- Produces: `DocumentId`, `QualifiedVersion`, `DOCUMENT_VERSIONS`, `DOCUMENT_DEPENDENCIES`, `parseQualifiedVersion()`, and `assertAllowedDependency()`.
- Consumes: no new interfaces.

- [ ] **Step 1: Record and archive the exact monolith bytes**

Run from the repository root:

```bash
shasum -a 256 docs/spec/heterodyne.md
mkdir -p docs/spec/archive
cp docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md
cmp -s docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md
```

Expected: `cmp` exits 0. Record the SHA-256 value in the archive map created in Task 9; do not edit the archive after this step.

- [ ] **Step 2: Write failing family grammar and DAG tests**

Create tests that assert:

```ts
expect(parseQualifiedVersion("core/0.5.0")).toEqual({ document: "core", semver: "0.5.0" });
expect(() => parseQualifiedVersion("0.5.0")).toThrow("qualified version");
expect(() => assertAllowedDependency("core", "comms")).toThrow("forbidden dependency");
expect(() => assertAllowedDependency("social", "control")).toThrow("forbidden dependency");
expect(() => assertAllowedDependency("control", "comms")).not.toThrow();
expect(() => assertAllowedDependency("social", "comms")).not.toThrow();
```

- [ ] **Step 3: Run the focused tests and verify failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/family.test.ts
```

Expected: FAIL because `family.ts` and its exports do not exist.

- [ ] **Step 4: Implement the family interfaces**

Use these exact public types and constants:

```ts
export type DocumentId = "core" | "comms" | "control" | "social";
export type QualifiedVersion = { document: DocumentId; semver: string };

export const DOCUMENT_VERSIONS: Record<DocumentId, string> = {
  core: "0.5.0",
  comms: "0.5.0",
  control: "0.5.0",
  social: "0.5.0",
};

export const DOCUMENT_DEPENDENCIES: Record<DocumentId, readonly DocumentId[]> = {
  core: [],
  comms: ["core"],
  control: ["core", "comms"],
  social: ["core", "comms"],
};
```

The parser accepts only `^(core|comms|control|social)/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$` and returns the document plus bare semver component.

- [ ] **Step 5: Add validation scripts**

Add these package scripts:

```json
{
  "family:check": "tsx src/cli.ts family-check",
  "coverage": "tsx src/cli.ts coverage"
}
```

Wire `family-check` as a CLI command that initially validates the family constants; later tasks extend it without changing the command.

- [ ] **Step 6: Run focused and full baseline verification**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/family.test.ts
npm --prefix docs/spec/vectors/generator run check
cmp -s docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md
```

Expected: focused tests PASS; full build/tests/vector verification exit 0; archive comparison exits 0.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/archive/heterodyne-0.4.0.md docs/spec/vectors/generator/src/family.ts docs/spec/vectors/generator/src/family.test.ts docs/spec/vectors/generator/src/types.ts docs/spec/vectors/generator/src/cli.ts docs/spec/vectors/generator/package.json docs/spec/vectors/generator/package-lock.json
git commit -m "spec: freeze monolith and add family validation"
```

---

### Task 2: Create the separately revisioned registry

**Files:**
- Create: `docs/spec/registry/manifest.json`
- Create: `docs/spec/registry/registry.schema.json`
- Create: `docs/spec/registry/kinds.json`
- Create: `docs/spec/registry/reason-codes.json`
- Create: `docs/spec/registry/security-invariants.json`
- Create: `docs/spec/registry/history/1.json`
- Create: `docs/spec/vectors/generator/src/registry.ts`
- Create: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/reason-codes.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`

**Interfaces:**
- Consumes: `DocumentId` from Task 1.
- Produces: `RegistryManifest`, `KindEntry`, `ReasonCodeEntry`, `InvariantEntry`, `loadRegistry()`, `computeRegistryDigest()`, and `validateRegistry()`.

```ts
export type RegistryStatus = "draft" | "stable" | "frozen";
export type RegistryManifest = { revision: number; schema_version: string; entry_set_sha256: string };
export type KindProfile = { profile_id: string; owner: DocumentId; discriminator: string; stamping: boolean; first_version: string; status: RegistryStatus };
export type KindEntry = { kind: number; allocation_authority: "heterodyne" | "nostr"; base_schema_owner: DocumentId | "nostr"; status: RegistryStatus; first_version: string; profiles: KindProfile[] };
export type ReasonCodeEntry = { code: string; owner: DocumentId; status: RegistryStatus; first_version: string; description: string; spec_refs: string[] };
export type InvariantEntry = { id: string; owner: DocumentId; status: RegistryStatus; first_version: string; description: string };
export type Registry = { manifest: RegistryManifest; kinds: KindEntry[]; reason_codes: ReasonCodeEntry[]; security_invariants: InvariantEntry[]; history: Map<number, unknown>; currentEntrySet: unknown };
export declare function loadRegistry(root: string): Registry;
export declare function computeRegistryDigest(registry: Pick<Registry, "kinds" | "reason_codes" | "security_invariants">): string;
export declare function validateRegistry(registry: Registry): void;
```

- [ ] **Step 1: Write failing registry tests**

Cover these exact rules:

```ts
expect(registry.manifest.revision).toBe(1);
expect(registry.history.get(1)).toEqual(registry.currentEntrySet);
expect(registry.kinds.find((entry) => entry.kind === 31001)?.base_schema_owner).toBe("core");
expect(registry.kinds.find((entry) => entry.kind === 31007)?.base_schema_owner).toBe("comms");
expect(registry.kinds.find((entry) => entry.kind === 10000)?.allocation_authority).toBe("nostr");
expect(() => validateRegistry(withDuplicateDiscriminator(registry))).toThrow("duplicate profile discriminator");
expect(() => validateRegistry(withFrozenMutation(registry))).toThrow("frozen entry");
expect(computeRegistryDigest(registry)).toMatch(/^[0-9a-f]{64}$/);
```

Also test the local downref gates: `draft -> stable -> frozen` is the only
allowed entry-state progression; no frozen entry may be removed, reassigned,
or semantically changed; a 1.0 document may require only frozen entries; and
the Comms 1.0 check remains blocked until the double-ratchet wire has an
immutable frozen profile.

- [ ] **Step 2: Verify the tests fail**

Run `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts`.

Expected: FAIL because registry files and loader are absent.

- [ ] **Step 3: Define the registry schema**

The schema requires `revision` to equal positive integer 1, `schema_version`
to equal `1.0.0`, and `entry_set_sha256` to match
`^[0-9a-f]{64}$`. The committed digest is always the actual return value of
`computeRegistryDigest()` over the seeded entry set; do not paste a sample or
sentinel digest.

Each kind requires `kind`, `allocation_authority`, `base_schema_owner`, `status`, and `first_version`. Profiles require immutable `profile_id`, `owner`, `discriminator`, `stamping`, and `first_version`. Status is exactly `draft`, `stable`, or `frozen`.

Each reason code requires `code`, `owner`, `status`, `first_version`, `description`, and qualified `spec_refs`. Each invariant requires `id`, `owner`, `status`, `first_version`, and `description`.

- [ ] **Step 4: Seed every current allocation**

Transcribe all kinds from archived §3.0. Apply ADR-033 ownership corrections, including:

```text
31000-31003, 31005, 31010 -> Core
31007, 31011, 31012, 30078 DR invite profile -> Comms
31004, 31008, 31009, Matrix/NIP-51 social profiles -> Social
31001 -> Core base schema; reserved Control session-device profile
kind:0 and kind:1 breadcrumb profiles -> Core, non-stamping
```

Move the reason-code vocabulary from `docs/spec/vectors/schema/reason-codes.json` into the registry container and allocate namespaced invariant IDs from the monolith threat model.

- [ ] **Step 5: Implement canonical digest and validation**

Compute `entry_set_sha256` over UTF-8 RFC 8785/JCS of one object containing
`kinds`, `reason_codes`, and `security_invariants`, excluding the manifest
digest field. Store that exact canonical entry set and digest in immutable
`history/1.json`. Validate schema, unique kinds, unique code/ID values, unique
discriminators per kind, monotonic states, qualified first versions, owners,
and byte equality between the current entry set and the current revision's
history snapshot.

- [ ] **Step 6: Switch reason-code validation to the registry**

Make `reasonCodeValues()` load the generated/committed registry reason-code container. Keep `docs/spec/vectors/schema/reason-codes.json` temporarily as a generated compatibility copy until Task 8 removes duplicate authority.

- [ ] **Step 7: Run tests and registry validation**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

Expected: all commands exit 0 and the manifest digest matches recomputation.

- [ ] **Step 8: Commit**

```bash
git add docs/spec/registry docs/spec/vectors/generator/src/registry.ts docs/spec/vectors/generator/src/registry.test.ts docs/spec/vectors/generator/src/reason-codes.ts docs/spec/vectors/generator/src/schema.ts docs/spec/vectors/schema/reason-codes.json
git commit -m "spec: add revisioned protocol registry"
```

---

### Task 3: Extract Heterodyne Core

**Files:**
- Create: `docs/spec/heterodyne-core.md`
- Create: `docs/spec/vectors/generator/src/docs-lint.ts`
- Create: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/cli.ts`

**Interfaces:**
- Consumes: qualified version grammar and registry pin from Tasks 1-2.
- Produces: permanent Core anchors and `lintFamilyDocs()`.

```ts
export type FamilyDocIssue = { path: string; line: number; code: "duplicate-anchor" | "unresolved-reference" | "forbidden-dependency" | "bare-normative-link"; message: string };
export declare function lintFamilyDocs(repoRoot: string): FamilyDocIssue[];
```

- [ ] **Step 1: Write a failing Core boundary test**

The test reads `heterodyne-core.md` and asserts:

```ts
expect(text).toContain("Document ID: `core`");
expect(text).toContain("Version: `core/0.5.0`");
expect(text).toContain("Registry revision: `1`");
expect(text).not.toMatch(/normative[^\n]*(heterodyne-comms|heterodyne-control|heterodyne-social)/i);
expect(text).not.toMatch(/follow|mutual follow|friend|Matrix identity-room cache/i);
```

- [ ] **Step 2: Verify failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`.

Expected: FAIL because `heterodyne-core.md` is absent.

- [ ] **Step 3: Create the Core document shell**

Use this front matter and permanent-anchor convention:

```markdown
# Heterodyne Core Protocol Specification

Document ID: `core`<br>
Version: `core/0.5.0`<br>
Registry revision: `1`

> Pre-release extraction draft. Until family cutover, the archived 0.4.0
> monolith remains normative.

Permanent anchors use explicit HTML IDs formed by the literal `core-` prefix
followed by a lowercase ASCII kebab-case topic, for example
`<a id="core-identity-model"></a>`.
```

- [ ] **Step 4: Extract exact Core-owned material**

Move and reconcile these monolith areas without weakening RFC 2119 language:

```text
§1 Core scope/non-goals; shared terminology needed downward
§3.0 canonical allocations/serialization owned by Core
§3.1-§3.7 identity, KEL, discovery, failures
§3.8.7 keys repository; generic encrypted-repository primitive
§3.9.8-§3.9.10 pointer/KERI/Radicle reconciliation
§3.11 Radicle multi-host seeding only
§3.12 social-neutral recovery mechanism only
§4.5 verification algorithm and ADR-032 authority rules
§7.0 node roles and npub->RID->serving-node discovery boundary
§7.7 Tor reachability
§10.1-§10.2 node/repo-relay substrate and client responsibilities
§10.5-§10.6 Nostr relay interoperability/profile
§11.3 kind:31005; KERI witnesses and did:webs export
§12 qualified versioning/capabilities/unknown-version behavior
Core portions of §13 and §14
```

Recast recovery roles as recovery peers, declared witnesses, cached identity material, and cold-root re-anchor. Define generic threshold authority and the Core keys-repository protection profile with zero Comms dependency.

Define all ADR-033 stamp classes explicitly: Heterodyne JSON content uses the
base-schema owner's qualified `spec_version`; empty/non-JSON Heterodyne kinds
use the registered version tag; adopted upstream kinds are unstamped unless an
immutable stamping profile opts in; non-stamping profiles never alter bytes;
DR outer kinds 1059/1060 carry no marker; encrypted inner rumors carry only
the Comms carrier stamp; and Control never owns a wire stamp. Define legacy
`0.4.0` inference only for monolith-stamped Heterodyne kinds and forbid
restamping historical events.

Define capability advertisements with a stable Core bootstrap shape,
per-document supported-version sets, required feature IDs, registry revision,
and strict-profile IDs. Peer sessions negotiate before sending a stamped
version; asynchronous consumers reject or explicitly degrade unknown stamped
versions. Enforce the document-level downref ordering `0.x < 1.0+` and the
registry-level ordering `draft < stable < frozen`.

- [ ] **Step 5: Implement the document linter**

`lintFamilyDocs()` parses explicit HTML anchors and qualified references using
the grammar
`heterodyne:(core|comms|control|social)/MAJOR.MINOR.PATCH#lowercase-kebab-anchor`,
plus normative dependency declarations. It reports duplicate anchors,
unresolved anchors, forbidden edges, and bare relative normative
cross-document links.

- [ ] **Step 6: Run focused checks**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts
npm --prefix docs/spec/vectors/generator run family:check
rg -n 'follow|mutual follow|friend|Matrix identity-room cache' docs/spec/heterodyne-core.md
cmp -s docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md
```

Expected: tests and family check pass; `rg` prints no Core recovery-policy leak; monolith/archive comparison exits 0.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/heterodyne-core.md docs/spec/vectors/generator/src/docs-lint.ts docs/spec/vectors/generator/src/docs-lint.test.ts docs/spec/vectors/generator/src/cli.ts
git commit -m "spec: extract Heterodyne Core"
```

---

### Task 4: Extract Heterodyne Comms and execute Thin-P1 closure

**Files:**
- Create: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: `core/0.5.0` permanent anchors and registry revision 1.
- Produces: Comms acceptance-hook, credential-sync, subprotocol-carrier, and org-threshold interfaces.

- [ ] **Step 1: Add failing Comms boundary tests**

Assert the document has a version-bound Core dependency, contains no normative Social/Control dependency, and contains all hook outcomes/contexts:

```ts
for (const outcome of ["accept", "hold-as-message-request", "reject"]) expect(text).toContain(outcome);
for (const context of ["ordinary-dm", "credential-sync", "control-enrollment"]) expect(text).toContain(context);
expect(text).not.toMatch(/follow.*gate|web-of-trust.*gate/i);
```

- [ ] **Step 2: Verify failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`.

Expected: FAIL because Comms is absent.

- [ ] **Step 3: Create the Comms shell and exact Core dependency**

Declare document `comms/0.5.0`, registry revision 1, and normative dependency `heterodyne:core/0.5.0#core-conformance`.

- [ ] **Step 4: Extract exact Comms-owned material**

Move and reconcile:

```text
Nostr-native event envelope and verification entry point
§5.2 privacy tiers and §6.10 encrypted/private repos
§5.7 DR DMs, invite/response/wire, retention
§6.1-§6.4 publishing, fan-out, idempotency, delivery contract
§6.7 generic feed-index ordering, including org threshold authorization
§6.8-§6.9 indexing/retrieval/backfill without social policy
§7.1-§7.2 generic outbox advertisement/location only
§9 Comms confidentiality and forward-secrecy portions
config-repository encryption profile bound to Core's generic primitive
```

- [ ] **Step 5: Define the acceptance hook and credential plane**

Specify authentication-before-policy, enumerated inputs, the three outcomes/contexts, no sender-observable signal before acceptance, and a Comms-native default. Define the credential-sync authorization as signed, target-NID-bound, purpose-bound, KEL-validated, revocable, and restricted to durable NID-bearing delegations.

- [ ] **Step 6: Define subprotocol negotiation and carrier ownership**

Define an encrypted inner frame with `protocol_id`, `supported_versions`, and
`required_features`. Require negotiation before payload interpretation and
local audit retention. Consume the Comms-owned generic carrier-rumor entries
already seeded in registry revision 1; do not mutate the registry here and do
not allocate Control stamping authority.

- [ ] **Step 7: Close Thin-P1 leaks**

Replace follow/reply/WoT DM admission with the hook. Remove the declaration that NIP-51 is a lower-layer construct. Move follower discovery, moderator-specific feed policy, private mute/feed preferences, and followed-repository payload semantics out of Comms.

- [ ] **Step 8: Verify boundaries**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts
npm --prefix docs/spec/vectors/generator run family:check
rg -n 'follow.*gate|web-of-trust.*gate|NIP-51.*core construct' docs/spec/heterodyne-comms.md
cmp -s docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md
```

Expected: tests pass; leak scan prints no matches; monolith remains unchanged.

- [ ] **Step 9: Commit**

```bash
git add docs/spec/heterodyne-comms.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: extract Heterodyne Comms"
```

---

### Task 5: Extract Heterodyne Social

**Files:**
- Create: `docs/spec/heterodyne-social.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: Core and Comms permanent anchors, including the acceptance hook.
- Produces: Social, Social+Matrix, Social NIP-51, moderation, and recovery-binding profiles.

- [ ] **Step 1: Add failing Social boundary tests**

Assert exact Core/Comms dependencies, no Control dependency, separate `Social` and `Social+Matrix` claims, and an explicit Matrix-free conformance statement.

- [ ] **Step 2: Run the focused test and observe failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`.

Expected: FAIL because Social is absent.

- [ ] **Step 3: Create the Social shell**

Declare `social/0.5.0`, registry revision 1, exact-version 0.x instability, and version-bound Core/Comms dependencies.

- [ ] **Step 4: Extract social interactions and discovery**

Move replies, reactions, threading, following, social graph, transitive/follower discovery, cross-persona ads, reply inboxes, mixed-tier fan-out, and feed presentation.

- [ ] **Step 5: Extract moderation, lists, org presentation, and ATProto**

Move NIP-72, Radicle editorial gating, mutes/NIP-51/policy lists, NIP-32,
WoT, starter packs, community/org presentation, and ATProto. Define the Social
NIP-51 marker and bind it to the immutable stamping profile already seeded in
registry revision 1 as `social/0.5.0`; plain upstream NIP-51 remains unstamped.

- [ ] **Step 6: Extract the complete optional Matrix feature**

Move MXID delegation/election/leases/failover, wrapped/bare envelopes, discussion rooms, Megolm/MLS, config room, homeserver exit, headless bridge, homeserver requirements, vanilla-Matrix interop, and fallback rendering. State that Matrix-free Social conformance is complete.

- [ ] **Step 7: Define Social policy bindings**

Bind mute/WoT admission as a tighten-only Comms hook implementation. Bind Core recovery roles to follows/friends/Matrix caches only inside Social.

- [ ] **Step 8: Verify boundaries**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts`, `npm --prefix docs/spec/vectors/generator run family:check`, and `rg -n 'heterodyne:control/' docs/spec/heterodyne-social.md`.

Expected: all tests pass and the Control scan prints no matches.

- [ ] **Step 9: Commit**

```bash
git add docs/spec/heterodyne-social.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: extract Heterodyne Social"
```

---

### Task 6: Create the Control profile draft and amend ADR allocation notes

**Files:**
- Create: `docs/spec/heterodyne-control.md`
- Modify: `docs/adr/2026-07-07-030-light-client-enrollment-rpc-over-dr-dms.md`
- Modify: `docs/adr/2026-07-07-031-vanilla-nostr-breadcrumbs-and-interop.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: Comms DR feature, acceptance hook, negotiation, and carriers.
- Produces: incomplete Control-profile document without a conformance claim.

- [ ] **Step 1: Add failing Control-profile tests**

Assert:

```ts
expect(text).toContain("incomplete 0.5.0 draft");
expect(text).toContain("Core + Comms conformant + Control profile");
expect(text).toContain("comms/0.5.0");
expect(text).toContain("double-ratchet");
expect(text).toContain("no Control conformance claim");
expect(text).not.toMatch(/control\/0\.5\.0.*stamp/i);
```

- [ ] **Step 2: Verify the test fails**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`.

Expected: FAIL because Control is absent.

- [ ] **Step 3: Create the incomplete Control document**

Define Control as a no-transport, no-wire-stamp Comms profile. Declare exact supported Comms set `{comms/0.5.0}`, require the DR feature, enumerate enrollment/RPC/grants/tokens/MCP scope, and state that ADR-030 acceptance/integration plus minimum vectors are required before conformance can be claimed.

- [ ] **Step 4: Amend ADR-030 allocation and sequencing**

Add an amendment section that assigns session-device base extensibility to Core; epoch invite, undelegated initiator, DR contexts, and negotiation to Comms; enrollment/RPC/grants/tokens/MCP to Control. Scope the no-key-export rule to session devices and preserve Comms credential sync for authorized NID devices. Change integration targets from monolith sections to qualified family documents.

- [ ] **Step 5: Amend ADR-031 allocation and sequencing**

Assign breadcrumb production/verification exclusion to Core and
vanilla-follow/UI behavior to Social. Reference the kind:0/kind:1
non-stamping breadcrumb profiles already seeded in registry revision 1.

- [ ] **Step 6: Verify profile and ADR consistency**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts
npm --prefix docs/spec/vectors/generator run family:check
rg -n 'docs/spec/heterodyne\.md|§[0-9]' docs/adr/2026-07-07-030-light-client-enrollment-rpc-over-dr-dms.md docs/adr/2026-07-07-031-vanilla-nostr-breadcrumbs-and-interop.md
```

Expected: tests pass; remaining monolith references occur only in explicitly labeled historical context, never integration targets.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/heterodyne-control.md docs/adr/2026-07-07-030-light-client-enrollment-rpc-over-dr-dms.md docs/adr/2026-07-07-031-vanilla-nostr-breadcrumbs-and-interop.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: establish Control profile boundary"
```

---

### Task 7: Split security/conformance profiles and update companion documents

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/security/threat-model.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `AGENTS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/architecture.md`
- Modify: `docs/glossary.md`
- Modify: `research/INDEX.md`
- Modify: `docs/spec/extensions/nips/README.md`
- Modify: `docs/spec/extensions/mscs/README.md`

**Interfaces:**
- Consumes: all four document boundaries.
- Produces: namespaced invariants, strict-mode profile IDs, and family-aware navigation.

- [ ] **Step 1: Write failing invariant and companion-doc lint tests**

Reject undecomposed invariant IDs `I1`, `I3`, `I6`, `I7`; require `CORE-I`, `COMMS-I`, `CONTROL-I`, and `SOCIAL-I` namespaces. Reject prose claiming one normative spec or using uppercase `CORE` as current conformance terminology.

- [ ] **Step 2: Run focused tests and verify failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts`.

Expected: FAIL on the current threat model and companion prose.

- [ ] **Step 3: Split invariants and strict mode**

Decompose threat-model assumptions and mitigations by owner. Define stable strict profile IDs:

```text
heterodyne-core-strict-v1
heterodyne-comms-strict-v1
heterodyne-control-strict-v1
heterodyne-social-strict-v1
heterodyne-social-matrix-strict-v1
```

Add explicit composition rules to Core, capabilities, and conformance reports.
Bind each decomposed rule to the invariant entries already seeded in registry
revision 1. Control audit encryption must depend only on Core/Comms/Control
invariants.

- [ ] **Step 4: Rewrite companion navigation and architecture**

Update all listed companions to name the family and four documents. `docs/architecture.md` includes the exact DAG. The glossary remains a non-normative index; normative shared terms live in Core. Requalify stale extension-index anchors.

- [ ] **Step 5: Verify family prose**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts
npm --prefix docs/spec/vectors/generator run family:check
rg -n 'single normative spec|the normative spec|fully drafted.*heterodyne\.md' README.md CLAUDE.md AGENTS.md docs/*.md research/INDEX.md
```

Expected: tests pass; scan returns only historical/archive descriptions that explicitly say 0.4.0.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md AGENTS.md CHANGELOG.md docs/architecture.md docs/glossary.md docs/security/threat-model.md docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/heterodyne-social.md research/INDEX.md docs/spec/extensions
git commit -m "docs: align security and navigation with protocol family"
```

---

### Task 8: Rework vector ownership and generate coverage manifests

**Files:**
- Modify: `docs/spec/vectors/fixtures.json`
- Modify: `docs/spec/vectors/schema/vector.schema.json`
- Modify: `docs/spec/vectors/generator/src/types.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`
- Modify: `docs/spec/vectors/generator/src/fixtures.ts`
- Modify: `docs/spec/vectors/generator/src/vector-helpers.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/topics-v04.ts`
- Modify: `docs/spec/vectors/generator/src/topics-v04b.ts`
- Modify: `docs/spec/vectors/generator/src/topics-keri-authority.ts`
- Modify: `docs/spec/vectors/generator/src/topics-keri-authority-b.ts`
- Modify: `docs/spec/vectors/generator/src/topics-keri-authority-c.ts`
- Create: `docs/spec/vectors/generator/src/stamping.ts`
- Create: `docs/spec/vectors/generator/src/stamping.test.ts`
- Create: `docs/spec/vectors/generator/src/coverage.ts`
- Create: `docs/spec/vectors/generator/src/coverage.test.ts`
- Create: `docs/spec/vectors/coverage/manifest.json`
- Create: `docs/spec/vectors/coverage/core.md`
- Create: `docs/spec/vectors/coverage/comms.md`
- Create: `docs/spec/vectors/coverage/control.md`
- Create: `docs/spec/vectors/coverage/social.md`
- Create: `docs/spec/vectors/coverage/family.md`
- Modify: `docs/spec/vectors/README.md`
- Modify: `docs/spec/vectors/schema/reason-codes.json`
- Modify: `docs/spec/vectors/schema/reason-codes.md`
- Create: `docs/spec/vectors/comms-envelope/001-nostr-native-event-valid.json`
- Create: `docs/spec/vectors/comms-envelope/002-owner-stamp-valid.json`
- Create: `docs/spec/vectors/core-redundancy/001-radicle-multihost-replication.json`
- Create: `docs/spec/vectors/core-redundancy/002-stale-seed-rejected.json`
- Create: `docs/spec/vectors/acceptance-gating/001-authentication-before-policy.json`
- Create: `docs/spec/vectors/acceptance-gating/002-message-request-no-receipt.json`
- Create: `docs/spec/vectors/acceptance-gating/003-social-mute-tightens.json`
- Create: `docs/spec/vectors/acceptance-gating/004-social-policy-cannot-loosen.json`

**Interfaces:**
- Consumes: family versions, registry digest, and permanent anchors.
- Produces: `Vector.owner_document`, `owner_version`, `dependency_versions`,
  `registry_revision`, `profile`, `stampOwner()`, `inferLegacyOwner()`, and the
  authoritative coverage manifest.

```ts
export type StampInput = { kind: number; profile_id?: string; content_is_heterodyne_json: boolean; is_dr_outer: boolean };
export declare function stampOwner(input: StampInput, registry: Registry): "core" | "comms" | "social" | null;
export declare function inferLegacyOwner(input: { kind: number; stamp?: string; adopted_upstream: boolean }): "monolith/0.4.0";
export type CoverageEntry = { vector_id: string; owner_document: DocumentId; owner_version: string; dependency_versions: Partial<Record<DocumentId, string>>; registry_revision: number; profile?: string; spec_refs: string[] };
export declare function buildCoverage(vectors: Vector[]): CoverageEntry[];
```

- [ ] **Step 1: Write failing schema and coverage tests**

Use this exact vector interface:

```ts
export type Vector = {
  vector_id: string;
  vector_schema_version: string;
  owner_document: DocumentId;
  owner_version: string;
  dependency_versions: Partial<Record<DocumentId, string>>;
  registry_revision: number;
  profile?: string;
  spec_refs: string[];
  description: string;
  direction: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
};
```

Assert no `spec_version` field remains and every spec reference is qualified.

Add table-driven tests for every wire-stamp class and legacy rule:

```ts
expect(stampOwner(kind31001Base)).toBe("core");
expect(stampOwner(kind31001ControlProfile)).toBe("core");
expect(stampOwner(socialNip51Profile)).toBe("social");
expect(stampOwner(plainNip51)).toBeNull();
expect(stampOwner(kind0Breadcrumb)).toBeNull();
expect(stampOwner(drOuter1060)).toBeNull();
expect(stampOwner(controlCarrierRumor)).toBe("comms");
expect(inferLegacyOwner(monolithStamped040)).toBe("monolith/0.4.0");
expect(() => inferLegacyOwner(unstampedUpstream)).toThrow("not inferable");
```

- [ ] **Step 2: Verify focused failures**

Run `npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts src/author.test.ts src/coverage.test.ts`.

Expected: FAIL because current vectors use scalar `spec_version` and coverage output is absent.

- [ ] **Step 3: Make fixtures and vector helpers version-neutral**

Replace fixture `spec_version` with:

```json
{
  "document_versions": {
    "core": "0.5.0",
    "comms": "0.5.0",
    "control": "0.5.0",
    "social": "0.5.0"
  },
  "registry_revision": 1
}
```

Update `baseVector()` to require owner and derive only permitted dependencies.

- [ ] **Step 4: Assign every existing vector individually**

Apply ADR-033 requirement 38 exactly: Matrix envelope vectors to Social; interop split; org/001-003 Core and org/004 Comms; redundancy to Social; recovery/config-backup split per vector. Preserve existing vector IDs when semantics are unchanged.

- [ ] **Step 5: Add required new split vectors**

Add Comms Nostr-native envelope vectors, Core Radicle multi-host redundancy vectors, Comms hook ordering/outcome/no-receipt vectors, and Social tighten-only mute/WoT policy vectors. Use new IDs for all new behavior.

Add Core vectors for qualified-version parsing, capability bootstrap and
per-document negotiation, unknown asynchronous stamps, all stamp-placement
classes above, scoped legacy inference, and the no-restamp rule. Add registry
vectors for downref rejection and frozen-entry immutability. Add no Control
conformance vectors: its coverage view must explicitly report
`incomplete-draft` until ADR-030's minimum corpus exists.

- [ ] **Step 6: Generate the single coverage source and views**

`coverage.ts` sorts by `vector_id` and emits entries containing owner, profile, qualified refs, dependencies, and registry revision. The four document maps and family map are generated Markdown projections of that JSON.

- [ ] **Step 7: Remove duplicate reason-code authority**

Generate `docs/spec/vectors/schema/reason-codes.json` and `.md` from the registry container, and document `docs/spec/registry/reason-codes.json` as authoritative.

- [ ] **Step 8: Regenerate and run the full suite**

Run:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
git add -u docs/spec/vectors docs/spec/vectors/generator
git add docs/spec/vectors/comms-envelope docs/spec/vectors/core-redundancy docs/spec/vectors/acceptance-gating docs/spec/vectors/coverage
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors
```

Expected: all commands exit 0; regeneration leaves no diff; every committed vector validates.

- [ ] **Step 9: Commit**

```bash
git add -u docs/spec/vectors docs/spec/vectors/generator
git add docs/spec/vectors/comms-envelope docs/spec/vectors/core-redundancy docs/spec/vectors/acceptance-gating docs/spec/vectors/coverage docs/spec/vectors/generator/src/stamping.ts docs/spec/vectors/generator/src/stamping.test.ts docs/spec/vectors/generator/src/coverage.ts docs/spec/vectors/generator/src/coverage.test.ts
git commit -m "test: assign family vector ownership and coverage"
```

---

### Task 9: Publish anchor migration, cut over, and prepare 0.5.0 releases

**Files:**
- Create: `docs/spec/archive/heterodyne-0.4.0-anchor-map.md`
- Replace: `docs/spec/heterodyne.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-social.md`
- Create: `docs/spec/releases/release-manifest.schema.json`
- Create: `docs/spec/releases/core/0.5.0.json`
- Create: `docs/spec/releases/comms/0.5.0.json`
- Create: `docs/spec/releases/control/0.5.0.json`
- Create: `docs/spec/releases/social/0.5.0.json`
- Modify: `CHANGELOG.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: all four final document anchor sets, registry digest, and coverage manifest.
- Produces: frozen migration map, non-normative family overview, and exact release manifests.

- [ ] **Step 1: Write failing archive-map and cutover tests**

Parse every ATX heading from the archive and require one explicit mapping row with a resolvable destination anchor. Assert the new overview contains no RFC 2119 uppercase keywords outside quotations/historical text and extraction banners are absent after cutover.

- [ ] **Step 2: Verify tests fail**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts`.

Expected: FAIL because the map and cutover overview do not exist.

- [ ] **Step 3: Create the complete anchor map**

Include the recorded archive SHA-256 and one row per old heading:

```markdown
| Old anchor | Owner | Qualified destination |
|---|---|---|
| `#identity-model` | Core | `heterodyne:core/0.5.0#core-identity-model` |
```

Generate or mechanically validate every remaining row; do not use range summaries.

- [ ] **Step 4: Replace the monolith with a non-normative family overview**

The overview contains mission, DAG, document/version table, conformance class table, archive link, anchor-map link, registry link, and vector coverage link. It contains no normative requirements.

- [ ] **Step 5: Remove extraction banners and finalize lineage**

Each sibling document states it is a first 0.5.0 release descended from monolith 0.4.x. Control remains labeled incomplete and makes no Control conformance claim.

- [ ] **Step 6: Create release manifests**

The schema requires `registry_sha256` to equal the lowercase 64-hex digest in
`docs/spec/registry/manifest.json`. Generate each manifest from the validated
registry object so this field is never hand-copied. The Core manifest has this
shape before canonical JSON serialization:

```ts
const coreRelease = {
  "document": "core",
  "version": "0.5.0",
  "qualified_version": "core/0.5.0",
  "registry_revision": 1,
  "registry_sha256": registry.manifest.entry_set_sha256,
  "dependencies": {},
  "features": [],
  "conformance_status": "conformant"
};
```

Comms depends exactly on Core 0.5.0; Social depends exactly on Core/Comms 0.5.0; Control depends exactly on Core/Comms 0.5.0, requires `double-ratchet`, and uses `conformance_status: incomplete-draft`.

- [ ] **Step 7: Run complete cutover verification**

Run:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors
task_archive_check=$(mktemp)
git show 13ec42c:docs/spec/heterodyne.md > "$task_archive_check"
cmp -s docs/spec/archive/heterodyne-0.4.0.md "$task_archive_check"
rm "$task_archive_check"
git diff --check
```

Expected: every command exits 0; archive matches commit `13ec42c`; generator output is clean; no whitespace errors.

- [ ] **Step 8: Review requirements line by line**

Check ADR-033 requirements 1-42 and record each corresponding document anchor, registry entry, vector, or generator test in the implementation notes. Any uncovered requirement blocks completion.

- [ ] **Step 9: Commit the cutover**

```bash
git add docs/spec/heterodyne.md docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/heterodyne-social.md docs/spec/archive docs/spec/releases CHANGELOG.md docs/spec/vectors/generator/src/docs-lint.ts docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: cut over to four-document protocol family"
```

- [ ] **Step 10: Create release tags only after explicit release approval**

Do not run this step while
`docs/superpowers/plans/2026-07-18-key-claims-oidc.md` remains queued for the
same 0.5.0 release. After that phase completes, or after the user explicitly
chooses a split-only 0.5.0 release and accepts that claims move to a later
Comms version, obtain release approval and run:

```bash
git tag -a core/v0.5.0 -m "Heterodyne Core 0.5.0"
git tag -a comms/v0.5.0 -m "Heterodyne Comms 0.5.0"
git tag -a control/v0.5.0 -m "Heterodyne Control 0.5.0 draft"
git tag -a social/v0.5.0 -m "Heterodyne Social 0.5.0"
```

Expected: `git tag --list '*/v0.5.0'` prints exactly the four tag names. Do not push tags without separate user authorization.
