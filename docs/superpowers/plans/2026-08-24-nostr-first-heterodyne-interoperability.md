# Nostr-First Heterodyne Interoperability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the required cold-root/KEL identity model with a vanilla-Nostr active-key baseline, retain cold-root/KERI continuity as optional Assurance, and make public, Marmot, signing, repository, seed, social, and workspace behavior interoperable without reconciling the frozen vector snapshot.

**Architecture:** Core owns active-key personas, NIP-01/NIP-05/NIP-65 state, and exact-event repositories. A new optional Assurance document owns cold roots, reciprocal enrollment, KERI succession, associated keys, and downgrade resistance. Comms, Control, Social, and Workspace consume the Core baseline and optionally compose Assurance; current-draft tooling learns the sixth owner while the historical five-document snapshot remains independently reproducible.

**Tech Stack:** Markdown normative specifications, JSON Schema draft 2020-12, JSON registry artifacts, TypeScript, Vitest, AJV, Nostr NIP-01/05/32/42/46/65, Marmot, Radicle.

**Spec:** `docs/superpowers/specs/2026-08-24-nostr-first-heterodyne-interoperability-design.md`

## Global Constraints

- The active Nostr public key is the only baseline persona identity and the Marmot account identity; bare keys without Assurance are first-class.
- Kind `0`, NIP-05, and kind `10002` replace required kind `31005` identity pointers and kind `31007` public feed indexes.
- NIP-01 authorship, signature, addressing, filtering, and replaceable-event selection are never altered by Heterodyne metadata.
- Repository and relay carriers store the same exact signed event bytes; current state is greatest `created_at`, then lowest event ID, regardless of carrier.
- Kind `0` and kind `10002` are refreshed at least every seven days; overdue state warns but remains valid.
- The kind-0 `heterodyne` member is closed; when present, `profile` is required and invalid extension data is ignored as a whole without invalidating the kind-0 event.
- Assurance is optional and depends on Core. It cannot be a baseline prerequisite for Comms, Control, Social, Workspace, Nostr, or Marmot conformance.
- Agent-key signing is preferred; persona-key signing requires explicit scope; every automated publication receives mandatory NIP-32-compatible attribution before signing.
- Full-node grants bind one persona, signing key, key class, NIP-46 client key, audience, methods/kinds, finite limits, and expiry; cross-vault fallback is forbidden.
- Nostr-key compromise assumes Marmot compromise and requires complete subordinate-authority and MLS-leaf reset.
- Trusted seeds are concurrent, replaceable availability providers. They write only their authorized NID refs and gain no persona, repository-owner, group-admin, or MLS authority.
- Private repo relays require NIP-42 plus a current private admin-signed ACL; missing, stale, expired, conflicting, revoked, unauthorized, or ambiguous state fails closed.
- Keep family label `heterodyne/0.5.0` as the current draft identifier. Do not add pre-1.0 release metadata or compatibility promises.
- Do not edit committed vector JSON, `docs/spec/vectors/fixtures.json`, vector schemas/reason projections, coverage projections, `snapshot.json`, conformance baselines/report/debt, or vector topic/metadata authoring sources.
- Do not run `author`, `coverage`, `snapshot-author`, baseline authoring, or report authoring. The frozen snapshot remains pinned to source `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43` and snapshot commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`.
- Current-draft family, registry, schema, docs-lint, and conformance tooling under `docs/spec/vectors/generator/` may change only to validate the live six-document family without rewriting snapshot-owned artifacts.
- Existing Nostr/Marmot/Radicle implementations must not require Heterodyne-specific changes.

---

### Task 1: Establish the decision record and six-document tooling boundary

**Files:**
- Create: `docs/adr/2026-08-24-047-nostr-first-interoperability.md`
- Modify: `docs/spec/vectors/generator/src/types.ts`
- Modify: `docs/spec/vectors/generator/src/family.ts`
- Modify: `docs/spec/vectors/generator/src/family.test.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`
- Modify: `docs/spec/vectors/generator/src/snapshot-envelope.ts`
- Modify: `docs/spec/vectors/generator/src/author.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/vectors/generator/src/registry.ts`
- Modify: `docs/spec/conformance/src/types.ts`
- Modify: `docs/spec/conformance/src/artifacts.ts`
- Modify: `docs/spec/conformance/src/artifacts.test.ts`
- Modify: `docs/spec/conformance/src/test-support.ts`
- Modify: `docs/spec/conformance/src/gates/anchors.ts`
- Modify: `docs/spec/conformance/src/gates/anchors.test.ts`
- Modify: `docs/spec/conformance/src/gates/invariant-completeness.ts`
- Modify: `docs/spec/conformance/src/gates/invariant-completeness.test.ts`

**Interfaces:**
- Consumes: the existing five-document current-draft inventory and historical snapshot loader.
- Produces: `DocumentId = "core" | "assurance" | "comms" | "control" | "social" | "workspace"`; DAG `assurance -> core`; optional Assurance discovery in historical source roots; proposed ADR-047.

- [ ] **Step 1: Write failing family and artifact-loader tests**

  Add literal assertions that the live inventory is `core, assurance, comms, control, social, workspace`, that Assurance may depend only on Core, and that Comms/Control/Social/Workspace baseline dependency arrays do not require Assurance. Add a temporary source-root fixture with all six documents and a historical fixture with only the original five; both must load, while an unknown seventh owner must fail.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run:

  ```bash
  npm --prefix docs/spec/vectors/generator test -- src/family.test.ts src/docs-lint.test.ts
  npm --prefix docs/spec/conformance test -- src/artifacts.test.ts src/gates/anchors.test.ts src/gates/invariant-completeness.test.ts
  ```

  Expected: FAIL because the owner unions, path/link regexes, and conformance inventories know only five documents.

- [ ] **Step 3: Implement the minimal backward-compatible inventory**

  Use this exact dependency shape:

  ```ts
  export type DocumentId =
    | "core" | "assurance" | "comms" | "control" | "social" | "workspace";

  export const DOCUMENT_LAYERING: Record<DocumentId, readonly DocumentId[]> = {
    core: [],
    assurance: ["core"],
    comms: ["core"],
    control: ["core", "comms"],
    social: ["core", "comms"],
    workspace: ["core", "comms", "control", "social"],
  };
  ```

  Extend current-source qualified anchors, owners, and invariant prefixes with `assurance` / `ASSURANCE-I-`. In conformance artifact loading, treat `docs/spec/heterodyne-assurance.md` as an optional source artifact so the historical five-document source commit still loads unchanged.

- [ ] **Step 4: Author proposed ADR-047**

  Record the approved active-key baseline, optional Assurance split, standard discovery/outbox model, exact-event repositories, trusted seed boundaries, pre-1.0 semantic replacement, and frozen-vector boundary. Set `**Status:** Proposed` and state that the ADR is non-canonical.

- [ ] **Step 5: Run GREEN checks and commit**

  Run both Step-2 commands plus:

  ```bash
  npm --prefix docs/spec/vectors/generator run build
  npm --prefix docs/spec/conformance run build
  ```

  Expected: PASS without changing any snapshot-owned file. Commit: `test: support optional Assurance family document`.

---

### Task 2: Rewrite Core around active-key personas and standard discovery

**Files:**
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/schemas/core/persona-profile-v1.schema.json`
- Modify: `docs/spec/conformance/schema/core-verification-context-v1.schema.json`
- Modify: `docs/spec/conformance/src/subjects/reference-checker.ts`
- Modify: `docs/spec/conformance/src/subjects/reference-checker.test.ts`
- Modify: `docs/spec/conformance/src/subjects/reference-boundary.test.ts`

**Interfaces:**
- Consumes: NIP-01 event verification and optional Assurance document inventory from Task 1.
- Produces: baseline active-key persona resolution, closed kind-0 extension validation, source-neutral replaceable selection, exact-event repository union, public seed/repo-relay rules, and an optional Assurance verification context.

- [ ] **Step 1: Add failing active-key baseline tests**

  Add tests proving: a correctly signed event whose `pubkey` is the persona active key accepts with no pointer/KEL context; a mismatched signer rejects; an invalid optional Assurance context cannot make a valid baseline event invalid unless the caller explicitly requests an Assurance claim; and NIP-01 event ID/signature checks remain mandatory.

- [ ] **Step 2: Add failing kind-0 extension schema tests**

  Test these literal cases independently from upstream kind-0 fields:

  ```json
  {"heterodyne":{"profile":"<the repository's existing canonical rad:z fixture>"}}
  ```

  accepts when the RID fixture is canonical; `identity_chain` is a canonical `naddr`; `cold_root` and `succession_authority` are lowercase 64-hex; missing `profile`, unknown extension members, invalid RID, invalid `naddr`, or uppercase hex reject the extension. The surrounding kind-0 object may carry arbitrary upstream fields.

- [ ] **Step 3: Run focused tests and verify RED**

  Run:

  ```bash
  npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts src/subjects/reference-boundary.test.ts
  npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts
  ```

  Expected: FAIL because current baseline acceptance requires pointer, KEL head, epoch authority, and delegated signer context, and the profile schema requires cold-root/publisher fields.

- [ ] **Step 4: Implement baseline verification and schema**

  Make baseline persona resolution equivalent to `event.pubkey === active_persona_key`. Preserve the raw-byte, identifier, and BIP-340 stages. Make Assurance context an optional later claim, not a prerequisite. Rewrite `persona-profile-v1.schema.json` as an upstream-open kind-0 content schema with only `heterodyne` closed and no required top-level extension.

- [ ] **Step 5: Rewrite Core normative sections**

  Replace cold-root/KEL baseline terminology and move those concepts out of Core. Define permanent anchors for: active-key persona, standard profile/NIP-05/NIP-65 discovery, seven-day refresh warning, source-neutral replaceable selection, exact-byte publication/retry, authorized-ref repository union, public repo relay, seed NID trust, and Assurance as optional composition. Explicitly retire required `31005` and `31007` behavior and remove KEL/epoch requirements from baseline verification and NIP-42.

- [ ] **Step 6: Run GREEN checks and commit**

  Run the Step-3 commands, generator and conformance builds, and `npm --prefix docs/spec/vectors/generator run family:check`. Expected: PASS. Commit: `spec: make active Nostr keys the Core identity`.

---

### Task 3: Define optional Assurance records and downgrade resistance

**Files:**
- Create: `docs/spec/heterodyne-assurance.md`
- Create: `docs/spec/schemas/assurance/enrollment-inception-v1.schema.json`
- Create: `docs/spec/schemas/assurance/active-key-acceptance-v1.schema.json`
- Create: `docs/spec/schemas/assurance/succession-v1.schema.json`
- Create: `docs/spec/schemas/assurance/associated-key-v1.schema.json`
- Modify: `docs/spec/registry/registry.schema.json`
- Modify: `docs/spec/registry/kinds.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/objects.json`
- Modify: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`

**Interfaces:**
- Consumes: Core active-key persona and optional Assurance hook.
- Produces: exact optional Assurance record contracts using kinds `31002` inception, `31000` active-key acceptance/head, `31003` succession, and `31001` associated-key grant/revocation; `assurance.*` registry owner entries.

- [ ] **Step 1: Write failing registry/schema tests**

  Require owner `assurance`, invariant prefix `ASSURANCE-I-`, the four schemas, and closed object validation. Require `31005` and `31007` to be explicitly retired from current behavior while their numbers remain reserved for historical decoding. Test reciprocal enrollment, predecessor/head binding, subject proof for public agents, expiry/revocation, compromise cutoff, no implicit subordinate continuation, and active-key-plus-recovery-authority downgrade consent.

- [ ] **Step 2: Run focused tests and verify RED**

  Run:

  ```bash
  npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/schema.test.ts
  ```

  Expected: FAIL because Assurance owner/types/schemas/entries do not exist.

- [ ] **Step 3: Define exact Assurance record contracts**

  Every record is closed and contains `profile`, `active_key`, `created_at`, `predecessor` (nullable only for inception), and its record-specific authority fields. Inception binds cold root, active key, optional succession authority, epoch policy, witnesses, and thresholds. Acceptance binds the exact inception event ID and cold-root signature. Succession binds previous active key/head, new active key, authorizing evidence, new-key acceptance, class `routine|compromise`, optional compromise time required only for compromise, and an explicit array of subordinate reauthorizations that must be empty for compromise. Associated-key state binds role, scope, issuer, subject key, created time, optional expiry, predecessor/head, and `active|revoked`.

- [ ] **Step 4: Write the Assurance specification**

  Define first-class unassured personas, reciprocal enrollment, TOFU/pinning, disappearance-resistant pins, KERI pre-rotation/witness/threshold semantics, cold-root recovery, succession without aliasing, associated keys, downgrade rules, compromise behavior, KERI export, failure outcomes, security invariants, optional conformance claims, and exact Core dependency. State that Assurance never changes NIP-01 or Marmot identity rules.

- [ ] **Step 5: Update live registry and author its digest**

  Re-home optional cold-root/KEL proof domains, reasons, invariants, and features under Assurance. Keep retired kind numbers reserved without a live baseline feature. Run:

  ```bash
  npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 14
  ```

  The numeric revision is bookkeeping only; do not create release metadata or registry history.

- [ ] **Step 6: Run GREEN checks and commit**

  Run the Step-2 tests, generator build, and family check. Expected: PASS. Commit: `spec: split optional identity Assurance from Core`.

---

### Task 4: Replace public Comms discovery and Marmot identity semantics

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/schemas/comms/marmot-group-directory-v1.schema.json`
- Modify: `docs/spec/schemas/comms/marmot-persona-inbox-bundle-v1.schema.json`
- Modify: `docs/spec/schemas/comms/marmot-persona-inbox-manifest-v1.schema.json`
- Modify: `docs/spec/schemas/comms/marmot-routing-binding-v1.schema.json`
- Modify: `docs/spec/schemas/comms/marmot-event-repository-genesis-v1.schema.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`

**Interfaces:**
- Consumes: Core active-key, NIP-65, source-neutral state, exact-event repository, and public seed primitives.
- Produces: one-event fan-out, standard outbox retrieval, active-key Marmot accounts, independent leaves, and active-key group/repository bindings without mandatory Assurance.

- [ ] **Step 1: Add failing schema/registry tests**

  Require Comms features to depend on Core Nostr/repository primitives rather than `core.marmot-role-attribution.v1`. Require Marmot directory/routing/genesis objects to bind the active account key and standard Marmot routing commit, never cold root, epoch key, KEL head, or `31005`/`31007`.

- [ ] **Step 2: Run focused tests and verify RED**

  Run registry/schema tests. Expected: FAIL on old KEL fields and prerequisites.

- [ ] **Step 3: Rewrite public publishing and discovery**

  Replace the generic feed-index section with NIP-01 filter/NIP-65 outbox behavior. Specify one signed event fanned out unchanged, partial-delivery success after one acceptance, same-byte retries, candidate union/deduplication, NIP-01 replaceable selection, repo-preferred reconciliation without source precedence, relay-only usability, and seven-day kind-0/kind-10002 refresh.

- [ ] **Step 4: Rewrite Marmot identity and storage**

  Make the active persona key the Marmot account identity; remove `marmot:human-messaging` and KERI-role prerequisites. Preserve independent per-device leaves, standard account proofs, exact event/media bytes, generation repositories, authorized writer refs, and canonical Marmot routing commits. Define explicit account/leaf transition on succession and no Heterodyne alias inside MLS.

- [ ] **Step 5: Update schemas, registry, and digest**

  Replace KEL/cold-root identity members with `account_key`, current Marmot routing evidence, authorized writer NIDs, and exact RID/h bindings. Keep objects closed. Re-author registry revision 14 in place to refresh only the digest.

- [ ] **Step 6: Run GREEN checks and commit**

  Run focused tests, generator build, and family check. Expected: PASS. Commit: `spec: use standard Nostr outboxes and Marmot accounts`.

---

### Task 5: Define trusted private seeds and automated authorship

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Create: `docs/spec/schemas/comms/trusted-seed-acl-v1.schema.json`
- Modify: `docs/spec/schemas/comms/agent-workload-registration-v1.schema.json`
- Modify: `docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/objects.json`
- Modify: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`

**Interfaces:**
- Consumes: Core seed/repository primitives and Comms Marmot routing.
- Produces: concurrent trusted seeds, NIP-42 private relay admission, closed ACL projection, agent-key/persona-key signing policy, and mandatory pre-sign automation attribution.

- [ ] **Step 1: Add failing ACL and authorship tests**

  Require a closed ACL with `profile`, allowed account keys/roles, Marmot `h`, private RID, seed NIDs, sequence, predecessor, group-state transition, issued time, and expiry. Test rejection of missing, expired, conflicting, revoked, unauthorized, ambiguous, or route-mismatched state. Require agent registration to bind persona, selected signer, key class, public agent key/role when present, permitted event kinds, expiry, and subject proof.

- [ ] **Step 2: Run focused tests and verify RED**

  Run registry/schema tests. Expected: FAIL because the ACL and flexible signer contract do not exist.

- [ ] **Step 3: Specify trusted-seed behavior**

  Define multiple concurrent trusted seeds by Radicle NID, independent endpoints/grants/refs, NIP-42 account authentication, metadata leakage to the chosen seed, exact-event ingest, authorized-ref union, revocation, no MLS leaf/plaintext, and fail-closed ACL evaluation. Keep seed, full-node, persona, repository-owner, and group-admin roles distinct.

- [ ] **Step 4: Specify automated authorship**

  Make agent-key signing the preferred default and allow persona-key signing only under explicit OIDC scope. Require NIP-32-compatible attribution plus an optional Heterodyne association tag before signing; forbid caller removal/falsification and public leakage of OIDC/token/audit identifiers. Keep actual event `pubkey` authoritative.

- [ ] **Step 5: Update live artifacts and commit**

  Add Comms seed/private-relay features, ACL object/proof domain/reasons/invariants, revise agent feature prerequisites, re-author registry digest, run focused tests/build/family check, and commit: `spec: define trusted seed relays and agent attribution`.

---

### Task 6: Rebase Control on multi-persona NIP-46 and OIDC signing grants

**Files:**
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/schemas/control/control-client-authorization-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-agent-publish-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-audit-record-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-capability-set-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-device-authorization-state-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-operation-record-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-recovery-completion-v1.schema.json`
- Modify: `docs/spec/schemas/control/control-recovery-grant-v1.schema.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`

**Interfaces:**
- Consumes: active-key Marmot accounts, standard NIP-46, Comms automation attribution, trusted seeds, and optional Assurance succession/recovery.
- Produces: isolated persona vaults, exact signer grants, full-node/light-client modes, no cross-vault fallback, and compromise-reset orchestration.

- [ ] **Step 1: Add failing authorization tests**

  Require exact fields: persona active key, NIP-46 client pubkey, signer audience, selected signing key, key class `persona|agent`, methods, event kinds, finite request/value limits, issued/expiry times, and revocation state. Test that changing any one binding rejects, cross-persona lookup fails, and NIP-46 metadata cannot widen authority.

- [ ] **Step 2: Add failing compromise and publication tests**

  Require automated requests to reach the Comms attribution step before signing. Require compromise recovery to revoke NIP-46/OIDC, invalidate clients/delegates/nodes/agents/seeds, remove all old Marmot leaves, advance reachable groups, publish fresh KeyPackages, and explicitly reauthorize every subordinate authority.

- [ ] **Step 3: Run focused tests and verify RED**

  Run registry/schema tests. Expected: FAIL on old node/KEL/epoch-bound grant shapes.

- [ ] **Step 4: Rewrite Control**

  Define zero-or-more isolated persona vaults per full node; local-key and remote-signing custody; OIDC activation of standard NIP-46; one-use connection secrets; server-side scope authority; user and agent signer selection; active-account Marmot proofs with device-local leaves; optional seed provisioning; and optional Assurance recovery integration. Remove locked epoch/KEL prerequisites from baseline Control.

- [ ] **Step 5: Update artifacts and commit**

  Rewrite closed schemas, features, reasons, and invariants; re-author registry digest; run focused tests/build/family check; commit: `spec: bind NIP-46 grants to isolated persona vaults`.

---

### Task 7: Make Social an ordinary Nostr extension

**Files:**
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/spec/schemas/social/agent-policy-receipt-v1.schema.json`
- Modify: `docs/spec/schemas/social/agent-policy-correction-v1.schema.json`
- Modify: `docs/spec/registry/kinds.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.test.ts`

**Interfaces:**
- Consumes: Core active-key/outbox selection, Comms automation attribution, and optional Assurance continuity.
- Produces: vanilla-compatible follows, replies, reactions, lists, communities, moderation, organizations, and ATProto attachment without KEL/feed-index validity rules.

- [ ] **Step 1: Write failing schema/registry tests**

  Require Social agent-policy objects to bind actual event author/agent association rather than cold root or KEL head. Require no live Social feature/profile prerequisite on kind `31007`, no KEL gate for ordinary social events, and Assurance-only vouch/recovery composition.

- [ ] **Step 2: Run focused tests and verify RED**

  Run registry/schema tests. Expected: FAIL on old cold-root, epoch, KEL, org-feed, and feed-index rules.

- [ ] **Step 3: Rewrite Social normative behavior**

  Use ordinary NIP-01/NIP-10/NIP-25/NIP-51/NIP-72 selection and authorship; make unassured vanilla keys first-class; derive feeds from NIP-65 relays/repo relays; make organization posts ordinary organization-active-key events; keep agent moderation advisory and subscriber-local; move recovery vouches to optional Assurance; bind ATProto to the active npub.

- [ ] **Step 4: Update live artifacts and commit**

  Remove the live Social org-feed profile, revise surviving extension profiles, schemas, features/reasons/invariants, re-author registry digest, run focused tests/build/family check, and commit: `spec: make Social vanilla Nostr compatible`.

---

### Task 8: Convert Workspace and organizations to active-key personas

**Files:**
- Modify: `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/schemas/workspace/workspace-manifest-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/workspace-policy-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/role-manifest-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/role-grant-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/role-revocation-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/role-checkpoint-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/resource-advertisement-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/host-advertisement-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/service-advertisement-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/workspace-relationship-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/joint-workspace-relationship-v1.schema.json`
- Modify: `docs/spec/schemas/workspace/resource-key-envelope-v1.schema.json`
- Modify: `docs/spec/registry/features.json`
- Modify: `docs/spec/registry/objects.json`
- Modify: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/vectors/generator/src/workspace-schema.test.ts`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`

**Interfaces:**
- Consumes: active-key organization personas, standard Marmot account leaves, trusted seeds, and optional Assurance.
- Produces: active-key workspace authority, private delegate policy, host/seed separation, and device-leaf-bound resource delivery without ambient KEL authority.

- [ ] **Step 1: Add failing common-contract tests**

  Across all twelve closed schemas require `workspace_key` as the active organization key and explicit policy/predecessor/checkpoint context. Remove generic `kel_head` and epoch-actor fields. Require leaf/account binding for invitations and resource envelopes, and require host/seed NIDs to remain availability/custody evidence only.

- [ ] **Step 2: Run focused tests and verify RED**

  Run:

  ```bash
  npm --prefix docs/spec/vectors/generator test -- src/workspace-schema.test.ts src/registry.test.ts
  ```

  Expected: FAIL because current objects require cold-root/KEL authority.

- [ ] **Step 3: Rewrite Workspace**

  Define human and organization personas with the same active-key wire model; private delegate/NIP-46 policy; no automatic authority transfer on succession; account-proof/device-leaf membership; separate repository writer, seed, host, custody, and governance roles; private-relay ACL composition; explicit bilateral/joint authority; independent resource keys; and future-only revocation.

- [ ] **Step 4: Update schemas and proof domain**

  Apply the same active-key authority tuple consistently to all twelve objects and update `heterodyne-workspace-object-v1` bound members. Preserve role narrowing, checkpoint freshness, private topology, and resource-key isolation.

- [ ] **Step 5: Update registry and commit**

  Revise Workspace features/reasons/invariants/objects, re-author registry digest, run focused tests/build/family check, and commit: `spec: use active-key organization workspaces`.

---

### Task 9: Close family documentation, threat model, and registry coherence

**Files:**
- Modify: `docs/spec/heterodyne.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `docs/architecture.md`
- Modify: `docs/glossary.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/spec/extensions/nips/README.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/family.test.ts`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/registry/manifest.json`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: complete six-document normative family and registry entries from Tasks 2–8.
- Produces: one coherent maintained explanation, retired-model lint, six-document invariant evidence, final registry digest, and explicit vector non-reconciliation record.

- [ ] **Step 1: Add failing maintained-guide and closure tests**

  Add mutations proving maintained guides reject: cold-root-as-persona, mandatory KEL, separate human Marmot account, required `31005`/`31007`, repository-over-relay source precedence, full-node-as-required-relay, single canonical trusted seed, agent attribution bypass, and bare-key incompleteness. Require Assurance invariant evidence in its document and threat model.

- [ ] **Step 2: Run focused tests and verify RED**

  Run family/docs-lint/registry tests. Expected: FAIL because maintained guides and overview still describe the retired model.

- [ ] **Step 3: Update family-facing documents**

  Document the six-document graph, Assurance optionality, active-key personas, NIP-05/NIP-65 discovery, standard Marmot accounts, persona-owned repositories, trusted seed boundaries, full-node signer role, weekly freshness, compromise reset, and historical-vector policy. Do not cite ADR-047 from any normative document.

- [ ] **Step 4: Run exhaustive retired-model sweep**

  Use `rg` across live normative and maintained documents for the exact retired literals and inspect every match:

  ```bash
  rg -n 'cold-root npub.*authoritative|kind:?`?31005|kind:?`?31007|marmot:human-messaging|KEL.*required|canonical feed index|one trusted seed' \
    AGENTS.md README.md docs/architecture.md docs/glossary.md docs/security/threat-model.md docs/spec/heterodyne*.md docs/spec/extensions/nips/README.md
  ```

  Historical ADRs, research, changelog history, and the design/plan may retain contextual references. Live references may only say the mechanism is retired, optional Assurance, or historical.

- [ ] **Step 5: Refresh registry digest and run the full pre-acceptance matrix**

  Run:

  ```bash
  npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 14
  npm --prefix docs/spec/vectors/generator run draft:check
  npm --prefix docs/spec/vectors/generator run snapshot-check
  npm --prefix docs/spec/conformance run build
  npm --prefix docs/spec/conformance test
  scripts/conformance-ci.sh
  git diff --check
  ```

  Expected: all pass; snapshot check still reports exactly 482 vectors from the pinned historical source; no snapshot-owned file changes.

- [ ] **Step 6: Commit**

  Commit: `docs: align family guidance with Nostr-first protocol`.

---

### Task 10: Accept ADR-047 after review and prove a clean frozen-snapshot boundary

**Files:**
- Move: `docs/adr/2026-08-24-047-nostr-first-interoperability.md` → `docs/adr/archive/2026-08-24-047-nostr-first-interoperability.md`
- Modify: `docs/adr/archive/2026-08-24-047-nostr-first-interoperability.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: reviewed complete normative patch and clean pre-acceptance matrix.
- Produces: accepted archived ADR, no normative ADR dependency, final clean verification evidence.

- [ ] **Step 1: Verify acceptance prerequisites**

  Confirm every prior task has a clean task review, no live normative file references ADR-047, registry digest matches the current entry set, and `git diff --name-only` contains no committed vector JSON, snapshot metadata, coverage projection, baseline, report, debt, vector topic, or vector metadata file.

- [ ] **Step 2: Move and accept the ADR**

  Change status to `Accepted`, move it to the archive, and add an acceptance section stating that the specification family and machine-readable artifacts stand alone; the frozen vector snapshot remains historical and unreconciled.

- [ ] **Step 3: Update changelog and maintained-path test**

  Add one current changelog entry for the semantic replacement and update only the ADR path fixture used by maintained-guide lint.

- [ ] **Step 4: Run the final clean matrix**

  Run:

  ```bash
  npm --prefix docs/spec/vectors/generator run family:check
  npm --prefix docs/spec/vectors/generator run check
  npm --prefix docs/spec/conformance run build
  npm --prefix docs/spec/conformance test
  scripts/conformance-ci.sh
  git diff --check
  git status --short
  ```

  Expected: every command exits zero; generator draft tests pass; historical snapshot reproduces exactly 482 vectors from source `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`; status contains only the intended acceptance edits before commit.

- [ ] **Step 5: Commit**

  Commit: `docs: accept Nostr-first interoperability model`.
