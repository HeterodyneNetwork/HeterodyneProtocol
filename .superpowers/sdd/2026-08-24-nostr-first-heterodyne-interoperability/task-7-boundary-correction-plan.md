# Task 7 Post-round Boundary Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close caller-controlled aliasing across the complete Comms publication request, ATProto binding/revocation inputs, and durable observation proofs.

**Architecture:** Each public trust boundary performs one schema-specific own-descriptor capture before semantic reads, preserving only its exact opaque authority identity while independently cloning and freezing data. ATProto selection carries the exact selected validated record into history, and observation v2 authenticates the strict Nostr proof, DID proof, resolution, and DID-signature digest as one durable statement.

**Tech Stack:** TypeScript, Vitest, Ajv, noble Ed25519/SHA-256, strict NIP-01 validation, Markdown normative specifications.

**Spec:** `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-boundary-correction-design.md`

## Global Constraints

- This is the `Post-round boundary correction`, not fix round 6.
- Preserve registry revision `14` and entry-set digest `9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`.
- Do not modify frozen topics, vectors, snapshots, projections, baselines, release artifacts, or generator authoring outputs.
- Keep capture helpers module-local and schema-specific; preserve opaque identity only from one data-descriptor capture.
- Do not claim JavaScript proves an object is not a Proxy. Reject non-data/open shapes and never reread an original after the single descriptor capture.
- Every production change requires an observed exploit-first RED.
- Finish as one commit named `fix: snapshot Social trust inputs`.

---

### Task 1: Snapshot the complete Comms publication request

**Files:**
- Modify: `docs/spec/vectors/generator/src/agent-authorship.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`

**Interfaces:**
- Consumes: the existing `signCommsSocialPublication` request and opaque `CommsSocialPublicationAuthority`.
- Produces: a private closed immutable request snapshot whose captured authority reference is used for lookup, clock, signing, and proof branding.

- [ ] **Step 1: Add the authority laundering RED**

Create an ordinary top-level request, replace `authority` with an enumerable accessor that returns authority A and then authority B, call `signCommsSocialPublication`, and assert rejection with zero signer calls. The production change that makes this pass is rejecting a non-data authority descriptor before WeakMap lookup.

- [ ] **Step 2: Add content and destination substitution REDs**

Use enumerable accessors for nested `event.content`, top-level `requested_feed`, and top-level `requested_resource` that return an authorized/small value first and a different/oversized value later. Assert each request rejects and never reaches `executeOnce`. The production change is one data-descriptor capture followed exclusively by an independent immutable snapshot.

- [ ] **Step 3: Run the focused tests and record RED**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-authorship.test.ts
```

Expected: the new exploit cases fail because the current implementation rereads/spreads request members or launders the authority reference.

- [ ] **Step 4: Implement the schema-specific request snapshot**

Add a private `snapshotCommsSocialPublicationRequest(value: unknown)` that calls `Object.getOwnPropertyDescriptors` once for the request, requires the exact nine enumerable data members and no symbols, captures `authority` without cloning it, and uses a private recursive data-descriptor copier for all other values. Require dense arrays and exact registration/event/token key sets, then deep-freeze the independent snapshot.

Refactor `signCommsSocialPublication` and `validateCommsSocialContext` to use only the snapshot. Replace token spread with a newly constructed token snapshot whose only changed member is `now`. Store the same captured authority reference in `SOCIAL_SIGNED_PUBLICATIONS`.

- [ ] **Step 5: Run focused GREEN**

Run the same focused command. Expected: all authorship tests pass, including the three new exploit categories and existing execute-once/signer-outcome fences.

### Task 2: Snapshot ATProto validation trees and seed the selected record

**Files:**
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`

**Interfaces:**
- Consumes: complete binding/revocation validation inputs and exact opaque `AtprotoResolverAuthority`.
- Produces: private snapshot-consuming binding and revocation validators plus one selected validated record shared with the historical/revocation universe.

- [ ] **Step 1: Add the candidate A-to-B revocation-bypass RED**

Construct candidate evidence whose member used during initial selection yields a valid revoked binding A but whose later read yields B, so the old implementation selects A then omits A from history. Assert `validateAtprotoBinding` rejects instead of accepting the revoked current binding. The production change is whole-input one-read capture plus direct selected-record seeding.

- [ ] **Step 2: Add open/accessor binding and revocation tree probes**

Cover an accessor inside candidate/history/revocation/current-resolution data and an unexpected member at each public input boundary. Assert binding uses `atproto-binding-invalid` and direct revocation uses `atproto-revocation-invalid` without accepting a partial tree.

- [ ] **Step 3: Run the ATProto test and record RED**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/social-atproto.test.ts
```

Expected: the A-to-B exploit is accepted or reread by the current two-pass loop.

- [ ] **Step 4: Implement schema-specific ATProto snapshots**

Add module-local `snapshotAtprotoBindingInput` and `snapshotAtprotoRevocationInput`. Capture their top-level descriptors once; retain one authority descriptor value; recursively snapshot the exact data schemas for evidence, resolution/observation envelopes, Nostr events, bindings, candidates, lineage, and revocations. Dense arrays and data descriptors are mandatory.

Split public functions from private snapshot-consuming implementations. Validate each candidate snapshot once for current selection, seed the exact selected checked record into `historical`, and skip revalidating that selected evidence while processing other captured candidates/lineage. Call the private revocation implementation from binding validation.

- [ ] **Step 5: Run focused GREEN**

Run the same ATProto command. Expected: all selection, lineage, fork, coordinate, and revocation tests pass, including the new A-to-B and open-tree probes.

### Task 3: Bind durable observation v2 to both binding signatures

**Files:**
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`

**Interfaces:**
- Produces: `AtprotoBindingObservationEnvelope` v2 with `did_signature_digest`, and observation authentication that verifies the strict Nostr event and exact DID signature under one captured resolution evidence.

- [ ] **Step 1: Add observation-v2 and signature-substitution REDs**

Update focused fixtures to sign `heterodyne:atproto-binding-observation:v2\0` envelopes with `did_signature_digest = sha256(hexToBytes(did_signature))`. Add a direct observation test that substitutes the DID signature after attestation and a Social binding test whose resolution accessor presents A and then B. Assert both reject.

- [ ] **Step 2: Run both focused files and record RED**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/atproto-did-resolution.test.ts src/social-atproto.test.ts
```

Expected: current v1 types/serialization do not authenticate the new digest and proof input, or the resolution alias remains semantically reread.

- [ ] **Step 3: Implement observation v2 and proof verification**

Change the observation type, domain separator, exact key set, canonical serializer, and validity checks to v2 plus `did_signature_digest`. Extend `authenticateAtprotoBindingObservation`'s expected proof with the Nostr event, canonical binding payload, DID signature, DID method id, binding hash/generation, and coordinate. Snapshot this input once, authenticate the single captured resolution, strict-validate the Nostr event and exact content/coordinate, verify the DID signature, compare the signature digest, and then verify the resolver attestation.

In `validateBindingEvidence`, take one local `resolutionEvidence` from the already immutable evidence snapshot and pass it to both DID and observation paths together with the exact canonical payload, event, signature, and method.

- [ ] **Step 4: Run focused GREEN**

Run the two-file command. Expected: all resolver authority/history tests and ATProto binding/revocation tests pass with v2 evidence; the resolution and signature substitutions reject.

### Task 4: Document, audit, verify, and finalize

**Files:**
- Modify if behavior language is missing: `docs/spec/heterodyne-comms.md`
- Modify if behavior language is missing: `docs/spec/heterodyne-social.md`
- Modify: `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-report.md`

**Interfaces:**
- Documents the one-read input boundary and observation-v2 proof without introducing a protocol-global resolver authority.

- [ ] **Step 1: Reconcile normative prose only where required**

Ensure Comms states that the complete authorization/signing request becomes one immutable snapshot before validation and authority lookup. Ensure Social states that current selection/history/revocation consume one captured universe and durable observations commit both the Nostr event and exact DID signature digest under the configured local resolver authority. Do not edit generator authoring or frozen artifacts.

- [ ] **Step 2: Run focused suite, build, and complete draft/family lane**

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-authorship.test.ts src/social-events.test.ts src/atproto-did-resolution.test.ts src/social-atproto.test.ts
npm --prefix docs/spec/vectors/generator run build
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
```

- [ ] **Step 3: Run history-bound snapshot and conformance gates**

```bash
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
scripts/conformance-ci.sh
```

Require the snapshot output to report exactly 482 verified vectors.

- [ ] **Step 4: Audit the complete correction diff**

Review every changed line for original-object rereads/spreads, opaque-authority substitution, open/accessor acceptance, selected-record revalidation, resolution aliasing, signature-digest canonicality, family layering, forbidden/frozen paths, revision 14, and the registry digest. Run `git diff --check` and compare prohibited paths against parent commit `b7f3c671eb76a2e1a36fc40f442f20526f627f52`.

- [ ] **Step 5: Append exact report evidence and finalize one commit**

Append heading `Post-round boundary correction` to Task 7's report with the exact RED commands/failures, GREEN commands/counts, full-gate outputs, ownership expansion, and concerns. Amend temporary commit `52cb09b` so the branch ends with one correction commit:

```bash
git add -A
git commit --amend -m "fix: snapshot Social trust inputs"
```

Request parent review only after fresh verification evidence and the final commit id are available.
