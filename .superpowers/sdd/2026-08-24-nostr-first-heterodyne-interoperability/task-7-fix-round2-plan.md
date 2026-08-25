# Task 7 fix round 2 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate snapshot compatibility, NIP-72 moderation, Social automation, and ATProto lineage with executable evidence.

**Architecture:** Current APIs stay strict and legacy behavior is available only inside a disposable runtime. Comms authorization and ATProto identity transitions are consumed as cryptographically or module-authenticated capabilities rather than caller assertions.

**Tech Stack:** TypeScript 5.9, Node ESM/compiler API, Vitest, noble BIP-340/Ed25519/SHA-256, Base58btc.

**Spec:** `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-fix-round2-design.md`

## Global constraints

- Strict exploit-first RED/GREEN for each review finding.
- Do not edit frozen topic sources, vector artifacts, snapshot metadata, registry revision/digest, or release artifacts.
- No authoring command against the repository; disposable test/runtime output only.

---

### Task 1: Snapshot-only runtime

**Files:** snapshot runtime test/module, `author.ts`, `coverage.ts`, generator build script.

**Interfaces:** Produces `buildSnapshotCompatibleVectors(fixtures)` for all current legacy execution entry points.

- [ ] Add an integration probe that executes the frozen moderation vector builder and prove current direct legacy dispatch still rejects.
- [ ] Run the probe and observe runtime failure through the live moderation API.
- [ ] Implement disposable compilation with the single frozen import rewrite and route author/coverage through it.
- [ ] Run the focused runtime/moderation tests to GREEN.

### Task 2: NIP-72 set revision and deletion

**Files:** `social-nip72.test.ts`, `social-nip72.ts`, Social specification.

**Interfaces:** `evaluateNip72CuratedView` additionally consumes signed deletion requests.

- [ ] Add exploit probes for trailing hints, pre-revision/re-added approvals, forged deletion, and same-author deletion.
- [ ] Observe the probes fail against exact matching and deletion-blind evaluation.
- [ ] Implement prefix matching, revision time, and strict NIP-09 validation.
- [ ] Run the NIP-72 tests to GREEN.

### Task 3: Opaque Comms authorization

**Files:** `agent-authorship.test.ts`, `agent-authorship.ts`, `social-events.test.ts`, `social-events.ts`, Social/Comms prose if needed.

**Interfaces:** Produces and consumes a WeakMap-backed `CommsSocialAuthorization` capability; no constructor/data fallback.

- [ ] Add probes showing a fabricated tuple/plain capability authorizes today and wrong kind/time/scope/grant bindings are not enforced.
- [ ] Observe RED.
- [ ] Add the capability producer through the three existing Comms validators and exact binding checks; replace Social tuple arrays.
- [ ] Run Comms/Social focused tests to GREEN.

### Task 4: ATProto canonical DID evidence

**Files:** `social-atproto.test.ts`, `social-atproto.ts`, Social specification and directly required schema/registry entries only.

**Interfaces:** Binding validation consumes a resolved DID document and Ed25519 proof, with one canonical serializer.

- [ ] Add probes for alternate JSON order, noncanonical DID/RID, unrelated verification method, and forged proof.
- [ ] Observe RED.
- [ ] Implement canonical serializers, identifiers, resolved-method selection, and direct Ed25519 verification.
- [ ] Run ATProto tests to GREEN.

### Task 5: Signed ATProto lineage and revocation

**Files:** `social-atproto.test.ts`, `social-atproto.ts`, Social specification.

**Interfaces:** Later binding validation consumes signed carrier evidence; revocations consume Nostr or DID signed evidence only.

- [ ] Add probes for forged predecessor objects, missing chain evidence, forged revocation, old countersignature replay, and valid fresh generation 2.
- [ ] Observe RED.
- [ ] Implement predecessor hash/event binding, full chain traversal, signed revocation verification, and recovery rules.
- [ ] Run ATProto tests to GREEN.

### Task 6: Full verification and handoff

**Files:** Task 7 report.

- [ ] Run all focused tests and generator build.
- [ ] Run family check and exact-482 snapshot check.
- [ ] Self-review the complete diff and forbidden paths.
- [ ] Append exact RED/GREEN evidence and ownership cost to the report.
- [ ] Commit `fix: authenticate Social moderation and lineage`.
