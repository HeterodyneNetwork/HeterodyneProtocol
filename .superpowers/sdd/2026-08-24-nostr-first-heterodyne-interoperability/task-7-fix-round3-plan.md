# Task 7 Fix Round 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate current Social automation and ATProto authority while hardening the isolated snapshot runtime.

**Architecture:** Comms mints and one-time consumes an exact WeakMap-backed publication capability after full current-state validation. ATProto uses a separate WeakMap-backed DID-resolution capability minted only from a locally trusted signed resolver envelope, selects one current carrier-neutral binding candidate, and verifies lineage/revocations against authenticated resolution state.

**Tech Stack:** TypeScript, Vitest, Noble Ed25519/BIP340/SHA-256, Node filesystem/compiler APIs.

**Spec:** `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-fix-round3-design.md`

## Global Constraints

- Keep registry revision 14 and its digest unchanged.
- Do not modify frozen topics, vectors, snapshot metadata, projections, baselines/reports/debt, or release artifacts.
- Resolver trust anchors are local configuration, never protocol identity authority or registry entries.
- Observe each exploit RED before its production change.

---

### Task 1: Exact one-use Comms capability

**Files:**
- Modify: `docs/spec/vectors/generator/src/agent-authorship.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.ts`

**Interfaces:**
- `authorizeCommsSocialPublication` additionally consumes `requested_feed` and `requested_resource`.
- `consumeCommsSocialAuthorization` consumes the capability once with current registration/token state and exact unsigned publication context, producing a one-use `CommsSocialAuthorship` proof for Social.

- [x] Add exploit tests for audience/JKT/destination cross-binding, changed registration/generation/status, replay, and plain objects.
- [x] Run the two focused test files and record the expected acceptance/replay REDs.
- [x] Store exact immutable state, re-run all validators at consume, and delete the WeakMap entry before the decision.
- [x] Route Social through the consuming function and run both files GREEN.

### Task 2: Resolver-authenticated DID capability

**Files:**
- Create: `docs/spec/vectors/generator/src/atproto-did-resolution.ts`
- Create: `docs/spec/vectors/generator/src/atproto-did-resolution.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`

**Interfaces:**
- `authenticateAtprotoDidResolution({envelope, signature, trust_anchor, now})` produces opaque `AtprotoDidResolution` only after exact domain-separated signature verification.
- `verifyAtprotoDidSignature({resolution, did, verification_method_id, payload, signature, now})` consumes no caller document and returns boolean.
- `currentAtprotoDidMethod({resolution, did, now})` returns only the authenticated selected method id internally needed for rotated-key revocation.

- [x] Add tests proving an arbitrary/fake victim document has no minting API and forged/stale/wrong-DID/wrong-method evidence rejects.
- [x] Run the resolver tests and record missing-interface RED.
- [x] Implement canonical closed envelopes, Web/PLC metadata checks, Ed25519/BIP340 resolver attestation, freshness, private branding, and direct DID signature verification.
- [x] Replace all caller DID documents in binding/lineage/revocation evidence and run resolver plus ATProto tests GREEN.

### Task 3: Carrier-neutral current binding and rotated revocation authority

**Files:**
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`

**Interfaces:**
- `validateAtprotoBinding` consumes `did`, `candidates`, `lineage`, `revocations`, and `now`, returning one `selected_event_id` and binding.
- DID-side revocation evidence carries its fresh current resolution capability and signature; Nostr-side evidence carries the signed event.

- [x] Add fork tests with repository/relay order reversed and a lower-id same-time tie.
- [x] Run focused selection tests and record both-forks/current-selection RED.
- [x] Strict-validate/deduplicate/sort the union before lineage and revocation evaluation.
- [x] Add rotated DID-method revocation and wrong-current-method probes, observe RED, then verify against the capability's selected current method and run GREEN.

### Task 4: Disposable loader failure isolation

**Files:**
- Modify: `docs/spec/vectors/generator/src/snapshot-topic-runtime.test.ts`
- Modify: `docs/spec/vectors/generator/src/snapshot-topic-runtime.ts`

**Interfaces:**
- Public snapshot builders are unchanged.
- All construction failures remove the newly created runtime tree before rethrowing.

- [x] Add a real copied-module integration probe whose absent tsconfig forces construction failure and assert no prefixed temporary tree remains.
- [x] Run it and record the leaked-directory RED.
- [x] Use `fileURLToPath`, copy registry recursively, and wrap materialization in cleanup-on-error.
- [x] Run snapshot-runtime and moderation tests GREEN.

### Task 5: Normative text, verification, and commit

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-report.md`

- [x] Specify exact one-use current-state Comms consumption and destination binding.
- [x] Specify local resolver attestations, no global identity authority, current carrier-neutral selection, and rotated DID revocation authority.
- [x] Run focused tests, build, family check, and snapshot check; require exact 482.
- [x] Review the full diff, confirm prohibited paths and rev14/digest, append exact RED/GREEN evidence, and commit `fix: authenticate Social current authority`.
