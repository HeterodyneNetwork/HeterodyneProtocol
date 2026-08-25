# Task 7 Fix Round 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Social publication-authority replay, signer-result substitution,
unobserved ATProto history, and cross-pubkey lineage influence.

**Architecture:** Comms issues one-use signed-publication proofs branded to an
exact authority and Social validates through an embedding-created closure.
Signer outcomes become one independent frozen snapshot after a single
descriptor read. The configured resolver authority authenticates durable
binding-observation envelopes, and ATProto selection is confined to an exact
`(DID,pubkey)` coordinate.

**Tech Stack:** TypeScript, Vitest, Ajv, noble Ed25519/BIP340/SHA-256, NIP-01
event validation, Markdown normative specifications.

**Spec:** `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-fix-round5-design.md`

## Global Constraints

- Preserve registry revision `14` and entry-set digest
  `9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`.
- Do not modify frozen topics, vectors, snapshots, projections, baselines,
  release artifacts, or generator authoring outputs.
- Comms must not import Control; the embedding owns trusted time and the
  durable execute-once signer.
- Every production change requires an observed exploit-first RED.
- Commit only after focused tests, build, family check, and exact-482 snapshot
  check pass.

---

### Task 1: Bind Social publication to the configured Comms authority

**Files:**
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.test.ts`

**Interfaces:**
- Consumes: `CommsSocialPublicationAuthority`, atomic signed-publication proof.
- Produces: `createSocialAuthorshipValidator({ publication_authority })` and
  authority-exact proof consumption.

- [x] Add tests showing a proof minted by an attacker/backdated authority is
  rejected by the expected validator, while the expected authority succeeds:

```ts
const validator = createSocialAuthorshipValidator({
  publication_authority: expectedAuthority,
});
expect(validator.validate(attackerPublication)).toEqual({
  verdict: "reject",
  reason_code: "social-author-binding-invalid",
});
```

- [x] Run the focused authorship tests and record RED caused by the current
  authority-agnostic proof consumer.
- [x] Store the issuing authority in the proof WeakMap, require the expected
  authority in consumption, and expose only the configured Social closure.
- [x] Capture `trusted_now` and `signer_execution.executeOnce.bind(...)` during
  authority construction; add a test that replaces the caller's method after
  construction and observes the originally captured implementation.
- [x] Run both focused test files and record GREEN.

### Task 2: Snapshot signer results from descriptors exactly once

**Files:**
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.test.ts`

**Interfaces:**
- Consumes: untrusted `CommsSocialSignerExecutionOutcome` returned by
  `executeOnce`.
- Produces: one closed, independently cloned and deeply frozen signer outcome
  used for all validation, storage, and return.

- [x] Add an accessor A-to-B exploit test whose `event` getter returns a valid
  event on its first read and a different event on its second read; assert the
  signer result rejects and no publication proof is returned.
- [x] Add open-object, symbol-key, array-hole, and nested-accessor probes that
  reject without rereading attacker-controlled members.
- [x] Run the focused test and record RED showing the current result/event is
  read more than once or accepts a non-data shape.
- [x] Implement a recursive descriptor snapshotter that calls
  `Object.getOwnPropertyDescriptors` once per source node, accepts only exact
  data-descriptor plain object/array trees, constructs fresh values, and
  deep-freezes the completed snapshot.
- [x] Strict-validate, compare, store, and return only that same snapshot; rerun
  the focused test and record GREEN.

### Task 3: Authenticate durable ATProto binding observations

**Files:**
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.ts`
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`

**Interfaces:**
- Produces: `AtprotoBindingObservationEnvelope`,
  `AtprotoBindingObservationEvidence`, and
  `authenticateAtprotoBindingObservation(...)` under the exact configured
  resolver authority.
- Binding evidence replaces `carrier` with optional `observation_evidence`.

- [x] Add tests for a valid durable observation and forged signature,
  mismatched event/hash/DID/pubkey/generation/resolution hash, too-early,
  expired/rotated-late, wrong-policy, and below-minimum-version observations.
- [x] Run resolver/ATProto focused tests and record RED because observation
  authentication and the new evidence shape do not exist.
- [x] Implement the closed observation envelope and domain-separated canonical
  serialization, verify it against the authority's private anchors and
  policy/version config, and enforce the referenced resolution interval.
- [x] Require observation for historical-only lineage/revocation targets while
  permitting a candidate freshly authenticated at trusted `now` to omit it.
- [x] Add a compromised-key backdating rejection and a fresh-verifier expired
  observed-history acceptance; run focused tests and record GREEN.

### Task 4: Constrain ATProto validation to the exact DID/pubkey coordinate

**Files:**
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`

**Interfaces:**
- `validateAtprotoBinding` consumes `did` and exact expected `pubkey` before
  candidate selection.
- Candidate, history, and revocation evaluation is source-neutral inside only
  that coordinate.

- [x] Add an exploit test where a newer same-DID/different-pubkey binding and
  its valid revocation are supplied with the expected coordinate; assert the
  expected lineage still selects and accepts.
- [x] Run the exact test and record RED because current selection filters only
  by DID.
- [x] Filter parsed candidates/history and revocation targets by both expected
  DID and pubkey before map insertion or selection.
- [x] Rerun all ATProto tests and record GREEN, including sibling/reset/fork and
  current-key revocation regressions.

### Task 5: Update normative prose, audit, verify, report, and commit

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-report.md`

**Interfaces:**
- Documents the executable authority, snapshot, observation, and coordinate
  contracts without making the local resolver a protocol authority.

- [x] Update Comms prose for exact authority-instance proof binding and the
  one-read immutable signer snapshot.
- [x] Update Social prose for configured validator consumption, durable
  historical observation, current-candidate exception, and exact coordinate.
- [x] Run the focused Task 7 suite, generator build, family check, and
  snapshot-check; require exactly 482 verified vectors.
- [x] Audit the complete diff for all Task 7 Critical/Important surfaces,
  descriptor rereads, authority substitution, observation timing, coordinate
  filtering, family layering, prohibited paths, revision, and digest.
- [x] Append exact RED/GREEN/full verification evidence and ownership costs to
  `task-7-report.md`, run `git diff --check`, and commit
  `fix: close Social authority replay`.
