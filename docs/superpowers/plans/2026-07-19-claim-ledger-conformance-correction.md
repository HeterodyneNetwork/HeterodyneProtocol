# Claim Ledger Conformance Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Task 4 claim-ledger decisions fully replayable and fail closed over canonical time, claim confirmation, reader enumeration, key epochs, onboarding, and fixed-layout snapshots.

**Architecture:** Extend the existing pure ledger validation context with canonical candidate-reader and key-epoch evidence rather than introducing mutable state. Keep signed Task 2/3 claim validation authoritative, make every vector serialize its complete replay input, and expose one deterministic replay function used by both the author and tests.

**Tech Stack:** TypeScript, Vitest, AJV draft-07, Noble cryptography, deterministic JSON/JCS vector generator.

## Global Constraints

- Preserve the 13 Task 4 vector IDs and registry revision 2.
- Produce no Control vectors.
- Keep Task 5 status allocation and Task 7 Status List encoding deferred.
- Treat repository carrier signatures as authorship only; signed claims/revocations and Task 3 decide semantic authority.
- Use TDD: each production behavior follows an observed focused-test failure.

---

### Task 1: Canonical decision time and claim confirmation

**Files:**
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Test: `docs/spec/vectors/generator/src/claim-ledger-conformance.test.ts`

**Interfaces:**
- Consumes: `LedgerMergeResult`, `ReaderAccessRequest`
- Produces: checkpoint/effect-time-safe `evaluateReaderAccess` and claim-only canonical confirmation.

- [ ] Write tests that backdated reader contexts fail and confirmed status invalidation cannot confirm or revoke a delivered claim.
- [ ] Run the focused test and observe failures from current backdated acceptance/source-claim confirmation.
- [ ] Restrict confirmation to canonical `record_type: "claim"` artifacts and require evaluation time at or after checkpoint and applicable reductions.
- [ ] Run the focused test to GREEN.

### Task 2: Exhaustive reader set and canonical key epochs

**Files:**
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Modify: `docs/spec/vectors/generator/src/topics-claim-ledger.ts`
- Test: `docs/spec/vectors/generator/src/claim-ledger-conformance.test.ts`

**Interfaces:**
- Consumes: all canonical signed reader claims, `reader_requests`, `audience_keys_by_epoch`
- Produces: exact active-reader derivation and digest-derived key IDs.

- [ ] Write tests for omitted candidate context, extra/missing recipients, same key/new label, and changed key/same ID.
- [ ] Run focused tests and observe current acceptance.
- [ ] Enumerate canonical reader claims, require one bound request per candidate, and compare the complete Task 3-authorized set to epoch recipients.
- [ ] Derive `key_id` from audience-key bytes and validate both old/new key ID and key material transitions.
- [ ] Run focused tests to GREEN.

### Task 3: Authenticated onboarding and snapshot-wide layout

**Files:**
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Test: `docs/spec/vectors/generator/src/claim-ledger-conformance.test.ts`

**Interfaces:**
- Consumes: current audience key, signed reader authorization, canonical checkpoint and snapshot
- Produces: audience-key MAC onboarding bundle and snapshot-wide 256-bucket materialization.

- [ ] Write tests that recomputed unkeyed onboarding forgeries fail and same-nonce record-set changes alter all 256 buckets.
- [ ] Run focused tests and observe failures.
- [ ] Replace bundle digest with a domain-separated HMAC over every bundle field and replay signed authorization identity/NID.
- [ ] Bind every bucket to a full sorted record-set digest plus epoch, nonce, and commit identifier.
- [ ] Run focused tests to GREEN.

### Task 4: Self-contained vectors and replay

**Files:**
- Modify: `docs/spec/vectors/generator/src/topics-claim-ledger.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.test.ts`
- Modify: `docs/spec/vectors/claim-ledger/*.json` (generated)

**Interfaces:**
- Consumes: serialized Task 4 replay input
- Produces: `replayClaimLedgerVector(input)` and all 13 expected outputs.

- [ ] Write a committed-vector replay test requiring each vector input to reconstruct its expected output without hidden fixture state.
- [ ] Run it and observe failure on incomplete current inputs.
- [ ] Add deterministic serializers/deserializers for maps, sets, signed artifacts, repository evidence, PoP, keys, records, and layout snapshots; make authoring call the same replay function.
- [ ] Run focused tests to GREEN.

### Task 5: Regenerate, verify, and commit

**Files:**
- Modify: `.superpowers/sdd/claims-task-4-report.md` (ignored report)
- Modify: generated Task 4 vectors and coverage only as commands require.

**Interfaces:**
- Consumes: all prior tasks
- Produces: deterministic committed vectors and verification evidence.

- [ ] Run focused tests and `tsc --noEmit`.
- [ ] Author vectors, stage them, author again, and require an empty second-pass diff.
- [ ] Run full `check`, `family:check`, `coverage`, and `git diff --check`.
- [ ] Update the Task 4 report with RED/GREEN evidence and deferred boundaries.
- [ ] Commit the correction and report the hash/range and exact verification counts.
