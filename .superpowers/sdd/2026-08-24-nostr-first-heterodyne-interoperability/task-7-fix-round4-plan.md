# Task 7 Fix Round 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind Social signing and DID resolution to embedding-owned authority instances while making historical resolution and revocation branch-independent.

**Architecture:** Comms atomically validates, attributes, executes once, verifies, and produces a one-use signed-publication proof through an embedding-configured authority. ATProto re-verifies persistable signed resolver attestations under one deep-frozen configured authority and evaluates durable revocations over the authenticated candidate/history universe before accepting the selected branch.

**Tech Stack:** TypeScript, Vitest, Noble Ed25519/BIP340/SHA-256, structural durable signer contract, module-private WeakMaps.

**Spec:** `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-fix-round4-design.md`

## Global Constraints

- Keep registry revision 14 and digest `9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc` unchanged.
- Do not edit frozen topic/vector sources, snapshot metadata, projections, baselines/reports/debt, or release artifacts.
- Preserve Comms-to-Control family layering: no production import from Control into Comms.
- Observe each exploit RED before its corresponding production change.

---

### Task 1: Atomic Comms signed-publication authority

**Files:**
- Modify: `docs/spec/vectors/generator/src/agent-authorship.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/vectors/generator/src/social-events.ts`

**Interfaces:**
- Produce: `createCommsSocialPublicationAuthority({ trusted_now, signer_execution })` closes over embedding-owned authority.
- Produce: `signCommsSocialPublication({ authority, registration, token, represented_persona, event, agent_association, requested_feed, requested_resource, execution_token, request_digest })` returns exact signed event and opaque `CommsSocialSignedPublication` proof.
- Consume: `consumeCommsSocialSignedPublication` burns the proof against exact Social context without mutable-state revalidation.

- [x] Add exploit tests proving signed-event stripping cannot mint, stale state at final trusted time prevents signer invocation, attribution is fixed before `executeOnce`, immutable snapshot mismatch rejects, proof replay rejects, and later revocation does not retroactively invalidate a returned proof.
- [x] Run focused Comms/Social tests and record the expected failures against the two-stage pre/post interface.
- [x] Implement the structural execute-once authority, atomic validation/injection/sign/strict-verification flow, trusted-time separation, immutable snapshots, and one-use proof.
- [x] Remove the obsolete pre-sign authorization/post-sign proof producers, route Social through the signed proof, and run focused tests GREEN.

### Task 2: Configured resolver authority instances

**Files:**
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.test.ts`
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.ts`

**Interfaces:**
- Produce: `createAtprotoResolverAuthority({ trust_anchors, allowed_policies, minimum_version, max_ttl })` returns opaque `AtprotoResolverAuthority`.
- Produce: `authenticateAtprotoDidResolution({ authority, evidence, validation_time })` returns a capability branded to that authority.
- Consume: DID signature/method verification requires the same authority instance.

- [x] Add exploit tests for attacker-selected anchors, fake authority capability, mutable envelope/document, disallowed policy, version downgrade, excessive TTL, and cross-authority consumption.
- [x] Run the resolver test file and record failures against caller-supplied trust configuration.
- [x] Implement deep-cloned/frozen configuration and evidence, semver/TTL/policy enforcement, per-authority branding, and same-authority consumers.
- [x] Run the resolver test file GREEN.

### Task 3: Persistable historical resolution

**Files:**
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`
- Modify: `docs/spec/vectors/generator/src/atproto-did-resolution.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`

**Interfaces:**
- Produce: durable `AtprotoResolutionEvidence = { envelope, signature }` carried by candidates and lineage.
- Consume: current candidates authenticate at trusted `now`; historical lineage authenticates at each binding event's `created_at`; current revocation resolution authenticates at trusted `now`.

- [x] Add a fresh-verifier generation-two probe whose generation-one attestation is expired at current time but valid at its historical event time.
- [x] Run focused ATProto tests and record failure from ephemeral/stale capability lineage.
- [x] Replace opaque carried capabilities with durable attestations and re-authenticate them at the correct current or historical validation time.
- [x] Run resolver/ATProto tests GREEN.

### Task 4: Revocation universe and fork rejection

**Files:**
- Modify: `docs/spec/vectors/generator/src/social-atproto.test.ts`
- Modify: `docs/spec/vectors/generator/src/social-atproto.ts`

**Interfaces:**
- Consume: authenticated universe is `candidates + lineage`; current selection remains greatest `created_at`, then lowest id.
- Produce: acceptance only when every valid revocation target for the identity is on the selected chain and has a strictly later fresh recovery generation.

- [x] Add exploit tests for a selected sibling after a revoked fork, a lower/reset fork hiding a revocation, and incompatible revoked forks.
- [x] Run focused ATProto tests and record current selected-branch-only revocation acceptance.
- [x] Authenticate historical universe bindings, independently verify every applicable durable revocation, and enforce selected-chain descent/recovery.
- [x] Run focused ATProto tests GREEN.

### Task 5: Normative text, report, verification, and commit

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `.superpowers/sdd/2026-08-24-nostr-first-heterodyne-interoperability/task-7-report.md`

- [x] Specify atomic trusted-time Comms signing, execute-once immutable attributed bytes, signed proof consumption, and non-retroactive later revocation.
- [x] Specify configured per-instance resolver authority, durable historical attestations, and branch-independent durable revocation evaluation.
- [x] Run focused tests, generator build, family check, and snapshot check; require exact 482.
- [x] Self-review the complete diff, confirm prohibited paths and rev14/digest, append exact RED/GREEN evidence and ownership rulings, then commit `fix: bind Social authority instances`.
