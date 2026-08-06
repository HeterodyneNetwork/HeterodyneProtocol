# Plan: Conformance test-vector suite (ADR-024)

**Slug:** test-vector-suite
**ADRs:** docs/adr/archive/2026-05-25-024-conformance-test-vector-suite.md
**Research:** docs/research/2026-05-25-test-vectors-research.md
**Mode:** --parallel
**Autopilot:** true
**Accept-ADRs:** false
**Lean:** false
**Bullets:** false
**Skills:** false
**Teammate-model:** opus
**Branch:** brains/test-vector-suite

Stub-level plan. Tasks are intentionally coarse so phase-3 re-architecture is
cheap. Each plan-phase is independently testable. Council seats: star-chamber
(gemini-3.1-pro, gpt-5.4) + codex (gpt-5). Plan revised after parallel review —
see "Council-integrated changes" at the bottom.

Serial-sweep: **not eligible** — ADR-024 introduces external deps
(nostr-tools, @noble/*). Standard multi-phase shape.

---

## Phase 1 — Generator & contract foundation (blocks all vector authoring)

- **T1.1 Scaffold generator project.** `docs/spec/vectors/generator/`:
  package.json (pinned deps: nostr-tools, @noble/curves, @noble/hashes,
  @noble/ciphers; test runner), tsconfig, non-normative-tooling README (G2).
  *Accept:* `npm ci && npm run build` clean; README states JSON vectors are the
  sole normative artifact.
- **T1.2 Crypto core A + KAT.** NIP-01 canonical serialization, SHA-256 event
  id, BIP-340 sign (aux_rand = 0^32) + verify. Gated by the official BIP-340
  known-answer vectors (G5). *Accept:* primitives unit-tested; BIP-340 KAT
  passes; aux_rand is an explicit parameter (F4).
- **T1.3 Crypto core B + KAT.** HKDF-SHA256 (index/post key derivation) and
  NIP-44 v2 symmetric encrypt/decrypt. Gated by the official NIP-44 v2 KAT
  (G5). *Accept:* HKDF + NIP-44 v2 KAT pass; nonce is an explicit parameter (F5).
- **T1.4 fixtures.json + resolver.** Named personas (cold-root + epoch
  keypairs), Matrix room ids, room secrets + key_ids, TEST_EPOCH, nonce policy;
  per-category keysets (F2); reference-by-id resolver (F3). *Accept:* fixtures
  schema-valid; categories use distinct keysets.
- **T1.5 vector.schema.json + reason-codes.json.** Full file shape (S1, S3) and
  a machine-readable reason-code source-of-truth (closed enum). *Accept:* schema
  validates a sample of each direction; reason_code enum is machine-checkable.
- **T1.6 reason-codes.md (human doc).** Prose for the closed enum, each code
  citing its spec section (V2, V6); kept in sync with reason-codes.json.
  *Accept:* every code has a citation and a json entry.
- **T1.7 Category-module interface + mocks.** The per-category authoring-module
  interface, plus simulated_clock handling (F6) and the transport-context
  adapter mock (E3) so time/transport-dependent vectors need no later generator
  refactor. *Accept:* a no-op sample category builds against the interface;
  clock/transport are injectable.
- **T1.8 Verify runner (table-driven).** Parse → schema-validate → feed input to
  the implementation-under-test adapter → compare expected_output /
  decision_trace; canonical-byte compare for produce/round-trip (P2). No
  normalization/policy logic (G4). *Accept:* runner green on T1.5 samples; lint
  rule forbids embedded policy logic.
- **T1.9 Author-mode / regeneration harness.** Compute outputs from
  input+fixtures and (re)write vector files deterministically. *Accept:* author
  then verify round-trips byte-identically.
- **T1.10 Determinism + adapter-boundary + normalized-schema reference.** The
  Phase-1-critical doc slice parallel teams depend on (determinism policy,
  Matrix→protocol adapter boundary, normalized-view schema). *Accept:* a
  category author can self-serve without reading code.
- **T1.11 Phase-1 CI.** lint + test + KAT + schema-validate + sample-runner
  only. *Accept:* CI green; governance gates intentionally deferred to T2.1.
- **T1.12 End-to-end baseline smoke vector.** One real vector exercising
  fixtures + schema + runner + author mode + CI + determinism together, before
  opening Phases 3–5. *Accept:* the smoke vector authors and verifies in CI.

## Phase 2 — Governance gates & normative docs (after T1.12 smoke vector)

- **T2.1 Governance CI.** staleness regen-diff (X1), coverage-non-empty per
  §14.3 (C4), spec_refs presence on every reason_code/normalized field (V6),
  and reason_code-value validation against reason-codes.json. *Accept:* CI fails
  on a mutated vector, an empty category dir, a missing citation, or an
  unknown reason_code.
- **T2.2 Spec §14.5 "Vector reproduction and schema."** Depends on the real
  runner + CI commands (T1.8/T1.9/T1.11). aux_rand/nonce/simulated_clock/
  created_at policy; vector_schema_version + vector_id immutability; pointers to
  the enum + normalized schema (D1).
- **T2.3 Expand vectors/README.md.** Full prose: schema, reason_code enum,
  normalized-view schema, transport adapter boundary, determinism policy (D2).

## Phase 3 — Crypto-bearing categories (produce / round-trip; parallel after Phase 1)

- **T3.1 identity/** — root attestation; delegation active/expired/revoked;
  revocation post-window; identity room full state.
- **T3.2 keri/ baseline** — inception; rotation (committed); rotation (none +
  witness threshold; witness_digest over content=""); did:key witness (no
  network); informal-vouch NOT counted.
- **T3.3 keri/ ordering & forks** — first-seen ordering verifier; fork
  resolution with conflicting rotations (the heavy state-machine cases, split
  from T3.2).
- **T3.4 envelope/** — minimal kind:1 wrapped (nip01_raw); bare DM with
  heterodyne_nostr_sig; fallback rendering; cross-kind wrap (1, 7, 30023).
- **T3.5 verification/** — bad sig; delegation mismatch; revoked-key post-
  revoked_at; backdated event in suspicion window (simulated_clock).
- **T3.6 index/** — room_key HKDF derivation; NIP-44 v2 encryption;
  prev_page_hash page-chain integrity; complete-fetch-attempt across relays.
- **T3.7 broadcast/** — private_broadcast room-key-wrapped post (signed-after-
  wrap, stable id); decrypt-by-member / non-member-cannot; reaction stays bare &
  not indexed; NIP-59 rejection; **context-binding vector (E2)**.
- **T3.8 outbox/** — full public outbox; scoped outbox; transitive discovery
  walk; cross-persona attestation (valid + invalid).
- **T3.9 relay-interop/** — NIP-42 AUTH signed by current epoch key (not cold
  root); AUTH rejection permanent; KERI rotation → AUTH under new epoch key.
- **T3.10 interop/** — wrapped → vanilla round-trip (comparison_surface = NIP-01
  serialization, P3); bare with hide-pref; vanilla-only follow; kind:31005
  pointer; **relay-mutation vectors (P4)**.
- **T3.11 config_room/** — minimal; persona_config private mutes; key_backup
  with various wrapping algorithms; cross-MXID sync with device_inventory NOT
  synced.

## Phase 4 — Logic / consume categories (parallel after Phase 1)

- **T4.1 bridge/** — Nostr permanent-fail (index NOT updated); Matrix permanent-
  fail (index updated + out-of-sync warning); idempotent re-pub via event-id
  reuse (§6.4.1 predicates).
- **T4.2 room-kind/** — four social kinds + identity/config round-trip; retired-
  kind rejection; legacy read-back map.
- **T4.3 multi-homing/** — active-room election (lex-min election_id tiebreaker);
  publish-lease acquire/renew; single-MXID revocation; kind:31005 race
  tiebreaker w/ KERI witness counts; partition-window void-and-requeue.
- **T4.4 transport/** — .onion reachable via embedded Tor; no clearnet DNS leak;
  WASM bridge + no-bridge indicator; egress-over-Tor off-by-default + indicator.
- **T4.5 moderation/** — NIP-72 approval; multi-mod; moderator rotation through
  KEL; redaction-of-approved-post; contributor submission + implicit-rejection
  window.
- **T4.6 encryption/** — encryption_version event; delegation-revocation →
  rotation (SHOULD path); **explicit opaque-Megolm negative-scope note (E1)**.
- **T4.7 versioning/** — older receiver vs newer sender; capabilities round-trip;
  cross-MAJOR placeholder; unknown room-kind tolerance.

## Phase 5 — Strict-mode, skippable & optional categories (each depends on its baseline)

- **T5.1 moderation/strict-mode/** (← T4.5) — invalid-broadcast-sig rejection;
  bare NOT hidden; kind:5 within 30s; state-downgrade warning; base/strict
  acceptance-surface pairing (E4).
- **T5.2 transport/strict-mode/** (← T4.4) — egress-over-Tor default-on unless
  explicitly disabled; base/strict pairing (E4).
- **T5.3 encryption/mls-migration/** (← T4.6, skippable) — eligibility gate;
  intent + ACK; abort on missing ACKs; receiver-verifiable flip; 60s tail;
  offline-reconnect re-encryption; non-MLS fallback.
- **T5.4 homeserver-exit/** (← T3.1 + T4.3, skippable) — identity-room
  migration; migration-pointer precedence over stale kind:31005; KERI rotation
  during exit window dual-publishes.
- **T5.5 redundancy/** (← T4.3, optional) — mirror_group + primary/replicas;
  promotion republishes cold-root kind:31005; private body relay-borne; re-key
  on removal not join; dedupe across replicas by event id.
- **T5.6 social-recovery/** (← T3.1 + T3.2/T3.3, optional) — three-tier caching
  (follower MAY / mutual SHOULD / witness MUST); cache rejects non-owner
  non-KERI; 30-day retention; cold-root re-anchor authoritative; cache-sourced
  state marked stale.
- **T5.7 relay-profile/** (← T3.9 + T4.4, optional) — NIP-11 Heterodyne-
  capability advert; vanilla NIP-01 unaffected; KEL-aware reputation continuity;
  passive witness-receipt store that signs nothing.

---

## Dependencies & sequencing

- Phase 1 blocks Phases 3–5. T1.2/T1.3 (crypto+KAT) precede T1.8/T1.9
  (runner/author). T1.12 smoke vector is the gate that opens parallel authoring
  and unblocks Phase 2's governance gates.
- Phase 2 governance CI (T2.1) lands right after T1.12; §14.5 + README prose
  (T2.2/T2.3) depend on the real runner + CI commands.
- Phases 3 and 4 are mutually parallel once Phase 1 lands; within each, category
  tasks are independent. Baseline-first: complete Phases 3+4 before Phase 5.
- Phase 5 is NOT blanket-parallel: each task depends on its baseline category
  (arrows above).
- A category task is "done" when its vectors pass the runner (X2) and the
  staleness gate (X1).

## Per-phase review tasks

Each plan-phase gets a concrete, schedulable **Nurture review** task and
**Secure review** task (not an umbrella). Phase 5 also gets a **Cleanup** task.

## Council-integrated changes (from parallel review)

1. Split overloaded T1.7 → interface/mocks (T1.7), runner (T1.8), author harness
   (T1.9). 2. Split crypto into KAT-gated A/B (T1.2/T1.3); removed standalone KAT
   task. 3. Split CI: Phase-1 lint/test/KAT/schema/sample (T1.11); governance
   gates deferred to T2.1. 4. Added end-to-end smoke vector (T1.12). 5. Pulled
   determinism/adapter/normalized reference into Phase 1 (T1.10). 6. Tasked
   simulated_clock + transport mocks in Phase 1 (T1.7). 7. Split keri baseline
   (T3.2) vs ordering/forks (T3.3). 8. Phase 5 depends per-baseline-category, not
   blanket Phase 1. 9. reason-codes machine-checkable (reason-codes.json + CI
   validation). 10. Nurture/Secure as concrete schedulable review tasks.
