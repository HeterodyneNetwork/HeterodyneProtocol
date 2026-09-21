# Under-Sixty-Minute Agent Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the August 28 Codex vector-maintenance workload correctly in less than 3,600 seconds, primarily by reducing agent steps, repeated context loading, and repair rounds.

**Architecture:** Compile a cited acceptance contract and edit-ready packets, then dispatch bounded parallel work through the existing agent host. A small deterministic coordinator owns a SQLite task/evidence store; agents submit immutable proposals, not authoritative state. Reuse current traceability tooling, and retain additional tools or faster models only when matched replays improve time to verified completion.

**Tech Stack:** Node.js, Git, SQLite behind a store interface, locked TypeScript compiler API, existing Semble/trace adapter, host agent bridge, Luna workers where appropriate. SARA, Serena, Inspect AI, and mini models are optional measured alternatives, not prerequisites.

**Spec:** [Verified repository maintenance in under sixty minutes](../specs/2026-09-04-sixty-minute-maintenance-design.md).

Status: Phase 1 tooling is implemented, reviewed, and locally verified; no
complete-workload sub-hour result is established. The former second-trial
treatment approval at 40 minutes 16 seconds was withdrawn after source-
authority adjudication found that one preserved case lacks an exact governing
rule. The first trial's all-275 semantic acceptance is withdrawn for the same
case; its 204/204 observed call counts remain historical metrics. Tasks 3–7
remain gated, not completed. See the [pilot findings and bounded continuation](../evaluations/sixty-minute-maintenance-pilot.md)
and [tooling evidence](../evaluations/sixty-minute-maintenance.md).
Existing SARA infrastructure is reusable, not completion of this plan.

Approved continuation: a fail-fast source-authority feasibility preflight before
any edit dispatch, documented in [the v3 preflight](../evaluations/sixty-minute-maintenance-preflight-v3.md).
The four-case read-only diagnostic retains source authority and unknowns; its
measured baseline and treatment reports are recorded, while the separately
reviewed feasible edit trial is tracked in the [v4 edit evaluation](../evaluations/sixty-minute-maintenance-edit-v4.md).
Tasks 3–7 remain gated on demonstrated improvement, not merely implementing this
preparation recipe.

The v3 preflight now reports three supported controls and one authority gap.
There is no honest all-275 ref-only repair to dispatch. Independent v4 review
selected three supported OIDC reference edits and excluded another case whose
frozen behavior lacks authority in the pinned specification. The existing
context renderer supplies narrow, line-cited excerpts; the common intent and
recipe are versioned under `scripts/maintenance-eval/contracts/reference-edit-v4.*`.
This tiny same-anchor trial tests source-bundle feasibility, not representative
full-workload throughput. Do not infer speed from unequal-quality or confounded
intervals. Tasks 3–7 still require a representative trial with fewer operations
and equal, source-backed acceptance; three substitutions cannot unlock them.

V4 did not establish that improvement: the baseline's edits were correct but
its evidence/operation ledger failed; the prepared candidate substituted a
current-style identifier prefix for the historical normative reference format.
Before another timed replay, freeze and verify the pinned reference conventions
alongside case-specific context, generate source citations and operation records
deterministically, and guard verification with exact checkout/HEAD assertions.
Reuse the existing schema's reference-format validation before the expensive
gate. Evaluate separating agent selection of a governing anchor from mechanical
reference rewriting that preserves the pinned qualifier; this is a proposed
bounded design, not an implemented or demonstrated optimization.
These are bounded correctness and measurement prerequisites, not authorization
for the datastore/scheduler. Preserve the failed trials; do not repair them
retroactively or use smaller input size as a proxy for accepted output.

## Global Constraints

- Complete the full August 28 vector-maintenance workload, with equivalent correctness and independent verification, in **less than 3,600 seconds**.
- The central datastore is the source of truth for **workflow state**, not for protocol requirements.
- Start with the available ceiling of four active agents: a coordinator and at most three workers.
- Initially target at most 8,000 tokens per worker packet; expansion is explicit, logged, and allowed when correctness needs it.
- No blanket Vitest parallelism, live-system access, or snapshot regeneration is introduced by this workflow.
- A cached result never replaces the required gate.
- Never merge automatically.
- Preserve unrelated files, private fixture/certificate identity, independent conformance, and current-draft versus history-bound snapshot separation.
- Primary job timing includes preparation, dependencies, indexing, all agents, retries, review, repair, actual local verification and commit. Remote PR/CI latency is reported separately.
- Raw archives and scorer-only artifacts stay private. No future solution commits or unrevealed corrective instructions enter worker-visible fixtures.
- This plan authorizes no implementation by itself. Generator refactoring is a separately reviewed, profiling-dependent change, not a prerequisite to building the coordinator.

---

## Delivery order and stop conditions

1. **Phase 1: establish the workload and prove fewer steps** — Tasks 1–2. Use
   the current host and a representative slice before building a platform.
2. **Phase 2: make the workflow durable and parallel** — Tasks 3–5. Add only
   machinery justified by the slice; no new general-purpose agent framework.
3. **Phase 3: expose and validate the workflow** — Tasks 6–7. Do not make it
   the default until repeated end-to-end acceptance succeeds.

Task dependency order is `1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7`. Within Task 4's
pilots, use independent workers with explicit file ownership; Task 5's check
runner can be developed alongside its host bridge once interfaces are fixed.
Tell every worker it is not alone and must preserve others' changes.

If the slice does not reduce agent decisions/read operations with equal
correctness, revise packet/contract design before Task 3. If the complete pilot
exceeds 90 minutes, address the measured dominant cause before adding tools.
The 90-minute checkpoint is diagnostic, not a relaxed acceptance threshold.

## File and responsibility map

All paths below are relative to the repository root. New workflow files are
proposed; existing protocol files listed under reuse are not automatic edits.

| Files | Responsibility |
| --- | --- |
| `scripts/maintenance-eval/{archive,fixture,score}.mjs` and matching `.test.mjs` | Private archive metrics, isolated replay inputs, evaluator contract and scoring |
| `scripts/maintenance-eval/contracts/aug28.json` | Redacted requirement IDs, provenance, reveal order, external-input boundaries; no solution patches |
| `scripts/maintenance/{metadata,packet,symbols}.mjs` and matching `.test.mjs` | Layout-specific declared contracts, exact cited context, static symbol spans, content-keyed chunk delivery |
| `scripts/maintenance/{store,reducer}.mjs` and matching `.test.mjs` | Schema migration, atomic events, leases, invalidation and restart state |
| `scripts/maintenance/{scheduler,host}.mjs` and matching `.test.mjs` | Ownership DAG, model routing, bounded host requests and immutable patch ingestion |
| `scripts/maintenance/{checks,report}.mjs` and matching `.test.mjs` | Trusted process execution, freshness-bound proofs and deterministic reports |
| `scripts/maintenance.mjs`, `scripts/maintenance.cli.test.mjs` | Versioned JSON command interface; no model SDK assumed |
| `.agents/skills/using-maintenance-workflow/SKILL.md`, `AGENTS.md` | Small opt-in agent recipe, authority/fallback rules and routing |
| `docs/superpowers/evaluations/sixty-minute-maintenance.md` | Reproducible run manifests, aggregate results, failures and rollout decision |

Runtime SQLite, graph caches, patch artifacts and raw logs live in a configured
per-run directory outside the source worktrees, not in Git or normative paths.
Add ignores only for deliberate local output locations; do not broad-ignore
existing user artifacts. Use built-in Node tests for the controller. The local
probe found Node 22.22.2 with working but experimental `node:sqlite`; pin/test
that runtime initially, check availability at startup, and isolate the driver
so a stable SQLite binding can replace it without rewriting scheduling.

## Task 1: Seal a fair workload and instrument actual work

**Files:** Create the `scripts/maintenance-eval/` files in the map and the initial
evaluation document. Read the authorized local August 28 archive, Git evidence,
and task reports. Do not commit the raw archive or hidden evaluator fixtures.

**Interfaces:**

```js
// archive.mjs: counts are separate, never summed across nesting levels.
export function summarizeArchive(records) {} // -> {spanMs, taskIntervalsMs,
// outerCalls, nestedCalls, processes, confirmedGateLaunches, provenance}
// fixture.mjs: evaluator-only entry point; no worker access to evidenceRepo.
export async function sealFixture({evidenceRepo, destination, contract, mode}) {}
// -> {workerRepo, baseTree, visibleContractDigest, oracleManifestDigest}
// score.mjs: input is a completed run manifest and independent check results.
export function scoreRun({elapsedMs, requiredChecks, completed, findings}) {}
// -> {correct, underBudget, accepted, reasons}
```

- [ ] **Step 1: Write failing archive, isolation and scoring tests.** Include
  a yielded command followed by polls: count one process and its actual
  start-to-exit time, not each poll as a launch. Include hidden descendant
  objects in the evidence repo and prove the worker fixture cannot read them.
  Use this exact score boundary:

  ```js
  test('an incomplete fast run is not a success', () => {
    const result = scoreRun({elapsedMs: 1200000, completed: true,
      requiredChecks: [{id: 'private-evidence', passed: false}], findings: []});
    assert.equal(result.accepted, false);
  });
  test('sixty minutes is not less than sixty minutes', () => {
    const result = scoreRun({elapsedMs: 3600000, completed: true,
      requiredChecks: [{id: 'independent-oracle', passed: true}], findings: []});
    assert.equal(result.underBudget, false);
  });
  ```

- [ ] **Step 2: Run RED.** Run `node --test scripts/maintenance-eval/*.test.mjs`;
  expect missing exports before implementation. Test fixtures must use synthetic
  logs, not personal sessions checked into Git.

- [ ] **Step 3: Implement the minimal importer, fixture builder and scorer.**
  Use public event fields only. Save timestamp/line provenance and counting rules.
  Define score acceptance as:

  ```js
  const correct = completed && requiredChecks.length > 0 &&
    requiredChecks.every(check => check.passed === true) && findings.length === 0;
  const underBudget = elapsedMs < 3600000;
  const accepted = correct && underBudget;
  ```

  The evaluator, not an agent, supplies the mandatory check set. Reject missing
  IDs or mismatched tree/toolchain/contract before calling this scoring core.
  Validate the first observed worker HEAD `b6416fda157529b708c86f21cc4ea66a7b24384c`
  and last worker commit `0dd150682903d14eddd8d14b57892395f750c47f`. Distinguish
  interleaved external snapshot changes from worker output. The endpoint is
  this worker's ten-round output, not the parent PR or subsequent snapshot
  regeneration. Model `0efa4a9`/`8f780ce` as external inputs with their own reveal
  boundaries, not changes credited to the benchmark worker. Use a fresh Git
  object store containing only permitted input/history objects, never a shared
  clone with future objects. Preserve the required pinned snapshot ancestors;
  a single-root export that makes `snapshot-check` impossible is not equivalent.

  Encode each of the design's ten rounds with `id`, `intent`, `source`,
  `confidence`, `reveal_after`, `external_inputs`, and `checks`. Where encrypted
  briefs prevent exact recovery, record that limitation and obtain a reviewed
  intent contract before timing the benchmark. The consolidated fixture uses
  final authorized behavior, not the abandoned runtime architecture; the causal
  fixture reveals the experiment and rollback at their decision boundaries.
  Deliver scripted maintainer decisions at those boundaries identically for
  all arms; exclude and disclose historical human idle gaps. Real approvals,
  if used instead, remain on every arm's clock. Verify later object reads fail,
  no alternates expose future history, and visible tree/lockfile/index/cache
  digests match the fixture manifest.
  Restrict all evaluated actors, including their coordinator, to permitted read
  roots; block future-solution fetches through Git/network. A trusted preparer
  provides locked dependencies. If the current host cannot enforce this, use an
  isolated runner before scoring acceptance; label unrestricted host trials
  exploratory rather than sealed.
  Keep independent negative fixtures and expected results outside worker access.

- [ ] **Step 4: Run GREEN and profile readiness.** Run the same Node tests.
  Measure one real full gate on each relevant sealed/current input environment,
  recording process start/exit, lane durations, CPU/memory, dependency setup,
  model availability and exact commits. The incomplete historical base may fail;
  record that failure, then use a evaluator-held completed tree to estimate final
  gate cost without showing its implementation to workers. Retain the gate's
  original lane order. Record the 1,882-call / 332-patch archived baseline and
  approximately 600 read/search commands, with explicitly different counting
  levels. Do not infer process duration from wrapper yields.

- [ ] **Step 5: Commit the redacted contract, harness and evidence.** Review
  `git diff --check` and staged paths for private content; commit with
  `test: define sealed August 28 maintenance benchmark`.

**Acceptance:** Reproducible worker-visible inputs, hidden independent oracle,
explicit uncertainty, and a measurable complete workload—not just round 1.

## Task 2: Deliver edit-ready packets and run a small vertical slice

**Files:** Create `scripts/maintenance/{packet,symbols}.mjs` and their tests.
Create `scripts/maintenance/metadata.mjs` and `scripts/maintenance/metadata.test.mjs`
for current and historical input-layout adapters.
Read/reuse `scripts/vector-trace.mjs`, `scripts/vector-trace/{projection,draft,impact}.mjs`.

**Interfaces:**

```js
export async function compilePacket({repo, graph, task, deliveredChunkIds}) {}
// -> {taskId, contractDigest, inputDigest, mustRead, mayNeed, unresolved,
//     deferred, deliveredChunkIds, estimatedTokens, complete}
export function symbolSpans({source, filePath}) {}
// -> [{symbol, startByte, endByte, sourceDigest}]; static parsing only
export async function readDeclaredContracts({repo, ref, layout}) {}
// layout: 'current-catalog' | 'legacy-authoring'; auto-detection must be recorded.
// -> {layout, inputDigest, records, unresolved}
// record: {id, evidenceKind: 'declared_current', specRefs, boundaryId,
// ownerDocument, profile, invariants, reasonCodes, provenance, unknownFields}
// Unavailable scalar fields are null, not guessed; unknown arrays have an
// explicit unknownFields entry. provenance: [{path, span, sourceDigest, kind}].
```

- [ ] **Step 1: Write failing packet tests.** A fixture with 96 related records
  and two exact affected cases must preserve all relationships while putting
  only necessary excerpts in `mustRead`. Test unknown runtime overrides,
  changed source under the same path, nested anchors, and historical/current
  lane separation. The key safety test is:

  ```js
  const packet = await compilePacket({repo, graph: partialGraph,
    task, deliveredChunkIds: []});
  assert.equal(packet.complete, false);
  assert.ok(packet.unresolved.length > 0);
  assert.equal(packet.mustRead.some(chunk => chunk.kind === 'normative'), true);
  ```

  Add a legacy fixture with no `current-vectors/` directory: require
  `readDeclaredContracts()` to return cited declarations and explicit unknowns,
  not fail due to a missing later catalog. Reject fixture-authored assertions as
  evidence of boundary execution. Current-layout tests retain profile overrides
  and terminal-only exclusions or mark unsupported expressions unresolved.

- [ ] **Step 2: Run RED.** Run `node --test scripts/maintenance/metadata.test.mjs scripts/maintenance/packet.test.mjs scripts/maintenance/symbols.test.mjs`.

- [ ] **Step 3: Implement static context compilation.** Reuse `buildGraph`,
  `queryPacket`, `compareProjections`, and `buildWorklist`; resolve exact symbol
  spans through the locked TypeScript parser. Do not execute family builders
  for metadata. Compute chunk identity with:

  ```js
  const chunkId = createHash('sha256')
    .update(JSON.stringify([lane, inputRef, sourceDigest, symbolOrAnchor, startByte, endByte]))
    .digest('hex');
  ```

  Include normative excerpts, affected implementation interfaces, acceptance
  checks, owned paths, unresolved links and expansion handles. Track delivered
  chunks; resend changed chunks and changed requirements, not unchanged files.
  Exceeding the approximate 8,000-token budget requests an explicit expansion,
  never truncates a normative obligation. Semble resolves discovery gaps; direct
  spans answer subsequent location requests. Record backend and token-estimator
  version. Do not silently treat `parallel_safe: false` as permission to fan out.
  A coordinator may derive a cited task-local ownership DAG while unrelated
  global links remain unresolved; relevant unknown ownership edges still block
  parallel edits. Preserve all unknowns for conservative verification selection.

  Current-main reuse includes `currentCaseContract()` and `currentCaseIds()` in
  `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`. The August
  28 base predates that catalog: bootstrap declared allocations from its prose,
  `src/vector-metadata.ts`, `src/author.ts` and `src/verify.ts` under the generator,
  labeling them `declared_current`, not execution evidence. Do not install the
  later catalog as if it already existed.
  Feed the adapter's declarations and unknowns into graph/packet construction;
  record which layout was selected. Proposed allocations are task inputs with
  provenance, never a fabricated execution certificate. Use `evidenceKind` in
  version-1 camelCase JSON; reserve snake_case for storage and source formats.

- [ ] **Step 4: Run GREEN and a matched slice.** Run the packet tests and existing
  `node --test scripts/vector-trace*.test.mjs`; distinguish optional SARA skips.
  Compare one representative contract-to-boundary implementation slice with
  and without compiled packets, using the same model and independent checks.
  Count all agent steps, repeats, reads, patches and repairs. Record wall time
  to accepted output. This is a feasibility experiment, not the full-workload
  speedup claim; stop expanding infrastructure if it shows no reduction.

- [ ] **Step 5: Commit packet code and slice results.** Commit with
  `feat: compile bounded maintenance context packets`.

**Acceptance:** Relevant source is delivered once with freshness and unknowns
intact; a representative task shows fewer agent-driven operations.

## Task 3: Implement the deterministic state and evidence reducer

**Files:** Create `scripts/maintenance/{store,reducer}.mjs` and their tests.

**Interfaces:**

```js
export function openStore({path, clock}) {} // -> {apply, readRun, close}
// apply({eventId, runId, taskId, expectedRevision, type, payload}) -> stored result
// readRun(runId) -> {revision, tasks, findings, checks, pendingEffects}
export function reduceEvent({state, event, now}) {} // -> {state, effects}
// Pure transitions; trusted service authorizes caller role before reduction.
```

- [ ] **Step 1: Write failing state-machine tests.** Cover two claims on one file,
  stale lease generations, conflicting event-ID reuse, invalid evidence, input
  changes after passing tests, dependency cycles and crash recovery. A minimum
  idempotency/concurrency test is:

  ```js
  const first = store.apply(claimAtRevision0);
  assert.deepEqual(store.apply(claimAtRevision0), first);
  assert.throws(() => store.apply(competingClaimAtRevision0), /revision|lease/);
  assert.throws(() => store.apply({...claimAtRevision0,
    payload: {...claimAtRevision0.payload, owner: 'different'}}), /event.*conflict/);
  ```

- [ ] **Step 2: Run RED.** Run `node --test scripts/maintenance/store.test.mjs scripts/maintenance/reducer.test.mjs`.

- [ ] **Step 3: Implement the minimum single-writer service.** Create versioned
  tables `runs`, `requirements`, `tasks`, `task_dependencies`, `file_leases`,
  `artifacts`, `findings`, `checks`, `events`, each keyed by `run_id`. Use atomic
  transactions and foreign keys; append events and update materialized state
  in the same transaction. A pending-effect record lives with its event so
  restart can reconcile an uncertain process/patch before retrying it.

  ```sql
  BEGIN IMMEDIATE;
  -- Check existing event ID and payload digest before revision validation.
  -- Compare expected revision, lease generation and current input digest.
  -- Insert immutable event and apply the validated state transition together.
  COMMIT;
  ```

  State transitions follow `planned -> ready -> leased -> submitted -> checked
  -> integrated`. Invalidated tasks return to `ready`, lose stale evidence and
  increment generation; invalidate transitive dependents as well. Submission
  alone cannot create a passing check. Only trusted runner/integrator roles can
  create `check_finished`/`integrated` events. Store raw outputs in immutable
  digest-addressed artifacts outside worker write roots; return structured
  rejection codes `STALE_INPUT`, `LEASE_CONFLICT`, `PATH_DENIED`,
  `EVIDENCE_MISSING`, `EVENT_CONFLICT`, and `DEPENDENCY_CYCLE`.

- [ ] **Step 4: Run GREEN and restart tests.** Reopen the database after an
  interrupted claim, check and integration. Replaying the same accepted event
  must not repeat a side effect. Confirm a worker can neither write the DB nor
  forge a trusted event through the host bridge. If the current host cannot
  restrict direct shell writes, report the trust limitation and require an
  isolated runner before making enforcement claims.

- [ ] **Step 5: Commit the reducer.** Commit with
  `feat: persist maintenance leases and evidence atomically`.

**Acceptance:** Multiple agents cannot silently overwrite ownership/state, and
resume recovers validated progress without rereading the full conversation.

## Task 4: Schedule isolated workers and route models by accepted-output cost

**Files:** Create `scripts/maintenance/{scheduler,host}.mjs` and their tests;
create `scripts/maintenance.mjs` and `scripts/maintenance.cli.test.mjs`.

**Interfaces:**

```js
export function planDispatch({run, capabilities, profiles}) {}
// -> [{taskId, leaseGeneration, profileId, ownedPaths, packetDigest}]
export async function ingestProposal({store, proposal, artifactRoot}) {}
// proposal: {runId, taskId, leaseGeneration, expectedRevision, inputDigest,
//            patchDigest, changedPaths, checkArtifactDigests, hostHandle}
export function chooseProfile({task, profiles, failedRepairs}) {} // -> profileId
export async function probeEnvironment({requestedProfiles, storeDriver, host}) {}
// -> {ok, missing, nodeVersion, sqliteVersion, resolvedProfiles, isolationMode}
// Host adapter: capabilities(), start(request), poll(handle), cancel(handle).
// start consumes a validated dispatch request, never arbitrary shell text.
```

- [ ] **Step 1: Write failing scheduler/bridge tests.** Assert no more than three
  active workers, conflicting paths serialize, unresolved ownership blocks
  dispatch, a reviewer never reviews its own change, and unknown models fail
  capability validation. Test an expired worker result, path traversal, symlink
  escape, a changed preimage and a submitted patch outside leased paths.

  ```js
  assert.equal(planDispatch({run: disjointRun, capabilities: fourSlots,
    profiles}).length, 3);
  assert.equal(chooseProfile({task: boundaryDecision, profiles,
    failedRepairs: 0}), 'capable');
  assert.equal(chooseProfile({task: boundedEdit, profiles,
    failedRepairs: 2}), 'capable');
  ```

- [ ] **Step 2: Run RED.** Run `node --test scripts/maintenance/scheduler.test.mjs scripts/maintenance/host.test.mjs scripts/maintenance.cli.test.mjs`.

- [ ] **Step 3: Implement a host-neutral dispatch bridge.** Expose JSON commands
  `prepare`, `packet`, `next`, `submit`, `check`, `status`, `resume`, `report`,
  and `replay` with schema version 1. `next` returns validated requests for the
  existing host coordinator to execute through available collaboration tools;
  do not invent a Node SDK for those tools. The fake adapter is deterministic
  for tests. A real adapter records spawn/finish IDs and capabilities and uses
  actual host operations, with no unapproved external model/provider switch.

  Configure routing explicitly:

  ```json
  {"maxWorkers":3,"profiles":{
    "fast":{"model":"gpt-5.6-luna","reasoningEffort":"medium"},
    "capable":{"model":"host-inherited"}},
   "escalateAfterFailedRepairs":2}
  ```

  `host-inherited` resolves to the actual configured model ID before a run is
  scored. Parsing, joins, hashing, leases and reporting use no model. Trust-boundary
  decisions, ambiguous requirements, integration and independent review use
  the capable profile. Repetitive edits and bounded discovery may use fast.
  A mini arm is enabled only after the host/provider confirms its exact ID and
  the maintainer configures access and a spend cap; unavailable is a result.

  Create isolated worker trees at immutable inputs, lease exact paths, and
  assign one integrator for shared catalogs/certificates. Patch ingestion verifies
  the digest, path policy and preimages before an integrator applies it. Workers
  can submit schema-validated catalog fragments, but only the owning integrator
  turns them into repository edits. Do not share mutable fixtures or certificates
  across processes. Schedule independent review in a freed worker slot and
  consolidate findings against an immutable candidate digest.

- [ ] **Step 4: Run GREEN and one three-worker pilot.** Record every attempt,
  model/effort, source chunks, process duration and accepted patch. Inject one
  stale proposal and one worker interruption; neither may corrupt the integrated
  tree. Show `status` and `resume` return only current evidence plus missing work.
  Compare same-model dispatch against fast-worker dispatch without changing
  retrieval or tests at the same time.

  `prepare` must call `probeEnvironment()` before dispatch/scoring. Resolve model
  IDs against host capabilities and record exact runtime/driver/profile versions
  in the run manifest; the Luna configuration above is an example for the
  observed host, not a universal dependency. An absent SQLite driver or model
  returns nonzero `CAPABILITY_MISSING`, without dispatch or silent substitution.
  An alternative pinned SQLite binding is allowed only when explicitly configured
  and covered by the same store tests. Probe/failed preparation time stays in the
  job record. Report `isolationMode: cooperative` for unrestricted shared-host
  trials; only an enforced isolated runner may report protected state/oracle
  integrity or count as sealed acceptance.

  `ingestProposal()` resolves `hostHandle` against trusted dispatch state and
  binds each check artifact to its actual runner/process identity and candidate
  input digest. Matching arbitrary digests supplied by a worker is insufficient.

- [ ] **Step 5: Commit scheduling and bridge code.** Commit with
  `feat: coordinate bounded parallel maintenance workers`.

**Acceptance:** Parallelism removes independent critical-path work without
sharing mutable state; model speed is measured including all required repairs.

## Task 5: Bind verification to inputs and eliminate redundant full gates

**Files:** Create `scripts/maintenance/{checks,report}.mjs` and tests. Read
`scripts/conformance-ci.sh`, generator package scripts and `vitest.current.config.ts`.
Do not change those files by default.

**Interfaces:**

```js
export function selectChecks({packet, changedPaths}) {} // -> bounded check IDs
export async function runChecks({repo, checkIds, inputDigest, contractDigest,
  toolchainDigest, runner, artifactRoot}) {} // -> immutable proof records
// runner is trusted configuration: command ID -> fixed argv, cwd policy, limits.
export function canFinalize({run, finalInputDigest}) {} // -> {ok, reasons}
export function buildReport({run, measurements}) {} // -> deterministic JSON
```

- [ ] **Step 1: Write failing check/freshness tests.** Verify partial graphs select
  broader feedback, changed lockfiles invalidate cached feedback, modified tests
  require independent review, and cached/old-tree full gates cannot finalize.

  ```js
  assert.equal(selectChecks({packet: incompletePacket,
    changedPaths: ['docs/spec/vectors/generator/src/author.ts']})
    .includes('draft-full'), true);
  assert.equal(canFinalize({run: passedOnTreeA,
    finalInputDigest: 'tree-B'}).ok, false);
  ```

- [ ] **Step 2: Run RED.** Run `node --test scripts/maintenance/checks.test.mjs scripts/maintenance/report.test.mjs`.

- [ ] **Step 3: Implement fixed command IDs and proof keys.** Bind proofs to
  all source/untracked input digests, contract, lockfiles, runtime, config, runner
  and command version. No agent-supplied shell strings or claimed verdicts are
  executable authority. The command map includes:

  ```js
  const commands = {
    'draft-full': ['npm', '--prefix', 'docs/spec/vectors/generator', 'run', 'draft:check', '--', repo],
    'final-full': ['bash', 'scripts/conformance-ci.sh']
  };
  ```

  Add bounded selected-test IDs using the existing `test:current` script and
  validated repository-relative test paths. Current graph evidence has 64
  unresolved links and reports `parallel_safe: false`; this cannot justify a
  minimal test selection. Treat narrowed tests as feedback, not conformance.
  Keep `maxWorkers: 1` and `fileParallelism: false` for current Vitest invocations.
  Separate worker processes may run disjoint checks only with independent module
  state/output directories and a measured resource cap.

  Require final independent review and one fresh successful `final-full` run on
  the integrated immutable candidate, plus evaluator-owned acceptance checks.
  If a relevant edit follows, invalidate proofs and rerun. Keep `buildCurrentCases`,
  `invokeCurrentBoundary`, `certifyBoundaryExecution`, and private WeakMap evidence
  in their intended process; store inspected digests, never serialized certificate
  tokens. The scorer is not modified by worker patches. Review any proposed
  repository test/verification changes against independent expected behavior.

  If profiling identifies eager fixture construction as dominant, open a bounded
  follow-up change in `current-vectors/index.ts`, the affected family builder,
  and its tests: separate pure metadata from fixture execution, prove identical
  case IDs/profile overrides/certificate rejection behavior before and after,
  then measure. Do not pre-authorize a whole-generator rewrite or delete
  `vector-metadata.ts`; no extraction lands without equivalence tests and review.

- [ ] **Step 4: Run GREEN and end-to-end gate verification.** Run the Node tests,
  followed by a real `scripts/conformance-ci.sh` in an isolated complete pilot
  tree. Record actual process start/exit and required lane order, not polling
  latency. Demonstrate invalidation after a synthetic input change. Report final
  gate repetitions honestly; one is the planned normal case, not a safety cap.

- [ ] **Step 5: Commit verification and reports.** Commit with
  `feat: require fresh independent maintenance verification`.

**Acceptance:** Passing state is derived from trusted, fresh evidence; repeated
full gates are replaced by focused feedback only where safe, never omitted at
the final acceptance boundary.

## Task 6: Expose a small opt-in workflow skill, not a generated protocol oracle

**Files:** Create `.agents/skills/using-maintenance-workflow/SKILL.md`; modify
`AGENTS.md` to link it. Preserve `.agents/skills/using-sara/SKILL.md` as the
trace-query recipe, linking it from the new skill rather than duplicating it.

**Interfaces:** The skill consumes the version-1 CLI from Task 4 and the
deterministic packet/status/report formats. It does not read/write SQLite directly.

- [ ] **Step 1: Load the skill-creator and writing-skills instructions.** Establish
  a fresh-agent baseline: ask for one affected change using only existing routing;
  record unnecessary full-file reads, missing ownership and stale status decisions.

- [ ] **Step 2: Write failing CLI/skill scenario assertions.** Extend
  `scripts/maintenance.cli.test.mjs` to require `status` to distinguish declared
  contract evidence from executed proof, preserve unresolved links, and fail
  completion without a final gate. Run it and confirm RED before adding routing.

- [ ] **Step 3: Write the bounded recipe and link it from AGENTS.** Start with:

  ```yaml
  ---
  name: using-maintenance-workflow
  description: Use for opted-in multi-file spec or vector maintenance requiring parallel ownership, resumable task state, and verification evidence.
  ---
  ```

  In fewer than 500 words, explain `prepare -> packet/next -> submit -> check ->
  status/report`, model escalation, source citations, unresolved-link expansion,
  and that only a dedicated reconciliation may author a snapshot. Generated
  packets must carry input digests and freshness and must not claim authority
  over the normative spec. The skill is a stable access recipe; don't regenerate
  a giant skill containing every repository fact. If the service is unavailable,
  fall back to the SARA/trace skill plus Semble and explicitly report the lack of
  durable state. Initially mark the AGENTS route opt-in pending Task 7 acceptance.

- [ ] **Step 4: Run GREEN and a fresh-agent skill trial.** Validate skill metadata,
  run CLI tests, then verify an agent uses bounded packets, recognizes stale state,
  and does not regenerate vectors for an ordinary draft edit. Record all extra
  calls; pass only if correctness is unchanged and the recipe reduces avoidable
  navigation. Review AGENTS wording for source-of-truth confusion.

- [ ] **Step 5: Commit the skill and routing.** Commit with
  `docs: expose opt-in maintenance coordination skill`.

**Acceptance:** Agents can discover and resume the workflow without a large
prompt or another manually maintained truth map.

## Task 7: Run matched replays, select tools, and gate rollout

**Files:** Extend `scripts/maintenance-eval/score.mjs` and its tests; update
`docs/superpowers/evaluations/sixty-minute-maintenance.md`. Modify AGENTS from
opt-in to default only after the criteria below pass.

**Interfaces:** The replay command consumes a sealed fixture from Task 1, a host
profile from Task 4, and immutable proof/report artifacts from Task 5. It emits
every run's elapsed time, correctness verdict, counters and environment manifest.

- [ ] **Step 1: Write failing aggregate scoring tests.** A set containing a
  3,601-second run, a wrong result, an omitted attempt or a missing held-out check
  must not pass. A complete-brief success must not become a causal-replay claim.

  ```js
  assert.equal(fiveRuns.every(run => run.correct && run.elapsedMs < 3600000), false);
  assert.equal(report.claims.causalReplayPassed, false);
  ```

- [ ] **Step 2: Run RED, then implement deterministic aggregation.** Preserve
  attempt IDs, unsuccessful runs, timeouts and escalation costs. Timeouts are
  censored results, not fabricated completion times. Keep outer calls, nested
  actions and actual processes separate, aggregated across all agents.
  Diagnostic budgets are 150 outer calls, 60 read/search requests, 40 patch units
  and one planned repair wave for complete-brief runs; record exceptions without
  suppressing needed work. Causal replay retains each revealed repair and
  architecture-decision wave and reports a separate critical path.

- [ ] **Step 3: Compare controlled arms.** Use identical input, resources, exposed
  requirements and independent scorer:

  | Arm | Change under test |
  | --- | --- |
  | A | Existing workflow and model allocation; cap long baseline runs and disclose censoring |
  | B | Deterministic packet/state/parallel workflow; same model allocation as A |
  | C | B with fast Luna workers; optional configured mini arm measured separately |
  | D | Best prior arm with SARA, Serena/TS-symbol access, or another retrieval backend varied one at a time |

  Evaluate Inspect AI's existing agent/logging integration before writing any
  general evaluation service; retain the small harness if integration adds more
  work than it removes. Consider LangGraph only if demonstrated host recovery
  requirements exceed the reducer. Record setup/cold/warm cost separately. No
  tool is adopted merely because lookup latency improves.

- [ ] **Step 4: Run GREEN and complete acceptance trials.** Run the full controller
  test suite, then five independent complete-brief attempts using the selected
  configuration, all correct and all under 3,600 seconds. Run two different
  held-out maintenance tasks with independent correctness checks; report their
  timing without implying a broader SLA. Run the causal fixture separately,
  preserving reveal/decision boundaries and explicitly reporting any compressed
  idle gaps. An exact August 28 evolving-session speedup claim requires that
  track to pass too. Freeze the chosen configuration before the five acceptance
  attempts; retuning starts a new disclosed series rather than hiding failures.

- [ ] **Step 5: Publish the result and rollout decision.** Commit aggregate
  results with `test: report end-to-end maintenance replay results`. Link run
  manifests, hardware/model versions, total step reductions, all failures,
  critical-path timings and remaining uncertainty. Do not claim population p95
  from five runs. If acceptance fails, retain opt-in status and name the measured
  bottleneck/next bounded experiment. If it passes, enable the reviewed default
  route. Push the verified feature branch and create/update its PR against the
  base branch; never merge automatically.

**Acceptance:** A repeatable, independently correct sub-hour workflow—not a
faster search demo, a single lucky run, or a renamed batch of hidden operations.

## Implementation handoff

Start with Tasks 1–2 only: a reviewed benchmark contract, actual process profile,
and the smallest matched packet-driven task. The proposed SQLite and model
routing design answers the central-state/fast-agent request, but its value must
be demonstrated before completing a larger controller. Keep current SARA work
available; it need not be the final workflow's central component.
