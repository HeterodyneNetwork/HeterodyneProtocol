# SARA Spec Workflow Implementation Plan

> **Objective superseded:** The [under-sixty-minute agent maintenance plan](2026-09-04-sixty-minute-maintenance.md)
> replaces this plan's human-investigation/query-latency objective and governs
> further workflow work. Existing Phase 1 remains reusable infrastructure; SARA
> adoption is not the acceptance criterion. No agent-session speedup has yet
> been demonstrated. Preserve the implementation history below as evidence.

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkboxes for tracking.

**Goal:** Reduce the time to locate, change, and verify Heterodyne requirements through a reproducible impact index and a small agent skill.

**Architecture:** Derive a graph from normative anchors, explicit current case contracts, and separately selected snapshot evidence. Expose a fast draft change packet through the Node wrapper, with SARA as its optional graph backend and Semble for investigating missing links. Preserve the existing separation between contract allocation, fixture construction, boundary execution, and independent conformance.

**Tech stack:** Node.js, Git plumbing, TypeScript compiler API where static source analysis is necessary, existing locked generator tools, optional SARA CLI.

**Spec:** [SARA design and 0.6 revision](../specs/2026-08-28-sara-vector-traceability-design.md).

## Baseline and supersession

This plan supersedes the August 28 implementation plan, preserved in local
commit `dc488c7`, and the obsolete implementation assumptions in sections 3,
6, and 7 of the original design. Reviewed against fetched GitHub `main`:
`adda8b522f9cb558b31cb27ac0f7e4f1150d5fac` (0.6 security closure, PR #28).

The committed snapshot now has 267 vectors, schema `3.0.0`, source commit
`c72f5ccdf855069550511d8e3e837dae55ed299c`, and history-derived snapshot commit
`80da4ded273ac746b9c56bc53a8f1c067835ad64`. These are observations at this base,
not constants to embed in tooling. Read `snapshot.json` and derive its history
binding on every invocation. Retain synthetic schema-2 history tests.

The previous Phase 1 branch contains CLI/projection work in `0c59fac` and
`74e6bdc`; it has not been integrated into this plan branch. Reuse reviewed
pieces after updating their assumptions, rather than treating those commits
as completion against 0.6. The older 482-vector count, numbered filenames,
18-vector privacy query expectation, and three unresolved references are not
acceptance expectations for current main.

## Assessment against the efficiency goal

The original plan helps historical lookup but is insufficient for faster
ordinary edits: draft mode has no case relationships, graph construction can
repeat expensive work, impact follows too few dependencies, and no latency or
task-time targets demonstrate a benefit. Adding another mandatory CLI and a
second metadata map could increase maintenance cost.

The revised first deliverable is a **draft change packet**: the requirement
and its citations, exact related case declarations, source boundaries, linked
schemas/registry entries, candidate tests, missing links, and shared-file
collisions. Each result states what is declared versus actually verified.
This lets an agent reach the files to edit without generating the corpus.

| Latest repository evidence | Consequence for implementation |
| --- | --- |
| `current-vectors/case-contracts.ts` declares owner, references, invariants, reasons, boundary IDs | Reuse allocation; do not introduce a parallel hand-maintained map |
| `currentCaseContract()` applies profile-oracle and boundary overrides | Reading only the literal contract object is incomplete |
| `current-vectors/index.ts` binds executed cases to certificates | A metadata index cannot claim executed coverage or mint certificates |
| Draft refs use `heterodyne:0.6.0#anchor`; packaged refs use `heterodyne:owner#anchor` | Normalize using validated owner and family version, preserving raw refs |
| Packaged paths are `<vector_id>.json` under family directories | Resolve manifest artifacts and actual IDs; never require numeric prefixes or infer owner from path |
| `vitest.current.config.ts` explicitly serializes workers | Benchmark isolated selection before proposing concurrency changes |
| `profile-oracles.ts` imports cryptographic and fixture machinery | Importing the contract accessor is not proof that indexing avoids expensive work |

Paths in this table are relative to `docs/spec/vectors/generator/src/` except
`vitest.current.config.ts`, which is at the generator package root.

SARA remains a useful experiment for graph validation and traversal. Keep it
only if the adapter is cheap enough to maintain and its workflow improves the
measured tasks. The repository already solves important parts of traceability;
reuse those before evaluating another requirements framework. No new external
product comparison or performance benchmark was performed for this revision.

## Global constraints

- Normative authority remains the six specs, live registry, and protocol schemas.
- Snapshot coverage comes solely from its coverage manifest. Draft metadata is
  declared authoring intent, not historical or executed conformance evidence.
- Preserve the three-root snapshot lifecycle: source, snapshot, snapshot-tool.
- Do not repair drift, regenerate vectors, or change conformance baselines here.
- The merged snapshot is evidence of reconciliation work, but further generator
  restructuring still requires the maintainer confirmation previously requested.
- Phase 1 changes only `scripts/`, the skill, AGENTS routing, and supporting docs.
  Phase 2 may change generator metadata loading after that gate.
- No automatic deletion of `vector-metadata.ts`: it is not the active current
  authoring path and may remain necessary for historical lifecycle support.
- Preserve certificate identity, private fixture boundaries, terminal-only
  exclusions, explicit `conformance_checks`, and independent harness isolation.
- Generated graph/cache files stay outside normative and snapshot trees.
- Git comparisons never check out refs over the user's working tree. Outputs
  are pure JSON on stdout; diagnostics go to stderr; errors exit nonzero.
- Always push a verified feature branch and open a PR against its base; never
  merge automatically.

## Task 1: Measure the actual contributor workflow

Execution scope: Phase 1 measures automated packet production and a fresh-agent
before/after scenario. It does not establish the human investigation-time
target: no matched human editing trial was available. That part of Task 1
remains open rather than being inferred from command timings. Measurements and
limitations are recorded in the [efficiency evaluation](../evaluations/sara-workflow-efficiency.md)
and [skill evaluation](../evaluations/using-sara-baseline.md).

**Files:** Create `docs/superpowers/evaluations/sara-workflow-efficiency.md`.

- [x] Record Git base, machine, Node/SARA versions, dependency installation,
  cold/warm state, wall time, peak memory where available, and command count.
- [x] Time five repetitions each of: anchor reverse lookup; a local Comms
  requirement edit; a Workspace change crossing Control/Assurance; and a shared
  registry/schema change. Use temporary copies and record exact changed paths.
  Include one case with intentionally absent links to expose incomplete impact.
- [ ] Establish the baseline with Semble plus the current read-only checks.
  Record first useful answer time, files opened, manually corrected omissions,
  and time to the first relevant test result. Keep dependency installation and
  full acceptance-gate time separate from repeated edit-loop cost.
- [x] Record proposed targets: warm query p95 at most 2 seconds, cold index at
  most 10 seconds, and at least 50% less median investigation time on the same
  tasks. These are targets, not measured results. Correctness requires every
  known dependency in fixtures to be reported or explicitly marked unresolved.
- [x] Commit the reproducible measurements before optimizing. Failure to meet
  a target triggers profiling and a documented scope decision, not weaker checks.

## Task 2: Port the projection core to current snapshot contracts

**Files:** Create `scripts/vector-trace.mjs`, `scripts/vector-trace.test.mjs`,
`scripts/vector-trace/projection.mjs`, and `scripts/vector-trace/history.mjs`.

**Interface:** `buildProjection({repo, lane, vectorRef})` returns
`{items, edges, receipt}`. Each item has `semantic_id`, `type`, `source_path`,
`source_digest`, and `evidence_kind`; each edge has endpoints, relation, and
source provenance. Receipt records resolved commits, all input digests, parser
and graph versions, unresolved references, and canonical graph digest.

- [x] Port stable IDs, bounded Git blob reads, paragraph/heading anchors, and
  input path checks from the existing branch. Add failing tests for schema 3,
  unnumbered paths, incorrect declared owner, and historical schema 2.
- [x] Implement manifest-to-vector matching from actual `vector_id` fields.
  Validate the closed inventory and hashes; read coverage only at the snapshot
  commit and source artifacts only at its source pin.
- [x] Make lane selection explicit in the CLI. `draft` reads current bytes;
  `snapshot` uses history; `reconciliation` requires an explicit vector ref and
  labels combined results maintenance-only. Do not default a spec-edit request
  to historical evidence.
- [x] Test changes during indexing, file additions/deletions, missing objects,
  stale cache, symlink escape, unknown schema, and conflicting IDs. Hash the
  input inventory as well as contents; timestamps alone do not prove freshness.
- [x] Run `node --test scripts/vector-trace.test.mjs` and commit the port.

## Task 3: Produce useful current-draft change packets

**Files:** Create `scripts/vector-trace/draft.mjs` and
`scripts/vector-trace/impact.mjs`; extend the CLI and focused tests.

**Interface:** `impact --lane draft --base <ref> --head <ref|WORKTREE>` returns
`{changed, related, unresolved, suggested_checks, collision_risks, receipt}`.
`query <semantic-id> --lane draft` returns the same provenance-bearing records
around a single requirement. Suggested checks are recommendations, not proof
that omitted tests are safe to skip.

- [x] Add fixtures for version-qualified draft refs, owner-qualified snapshot
  refs, contract overrides, terminal-only exclusions, and profile allocations.
  Normalize the reference only after owner/version/anchor validation.
- [x] Build a conservative static inventory using the locked TypeScript parser.
  Read contract declarations and explicit overrides; support only tested literal
  and reference forms. Represent unresolved runtime profile computations as
  gaps with exact source locations. Do not execute arbitrary historical code,
  fixture builders, or crypto to answer a lookup.
- [x] Include source relationships from explicit boundary allocations and
  resolved import/export references. Topic basename matching is insufficient.
  Preserve both allocation and override provenance. Only label a relation
  complete when all relevant supported references resolve.
- [x] Compare both ends of a diff, retaining deleted anchors and old edges.
  Include changes to schemas, registry entries, contracts, evaluator modules,
  and text outside explicit anchors. Treat unanchored changes conservatively
  as document-level impact, not as no impact.
- [x] Derive candidate test files from resolved dependencies and existing test
  configuration. Dynamic/unresolved dependencies require broader checks. Add
  tests for shared fixtures, deleted imports, cyclic imports, and shared specs.
- [x] Expose `worklist` with owned files and collision groups. Two different
  vector IDs are not independent if they edit the same contract or fixture file.
- [x] Run focused tests and repeat Task 1 lookup measurements. Commit a useful
  draft packet even if some profile links remain explicitly unresolved.

## Task 4: Integrate SARA and the agent skill

**Files:** Create `scripts/sara/model.yaml`,
`scripts/vector-trace/sara.mjs`, `.agents/skills/using-sara/SKILL.md`, and
`docs/superpowers/evaluations/using-sara-baseline.md`; update `AGENTS.md`.

- [x] Retest the prior SARA 0.10.x compatibility choice against its official
  CLI documentation and real fixture traversal before retaining the pin.
  Keep SARA installation optional and outside ordinary conformance CI.
- [x] Materialize temporary graph items for anchors, draft cases, snapshot
  vectors, modules, schemas, and registry artifacts. Distinguish declared links
  from executed evidence in the model. Use stable semantic IDs at the CLI.
- [x] Test graph cleanup, missing/unsupported SARA, broken relations, JSON
  preambles, and output-path safety. Core receipt and draft packet operations
  should remain available without SARA; SARA-specific validation fails clearly
  if the tool is missing.
- [x] Implement `check`, `query`, `coverage`, `matrix`, `impact`, `worklist`, and
  `receipt`. Label coverage as declared relationships; absence of an edge is
  neither proof of absent tests nor a claim of protocol nonconformance.
- [x] Write a skill under 500 words with frontmatter `name: using-sara` and a
  description covering spec changes, reverse lookup, impact, and reconciliation.
  Route ordinary edits to a draft packet; historical questions to snapshot;
  mixed questions to reconciliation. Verify the receipt included with the query
  instead of requiring two complete graph builds for receipt then query.
- [x] Require citations to normative anchors and exact source locations. Use
  Semble to investigate gaps and implementation details. The skill is a query
  recipe, not an automatically generated second specification.
- [ ] Evaluate the same editing scenario before/after the skill; record actual
  responses, time, source citations, and lane mistakes. Validate frontmatter
  with the installed skill-creator validator. Add a direct AGENTS skill link.
- [x] Run focused tests plus one real SARA integration test and commit.

## Task 5: Verify Phase 1 and make the next optimization decision

- [x] Derive expected snapshot query IDs directly from the selected coverage
  manifest and compare sets exactly; do not hard-code the old privacy count.
- [x] Run focused wrapper tests and `scripts/conformance-ci.sh` once with locked
  dependencies. The latter already runs both read-only lanes and independent
  conformance. Record failures without repairing unrelated protocol artifacts.
- [x] Check `git diff --check` and confirm only Phase 1 paths changed. Re-run
  Task 1 scenarios and publish measured results including unresolved links.
- [x] Require no loss of dependency recall in known fixtures; benchmark human
  editing tasks separately from graph traversal latency. State explicitly if
  faster generation or verification has not yet been demonstrated.
- [x] Push the feature branch and open a PR with results, limitations, and the
  next proposed optimization. Do not merge automatically.

## Phase 2: Gated, evidence-driven maintenance improvements

Phase 1 implementation and verification evidence are in the linked evaluations.
The remaining unchecked measurement steps concern complete matched human timing,
not missing adapter functionality. The qualitative agent skill evaluation passed;
it does not substitute for the unmeasured human speedup target. Full-gate runtime
is unchanged, so Phase 2 should prioritize metadata/fixture separation and
selected feedback before additional graph features or broad parallelism.

After maintainer confirmation, write the detailed implementation tasks against
the then-current main in this order:

1. **Resolve metadata without behavior execution.** Extract a pure declaration
   interface from case contracts and profile allocation metadata. Preserve
   contract identity and certificate enforcement; fixture builders must not
   mint their own traceability claims. Prove equivalent resolved allocations
   and byte-identical output for unchanged cases before switching consumers.
2. **Offer selected feedback.** Add explicit case/boundary selection for local
   verification. Keep shared checks and the full merge gate. Test selection
   against the full suite on seeded dependency changes; uncertain selection
   falls back to the broad suite.
3. **Cache measured bottlenecks.** Key derived indexes by inventory, content,
   graph/parser version, refs, and dependency versions. Cache execution outputs
   only after including transitive dependencies, fixtures, toolchain, and
   configuration. A cache entry never substitutes for a required acceptance run.
4. **Parallelize only proven independent work.** First profile the serial
   current-case builder and tests. Use isolated processes/output shards where
   private registrations and certificate state require them; preserve stable
   output ordering. Shared metadata and snapshot packaging remain convergence
   points. Do not globally enable Vitest parallelism as an assumed speed fix.

Each optimization must show reduced time on the Task 1 workload, equivalent
outputs, and unchanged defensive assurance checks. If search accounts for
little of the elapsed time, prioritize selective feedback or expensive fixture
construction rather than extending the SARA graph.
