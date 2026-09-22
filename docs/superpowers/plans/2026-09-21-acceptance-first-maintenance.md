# Acceptance-first Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Test whether upfront acceptance review and batched repairs materially reduce complete maintenance workflow time at equal correctness.

**Architecture:** Use two Markdown records and existing repository tools. Establish a fair workload before dispatching implementation agents; do not build orchestration infrastructure.

**Tech Stack:** Git, Markdown, existing repository checks, isolated agent sessions.

**Spec:** [Acceptance-first experiment](../specs/2026-09-21-acceptance-first-maintenance.md).

## Global Constraints

- No protocol changes, new skill, datastore, or scheduler are needed.
- Preparation costs count: moving work earlier is not itself acceleration.
- An incomplete or failed arm establishes no equal-quality speedup.
- This procedure is opt-in experimental guidance, not a new mandatory repository-wide review layer.
- No rolling snapshot reconciliation, source-generator restructuring, security work outside local synthetic fixtures, or remote configuration change is authorized.

## Task 1: Procedure and workload readiness

**Files:** Create this plan and the linked design. Read the existing historical
evaluation, `scripts/maintenance-eval/contracts/aug28.json`, and bounded provenance
reports. Do not modify the historical scorer, contracts, or previous outcomes.

**Consumes:** Approved conversational workflow and existing archive evidence.
**Produces:** Reviewed procedure and an explicit eligible-workload or blocked verdict.

- [x] Write the acceptance and finding record fields, representative-case checkpoint,
  batch review, impact-aware re-review, and full final verification procedure.
- [x] Define equal-information/equal-correctness comparison and stop rules before timing.
- [x] Audit original request availability, initial commit, authority, external inputs,
  and independent final acceptance evidence using a bounded read-only Luna task.
- [x] Independently review the procedure and publish the readiness outcome.

## Task 2: One paired complete-task experiment — blocked on workload selection

**Files:** Task-specific acceptance, findings, timing, and test evidence in isolated
trial directories; publish aggregate results under `docs/superpowers/evaluations/`
only after an eligible workload is selected. Exact implementation paths must be
derived from that authorized task, not invented here.

**Consumes:** Complete authorized task, pinned initial inputs, independent acceptance
standard, and the Task 1 procedure.
**Produces:** Two preserved candidates, independent verdicts, full timing, and a
go/no-go result. This task is not executable while those inputs are missing.

- [ ] Pin the request, initial tree, normative sources, allowed edit scope, and
  evaluator criteria. Reject hindsight leakage or unresolved authority.
- [ ] Freeze identical model/concurrency/environment policy for both arms; record
  trial order and known isolation limits. Create fresh worker contexts/checkouts.
- [ ] Start each arm's clock before preparation; execute the complete baseline and
  treatment, keeping independent final evaluation and all verification on the clock.
- [ ] Preserve all attempts and score both candidates. Report unknown measurements
  explicitly and classify late requirements separately from new scope.
- [ ] Apply the design's 30% exploratory investment threshold. Do not expand the
  workflow when savings are incremental, quality differs, or evidence is incomplete.
- [ ] Publish measured outcomes, verify affected artifacts, and push the feature PR;
  never merge automatically.

## Readiness findings — 2026-09-21

The existing August 28 machine-readable contract explicitly has
`review_required: true`, says encrypted child briefs were not literally recovered,
and retains `external_snapshot_handoff: unresolved-user-decision`. Its round
intents are reconstructions from later reports. The existing evaluation also
identifies unresolved independent identity-oracle and external-source leakage
concerns. These are not suitable grounds for claiming that rounds 2–6 could have
been avoided from the original information.

Bounded audit receipt: on 2026-09-21, isolated Luna/medium agent
`acceptance_workload_audit` examined the historical evaluation and the preserved
reference-guard audit, then followed their links to the pilot/V2/V3/V4 records and
V4 contracts. It returned a read-only report to the coordinator; no tests or edits
were performed. Coordinator verification read the historical evaluation,
`scripts/maintenance-eval/contracts/aug28.json`, and the preserved Task 1 report
at branch input `a5028b62b419c1fc98d2d79d6f065fb87a9bbb95`. The findings above
are directly reproducible from the tracked contract and evaluation. No whole-archive
rescan or exhaustive claim that no suitable historical task exists is made.

The V4 three-reference task retains source-authority evidence but is too narrow
and refs-only for this hypothesis; failed past arms alone do not disqualify a task.
Luna/high agent `acceptance_procedure_review` independently reviewed these two
documents on the same date. Its batch identified unclear reviewer independence,
baseline rules, audit provenance, recordkeeping wording, and reconstruction
conditions; the procedure was amended in one batch. This document review is not
a maintenance-performance trial or proof that the workflow saves time.

No historical timed trial is launched on this evidence. This is a readiness
result, not evidence for or against the workflow's speed. The next safe input is
a complete upcoming maintenance task with an exact request captured before work
starts, or an explicitly approved reconstruction with the same complete brief in
both arms, after authority and external-input review are resolved. That is a new
complete-brief execution, not historical acceptance. It measures execution with known requirements, not discovery
of previously omitted requirements. The stopped packet/reference work remains
stopped; the original under-one-hour goal remains unmet.

## Verification record

The fresh tooling suite passed 154 tests with two optional SARA skips and no
failures. The first full-gate attempt passed 2,016 draft tests, 267 historical
vectors, and 178 independent tests, but exited 1: the coordinator edited the
tracked old-plan cross-link while the gate was running. Its unchanged-tree
guard correctly rejected that attempt. This is an orchestration error, not a
passing gate or a protocol regression. Freeze all tracked/index changes before
the required rerun; report its actual result separately in the PR handoff.
