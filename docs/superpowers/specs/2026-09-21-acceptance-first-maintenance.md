# Acceptance-first maintenance experiment

Status: procedure approved in conversation; measurement not yet performed.
This is a distinct experiment, not a restart of the stopped packet/reference
optimization. No protocol changes, new skill, datastore, or scheduler are needed.

## Hypothesis and limits

Reviewing acceptance criteria before implementation, validating one complete
example, and batching review findings may reduce repeated discovery and repair.
Preparation costs count: moving work earlier is not itself acceleration.
Neither fewer review rounds nor passing existing tests establishes equal quality.

The August 28 archive's rounds 2–6 suggest possible omissions, but the original
encrypted worker briefs were not recovered. Do not assume all later requirements
were knowable initially. Architecture experiments and reversals are not automatically
avoidable repair. See the [historical contract](../evaluations/sixty-minute-maintenance.md).

## Minimal records

Keep these two Markdown records with the task's evidence. No new runtime tooling
is required for recordkeeping. Pin the initial commit and exact authorized request before preparation.
Record scope exclusions, selected draft/snapshot lane, commands, and the identities
of the workers/reviewers. Never put raw private transcripts or credentials in Git.

Acceptance rows use these fields:

| Field | Required content |
| --- | --- |
| ID | Stable task-local identifier, such as A1 |
| Requirement | Observable behavior, not an implementation slogan |
| Authority | Pinned normative source and anchor; for tooling, authorized task requirement |
| Provenance | Initially supplied, derived from initially available authority, or later scope addition |
| Evidence | Execution path and assertions proving behavior; positive and negative cases where applicable |
| Ownership | Worker and affected paths; shared files have one integrator |
| Status | Unresolved, ready, implemented, or independently verified, with evidence location |

A requirement with no governing authority is unresolved, not permission to invent
protocol semantics. Explain any non-applicable positive/negative evidence. Tests
and expected results must not be derived solely from the implementation under test.
The specification family, registry, and schemas remain protocol authority. SARA
links and Semble discovery assist navigation; freshness does not prove completeness.

Findings rows use these fields:

| Field | Required content |
| --- | --- |
| ID and candidate | Stable finding ID and reviewed commit/tree digest |
| Requirement and severity | Acceptance ID or newly discovered governing requirement; correctness impact |
| Evidence | Specific source/test location and observed failure or missing proof |
| Classification | Initial omission, implementation defect, repair regression, or new scope |
| Closure | Required change, regression assertion, owner, and verified candidate |

Record timestamps at preparation start, checklist review, representative-case
review, each integrated candidate, each returned repair batch, and final acceptance.
Preserve failed attempts. Unknown token/tool counts remain unknown, never zero.

## Procedure

1. **Prepare acceptance rows.** Read the governing sources, identify affected
   boundaries and preservation constraints, and name the tests needed to prove
   them. Resolve consequential ambiguity before implementation. Timebox this
   preparation initially to ten minutes; exceeding the budget is a recorded cost,
   not grounds for dropping obligations.
2. **Challenge the checklist independently.** Assign a distinct reviewer in a fresh
   context, given the initial sources and checklist, not implementation output.
   Preserve reviewer identity, timestamp, and findings before coding. Ask: “What implementation could pass
   every listed check and still violate the authorized requirement?” Check parsing,
   authentication, authorization, verification, state effects, privacy, and bounded
   work where relevant. Record missing evidence and ambiguity in one response.
   Do not manufacture applicable requirements from generic security checklists.
3. **Build and review one end-to-end example.** A reviewer other than the implementer
   follows the real execution path and assertions before pattern replication.
   Record reviewer identity, timestamp, case-to-acceptance mapping, and verdict.
   This is a semantic checkpoint, not a
   demand for another full repository gate. A unique task can use its single case.
4. **Implement independent pieces.** Use Luna for bounded mechanical work and
   explicit tests; reserve stronger reasoning for unresolved semantics and
   integration. Give workers acceptance rows, source evidence, commands, and exact
   file ownership. Escalate uncertainty instead of silently guessing. All workers
   preserve each other's changes; the integrator owns shared edits.
5. **Review one pinned integrated candidate.** Assign complementary review scopes.
   Each reviewer returns all findings found in scope, coverage checked, and any
   unreviewed areas. Do not stop at the first ordinary defect; stop unsafe execution
   immediately. Deduplicate findings and send one actionable repair batch.
6. **Repair and re-review affected behavior.** Reuse finding IDs. Reopen evidence
   invalidated by the patch and inspect affected dependencies. Broaden review when
   impact is uncertain. New correctness findings must not be suppressed to meet a
   round budget. Scope additions are reported separately, not relabeled as failures.
7. **Verify the final candidate.** Run focused checks during development and the
   normal `scripts/conformance-ci.sh` on the integrated stable tree. Record actual
   process start/exit, exit codes, and logs. Subsequent code changes require reruns
   appropriate to their impact; final acceptance cannot cite stale evidence.

## Measurement protocol

Use a complete bounded authorized maintenance task, not selected easy cases. Both
arms receive the same request, source commit, permitted evidence, dependencies,
model assignments, concurrency limit, and final independent acceptance standard.
Treatment differs only in the acceptance-first/batched-review procedure. The
baseline is an explicit implementation-then-review control, not a claim to exactly
reproduce historical agent behavior. Freeze its protocol before launch: workers
receive the common request/sources, implement the complete task without a mandated
pre-implementation checklist review or representative-case checkpoint, then receive
independent integrated review. Both arms use the same reviewer scopes, full findings
batch, repair/re-review rules, final gate, and independent final assessment. Ordinary
worker planning is permitted and recorded, not artificially prohibited. Count a
repair batch as one consolidated set of findings returned on an integrated candidate
requiring a subsequent edit; track pre-implementation findings and representative-case
repairs separately and include all their time. This comparison isolates the added
upfront checkpoints within a shared batched-review workflow; it does not separately
measure batching's benefit. A different baseline requires a revised frozen protocol.
Use isolated fresh
agent contexts and checkouts; neither arm receives the other's checklist or output.
Record run order and environment/cache differences. A single pair is exploratory,
not proof of a general effect. Do not compare a small task directly to the complete
7h50m28s historical workload.

For a historical comparison, reconstruct initial information and reveal boundaries
without supplying later outcomes to only one arm. If all legitimate outcomes are
given upfront to both arms, label it a complete-brief reconstruction, not a causal
replay or evidence that agents would have discovered those requirements early.
Unavailable original intent, unresolved authority, or unreviewed external inputs
block a historical acceptance run. Cooperative filesystem restrictions do not
establish OS-sealed isolation; retain the historical evaluator's stricter limits.

Start each arm's clock before task-specific preparation, dependency setup, and
review. Include orchestration, repairs, all attempted verification, and independent
final assessment. Report experiment setup separately and also report total project
effort; do not hide costly setup behind a shorter execution clock. Report elapsed
wall time, cumulative agent time where available, measured tokens/cost where
available, number of repair batches, and late findings by classification/severity.
Repeated sampling or final assessment overhead must not be omitted selectively.

Before launching, freeze the acceptance standard and these decision rules:

- Both arms must independently satisfy every authorized requirement and final gate.
  An incomplete or failed arm establishes no equal-quality speedup.
- A first paired run is promising only if total treatment elapsed time is at least
  30% lower, with fewer repair batches and no outstanding correctness findings.
  This is an investment threshold, not a predicted effect or statistical claim.
- If preparation cancels repair savings, do not add infrastructure. Record the
  result and stop expansion. A failed feasibility check is not a performance result.
- Even a promising bounded pair does not establish the original under-60-minute
  goal. That needs complete-workload acceptance, including verification, below
  3,600 seconds. Replication is required before generalizing a bounded result.

## Scope and next action

No rolling snapshot reconciliation, source-generator restructuring, security work
outside local synthetic fixtures, or remote configuration change is authorized.
The [execution plan](../plans/2026-09-21-acceptance-first-maintenance.md) records
readiness and the smallest next action. This procedure is opt-in experimental
guidance, not a new mandatory repository-wide review layer.
