# Verified repository maintenance in under sixty minutes

Status: proposed architecture and acceptance criteria. No under-sixty-minute
result has been demonstrated. This is a planning deliverable, not authorization
to restructure the generator or reconcile the live snapshot.

## 1. Outcome, not product adoption

Complete the full August 28 vector-maintenance workload, with equivalent
correctness and independent verification, in **less than 3,600 seconds**.
Optimize agent decisions, navigation, repeated context loading, and repair
cycles before optimizing individual search calls. SARA is optional.

This replaces the human-investigation and query-latency objectives in the
[SARA plan](../plans/2026-09-04-sara-spec-workflow.md). Its existing projection,
receipt and impact code are reusable infrastructure, not the success criterion.

The relevant Codex archive is session
`01a04813-8253-7573-a65f-0b00c8b8e7f0`, agent `/root/pr28_task8_vectors`:

| Observed August 28 measure | Baseline |
| --- | ---: |
| First task start to last completion | 10h47m12s |
| Sum of ten task intervals, including tool execution/waiting | 7h50m28s |
| Outer tool/orchestration calls | 1,882 |
| Parsed read/search-bearing shell commands | approximately 600 |
| Nested patch operations | 332 |
| Explicitly identified compactions (not all context records) | 16 |
| Explicit full-gate launches | at least 14 |

These are one worker's records, not the sum of all cooperating agents. Command
categories overlap. A yielded tool's 1–11-second wrapper duration is **not** the
underlying test-process runtime. No runtime attribution uses that shortcut.
The target needs roughly an eightfold reduction in recorded task-interval time;
merely removing the gaps between handoffs is insufficient.

## 2. Define the workload before claiming a speedup

The first implementation commit is `15a55698b7d1a3e4c5ce02cb79d8d2ee4b385c2b`;
its parent is `b6416fda157529b708c86f21cc4ea66a7b24384c`. The last worker commit
is `0dd150682903d14eddd8d14b57892395f750c47f`. These identify evidence, not yet
a ready-to-run benchmark: other agents changed the shared branch between this
worker's commits. Task 1 must distinguish their prerequisite inputs from this
worker's required outputs and seal a reproducible start tree.

The endpoint is this selected worker's ten-round deliverable at `0dd1506`, not
all work in the parent PR. Separate snapshot-worker commits `0efa4a9` and
`8f780ce` are external inputs, not output credited to this worker. Subsequent
snapshot regeneration requested at its handoff is outside this measured
workload. Report those exclusions beside any speedup claim.

The first actual worker checkout inspection confirms `b6416fda` as its HEAD;
the session metadata's `6f439250` describes a different starting context.
Some parent briefs are encrypted in the child archive. Reconstruct their intent
from observable task reports and outputs, marking provenance and uncertainty;
do not claim to have recovered their literal messages. The recovered rounds are:

| Round | Required outcome or decision |
| --- | --- |
| 1 | Six-family current catalog, schema-3 traceability, current-only imports, temporary author/verify, frozen snapshot preservation |
| 2 | Executable boundary evidence and exact rejection traces; no registry-derived semantic labels |
| 3 | Private identity-bound evidence, profile/reason/invariant closure, exact loader resolution, audited exclusions |
| 4 | Independent 31-row profile oracle, scope-aware loader analysis, byte-derived Assurance/KERI classification |
| 5 | Composition-only static audit, exact Core/Tier-3/Control/revocation semantics, complete CESR framing |
| 6 | Concealed-capability denial, module-owned Tier-3 authority, revocation verification through merge/effect |
| 7 | Investigate runtime isolation; wait for architecture direction before implementing it |
| 8 | Approved bounded child-runtime experiment, with exact graph/assets and same-process semantic closure |
| 9 | Withdraw runtime isolation; restore direct authoring and retain composition-only graph audit |
| 10 | Resolve 44 stale/mismatched refs to 27 live anchors; reject invalid refs before authoring mutation |

Rounds 2–6 principally repair missed requirements. Rounds 7–9 include genuine
architecture changes, including a rollback; round 10 follows an external
snapshot-task handoff. The final-state reconstruction must not require both the
withdrawn runtime and its absence. Causal replay must exercise the experiment,
decision and rollback without pretending those steps were foreseeable.

Create two separately labeled fixtures:

1. **Complete-brief reconstruction:** same final workload, all legitimate
   requested outcomes supplied upfront, without the historical solution patch,
   implementation instructions from later fixes, or scorer-only tests. Both
   baseline and optimized agents receive exactly the same brief and start tree.
   This is the primary operational under-sixty-minute target.
2. **Causal replay:** later scope additions and external changes are delivered
   at their recorded dependency/decision boundaries. Do not reveal future
   corrections early. Measure it independently; success on reconstruction must
   not be advertised as success on the original evolving conversation. Compress
   historical human idle gaps only explicitly, never silently.

Causal replay uses scripted maintainer decisions delivered at the recorded
decision boundary, identically for every arm. It measures agent execution under
that decision schedule, not the original human-response latency. If real human
approval is required instead, keep its elapsed time in all arms and label it.

The acceptance contract must include all ten rounds, not just the first
44-minute task. It must account for the final temporary current-draft corpus,
boundary execution, certificate identity, valid specification references,
negative conformance, and preservation of the independently pinned snapshot.
Historical counts such as 275 temporary current vectors and 482 frozen vectors
belong to this fixture, not the current main's 267-vector snapshot.
The latter count is pinned here to reviewed main
`adda8b522f9cb558b31cb27ac0f7e4f1150d5fac`, not a permanent repository property.

An evaluator maintains the oracle outside worker-visible Git history. A clone
must not expose later solution commits through refs, reflogs, object storage,
research notes, or shared alternate object directories. Publish only redacted
aggregate transcript statistics and task intent; never publish raw sessions,
hidden reasoning, credentials, or private messages.
Test object isolation, not just visible branch names: later commit reads must
fail, alternates must be absent, and allowed history/tree/lockfile/index/cache
digests must match the fixture manifest. A linked worktree of the full evidence
repository does not provide this isolation.
Apply that boundary to every evaluated actor, including its coordinator: limit
filesystem reads to permitted inputs and keep evaluator storage inaccessible.
Do not allow unrestricted network/Git fetches that recover public future
solutions; a trusted preparer supplies locked dependencies. If the current host
cannot enforce the boundary, use an isolated evaluation runner or label the
exercise an unsealed exploratory pilot, not an acceptance replay.
This is evaluation/worker isolation outside the protocol generator, not a
reintroduction of the authoring-runtime architecture withdrawn in round 9.

## 3. What the clock measures

Start when the prepared workflow receives the job, its input tree, and its
authorized brief. Include per-job worktree creation, dependency preparation,
indexing, all model calls/retries, local tests, review, repair, final full
verification, evidence assembly, and the resulting commit. Do not pause the
clock for a failed attempt, compaction, model escalation, or additional checks.

Preinstalled workflow software, model access, and a provisioned machine are
explicit environmental prerequisites; building this workflow is not part of a
production job. Dependency-cache state and any preexisting repository index are
recorded, and the primary replay starts without a task-specific graph or answer
cache. Report installation cost and amortized warm-run performance separately.

The required result is a correct, reviewed, locally verified commit. Authorized
PR submission is recorded separately, including its latency; remote CI queue
time is not called local workflow time. Never merge automatically. A run with
open required findings or missing verification is a failure, even at 59 minutes.

Provisional operating budget, to be validated rather than assumed:

| Minutes | Critical-path work |
| --- | --- |
| 0–5 | Snapshot inputs, prepare dependencies, profile readiness, initialize state |
| 5–10 | Resolve acceptance requirements, assemble edit packets, assign ownership |
| 10–30 | Up to three independent workers implement and run focused checks |
| 30–40 | Integrate, independent review, one planned consolidated repair wave |
| 40–55 | Full required gate and evaluator checks on the integrated immutable tree |
| 55–59 | Check evidence completeness, commit, report result and remaining limitations |

If profiling shows the mandatory gate cannot fit its 15-minute reserve, that
is an explicit feasibility problem. Optimize its measured dependencies or
provision documented resources; never omit it to hit the deadline. Additional
repair/check waves remain permitted for correctness, but count against the SLA.

## 4. Recommended architecture: deterministic control, bounded agent work

```text
Job + immutable inputs
          |
Acceptance contract + focused context + ownership DAG
          |
     Leased parallel workers -- proposals and artifacts --+
          ^                                               |
          +---- SQLite state / validated event reducer ----+
                                  |
                      Integration + independent review
                                  |
                         Full gate -> verified commit
```

The central datastore is the source of truth for **workflow state**, not for
protocol requirements. The specs, registry, and schemas remain authoritative.
Agents propose changes and findings. Deterministic code owns scheduling,
invalidation, status transitions, integration eligibility, and proof freshness.

### 4.1 Central state

Use a per-run SQLite database outside worker-writable source trees, with a
single writer service, transactions, and an append-only event table. Workers
submit structured requests through a local CLI/host bridge; they do not edit
the database or write free-form status files. SQLite's writer serialization and
reader isolation suit a local coordinator with parallel workers; this is not a
distributed database proposal. [SQLite isolation](https://www.sqlite.org/isolation.html).

Store `runs`, `requirements`, `tasks`, `task_dependencies`, `file_leases`,
`artifacts`, `findings`, `checks`, and `events`. Every record belongs to a run.
Record input commit/tree/content digests, contract version, tool/model versions,
task attempt/generation, ownership, and evidence identifiers. Store large
outputs as content-addressed artifacts; keep compact references in task state.

Task states are `planned -> ready -> leased -> submitted -> checked -> integrated`.
A dependency/input change invalidates affected evidence and returns its tasks
to `ready`; failures remain explicit. Only the trusted check runner can create
passing check records. Only the reducer can advance state after validating
preconditions. An agent saying "done" is not a completion event.

Submission requires the current lease generation, expected state revision,
input digest, allowed changed paths, and patch digest. Reject stale submissions,
unauthorized paths, duplicate/conflicting events, and dependency cycles. Retried
identical event IDs return the original result; conflicting payloads fail.
After a crash, restore the DAG and artifacts, not the entire conversation.
Reconcile an uncertain process completion before retrying a side effect.

Leases are scheduling controls, not filesystem security boundaries. Use isolated
worker write roots when available and always validate patches at integration.
An arbitrary worker shell must not have write access to trusted state or the
evaluator oracle. Invalid or untrusted evidence never becomes a protocol claim.

### 4.2 Context compiler: return what enables an edit

Build one cached input inventory, then compile each task's packet into:

- `mustRead`: exact normative excerpts, affected symbols, interfaces and tests;
- `mayNeed`: symbol references and dependency summaries available on demand;
- `unresolved`: relevant unknowns requiring discovery or broader checking;
- `deferred`: background relationships with counts and retrieval handles.

Version-1 packet JSON uses camelCase field names, including `taskId`,
`inputDigest` and `deliveredChunkIds`; SQLite table names may use snake_case.

Initially target at most 8,000 tokens per worker packet; expansion is explicit,
logged, and allowed when correctness needs it. A list of 96 related files is
not an edit packet. Preserve all relevant unknowns even when the packet grows.

Reuse `buildGraph`, `queryPacket`, `compareProjections`, and `buildWorklist` in
the existing adapter. Add exact TypeScript symbol spans using the already
locked compiler API or evaluate Serena. Use Semble for intent discovery and
unresolved links; use direct symbol/excerpt access afterward. Version-qualified
refs and history/draft evidence must remain distinct.

Cache excerpts by content digest and symbol/anchor identity, not path alone.
Track already delivered chunks per worker. On resume, deliver a compact task
state plus changed chunks and open findings. Changed inputs invalidate stale
chunks. If the historical start tree lacks the new contract catalog, bootstrap
from existing prose/code and explicit proposed allocations; never smuggle the
final solution's metadata into the benchmark input.

### 4.3 Work partition and integration

Start with the available ceiling of four active agents: a coordinator and at
most three workers. Reuse a freed worker slot for independent review. Measure
higher concurrency only in a separately recorded environment.

Partition by dependency/ownership conflicts, not vector IDs. Each worker gets
an immutable base, exact allowed files, acceptance requirements, and bounded
focused checks. Shared catalog, registry-facing, certificate, and integration
files have one owner. Where many tasks need the same catalog, workers submit
validated per-task fragments and one integrator applies the batch; these are
temporary proposals, not a new permanent metadata map.
An incomplete repository-wide graph need not force unrelated file owners to
work serially: the coordinator can establish a cited, task-local ownership DAG.
Unresolved relevant ownership edges remain barriers; unrelated unresolved edges
stay visible. This does not make a partial graph sufficient for narrow final
verification.

Integrate verified patch units, not hundreds of conversational micro-edits.
Validate preimage hashes and inspect diffs; do not use blind whole-file rewrites.
Independent review starts from a stable patch/contract snapshot and accumulates
all findings for one correction wave, rather than repeatedly reviewing mutable
files. Do not cap genuine findings or suppress additional required repairs.

### 4.4 Model routing

Use no model for parsing, graph joins, hashing, scheduling, status transitions,
evidence validation, or report formatting. Use a fast agent for bounded symbol
lookup, repetitive implementation, and locally testable changes. Use a capable
agent for ambiguous requirements, architecture, security boundaries, integration
decisions, and independent review.

Luna is an available fast-worker candidate. A mini model is a candidate, not an
assumed runtime capability: for example, OpenAI documents GPT-5.4 Mini for
coding/subagent use, but access through this host must be checked separately.
[Mini model documentation](https://developers.openai.com/api/docs/models/gpt-5.4-mini).
Host role/model configuration is distinct from model availability.
[Codex subagent configuration](https://learn.chatgpt.com/docs/agent-configuration/subagents).

Record exact provider/model ID, reasoning effort, concurrency, latency, tokens,
cost when available, and attempts for every task. Initially use Luna medium for
bounded work and the configured capable profile for coordinator/reviewer.
Escalate one task on an unresolved trust-boundary decision, failed contract
interpretation, or a second failed focused repair; transfer its packet/evidence,
not its entire chat. Compare time to **accepted output**, including repair cost,
not tokens/second. No automatic paid provider or model switch without configured
authority and a run-level spend cap.

### 4.5 Verification pipeline

Compile an acceptance matrix before editing: requirement, source citation,
owner, positive/negative check, and evidence needed. A requirement with no proof
blocks completion. Resolve contracts independently of fixture execution when
profiling and equivalence tests justify that extraction; do not mint certificates
from fixture-authored assertions or weaken private boundary registrations.

Run cheap structural checks and selected tests while workers operate in isolated
outputs. Dynamic/unresolved dependencies require conservative broader checks.
Cache only intermediate feedback with full input/toolchain/configuration keys.
Measure actual process start/exit and resource usage, not poll/yield durations.

After integration/review, run the unmodified required
`scripts/conformance-ci.sh` on the resulting tree: current-draft lane, pinned
snapshot lane, then independent conformance. Also run the sealed evaluator's
acceptance checks. One successful final full gate is the normal budget, not a
prohibition on rerunning after a relevant change. A cached result never replaces
the required gate. No blanket Vitest parallelism, live-system access, or snapshot
regeneration is introduced by this workflow.

The evaluator and its expected results remain outside worker control. Review
changes to repository tests and verifier code explicitly; a worker-modified
test suite cannot certify itself. Bind independent checks to the same final
tree and reject evidence from a different tree, contract or toolchain.

## 5. Tools to compare, not tools to mandate

| Approach | Role and decision |
| --- | --- |
| Custom Node + SQLite controller, existing host agents | Recommended first: directly enforces this repository's state and ownership rules without a new agent platform |
| Semble + current trace adapter; SARA optional | Reuse intent search, requirement relationships and receipts; keep SARA only if it improves whole-task steps/correctness |
| Serena or direct TypeScript symbol queries | Test reduction in code reads/reference discovery; prose still needs anchor-aware parsing. [Symbol tools](https://oraios.github.io/serena/01-about/035_tools.html) |
| Inspect AI / Inspect SWE | Candidate replay/scoring harness for existing coding agents, limits and logs; reuse instead of building a general evaluation product. [Agent integration](https://inspect.aisi.org.uk/agents.html), [logs](https://inspect.aisi.org.uk/eval-logs.html) |
| LangGraph with persistent checkpoints | Alternative if host-resume/interrupt requirements exceed the small controller; not a prerequisite. Checkpoints persist execution state, not validated repository truth. [Persistence](https://docs.langchain.com/oss/python/langgraph/persistence) |

The alternative of only changing prompts/models is cheaper but cannot enforce
freshness, leases or evidence transitions. A full agent framework provides more
orchestration but adds integration and maintenance cost. Select via matched task
results. Do not add several retrieval backends or another hand-maintained map
without an observed benefit.

## 6. Acceptance and honest measurement

Count model decision turns, outer calls and nested tool actions separately,
across the entire team. Also count shell processes, delivered source chunks,
bytes/tokens, repeated unchanged chunks, patch units, repair waves, process wait
time, and compactions. A wrapper around 100 operations is not reported as one
operation. Deterministic bulk processing is measured separately from agent work.

Complete-brief diagnostic budgets: at most 150 outer agent/tool calls, 60 agent-requested
read/search operations, 40 patch units, and one planned review/repair wave.
These are hypotheses, not correctness gates or permission to hide necessary
work. Missing a budget triggers a recorded replan/escalation; missing 3,600
seconds fails the performance criterion while preserving all unfinished work.
The one-wave budget and the provisional stage schedule apply to complete-brief
reconstruction. Causal replay permits every revealed repair/decision wave and
reports its own critical path; it cannot suppress a round to fit that schedule.

Compare A: existing workflow; B: deterministic pipeline with the same model
allocation; C: B with fast-worker routing; D: the best prior arm with each
optional retrieval backend added separately. Use the same sealed brief, input,
resources, and scorer for comparable arms. Include a capped baseline result
rather than requiring repeated eight-hour baseline runs. A timed-out baseline
is censored, not an invented speedup factor.

Acceptance requires five independent complete-brief runs, all correct and all
under 3,600 seconds, plus two different held-out maintenance tasks passing their
correctness checks. Record every attempt; no cherry-picked restarts. This small
sample is a repeatability check, not a population p95 guarantee. Report causal
replay separately, and do not claim exact historical-session acceleration until
that track also passes. Public reports must disclose remaining uncertainty.

## 7. Feasibility gates

1. Seal the benchmark and profile the critical path before changing architecture.
2. Demonstrate fewer steps on one representative subtask before building a
   full controller or adding a retrieval backend.
3. Demonstrate a complete integrated pilot; if it exceeds 90 minutes, inspect
   the trace and change the dominant mechanism before adding more features.
4. Validate the under-sixty-minute repetitions and safety checks before claiming
   success or routing ordinary repository work through the workflow by default.

The [implementation plan](../plans/2026-09-04-sixty-minute-maintenance.md)
breaks this into independently testable deliverables. Tool deployment alone
cannot complete this project.
