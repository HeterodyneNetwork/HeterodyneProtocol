# Phase 1 matched-slice experiment

## Decision

The first packet design has **not demonstrated a reduction in total workflow
steps at equal correctness**. The under-sixty-minute goal remains unmet.
Tasks 3–7 are not implemented: adding durable state, scheduling, or default
agent routing is gated on a better representative result.

This is an exploratory, cooperative-host experiment, not a sealed replay or a
full August 28 workload result. It measures a historical reference-maintenance
slice; it does not update today's protocol or frozen vectors.
Candidate commits and raw evidence remain in local evaluator-owned pilot
repositories; their IDs below are provenance identifiers, not public GitHub
commit links or a portable, independently reproducible benchmark bundle.

## Frozen inputs and treatment

Both arms started from `8f780cea2119738e3db1a37e7c0c94b4cd200cb3`, the
legitimate pre-round-10 input, in separate repositories with matching locked
dependencies. The input object store excluded the later solution commit and
had no alternates. Both workers used Luna with high reasoning effort, the same
written intent, available Semble/current trace CLI, allowed paths, and
independent Sol reviews. Workers could not inspect the other arm or scorer by
instruction; the host did not enforce that boundary at OS level.

The task was to audit all 275 current reference allocations against their
governing specification sections and reject invalid references before
authoring mutates output. It was not merely to reproduce the historical
endpoint's 44 replacements. Independent review identified another 19
wrong-but-existing umbrella references; both arms received the same corrective
source-backed feedback. Anchor existence alone was never the semantic oracle.

Only the packet arm received a compiled bootstrap packet, frozen at compiler
`7ddbe54`: document conventions, `authorAllVectors`, and
`currentCaseContract`. It contained three source chunks, 9,068 estimated
tokens, an explicit 1,068-token expansion, and 107 unresolved relationships.
It was correctly labeled incomplete. Graph construction, compilation and
sidecar creation took 1,120 ms; that is not total preparation time.

The input intent digest was
`b4b6c044dd247fdfea9ada69e33cff422b2b28f65d72d8f612777f3591b08a71`;
packet task configuration digest
`36950aae790ee8ea058dbbcf52d7ba4362719bc857b6b24ba5ddbc858a8b64d6`;
delivered context digest
`8920cede5cfb357a0db6ad92cefa168edf72d17b5ba7531c12fbc8b87ec7d98f`.

## What the experiment exposed

Neither initial candidate was accepted. Reviews and repairs had to resolve
incorrect governing references, valid cross-family dependencies, validation
before any output mutation, and preservation of the fixed certified catalog
builder. Test injection callbacks introduced into the production authoring API
required removal; tests can mock the module without widening that API.

The packet omitted existing family-metadata/cardinality validation and the
fixed builder's private-evidence and complete-catalog guarantees. Its selected
entry points were useful navigation, but did not constitute an edit-ready
preservation contract. Review also required correction: an initial baseline
acceptance missed the umbrella references and was explicitly revoked. Every
attempt and correction remains part of the experiment, not discarded setup.

The two-arm experiment reached the 90-minute diagnostic checkpoint while
closing verification/review. Workers were implemented sequentially, with
reviews overlapping the other arm and some repairs queued. Consequently that
elapsed interval is not a clean head-to-head speed ratio or either arm's pure
active runtime. It does establish that this run is not sub-hour acceptance.

## Accounting limits

All candidate attempts and reviewer corrections are included below. These are
worker/reviewer subtotals, **not complete workflow totals**:

| Measure | Baseline | Packet-assisted |
| --- | ---: | ---: |
| Candidate attempts, including repairs | 4 | 3 |
| Worker observed outer calls | 138 | 132 |
| Reviewer observed outer calls | 66 | 72 |
| Worker + reviewer outer calls | **204** | **204** |
| Literal shell read/search-bearing candidates, worker + reviewer | 100 | 104 |
| Separate Semble call candidates, worker + reviewer | 8 | 4 |
| Worker provider-reported task duration, ms | 2,141,115 | 1,814,203 |
| Reviewer provider-reported task duration, ms | 1,126,711 | 1,280,201 |
| Final full-gate process wall time, seconds | 139.02 | 135.98 |

The packet saved six worker outer calls but added six reviewer calls. Even
before coordinator costs, this is no outer-call reduction. The shell-only
read/search classifier does not establish fewer reads either. Four failed
baseline-review trace commands used a script path absent from the historical
tree; that asymmetry is disclosed and must not be credited as packet benefit.

Full gates ran on all four baseline candidates (145.28, 142.57, 141.58,
139.02 seconds) and all three packet candidates (144.41, 143.98, 135.98
seconds). Those seven gates consumed 992.82 seconds of aggregate process wall
time, already included within worker task intervals, not an additional amount
to add to them. The next trial should schedule focused checks during repair
and one required unchanged full gate on the reviewed final candidate, while
retaining a fresh gate whenever a subsequent code change invalidates it.

The former final baseline candidate was
`573811230060f0e63d1181701a3beaf44b173295`. It was reported to pass independent review,
all 275 static reference checks (63 changed allocations), and the actual
authoring/no-mutation probe. Its final gate passed 1,178 generator and 176
independent tests; the different generator test counts reflect the arms' own
allowed helper tests, not different verification policies. Baseline acceptance
was recorded at 2026-09-05 04:03:21 UTC; packet acceptance at 04:00:17 UTC.
The baseline dispatch clock was 02:29:23 UTC, making the paired experiment
93 minutes 58 seconds from that dispatch to both accepted candidates, excluding
earlier preparation. Sequential arm/repair queues make this diagnostic rather
than a per-arm speed comparison.

The former final packet candidate was `7d6e988a541cc2ed8be5e9bd7930a3c8c5b82447`.
It was reported to pass independent governing-reference/scope review, all 275 static
reference checks (63 changed allocations), and a successful authoring control
followed by invalid-reference rejection with byte-identical seeded output.
Its unchanged full gate was reported to pass 1,177 generator and 176 independent conformance
tests in 135.98 seconds. That is the final gate, not the whole job.

Packet worker effort across its initial attempt and two repairs was 1,814,203
provider-reported milliseconds, 132 observed outer calls, and 47 read/search-
bearing literal shell commands. Its reviewer contributed another 72 outer
calls and 57 read/search-bearing literal commands across initial review,
correction, and scoped re-reviews. Worker and reviewer therefore used 204
observed outer calls before coordinator/preparation/evaluation operations.
There were also four worker Semble call candidates. These categories must not
be added together as if they measured the same thing.

Observed outer tool calls are counted from public archive events. Lexical tool
and literal-shell command candidates are separate metrics, not executed
process counts. Read/search categories overlap and do not cover every possible
read. Repeated exact shell commands do not measure all repeated source bytes.
Preparation, coordinator evaluation, review, retries and gate time must remain
visible; worker-only numbers cannot establish a whole-workflow improvement.
Coordinator operations have not been completely allocated by arm. Recorded
setup components were clone 423/366 ms, generator dependency install
2,111/1,676 ms, independent dependency install 1,450/1,446 ms, and identical
Semble warm-up 1,674/1,651 ms (baseline/packet). Normal full gates repeated their
own installs. Final evaluator static/probe runs took 21,012/21,256 ms, followed
by exact reviewed-digest approval checks. Earlier probes, review packaging,
clarifications, scheduling and report preparation are additional overhead,
not zero-cost exclusions from a claimed win. No whole-workflow total-step
reduction is claimed in the absence of that complete allocation.

Provider token counters sometimes continue and sometimes reset across resumed
turns. Their per-turn snapshots are not safely additive, so no verified dollar
or token-bill saving is claimed. Luna performed all historical candidate coding
and repairs; higher-tier review and tooling repairs are real costs, not free
work excluded from the goal.

## Adjudication correction

The historical 204/204 worker-plus-reviewer outer-call counts remain observed
metrics, but the first pilot's all-275 semantic acceptance is withdrawn. The
same preserved `core/org-member-add-unauthorized` behavior lacks an exact
governing live-spec rule, so passing structural checks, authoring probes, or a
full gate cannot establish equal correctness for that case. The candidate
repositories and raw evidence are no longer available for a byte-for-byte
rerun. This correction does not claim a re-review of all 275 allocations. The
normative authority evidence is the [pinned Core threshold passage](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L322-L334);
the frozen, non-normative [vector-envelope schema `spec_refs` rule](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/vectors/schema/vector.schema.json#L111-L118)
records benchmark reference shape only and is not protocol authority.

## Next bounded experiment, before Task 3

The approved [second experiment](sixty-minute-maintenance-pilot-v2.md) pre-runs
predictable source queries into files. Its preparation encountered host disk
exhaustion; the failure and retry are recorded, with no second matched result yet.

Revise packet selection to include the existing family-metadata validator,
its layering/cardinality tests, the fixed `buildCurrentVectors` certification
contract, and source-cited governing-reference groups. Distinguish structural
checks from mandatory semantic review, and explicitly forbid production test
seams that bypass existing provenance. Freeze this revised contract before
dispatch, then repeat a matched slice with complete coordinator/reviewer
accounting and identical verification policy.

Do not introduce a new semantic truth table, execute arbitrary metadata
helpers, relax correctness, or build a workflow platform to compensate for an
incomplete packet. The specification family remains protocol authority; any
future datastore records workflow state only.
