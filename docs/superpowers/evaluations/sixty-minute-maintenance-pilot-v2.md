# Second slice: pre-run predictable queries

Status: preparation in progress; **no second matched result yet**. The first
[pilot](sixty-minute-maintenance-pilot.md) remains a 204/204 worker-plus-reviewer
outer-call tie. No under-sixty-minute claim or Phase 2 rollout is justified.

The next timed dispatch is blocked by the collaboration host's thread limit:
fresh Luna worker creation was rejected. Reusing the preparation agent would
contaminate the baseline with treatment-specific source knowledge, so that agent
is not substituted as the baseline. A fresh-agent-capable session is required
to run this comparison fairly.

## Change under test

Prepare expected read/query results deterministically before dispatch. Give the
agent a small starting document and linked files containing:

- Existing validator, dependency-layering and cardinality behavior.
- Fixed catalog-builder and private execution-evidence preservation context.
- All declared case/reference groups, with missing anchors explicitly unresolved.
- A source-cited heading index for the six supplied specifications.
- Exact source identities, unknowns and explicit packet-budget expansion.

These are generated views, not a new source of protocol authority. An existing
anchor is not necessarily the governing requirement. The agent still audits
semantics and implements changes; deterministic code handles enumeration, grouping,
hashing and excerpt preparation. Post-edit verification is never precomputed.

The pinned [v2 recipe](../../../scripts/maintenance-eval/contracts/reference-pilot-v2.json)
selects sources from historical input
`8f780cea2119738e3db1a37e7c0c94b4cd200cb3`. It supplies no corrected case-to-anchor
map. Its test line ranges and catalog count are historical fixture facts, not
live repository defaults. Existing packet compilation is reused; no datastore,
scheduler, metadata interpreter or default agent route is added.

## Preparing files before dispatch

The bounded [preparer](../../../scripts/maintenance/prepare.mjs) wraps existing
graph and packet APIs. From the tooling checkout, with a clean supplied input
repository and an existing output parent directory:

```bash
node --input-type=module -e '
  import fs from "node:fs/promises";
  import {prepareContext} from "./scripts/maintenance/prepare.mjs";
  const recipe = JSON.parse(await fs.readFile(
    "scripts/maintenance-eval/contracts/reference-pilot-v2.json", "utf8"));
  console.log(await prepareContext({
    repo: process.argv[1], recipe, outputDirectory: process.argv[2]
  }));
' /absolute/path/to/historical-input /absolute/path/to/run/prepared-context
```

The output directory must not exist and must be outside the input repository.
The helper refuses a wrong pinned commit, dirty input and unsafe excerpts rather
than overwriting outputs or silently claiming freshness. Dependencies must already
be installed; installation and any indexing still count as job preparation.

Give the treatment agent the common task brief plus `START-HERE.md`. It links to
`packet.json`, `references.md`, `anchors.md`, `tests.md` and `manifest.json`, with
compiler-owned detailed context in `artifacts/`. File identities and combined
size estimates make explicit expansion visible. The files are input context,
not passing evidence after an edit. Do not tell the agent to run these same
queries again unless an input changed or the prepared result leaves a relevant gap.

## Preregistered comparison

Use fresh sequential arms with the same historical input, dependencies, common
intent, Luna/high worker and Sol/high independent reviewer. Both arms receive
the clearer preservation requirements and review-first verification policy.
Only the treatment receives generated excerpts, reference inventory and heading
index. Comparison with pilot 1 is descriptive: its brief and schedule differed.

Both arms must audit all 275 reference allocations, preserve non-reference
behavior and the fixed certified builder, reject invalid refs before **any**
output mutation, complete valid authoring, and preserve the frozen snapshot.
Scope remains the two existing author/catalog files and the same two optional
helper/test paths from pilot 1, each at most 65,536 bytes. No production test seam
may bypass provenance, complete-catalog or duplicate checks.

During implementation and repairs, use focused feedback. Review the committed
candidate semantically and for scope before running the unchanged full gate.
The evaluator also runs static preservation/reference checks and actual positive
authoring plus invalid-reference/no-mutation checks. A later code change
invalidates passing evidence and requires fresh verification. One final full
gate is the planned normal case, not a safety cap.

Start each arm's clock before cloning, dependency preparation and indexing;
stop only after the committed candidate, independent review, gate and evaluator
checks are complete. Count all worker, reviewer and coordinator operations,
including unsuccessful preparation, repairs and reporting. Report shared
preparation/development separately rather than silently dropping it or assigning
arbitrary per-arm elapsed savings. Keep outer calls, lexical operation candidates
and observed process runtimes separate. No dollar saving is inferred from
provider counters that reset or continue inconsistently.

This host uses cooperative read restrictions, not OS-enforced isolation. Even
a successful slice would not establish sealed full-workload acceptance.

## Preparation failure and recovery

On 2026-09-05 at 06:11:59 UTC, baseline preparation began. Clone and both locked
dependency installs succeeded. Semble's warm-up then emitted
`Error saving index: [Errno 28] No space left on device` despite returning exit
status zero. The preparation script's success status was therefore rejected
by the coordinator; the arm is **not ready** and no worker was dispatched.

A read-only capacity check showed the data volume at 100%, with about 120 MiB
available. Recorded clone/install/warm-up process wall times were 537 ms,
1,236 ms, 1,331 ms and 2,404 ms respectively. These are failed-preparation
components, not an accepted job runtime. The failed attempt remains recorded.
No unrelated files, prior candidate commits or retained evaluator evidence were
deleted to free space.

Without agent cleanup, available capacity subsequently rose to about 2.1 GiB.
Repeating the same Semble warm-up succeeded without the error in 2.19 seconds
(6.83 user, 0.59 system). This retry does not erase the failed preparation or
establish that the shared host's capacity will remain stable.

Capacity then fell again: creating even the preview packet's output directory
failed with `ENOSPC`. Development was paused safely with the preparer's test-first
implementation preserved but not yet GREEN-verified. A later read-only check
reported about 9.9 GiB free, allowing focused verification to resume. No agent
cleanup caused these changes; their external cause was not established.

Run the matched trial only while enough space is available for two isolated
dependency trees, search indexes, test outputs and evaluator copies. A practical
initial allowance is several GiB, then confirm actual preparation succeeds.
Do not count a retry as a fresh successful series while hiding this failure.

## Decision remains gated

If prepared results reduce total agent work at equal correctness, retain the
useful preparation steps and evaluate the smallest justified parallel/state
mechanism next. If not, change task decomposition or test deterministic bulk
edits; do not add a platform to compensate for an ineffective packet.
