# Second slice: pre-run predictable queries

Status: former treatment approval is **withdrawn** after independent source-
authority adjudication. The treatment reached its former approval point in
**40 minutes 16 seconds**, but that interval is not time to a correct accepted
output: `core/org-member-add-unauthorized` remains an authority gap. The
baseline and treatment therefore do not form an equal-correctness comparison.
No complete-workload under-sixty-minute claim or Phase 2 rollout is justified.

The ephemeral candidate repositories are absent and the exact treatment mapping
was recovered from visible archived tool output; a byte-for-byte candidate
rerun is unavailable. Original tests, counters, candidate identifiers and
timings remain historical observations only.

The earlier pre-run dispatch block from the collaboration host's thread limit
is preserved as historical context: fresh Luna worker creation was rejected.
Reusing the preparation agent would contaminate the baseline with
treatment-specific source knowledge, so that agent was not substituted as the
baseline. A fresh-agent-capable session was required and was subsequently used
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
  const result = await prepareContext({
    repo: process.argv[1], recipe, outputDirectory: process.argv[2]
  });
  console.log(result.outputDirectory);
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

## Concrete preparation evidence

The default, real graph/compiler path at final implementation commit `61a167b`
prepared the pinned historical input in **832 ms**. This is preparation on an
existing dependency-ready checkout, not a complete job or a speedup comparison.
It emitted nine source chunks and retained 107 unresolved records; the packet
remains explicitly incomplete. The inventory retains all 275 declarations,
including 44 allocations pointing at missing anchors. Existing anchors still
require governing-semantic review.

The corrected manifest distinguishes these measurements:

| Byte universe | Bytes | Approximate tokens |
| --- | ---: | ---: |
| Generated root reading files, including manifest | 251,271 | 62,818 |
| Optional graph-context sidecar | 208,858 | 52,215 |
| Available original source inputs, not copied or preloaded | 4,458,482 | 1,114,621 |

These estimates use UTF-8 bytes divided by four, rounded up; they are not billed
tokens. The compiler separately estimates its compact packet fields at 11,691
tokens. Reading every generated root file is substantially above the initial
8,000-token target; that expansion is explicit. The trial must measure what
agents actually load, including later expansion, rather than treating all
available context as either free or already consumed.

An initial manifest incorrectly presented full source availability as delivered
context size and omitted generated-file identities. Independent review caught
that error. The repair separates categories, hashes every non-manifest generated
file, labels section versus full-source hashes, and budgets the manifest's own
serialized bytes without a recursive self-hash. Parent verification independently
checked all six non-manifest output hashes/sizes, the exact root-file set, and
the root/optional byte totals on the real prepared directory.

Fresh combined maintenance/evaluator/trace verification after the repair:
`node --test scripts/maintenance/*.test.mjs scripts/maintenance-eval/*.test.mjs scripts/vector-trace*.test.mjs`
passed 154 tests with two optional SARA skips and zero failures in 22,796.683 ms.
This verifies tooling behavior, not completion of a maintenance task. Protocol,
generator, dependency, snapshot and independent-conformance sources are unchanged
by this continuation.

The final scoped review passed after removing caller-selectable graph/compiler
test callbacks; the public entry point always uses the fixed implementations.
The regression now exercises a real temporary Git fixture and the real graph/
packet dependencies. Earlier valid default-path preparation took 799 ms; the
832 ms rerun verifies the repaired entry point, not a claimed timing trend.

The unchanged full gate also passed on this implementation:

```text
/usr/bin/caffeinate -i -t 1200 /usr/bin/time -p scripts/conformance-ci.sh
86 current-draft files / 2,016 tests passed; document-family check passed
267 history-bound snapshot vectors verified
19 independent-conformance files / 178 tests passed
real 560.32; user 609.78; sys 18.06 seconds
```

Snapshot source was `c72f5ccdf855069550511d8e3e837dae55ed299c`, history-bound
to snapshot commit `80da4ded273ac746b9c56bc53a8f1c067835ad64`. Temporary historical
authoring is the existing snapshot-check procedure, not reconciliation of the
repository snapshot. Tracked/index state stayed unchanged throughout the gate;
only reporting prose was finalized afterward. The process-scoped sleep inhibitor
does not change persistent power settings. Locked installs reported the existing
five generator dependency audit findings (one low, four high) and one high
independent-package finding; dependencies were not changed in this task.

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

## Second matched trial result (former approval, now withdrawn)

The sequential cooperative-host trial ran on September 5 with fresh Luna/high
workers and fresh Sol/high reviewers. The common brief and verification policy
were frozen before dispatch. The treatment's only additional input was the
deterministically generated `START-HERE.md` set. This remains exploratory: the
host did not enforce read isolation, and earlier preparation failures remain
part of the record.

The baseline did not reach accepted correctness. Its first candidate and two
repair commits were `b1ab0bb`, `bbe9c4c`, and `39a6a6c`. Review found 19
semantic allocation errors, missing pre-mutation coverage, duplicate-anchor
handling, and a repair-introduced production test seam. Repairs corrected 18
allocations and the implementation/test defects, but the preserved
`core/org-member-add-unauthorized` behavior has no exact governing rule in the
six live specifications within the frozen edit scope. No catalog-only change
could supply missing normative authority. The baseline therefore stopped at
spec/quality FAIL before the full gate and evaluator, rather than fabricating a
reference. Its original 06:11:59 UTC preparation start, ENOSPC failure, later
retry, session suspension, and all repair work remain counted; it cannot support
an under-hour claim.

The treatment reached its former approval point at `929e478`. Its initial worker
used all six generated root files, summarized the optional 208,858-byte sidecar,
opened four full specifications, and left Control and Social full sources on
demand. Independent review opened the generated reference/anchor indexes and all
six normative specifications. The initial candidate still had a fail-open
version regex and 19 wrong-but-existing allocations; the worker reported both
fixed in one repair round, but later authority adjudication found that the
organization-member semantic gap persisted.
Scoped review was reported to pass with no Critical or Important findings;
that former approval is withdrawn by the adjudication below.

Coordinator evaluator evidence on the then-immutable candidate reported 275 cases,
275 references, 123 reference changes, four allowed changed paths, no findings,
approved helper hashes, successful real authoring, and synthetic missing-anchor
rejection with the complete seeded output manifest unchanged. The unchanged
ordered gate was reported to pass:

```text
/usr/bin/caffeinate -i -t 1200 /usr/bin/time -p scripts/conformance-ci.sh
64 current-draft files / 1,179 tests passed; document-family check passed
275 history-bound snapshot vectors verified
19 independent-conformance files / 176 tests passed
real 138.41; user 353.81; sys 17.77 seconds
```

Successful treatment preparation began at 20:47:12 UTC and former approval evidence ended
at 21:27:28 UTC: 40 minutes 16 seconds. Immediately preceding it, two controller
commands failed before cloning (nonexistent working directory and a wrong macOS
`date` path), and the first clone command then used relative package prefixes
from the wrong directory; clone succeeded but that install invocation failed.
Those coordination failures are retained in team totals rather than hidden.

Observed agent operations were lower for the treatment. The original comparison
was not an equal-correctness result because the baseline was unaccepted while
the treatment received former approval; reassessment finds neither arm
semantically accepted for the preserved organization-member case:

| Arm | Worker operations | Reviewer operations | Outcome |
| --- | --- | --- | --- |
| Baseline | about 122 tool calls; about 89 shell invocations; 275 trace queries plus reported reads; 3 commits and 2 repair rounds | 45 tool calls; about 36 shell executions; initial review plus 2 scoped re-reviews | Not accepted: one normative-authority gap |
| Prepared context | 73 tool calls; 64 shell commands; 35 read/search batches; 10 patches; 2 commits and 1 repair round | 44 tool calls; 38 shell invocations; 38 read/hash batches; initial review, scoped re-review, final hash approval | Former approval withdrawn: authority gap |

The treatment used 117 worker-plus-reviewer tool calls versus about 167 for the
baseline, but that is not a fewer-steps/equal-correctness result. Counts are
agent-reported operational counters; shell/read classifiers differ slightly by
report and are not process, token, or billing counters. Controller preparation,
dispatch, waits, packaging retries, evaluator, gate, reporting, the earlier
failed preparation series, and preparer development/review are additional team
work. The treatment interval contained 35 reconstructed controller tool calls
from successful preparation through the gate, plus the three preparation-command
failures described above. The baseline's long suspension makes elapsed comparison
descriptive only.

The correct decision is to keep Tasks 3–7 gated. Prepared context is useful and
the former treatment approval was under an hour, but the matched pair did not
demonstrate fewer steps at equal correctness, and neither arm is the complete
August 28 workload. The next bounded work is a fail-fast source-authority
feasibility preflight before any edit dispatch; it must not invent a reference.

## Adjudication correction

The recovered treatment mapping changed this case from
`heterodyne:0.6.0#core-conformance` to
`heterodyne:0.6.0#core-threshold-authority`. The latter permits threshold
custody and higher-layer policy but does not entail the tested combination of
member-KEL authorization and organization-admin-threshold authorization. The
reason-code registry's `org_member_add_unauthorized` entry is vocabulary, not a
substitute for a governing family-document anchor; the frozen schema permits a
family-document `spec_refs` URI, not a reason-code reference. Accordingly the
former approval is withdrawn. This adjudication does not re-review all 275
allocations. The immutable sources are [Core threshold authority at
8f780ce](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L322-L334),
the [reason-code registry entry](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/registry/reason-codes.json#L373-L381),
and the [vector schema's `spec_refs` constraint](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/vectors/schema/vector.schema.json#L111-L118).
