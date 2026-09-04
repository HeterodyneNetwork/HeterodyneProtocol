# Task 1 report — sealed workload and benchmark harness

Status: harness implemented and focused checks green; acceptance remains
pending an OS-sealed evaluation runner, exact independent identity oracle,
complete-brief external-input placement review, and parent-owned full-gate
readiness profiling.

## TDD evidence

RED command:

```text
node --test scripts/maintenance-eval/*.test.mjs
```

Result: expected `ERR_MODULE_NOT_FOUND` for `archive.mjs`, `fixture.mjs`, and
`score.mjs` (three test files failed before implementation).

GREEN command:

```text
node --test scripts/maintenance-eval/*.test.mjs
```

Result: 7 tests passed, 0 failed, 0 skipped. Coverage includes one yielded
command followed by polls (one process and explicit start-to-exit duration),
separate outer/nested call counts, hidden descendant object rejection with no
Git alternates, the incomplete-fast-run rejection, the exact 3,600,000 ms
boundary, complete acceptance, and check-ID validation.

A production-mode smoke fixture against the approved endpoint objects also
completed successfully in a fresh temporary repository while hiding the
current branch's later HEAD. This verifies the source-only Git boundary; it is
not an OS-sealed acceptance run.

## Implemented contract

`archive.mjs` consumes event metadata and returns span, task intervals, outer
calls, nested calls, process count, confirmed gate launches, and line/time
provenance. Wrapper yield and polling records do not become process launches.
`fixture.mjs` is evaluator-side: it copies only the selected commit's
reachable objects into a fresh Git repository, validates approved worker
history, checks ancestry/alternates/later-object visibility, and compares
visible tree/lockfile/index/cache digests. It returns only worker repo and
digest metadata. `score.mjs` uses the required strict under-one-hour predicate.

The approved endpoints are worker HEAD
`b6416fda157529b708c86f21cc4ea66a7b24384c` and last worker commit
`0dd150682903d14eddd8d14b57892395f750c47f`. External snapshot commits
`0efa4a9fca289b53289472e9490f531c5682912a` and
`8f780cea2119738e3db1a37e7c0c94b4cd200cb3` are modeled as external inputs,
not worker output. The ten round intents and both complete-brief/causal-replay
labels are recorded in the initial evaluation contract.

Archive provenance used for the report is limited to public event metadata.
The ten task-start lines are 2, 1252, 3555, 6123, 7412, 8407, 9712, 9835,
10753, and 11078; their completion lines are 1251, 3554, 6122, 7411, 8406,
9711, 9834, 10752, 11077, and 11743. Human-readable result lines are 1249,
3552, 6120, 7409, 8404, 9709, 9832, 10750, 11075, and 11740. No raw archive
content is included.

As a non-acceptance sanity check, importing the authorized archive's public
event metadata produced a 38,832,193 ms span (about 10h47m12s), 1,882 outer
calls, and 332 nested patch operations. No process duration was inferred: the
archive has no explicit public process start/exit pair for those launches.

## Concerns and pending work

- The unrestricted host cannot enforce OS-level permitted roots or network/Git
  fetch denial. A source-only Git fixture is not an OS-sealed acceptance run;
  label host trials exploratory and fail closed for acceptance.
- Exact independent identity-oracle inputs and the complete-brief placement of
  external snapshot inputs require maintainer review.
- Parent owns full-gate process start/exit, lane timing, CPU/memory,
  dependency-setup, model-availability, and exact-input profiling. Those
  measurements are intentionally pending here; no under-sixty-minute result is
  claimed.
- The archive's approximately 600 read/search commands overlap the 1,882 outer
  calls and 332 nested patch operations and are reported at separate levels.
