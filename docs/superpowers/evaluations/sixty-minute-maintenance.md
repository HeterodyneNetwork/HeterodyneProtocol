# Sixty-minute maintenance evaluation contract

Status: Phase 1 harness, static packet compiler, and independent slice checks
are implemented. The [first matched pilot](sixty-minute-maintenance-pilot.md)
retains its equal 204/204 worker-plus-reviewer call count, but its semantic
acceptance is withdrawn after source-authority adjudication; later phases remain
gated. The [v3 preflight](sixty-minute-maintenance-preflight-v3.md) is measured;
its separately reviewed feasible edit trial remains pending.
This is not a sub-hour acceptance result. The current host can provide Git object isolation, but it
does not provide an OS-sealed worker/evaluator boundary; runs here are
exploratory until an isolated runner enforces permitted read roots and blocks
future Git/network access.

## Workload

The primary arm is a complete-brief reconstruction: both agents receive the
same immutable start tree and all ten legitimate outcomes up front. The causal
replay is a separate arm: the round additions, rollback decision, and external
snapshot inputs are delivered at their recorded reveal boundaries. A success in
one arm is not a success claim for the other. Historical human idle gaps are
excluded only when the same scripted maintainer decision is delivered to every
arm; real approvals remain on every arm's clock.

The endpoint is the selected worker's ten-round output at
`0dd150682903d14eddd8d14b57892395f750c47f`, starting from the first observed
worker HEAD `b6416fda157529b708c86f21cc4ea66a7b24384c`. External snapshot inputs
`0efa4a9fca289b53289472e9490f531c5682912a` and
`8f780cea2119738e3db1a37e7c0c94b4cd200cb3` are prerequisites with their own
reveal boundaries, not worker output. Subsequent snapshot regeneration and the
parent PR are outside this endpoint.

The ten-round intent contract is:

| Round | Required outcome |
| --- | --- |
| 1 | Six-family catalog, schema-3 traceability, current-only imports, temporary author/verify, frozen snapshot preservation |
| 2 | Executable boundary evidence and exact rejection traces; no registry-derived semantic labels |
| 3 | Private identity-bound evidence, profile/reason/invariant closure, exact loader resolution, audited exclusions |
| 4 | Independent 31-row profile oracle, scope-aware loader analysis, byte-derived Assurance/KERI classification |
| 5 | Composition-only static audit, exact Core/Tier-3/Control/revocation semantics, complete CESR framing |
| 6 | Concealed-capability denial, module-owned Tier-3 authority, revocation verification through merge/effect |
| 7 | Runtime-isolation investigation; wait for architecture direction before implementation |
| 8 | Approved bounded child-runtime experiment with exact graph/assets and same-process semantic closure |
| 9 | Runtime-isolation withdrawal; restore direct authoring and retain composition-only graph audit |
| 10 | Resolve 44 stale/mismatched references to 27 live anchors; reject invalid references before authoring mutation |

Each machine-readable round record carries `id`, `intent`, `source`,
`confidence`, `reveal_after`, `external_inputs`, and `checks`. Encrypted child
briefs were not literally recovered; any unresolved intent must be reviewed
before timing. The final fixture uses the authorized final behavior. Causal
replay additionally exercises the experiment, decision, and rollback.

## Sealing and scoring

The evaluator-side fixture creates a new Git object store and fetches only the
worker-visible base and its permitted ancestors. The endpoint is an
evaluator-only reference and is automatically forbidden in the worker store.
It verifies start/end ancestry, no alternates, unreadable later objects, and
manifest digests for the visible tree, lockfile, index, and cache. The worker
receives a concrete `benchmark-contract.json` plus its digest; independent
oracle material stays evaluator-held. A trusted preparer supplies locked
dependencies. The fixture does not claim OS-level filesystem or network
enforcement.

The score is accepted only when the run is complete, every evaluator-supplied
check passes, no findings remain, and `elapsedMs < 3_600_000`. Missing or
duplicate check IDs are rejected before scoring. A completed run with a failed
private-evidence or independent-oracle check is therefore not successful,
regardless of elapsed time.

## Baseline and pending readiness

The redacted August 28 archive has 1,882 observed outer calls (1,562 `exec`,
226 `wait`, 88 `send_message`, and 6 `wait_agent`) and 1,599 lexical `tools.*`
call candidates (1,073 `exec_command`, 163 `write_stdin`, 332 `apply_patch`,
22 `mcp__semble__search`, and 9 `update_plan`). The scanner skips comments and
quoted/template strings but can include regex literals and nested receivers;
this is not a lower bound on direct calls. The historical count is retained,
not remeasured. These candidates are not observed nested runtime events,
executions, or processes. A prior manual source audit identified approximately
600 read/search-bearing
shell-command candidates and at least 14 full-gate command candidates; it did
not instrument or confirm their launches. The archive also contains 16
explicit compaction records.

Ten matched `turn_id` task pairs have provider-reported
`task_complete.duration_ms` values totaling 28,227,508 ms. The corresponding
spans between matched outer-record timestamps total 28,227,438 ms; this is a
separate timing definition. The archive provides no structured process
start/exit instrumentation, so process count and duration remain unknown.
Zero gate launches are confirmed by instrumentation, which does not imply
that zero launches occurred. Process time requires real process start-to-exit
timestamps, not a yield wrapper or poll duration. The separate readiness
profiles below measure actual process lifetimes, not archive wrapper times;
they are not acceptance results.

## Exploratory readiness profile

Parent-owned profiles on Node 22.22.2, macOS 26.4.1, Mac15,7 hardware,
12 CPUs and 18 GiB RAM, used a
fresh clone with normal warmed dependency caches. The completed endpoint tree
at `0dd1506` passed its ordered draft, snapshot (275 vectors), and independent
lanes in 136,563 ms (136.55 real, 359.69 user, 17.20 sys, max RSS
795,852,800 bytes). The historical base at `b6416fda` took 31,379 ms and
failed in the snapshot lane because it is an incomplete base; it is not a
workflow regression. Current main at immutable `8d263b8` had a separate
606,669 ms exploratory gate profile and passed, fitting the provisional
15-minute gate reserve on this machine. These are environment measurements
only, not a sub-sixty-minute workflow result or acceptance evidence.

The completed endpoint snapshot is stage-specific: its manifest has 275
vectors, source commit `08ac4418b14586b0053829349ee7173febeb806e`, schema
`3.0.0`, and snapshot commit `0efa4a9fca289b53289472e9490f531c5682912a`.
The historical 482-vector snapshot is a preserved earlier reveal stage, not a
hardcoded final endpoint. The external handoff and independent identity oracle
remain review-required.

The external snapshot pins a source commit containing earlier original-worker
implementation. Giving that source history to a worker at the initial base
would reveal later solution code. A fair complete-brief run therefore still
needs a reviewed dependency-handoff policy or an evaluator-only historical
gate; the current fixture helper alone does not solve this boundary.

The fixture and scorer live in `scripts/maintenance-eval/`. Synthetic negative
fixtures and expected results remain outside worker-visible evidence. No raw
session archive, hidden reasoning, credential, or private message is checked
in.

## Phase 1 tools and limits

`scripts/maintenance/metadata.mjs` reads declared current or historical
allocations with the locked TypeScript parser. It does not execute family
builders or turn declarations into execution evidence. Unsupported runtime
initializers/imports and transformations remain explicit unknowns, including
the live profile-oracle module's runtime prelude.

`scripts/maintenance/packet.mjs` exports `compilePacket()` and
`resolvePacketHandle()`. Callers supply the existing `buildGraph()` result,
task semantic IDs, exact optional symbol selectors, owned paths, acceptance
checks, and a contract. Source spans use UTF-8 byte coordinates and content
digests; normative section hashes and full-file freshness hashes retain their
different meanings. Current-draft and historical snapshot inputs are resolved
from their own receipt refs. Unchanged delivered chunk IDs are cumulative;
changed source cannot silently reuse a prior chunk.

An optional `artifactDirectory` outside the source worktree stores immutable,
digest-checked relationship/receipt sidecars. The returned
`relationships.graphArtifact` handle is resolved with that same directory;
it is not a request to reconstruct old WORKTREE state from today's files.
Without a backing store, details remain inline. The approximate budget is
8,000 tokens using `utf8-json-bytes-per-4-v1`; an excess produces an explicit
expansion request, not missing obligations. Partial packets remain incomplete.

The real current issuer-continuity packet has two exact declaring cases,
one governing section and one implementation interface, preserving 96 related
records and 999 edges through a resolvable sidecar. Its 8,240 estimated tokens
request a 240-token expansion after unsupported live profile setup is exposed
as unknown. This is a bounded-context observation, not a measured speedup.

`scripts/maintenance-eval/slice.mjs` provides evaluator-owned static
reference/scope/preservation checks and an actual temporary authoring probe.
The latter requires valid authoring to complete and an injected invalid
reference to reject without changing any seeded output. Governing semantic
correctness still needs independent review; merely finding an anchor is not
enough. New pilot helper files require exact reviewed path/digest approvals.

Tool readiness after the consolidated Phase 1 review repairs (September 4):

```bash
node --test scripts/maintenance/*.test.mjs scripts/maintenance-eval/*.test.mjs scripts/vector-trace*.test.mjs
```

Result: 149 tests, 147 passed, two optional SARA skips, zero failures
(18,548.366 ms). These tests do not replace a fresh candidate conformance gate
or the plan's matched slice and full-workload acceptance trials. No durable
store, scheduler, new agent skill, or default routing is claimed yet.

## Final local verification

The consolidated repair `59d93c6` passed scoped independent review. A fresh
coordinator run of the command above passed 147 tests, with two optional SARA
skips and zero failures, in 21,014.456 ms. Subsequent changes were documentation
only.

The first fresh `scripts/conformance-ci.sh` attempt failed two existing test
timeouts: 2,014 draft tests passed and two failed; snapshot and independent
lanes were not reached. It took 2,484.91 seconds wall time versus 560.74 user
and 9.25 system CPU seconds. Local power logs recorded 954- and 1,015-second
sleep intervals aligned with the two unusually long tests. The generator,
dependencies, gate, and test limits were unchanged from the base tree.

The unchanged gate was rerun with a command-lifetime idle-sleep inhibitor
(no permanent power-setting change):

```bash
/usr/bin/caffeinate -i -t 1200 /usr/bin/time -p scripts/conformance-ci.sh
```

It passed on the final source tree (`88370c6`, before this documentation-only
evidence update): 2,016 draft tests in 86 files, 267 history-bound snapshot
vectors, and 178 independent tests in 19 files. Actual process time was
564.13 seconds wall, 609.22 user and 19.89 system CPU seconds. The snapshot
remained bound to source `c72f5ccdf855069550511d8e3e837dae55ed299c` and snapshot
commit `80da4ded273ac746b9c56bc53a8f1c067835ad64`. No snapshot was reconciled.

Locked installs reported the existing audit findings (five in the generator
package and one in conformance); no dependency upgrade was attempted. These
verification results establish the partial tooling branch's local readiness,
not fewer workflow steps or completion of the full maintenance plan.
