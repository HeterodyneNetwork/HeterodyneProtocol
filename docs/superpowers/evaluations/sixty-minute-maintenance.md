# Sixty-minute maintenance evaluation contract

Status: initial redacted contract and harness definition. This is not an
acceptance result. The current host can provide Git object isolation, but it
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

The redacted August 28 archive establishes 1,882 outer
tool/orchestration calls, 332 nested patch operations, approximately 600
read/search-bearing shell commands, 16 explicit compactions, and at least 14
explicit full-gate launches. These are separate counting levels; they are not
summed. Process time must use real process start-to-exit timestamps, not a
yield wrapper or poll duration. Full-gate process/lane/CPU/memory/dependency
readiness profiling remains pending and is not represented as an acceptance
result here.

Archive-parser correction (2026-09-04): the 332 patch operations and gate
launch estimate above came from orchestration source, not observed nested
runtime events. The archive has 1,882 observed outer calls (1,562 `exec`, 226
`wait`, 88 `send_message`, and 6 `wait_agent`) and a static lower bound of
1,599 direct `tools.*` call sites (1,073 `exec_command`, 163 `write_stdin`, 332
`apply_patch`, 22 `mcp__semble__search`, and 9 `update_plan`). Those static
sites are not execution or process evidence. Ten `turn_id` task pairs report
28,227,508 ms total duration; their separately retained outer-event spans sum
28,227,438 ms. The archive provides no structured process start/exit
instrumentation, so process count and duration remain unknown and zero gate
launches are explicitly confirmed; the total launch count is unknown.

## Exploratory readiness profile

Parent-owned profiles on Node 22.22.2, macOS 15,7, 12 CPU/18 GiB, used a
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

The fixture and scorer live in `scripts/maintenance-eval/`. Synthetic negative
fixtures and expected results remain outside worker-visible evidence. No raw
session archive, hidden reasoning, credential, or private message is checked
in.
