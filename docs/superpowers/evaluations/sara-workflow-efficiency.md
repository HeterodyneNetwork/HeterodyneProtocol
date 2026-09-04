# SARA workflow efficiency evaluation

## Baseline before implementation

Base: `e36d94d028425fb804e9549a43c344e7deaf6a68`, based on main `adda8b5`.
Environment: macOS arm64, Node v22.22.2. Locked generator dependencies installed
with `npm ci` (75 packages, about one second as reported by npm). SARA absent
from PATH; a temporary 0.10.0 installation is being evaluated separately.
Dependency installation is excluded from feedback timing.

Five repeated Semble MCP searches per scenario, top three results, four-line
snippets. Times below measure tool response, not human investigation. The
repository index was already cached; these are not cold indexing measurements.

| Scenario / exact query | Five response times (ms) | Inspection outcome |
| --- | --- | --- |
| `vectors for comms privacy tiers specification anchor` | 90, 69, 66, 67, 66 | Top results included legacy `vector-metadata.ts` and 0.5 topic definitions; no current-lane completeness guarantee |
| `Comms OIDC continuity manifest requirements case contracts` | 65, 65, 66, 65, 65 | Current contract at line 1353 and schema test located |
| `Workspace effect time revocation Control Assurance boundary` | 65, 69, 70, 72, 75 | Boundary runner, certificate metadata, and Workspace test located |
| `proof domains registry schema uses current cases` | 73, 72, 95, 74, 74 | Registry tests, conformance artifact loader, and docs lint located |

One search per answer attempt; 20 searches total. Four top-result source
excerpts were opened to inspect current/legacy provenance. These searches do
not enumerate all dependencies. No numerical omission count is claimed because
there was no independently labeled full-repository dependency set.

First relevant test feedback, before implementation:

```bash
/usr/bin/time -p npm --prefix docs/spec/vectors/generator run test:current -- src/current-traceability.test.ts
```

Result: one test passed; wall 12.44 seconds, user 13.54 seconds, system 0.31
seconds. Test runner duration 12.15 seconds; test execution 11.12 seconds.
This is one observation, not a five-run distribution. Peak memory unavailable
from this invocation. Do not extrapolate it to the full gate.

## Acceptance targets and limitations

Targets: cold index at most 10 seconds; warm query p95 at most 2 seconds; at
least 50% lower median investigation time on matched editing tasks. Performance
must not hide unresolved dependencies or mix historical and draft evidence.

Human editing/investigation time has not been measured, and automated command
timing cannot establish the 50% human improvement target. Later measurements
will report packet production separately. No claim of faster vector generation
or full verification follows from faster lookup. Parallel local development
may add scheduling noise; report environment and raw samples rather than
presenting these numbers as controlled laboratory results.

## Full acceptance gate

`scripts/conformance-ci.sh` passed in a clean detached temporary worktree at
`afa066d`, with both locked packages installed by the script. The current-draft
lane passed 86 files / 2,016 tests (534.38 seconds), then validated the document
family. The snapshot lane verified all 267 vectors at snapshot `80da4ded`,
against source `c72f5ccd`. The independent conformance package built and passed
19 files / 178 tests (4.81 seconds). The script's tracked/index-state guard
passed; the validation worktree remained clean.

Subsequent review fixes are confined to the new adapter and its tests/docs;
the gate's protocol, generator, conformance, and gate-script inputs are unchanged.
Focused adapter tests are rerun separately after those fixes. This validates
integration safety, not a reduction in full-gate cost: the nine-minute current
lane remains the dominant measured verification cost.

Historical compatibility was also checked against the actual schema-2 snapshot
`5d4bb5fb58b35c88d8a9db120a09f1087237f35c`, not only synthetic fixtures. Its
receipt resolves source `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, is fresh,
and exposes three historical unresolved references. A fresh receipt establishes
input identity; it does not mean every relationship is resolved.

## Installed-worktree lookup cross-check

Five fresh processes running
`node scripts/vector-trace.mjs query heterodyne:comms#comms-issuer-continuity --lane draft --compact`
in the installed PR worktree took **1,523, 1,434, 1,440, 1,469, and 1,470 ms**
at `ef21da4` (median 1,469 ms; nearest-rank sample p95 1,523 ms). This includes
graph construction, static parsing, inventory revalidation, and JSON output.
No persistent graph cache is used; filesystem caching was uncontrolled.

The source inventory walks the generator directory before filtering files, so
installed `node_modules` directories add traversal overhead even though their
contents are not graph inputs. Temporary benchmark clones omit those directories
and load parser dependencies from the adapter's installed checkout. The installed
measurement therefore guards against reporting clone-only query performance.
Pruning irrelevant directories is a small follow-up optimization; these samples
do not justify adding a persistent cache or changing verification concurrency.

A single cached Semble search was faster than this richer packet. The intended
benefit is fewer manual provenance/dependency reconciliation steps, not faster
semantic search. That benefit still needs a matched contributor trial; these
measurements cannot establish a 50% investigation-time improvement.

## Adapter regression verification

At `5f4ecdd`,
`SARA_BIN=<temporary 0.10.0 binary> node --test scripts/vector-trace*.test.mjs`
passed **56 tests, zero failures and zero skips**. This includes real SARA
validation/traversal and invalid relation rejection. Regressions cover input
inventory tampering, actual historical layouts, owner/reference validation,
unsupported allocations, removed relationships, nested anchor spans, mixed
anchored/unanchored edits, and cyclic transitive test discovery. Known fixture
dependencies remain visible or explicitly unresolved; this is not a complete
recall measurement over all possible repository edits.

Final review found no remaining major correctness findings. Nonblocking
maintenance opportunities are pruning irrelevant input-directory traversal and
consolidating the currently duplicated anchor-boundary logic while preserving
the nested-section regressions. Neither requires changes to vector generation.

## Repeatable edit-loop probe

Run `node scripts/vector-trace.bench.mjs` after installing the adapter's locked
generator dependencies. It makes and removes only its own temporary clone;
it never edits the user's working draft. [Raw samples and exact paths/commands](sara-workflow-samples.json)
record six scenarios, five fresh CLI processes each (30 invocations), at
`5f4ecdd`. Peak memory was not collected. The final probe ran after the focused
suite, without a concurrent full conformance run.

| Scenario | Median ms | Sample p95 ms | Changed / related / unresolved records |
| --- | ---: | ---: | ---: |
| snapshot anchor reverse lookup | 810.05 | 845.18 | 1 / 0 / 0 |
| draft issuer-continuity reverse lookup | 1092.59 | 1147.44 | 1 / 96 / 64 |
| Comms local draft change | 2171.77 | 2248.53 | 1 / 96 / 64 |
| Workspace with Control and Assurance changes | 2188.52 | 2207.83 | 3 / 122 / 64 |
| shared registry and schema change | 2191.29 | 2227.64 | 2 / 3 / 64 |
| unanchored text with intentionally absent relationship | 2308.43 | 2350.82 | 1 / 199 / 65 |

The Comms edit changes the issuer-continuity section and asserts its known case
is returned. Workspace/Control/Assurance edits change each document's first
anchored heading section. The shared JSON scenario adds whitespace, testing
artifact invalidation rather than a protocol-semantic change. The Core scenario
adds an unanchored preamble comment. Exact changed paths are asserted; anchored
scenarios must not produce document fallback and the preamble must produce it.
The draft query separately asserts exactly the two issuer-continuity cases.

Related records include modules and transitive tests, not only cases. The 64
current unresolved records are graph-wide missing/unsupported allocations;
they remain visible rather than being hidden to make a selected packet appear
complete. Unanchored impact adds one explicit document-level gap. The selected
snapshot privacy anchor has no declared vectors at this snapshot; this is not
a claim that no tests exist. Historical lookup returns its pinned receipt.

Fresh-process query samples meet the two-second target; the two-projection edit
packets take about 2.2–2.3 seconds. Those are different operations. The first
fresh-process build is below ten seconds, but no filesystem-cold experiment was
performed, so the strict cold-index target is unproven. Human investigation,
vector generation and verification speedups remain unproven.

Decision: retain Phase 1 as an optional, provenance-bearing query workflow and
pilot it on real contributor edits. Do not add a second maintained requirement
map, mandatory SARA install, persistent cache, or blanket test parallelism.
For Phase 2, first separate pure metadata from fixture construction and measure
selected feedback against the unchanged full gate, subject to its maintainer gate.
