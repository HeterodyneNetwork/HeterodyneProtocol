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
