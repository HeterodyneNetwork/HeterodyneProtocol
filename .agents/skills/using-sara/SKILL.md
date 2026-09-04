---
name: using-sara
description: Use when changing Heterodyne specifications, finding related cases or historical vectors, inspecting coverage or impact, or dividing vector maintenance work.
---

# Using SARA for Heterodyne

Use the repository wrapper to obtain a fresh change packet. Normative authority
remains the six specs, registry, and schemas identified in `AGENTS.md`.
This skill is a query recipe, not a second specification.

From the repository root:

```bash
node scripts/vector-trace.mjs query heterodyne:comms#comms-issuer-continuity --lane draft --compact
```

The packet includes current case declarations, exact source locations,
dependencies, candidate tests, unresolved links, and a freshness receipt.
`--compact` replaces the receipt's full inventory with counts and digests;
`receipt --lane draft` exposes the complete inventory when needed.

| Question | Command/lane |
| --- | --- |
| Current requirement or source relationships | `query <semantic-id> --lane draft --compact` |
| Local edit impact | `impact --lane draft --base HEAD --head WORKTREE --compact` |
| Work ownership and collisions | `worklist --lane draft --base HEAD --head WORKTREE --compact` |
| Historical vector coverage | `query <anchor> --lane snapshot --compact` |
| Current requirements with selected historical vectors | `query <anchor> --lane reconciliation --vector-ref <commit> --compact` |
| Declared coverage or matrix | `coverage` or `matrix`, with an explicit lane |

For questions asking both current cases and historical vectors, run separate
draft and snapshot queries. Cite each lane's resolved source/vector commits.
Reconciliation output is maintenance information, not current conformance.

Inspect `receipt.fresh`, input identities/digests, and `unresolved` before
drawing conclusions. Diff receipts contain `before` and `after`. An unresolved
runtime profile override or missing dependency means the graph is partial;
report that limitation and use Semble to locate the relevant implementation.
An empty result does not establish absence of tests. Declared coverage does
not prove boundary execution or certificate verification.

Read the returned normative anchors and source locations before editing.
Suggested tests are advisory; the normal acceptance gate remains
`scripts/conformance-ci.sh`. Worklists identify shared-file conflicts and do
not authorize snapshot regeneration. Follow AGENTS' ordinary-draft versus
reconciliation rules.

Core commands need no SARA installation. Draft parsing uses the repository's
locked TypeScript dependency: `npm --prefix docs/spec/vectors/generator ci`.
For SARA validation/traversal add `--backend sara` to `check` or `query`.
The tested CLI is 0.10.x: `cargo install sara-cli --version 0.10.0 --locked`.
Use `--help` for graph export and other options.

Common mistakes: trusting old vector counts in prose instead of the selected
manifest; treating a fresh but partial graph as complete; citing generated
SARA files as protocol authority; treating different case IDs as independent
when they share a contract or fixture file.
