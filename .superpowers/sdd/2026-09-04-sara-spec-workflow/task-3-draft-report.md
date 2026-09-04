# Task 3 draft enrichment report

Implemented `enrichDraft(projection, { repo })` in `scripts/vector-trace/draft.mjs`.

The synchronous enrichment pass statically parses the current generator inputs
with the TypeScript compiler resolved from this worktree's locked generator
package. It adds declared `draft_case` items, validates and normalizes
version-qualified references, preserves `raw_refs`, records declaration and
boundary-override provenance, and links cases to exact exported boundary
declarations when they resolve. Runtime profile-oracle cases and unsupported,
invalid, missing, or ambiguous links remain explicit receipt unresolved
references with source paths and lines. The terminal-only auth rejection case
retains its terminal invariants separately and makes no semantic invariant
claim.

Static local imports/exports (including cycles) become `imports` edges. Literal
dynamic imports are resolved the same way; missing and nonliteral dynamic or
`require()` dependencies are unresolved. Builtin and package imports are
recorded in `receipt.external_dependencies` without inventing graph nodes.
Generator configuration and lock inputs retain their normal source provenance.
The pass mutates only the projection graph/receipt and leaves `sourceContents`
unchanged; the caller remains responsible for final ordering and graph hash.
The receipt records the actual TypeScript parser version loaded from this tool
worktree (`typescript_version`), independently of selected-repository inputs.

Verification:

* `node --test scripts/vector-trace.draft.test.mjs` — 5 passing tests.
* Real current-worktree smoke: 267 draft cases, 267 resolved boundary edges,
  cyclic/static import edges preserved, profile overrides reported unresolved,
  and external dependencies recorded without executing generator code.

Known conservative gaps are retained in the receipt: four boundary modules are
not represented by exact source basenames, and unsupported/nonliteral imports
remain unresolved. The full CLI query test was not used as a completion gate
because its parent impact/query path hung beyond 30 seconds; the direct
enrichment smoke and focused tests complete successfully.
