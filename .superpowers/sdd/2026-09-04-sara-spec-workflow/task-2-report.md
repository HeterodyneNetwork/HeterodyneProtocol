# Task 2 report: projection core

Implemented the SARA projection core in `scripts/vector-trace/projection.mjs`
and the bounded, batched Git/worktree reader in
`scripts/vector-trace/history.mjs`. The public core interface is:

- `buildProjection({ repo, lane, vectorRef, ref })`
- `extractSpecAnchors(options)`
- `semanticUuid(type, semanticId)`
- `verifyReceipt(projection)`
- `readInputs(repo, ref, options)`

`lane` is mandatory. Draft defaults to `WORKTREE` and accepts an explicit
source `ref`; snapshot source bytes remain pinned by snapshot history;
reconciliation requires `vectorRef` and is marked maintenance-only.

## TDD evidence

RED, before production modules existed:

```text
Error [ERR_MODULE_NOT_FOUND]: Cannot find module
scripts/vector-trace/projection.mjs
tests 1; pass 0; fail 1
```

GREEN after implementation:

```text
node --test scripts/vector-trace.test.mjs
tests 8; pass 8; fail 0
```

The tests cover stable IDs, heading/paragraph anchors, explicit lanes, draft
inventory and freshness, current schema 3, historical schema 2, vector ID
matching independent of paths, declared-owner rejection, edge provenance,
and worktree symlink rejection.

Historical reads use one `ls-tree` inventory operation and one batched
`cat-file --batch` operation rather than one subprocess per blob. Selected
source bytes are parsed as data and never executed. Receipts hash both input
contents and inventory paths, and the source contents map is exposed as the
non-enumerable `projection.sourceContents` property for downstream parsers.
