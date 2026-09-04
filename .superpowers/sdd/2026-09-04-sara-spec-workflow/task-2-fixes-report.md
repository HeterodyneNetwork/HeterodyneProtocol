# Task 2 fixes report

Implemented the projection-core review fixes in `scripts/vector-trace/projection.mjs`,
`scripts/vector-trace/history.mjs`, and `scripts/vector-trace.test.mjs`.

- Snapshot manifests now enforce the exact schema/version/count/commit/path/digest
  grammar and compare the declared artifact set with the historical vector tree.
- Historical vector artifacts are validated against the selected snapshot schema via
  the locked current Ajv dependency. Coverage owner/profile/reference declarations
  must match the vector envelope; syntactically valid but absent anchors remain in
  `receipt.unresolved_references`.
- Historical symbolic refs are resolved before input records are written, inventory
  fingerprints include immutable refs and digests, and worktree/history paths reject
  newline input and symlink-parent traversal.
- `source_line` is included on spec-anchor items; relative Markdown schema/registry
  links resolve against the owning specification path.
- Exported `finalizeProjection(projection)` refreshes the canonical graph digest and
  returns the same projection; `verifyReceipt` now checks graph integrity.
- Synthetic snapshot fixtures now contain the complete envelope, packaged schema,
  support artifacts, and per-test cleanup.

Verification:

```text
node --test scripts/vector-trace.test.mjs                  14 passed
node --test scripts/vector-trace*.test.mjs                 38 passed, 2 skipped
node --check projection/history/vector-trace.test modules   passed
git diff --check                                             passed
```

The CLI deliverable remains owned by the parent task; no normative specifications or
vector artifacts were changed.
