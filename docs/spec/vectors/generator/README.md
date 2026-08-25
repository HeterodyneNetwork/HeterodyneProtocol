# Heterodyne vector generator

This package is non-normative tooling for the current draft and the rolling
pre-1.0 validation snapshot in `docs/spec/vectors/`. The specifications,
protocol schemas, and registry remain protocol authority. No pre-1.0 release
manifest exists, and snapshot vectors are conformance evidence for their pinned
source commit rather than protocol authority. Implementations do not need
Node.js, TypeScript, `nostr-tools`, or `@noble/*` to claim conformance.

Commands:

- `npm run draft:check -- <repo-root>` checks current draft inputs without
  changing or importing the rolling snapshot. Its explicit
  `tsconfig.current.json` allowlist covers current family/docs/registry,
  protocol-schema, and reference-semantic tests. It excludes vector topics,
  authoring, coverage, packaging, historical OIDC/token-status continuity
  fixtures, and snapshot orchestration.
- `npm run snapshot-check -- <repo-root>` reproduces the committed snapshot
  from its exact pinned source commit and checks its bytes read-only.
- `npm run check -- <repo-root>` runs both read-only lanes.
- `npm run snapshot-author -- <repo-root> <source-commit>` is reserved for a
  periodic reconciliation. The maintainer runs author, reviews the complete
  replacement, commits it, and then runs `snapshot-check`.

`src/current-cli.ts` is the live-draft entry point for family validation and
registry authoring. `src/cli.ts`, vector topic projections, the legacy
OIDC/token-status continuity modules, and the author/coverage/verify pipeline
are snapshot-compatibility tooling. Normal draft validation does not execute
them; the history-bound snapshot lane materializes the exact source and tool
commits that own those semantics.
