# Heterodyne vector generator

This package is non-normative tooling for the current draft and the rolling
pre-1.0 validation snapshot in `docs/spec/vectors/`. The specifications,
protocol schemas, and registry remain protocol authority. No pre-1.0 release
manifest exists, and snapshot vectors are conformance evidence for their pinned
source commit rather than protocol authority. Implementations do not need
Node.js, TypeScript, `nostr-tools`, or `@noble/*` to claim conformance.

Commands:

- `npm run draft:check -- <repo-root>` checks current draft inputs without
  changing the rolling snapshot.
- `npm run snapshot-check -- <repo-root>` reproduces the committed snapshot
  from its exact pinned source commit and checks its bytes read-only.
- `npm run check -- <repo-root>` runs both read-only lanes.
- `npm run snapshot-author -- <repo-root> <source-commit>` is reserved for a
  periodic reconciliation. The maintainer runs author, reviews the complete
  replacement, commits it, and then runs `snapshot-check`.
