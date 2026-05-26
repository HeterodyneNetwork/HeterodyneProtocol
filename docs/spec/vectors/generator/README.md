# Heterodyne vector generator

This package is non-normative tooling for authoring and checking the JSON
vectors in `docs/spec/vectors/`. The committed JSON vectors are the normative
artifact; implementations do not need Node.js, TypeScript, `nostr-tools`, or
`@noble/*` to claim conformance.

Commands:

- `npm run author` rewrites generated vector files deterministically.
- `npm run verify` validates committed vectors and checks generated outputs.
- `npm run check` runs TypeScript, tests, and vector verification.
