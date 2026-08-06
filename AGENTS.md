# Heterodyne agent guide

## Protocol authority

The current protocol stands on the specification family and its normative
artifacts:

- [`docs/spec/heterodyne-core.md`](docs/spec/heterodyne-core.md): identity,
  registry, versions, repositories, and base conformance.
- [`docs/spec/heterodyne-comms.md`](docs/spec/heterodyne-comms.md): publishing,
  privacy, direct messages, claims, private ledger, and OIDC/JWT.
- [`docs/spec/heterodyne-control.md`](docs/spec/heterodyne-control.md):
  own-device enrollment and RPC; currently incomplete and non-claimable.
- [`docs/spec/heterodyne-social.md`](docs/spec/heterodyne-social.md): social
  behavior and optional Matrix support.
- [`docs/spec/registry/`](docs/spec/registry/),
  [`docs/spec/schemas/`](docs/spec/schemas/),
  [`docs/spec/releases/`](docs/spec/releases/), and
  [`docs/spec/vectors/`](docs/spec/vectors/): normative machine-readable
  artifacts.

The family dependency direction is:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

ADRs are non-canonical point-in-time decision records. They explain why a
change was made but cannot add, amend, activate, or override protocol
requirements. If an ADR and the specification disagree, the specification
governs.

## Changing the protocol

1. Create one or more proposed ADRs in [`docs/adr/`](docs/adr/).
2. Implement the complete corresponding specification change in the same
   branch and patch or pull request.
3. Update every affected normative artifact in that patch: specification
   prose, registry, schemas, release metadata, and conformance vectors.
4. Review the ADR and complete specification patch together.
5. Once accepted, mark the ADR accepted and move it to
   [`docs/adr/archive/`](docs/adr/archive/) before merge.
6. Merge only when the specification stands on its own without the ADR.

An accepted ADR without complete specification integration is not mergeable.
Live normative documents and conformance checks must cite specification
anchors and normative artifacts, not ADRs.

## Working rules

- Use Semble semantic search first to locate code or prose. Use `rg` when every
  occurrence of a literal is required.
- Wire-level changes require corresponding normative vector changes.
- The protocol is in its 0.x phase and may break between 0.x releases.
  Compatibility and vector-ID immutability begin at 1.0.
- Do not edit `research/sources/`; use [`research/INDEX.md`](research/INDEX.md)
  to find preserved research.
- Keep the family implementation-agnostic. Vanilla Nostr relays, Radicle
  nodes, and Matrix homeservers must not require Heterodyne-specific changes.
- Preserve unrelated user changes and untracked files.

## Verification

Run from the repository root:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```
