# Heterodyne agent guide

## Protocol authority

The current protocol stands on the specification family and its normative
artifacts:

- [`docs/spec/heterodyne-core.md`](docs/spec/heterodyne-core.md): identity,
  registry, versions, repositories, and base conformance.
- [`docs/spec/heterodyne-comms.md`](docs/spec/heterodyne-comms.md): publishing,
  privacy, direct messages, claims, private ledger, and OIDC/JWT.
- [`docs/spec/heterodyne-control.md`](docs/spec/heterodyne-control.md):
  Marmot-carried own-device enrollment and RPC plus optional recovery profiles.
- [`docs/spec/heterodyne-social.md`](docs/spec/heterodyne-social.md): social
  behavior, public interactions, moderation, and durable social assets.
- [`docs/spec/heterodyne-workspace.md`](docs/spec/heterodyne-workspace.md):
  workspace identity, roles, private discovery, federation, hosting, and
  resource-key delivery.
- [`docs/spec/registry/`](docs/spec/registry/),
  [`docs/spec/schemas/`](docs/spec/schemas/), and generator-owned protocol
  inputs: live normative machine-readable artifacts for the current draft.

[`docs/spec/vectors/`](docs/spec/vectors/) is the one rolling, non-normative
pre-1.0 validation snapshot. No pre-1.0 release manifest exists, and the
snapshot does not add authority to the current draft.

The family composition direction is below. Workspace requires Core+Comms;
its Control and Social compositions are optional.

```text
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

ADRs are non-canonical point-in-time decision records. They explain why a
change was made but cannot add, amend, activate, or override protocol
requirements. If an ADR and the specification disagree, the specification
governs.

## Changing the protocol

1. Create one or more proposed ADRs in [`docs/adr/`](docs/adr/) when the change
   records a material protocol decision.
2. Implement the complete corresponding current-draft change in the same
   branch and patch or pull request.
3. Update only affected live draft artifacts: specification prose, registry
   entries, protocol schemas, and source generator inputs. An ordinary
   pre-1.0 change does not update vectors or snapshot metadata.
4. Review the ADR, when present, and complete specification patch together.
5. Once an ADR is accepted, mark it accepted and move it to
   [`docs/adr/archive/`](docs/adr/archive/) before merge.
6. Merge only when the specification stands on its own without the ADR.

An accepted ADR without complete specification integration is not mergeable.
Live normative documents and conformance checks must cite specification
anchors and normative artifacts, not ADRs.

## Working rules

- Use Semble semantic search first to locate code or prose. Use `rg` when every
  occurrence of a literal is required.
- During pre-1.0 ordinary authoring, wire-level changes remain confined to the
  affected live draft artifacts. Vector coupling applies only in a dedicated
  rolling-snapshot reconciliation, or under the future 1.0 release policy.
- The protocol is in its 0.x phase and may break between 0.x releases.
  Compatibility and vector-ID immutability begin at 1.0.
- Do not edit `research/sources/`; use [`research/INDEX.md`](research/INDEX.md)
  to find preserved research.
- Keep the family implementation-agnostic. Vanilla Nostr relays, Radicle
  nodes, and standard Marmot implementations must not require
  Heterodyne-specific changes.
- Preserve unrelated user changes and untracked files.

## Verification

The normal verification path is read-only and has two independent lanes. Run
the current-draft lane and the history-bound rolling-snapshot lane from the
repository root:

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

The shared hosted/local gate installs both locked packages, runs those lanes in
that order, then builds and tests the independent conformance package:

```bash
scripts/conformance-ci.sh
```

The snapshot lane derives the snapshot commit from the last commit that
changed `docs/spec/vectors/snapshot.json`; it does not trust an uncommitted
snapshot as history. A reconciliation maintainer selects a stable full source
commit, runs `snapshot-author`, reviews the replacement, commits it, and only
then runs `snapshot-check`. Authoring and baseline/report commands are never CI
steps. GitHub checks out full history; Radicle must make the pinned object
available or the lane fails with an actionable full-history error.

Before merging a Radicle patch, require a green `scripts/conformance-ci.sh` run
through a delegate-operated, isolated podman adapter. GitHub repository
administrators should configure the stable `conformance` check as required;
changing that remote setting is outside repository verification and must not
be performed by agents working here.
