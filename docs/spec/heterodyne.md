# Heterodyne Protocol Family

This page is the non-normative family overview and navigation map. Normative
requirements live only in the six documents and machine-readable artifacts
linked below.

Heterodyne composes ordinary Nostr signed events, standard Marmot accounts and
MLS groups, and Radicle-backed repositories. One active Nostr public key is a
human or organization persona's baseline identity and Marmot account identity.
A bare key is a complete, first-class persona. Cold-root and KERI continuity
are optional Assurance rather than prerequisites.

## Document graph

All six documents carry `heterodyne/0.5.0`. Assurance depends only on Core.
Comms, Control, Social, and Workspace may compose Assurance but do not require
it for baseline conformance. Workspace's Core+Comms base is solid; its Control
and Social integrations are optional.

```text
Core <- Assurance
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

## Current documents

| Document | Scope | Status |
|---|---|---|
| [Core](heterodyne-core.md) | Active-key personas, NIP-01 verification, kind `0`/NIP-05/NIP-65 discovery, source-neutral state, repositories, registry, and base conformance | Normative 0.x |
| [Assurance](heterodyne-assurance.md) | Optional cold-root/KERI continuity, reciprocal enrollment, succession, associated keys, and downgrade resistance | Normative 0.x |
| [Comms](heterodyne-comms.md) | Publishing, privacy, standard Marmot accounts and groups, claims, OIDC/JWT, automated authorship, and trusted-seed routing | Normative 0.x |
| [Control](heterodyne-control.md) | Isolated vaults, standard NIP-46, OIDC-bound signing grants, Marmot operations, and compromise reset | Normative 0.x |
| [Social](heterodyne-social.md) | Vanilla-compatible social behavior, moderation, lists, communities, durable assets, and ATProto attachment | Normative 0.x |
| [Workspace](heterodyne-workspace.md) | Active-key organizations, roles, private discovery, federation, hosts, and resource-key delivery | Normative 0.x |

The single live registry pin is
[`registry/manifest.json`](registry/manifest.json). No pre-1.0 release
manifest exists. The specifications, [`schemas/`](schemas/), and
[`registry/`](registry/) are current authority; ADRs and this map are not.

## Baseline interoperability

Public discovery starts from an active npub directly or through NIP-05, then
uses ordinary kind `0` and NIP-65 kind `10002`. Public events are signed once
and fanned out unchanged. Ordinary relays and Radicle-backed repo relays carry
the same exact event bytes; a client unions valid candidates and applies
NIP-01 selection without carrier precedence. Kind `0` and kind `10002` are
refreshed at least every seven days, with overdue state producing a warning
rather than invalidity.

Persona- and group-owned repositories are durable location and replication
mechanisms, not alternate identity or authorship systems. Writer NIDs enter
the accepted union only through exact owner authorization. A public repo relay
is an ordinary NIP-01 endpoint from a vanilla client's perspective.

The active persona key is the standard Marmot account. Devices retain
independent MLS leaves. Heterodyne succession never aliases Nostr authors or
Marmot accounts and never silently transfers group membership.

## Roles and authority boundaries

A full node is an optional authorization and signing service. It may manage
several isolated persona vaults, standard NIP-46 connections, and OIDC-bound
grants; it need not host a relay or repository. The node acquires no persona
identity merely by operating.

Several trusted seed NIDs may concurrently provide Radicle availability and
public or private relay service. Each seed uses its own authorized writer ref.
Seed, signer, repository-owner, workspace governor, Marmot administrator, and
MLS member authority remain separate.

Agent-key signing is preferred. Persona-key signing needs explicit scope.
Every automated intent receives NIP-32-compatible attribution before signing,
and the actual event `pubkey` always remains the NIP-01 author.

Active-key compromise triggers a complete reset: revoke NIP-46 and OIDC
grants, invalidate clients, delegates, agents, nodes, repositories and seeds,
remove old-account leaves, advance reachable groups, publish fresh successor
KeyPackages, and explicitly reauthorize each continuing subordinate.

## Conformance classes

| Claim | Required documents | Optional composition |
|---|---|---|
| Core | Core | Assurance |
| Comms persona | Core + Comms | Assurance |
| Control | Core + Comms + Control | Assurance |
| Social | Core + Comms + Social | Assurance |
| Workspace | Core + Comms + Workspace | Assurance, Control, Social |

Claims name the family version, registry revision or digest, features, and
strict profiles. Optional Assurance has its own conformance claim and cannot
lower the baseline status of an unassured persona.

## Live validation and frozen history

`draft:check` validates live prose, schemas, registry, and current reference
semantics. It does not execute the frozen pre-redesign vector topic sources.

The one rolling validation snapshot is non-normative historical evidence. It
contains exactly 482 vectors, pins source commit
`2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, and is history-bound to snapshot
commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`. Historical generation,
packaging, fixtures, vector schema/reason projections, coverage, and metadata
belong to `snapshot-check`. Ordinary current-draft work does not rewrite them.

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

Only a deliberate future reconciliation may author a replacement snapshot.
