# Heterodyne

**Own your social identity.** No company owns it, and no particular service is
required to host it. Heterodyne is a specification-first, implementation-
agnostic protocol family composed from standard Nostr events, standard Marmot
accounts and MLS groups, and Radicle-backed durable storage.

**Repository mirrors:** [GitHub](https://github.com/HeterodyneNetwork/HeterodyneProtocol)
· [Radicle](https://radicle.network/nodes/iris.radicle.network/rad:z2zX5XvPiggGJvCn8DPkp1hRNGA5)

The current documents are 0.x drafts and may make breaking changes before
1.0. [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is the
non-normative family map; the specifications and machine-readable artifacts
linked below carry current authority.

## Protocol family

The six-document family has one draft identifier, `heterodyne/0.6.0`:

| Document | Responsibility |
|---|---|
| [Core](docs/spec/heterodyne-core.md) | Active-key personas, NIP-01 verification, kind `0`/NIP-05/NIP-65 discovery, source-neutral state, repositories, registry, and base conformance. |
| [Assurance](docs/spec/heterodyne-assurance.md) | Optional cold-root/KERI continuity, reciprocal enrollment, succession, associated keys, and downgrade resistance. |
| [Comms](docs/spec/heterodyne-comms.md) | Publishing, privacy, standard Marmot accounts and groups, claims, private ledger, OIDC/JWT, automation attribution, and trusted-seed private relay ACLs. |
| [Control](docs/spec/heterodyne-control.md) | Isolated persona vaults, standard NIP-46, OIDC-bound signing grants, node-mediated Marmot operations, and compromise reset. |
| [Social](docs/spec/heterodyne-social.md) | Vanilla-compatible following, interactions, lists, communities, moderation, durable assets, and ATProto attachment. |
| [Workspace](docs/spec/heterodyne-workspace.md) | Active-key organizations, roles, private discovery, federation, hosting, and resource-key delivery. |

Assurance is optional. Workspace requires Core+Comms; its Assurance, Control,
and Social compositions are optional.

```text
Core <- Assurance
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

No pre-1.0 release manifest exists. The six specifications, live protocol
schemas, and registry are the current authority. Generator-owned live inputs
are non-normative authoring inputs kept synchronized with them.

## What the family provides

- **Nostr-native identity.** One active Nostr public key is the baseline
  persona identity and the standard Marmot account identity. A bare active key
  without Assurance is complete and first-class.
- **Standard discovery.** Ordinary kind `0`, NIP-05, and NIP-65 kind `10002`
  provide profile and outbox discovery. Required custom identity pointers and
  public feed indexes are retired.
- **Source-neutral state.** Relays and repositories carry the same exact
  signed event bytes. Clients union valid candidates and apply NIP-01 current-
  state selection without giving either carrier authority by location.
- **Persona-owned repositories.** A RID locates durable event storage; it is
  not an identity. Only owner-authorized writer refs enter the accepted union,
  and Nostr signatures remain authoritative for event authorship.
- **Warning-only freshness.** Publishing clients refresh kind `0` and kind
  `10002` at least every seven days. Overdue state produces a warning, never
  signature invalidity.
- **Standard Marmot operation.** The active persona key is the Marmot account.
  Every device keeps an independent leaf, and succession changes accounts
  through explicit standard group operations rather than aliasing identities.
- **Accountable automation.** Agent-key signing is preferred. Persona-key
  signing requires explicit scope, and every automated intent receives
  NIP-32-compatible attribution before any signature.
- **Full-node signing policy.** A full node may manage isolated vaults and
  sign under exact NIP-46/OIDC grants. It is not required to be a relay or
  repository host and gains no persona authority merely by operating.
- **Replaceable trusted seeds.** Several trusted seed NIDs may concurrently
  provide repository availability and public or private relay service. Each
  writes only its authorized ref and receives no persona, repository-owner,
  group-admin, full-node, or MLS authority.
- **Complete compromise reset.** Active-key compromise revokes NIP-46/OIDC
  grants, invalidates every subordinate authority and seed, removes old
  Marmot leaves, advances reachable groups, publishes fresh KeyPackages, and
  explicitly reauthorizes every continuing subordinate.
- **Optional enhanced assurance.** Existing Nostr users may attach cold-root
  and KERI continuity later without rotating the active key. Assurance never
  changes NIP-01 authorship, filtering, replacement, or Marmot membership.

Vanilla Nostr relays, Radicle nodes, and standard Marmot implementations do not
need Heterodyne-specific changes. Heterodyne extensions remain ignorable and
must not interfere with baseline protocol behavior.

## 0.x conformance

Every implementation claims Core. Comms, Assurance, Control, Social, and
Workspace claims are separately composable according to the graph. A claim
names the family version, registry revision or digest, feature IDs, and any
strict profiles. The required invariant set is the transitive closure of the
claimed profiles and features.

The registered strict profile IDs are:

- `heterodyne-core-strict-v1`
- `heterodyne-assurance-strict-v1`
- `heterodyne-comms-strict-v1`
- `heterodyne-control-strict-v1`
- `heterodyne-social-strict-v1`
- `heterodyne-workspace-strict-v1`

Assurance remains a separately composable optional document claim even when
its document-specific strict profile is claimed. There is no singular strict
profile for the six-document family.

## Current draft versus frozen snapshot

The live specifications, registry, schemas, and current reference semantics
are validated independently from the one frozen historical vector snapshot.
That snapshot is non-normative evidence for source commit
`2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, is history-bound to snapshot
commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`, and contains exactly 482
vectors. Ordinary draft work does not regenerate its vector payloads,
fixtures, packaged schema, reason/coverage projections, or metadata.

Run the two read-only lanes separately:

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

`draft:check` validates current prose, schemas, registry, and reference
semantics without executing frozen pre-redesign topic projections.
`snapshot-check` materializes the pinned source and snapshot history, uses the
historical generator and packager, and verifies the exact 482-vector corpus.
A dedicated reconciliation maintainer alone selects a future stable source,
runs `snapshot-author`, reviews the complete replacement, commits it, and then
runs `snapshot-check`.

The shared hosted/local gate is:

```bash
scripts/conformance-ci.sh
```

## Repository map

| Path | Purpose |
|---|---|
| [docs/spec/heterodyne.md](docs/spec/heterodyne.md) | Non-normative family map |
| [docs/spec/heterodyne-core.md](docs/spec/heterodyne-core.md) | Core normative document |
| [docs/spec/heterodyne-assurance.md](docs/spec/heterodyne-assurance.md) | Assurance normative document |
| [docs/spec/heterodyne-comms.md](docs/spec/heterodyne-comms.md) | Comms normative document |
| [docs/spec/heterodyne-control.md](docs/spec/heterodyne-control.md) | Control normative document |
| [docs/spec/heterodyne-social.md](docs/spec/heterodyne-social.md) | Social normative document |
| [docs/spec/heterodyne-workspace.md](docs/spec/heterodyne-workspace.md) | Workspace normative document |
| [docs/spec/registry](docs/spec/registry/) | Current kind, profile, reason, invariant, feature, object, and proof-domain registry |
| [docs/spec/schemas](docs/spec/schemas/) | Current protocol schemas |
| [docs/spec/vectors](docs/spec/vectors/) | Frozen rolling validation snapshot and snapshot tooling |
| [docs/spec/conformance](docs/spec/conformance/) | Independent read-only conformance harness |
| [docs/architecture.md](docs/architecture.md) | Non-normative architecture |
| [docs/glossary.md](docs/glossary.md) | Non-normative term index |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Family threat analysis |
| [docs/adr](docs/adr/) | Non-canonical decision-record staging and archive |
| [research/INDEX.md](research/INDEX.md) | Topic-keyed preserved research index |

## Standards

- [Nostr NIPs](https://github.com/nostr-protocol/nips), including NIP-01,
  NIP-05, NIP-32, NIP-42, NIP-46, NIP-51, NIP-65, and NIP-72
- [Marmot](https://github.com/marmot-protocol/marmot) and
  [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [Radicle Heartwood](https://radicle.xyz)
- [KERI](https://arxiv.org/abs/1907.02143) for optional Assurance
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  and [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

## License

The specification and documentation are licensed under
[CC BY 4.0](LICENSE).
