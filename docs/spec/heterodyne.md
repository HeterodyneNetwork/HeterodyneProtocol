# Heterodyne Protocol Family

This page is the non-normative family overview and navigation map. Normative
requirements live only in the independently versioned documents linked below.

Heterodyne is a decentralized protocol family built from Nostr signed events,
Marmot conversations and encrypted media, and Radicle-backed durable
repositories. A persona's KERI-anchored cold-root npub remains authoritative
independently of the relay, repository host, or Marmot account carrying its
activity.

Canonical persona metadata lives in the public Radicle profile repository and
is mirrored to ordinary Nostr by one delegated profile publisher. Tier 3
delivery targets active delegated device keys, allowing authenticated light
clients to decrypt without bringing the persona cold root or epoch key online.
The exact adopted Marmot specification bytes are vendored under
[`external/marmot/`](external/marmot/) with a closed digest manifest.

## Document graph

The family dependency graph is:

```text
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

Control and Social are siblings above Comms. Workspace is a higher-layer
organizational control plane: its base profile uses Core and Comms, while
optional compositions add Control and Social without creating a cycle.

## Prepared documents

| Document | Prepared version | Scope | Status |
|---|---|---|---|
| [Core](heterodyne-core.md) | `core/0.5.0` | Identity, KEL verification, node roles, repositories, registry, versioning, and base conformance | Normative |
| [Comms](heterodyne-comms.md) | `comms/0.5.0` | Privacy tiers, publishing, Marmot conversations and media, Radicle conversation storage, atomic key claims, private claim ledger, and OIDC/JWT projection | Normative |
| [Control](heterodyne-control.md) | `control/0.5.0` | Marmot-carried own-device enrollment, grants, RPC, node-mediated operations, agent semantics, and optional recovery | Normative 0.x |
| [Social](heterodyne-social.md) | `social/0.5.0` | Public social graph, interactions, moderation, lists, durable assets, and ATProto attachment | Normative 0.x |
| [Workspace](heterodyne-workspace.md) | `workspace/0.1.0` | Independently governed workspaces, roles, private discovery, cross-workspace allowances, hosts, and resource-key delivery | Normative 0.x |

Core, Comms, Control, and Social are independent version lineages descended
from the 0.4.x monolith. Workspace begins its own independent lineage at
`workspace/0.1.0`; family versions are not synchronized. Their contents are
current normative authority at these repository paths. All prepared artifacts
remain unreleased pending explicit release approval.
Machine-readable prepared-release manifests are under
[`releases/`](releases/).

## Conformance classes

| Claim | Document combination | Feature notes |
|---|---|---|
| Core | `core/0.5.0` | Baseline for every implementation |
| Heterodyne persona | `core/0.5.0` + `comms/0.5.0` | Standard-compatible or Radicle-private Marmot conversations |
| Social | Core + Comms + `social/0.5.0` | Public social behavior and durable assets |
| Control profile | Core + Comms + `control/0.5.0` | Standard Marmot carriage; recovery features are optional independent claims |
| Workspace | Core + Comms + `workspace/0.1.0` | Role control plane with Radicle transport backstop; Control and Social compositions are optional |

Exact versions, registry revision or digest, feature IDs, and strict-profile
IDs belong in each conformance claim.

Core distinguishes public-reader, authenticated-light, and full-node roles.
Full nodes are persistent v3 onion services with Tor-default backend egress.
Light clients should implement outbound Tor; a browser tab without it may use
an authenticated shared relay only as explicit reduced-assurance operation.

Comms defines a universal fragment-only public launcher for locally resolving
verified Tier-1 persona content. It also requires every AI or programmatic
publisher to use a scoped temporary OIDC workload token and a dedicated,
full-node-held agent role key; automation cannot fall back to user device keys
or unlabeled publication. Social policy receipts are public information, while
only subscribed verified canonical policy lists affect local visibility.

## Machine-readable material

- Current registry pin: [`registry/manifest.json`](registry/manifest.json)
- Registry entries and schemas: [`registry/`](registry/)
- Normative vector corpus: [`vectors/`](vectors/)
- Machine-readable family vector coverage: [`vectors/coverage/manifest.json`](vectors/coverage/manifest.json)
- Human-readable family vector coverage: [`vectors/coverage/family.md`](vectors/coverage/family.md)
- Per-document coverage maps: [`vectors/coverage/`](vectors/coverage/)
