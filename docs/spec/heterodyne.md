# Heterodyne Protocol Family

This page is the non-normative family overview and navigation map. Normative
requirements live only in the documents linked below.

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

The five documents ship as one specification at one version. They are split
for readability and to keep the blast radius of a change inside one section;
each document may normatively depend only on the documents below it:

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

| Document | Scope | Status |
|---|---|---|
| [Core](heterodyne-core.md) | Identity, KEL verification, node roles, repositories, registry, versioning, and base conformance | Normative |
| [Comms](heterodyne-comms.md) | Privacy tiers, publishing, Marmot conversations and media, Radicle conversation storage, atomic key claims, private claim ledger, and OIDC/JWT projection | Normative |
| [Control](heterodyne-control.md) | Marmot-carried own-device enrollment, grants, RPC, node-mediated operations, agent semantics, and optional recovery | Normative 0.x |
| [Social](heterodyne-social.md) | Public social graph, interactions, moderation, lists, durable assets, and ATProto attachment | Normative 0.x |
| [Workspace](heterodyne-workspace.md) | Independently governed workspaces, roles, private discovery, cross-workspace allowances, hosts, and resource-key delivery | Normative 0.x |

All five documents carry the single family version `heterodyne/0.5.0` and pin
the one registry revision recorded in
[`registry/manifest.json`](registry/manifest.json). Their contents are current
normative authority at these repository paths. All prepared artifacts remain
unreleased pending explicit release approval.

No pre-1.0 release manifest exists. The five specifications, protocol schemas,
and registry remain the current authority; release and compatibility metadata
is deferred to the future 1.0 policy.

## Conformance classes

| Claim | Documents | Feature notes |
|---|---|---|
| Core | Core | Baseline for every implementation |
| Heterodyne persona | Core + Comms | Standard-compatible or Radicle-private Marmot conversations |
| Social | Core + Comms + Social | Public social behavior and durable assets |
| Control profile | Core + Comms + Control | Standard Marmot carriage; recovery features are optional independent claims |
| Workspace | Core + Comms + Workspace | Role control plane with Radicle transport backstop; Control and Social compositions are optional |

Every claim names the family version, the registry revision or digest, the
feature IDs, and the strict-profile IDs it satisfies. A document class is an
entry point, not a bill of materials: the invariants a claim owes follow from
its baseline plus the features it actually claims, so a persona that only
sends and receives owes nothing from the claims, OIDC, status, or agent
stacks.

Core distinguishes public-reader, authenticated-light, and full-node roles.
Full nodes are persistent v3 onion services with Tor-default backend egress.
Light clients should implement outbound Tor; a browser tab without it may use
an authenticated shared relay only as explicit reduced-assurance operation.

Comms defines a universal fragment-only public launcher for locally resolving
verified Tier-1 persona content. An implementation that works with agents
additionally requires every AI or programmatic publisher to use a scoped
temporary OIDC workload token and a dedicated, full-node-held agent role key;
automation cannot fall back to user device keys or unlabeled publication. That
is the one path that makes the OIDC issuer mandatory, and it is why
`comms.agent-authorship.v1` requires `comms.oidc-jwt-projection.v1`. Social
policy receipts are public information, while only subscribed verified
canonical policy lists affect local visibility.

## Machine-readable material

- Current registry pin: [`registry/manifest.json`](registry/manifest.json)
- Registry entries and schemas: [`registry/`](registry/)
- Rolling non-normative validation snapshot: [`vectors/`](vectors/)
- Machine-readable family vector coverage: [`vectors/coverage/manifest.json`](vectors/coverage/manifest.json)
- Human-readable family vector coverage: [`vectors/coverage/family.md`](vectors/coverage/family.md)
- Per-document coverage maps: [`vectors/coverage/`](vectors/coverage/)
