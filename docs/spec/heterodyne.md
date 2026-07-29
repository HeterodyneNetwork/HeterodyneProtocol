# Heterodyne Protocol Family

This page is the non-normative family overview and navigation map. Normative
requirements live only in the independently versioned documents linked below.

Heterodyne is a decentralized protocol family built from Nostr signed events,
Radicle-backed durable repositories, and an optional Matrix feature. A
persona's KERI-anchored cold-root npub remains authoritative independently of
the relay, repository host, or Matrix account carrying its activity.

## Document graph

The family dependency graph is:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Control and Social are siblings above Comms. Social has no dependency on
Control; clients can compose their independently stated claims.

## Prepared 0.5.0 documents

| Document | Prepared version | Scope | Status |
|---|---|---|---|
| [Core](heterodyne-core.md) | `core/0.5.0` | Identity, KEL verification, node roles, repositories, registry, versioning, and base conformance | Normative |
| [Comms](heterodyne-comms.md) | `comms/0.5.0` | Privacy tiers, publishing, direct messages, atomic key claims, private claim ledger, and OIDC/JWT projection | Normative |
| [Control](heterodyne-control.md) | `control/0.5.0` | Own-device enrollment, grants, RPC, and agentic semantics over Comms | Incomplete draft; not claimable |
| [Social](heterodyne-social.md) | `social/0.5.0` | Social graph, interactions, moderation, lists, ATProto attachment, and the Matrix feature | Normative 0.x |

These are four independent version lineages descended from the 0.4.x
monolith, not a synchronized family version. Their contents are current
normative authority at these repository paths. The 0.5.0 artifacts remain
unreleased pending explicit release approval.
Machine-readable prepared-release manifests are under
[`releases/`](releases/).

## Conformance classes

| Claim | Document combination | Feature notes |
|---|---|---|
| Core | `core/0.5.0` | Baseline for every implementation |
| Heterodyne persona | `core/0.5.0` + `comms/0.5.0` | Direct-ratchet messaging is separately feature-qualified |
| Social | Core + Comms + `social/0.5.0` | Matrix-free social behavior |
| Social+Matrix | Social plus its Matrix feature | Adds the complete Matrix behavior set |
| Control profile | Core + Comms + `control/0.5.0` + `double-ratchet` | Gate closed while Control remains incomplete |

Exact versions, registry revision or digest, feature IDs, and strict-profile
IDs belong in each conformance claim.

## Migration and machine-readable material

- Frozen 0.4.0 bytes: [`archive/heterodyne-0.4.0.md`](archive/heterodyne-0.4.0.md)
- Old-heading migration map: [`archive/heterodyne-0.4.0-anchor-map.md`](archive/heterodyne-0.4.0-anchor-map.md)
- Current registry pin: [`registry/manifest.json`](registry/manifest.json)
- Registry entries and schemas: [`registry/`](registry/)
- Normative vector corpus: [`vectors/`](vectors/)
- Machine-readable family vector coverage: [`vectors/coverage/manifest.json`](vectors/coverage/manifest.json)
- Human-readable family vector coverage: [`vectors/coverage/family.md`](vectors/coverage/family.md)
- Per-document coverage maps: [`vectors/coverage/`](vectors/coverage/)

The archive preserves historical signed-byte interpretation. The migration map
redirects old section links to permanent, version-qualified family anchors.
