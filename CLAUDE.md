# Heterodyne project orientation

Heterodyne is a decentralized protocol family built from Nostr signed events,
Radicle-backed durable repositories, and an optional Matrix feature. A
persona's cold-root npub remains authoritative independently of whichever
relay, repository host, or Matrix account currently carries its activity.

The protocol is implementation-agnostic and in its 0.x phase. Breaking changes
between 0.x releases are permitted. Do not promise backward compatibility
before 1.0.

[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is the non-normative
family map. Normative authority is divided among the four independently
versioned documents below. The 0.4.0 monolith is frozen under
[`docs/spec/archive/`](docs/spec/archive/).

## 0.5.0 family

The prepared 0.5.0 documents are current normative authority in the repository
but remain unreleased pending explicit release approval.

| Document | Owns |
|---|---|
| [`docs/spec/heterodyne-core.md`](docs/spec/heterodyne-core.md) | Identity, KEL, canonical bytes, delegations, node roles, repositories, registry, versioning, and base conformance |
| [`docs/spec/heterodyne-comms.md`](docs/spec/heterodyne-comms.md) | Privacy tiers, publishing, direct messages, atomic key claims, the private claim ledger, and OIDC/JWT projection |
| [`docs/spec/heterodyne-control.md`](docs/spec/heterodyne-control.md) | Own-device enrollment, grants, RPC, and agentic semantics; currently incomplete and non-claimable |
| [`docs/spec/heterodyne-social.md`](docs/spec/heterodyne-social.md) | Social graph, interactions, moderation, lists, ATProto attachment, and optional Matrix behavior |

The only normative dependency edges are:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Social never depends on Control. Client implementations may compose the two
claims. Document versions are independent qualified identifiers such as
`core/0.5.0` and `comms/0.5.0`; there is no synchronized family version.

The [anchor migration map](docs/spec/archive/heterodyne-0.4.0-anchor-map.md)
redirects old monolith section links to permanent family anchors.

## Core design intuition

- Nostr signatures are the canonical authorship proof.
- A KERI cold root anchors the persona; rotating epoch keys sign routine
  attestations.
- Ordinary Nostr relays and Radicle-backed repo relays are co-equal Comms
  carriers. Light clients verify locally.
- Tier 1 is public, Tier 2 is selectively replicated plaintext, and Tier 3 is
  encrypted before storage.
- Double-ratchet direct messages are Comms behavior and have no repository
  backfill.
- Persona-issued device authority is resolved from the encrypted private claim
  ledger. OIDC and JWT are interoperable projections, not canonical
  authorization.
- Matrix is optional inside Social and never supplies persona authority.
- Control is a Comms profile, not another transport.

## Conformance shape

Under the 0.5.0 rules, every implementation claims Core.
A Heterodyne persona claims Core+Comms.
Social and Social+Matrix are separate claims. Control requires Core+Comms plus
the Control profile, but its 0.5.0 gate remains closed.

Claims pin exact document versions, registry revision or digest, features, and
strict-profile IDs. Wire conformance is byte-exact. Vectors are normative for
covered behavior.

## Repository map

| Path | Purpose |
|---|---|
| `docs/spec/heterodyne.md` | Non-normative family overview and map |
| `docs/spec/heterodyne-core.md` | Core 0.5.0 normative document |
| `docs/spec/heterodyne-comms.md` | Comms 0.5.0 normative document |
| `docs/spec/heterodyne-control.md` | Incomplete Control 0.5.0 profile |
| `docs/spec/heterodyne-social.md` | Social 0.5.0 normative document |
| `docs/spec/registry/` | Core-owned revisioned allocation registry |
| `docs/spec/releases/` | Untagged per-document release manifests and schema |
| `docs/spec/vectors/` | Normative vectors plus generator tooling |
| `docs/spec/archive/` | Frozen 0.4.0 monolith and anchor map |
| `docs/adr/` | Architecture Decision Records |
| `docs/architecture.md` | Non-normative architecture rationale |
| `docs/glossary.md` | Non-normative term index |
| `docs/security/threat-model.md` | Family threat analysis |
| `research/INDEX.md` | Topic-keyed index into immutable research sources |

## Working rules

- Material decisions go through ADRs. Numbering is global and sequential.
- Wire-level behavior changes require conformance-vector updates.
- Do not edit `research/sources/`; update `research/INDEX.md` or authored design
  documents instead.
- Keep the dependency DAG downward-only. Normative cross-document references
  use a qualified `heterodyne:<doc>/<version>#<anchor>` URI.
- Keep Core self-contained. Comms may depend on Core; Control and Social may
  depend on Comms and Core; Social must not depend on Control.
- Do not infer kind ownership from number ranges. Use the pinned registry and
  immutable profile discriminator.
- Control has no wire-stamp authority. Its session payloads use Comms carriers.
- Vanilla relays, Radicle nodes, and Matrix homeservers require no
  Heterodyne-specific server changes.

## Where to research

Start at [`research/INDEX.md`](research/INDEX.md), which maps topics to exact
line ranges in preserved source reports. For standards behavior, use the
authoritative links in [`AGENTS.md`](AGENTS.md) rather than memory.

## Verification

From the repository root:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

The first validates document DAG, registry, and family prose. The second runs
the generator tests and verifies the authored vector corpus.
