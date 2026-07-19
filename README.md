# Heterodyne

Heterodyne is a decentralized protocol family for portable personas,
authenticated communication, own-device control, and social interaction. It
uses Nostr signed events, Radicle-backed durable storage, and an optional
Matrix feature for real-time group communication.

The project is specification-first and implementation-agnostic. All current
documents are 0.x drafts and may make breaking changes before 1.0.

[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is the non-normative
family map. Normative authority is divided among the four versioned documents
below; the former 0.4.0 monolith is frozen in the archive.

## Protocol family

The family has four independently versioned documents:

| Document | Current lineage | Responsibility |
|---|---:|---|
| [Heterodyne Core](docs/spec/heterodyne-core.md) | `core/0.5.0` | Persona identity, KEL verification, canonical Nostr bytes, Radicle delegation, node roles, repository substrate, registry, versioning, and base conformance. |
| [Heterodyne Comms](docs/spec/heterodyne-comms.md) | `comms/0.5.0` | Nostr-native envelopes, privacy tiers, publishing, retrieval, feeds, double-ratchet direct messages, credential sync, and encrypted subprotocol carriage. |
| [Heterodyne Control](docs/spec/heterodyne-control.md) | `control/0.5.0` | Own-device enrollment, grants, RPC, and agentic sessions as a Comms profile. This release is incomplete and not claimable. |
| [Heterodyne Social](docs/spec/heterodyne-social.md) | `social/0.5.0` | Following, interactions, moderation, lists, social discovery, ATProto attachment, and optional Matrix behavior. |

The dependency graph is exactly:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

Versions are qualified per document. `core/0.5.0` and `social/0.5.0`, for
example, are independent releases rather than one synchronized family version.
The frozen [0.4.0 archive](docs/spec/archive/heterodyne-0.4.0.md) preserves the
former monolith bytes. The complete
[old-section anchor map](docs/spec/archive/heterodyne-0.4.0-anchor-map.md)
redirects historical section links.

## What the family provides

- **Portable identity.** A persona is anchored by a cold-root Nostr npub and
  an accepted KERI key-event log. Rotating epoch keys handle routine signing;
  Radicle node identities are dual-proof delegated.
- **Plural storage and delivery.** Ordinary Nostr relays and Radicle-backed
  repo relays carry signed content. Browsers and phones can remain light
  clients and verify locally.
- **Honest privacy boundaries.** Tier 1 is public. Tier 2 is selectively
  replicated plaintext on allowed seeders. Tier 3 is encrypted before any
  repository or carrier receives it.
- **Forward-secret direct messages.** Comms uses a Signal-style double ratchet
  over Nostr events, with no repository retention or backfill. NIP-17 remains
  an interoperability fallback with weaker guarantees.
- **Independent feature growth.** Control and Social both build on Comms but do
  not depend on each other. Matrix remains optional inside Social.
- **Client-side trust.** Relays, full nodes, routing nodes, and Matrix
  homeservers are carriers. Identity, decryption, bridging, and policy
  evaluation remain on user-controlled clients.

## 0.5.0 conformance

Every implementation claims Core. A Heterodyne persona claims Core+Comms.
Social and Social+Matrix are distinct claims. Control requires a conformant
Core+Comms implementation plus the Control profile, but the current incomplete
Control release cannot be claimed.

Claims name exact qualified versions, required features, registry revision or
digest, and any strict profiles. The stable strict IDs are:

- `heterodyne-core-strict-v1`
- `heterodyne-comms-strict-v1`
- `heterodyne-control-strict-v1` (reserved-inactive)
- `heterodyne-social-strict-v1`
- `heterodyne-social-matrix-strict-v1`

Conformance vectors in [docs/spec/vectors](docs/spec/vectors/) are normative
for the behavior they cover. Canonical bytes and expected verdicts must match
exactly; semantic similarity is not conformance.

## Repository map

| Path | Purpose |
|---|---|
| [docs/spec/heterodyne.md](docs/spec/heterodyne.md) | Non-normative family overview and document map |
| [docs/spec/heterodyne-core.md](docs/spec/heterodyne-core.md) | Core 0.5.0 normative document |
| [docs/spec/heterodyne-comms.md](docs/spec/heterodyne-comms.md) | Comms 0.5.0 normative document |
| [docs/spec/heterodyne-control.md](docs/spec/heterodyne-control.md) | Incomplete Control 0.5.0 profile |
| [docs/spec/heterodyne-social.md](docs/spec/heterodyne-social.md) | Social 0.5.0 normative document |
| [docs/spec/registry](docs/spec/registry/) | Core-owned kind, profile, reason-code, and invariant registry |
| [docs/spec/vectors](docs/spec/vectors/) | Normative conformance vectors and verification tooling |
| [docs/architecture.md](docs/architecture.md) | Non-normative family architecture and rationale |
| [docs/glossary.md](docs/glossary.md) | Non-normative term index |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Family threat analysis |
| [docs/adr](docs/adr/) | Architecture Decision Records |
| [research/INDEX.md](research/INDEX.md) | Topic-keyed research index |

## Working on Heterodyne

Start with the family document that owns the behavior you are changing, then
read the relevant ADR and registry entry. Wire changes require corresponding
conformance vectors. Material decisions require an ADR. Files under
`research/sources/` are preserved research artifacts and must not be edited.

Useful checks:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

## Standards

Heterodyne composes established standards rather than defining new
cryptography or backend protocols:

- [Nostr NIPs](https://github.com/nostr-protocol/nips), including NIP-01,
  NIP-44, NIP-49, NIP-51, NIP-65, NIP-72, and NIP-78
- [Radicle](https://radicle.xyz) Heartwood repositories and signed refs
- [KERI](https://arxiv.org/abs/1907.02143) and the
  [ToIP KSWG specification](https://trustoverip.github.io/kswg-keri-specification/)
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Matrix](https://spec.matrix.org/latest/) and
  [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)

## License

The specification and documentation are licensed under
[CC BY 4.0](LICENSE).
