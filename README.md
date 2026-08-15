# Heterodyne

**Own your social identity.** No company owns it, nobody's required to host
it. Any device with an internet connection can share content, whether public
or private, and nobody can take it away. You can host it yourself publicly or
anonymously. **You can't stop the signal!**

**Repository mirrors:** [GitHub](https://github.com/HeterodyneNetwork/HeterodyneProtocol)
· [Radicle](https://radicle.network/nodes/iris.radicle.network/rad:z2zX5XvPiggGJvCn8DPkp1hRNGA5)

Heterodyne is a decentralized protocol family for portable personas,
authenticated communication, own-device control, and social interaction. It
uses Nostr signed events, Radicle-backed durable storage, and Marmot for
encrypted direct and group communication.

The project is specification-first and implementation-agnostic. All current
documents are 0.x drafts and may make breaking changes before 1.0.

[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is the non-normative
family map. Normative authority is divided among the five versioned documents
below.

## Protocol family

The family has five independently versioned documents:

| Document | Prepared version | Responsibility |
|---|---:|---|
| [Heterodyne Core](docs/spec/heterodyne-core.md) | `core/0.5.0` | Persona identity, KEL verification, canonical Nostr bytes, Radicle delegation, node roles, repository substrate, registry, versioning, and base conformance. |
| [Heterodyne Comms](docs/spec/heterodyne-comms.md) | `comms/0.5.0` | Nostr-native envelopes, privacy tiers, publishing, Marmot conversations and media, Radicle conversation storage, atomic key claims, the private claim ledger, and the OIDC/JWT projection. |
| [Heterodyne Control](docs/spec/heterodyne-control.md) | `control/0.5.0` | Active own-device enrollment, grants, RPC, node-mediated Marmot access, and agentic sessions as a Comms profile. |
| [Heterodyne Social](docs/spec/heterodyne-social.md) | `social/0.5.0` | Public following, interactions, moderation, lists, social discovery, durable assets, and ATProto attachment. |
| [Heterodyne Workspace](docs/spec/heterodyne-workspace.md) | `workspace/0.1.0` | Independently governed workspaces, roles, private discovery, federation, hosting, and resource-key delivery. |

The allowed composition graph is exactly; Workspace's solid base dependency
is Core+Comms, while its Control and Social edges are optional:

```text
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

These prepared 0.x documents are current normative authority in the
repository, but remain unreleased pending explicit release approval.

Versions are qualified per document. `core/0.5.0` and `social/0.5.0`, for
example, are independent releases rather than one synchronized family version.

## What the family provides

- **Portable identity.** A persona is anchored by a cold-root Nostr npub and
  an accepted KERI key-event log. Rotating epoch keys handle routine signing;
  Radicle node identities are dual-proof delegated.
- **Plural storage and delivery.** Ordinary Nostr relays and Radicle-backed
  repo relays carry signed content. Full nodes are onion services by default;
  light clients should use outbound Tor and verify locally. Browser tabs may
  use an authenticated shared relay with an explicit reduced-assurance
  indicator.
- **Universal public reading.** A centrally hosted static browser client can
  open one fragment-only persona/event link, resolve public content locally
  from supplied and discovered clearnet relays, and render verified Tier 1
  without learning the target at the web origin.
- **Honest privacy boundaries.** Tier 1 is public. Tier 2 is selectively
  replicated plaintext on allowed seeders. Tier 3 is encrypted before any
  repository or carrier receives it.
- **Encrypted conversations and media.** Comms adopts pinned Marmot semantics
  for MLS groups, two-member direct conversations, application events, and
  encrypted media. Standard Nostr delivery and Radicle-backed delivery preserve
  the same signed event and ciphertext bytes.
- **Key claims and interoperable tokens.** Comms verifies atomic claims about
  typed keys against a persona's encrypted multi-writer ledger. Its OIDC/JWT
  surface is a consent-limited projection for third-party interoperability,
  never the canonical authorization source; canonical device authority stays
  in verified private-ledger state.
- **Accountable automation.** AI and programmatic publishers receive only
  scoped, temporary, sender-constrained workload tokens. A full node adds
  canonical agent attribution and signs with a stable dedicated role key that
  is never released to the agent; direct user-device signing is forbidden.
- **Workspace collaboration.** Workspace roles distribute private policy,
  resource and service advertisements, bilateral allowances, host selection,
  and independently rotated resource keys across organizational boundaries.
- **Independent feature growth.** Control and Social are independent Comms
  siblings. Workspace composes them only for optional RPC and social-policy
  integrations.
- **Client-side trust.** Relays, full nodes, routing nodes, and Radicle hosts
  are carriers or designated endpoints. Identity, decryption, authorization,
  and policy evaluation remain within user-controlled clients and nodes.

## 0.x conformance

Every implementation claims Core. A Heterodyne persona claims Core+Comms.
Social adds public social behavior. Control requires a conformant Core+Comms
implementation plus the active Control profile. Workspace requires Core+Comms;
its Control and Social compositions are optional and separately advertised.

Claims name exact qualified versions, required features, registry revision or
digest, and any strict profiles. The stable strict IDs are:

- `heterodyne-core-strict-v1`
- `heterodyne-comms-strict-v1`
- `heterodyne-comms-strict-v2`
- `heterodyne-control-strict-v1`
- `heterodyne-social-strict-v1`
- `heterodyne-social-strict-v2`
- `heterodyne-workspace-strict-v1`

Conformance vectors in [docs/spec/vectors](docs/spec/vectors/) are normative
for the behavior they cover. Canonical bytes and expected verdicts must match
exactly; semantic similarity is not conformance.

## Repository map

| Path | Purpose |
|---|---|
| [docs/spec/heterodyne.md](docs/spec/heterodyne.md) | Non-normative family overview and document map |
| [docs/spec/heterodyne-core.md](docs/spec/heterodyne-core.md) | Core 0.5.0 normative document |
| [docs/spec/heterodyne-comms.md](docs/spec/heterodyne-comms.md) | Comms 0.5.0 normative document |
| [docs/spec/heterodyne-control.md](docs/spec/heterodyne-control.md) | Active Control 0.5.0 profile |
| [docs/spec/heterodyne-social.md](docs/spec/heterodyne-social.md) | Social 0.5.0 normative document |
| [docs/spec/heterodyne-workspace.md](docs/spec/heterodyne-workspace.md) | Workspace 0.1.0 normative document |
| [docs/spec/registry](docs/spec/registry/) | Core-owned kind, profile, reason-code, and invariant registry |
| [docs/spec/releases](docs/spec/releases/) | Untagged per-document release manifests pinned to an exact registry snapshot |
| [docs/spec/vectors](docs/spec/vectors/) | Normative conformance vectors and verification tooling |
| [docs/architecture.md](docs/architecture.md) | Non-normative family architecture and rationale |
| [docs/glossary.md](docs/glossary.md) | Non-normative term index |
| [docs/security/threat-model.md](docs/security/threat-model.md) | Family threat analysis |
| [docs/adr](docs/adr/) | Non-canonical decision-record staging and archive |
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
- [Marmot](https://github.com/marmot-protocol/marmot) and
  [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  and [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html),
  with the OAuth/JWT sources indexed in [AGENTS.md](AGENTS.md)

## License

The specification and documentation are licensed under
[CC BY 4.0](LICENSE).
