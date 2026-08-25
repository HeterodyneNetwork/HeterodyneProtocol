# Future NIP extractions

This is an upstream-facing, non-normative extraction index. It is not a home
for sibling Heterodyne protocols and it does not allocate NIP numbers.

[`docs/spec/heterodyne.md`](../../heterodyne.md) is the non-normative map for
the six-document family: [Core](../../heterodyne-core.md),
[Assurance](../../heterodyne-assurance.md),
[Comms](../../heterodyne-comms.md),
[Control](../../heterodyne-control.md),
[Social](../../heterodyne-social.md), and
[Workspace](../../heterodyne-workspace.md). The qualified owner anchors below
are the current normative references.

The active Nostr public key is the baseline persona identity. A bare active key
is first-class; optional Assurance adds continuity and recovery without
changing NIP-01 authorship or Marmot account identity. Candidate NIPs must keep
repository and relay observations source-neutral and must remain usable by
vanilla Nostr relays and standard Marmot implementations.

## Candidate extractions

| Qualified family source | Working title | Generalized scope |
|---|---|---|
| `heterodyne:0.5.0#core-discovery` | Source-neutral Nostr repository discovery | Active-key-signed hints for persona-owned repositories, serving nodes, and relays without making any carrier authoritative. |
| `heterodyne:0.5.0#assurance-continuity` | Optional Nostr account continuity | Reciprocal active-key and recovery-authority enrollment, explicit succession, and non-aliasing continuity as an opt-in layer. |
| `heterodyne:0.5.0#comms-marmot-radicle-routing` | Marmot archive routing through Radicle | Exact-byte encrypted-event archiving and routing authorization that preserves upstream Marmot semantics. |
| `heterodyne:0.5.0#comms-trusted-seeds` | Concurrent trusted-seed discovery | Availability-oriented seed grants with no canonical seed and no identity, repository-owner, group-admin, or MLS authority. |
| `heterodyne:0.5.0#social-moderation` | Anchored editorial approvals | Likely an amendment or profile around NIP-72 rather than a new NIP. |
| `heterodyne:0.5.0#social-lists` | Stamped Social list profile | A general profile-marker approach that preserves plain NIP-51 interoperability. |

Control is a Comms-carried application profile, so this directory does not
host Control protocol drafts. A reusable Control behavior needs an upstream
venue and an independently reviewed boundary.

## Coordination

- NIP numbering is assigned upstream; local drafts use descriptive slugs.
- Kind and profile allocation comes from the current Core registry, not a
  numeric-range assumption.
- Each extracted draft records its source specification anchor and immutable
  profile discriminator where applicable.
- Track NIP-01, NIP-05, NIP-46, NIP-65, NIP-72, NIP-78, NIP-85, and Marmot for
  upstream changes that may replace family behavior.
- Historical topic projections and the rolling vector snapshot are frozen
  validation history, not extraction sources for the current draft.
