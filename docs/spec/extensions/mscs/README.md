# Future MSC extractions

This directory tracks which sections of the Heterodyne specification
could eventually be proposed as Matrix Spec Changes (MSCs) for adoption
by the broader Matrix ecosystem. It is a forward-reference index; the
proposals themselves do not exist yet.

## Candidate extractions

| Spec section | Working title | Generalized scope |
|---|---|---|
| §3.2 Identity room | "Identity rooms with external cryptographic anchors" | A conventional Matrix room cryptographically bound to an external identity (Nostr `secp256k1`, or any other algorithm). Could generalize MSC1769 (extensible profiles as rooms) and complement MSC2313 (policy rooms). |
| §3.3 Delegation | "Cross-identity delegation state events" | A Matrix-native way to express "this MXID acts on behalf of external identity X with cryptographic proof." Useful well beyond Heterodyne (e.g., for any federated identity system that wants to use Matrix as a publish substrate). |
| §4.2 Wrapped event | (probably no MSC) | The `m.heterodyne.note.v1` event type stays vendor-specific; not a candidate for upstream MSC. |
| §4.3 Wrap-mode signaling | "Optional external authenticity attachments on `m.room.message`" | A generic `external_signature` field for any external signature scheme on standard Matrix messages. Useful for any system that wants to add cryptographic authenticity to Matrix messages without minting a new event type. |
| §8 Moderation | (no MSC needed) | Reuses MSC2313 policy rooms verbatim. |
| §9 Encryption guarantees | (already MSC4362) | Encrypted state events are already in the Matrix MSC pipeline. We track and consume. |

Each row should grow into its own subdirectory (`<NNNN>-<slug>/`) with
an MSC draft when the corresponding spec section stabilizes. The draft
should target the [`matrix-org/matrix-spec-proposals`](https://github.com/matrix-org/matrix-spec-proposals)
contribution model: a single markdown file with proposal, alternatives,
security considerations, unstable prefix, and dependencies.

## Coordination notes

- Track upstream MSC4362 (encrypted state events) — Heterodyne depends
  on it for §9.
- Track upstream MSC1769 (profile rooms) — partial overlap with §3.2;
  Heterodyne's identity room is a more specific use of the same idea.
- Track upstream MSC2313 (moderation policy rooms) — Heterodyne uses it
  unmodified in §8.
- Track upstream MSC2836 (free-form threading) — relevant if §5 / §6
  adopts arbitrary-depth thread modeling for social-media-style
  conversations.
- Any MSC we author should mark itself "in flight" here with a link to
  the upstream PR so the spec body can reference the unstable prefix
  until stable adoption.
