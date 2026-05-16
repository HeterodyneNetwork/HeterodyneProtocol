# Future NIP extractions

This directory tracks which sections of the Heterodyne specification
could eventually be proposed as Nostr Improvement Proposals (NIPs) for
adoption by the broader Nostr ecosystem. It is a forward-reference
index; the proposals themselves do not exist yet.

The intent: keep the living spec coherent in one document during rapid
iteration, then graduate stable, generally-useful pieces into formal
NIPs once they prove out.

## Candidate extractions

| Spec section | Working title | Generalized scope |
|---|---|---|
| §3.5 Identity chain | "Persona-preserving key rotation via successor chains" | Could be a generic Nostr-only NIP if the chain events are also published to plain Nostr relays. Useful to any Nostr user wanting rotation without losing followers. **Highest extraction priority.** |
| §3.6 Identity discovery | "External-transport identity hints" | A Nostr-side pointer event a user could publish to alert clients where to find a Matrix-backed identity room (or other external transport). Generalizes beyond Heterodyne. |
| §4.2 Wrapped event | "Heterodyne event envelope on non-Nostr transports" | The wrap convention; only relevant if non-Matrix transports adopt the pattern. Probably stays Heterodyne-specific. |
| §8 Moderation | "Editorial approval signatures for any transport" | A generalization of NIP-72's approval semantics. Likely belongs upstream as a NIP-72 amendment rather than a new NIP. |
| §10.5 Vanilla Nostr interop | (no NIP needed) | Already supported by NIP-01 + NIP-65; we just compose them. |

Each row should grow into its own subdirectory (`<NN>-<slug>/`) with a
NIP-style draft when the corresponding spec section stabilizes. The
draft should target the [`nostr-protocol/nips`](https://github.com/nostr-protocol/nips)
contribution model: a single markdown file describing motivation,
specification, examples, and security considerations.

## Coordination notes

- NIP numbering is decided upstream; this index uses descriptive slugs
  only until a number is assigned.
- Reserve a Heterodyne-specific kind range (currently 31000-31099 for
  identity-room state events) and document it once we propose any of
  these NIPs.
- Heterodyne SHOULD continue to track upstream NIP development that
  affects the spec — particularly NIP-EE/Marmot (MLS), NIP-65 (outbox),
  NIP-85 (WoT assertions). Changes there may upstream-replace parts of
  this spec.
