# AGENTS.md

Orientation for AI coding agents working in this repository. This file is the
agent-neutral companion to [`CLAUDE.md`](CLAUDE.md): read CLAUDE.md first for
project mission and the in-repo map; AGENTS.md focuses on **externally-anchored
ground truth** (the standards Heterodyne composes on top of) and a few
agent-specific working conventions.

## Where to look first

| If you need… | Go to |
|---|---|
| Project mission, room taxonomy summary, full repo map | [`CLAUDE.md`](CLAUDE.md) |
| The normative protocol document | [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) |
| Why a decision was made the way it was | [`docs/adr/`](docs/adr/) |
| Conformance test vector format and current corpus | [`docs/spec/vectors/`](docs/spec/vectors/) |
| Non-normative architecture rationale | [`docs/architecture.md`](docs/architecture.md) |
| Security model and threat analysis | [`docs/security/threat-model.md`](docs/security/threat-model.md) |
| Topic-keyed index into background research | [`research/INDEX.md`](research/INDEX.md) |

## Authoritative external references

Every link below was verified to resolve to its canonical current source on
2026-05-27. When you need ground truth for a standard Heterodyne builds on,
fetch one of these — do not rely on training-data recall alone, because the
ecosystem moves and several otherwise-plausible URLs are stale.

### Nostr (identity & broadcast layer)

- **[Nostr NIPs](https://github.com/nostr-protocol/nips)** — the authoritative
  set of *Nostr Implementation Possibilities*. *Use when:* you need the exact
  status, scope, or wire format of any NIP, or you're not sure which NIP
  governs a behavior. Source of truth for Nostr event semantics.
- **[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)** —
  base event format, `secp256k1` Schnorr signatures, replaceable events
  (`kind:30000–39999`). *Use when:* implementing or validating any Nostr event
  envelope, canonical serialization, signing, or `kind:31007` (Heterodyne's
  feed index) replaceable-event semantics.
- **[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)** —
  bech32-encoded entities (`npub`, `nsec`, `note`, `nevent`, …). *Use when:*
  parsing or producing human-shareable identifiers.
- **[NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md)** —
  relay list metadata (the "outbox" model). *Use when:* reasoning about where
  a user's events should be published or fetched from.
- **[NIP-72](https://github.com/nostr-protocol/nips/blob/master/72.md)** —
  moderated communities. *Use when:* working on Heterodyne's
  `public_discussion` moderation flow (`m.heterodyne.moderators.v1`,
  approval-driven feeds).
- **[NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md)** —
  MLS-based end-to-end encryption for Nostr. *Use when:* implementing or
  reasoning about the MLS migration path or Marmot-style flows.

### Matrix (transport, state & encryption layer)

- **[Matrix specification](https://spec.matrix.org/latest/)** — the canonical
  Matrix protocol: rooms, room state, federation. *Use when:* you need the
  authoritative behaviour of any Matrix API. Default to `latest`; only pin to
  a versioned page when reasoning about a historical compatibility note.
- **[Client-Server API — E2EE](https://spec.matrix.org/latest/client-server-api/#end-to-end-encryption)**
  — the E2EE module, including the `m.megolm.v1.aes-sha2` scheme and
  key-sharing rules. *Use when:* reasoning about how Heterodyne's rooms
  encrypt and how Megolm sessions are distributed.
- **[Megolm ratchet](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md)**
  — the cryptographic design document for the group ratchet. *Use when:* you
  need the actual ratchet construction, message-key derivation, or session-
  sharing semantics — depth beyond what the Matrix spec describes.

### Cryptography & identity

- **[MLS — RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)** — the IETF
  *Messaging Layer Security* standard. *Use when:* implementing or comparing
  against MLS group state, the key schedule, or commit/proposal semantics
  (Heterodyne's planned successor to Megolm; see also NIP-EE above).
- **[secp256k1 — SEC 2](https://www.secg.org/sec2-v2.pdf)** — SECG standard
  defining the elliptic curve. *Use when:* you need exact curve parameters or
  point-encoding rules (PDF; jump to the "Recommended Parameters secp256k1"
  section).
- **[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)**
  — *Schnorr signatures over secp256k1*; the signature scheme Nostr uses for
  event signing. *Use when:* implementing or test-vectoring Nostr signature
  verification, or producing canonical signing inputs.
- **[KERI (arXiv 1907.02143)](https://arxiv.org/abs/1907.02143)** — Smith,
  *Key Event Receipt Infrastructure*. **Primary citation** for the
  cold-root / epoch-key identity model — the user explicitly prefers this
  over the IETF draft because the arXiv paper stays current. *Use when:*
  reasoning about KERI key events, witness receipts, rotation, recovery, or
  duplicity detection. **NB:** the older
  `datatracker.ietf.org/doc/draft-ssmith-keri/` IETF draft has **expired** —
  do not cite it.
- **[ToIP KSWG KERI specification](https://trustoverip.github.io/kswg-keri-specification/)**
  ([repo](https://github.com/trustoverip/kswg-keri-specification)) — the
  active working-group specification. *Use when:* you need normative
  wire-format detail beyond the arXiv paper. **The working group is
  "KSWG" — *not* "TSWG"** (the `tswg-` variant of the URL 404s; easy to
  mistype).
- **[keri.one](https://keri.one/)** — KERI project home and pointer hub.
  Useful for discoverability; *less authoritative* than the arXiv paper or
  the KSWG spec.

## Working conventions

- **Decisions go through ADRs.** Material changes to the spec or architecture
  MUST be recorded as an ADR in [`docs/adr/`](docs/adr/). Numbering is
  globally sequential — check the highest existing `NNN` before authoring a
  new file (current naming: `YYYY-MM-DD-NNN-<slug>.md`).
- **Conformance vectors are normative.** When changing a wire-level behaviour
  in the spec, update or add the corresponding vector in
  [`docs/spec/vectors/`](docs/spec/vectors/). "Close enough" semantic
  equivalence is explicitly not conformance (spec §14.2).
- **The protocol is in its 0.x phase — in flux until 1.0.** Per the semver
  0.x rule (spec §12.1), any `0.x` release MAY break the previous one. Do not
  assume backward compatibility within 0.x; do not promise it in code,
  comments, or docs.
- **Research is read-only.** Files under [`research/sources/`](research/sources/)
  are raw deep-research output stored verbatim with citations — do not edit
  them. Use [`research/INDEX.md`](research/INDEX.md) to navigate.
- **The spec is implementation-agnostic.** No language or runtime is
  prescribed; do not introduce one without an ADR. Heterodyne is a pure
  client-side bridge — vanilla Matrix homeservers and Nostr relays must
  carry traffic without protocol-specific modifications.
