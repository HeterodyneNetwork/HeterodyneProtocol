# AGENTS.md

Orientation for AI coding agents working in this repository. This file is the
agent-neutral companion to [`CLAUDE.md`](CLAUDE.md): read CLAUDE.md first for
project mission and the in-repo map; AGENTS.md focuses on **externally-anchored
ground truth** (the standards Heterodyne composes on top of) and a few
agent-specific working conventions.

[`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) is the non-normative
family map. Normative authority is divided among the four independently
versioned 0.5.0 documents below. The former 0.4.0 monolith and its anchor
migration map live under [`docs/spec/archive/`](docs/spec/archive/).

## Where to look first

| If you need… | Go to |
|---|---|
| Project mission, room taxonomy summary, full repo map | [`CLAUDE.md`](CLAUDE.md) |
| Family overview and migration links | [`docs/spec/heterodyne.md`](docs/spec/heterodyne.md) |
| Identity, registry, versions, base conformance | [`docs/spec/heterodyne-core.md`](docs/spec/heterodyne-core.md) |
| Publishing, privacy, DMs, credential sync | [`docs/spec/heterodyne-comms.md`](docs/spec/heterodyne-comms.md) |
| Own-device control profile | [`docs/spec/heterodyne-control.md`](docs/spec/heterodyne-control.md) |
| Social behavior and optional Matrix | [`docs/spec/heterodyne-social.md`](docs/spec/heterodyne-social.md) |
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

Entries tagged *(0.x draft)* were added during the historical 0.4.0 substrate
pivot (ADR-026 through ADR-029) and remain relevant to the 0.5.x family;
they follow the same canonical-source rule - fetch them rather than relying
on recall.

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
- **[NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md)**
  *(0.x draft)* - event deletion (`kind:5` deletion requests). *Use when:*
  implementing post-hoc removal for any tier or moderation flow - deletion
  signals intent, not erasure ([Social revocation](docs/spec/heterodyne-social.md#social-revocation);
  [Comms encrypted branches](docs/spec/heterodyne-comms.md#comms-encrypted-branches)).
- **[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)** —
  bech32-encoded entities (`npub`, `nsec`, `note`, `nevent`, …). *Use when:*
  parsing or producing human-shareable identifiers.
- **[NIP-32](https://github.com/nostr-protocol/nips/blob/master/32.md)**
  *(0.x draft)* - labeling (`kind:1985` label events, `L`/`l` namespace and
  label tags). *Use when:* implementing Heterodyne's advisory moderation
  labels - a graded signal that gates nothing on its own
  ([Social labels](docs/spec/heterodyne-social.md#social-labels)).
- **[NIP-49](https://github.com/nostr-protocol/nips/blob/master/49.md)**
  *(0.x draft)* - private-key encryption (scrypt-wrapped `nsec` export).
  *Use when:* implementing the keys repository's at-rest `nsec` wrap or any
  wrapped-nsec backup ([Core keys repository](docs/spec/heterodyne-core.md#core-keys-repository);
  CORE-I-KEY-MATERIAL-AT-REST).
- **[NIP-51](https://github.com/nostr-protocol/nips/blob/master/51.md)**
  *(0.x draft)* - lists and sets (mute lists `kind:10000`, standard lists
  `kind:10000-10102`, sets `kind:30000-39092`, private items
  NIP-44-encrypted to self). *Use when:* implementing Social's mute-list and
  sets profiles, community policy lists, or subscribable curation
  ([Social lists](docs/spec/heterodyne-social.md#social-lists)).
- **[NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md)** —
  relay list metadata (the "outbox" model). *Use when:* reasoning about where
  a user's events should be published or fetched from.
- **[NIP-72](https://github.com/nostr-protocol/nips/blob/master/72.md)** —
  moderated communities (`kind:34550` community definition, `kind:4550`
  approval). *Use when:* working on Heterodyne Social moderation - the
  `kind:34550` moderator declaration with the `approvals_required` extension
  tag and anchored `kind:4550` approvals
  ([Social moderation](docs/spec/heterodyne-social.md#social-moderation)); the
  `m.heterodyne.moderators.v1` state event is the OPTIONAL Matrix carrier of
  the same declaration.
- **[NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md)**
  *(0.x draft)* - arbitrary application-specific data (addressable
  `kind:30078`). *Use when:* implementing Comms double-ratchet device
  invites (`d` = `double-ratchet/invites/<device>`,
  [Comms DM wire](docs/spec/heterodyne-comms.md#comms-dm-wire)).
- **[NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md)** —
  MLS-based end-to-end encryption for Nostr. *Use when:* implementing or
  reasoning about the MLS migration path or Marmot-style flows.
- **[nostr-double-ratchet](https://github.com/irislib/nostr-double-ratchet)**
  *(0.x draft)* - the Signal-style Double Ratchet wire over Nostr events
  (NIP-44 v2 payloads, outer events signed by the current ratchet key,
  rotated per DH ratchet step) that Heterodyne adopts for Comms DMs. *Use when:* implementing the `kind:1060` ratchet
  message / `kind:1059` invite response / `kind:30078` invite flow or
  reasoning about DM forward secrecy
  ([Comms direct messages](docs/spec/heterodyne-comms.md#comms-direct-messages)).
  The 0.x Comms document treats this
  as the normative reference until a frozen wire spec is extracted pre-1.0.

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
- **[Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)**
  *(0.x draft)* - the canonical Double Ratchet algorithm (DH ratchet +
  symmetric-key ratchet, message-key deletion). *Use when:* reasoning about
  the forward-secrecy and post-compromise-security guarantees of Heterodyne's
  Comms DMs, whose nostr-double-ratchet wire is this construction over Nostr
  events ([Comms direct messages](docs/spec/heterodyne-comms.md#comms-direct-messages)
  and [security](docs/spec/heterodyne-comms.md#comms-security)).
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

### Agentic clients

- **[Model Context Protocol (MCP) - specification revision 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)**
  ([repo](https://github.com/modelcontextprotocol/modelcontextprotocol))
  *(0.x draft, ADR-030; verified 2026-07-07)* - the open agent-capability
  protocol: JSON-RPC 2.0 framing, an initialize lifecycle with
  bidirectional capability negotiation, tools with JSON schemas, and
  notifications. Heterodyne adopts the **data layer only**, carried as
  Comms DR inner rumors
  ([Comms direct messages](docs/spec/heterodyne-comms.md#comms-direct-messages),
  a custom transport that MCP permits); MCP's
  stdio and Streamable HTTP/SSE transports are not used. *Use when:*
  working on the ADR-030 agentic RPC profile - the capabilities exchange,
  tool schemas as the grant-enforcement surface, and driving ongoing
  agent/terminal sessions on an agentic light client.
- **[Agent Host Protocol (AHP)](https://github.com/microsoft/agent-host-protocol)**
  *(considered, not adopted; verified 2026-07-07)* - Microsoft's protocol
  for synchronized multi-client state over AI agent sessions (immutable
  state, pure reducers, write-ahead reconciliation). Rejected for the
  agentic profile because its state-sync model presumes reconnect/catch-up,
  which the no-backfill DR carrier cannot provide (ADR-030, Alternatives
  Considered). *Use when:* revisiting synchronized multi-device live
  viewing of one agent session - the stated reopening condition.

### Reference implementations (prior art)

- **[radicle-keri](https://github.com/radicle-dev/radicle-keri)**
  *(dormant, Nov-Dec 2022, pre-Heartwood; verified 2026-07-08)* - the
  Radicle team's early KERI-for-Radicle exploration. Code NOT reusable
  (KEL write path unimplemented; vendored keriox 0.8.2 carries
  RUSTSEC-2022-0093). Cited as prior art for ADR-032: git-anchored
  KELs, the dual log/state
  [materialized-KEL profile](docs/spec/heterodyne-core.md#core-materialized-kel),
  and point-in-time key-state binding
  ([Core `kel_head`](docs/spec/heterodyne-core.md#core-kel-head)). *Use when:* consulting the design README
  behind those constructs; never as a dependency.
- **[keripy](https://github.com/WebOfTrust/keripy)** *(current stable;
  verified 2026-07-08)* - the canonical KERI reference implementation;
  the consumer the [Core KERI export](docs/spec/heterodyne-core.md#core-keri-export)
  targets.
  **[keriox (THCLab fork)](https://github.com/THCLab/keriox)**
  *(keri-core 0.17.x, EUPL-1.2; verified 2026-07-08)* - the maintained
  Rust KERI core, candidate for the first-party client; do NOT use
  radicle-keri's vendored 0.8.2.
  **[did:webs](https://trustoverip.github.io/tswg-did-method-webs-specification/)**
  *(ToIP draft v0.9.x; verified 2026-07-08)* - the DID method the
  [Core KERI export](docs/spec/heterodyne-core.md#core-keri-export) produces
  artifacts for; the export AID is derived and
  never authoritative over the npub.
- **[iris-client](https://github.com/irislib/iris-client)** *(0.x draft)* -
  a production Nostr client. Several Heterodyne mechanisms adopt patterns
  proven here and adapt them with Heterodyne's delegation binding:
  double-ratchet DMs over the nostr-double-ratchet wire
  ([Comms DMs](docs/spec/heterodyne-comms.md#comms-direct-messages)), the
  NIP-51 private-item pattern for mute lists
  ([Social lists](docs/spec/heterodyne-social.md#social-lists)), and web-of-trust
  filtering ([Social admission policy](docs/spec/heterodyne-social.md#social-admission-policy)).
  *Use when:* you want a working
  reference for any of those before pinning Heterodyne's normative
  variation. It is prior art, not a dependency or a conformance target.

## Working conventions

- **Decisions go through ADRs.** Material changes to a family document or architecture
  MUST be recorded as an ADR in [`docs/adr/`](docs/adr/). Numbering is
  globally sequential — check the highest existing `NNN` before authoring a
  new file (current naming: `YYYY-MM-DD-NNN-<slug>.md`).
- **Conformance vectors are normative.** When changing a wire-level behaviour
  in the spec, update or add the corresponding vector in
  [`docs/spec/vectors/`](docs/spec/vectors/). "Close enough" semantic
  equivalence is explicitly not conformance
  ([Core conformance](docs/spec/heterodyne-core.md#core-conformance)).
- **The protocol family is in its 0.x phase — in flux until 1.0.** Per the
  [Core version rule](docs/spec/heterodyne-core.md#core-versioning), any `0.x`
  document release MAY break the previous one. Do not
  assume backward compatibility within 0.x; do not promise it in code,
  comments, or docs.
- **Research is read-only.** Files under [`research/sources/`](research/sources/)
  are raw deep-research output stored verbatim with citations — do not edit
  them. Use [`research/INDEX.md`](research/INDEX.md) to navigate.
- **The family is implementation-agnostic.** No language or runtime is
  prescribed; do not introduce one without an ADR. Heterodyne is a pure
  client-side bridge — vanilla Matrix homeservers and Nostr relays must
  carry traffic without protocol-specific modifications.
