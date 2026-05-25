# Research — Authoring Heterodyne conformance test vectors

Date: 2026-05-25
Slug: `test-vectors`
Prompt: "Author all needed vectors for validating test clients, covering as
much of the MUSTs and SHOULDs in the specification as possible."

## 1. What the spec already fixes

The spec is unusually complete on this topic. Two artifacts already constrain
the work:

- **§14 (Conformance and test vectors)** defines verdict semantics
  (`produce` / `consume` / `round-trip`), the canonical-serialization rules
  (§14.1), and a full **coverage map** (§14.3) mapping every vector category
  to spec sections and to the behaviors each must cover.
- **`docs/spec/vectors/README.md`** restates the planned taxonomy with the
  per-file JSON shape (`vector_id`, `spec_section`, `description`,
  `direction`, `input`, `expected_output`, `notes`) and the conformance
  levels (baseline / strict-mode / optional).

So the *what* is largely specified. The open work is (a) the **mechanism** to
produce byte-exact outputs, (b) **fixture/identity** conventions, and (c)
**how much** of the map to author in this pass. Counts: 358 MUST, 70 MUST NOT,
118 SHOULD, 10 REQUIRED, 2 SHALL in the spec; §14.3 lists ~22 categories.

## 2. The crux: byte-exact reproducibility

§14.2 is absolute — "No tolerance is permitted. 'Close enough' semantic
equivalence is not conformance." A `produce` vector therefore must carry the
**real wire bytes**, and a conformant client must regenerate them identically.

Every cryptographic primitive Heterodyne uses is *deterministic-friendly* —
identical inputs yield identical bytes *iff* all randomness is pinned:

| Primitive | Where used | Determinism knob |
|---|---|---|
| SHA-256 event id over NIP-01 `[0,pubkey,created_at,kind,tags,content]` | every signed Nostr event (§3.0.1) | fully deterministic given the canonical string |
| BIP-340 Schnorr `sig` | every Nostr signature | **aux_rand** must be pinned (default BIP-340 uses fresh randomness → different bytes each run). Pin `aux_rand = 0x00*32`. Verification is aux-independent; only the produced bytes vary. |
| HKDF-SHA256 (RFC 5869) | `room_key` derivation (§6.7.4), post key (§6.10) | fully deterministic |
| NIP-44 v2 symmetric (ChaCha20 + HMAC-SHA256, HKDF-derived subkeys) | private `kind:31007` index + private_broadcast post content | **nonce** (32 bytes) is the only randomness and is embedded in the payload → pin the nonce |
| Matrix Canonical JSON / Megolm | room transport | Megolm ciphertext is non-reproducible and **out of scope** — vectors treat it as opaque and test the *decrypted* payload + the room-secret→`room_key`→NIP-44 chain |

**Conclusion.** Byte-exact `produce` and `round-trip` vectors are achievable
*only* by pinning all randomness in `input` (private keys, `created_at`,
`aux_rand`, NIP-44 nonces, room secrets, `key_id`s) and **running real crypto**
to compute the expected bytes. Hand-authoring a valid Schnorr signature or
NIP-44 ciphertext is infeasible. A small **generator** (test fixture, not a
reference client) is the natural way to compute and re-verify them.

A subset of categories needs **no live crypto** and can be authored by hand:
KERI first-seen ordering & fork-resolution verdicts, delegation
active/expired/revoked window logic, `prev_page_hash` page-chain integrity
(it is a hash *of* a canonical string we can compute), room-kind
current/retired/legacy mapping, asymmetric-delivery index-update contract
(ADR-010), versioning tolerance, mute-list logic, SSRF-policy verdicts. These
are mostly `consume` vectors with `accept`/`reject` verdicts.

## 3. Prior-art vector formats (ecosystem, current)

- **Wycheproof** (Google) — the gold standard JSON crypto test-vector schema:
  grouped tests with `tcId`, `comment`, `flags[]`, and a
  `result: valid|invalid|acceptable`. Strong model for our `consume`
  reject-reason taxonomy.
- **NIP-44 official vectors** (`nip44.vectors.json`, paulmillr/nostr) — nested
  `valid`/`invalid`, fields `sec1/sec2/conversation_key/nonce/plaintext/payload`.
  Direct model for `index/` and `broadcast/` crypto vectors; our wrap uses the
  *symmetric* layer (room_key used directly as the conversation key, no ECDH).
- **BIP-340 test vectors** (CSV) — `index, secret key, public key, aux_rand,
  message, signature, verification result`. Confirms aux_rand must be an input
  for byte-exact signatures.
- **Matrix canonical JSON** test data — sorted-key/no-whitespace examples;
  relevant only where we show a Matrix-layer object (mostly we don't — Megolm
  is opaque).

Idioms worth adopting: a `flags[]`/`reason` taxonomy on rejects; embed the
exact `nip01_raw` canonical string in produce vectors so a harness verifies
the signature independent of its own JSON serializer; carry both wire bytes
and a decoded/normalized view.

## 4. Generator runtime options (if a generator is chosen)

| Runtime | NIP-44 v2 | BIP-340 | HKDF | Notes |
|---|---|---|---|---|
| **TypeScript/Node** | `nostr-tools` `nip44` (matches official vectors) or `@noble/ciphers` | `@noble/curves` schnorr | `@noble/hashes` hkdf | De-facto nostr stack; audited, zero-dep noble; lowest friction; turnkey NIP-44 v2 |
| Python | `pycryptodome` (ChaCha20) + manual HMAC, or `cryptography` | `coincurve` / `secp256k1` | `cryptography` HKDF | No turnkey NIP-44 v2; more glue code |
| Rust | `nostr` crate (`nip44`) | `secp256k1`/`k256` | `hkdf` crate | Solid, heavier toolchain for a fixture |

**Idiomatic pick: TypeScript + noble/nostr-tools.** It is the canonical Nostr
implementation language and ships a NIP-44 v2 that already passes the official
vectors, minimizing the chance the generator itself is wrong. Risk: the repo
is currently code-free and "implementation-agnostic"; a generator is a
*dev/test fixture*, not a prescribed client runtime, but the distinction
should be stated explicitly (e.g. under `vectors/generator/` with a README
disclaiming it as non-normative tooling).

## 5. Spec implication to flag

Byte-exact BIP-340 vectors require a pinned `aux_rand`. The spec does not
currently say anything about aux_rand (correctly — it is irrelevant to
*verification*). For *vector reproduction only*, we need a testing-scoped rule:
"to regenerate a `produce` vector byte-identically, sign with
`aux_rand = 0x00..00`." This is a conformance/testing note, not a wire-format
or runtime change, and belongs in §14 (or the vectors README), **not** in any
broadcast/identity-room/relay surface.

## 6. Open architectural forks (feed into questionnaire)

1. **Mechanism for byte-exact outputs** — commit a generator (which runtime?)
   vs. author logic/consume vectors only and defer crypto-exact produce.
2. **Coverage scope this pass** — baseline-minimum only / + strict-mode + skippable / full §14.3 incl. optional / vertical slice first.
3. **Fixture model** — shared `fixtures.json` vs. fully self-contained vectors vs. hybrid (shared keys + inlined per-vector I/O).
4. **aux_rand / nonce pinning policy** — and whether to add a §14 "vector reproduction" note.
5. **Self-validation** — generator also re-verifies (CI round-trips its own output) vs. data-only.
