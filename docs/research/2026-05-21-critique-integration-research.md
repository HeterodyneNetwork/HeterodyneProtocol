# Critique Integration Research — 2026-05-21

External critique of Heterodyne v0.2.0 spec received 2026-05-21. This document verifies each of the 16 critique claims against the actual spec text at `docs/spec/heterodyne.md`, reports the change surface, and sanity-checks severity. No fix recommendations here — that is for the ADR phase.

## Verification methodology

All citations refer to `docs/spec/heterodyne.md` at HEAD `5675dc8` (Rename spec version from 0.1.5 to 0.2.0).

---

## 1. Public feed-index contradicts itself

**Claim:** The spec is internally inconsistent about where the feed index lives — some passages say Nostr (`kind:31007`), others say Matrix state.

**Spec verification:**

Three different locations make three different assertions:

- Lines 1192–1194 (`m.heterodyne.room_kind.v1` kind enum, §5): `"public_broadcast — unencrypted; full events on Nostr relays; the Matrix room holds the feed index (kind:31007) and standard room state (§5.2)."` — says Matrix holds the feed index.
- Lines 1238–1256 (§5.2 `public_broadcast` body): `"Content lives on Nostr relays; the Matrix room holds only state events. … The Matrix room does not carry the index."` — says Matrix does NOT hold the index.
- Line 1028 (§4.4 wrap-mode table): `"public_moderated | N/A — full events on Nostr relays, indexes in Matrix. See §5.3."` — says `public_moderated` has "indexes in Matrix".
- Lines 1296–1306 (§5.3 body): every moderator publishes their own `kind:31007` feed index on Nostr relays, not in Matrix.
- Lines 1582–1600 (§6.7): `"Matrix state events MUST NOT be used to carry append-only feed indexes."` — categorical prohibition.

**Change surface:**

- Line 1193: remove `the Matrix room holds the feed index (kind:31007) and` from the kind enum description for `public_broadcast`.
- Line 1028: the wrap-mode table cell for `public_moderated` says "indexes in Matrix" — change to "indexes on Nostr relays (§5.3, §6.7)".
- Lines 1238–1256, 1296–1306, and 1582–1600 are correct and do not need editing.

**Severity:** Critical blocker rating is reasonable — line 1193 directly contradicts §5.2, §6.7, and the opening preamble (lines 5–8). A conforming implementer reading the kind-enum description would implement something §6.7 explicitly forbids.

---

## 2. Nostr kind table is wrong (kind 17)

**Claim:** The spec lists "kind 17 — Sealed/gift-wrapped DM" but NIP-17 is a NIP number, not a kind number; the actual kind flow is 14/15/13/1059/10050.

**Spec verification:**

Line 202: `| 17 | Sealed/gift-wrapped DM | §11.4 (vanilla-Nostr-only DMs) | NIP-17 |`

This is the only occurrence of `kind 17` or `kind:17` in the spec. The spec then correctly uses `kind:1059` in the context of gift-wrapped private feed indexes (lines 1691–1695). NIP-17 defines the DM flow using kinds 14 (chat message rumor), 13 (seal), and 1059 (gift wrap), with kind 10050 for DM relay lists. Kind 17 does not exist in NIP-17.

**Change surface:** Line 202 only. The entire row should be revised: the kind numbers 14, 13, 1059, and 10050 should be listed (or the row restructured), with NIP-17 remaining correct as the NIP reference.

**Severity:** Major. The kind number is simply wrong. Error is isolated to one table row.

---

## 3. Delegation acknowledgement under-authenticated

**Claim:** §3.3 removed the MSK signature and now relies only on Matrix `/send/state` authorization, but the spec still refers to the delegation as "double-signed" in the threat-mitigation table.

**Spec verification:**

- Lines 13–16 (preamble): `"delegation acknowledgement no longer requires a Matrix MSK signature — the delegation is authenticated by the homeserver's normal /send/state authorization on the npub-signed payload"` — confirms MSK removed.
- Lines 480–487 (§3.3 body): explains the removal explicitly. Consistent.
- Line 3508 (§13.3 threat table): `"| Phantom delegation | §3.3 (double-signed), I3 |"` — still says "double-signed".
- Lines 3480–3482 (§13.2 invariant I3): `"I3 — Double-signed delegations. A delegation is active only with both an npub-side Nostr signature AND an MXID-side Matrix signature (§3.3). Single-signed delegations MUST be rejected."` — invariant label "Double-signed" remains; "MXID-side Matrix signature" is now just homeserver access-token authorization, not a cross-signing signature.
- Lines 2148–2204 (§7.5): `"double-signed by both npubs"` — refers to cross-persona attestation, not delegation. Correct usage, unrelated.

**Change surface:**

- Line 3508: update the threat-table cell from `§3.3 (double-signed)` to something accurate (e.g., `§3.3 (npub-signed + MXID self-publication)`).
- Lines 3480–3482: invariant I3's label should be renamed (e.g., "Dual-authenticated delegations") and description revised to match the current model.

**Severity:** Minor as a security matter (§3.3 prose is correct), but the stale label in §13 is a real documentation inconsistency. Critique's framing as "under-authenticated" conflates two separate issues: (a) whether the current design is strong enough (a substantive design question), and (b) whether the spec correctly describes the current design (a documentation question). (b) needs fixing; (a) is a separate decision.

---

## 4. ±5 minute root-attestation rule

**Claim:** The ±5 minute clock-skew rule on `created_at` makes any identity older than 5 minutes unverifiable at verification time.

**Spec verification:**

Lines 425–432 (§3.2.1): `"The Nostr created_at MUST be within a strict ±5 minute window of the verifier's current wall-clock time at the moment of verification. Events outside this window MUST be rejected. (This hardens against replay of an old signed attestation re-injected into a fresh identity room. Genuine re-publication of a long-ago attestation is supported by re-signing with the persona's current epoch key — the cold root remains the same, and the new signature carries a current created_at.)"`

**The critique misreads the spec.** The rule applies to the `m.heterodyne.root.v1` attestation event specifically. The spec's own parenthetical acknowledges the concern: the cold root is permanent; what must be fresh is the signed attestation event inside the identity room. A persona whose identity is older than 5 minutes does NOT become unverifiable — they re-sign the attestation with their current epoch key and a current `created_at`. The cold root pubkey remains the same.

**Change surface:** No normative change strictly needed. However, the parenthetical explanation at lines 428–432 could be made more prominent (e.g., moved to a NOTE block) to prevent exactly the misreading the critique makes. Also relevant: lines 2627–2628 refer to "the strict ±5 minute clock-skew enforcement of §3.2.1" in the security model without clarifying scope.

**Severity:** Critique is factually wrong, but the spec invites the misreading. Minor clarity issue.

---

## 5. `nip01_raw` requirement

**Claim:** The spec mandates a raw stringified NIP-01 serialization on every embedded Nostr event with a false rationale (JSON parsers reorder arrays — arrays are ordered in JSON).

**Spec verification:**

Lines 252–254 (§3.0.1.1): `"To prevent Matrix homeservers or intermediary JSON parsers from silently breaking signature validation by reordering JSON arrays or normalizing whitespace, every m.heterodyne.note.v1 event MUST include a nip01_raw field…"`

The critique is technically correct that JSON arrays are ordered by spec (RFC 8259 §5); a conforming parser cannot reorder an array. However, the real threats the spec is guarding against are: (a) JSON object key reordering (objects are unordered; parsers commonly reorder keys), which would corrupt `id` and `sig` if reconstructed from the parsed object; (b) numeric serialization differences (`1.0` vs `1`); (c) whitespace normalization.

**Change surface:**

- Lines 252–254: clarify the rationale. Replace "reordering JSON arrays" with something accurate such as "re-serializing the parsed object (which may reorder keys, normalize numbers, or alter whitespace)".
- The requirement itself (lines 254–287) and the normative rules (lines 939–950) are sound and do not need editing.

**Severity:** Minor documentation issue (imprecise rationale). The mechanism is well-motivated and correct.

---

## 6. Private feed indexes via NIP-44/NIP-17 — wrong kind label

**Claim:** Lines 1691–1692 call `kind:1059` a "seal" when per NIP-59 kind 1059 is the gift wrap; kind 13 is the seal. Also, per-member wrapping scales badly.

**Spec verification:**

Lines 1688–1695 (§6.7.4): `"the persona MAY publish a kind:31007 index gift-wrapped per NIP-44 / NIP-17 to the room's members. When gift-wrapped, the outer event is a kind:1059 seal whose sealed content is a kind:31007 index event. The seal addresses each room member's npub."`

In NIP-59: rumor (unsigned event) → seal (kind:13, encrypted rumor, signed by author) → gift wrap (kind:1059, encrypts the seal, signed by random one-time key, addressed to recipient). So `kind:1059` is the gift wrap, not the seal. Each recipient gets their own distinct gift wrap encrypted to their pubkey. For a 500-member room, this is 500 separate `kind:1059` events.

**Change surface:**

- Line 1691: "the outer event is a `kind:1059` seal" — change "seal" to "gift wrap".
- Line 1692: "The seal addresses each room member's npub" — change to "A separate gift wrap addresses each room member's npub".
- Line 1688: NIP citation "NIP-44 / NIP-17" is imprecise — correct citation is NIP-59 for wrapping; NIP-44 for the inner encryption primitive.

**Severity:** Major for the terminology inversion. The scaling concern for large private rooms is a separate design issue.

---

## 7. "Latest stable Matrix room version"

**Spec verification:**

- Line 1266 (§5.2 REQUIRED state): `"m.room.create.room_version: latest stable Matrix room version."`
- Line 1342 (§5.4 REQUIRED state): `"m.room.create.room_version: latest stable."`

These are the only two occurrences. No specific room version number is given.

**Change surface:** Lines 1266 and 1342. Pin a specific room version or define "latest stable" normatively.

**Severity:** Minor for Heterodyne's current featureset (Matrix room versions are largely backward compatible), but normatively imprecise. Critique's concern is reasonable for long-term conformance.

---

## 8. Peek endpoint `/peek/{roomId}`

**Spec verification:**

Lines 630–633 (§3.6, normative algorithm step 3): `"Peek the identity room. Resolve the matrix: URI to a room ID and via server hints, then peek via GET /_matrix/client/v3/peek/{roomId} (or join if peek is not permitted by the room)."`

The critique is correct. `GET /_matrix/client/v3/peek/{roomId}` is not a stable Matrix C-S API endpoint. The stable way to access world-readable room state without joining is via `GET /_matrix/client/v3/rooms/{roomId}/state` (subject to history visibility) or by joining the room. MSC2753 covers server-side peeking but is not merged.

**Change surface:**

- Lines 631–633: replace the specific endpoint with the stable mechanism, or cite MSC2753 as OPTIONAL and define a stable fallback.
- Line 603 (sequence diagram) and prose mentions (lines 361, 382, 1258, 1906, 1917, 1934, 1937, 1940) use "peek" informally — fine if normative text is fixed.

**Severity:** Major. Referenced endpoint does not exist in stable Matrix.

---

## 9. Encrypted state events MUST follow MSC4362

**Spec verification:**

MSC4362 referenced with MUST language 5 times:

- Line 727 (§3.8 config room): `"All state events MUST be encrypted (MSC4362)."`
- Lines 1345–1347 (§5.4 `private_verifiable` REQUIRED): `"Encrypted state events: MUST follow MSC4362."`
- Lines 2526–2528 (§9.1): `"Every event in a private_verifiable, … MUST be end-to-end encrypted, including state events (MSC4362). No exceptions."`
- Lines 2078–2079: `"The advertising room MUST be E2EE; the state event MUST therefore be encrypted per §9 and MSC4362."`
- Lines 3474–3475 (§13.2 invariant I1): `"… including state events (§9.1, MSC4362)."`

Framed as mandatory baseline, not an optional profile. MSC4362 is an unmerged MSC.

**Change surface:** 5 locations need a caveat about MSC stability. Alternative: split into a baseline profile (no encrypted state required) and an encrypted-state profile (MSC4362 required).

**Severity:** Major. Spec mandates an unstable Matrix feature. Real implementation blocker if MSC4362 remains a draft.

---

## 10. KERI invoked but not specified; witness-agreement rule

**Spec verification:**

Lines 559–565 (§3.5): `"The exact payload schemas, ceremony procedures, and verifier algorithms are normative in the Cold Root + Epoch Keys design document at docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md. That document is incorporated by reference into this section; implementations claiming Heterodyne v0.2.0 conformance MUST implement it."` — explicitly defers KERI payload schemas, but "incorporated by reference" not a punt.

Lines 550–553 (§3.5 witness-agreement rule): `"Two rotation events claiming the same s are a fork; verifiers MUST apply KERI's deterministic resolution rule (highest cumulative witness weight by static witness configuration wins; on tie, the lexicographically smallest event id wins)."`

KERI's canonical fork resolution (Smith 2021) uses "first-seen" ordering at each witness, not "highest cumulative witness weight." The "lexicographically smallest event id" tiebreaker is a Heterodyne-local convention. Calling this "KERI's deterministic resolution rule" is a false conformance claim.

**Change surface:**

- Lines 550–553: correct to match KERI's actual algorithm or explicitly state that this is a Heterodyne-local extension.
- Lines 559–565: companion document at `docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md` is normatively incorporated — should be audited for the same rule.

**Severity:** Critical blocker for the KERI conformance claim. Companion-document-as-normative is defensible if the companion is actually authoritative; the rule itself is the more serious issue.

---

## 11. Version inconsistency

**Spec verification:**

- Line 3: `**Version:** 0.2.0`
- All `spec_version` schema occurrences use `"0.1"`: lines 394, 451, 771, 800, 832, 858, 918, 1176, 1866, 1976, 2049, 2156, 2315, 2453, 2550, 2869, 3039, 3106, 3131, 3337, 3338 (~21 instances).
- §12.1 (line 3298): `spec_version` is "semver-formatted string (MAJOR.MINOR.PATCH)" — but all examples use two-component `"0.1"`, not `"0.1.0"` or `"0.2.0"`.

**Change surface:** Pervasive — ~21 schema instances. Decisions to make:

(a) Update all schema `spec_version` to `"0.2.0"` to match document header.
(b) Declare `"0.1"` legacy and require `"0.2.0"` going forward.
(c) Revise §12.1 to formally permit two-component version strings.

**Severity:** Major. §12.1 says `MAJOR.MINOR.PATCH` but examples use `MAJOR.MINOR`. Ambiguous for parser implementers; makes v0.2.0 header meaningless from a wire-compatibility standpoint.

---

## 12. `private_deniable` overclaim

**Spec verification:**

- Lines 1203–1207: `"Strong cryptographic deniability via the underlying Megolm/MLS ratchet — no participant can prove to a non-participant who said what."`
- Lines 1371–1372 (§5.5): `"inherits Megolm/MLS-grade deniability — no participant can cryptographically prove to a non-participant who sent what message."`
- Lines 969–972 (§4.3): `"Inside an E2EE room a bare event is deniable in the same way any encrypted Matrix message is: only recipients know the sender, and the sender can claim the homeserver forged it."` — more circumspect.
- Line 1336: `"private_verifiable rooms do NOT offer cryptographic deniability"` — correct contrast.

Megolm session keys are shared among room members — any member who exports session key + ciphertext can decrypt and attribute. Deniability holds against non-members; broken by any member who shares keys. MLS has better forward secrecy but does not provide OTR-style deniability either.

**Change surface:**

- Lines 1204–1206: replace strong claim with accurate language (deniability against non-members only; broken by colluding members).
- Lines 1371–1372: same revision.
- Lines 969–972: already cautious, may not need changing.

**Severity:** Major. Security property claim that may mislead users.

---

## 13. Too many identity authorities

**Spec verification:**

§3.6 (lines 614–661) defines a sequential resolution algorithm with implicit precedence:

1. Matrix profile → identity room URI (line 616)
2. Root attestation `m.heterodyne.root.v1` (line 635)
3. Delegation `m.heterodyne.delegation.v1` (line 640)
4. KERI log replay (line 644)
5. `kind:31005` identity pointer (line 652) — can redirect, restarting from step 3.

Additional authorities not integrated into §3.6 ladder:
- Cold root (`kind:31002`) — authoritative for inception (line 537).
- Witness thresholds (KERI rotation, lines 554–557).
- ATProto witness (`kind:31000` co-signer, lines 3205–3219) — additive only.

No concise stand-alone "authority ladder" table exists. The procedure at §3.6 is the closest thing.

**Change surface:** Add a priority/ladder summary, probably as a new §3.0.2 or a callout in §3.6. Additive change; does not alter any normative rules.

**Severity:** Minor as a correctness issue, but a real documentation gap that makes auditing hard.

---

## 14. Relay availability hand-waved

**Spec verification:**

- `previous_index` chaining: lines 1663–1666 define the page-chaining tag as OPTIONAL. No integrity verification between pages is specified beyond per-event BIP-340 signatures.
- Relay retention: line 2707 mentions "beyond Nostr relay retention windows" only in the context of user-hosted archives as a remedy. No normative language addresses what happens when relays drop events.
- Partition detection: not mentioned anywhere.
- Archive fallback: Channel 2 (user-hosted archive, §6.9.2, lines 1855–1876) is OPTIONAL. No normative behavior is specified when both channels fail.

**Change surface:**

- §6.7.2 (pagination, lines 1653–1672): add normative language for missing-page handling.
- §6.9.1 (channel 1): add normative behavior for unavailable relays.
- New subsection or note in §6.7 addressing relay availability as a known risk.

**Severity:** Major. Real data-loss scenario for users; no normative handling currently.

---

## 15. Moderation not enforceable at wire layer

**Spec verification:**

Lines 2803–2804 (§11.1): `"The room itself does not actively reject bare events. Matrix has no event-admission machinery suited to this."` — spec explicitly acknowledges.

Lines 2816–2822: `"Strict rooms MAY operationally reject bare events by configuring a moderator to issue Nostr kind:5 deletions (§8.4) for any non-wrapped event … This is enforcement by editorial action, not by admission policy."` — editorial-only.

Lines 3429–3440 (§12.3): `"rooms do NOT enforce version admission. The wire protocol accepts what it accepts."` — deliberate design choice.

No "strict client mode" / "moderated feed mode" / enforcement profile exists.

**Change surface:** Adding a client-side enforcement profile would require a new normative section. The spec's current framing is intentional, not an oversight.

**Severity:** Architectural decision, not a bug. Critique's request for explicit profiles is a real-world UX improvement but not a correctness issue.

---

## 16. Stale terminology

### (a) "Identity chain" / "successor chain of npubs" language post-KERI

- Line 168–170 (§2 Terminology): `"Identity chain — the linked succession of npubs a persona has rotated through."` — describes deprecated v0.1.4 single-key chain, not KERI.
- Lines 2387–2393 (§8.3): `"Moderators inherit the identity chain mechanism from §3.5. … The identity chain validates (paired successor/predecessor events)."` — still references deprecated successor/predecessor events deleted in v0.2.0.
- Lines 2400–2404: `"When walking a moderator's identity chain, verifiers MUST use the matrix: URI form…"` — uses "identity chain" in a normative MUST.
- Lines 2680–2681: conformance checklist mentions "identity chain".
- Line 2854–2856: vanilla Nostr discovery refers to "identity chain".
- Line 3582: test vectors table mentions "moderator rotation through identity chain".

### (b) "Double-signed" delegation language

- Line 3508 (threat map): `"§3.3 (double-signed)"` — stale.
- Lines 3480–3482 (invariant I3): `"Double-signed delegations … npub-side Nostr signature AND an MXID-side Matrix signature"` — stale label.

### (c) Table mentioning Matrix feed indexes

- Line 1028 (§4.4 wrap-mode table): `"public_moderated | N/A — full events on Nostr relays, indexes in Matrix."` — contradicts §5.3.
- Line 1193 (kind enum): `"the Matrix room holds the feed index (kind:31007)"` — contradicts §6.7.

### (d) "npub hex" or "hex npub"

The term "npub" in Nostr is the bech32-encoded form (prefix `npub1…`). The raw public key in hex is `pubkey`. The spec uses "npub hex" in approximately 15–20 schema example placeholders:

- Lines 798, 802, 830, 1606, 1607, 2047, 2080, 2154, 2160, 2165, 2173, 2178, 2863, 3044, 3110 — pattern `<… npub hex>`.

In every case the intended value is the 32-byte hex pubkey (as used in NIP-01), not the bech32 npub encoding.

**Change surface (§16 combined):**

- Line 168–170: rewrite "Identity chain" definition to describe the KERI key event log.
- §8.3 (lines 2387–2404): replace "identity chain" / "successor/predecessor events" with KERI log terminology — this section appears to have been missed during the v0.2.0 KERI migration.
- Lines 2680–2681, 2854–2856, 3582: replace "identity chain" with "KERI key event log".
- Lines 3480–3482, 3508: rename invariant I3 and threat-table cell per issue 3.
- Lines 1028 and 1193: fix per issue 1.
- All `<… npub hex>` placeholders: replace with `<32-byte hex pubkey>` or `<pubkey hex>`. ~15–20 occurrences.

**Severity:** Major for "npub hex" (misleads implementers on encoding). Major for §8.3 — moderator rotation is essentially unspecified for KERI personas because §8.3 still describes deprecated mechanisms. Minor for I3 label.

---

## Cross-cutting observations

1. **Version drift between schemas and document header appears ~21 separate times.** Every schema block uses `spec_version: "0.1"` while the document is titled v0.2.0. Single most pervasive inconsistency.

2. **The v0.2.0 KERI migration left §8.3 (Moderator key rotation) unrewritten.** §3.5 explicitly deletes single-key successor chains, but §8.3 still uses "identity chain," "successor/predecessor events" as if those mechanisms exist. This is a significant **specification gap**, not just stale wording — moderator rotation procedure is now unspecified for KERI personas. Not flagged in the critique but uncovered during verification.

3. **Two feed-index contradictions in lines 1192–1197 vs §5.2 and §6.7** stem from the same v0.2.0 migration: kind-enum prose and §4.4 wrap-mode table were not updated when §5.2/5.3/6.7 were rewritten. Surgical fix (two locations), not structural.

4. **The `kind:1059` (issue 6) and `kind:17` (issue 2) errors both stem from inconsistent NIP-59 terminology application.** A single NIP-59 terminology pass would resolve both.

5. **The ±5 minute clock-skew rule (issue 4) is correctly specified** but scope is not clearly delimited — applies only to the root attestation, but referred to broadly in §13.

6. **Two hard dependencies on unstable Matrix features without fallback paths:** `/peek/{roomId}` (MSC2753 territory, issue 8) and MSC4362 encrypted state (issue 9). Real conformance risk.

7. **The "double-signed" label survives in §13 after explicit removal from §3.3.** Three-location inconsistency: preamble (removed), §3.3 body (removed with explanation), §13.2/§13.3 (still present).

8. **Critique items vary substantially in nature:** factual errors (2, 6, 8), spec inconsistencies (1, 3, 11, 16), security/correctness questions (3, 9, 10, 12), missing-specification gaps (14, 15), documentation clarity (4, 5, 13). Conflating "fix all 16" treats different problem classes uniformly; they likely need different remedies (terminology pass vs. ADR vs. companion-doc audit).
