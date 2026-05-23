# Critique Integration Architecture — 2026-05-21

Synthesis of the 9 decisions made during the BRAINS grill questionnaire. Drives the ADR production phase.

## Decisions captured

| Ref | Topic | Decision |
|---|---|---|
| Q1 | MSC dependency strategy | MSC4362 and other unstable Matrix features implemented **client-side only**; vanilla servers remain unaltered. The MUST language stays, scoped to client implementation. |
| Q2 | KERI normative scope + §8.3 gap | **Inline a Heterodyne KERI profile** in §3.5. Mechanically port §8.3 (moderator key rotation) using the inlined KERI primitives. |
| Q3 | Security claims hygiene | **Differentiated treatment** per item: deniability gets a real revision; ±5 min gets a scoped NOTE block; `nip01_raw` rationale gets a one-line fix. |
| F1 | Packaging | Revise **v0.2.0 in place**. Version label stays 0.2.0 until first-party-client validation closes the freeze. ADRs document the substantive decisions. |
| F2 | Versioning consistency | Update **all ~21 schema instances** to `spec_version: "0.2.0"`. Three-component MAJOR.MINOR.PATCH everywhere per §12.1. |
| F3 | Witness-agreement rule | **Correct to canonical KERI first-seen ordering.** The cumulative-weight rule was a misremembering — no design rationale exists in the companion doc or elsewhere. |
| F4 | NIP-59 terminology | **Single comprehensive pass.** Add NIP-59 terminology entry to §2; fix line 202 (kind 17 row) and lines 1688–1693 (kind:1059 mislabel); audit for other rumor/seal/gift-wrap usage. |
| F5 | Vanilla-Matrix-client compatibility | **Heterodyne private rooms are Heterodyne-only.** A non-Heterodyne Matrix client joining can read the Megolm timeline but not encrypted state. Add a normative note to §5.4/§5.5; recommend client UX warning before inviting non-Heterodyne MXIDs. |
| F6→F7 | Private feed index design | **New wire format — Heterodyne room-key wrap.** Withdraw the per-recipient NIP-59 gift-wrap path. Specify a per-room symmetric key derived from the Matrix Megolm session; kind:31007 index content encrypted under that key; one event per index update; all members can decrypt. Significant new design surface. |
| F8 | Relay partitioning | **Add normative missing-page + relay-set timeout behavior.** §6.7.2 specifies missing-page UX (truncation indicator, continue from latest resolvable page). §6.9.1 specifies fetch timeout/retry budget. |
| F9 | Moderation enforcement | **Define formal "Heterodyne strict-mode client" profile.** New subsection: MUST hide bare events in `private_verifiable`; MUST honor moderator `kind:5` deletions within timeout; MUST surface "unmoderated" warning. Clients advertise capability. |

## Three workstreams

### Workstream 1 — Editorial cleanup pass (one commit, no ADR)

Items with one obvious answer, no architectural fork:

| Item | Spec change | Source |
|---|---|---|
| #1 feed-index contradiction | Fix lines 1028 and 1193 (delete stale "Matrix holds the index" phrasing) | Verification |
| #2 + #6 NIP-59 terminology | Comprehensive pass: line 202 (kind 17 row → rumor/seal/gift-wrap kinds 14/13/1059/10050), lines 1688–1693 (kind:1059 "seal" → "gift wrap"; NIP-44/NIP-17 citation → NIP-59 + NIP-44). Add NIP-59 terminology entry to §2. | F4 |
| #3 + #16(b) "double-signed" stale label | Rename invariant I3 (e.g., "Dual-authenticated delegations"); fix §13.3 threat-table cell ("§3.3 (double-signed)" → "§3.3 (npub-signed + MXID self-publication)") | Verification |
| #7 "latest stable Matrix room version" | Pin to room version 11 (current latest stable). Lines 1266, 1342. | Verification |
| #11 versioning consistency | Update all ~21 schema instances `spec_version: "0.1"` → `"0.2.0"`. Affects: lines 394, 451, 771, 800, 832, 858, 918, 1176, 1866, 1976, 2049, 2156, 2315, 2453, 2550, 2869, 3039, 3106, 3131, 3337, 3338. | F2 |
| #13 authority ladder | Add a precedence-ladder table to §3.6 summarizing the existing algorithm. Default action; no fork. | Default |
| #16(a) "identity chain" terminology in code paths that DON'T need a substantive KERI rewrite | Mechanical rename to "KERI key event log" in lines 168–170 (glossary), 2680–2681 (conformance checklist), 2854–2856, 3582. (§8.3 itself is part of ADR-002.) | Verification |
| #16(c) tables mentioning Matrix feed indexes | Covered by #1 fix. | — |
| #16(d) npub hex placeholders | Replace ~15–20 `<… npub hex>` placeholders with `<pubkey hex>` or `<32-byte hex pubkey>`. Lines: 798, 802, 830, 1606, 1607, 2047, 2080, 2154, 2160, 2165, 2173, 2178, 2863, 3044, 3110. | Verification |

Commit message: `spec: editorial cleanup pass — NIP-59 terminology, version consistency, terminology drift, peek/MSC labels`

### Workstream 2 — Substantive ADRs

Six themed ADRs in `docs/adr/`. Each ADR has its own commit; ADRs are the source of truth for the corresponding spec edits.

#### ADR-001: MSC dependency strategy — client-side implementation, vanilla-server compatibility

- **From:** Q1 + F5
- **Decision:** MSC4362 encrypted state, peek endpoint, and any other unmerged Matrix features are implemented **client-side only**. The MUST language stays, scoped to client behavior. Vanilla Matrix servers store encrypted state as opaque content; servers do NOT need MSC4362 support. Heterodyne private rooms are Heterodyne-only — non-Heterodyne clients can read the Megolm timeline but not encrypted state.
- **Spec changes:**
  - §3.6 (lines 630–633): replace `/peek/{roomId}` endpoint reference. Clients use `GET /rooms/{roomId}/state` when world-readable, or join when not. Experimental MSC2753 peek may be used when servers support it.
  - §3.8 (line 727): clarify MSC4362 means client-side implementation; server stores as opaque.
  - §5.4 (lines 1345–1347): same clarification + add normative note that Heterodyne private_verifiable rooms are Heterodyne-only.
  - §5.5: parallel note for private_deniable rooms.
  - §9.1 (lines 2526–2528): same clarification for invariant I1.
  - §13.2 (lines 3474–3475): rewrite invariant I1 to reflect client-side encryption model.
  - New subsection or callout: explicit guidance to clients about inviting non-Heterodyne MXIDs.

#### ADR-002: KERI normative scope — inline profile + §8.3 mechanical port + witness rule correction

- **From:** Q2 + F3
- **Decision:** Inline a self-contained "Heterodyne KERI profile" in §3.5. Correct the witness-agreement rule to canonical KERI first-seen ordering (cumulative-weight was a misremembering; no upstream rationale). Mechanically port §8.3 (moderator key rotation) to use the inlined KERI primitives. The Cold Root + Epoch Keys companion document is either inlined entirely or demoted from "incorporated by reference" to "informative companion."
- **Spec changes:**
  - §3.5 (lines 537–565): expand significantly to inline KERI payload schemas, ceremony procedures, verifier algorithms. Correct lines 550–553 (witness rule) to first-seen.
  - §8.3 (lines 2387–2404): rewrite — replace "identity chain" / "successor/predecessor events" with KERI key event log terminology and primitives.
  - §3.5 conformance language (lines 559–565): tighten "incorporated by reference" framing or remove the companion-doc dependency entirely.
- **Open design questions deferred to v0.3:** stricter moderator-specific rotation (NIP-72 owner re-attestation, mandatory witness threshold). To be addressed after first-party-client surfaces real attack scenarios.

#### ADR-003: Security claims hygiene — differentiated remediation

- **From:** Q3
- **Decision:** Match remedy to severity. Three separate fixes in one ADR.
- **Spec changes:**
  - (a) **Deniability overclaim:** rewrite lines 1204–1206 and 1371–1372 from "strong cryptographic deniability" / "no participant can prove" to accurate language: "No per-message signature names the sender; any room member with the Megolm session key can decrypt all messages. Deniable against non-members; broken by colluding members who share session keys." Add a security-model note about the member-collusion attacker.
  - (b) **±5 min rule scope clarity:** add a scoped NOTE block in §3.2.1 (after line 432) explicitly stating the rule applies ONLY to `m.heterodyne.root.v1` attestation events. Lines 2627–2628 in §13 get a forward reference to the §3.2.1 NOTE.
  - (c) **`nip01_raw` rationale:** one-line fix at lines 252–254. Replace "reordering JSON arrays" with "re-serializing the parsed object (which may reorder object keys, normalize numbers, or alter whitespace)."

#### ADR-004: Private feed index — Heterodyne room-key wrap

- **From:** F7 (user-introduced design intent)
- **Decision:** Replace the OPTIONAL per-recipient NIP-59 gift-wrap path for private kind:31007 indexes with a Heterodyne-defined room-key wrap. Specify: a per-room symmetric key derived from the Matrix Megolm session (or independently distributed via the Matrix room as a Heterodyne-defined state event); kind:31007 index content encrypted under that key; one Nostr event per index update; all room members can decrypt because they share the key.
- **Spec changes:** rewrite §6.7.4 entirely. May require new schema in §4.
- **Open design questions (to resolve during ADR drafting):**
  - Key derivation: derive from Megolm session (couples key lifecycle to Megolm rotation) vs. independent Heterodyne key distributed via a new Matrix state event (independent lifecycle, more surface).
  - Encryption primitive: NIP-44 vs. AES-GCM with HKDF.
  - Member-removal behavior: when does the key rotate? on every membership change or only on remove?
  - Backward compatibility: should the existing NIP-59 gift-wrap path remain as a deprecated OPTIONAL fallback?
- **Significant new design surface.** This ADR likely requires its own follow-up grill to nail down the key-derivation choice.

#### ADR-005: Relay partitioning — normative missing-page + timeout behavior

- **From:** F8
- **Decision:** Add normative client behavior for relay partitions and missing pages.
- **Spec changes:**
  - §6.7.2 (lines 1653–1672): when a `previous_index`-linked page does not resolve across N relay attempts, clients MUST surface a "feed truncated" indicator and continue from the most recent resolvable page.
  - §6.9.1: define what constitutes a "complete" relay fetch attempt — timeout (default value), retry budget, fallback-relay traversal order — before declaring pages missing.
- **No new wire format.** Pure client-behavior normative additions.

#### ADR-006: Moderation enforcement — Heterodyne strict-mode client profile

- **From:** F9
- **Decision:** Add a formal `heterodyne-strict-mode` client profile alongside the editorial-enforcement baseline.
- **Spec changes:**
  - New subsection (likely §11.5 or §14.x): "strict-mode clients" — normative MUST behaviors.
    - Hide bare events in `private_verifiable` rooms (do not render in primary timeline; show in a "filtered" view if at all).
    - Honor moderator `kind:5` deletions within a normative timeout (e.g., 30 seconds).
    - Surface "unmoderated" / "pre-approval" warnings for non-wrapped events.
  - §12 (capability negotiation): add `strict-mode` capability advertisement so other clients know which mode peers operate in.
  - §11.1 prose unchanged in framing ("wire protocol accepts what it accepts"); strict mode is explicitly a client-side layer on top.

### Workstream 3 — Known gaps documented for v0.3

Items the architect deferred:

- Stricter moderator-specific KERI rotation (NIP-72 owner re-attestation, mandatory witness threshold). To be addressed after first-party-client surfaces real scenarios.
- ADR-004 key-derivation specifics (Megolm-coupled vs independent). Open until first-party-client builds it.

## ADR sequencing

Suggested dependency order (some ADRs touch overlapping sections):

1. **Editorial cleanup commit** (no ADR) — first, so subsequent ADRs work against a clean base.
2. **ADR-001** (MSC client-side) — gates §3, §5, §9, §13 edits.
3. **ADR-002** (KERI inline + §8.3) — gates §3.5 and §8.3.
4. **ADR-003** (security claims) — independent of 001/002; can land in parallel.
5. **ADR-004** (room-key wrap) — gates §6.7.4. Has open design questions; may need its own grill.
6. **ADR-005** (relay partitioning) — gates §6.7.2 and §6.9.1.
7. **ADR-006** (strict-mode client) — independent of others; touches §11 and §12.

## Test vectors that become possible after these changes

Each ADR enables specific test vectors that the next milestone (per CLAUDE.md) requires:

- ADR-001 → vector: vanilla-server compatibility test (encrypted state stored and retrieved as opaque content).
- ADR-002 → vectors: KERI inception, rotation, fork resolution (first-seen), moderator rotation.
- ADR-003 → vector: deniability assertion verification (none — explicitly documented as non-property).
- ADR-004 → vectors: room-key derivation, index encryption/decryption, member-removal key rotation.
- ADR-005 → vectors: missing-page detection, relay timeout behavior.
- ADR-006 → vectors: strict-mode client filtering, kind:5 deletion observation.

## Items the critique flagged that we are NOT acting on

- **Item 4 (±5 min rule "fatal"):** verification confirmed the critique misreads the spec. The rule applies only to the root attestation event and re-publication is the documented remedy. ADR-003 (b) adds a scoped NOTE block to prevent the misreading; no normative change.

## What changes in CLAUDE.md

The room taxonomy table in CLAUDE.md describes `private_deniable` as offering deniability. After ADR-003, the entry should be revised: "deniable against non-members; breakable by colluding members who share Megolm session keys."
