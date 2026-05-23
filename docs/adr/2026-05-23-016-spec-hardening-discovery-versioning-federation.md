# ADR-016: Spec hardening — discovery scope, versioning extension policy, federation-peer attacker class

**Date:** 2026-05-23
**Status:** Accepted
**Decision makers:** Liam Helmer (architect); star-chamber providers: gpt-5 (via Fuel-IX, two-instance parallel review); local Claude subagent

## Context

Three small spec-hardening additions surfaced in the v0.2.0 gap audit (`docs/research/2026-05-22-spec-gaps-research.md` findings C5, C6, C7). Each is documentation-style or scope-clarification; none changes wire format. Bundling into one ADR avoids three minimal ADRs for what are conceptually a single hardening pass.

**Discovery extensions (C5).** §7 specifies audience-stratified discovery via outbox state events, the discovery walk, follow semantics, and cross-persona advertisement. The research index (CLAUDE.md, research/INDEX.md) catalogs NIP-50 (relay-side search), NIP-90 (Data Vending Machines for algorithmic feeds and AI moderation), and `kind:39089` (starter packs for new persona follows). None appears in §7 normatively or as an explicit non-goal. Implementers reading §7 today have no guidance on whether to support these mechanisms; first-party-client implementation will diverge from third-party clients on user-facing discovery UX.

**Versioning extension policy (C6).** §12.1 (lines 3829–3845) defines MAJOR/MINOR/PATCH semantics. The MAJOR triggers cover field removal, semantic change, retirement of event types, kind-number changes in the Heterodyne-reserved 31000 range, and new MUSTs that would reject prior-version events. The MINOR triggers cover new OPTIONAL fields, new event types, and loosened MUSTs. Two common addition patterns are not addressed:
- Adding a new room kind to the §5.1 enumeration (currently closed: "The `kind` field MUST be one of: [8 specific values]").
- Adding a new Nostr kind to the §6.8.1 default-indexing-classification table where the kind previously fell under the catch-all rule.

Both are likely future extension points and need an explicit policy to avoid being landmines.

**Federation-peer attacker class (C7).** §13.1.1 (lines 4008–4056, added by ADR-004) enumerates six attacker capability classes: external observer, curious homeserver, member-with-Megolm, colluding members, time-window attacker, JSON-canonicalization attacker. Neither this enumeration nor the companion threat model (`docs/security/threat-model.md`) lists Matrix **federation peers** — homeservers participating in a room's server-server federation that are neither the persona's own homeserver nor the persona's adversary. A federation peer is distinct from "curious homeserver" (the persona's own) and sees materially different things: full unencrypted state in public rooms, all Megolm ciphertexts as opaque blobs, all `m.room.member` events, sender MXIDs and timestamps, the federation join-event graph.

The federation-peer omission does not change any existing invariant (I1 already covers private-room content), but it is a completeness gap in the threat model.

## Decision

Add a new §7.6 declaring discovery-extension scope (NIP-50 OPTIONAL, kind:39089 RECOMMENDED, NIP-90 explicit non-goal for v0.2). Amend §12.1 with two sentences covering new room kinds and new indexing-table entries. Add a federation-peer entry to §13.1.1's attacker enumeration.

## Requirements (RFC 2119)

### Discovery extensions — new §7.6

1. The spec MUST add a new subsection §7.6 "Discovery extensions" containing the following statements:
2. **NIP-50 (relay-side search) — OPTIONAL.** Clients MAY support NIP-50 search queries against subscribed relays. Search results referencing npubs MUST be resolved via the standard discovery walk (§7.3) before being trusted; relay-returned npub lists are NOT authoritative for identity resolution.
3. **kind:39089 (starter packs) — RECOMMENDED.** Clients SHOULD recognize `kind:39089` events as a discovery mechanism for new persona follows. Each npub in a starter pack MUST be resolved via the standard discovery walk before being added to the user's follow set.
4. **NIP-90 (Data Vending Machines for algorithmic feeds, AI moderation) — explicit non-goal for v0.2.** Heterodyne v0.2 makes no statement about DVM use; clients neither REQUIRE nor are PROHIBITED from supporting them, but baseline conformance does not depend on DVM behavior. A future spec version may define DVM integration semantics.

### Versioning extension policy — amendments to §12.1

5. The §12.1 versioning triggers MUST be extended with two sentences:
6. **New room kinds.** "Adding a new room kind to the §5.1 enumeration is a MINOR bump. Receivers MUST tolerate unknown room-kind values per §12.3 (render placeholder, do not reject the room)."
7. **New indexing-table entries.** "Adding a new Nostr kind to the §6.8.1 default-indexing-classification table — where that kind previously fell under the catch-all rule — is a PATCH bump. The behavior change is additive clarification of existing classification rules, not a wire-format change."

### Federation-peer attacker class — addition to §13.1.1

8. The §13.1.1 attacker enumeration MUST be extended with a new entry:
   > **Federation peer.** A Matrix homeserver participating in a room's server-server federation that is neither the persona's own homeserver nor the persona's adversary. Distinct from "curious homeserver" (the persona's own homeserver).
   >
   > **What a federation peer can observe:** all unencrypted state events in public rooms (room kind, outbox advertisements, moderator list, member power levels); all Megolm-encrypted timeline events as opaque ciphertext (envelope metadata visible); all `m.room.member` events (full membership list); sender MXIDs and origin_server_ts on every event; the federation join event graph (which servers federated with the room and when).
   >
   > **What a federation peer cannot observe:** Megolm-encrypted timeline or state content in private rooms (content protected by Megolm); identity-room content for personas hosted on homeservers the federation peer is not federated with; encrypted config-room contents (per ADR-009).
   >
   > **Mitigations.** Invariant I1 covers private-room content confidentiality and is unaffected by federation-peer presence. Public-room membership-graph leakage is an acknowledged Matrix-layer limitation; personas concerned about membership-graph exposure SHOULD host their identity room on a homeserver whose federation peer set they trust (e.g., a homeserver federated only with vetted peers). Heterodyne's wire-level invariants (I1–I7) do not change because of federation peers; this entry is a completeness addition to the attacker enumeration, not a new mitigation requirement.

### Cross-references

9. The threat model document (`docs/security/threat-model.md`) MUST be updated to include the federation-peer actor in its actors table, with the same observation/cannot-observe split and mitigation note as §13.1.1 (consistency with the normative spec).

## Rationale

Bundling three small documentation-style additions into one ADR keeps ADR overhead proportional to the change size. None of the three has a meaningful design choice — they are all "make explicit what was previously implicit."

The NIP-50 OPTIONAL + kind:39089 RECOMMENDED + NIP-90 non-goal split (reqs 2–4) reflects implementation maturity: NIP-50 is widely supported and useful but not load-bearing; kind:39089 is a low-cost UX win for new-user onboarding; NIP-90 is a substantial integration with complex security properties (algorithmic feeds shape user attention) and warrants its own dedicated ADR rather than a passing mention.

The versioning amendments (reqs 6–7) classify common extension patterns. The MINOR-bump rule for new room kinds requires receivers to tolerate unknowns — a forward-compat invariant that costs nothing and prevents future hard breaks. The PATCH-bump rule for new indexing-table entries acknowledges that promoting a kind from catch-all to an explicit table entry doesn't change the wire format; it clarifies a previously-defaulted behavior.

The federation-peer entry (req 8) restores threat-model completeness. The honest framing — "we cannot prevent federation-peer membership-graph observation, this is a Matrix-layer limitation, here is what mitigation is available" — is consistent with ADR-004's overall stance on security claims hygiene.

## Alternatives Considered

### (A) Three separate one-paragraph ADRs
- **Pros:** Each item is independently citable.
- **Cons:** ADR overhead exceeds change size; encourages micro-ADR proliferation.
- **Why rejected:** Bundling is proportional.

### (B) Make NIP-50 RECOMMENDED (stronger discovery story)
- **Pros:** Better search UX across implementations.
- **Cons:** Forces every client to implement NIP-50 query handling; not all relays support it; relay-returned npub lists need careful trust handling.
- **Why rejected:** OPTIONAL is the right fit; clients that want it can add it.

### (C) Include NIP-90 DVMs as RECOMMENDED for algorithmic feeds
- **Pros:** Enables algorithmic feed-ranking and AI-assisted moderation.
- **Cons:** DVMs shape user attention; the security and UX implications need dedicated design attention; first-party client hasn't validated DVM behavior.
- **Why rejected:** Explicit non-goal for v0.2; revisit in a dedicated ADR.

### (D) Require federation-peer mitigation as a new MUST
- **Pros:** Strengthens privacy story.
- **Cons:** No client-side or wire-level mitigation exists for membership-graph observation; making a MUST would be aspirational. Matrix doesn't provide the primitives.
- **Why rejected:** Document the limitation honestly; don't manufacture mitigations that don't exist.

## Assumed Versions (SHOULD)

- NIP-50 (search): stable.
- NIP-90 (DVMs): stable but evolving; non-goal for v0.2.
- kind:39089 (starter packs): convention exists in the Nostr ecosystem; no formal NIP yet but widely supported.
- ADR-004 (security claims hygiene): foundational; this ADR extends §13.1.1 in the same spirit.

## Consequences

- New §7.6 added per reqs 1–4.
- §12.1 amended with reqs 6–7.
- §13.1.1 amended with req 8.
- `docs/security/threat-model.md` updated per req 9.
- No new wire formats, capabilities, or test-vector categories required for the discovery scope or versioning amendments.
- Test vectors required (per ADR-011): none for discovery scope (OPTIONAL/RECOMMENDED behaviors are not in the baseline vector floor); none for versioning amendments (documentation only); the federation-peer entry is documentation — no vector test.
- The room-kind tolerance requirement (req 6) implies that current Heterodyne clients MUST already implement the §12.3 placeholder behavior; baseline conformance vectors (per ADR-011) include this implicitly via the existing §12.3 testing.
- Setting NIP-90 as explicit non-goal closes one common implementer question (per CLAUDE.md research/INDEX.md, DVMs are research-mentioned with no spec disposition).

## Council Input

Star-chamber's review did not raise specific concerns with the three additions. The federation-peer omission is straightforward (it's a completeness gap that ADR-004 addressed adjacent material but didn't catch). The versioning amendments are mechanical. The discovery scope clarifies what was previously silent.

The architect's choice to bundle these three into a single ADR (rather than three ADRs) was guided by ADR overhead proportionality — none of the three has architectural depth warranting standalone treatment.
