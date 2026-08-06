# Heterodyne v0.2.0 Spec Gap Research

**Date:** 2026-05-22
**Subject:** Gaps and improvement opportunities NOT covered by ADR-001 through ADR-007
**Source documents reviewed:**
- `docs/spec/heterodyne.md` (v0.2.0, 4209 lines)
- All seven ADRs in `docs/adr/` (001–007, dated 2026-05-21)
- `docs/architecture.md`
- `docs/security/threat-model.md`
- `docs/glossary.md`
- `docs/research/2026-05-21-critique-integration-research.md`
- `docs/research/2026-05-21-critique-integration-synthesis.md`
- `docs/spec/vectors/README.md`

---

## Summary

After the seven ADRs resolved all 16 external-critique items (MSC4362
client-side implementation, room-version pin, KERI inline profile and §8.3
port, security-claims hygiene, private-index Megolm-derived key wrap, relay
partitioning and page integrity, and strict-mode client profile), a
significant residual gap surface remains unaddressed. The most severe open
areas are:

- The MLS migration path is entirely schema-reserved but protocol-free.
- The anti-abuse contract for public Nostr relays carrying Heterodyne
  content has no normative wiring in the spec.
- Simultaneous multi-homed publishing and `kind:31005` race resolution are
  deferred with no conformance consequence stated.
- The conformance section contains zero authored test vectors and no
  definition of a minimum passing set.
- The bridge model is silent on asymmetric delivery failure (Matrix
  accepts, relay rejects permanently).
- A stale reference to the removed DM-based backfill protocol survives in
  §10.2.
- The §3.3 delegation `valid_until` check incorrectly inherits the ±5 min
  clock-skew rule that ADR-004 scoped to root attestations only.
- The NIP-72 contributor submission flow has no sender-side normative
  guidance.
- The federation-peer metadata exposure surface is absent from the §13.1.1
  attacker enumeration.

Twelve findings below; none is covered by ADRs 001–007. Spot-checks of
F3 (§3.3 lines 553–556) and F6 (§10.2 lines 3147–3149) confirmed the
contradictions are present verbatim in the current spec text.

---

## Coverage matrix

| # | Dimension | Gap exists? | Severity |
|---|---|---|---|
| 1 | Normatively underspecified spec sections | Yes — §10.2 stale reference; §3.3 valid_until conflict | major + major |
| 2 | MLS migration readiness | Yes — zero protocol machinery for the migration path | major |
| 3 | Anti-abuse / anti-spam contract | Yes — NIP-13/43/57/86 appear nowhere normatively | major |
| 4 | Cross-account / multi-homing semantics | Yes — race, conflict, and sync undefined | major |
| 5 | Migration / portability | Yes — homeserver-exit procedure entirely absent | minor |
| 6 | Bridge model invariants | Yes — asymmetric delivery failure unspecified | major |
| 7 | Discovery surface gaps | Yes — NIP-50, NIP-90, kind:39089 absent from §7 | minor |
| 8 | Conformance and test vectors | Yes — zero vectors authored; no minimum set defined | major |
| 9 | Privacy / metadata exposure | Yes — federation-peer attacker class absent from §13.1.1 | minor |
| 10 | NIP-72 moderated communities | Yes — contributor submission flow undefined | minor |
| 11 | Backward / forward compatibility | Yes — versioning silent on new room kinds and new indexing kinds | minor |
| 12 | Editorial / structural issues | Yes — stale DM-backfill ref in §10.2; vectors README references deprecated successor chain | editorial |

---

## Findings

### F1. MLS migration is schema-reserved but protocol-free

**Severity:** major

**Spec location(s):** §9.2 lines 2998–3039; §5.4 line 1570–1571;
§3.8.1 line 943; §9.2 lines 3036–3039

**Gap:** §9.2 reserves an `m.heterodyne.encryption_version.v1` state event
with `algorithm: "megolm"`, `migrated_from: null`, `migrated_at: null`. The
MLS migration procedure is explicitly deferred: "The MLS migration procedure
(re-key, member re-acknowledgement, atomic flip of `algorithm`, populating
`migrated_from` and `migrated_at`) is deferred to a future spec version."
The spec elsewhere references "the MLS variant once stabilized" as a
near-term drop-in. No dual-protocol period is defined; no capability
negotiation hook exists in `m.heterodyne.capabilities.v1` (§12.2) for
encryption-algorithm advertisement; no key-continuity guarantee is described
across the Megolm→MLS switch; no normative trigger condition is defined.
The state event itself is encrypted (ADR-001 client-side MSC4362), creating
a bootstrapping problem for MLS migration signaling.

**Why it matters:** First-party-client implementers targeting MLS readiness
have no protocol surface to implement against. If two independent clients
ship MLS support simultaneously and trigger migration independently, the
room enters an undefined state.

**Not covered by:** None of ADR-001 through ADR-007. ADR-001 covers
MSC4362 client-side state encryption; it does not touch the
Megolm→MLS plane.

**Suggested remediation shape:** Add `encryption_algorithms_supported` to
the `m.heterodyne.capabilities.v1` schema; define a normative migration
readiness check; specify atomic flip semantics and the in-flight Megolm
message handling; define receiver behavior when a non-MLS-capable client
encounters a flipped room.

---

### F2. Anti-abuse contract for public Nostr relays: no normative wiring

**Severity:** major

**Spec location(s):** §7.1 lines 2402–2413 (relay list); §10.5
lines 3190–3225 (vanilla relay interop); §3.0 lines 217–248
(kind table); §8 (moderation)

**Gap:** The spec lists Nostr relays as a first-class publish target for
all public content and feed indexes. The research index catalogs NIP-13
(PoW), NIP-43 (client auth), NIP-86 (relay admin), NIP-57 (zap-gating),
NIP-51 (mute lists), NIP-72 (community moderation). None appears in the
normative spec. There is no MUST/SHOULD on: NIP-43 AUTH challenge handling;
NIP-86-protected private relay discovery; whether PoW is required for
write-side; how `kind:31007` indexes behave when a relay rejects a write
due to spam scoring.

**Why it matters:** Independent implementations will diverge on relay
authentication. Clients that don't implement NIP-43 AUTH cannot write to
spam-resistant relays, silently breaking public publishing.

**Not covered by:** ADR-006 covers retrieval-side partitioning, not
write-side relay access control or spam resistance.

**Suggested remediation shape:** Add a normative subsection to §10.5 or
§7.1: clients MUST implement NIP-43 AUTH challenge/response; SHOULD
implement NIP-13 PoW with configurable target; MUST surface relay-rejection
errors. Whether zap-gating (NIP-57) is in-scope for v0.2 is an explicit
design decision to record.

---

### F3. §3.3 delegation `valid_until` check incorrectly inherits the ±5 min root-attestation rule

**Severity:** major

**Spec location(s):** §3.3 lines 553–556; §3.2.1 NOTE block (ADR-004
addition)

**Gap:** §3.3 active-delegation rule 4 reads: "`nostr_attestation.tags`
includes a `["valid_until", "<unix-seconds>"]` tag that is either empty
(no expiry) or strictly greater than the verifier's current time, **within
the strict ±5 minute clock-skew bound of §3.2.1**." The ADR-004 NOTE block
in §3.2.1 states explicitly: "This ±5 minute rule applies ONLY to
`m.heterodyne.root.v1` root attestation events … Verifiers MUST NOT apply
the ±5 minute rule to other event kinds." These two normative statements
are in direct conflict.

**Why it matters:** Two independent implementations will resolve
differently. One will interpret the ±5 min bound as a clock-skew tolerance
(`valid_until > now − 5m`); the other as inapplicable to delegations per
the NOTE. Silent interoperability failure: one client accepts a
just-expired delegation, the other rejects it.

**Not covered by:** ADR-004 added the NOTE block to §3.2.1 and forward
references in §13. It did not audit downstream uses of "±5 minute" in §3.3
rule 4. The critique-integration research item 4 confirmed the rule was
correctly scoped to root attestations but did not notice the §3.3 conflict.

**Suggested remediation shape:** Delete "within the strict ±5 minute
clock-skew bound of §3.2.1" from §3.3 rule 4. Either (a) treat
`valid_until` as a simple wall-clock comparison, or (b) define a separate
explicit clock-skew tolerance for delegations rather than inheriting from
a rule the NOTE says doesn't apply.

---

### F4. Multi-homing semantics: simultaneous publishing and `kind:31005` race conditions undefined

**Severity:** major

**Spec location(s):** §3.1 lines 328–334; §3.2 lines 356–368; §3.8.4
lines 1095–1105; §6.1 lines 1716–1726; §6.3 lines 1754–1772

**Gap:** Multi-homing (one npub, multiple MXIDs on multiple homeservers)
is the core intuition, but three scenarios are normatively undefined:

1. **Simultaneous publish from two delegated devices.** Device A on H1
   and device B on H2 both sign a kind:1 at the same millisecond with
   the same nsec. §6.1's "exactly one signed Nostr event per intent"
   rule is violated; no coordination surface is specified. §3.8.4
   explicitly defers cross-MXID synchronization.

2. **`kind:31005` race conditions.** Two devices publish updated
   identity-pointers simultaneously pointing to different identity rooms.
   NIP-01 resolves by `created_at` desc then event-id asc. The spec says
   "verifiers MUST prioritize the `matrix_identity_room` value carried by
   the latest valid `kind:31005`" without defining "latest" in the
   concurrent case, or what happens with divergent relay state.

3. **Single-MXID revocation.** §3.3 says revoke by "revoking the
   delegation and rotating Matrix credentials." No procedure for removing
   a single MXID's delegation while keeping others active; no handling
   for in-flight Megolm messages signed by the revoked MXID's device
   keys.

**Why it matters:** Multi-homing is the explicit design goal, not a
corner case. Without normative semantics, first-party clients will
diverge and cross-device/cross-homeserver users will experience
unpredictable behavior.

**Not covered by:** No ADR addresses cross-device coordination,
`kind:31005` race resolution, or single-MXID revocation. ADR-003 covers
persona-level KERI rotation, not MXID-level delegation lifecycle.

**Suggested remediation shape:** Add a normative §3.9 (or extend §3.3/§3.7)
specifying: (a) MUST that publishing devices coordinate signing via a
shared queue (mechanism implementation-defined); (b) a normative
tiebreaker for concurrent `kind:31005` events beyond NIP-01's
`created_at`; (c) an explicit single-MXID revocation procedure.

---

### F5. Bridge model: asymmetric delivery failure is unspecified

**Severity:** major

**Spec location(s):** §6.3 lines 1754–1772 (idempotency); §6.4
lines 1774–1796 (fan-out patterns); §10.1 lines 3121–3131; §10.2
lines 3132–3157

**Gap:** Idempotency is defined (Nostr event id is canonical, Matrix
txn_id ties to it). Four fan-out patterns are described. The spec is
silent on asymmetric failure: Matrix delivery succeeds (event in DAG)
but Nostr relay delivery permanently fails (all write relays reject).
This is not theoretical — a relay may reject for PoW insufficient
(F2), auth required (F2), content policy, or rate limits. The event
exists in the room but not in the persona's feed index and not on any
relay. §6.4 says clients SHOULD surface partial-failure state but
provides no normative definition of "permanent" relay failure, no MUST
for re-queuing, no MUST for index update. Reverse case (Nostr OK,
Matrix fail) is similarly silent — is the event "published" for
indexing purposes?

**Why it matters:** Without a normative failure contract, clients will
diverge: some index only on full-delivery success, others on partial
success, producing inconsistent feed views for the same persona's
followers.

**Not covered by:** ADR-006 covers relay partitioning during retrieval
(consumer side). No ADR addresses publication-side delivery failure.

**Suggested remediation shape:** Add a normative subsection to §6.4:
define "permanent" relay failure (non-transient NIP-01 NOTICE or
repeated connection failure beyond ADR-006's retry budget); specify
whether partially-delivered events are indexable; MUST that
partial-delivery state surface destination-level status, not a generic
"partial failure."

---

### F6. §10.2 contains a stale reference to the removed DM-based backfill protocol

**Severity:** major (direct internal contradiction)

**Spec location(s):** §10.2 lines 3147–3149; §6.9.3 lines 2290–2301

**Gap:** §10.2 lists required client capabilities; the third bullet
reads: "Event retrieval against the three channels (§6.9): NIP-01 REQ
to Nostr relays, HTTPS GET against archive URLs, **optional DM-based
retrieval request/response/push**." §6.9 and §6.9.3 explicitly remove
and forbid this: "Automated Matrix-DM-based backfill requests are
explicitly forbidden" (§6.9, line 2199–2200); "No Matrix-DM backfill
protocol" (§6.9.3 line 2293). The §10.2 reference is both stale and
normatively contradictory.

**Why it matters:** An implementer reading §10.2 first would implement
the DM backfill protocol, then discover §6.9.3 forbids it. Direct
internal contradiction on a deliberately-removed capability.

**Not covered by:** No ADR addresses this stale reference. The removal
is documented in the preamble (lines 28–30) and §6.9 but was not
propagated to §10.2.

**Suggested remediation shape:** Replace §10.2 bullet 3 with: "Event
retrieval via two channels (§6.9): NIP-01 REQ to Nostr relays (with
complete-fetch-attempt semantics per §6.9.1 / ADR-006) and HTTPS GET
against user-hosted archive URLs (§6.9.2). DM-based retrieval is
explicitly forbidden (§6.9.3)."

---

### F7. NIP-72 contributor submission flow: no sender-side normative guidance

**Severity:** minor

**Spec location(s):** §8.1 lines 2661–2708 (approval wire form); §8.4
lines 2838–2870 (no explicit rejection); §5.3 lines 1507–1551
(public_moderated room)

**Gap:** §8 specifies the moderator side fully: candidate fetch, `kind:4550`
approval, `kind:31007` index update, `kind:5` revocation. The follower
side is specified (read moderator indexes, count approvals, render).
The contributor side has no normative guidance: which relays to publish
to for moderator discoverability; what NIP-72 community tags
(`["a", "34550:<pubkey>:<d-tag>"]`) Heterodyne adopts; how to detect
pending-approval status; how long to wait before concluding rejection.

**Why it matters:** Without sender-side guidance, contributors to
`public_moderated` rooms have no protocol to implement. NIP-72's own
spec is sufficiently vague that implementations diverge.

**Not covered by:** ADR-007 covers follower UI (strict-mode rendering),
not contributor submission.

**Suggested remediation shape:** Add §8.0 or §8.1.1: contributor MUST
tag with NIP-72 community address; SHOULD publish to moderator NIP-65
write relays (discoverable via `m.heterodyne.moderators.v1`);
RECOMMENDED pending-approval detection (poll for the post id in
`kind:4550`).

---

### F8. Homeserver portability: no room-export or homeserver-exit procedure

**Severity:** minor

**Spec location(s):** §3.2 lines 348–368 (identity room disposability);
§3.7 lines 898–921; §3.8 lines 923–934

**Gap:** The identity room is "disposable" — a persona can abandon
compromised state. But voluntary homeserver-exit (H1 shuts down, raises
prices, or is deplatformed) has no procedure: no export format for
private room history + Megolm session keys; no procedure for
re-publishing private room encrypted state to a new room ID on H2; no
guidance for members of abandoned private rooms; config room (§3.8) is
scoped to a single MXID and its portability is undefined.

**Why it matters:** Homeserver exit defines practical
censorship-resistance. Users on a shutting-down homeserver with no exit
procedure effectively lose private room history and membership.

**Not covered by:** No ADR addresses portability.

**Suggested remediation shape:** Add §3.10 or §10.6 homeserver-exit
section: voluntary identity-room migration steps; whether private room
history is exportable and via which mechanism; RECOMMENDED member
notification of new room ID via scoped outbox or transitional
announcement event.

---

### F9. §14 conformance: zero vectors authored, no minimum passing set defined

**Severity:** major

**Spec location(s):** §14.3 lines 4175–4194; §14.4 lines 4196–4208;
`docs/spec/vectors/README.md`

**Gap:** §14.3's coverage map lists nine vector topic directories.
`vectors/` contains only `README.md`. The spec says "Any client
implementation claiming conformance MUST pass every vector in
`vectors/`" but with no vectors, the claim is vacuous. Additionally:

1. No minimum subset is defined. §14.4 allows skipping with rationale,
   but with no floor, "MLS not yet supported" rationale for every
   vector would technically satisfy §14.4.
2. `vectors/README.md` (pre-v0.2.0) lists "successor chain" as a
   planned category — that mechanism was deprecated and removed
   (§3.5.4). ADR-003 requires new KERI vectors; README is not updated.
3. No definition of baseline-conformance vs. strict-mode-conformance
   vector splits. Strict-mode (§11.7) introduces new MUSTs;
   conformance split is unclear.

**Why it matters:** Two independent implementations cannot verify
interoperability. The conformance claim is currently unfalsifiable.
The first-party client milestone depends on vectors.

**Not covered by:** Each ADR's consequences list says "test vectors
required" but none defines the minimum set or updates the README.

**Suggested remediation shape:** (a) Update `vectors/README.md` to
replace "successor chain" with KERI categories and add the ADR-required
vector categories; (b) define in §14.3 a normative minimum set; (c)
note that strict-mode conformance additionally requires all
`moderation/` vectors from §11.7.

---

### F10. Discovery: NIP-50 search, NIP-90 DVMs, kind:39089 starter packs absent from §7

**Severity:** minor

**Spec location(s):** §7 lines 2303–2609; §3.0 kind table lines 217–248

**Gap:** §7 specifies audience-stratified discovery via outbox state
events, the discovery walk, follow semantics, and cross-persona
advertisement. The research index catalogs NIP-50 (search), NIP-90 DVMs
(algorithmic feeds), kind:39089 starter packs. None appears in §7
normatively or as an explicit non-goal. NIP-50 is relevant because
Heterodyne public content lives on relays that may support search.
NIP-90 DVMs are relevant for algorithmic feed ranking and AI moderation
(research-documented). kind:39089 is directly relevant to the discovery
walk.

**Why it matters:** Discovery is user-facing. Without normative
guidance on search and algorithmic feeds, implementations diverge.

**Not covered by:** No ADR addresses discovery beyond what the spec
already specifies.

**Suggested remediation shape:** Add §7.6: whether NIP-50 search is
RECOMMENDED or out-of-scope; whether kind:39089 starter packs are a
recognized discovery mechanism; whether NIP-90 DVM-based feed ranking
is an explicit non-goal for v0.2 (defer to v0.3). Explicit silence is
better than current omission.

---

### F11. §12 versioning policy: silent on new room kinds and new indexing-table entries

**Severity:** minor

**Spec location(s):** §12.1 lines 3829–3845 (strict semver); §5.1
lines 1389–1456 (taxonomy); §6.8.1 lines 2155–2191 (indexing table);
§3.0 lines 217–248 (kind table)

**Gap:** §12.1 defines MAJOR/MINOR/PATCH triggers. Two addition-type
changes are not addressed:

1. **Adding a new room kind.** §5.1 uses a closed enumeration: "The
   `kind` field MUST be one of: [8 specific values]." Adding a new kind
   requires clients to accept unknown kinds without breaking. Is this
   MAJOR (receivers reject unknown) or MINOR (receivers render
   placeholder)? Spec is silent.
2. **Adding a new Nostr kind to §6.8.1.** Changes catch-all behavior
   for previously-conformant implementations. MAJOR? Spec silent.

**Why it matters:** Without explicit policy for these common extension
patterns, additions become a potential breaking-change landmine.

**Not covered by:** No ADR addresses versioning extension surface.
ADR-002 pins the Matrix room version explicitly but no analogous
mechanism for the Nostr kind table or room kind enumeration.

**Suggested remediation shape:** Two sentences to §12.1: (1) "Adding a
new room kind to the §5.1 enumeration is a MINOR bump; receivers MUST
tolerate unknown room-kind values per §12.3 (render placeholder) rather
than rejecting." (2) "Adding a new Nostr kind to §6.8.1 where it
previously fell under catch-all is a PATCH bump; additive
clarification, not a wire-format change."

---

### F12. Federation-peer attacker class absent from §13.1.1

**Severity:** minor

**Spec location(s):** §13.1.1 lines 4008–4056 (attacker capabilities
per ADR-004); `docs/security/threat-model.md` actors table

**Gap:** §13.1.1 enumerates six attacker classes: external observer,
curious homeserver, member-with-Megolm, colluding members, time-window,
JSON-canonicalization. The threat model lists six actors: trusted
client, hostile homeserver, hostile relay, passive network observer,
compromised delegation, compromised npub root. Neither enumeration
includes a **Matrix federation peer** — a homeserver participating in a
room's federation that is neither the persona's own homeserver nor an
adversary's. A federation peer sees: all plaintext public-room state;
all Megolm ciphertexts (opaque); all `m.room.member` events; sender
MXIDs and timestamps; the federation join event graph. Distinct from
"curious homeserver" (the persona's own).

**Why it matters:** Heterodyne's claim that the Matrix homeserver is a
blind state manager is partially undermined by federation peers
receiving the same state. Documenting this attacker class precisely
lets implementers reason about, e.g., hosting a `public_broadcast`
identity room on a well-known homeserver.

**Not covered by:** ADR-004 added §13.1.1 with scope "ones whose
precise naming changes how §13.2 invariants are interpreted."
Federation-peer exposure does not change any current invariant but is
a completeness gap.

**Suggested remediation shape:** Add a "Federation peer" entry to
§13.1.1 enumerating what it sees (membership, timing, public state)
and cannot see (Megolm content in private rooms); note which invariants
mitigate (I1 covers private content; nothing covers public-room
membership-graph leakage, acknowledged as Matrix-layer limitation).

---

## Items considered and rejected because an ADR covers them

The following items were investigated but found to be addressed by
existing ADRs:

- **MSC4362 server dependency** → ADR-001
- **Non-Heterodyne client interop in private rooms** → ADR-002
- **Matrix room version pinning** → ADR-002 (v11, ADR-required to bump)
- **KERI witness-agreement rule correction** → ADR-003
- **§8.3 moderator key rotation stale terminology** → ADR-003
- **Deniability overclaim in §5.5 and §5.4** → ADR-004
- **±5 min clock-skew scope ambiguity in §13** → ADR-004 (NOTE + §13
  forward ref) — note F3 above is a separate site that ADR-004 missed
- **`nip01_raw` rationale (array vs object key reorder)** → ADR-004
- **Private index per-recipient NIP-59 scaling** → ADR-005
- **Missing-page handling and relay-set timeout** → ADR-006
- **`prev_page_hash` page-chain integrity** → ADR-006
- **State-downgrade attack** → ADR-001 req 5 + ADR-007 strict-mode UX
- **Bare event filtering in private_verifiable rooms** → ADR-007
- **kind:5 deletion enforcement timeout** → ADR-007 (30s MUST)

---

## Essential files for understanding this topic

- `docs/spec/heterodyne.md` — normative spec, all findings cite line
  numbers within this file
- `docs/adr/archive/2026-05-21-001-client-side-msc-implementation.md`
- `docs/adr/archive/2026-05-21-002-private-room-interop-profile.md`
- `docs/adr/archive/2026-05-21-003-keri-inline-profile.md`
- `docs/adr/archive/2026-05-21-004-security-claims-hygiene.md`
- `docs/adr/archive/2026-05-21-005-private-feed-index-room-key-wrap.md`
- `docs/adr/archive/2026-05-21-006-relay-partitioning-page-integrity.md`
- `docs/adr/archive/2026-05-21-007-strict-mode-client-profile.md`
- `docs/security/threat-model.md`
- `docs/spec/vectors/README.md`
- `docs/research/2026-05-21-critique-integration-research.md`
- `docs/research/2026-05-21-critique-integration-synthesis.md`
