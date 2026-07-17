# Three-protocol split research: persona communication, command-and-control, social media

Date: 2026-07-15
Status: research (non-normative)
Subject: Feasibility and packaging of dividing Heterodyne (currently one 0.4.0-draft
spec) into three separable protocols - Protocol 1 (secure persona communication over
Nostr: identity, transport, 1-1 messaging, 1-many publishing, confidentiality),
Protocol 2 (command-and-control over Nostr: device enrollment, RPC, agentic
clients), and Protocol 3 (social media, still to be fleshed out, draft-only) - so
that P1/P2 can stabilize and release ahead of P3.

## Summary

The current spec (`docs/spec/heterodyne.md`, working tree includes uncommitted
ADR-032 integration for `kel_head`, repo authority, materialized KEL refs, and
did:webs export) is dividable along the requested lines, but identity (KERI, the
kind-number registry, node/repo topology) is used by all three protocols and is the
central unresolved question: fold it into Protocol 1, or extract a fourth
"Identity Core" layer beneath all three. Protocol 2 barely exists as spec surface
today - it is seeded by exactly one proposed, not-yet-integrated ADR (ADR-030,
light-client enrollment/RPC over double-ratchet DMs) riding Protocol 1's §5.7 DM
engine as its transport. Protocol 3 is almost everything social-specific:
moderation (§8), communities, feed-index curation for orgs, the OPTIONAL Matrix
discussion layer, NIP-51 lists (partially), outbox threading, and discovery's
"following" semantics.

The closest external precedent for the user's shape is AT Protocol's
`com.atproto.*` core vs `app.bsky.*` application lexicons - a generic
identity/transport/sync layer that is heading toward IETF standardization while
the social-application layer keeps churning informally. KERI/ACDC (two separate
ToIP specs, one-directional dependency) is the best precedent for extracting
identity as its own foundation layer. The IETF downref rule (RFC 3967/4897,
draft-kucherawy-bcp97bis) is the sharpest concrete constraint on the "P1/P2 hit
1.0 while P3 stays 0.x" goal: a mature document cannot carry a normative
dependency on an unstable one, which means any shared registry a stabilizing P1/P2
still shares with a churning P3 (kind numbers, reason codes) must be resolved
before 1.0, not deferred.

## A. Current spec inventory and mapping

### A.1 Method

Mapping was built by reading the ADR index (`docs/adr/`, all 32 entries, with full
text read for ADR-026 through ADR-032 plus the two untracked/proposed ADRs
ADR-030 and ADR-031), `docs/architecture.md` (the "load-bearing decisions" list),
the full table of contents of `docs/spec/heterodyne.md` (grepped headings, all
221+ section/subsection headers), and close reads of §1-§2, §3.0 (the kind
allocation table, the single most useful classification artifact in the spec),
§4.1-§4.3, §5.7, §7.0, §8 (opening + §8.0-8.1), §9.0, §10.1-10.2, §12.1, §14.3
(the coverage map), plus `docs/spec/vectors/README.md`'s CORE-vs-OPTIONAL-Matrix
split and `docs/spec/extensions/{nips,mscs}/README.md`. Section numbers below are
verified against the live table of contents, not recalled.

**Protocol legend:** P1 = secure persona communication (identity, transport, 1-1
messaging, 1-many publishing, confidentiality). P2 = command-and-control
(enrollment, RPC, agentic clients). P3 = social media (draft). FOUNDATION = used
identically by all three; a candidate for a fourth "Identity Core" or
"Substrate Core" document regardless of how P1-P3 are packaged.

### A.2 Section-by-section mapping

| Spec section | Title | Classification | Note |
|---|---|---|---|
| §1.1 | Scope | FOUNDATION | Enumerates all of identity, envelope, tiers, publishing, discovery, moderation, DMs, backup, bridge, Tor, redundancy, social recovery, relay profile in one list - would itself need to be split three ways or kept as a foundation-plus-pointers document. |
| §1.2 | Non-goals | FOUNDATION | No transport/new-kind/directory/replace-vanilla claims apply identically to all three. |
| §2 | Terminology | FOUNDATION | npub, persona, Radicle, NID, RID, repo relay, node roles, KEL, delegation, wrap mode - reused verbatim by P2 and P3. A few terms ("broadcast vs discussion," "sets file") lean P3. |
| §3.0 | Nostr kind allocations | FOUNDATION (hard case) | The single global 31000-31099 reserved range plus every adopted upstream kind (1, 5, 7, 1059/1060, 4550, 10000-39999, ...) is one registry today. Splitting requires either partitioning the numeric range per protocol now, or keeping one shared registry document all three normatively reference (an IETF-downref-shaped problem, see §C.7). |
| §3.0.1 | Canonical Nostr serialization / `nip01_raw` | FOUNDATION | Every wire form in P1, P2 (RPC rumors), and P3 depends on this one verification primitive. |
| §3.1 | npub is canonical | P1 / FOUNDATION | Core identity claim. |
| §3.2, §3.2.1 | Identity pointer (`kind:31005`), root attestation | P1 | Discovery-adjacent but framed as identity, not social. |
| §3.3, §3.3.1 | Delegations, NID delegation | P1 (hard case) | The delegation attestation class is P1's, but ADR-030 extends it with a new "session device" subtype for P2, and organizations (ADR-027, `crefs` governance) extend it for P3-flavored community use. One schema, three consumers. |
| §3.3.2 | MXID delegation | P3 (OPTIONAL Matrix layer) | Matrix-specific delegation target only. |
| §3.4 | Multiple personas | P1 | Org personas (a `§3.4`-adjacent concept via ADR-027) trend P3; ADR-030 explicitly excludes org personas from P2 enrollment. |
| §3.5 (all subsections) | KERI root inception/rotation | FOUNDATION (hard case, explicitly flagged by task) | The identity/rotation core every other mechanism (DM binding, delegation, feed-index canonicity, RPC enrollment) verifies against. Strongest single candidate for extraction into a fourth "Identity Core" spec. |
| §3.6, §3.6.1 | Identity discovery, authority ladder | FOUNDATION | Same reasoning as §3.5. |
| §3.7 | Failure modes | P1 / FOUNDATION | |
| §3.8-§3.8.5 | Client config / OPTIONAL Matrix config room | P3 (Matrix mirror only) | |
| §3.8.6-§3.8.8 | Config repo, keys repo, USB backup | FOUNDATION | Used by P1 (persona backup) and by P2 (ADR-030 item 8: grant table/token registry are explicitly carved out of, but stored alongside, this same config-repo/keys-repo model). |
| §3.9-§3.9.10.1 | Multi-homing, KEL/Radicle reconciliation, repo authority (ADR-032) | FOUNDATION | |
| §3.10 | Voluntary homeserver-exit | P3 (OPTIONAL Matrix layer) | |
| §3.11 | Mirroring / multi-homed redundancy | FOUNDATION | Radicle seeding benefits P1 broadcast, P2 full-node durability, and P3 community repos identically. |
| §3.12 | Social recovery | P1 | Identity continuity, not a "social" feature despite the name. |
| §4.1 | Canonical event, two envelope types | P1 / FOUNDATION | |
| §4.2, §4.3, §4.4 | Wrapped event, bare event, wrap-mode defaults | P3 (OPTIONAL Matrix layer) | These are specifically the Matrix-envelope forms (`m.heterodyne.note.v1`, `m.room.message` + `heterodyne_nostr_sig`); the underlying nip01_raw/signature discipline they reuse is FOUNDATION, but the envelope *types themselves* only exist because Matrix is in play. |
| §4.5, §4.5.1, §4.5.2 | Verification algorithm, `kel_head` accelerator, provisional acceptance | FOUNDATION | Used by every kind in every protocol. |
| §5.1, §5.2, §5.2.1-3, §5.6 | Repo-visibility tiers (public/private/encrypted), multi-feed patterns | P1 | This is "1-many publishing" in the task's own framing. |
| §5.4, §5.5 | `public_discussion`, `private_discussion` (OPTIONAL Matrix) | P3 | |
| §5.7 (all subsections) | Direct messages (CORE double ratchet) | **P1, and explicitly the literal wire ADR-030 (P2) rides** | The task's own flagged hard case, confirmed by reading: §5.7.1 defines invites/`kind:1060`/inner rumors; ADR-030 item 6 says "Requests and responses are NIP-46-shaped payloads... carried as new inner rumor kinds inside the DR session." P2 has no transport of its own - it is a payload profile inside P1's session. |
| §6.1-§6.4, §6.4.1 | Publishing flow, destination set, idempotency, fan-out, asymmetric delivery | P1 | |
| §6.5 | Replies and threading (outbox model) | P3 (hard case) | Reactions/replies are social-interaction semantics; the mechanism (write into your own outbox) is generic enough to be P1, but nothing consumes it except social feeds today. |
| §6.6 | Mixing tiers/relays/OPTIONAL Matrix in one fan-out | P3 | |
| §6.7, §6.7.1-§6.7.6 | Feed index (`kind:31007`) | P1 / FOUNDATION | Canonical ordering/curation authority for any persona's outbox - not inherently social. |
| §6.7.0 | Org feed canonicity (delegate-threshold branch) | P3 (hard case) | Built on the P1/FOUNDATION identity model (ADR-027 orgs), but its only real consumer is community/moderation use. |
| §6.8, §6.8.1 | Indexed vs non-indexed events | P1 | |
| §6.9-§6.9.3 | Event retrieval / backfill | P1 / FOUNDATION | |
| §6.10-§6.10.4 | Encrypted-blobs-in-repo (Tier 3), private-repo tier (Tier 2), key-ID branch rotation | P1 | |
| §7.0 | Discovery primitives and node roles | FOUNDATION | `kind:31005`/`kind:31010`, full/routing/light node roles - identical machinery for all three protocols. |
| §7.1, §7.2 | Public / audience-scoped outbox advertisement | P1 | |
| §7.3 | Discovery flow | FOUNDATION | |
| §7.4 | Following semantics | P3 (hard case) | "Following" as a first-class social-graph relationship (vs. bare content-fetch subscription, which would be P1) is the softest line in the whole map - the coverage map currently bundles it into the CORE `outbox/` vector category. |
| §7.5 | Cross-persona advertisement | P3 | |
| §7.6 | Discovery extensions (ADR-016) | FOUNDATION | |
| §7.7 | Onion reachability / Tor transport | FOUNDATION | |
| §8 (all) | Moderation - NIP-72 approval, Radicle editorial-gating (§8.8), NIP-51 blocklists (§8.6), NIP-32 labels (§8.9), web-of-trust (§8.10) | P3 | Overwhelmingly community/social-curation. §8.5 personal mute lists is the one hard exception (see below). |
| §8.5 | Personal mute lists (NIP-51 `kind:10000`) | SHARED (hard case) | Normatively reused by P1's own DM acceptance-gating (§5.7.4 references "the §8.10 web-of-trust guidance" and mute state generally); primarily framed and vectored (§8.5/§8.6) as community-curation infrastructure. Cannot cleanly live in only one document. |
| §9.0 | Three privacy tiers and trust boundaries | P1 | Restates §5's confidentiality model - broadcast privacy, not discussion privacy. |
| §9.1, §9.1.1, §9.1.2 | Core-substrate invariants, OPTIONAL Matrix state-downgrade | P1 / FOUNDATION, P3 | |
| §9.2, §9.2.1 | Megolm/MLS migration (OPTIONAL Matrix) | P3 | |
| §9.3, §9.4 | Delegation revocation + Megolm lifecycle, KERI rotation interaction | P3 (Matrix-specific), FOUNDATION | |
| §9.5 | Forward secrecy posture per mechanism | P1 / FOUNDATION | Covers DM (P1) and Tier 3 broadcast (P1) alongside Matrix (P3) in one comparative table. |
| §9.6 | Backup and recovery | FOUNDATION | |
| §10.1, §10.1.1, §10.1.2 | Nostr + repo-relay client, node roles, repo-relay adapter | FOUNDATION | Storage/replication substrate for all three. |
| §10.2 | Client library responsibilities | FOUNDATION | |
| §10.3 | Personal headless bridge | P2-adjacent | An unattended, always-on bridging component is conceptually closest to P2's "agentic control node" framing even though currently written Matrix-bridge-flavored. |
| §10.4 | What homeservers MUST/MUST NOT do | P3 (OPTIONAL Matrix) | |
| §10.5, §10.5.1 | Vanilla Nostr relay interop, anti-abuse | P1 / FOUNDATION | |
| §10.6 | OPTIONAL Heterodyne-aware relay profile | FOUNDATION | |
| §11.1 | Vanilla Matrix clients | P3 | |
| §11.2-§11.4 | Vanilla Nostr interop, `kind:31005` cross-protocol verification, following vanilla users | P1 / FOUNDATION (hard case on §11.4, same "following" tension as §7.4) | |
| §11.5 | `fallback` field for vanilla Matrix rendering | P3 | |
| §11.6 (all) | ATProto attached outbox, KERI social witnesses | P1 (witnessing) + P3 (outbox mirroring) | Splits internally - the witness role is identity/P1, the mirror-outbox is broadcast-distribution/arguably-P3. |
| §11.7, §11.7.1-3 | Strict-mode client profile | Cross-cutting (hard case) | Bundles §8 moderation-enforcement MUSTs (P3) with transport/Tor MUSTs (FOUNDATION) into ONE profile. |
| §11.8 | Canonical-KERI interop: did:webs export (ADR-032) | FOUNDATION | |
| §12 (all) | Versioning and capability negotiation | FOUNDATION (mechanism), but must be tripled (content) | Same design pattern, independent `spec_version` per split document. |
| §13.1, §13.1.1 | Trust assumptions, attacker capabilities | FOUNDATION | |
| §13.1.2 | Pseudonymity, not deniability | P1 | |
| §13.2 | Normative security invariants (I1-I7-style labels) | FOUNDATION | A second cross-cutting registry (see §B.4). |
| §13.3 | Threat -> mitigation map | Mixed | Repo-relay/routing-node threats = FOUNDATION; DM metadata = P1; moderation-as-of integrity = P3; ADR-032 `kel_head`/repo-rollback threats = FOUNDATION. |
| §13.4 | Vanilla-relay reputation limitation | P1 / FOUNDATION | |
| §14 (all) | Conformance and test vectors | FOUNDATION (methodology); content splits along the §14.3 coverage map (see §A.3) | |

### A.3 Hard cases (detailed)

These are the calls that resist a clean single-protocol assignment, in the order
requested by the task, with an added correction the reading surfaced:

1. **Identity/KERI (§3, §3.0 kind registry) - part of P1 or a fourth "Identity
   Core"?** Every one of P1, P2, and P3's normative checks bottoms out in KEL
   replay (§3.5.3) or the `kel_head` accelerator (§4.5.1, ADR-032). Folding
   identity into P1 keeps today's document shape (minimal mechanical diff) but
   makes "P1 reaches 1.0" a much bigger bar, since P1 would then also carry all
   of KERI's own remaining churn (e.g. the roadmap compromised-key revocation
   item in ADR-032 §6, still unscheduled). Extracting identity as a fourth
   document mirrors the KERI/ACDC precedent (§C.6) exactly.

2. **§5.7 direct messages is P1's 1-1 messaging mechanism AND the literal
   carrier ADR-030 (P2) rides.** ADR-030 item 6 states RPC requests/responses
   are "carried as new inner rumor kinds inside the DR session" - P2 currently
   has no transport of its own. A packaging that ships P1 first and leaves P2 in
   draft is fine (P2 just isn't usable until its host protocol ships), but a
   packaging that ships P2 independently of P1 is not coherent under the current
   design - P2 has a hard runtime dependency on P1's session engine, not merely a
   documentation dependency.

3. **ADR-030 vs ADR-031 - only one of the two is actually Protocol 2 seed
   material.** The task's framing groups both proposed ADRs as "the SEED of
   Protocol 2." Reading both in full shows this is only half right: ADR-030
   (light-client enrollment/RPC, NIP-46-shaped payloads, MCP-framed agentic
   profile, grant model) is genuinely P2. ADR-031 (vanilla-Nostr rotation
   breadcrumbs - `kind:0`/`kind:1` continuity hints for non-Heterodyne followers
   surviving epoch rotation) is P1/identity-interop, not command-and-control; it
   has nothing to do with device enrollment or RPC. This is worth correcting
   before questionnaire generation so P2's scope estimate isn't inflated.

4. **Personal NIP-51 mute lists (§8.5) are a P1 primitive reused as P3
   infrastructure.** §5.7.4 (DM acceptance gating) leans on the same web-of-trust
   /mute machinery that §8.5-§8.10 build into full community curation. A
   three-way split forces either duplicating the mute-list schema across
   documents or accepting a SHARED dependency edge that the "P1/P2 ship, P3
   stays draft" goal would then have to tolerate (mute lists would need to be
   pulled into FOUNDATION or P1 outright, not left in the P3 moderation
   document).

5. **Node topology / repo-relay substrate (§7, §10) is used identically by
   all three, not "part of" any one of them.** Full/routing/light node roles,
   the repo-relay adapter, and the `kind:31005`/`kind:31010` pointer/advert pair
   are storage and location machinery consumed by P1 broadcast content, P2's
   full-node-as-controller relationship (the full node holds the epoch key and
   executes RPC on the light client's behalf per ADR-030), and P3 community
   repos equally. This is the strongest FOUNDATION candidate alongside identity.

6. **Outbox model / replies+reactions (§6.5) and "following" (§7.4, §11.4) -
   generic subscription primitive or inherently social-graph semantics?** The
   mechanism ("write a reply into your own outbox, referencing the target id")
   is protocol-agnostic enough to be P1, but every consumer described in the
   spec is a social-feed use case. The current §14.3 coverage map already
   bundles this into the CORE `outbox/` vector category regardless of Matrix
   optionality, which is a data point for keeping it in P1/FOUNDATION rather
   than P3, but it is a genuine judgment call, not a settled fact.

7. **Organizations as personas (ADR-027, `org/` vector category) are an
   identity-model extension whose only real-world consumers are
   community/moderation.** ADR-027 defines orgs as first-class personas
   (delegate-threshold governance, `crefs`) at the identity layer - structurally
   FOUNDATION/P1 - but ADR-030 explicitly excludes org personas from P2 session-
   device enrollment "until a later revision specifies the governance flow,"
   and §6.7.0/§8.8 (the org-specific consumers) are P3. Orgs may need to ship as
   a P1/FOUNDATION primitive with a P3-only feature surface layered on top.

8. **The strict-mode client profile (§11.7) bundles P3 and FOUNDATION
   requirements into one conformance claim.** §11.7.1 is moderation/privacy-tier
   enforcement (P3-flavored, though privacy-tier enforcement is P1); §11.7.2 is
   Matrix state-downgrade (P3); the vector split already reflects this
   (`moderation/strict-mode/` vs `transport/strict-mode/`, per ADR-007/ADR-019).
   A three-document split needs to decide whether "strict mode" becomes three
   separate profiles or one composite profile that normatively spans documents
   - the latter is exactly the kind of cross-spec conformance profile Matrix's
   client-server-vs-federation split does NOT have to solve (each of its APIs is
   independently conformant), so there is no clean precedent to copy here.

### A.4 Vector-category mapping (from §14.3 / `docs/spec/vectors/README.md`)

The existing vector corpus already partitions almost cleanly along protocol
lines, which is strong evidence the split is mechanically tractable at the
conformance-suite level even before any spec-text reorganization:

| Vector category | Classification |
|---|---|
| `identity/`, `keri/`, `keri-authority/`, `verification/`, `nid-binding/`, `identity-doc/`, `config-backup/`, `relay-interop/`, `transport/` (+ strict-mode), `repo-relay/`, `routing-node/`, `node-advert/`, `light-node/`, `relay-profile/`, `redundancy/`, `versioning/` | FOUNDATION |
| `envelope/`, `privacy-tiers/`, `dm/`, `social-recovery/`, `interop/` | P1 |
| (none yet exist for ADR-030 - see §B) | P2 (not yet authored) |
| `moderation/` (+ strict-mode), `lists/`, `org/`, `outbox/`, `room-kind/`, `broadcast/`, `bridge/`, `index/`, `config_room/`, `multi-homing/`, `encryption/` (+ mls-migration), `homeserver-exit/` | P3 |

`lists/` is listed under P3 above per its primary framing (§8.5/§8.6) even
though §A.3 item 4 flags it as genuinely shared; a split would need to either
duplicate a subset of `lists/` into a FOUNDATION or P1 corpus, or accept the
cross-reference.

**Concrete finding: Protocol 2 has zero authored vectors today.** ADR-030's own
"Consequences" section lists the vector categories it *would* need (session-
device delegation binding, epoch-key invite staleness, enrollment carve-out,
grant enforcement including security-policy write refusal, token lifecycle,
self-revocation/inactivity lapse, capabilities-exchange-before-invocation) but
none of these exist as JSON files yet, because ADR-030 is Proposed, not
integrated. Any P1/P2 release plan needs to budget for authoring this corpus
from scratch, not repartitioning an existing one.

## B. Dependency graph

```
FOUNDATION
  (KERI identity/KEL, npub, kind-number registry, nip01_raw,
   kel_head + verification algorithm, node roles, repo-relay
   substrate, config-repo/keys-repo, Tor reachability,
   versioning + conformance methodology)
        |
        v
     Protocol 1 (secure persona comms)
  (event envelope's Nostr-native form, repo-visibility privacy
   tiers, publishing flow + feed index, CORE double-ratchet DMs)
        |
        +------------------------------+
        v                              v
    Protocol 2 (command & control)   Protocol 3 (social media, draft)
  (rides P1's §5.7 DR session as     (moderation, communities, OPTIONAL
   its transport; adds NIP-46-       Matrix discussion, feed-index org
   shaped RPC framing, grant/token   canonicity, outbox threading,
   model, MCP data-layer framing     following/discovery)
   for the agentic profile)                |
        ^                                  |
        |__________________________________|
       (aspirational: P3's own-device sync SHOULD ride
        P2's RPC/grant model rather than a bare P1 self-DM,
        but the current spec text - §3.8.7 - still specifies
        it as a plain DR self-DM session, i.e. P1-only)
```

### B.1 What P2 needs from P1

- The persona identity model and delegation attestations (`kind:31001`), so a
  session-device delegation can be issued and verified the same way any other
  delegation is (ADR-030 item 2 explicitly mirrors §3.3.1's schema).
- The §5.7 double-ratchet session as transport, unmodified: invites
  (`kind:30078`), invite responses (`kind:1059`), outer messages
  (`kind:1060`), NIP-44 v2 payload encryption, and the no-repo/no-backfill
  retention rule.
- The `kel_head`/verification-accelerator machinery (ADR-032) for freshness
  checks on the epoch-key invite and delegation state.
- The config repository / keys repository model (§3.8.6-§3.8.8) as the home
  for configuration delivery, with the grant table/token registry explicitly
  excluded from the ordinary configuration grant (ADR-030 item 8).
- NIP-44 v2 and the full-node/repo-relay write path (§10.1.2), since the full
  node executing RPC on the light client's behalf is doing ordinary P1
  publish/commit operations under the hood.

P2 adds, net-new: NIP-46-shaped `{id, method, params}`/`{id, result, error}`
framing, a permission-grant model (baseline/regular/full/media-upload tiers),
a one-time-token registry for automated enrollment, session-scoped
(disposable) delegation semantics, and - for the agentic profile - MCP data-
layer framing (JSON-RPC 2.0, initialize/capability lifecycle, tools with
schemas) carried as DR inner rumors.

### B.2 What P3 needs from both

From P1: the entire attribution/delegation model (every post attributable via
a §3.3-style delegation), the repo-visibility privacy tiers as the substrate
broadcast feeds live under, and - by the task's own framing - P1's DM
mechanism specifically for person-to-person communication inside the social
app.

From P2 (aspirational, not yet wired): per the task's framing, "communication
between a person's own devices" should ride P2. The current spec instead
specifies own-device sync (§3.8.7 keys-repository sync, §3.9 multi-homing) as
a plain P1 §5.7 self-DM session, with no RPC/grant framing at all. Splitting
the protocols would force an explicit decision here: either (a) re-plumb
device-to-device sync through P2's RPC/grant model once P2 exists, unifying
"my devices talk to each other" under one mechanism regardless of whether the
peer is a UI device or a headless/agentic one, or (b) accept that P3's
intra-persona sync is a P1-only concern and P2 is reserved for
human-controller-to-agent and controller-to-subagent relationships only. This
is a real open design question the split surfaces, not just a documentation
question.

### B.3 Cycles

None, if identity is extracted to FOUNDATION: FOUNDATION -> P1 -> {P2, P3} is
a clean DAG, and P2/P3 have no edge to each other except transitively through
P1. If identity stays inside P1 instead, the graph is still acyclic (P1 -> P2,
P1 -> P3, no P2 <-> P3 edge), but P1 becomes proportionally larger and its own
1.0 bar rises to include KERI's remaining churn (e.g., the ADR-032 §6
compromised-key-revocation roadmap item, unscheduled).

### B.4 Shared normative text and registries that resist splitting

- **The kind-number registry (§3.0).** One reserved range (31000-31099) plus
  every adopted upstream NIP kind. A three-way split needs either a
  partitioned range per protocol now, or a single shared registry document all
  three normatively reference - the latter recreates the IETF downref problem
  (§C.7): can P1/P2 hit 1.0 while normatively depending on a registry document
  that P3 keeps adding entries to?
- **`reason_code` vocabulary** (`docs/spec/vectors/schema/reason-codes.json`,
  `reason-codes.md`) - a closed, cross-cutting verification-outcome
  vocabulary referenced by consume-vectors in every category.
- **`nip01_raw` / canonical serialization (§3.0.1)** and the **`kel_head` /
  verification algorithm (§4.5, §4.5.1, §4.5.2, ADR-032)** - one shared
  verifier shape that every signed construct in all three protocols runs
  through, including the ADR-030 session-device delegation itself (which is
  explicitly listed as MUST-carry `kel_head` in the applicability matrix,
  §3.0).
- **§13.2's labeled security invariants** (referenced elsewhere in the spec
  and in `docs/security/threat-model.md` as I1-I7-style handles) - a second
  cross-cutting registry, smaller than the kind table but with the same
  splitting problem.
- **§12 versioning mechanism and §14 conformance/vector methodology** - the
  *design* (RFC 2119 usage, capability-advertisement shape, vector schema,
  coverage-map idea) should probably stay one shared pattern even if each
  split document gets its own independent `spec_version`, the same way NIP-01
  fixes the wire format every other NIP assumes without dictating their
  content.
- **The strict-mode profile (§11.7)** - already flagged in §A.3 item 8 as a
  single conformance claim spanning what would become two or three documents.

## C. Prior art on layered / split protocol suites

### C.1 Nostr NIPs

A tiny core (NIP-01: event format, signatures, relay wire, replaceable-event
convention) plus a large family of independently-numbered NIPs, each with its
own adoption status, no shared version number, and a strong "receivers MUST
tolerate unknown fields/kinds" forward-compatibility norm that Heterodyne
already mirrors in its own §12.3. Weakness: no formal deprecation process
comparable to Matrix's - a NIP can be effectively withdrawn from practice with
no version marker (Heterodyne's own history shows this pattern internally:
NIP-04 is dead, and Heterodyne's own considered-then-withdrawn `NIP-59`-for-
broadcast and Matrix-Megolm-derived index-key construction are the same
shape). The repo's own `docs/spec/extensions/nips/` index already anticipates
this exact core-plus-numbered-extensions pattern, but today aimed at
upstreaming Heterodyne pieces to the Nostr ecosystem, not at partitioning
Heterodyne's own three protocols.

### C.2 Matrix

One specification, but with genuinely separate, independently-versioned API
surfaces: Client-Server, Federation (Server-Server), and Application Service.
Versioning is per-endpoint (`/v3/sync` can deprecate independently of
`/v3/profile`), with an explicit MSC-driven deprecate-then-remove workflow
(deprecated for at least one version cycle before an MSC can remove it).
Relevant precedent for either packaging option 1 (separate documents, one
repo) or option 3 (one document, normatively partitioned parts), since Matrix
already demonstrates that "one spec site" and "independently versioned APIs"
are compatible.

### C.3 ActivityPub / ActivityStreams 2.0

A two-layer W3C split: AS2 Core (JSON syntax) underneath AS2 Vocabulary
(activity/object types and properties), with ActivityPub itself defined on
top of both. Community extensions graduate into the vocabulary through the
lightweight Fediverse Enhancement Proposal (FEP) process, gated on a concrete
adoption bar (independent namespace, resolvable JSON-LD context, and
demonstrated interop from at least two independent producers and two
independent consumers) before being folded into the core vocabulary document.
This is the best-documented precedent for a graduation-gated core-plus-
extensions packaging (option 4), and it is stricter than Nostr's informal NIP
process about what counts as "ready."

### C.4 AT Protocol

The closest structural match to the user's ask. atproto is explicitly layered
as a generic "speech" layer (identity, repo/commit sync, transport - the
`com.atproto.*` Lexicon namespace) underneath a "reach" application layer
(`app.bsky.*` - follows, feeds, moderation UI, all social-specific). The core
deliberately does not define social-media primitives like "follow" at all -
that is entirely an application-Lexicon concern. As of mid-2026, the core
layer is moving toward IETF standardization (an active ATP working group,
Internet Drafts for repo format/sync/architecture) while `app.bsky` lexicons
remain informally versioned and still break their own stated compatibility
rule in practice (e.g. `app.bsky.actor.defs#savedFeedsPrefV2`). This is
simultaneously the strongest positive precedent for "core stabilizes first,
application layer keeps churning" and a cautionary data point that informal
lexicon versioning is hard to hold the line on even for the reference
implementer.

### C.5 DIDComm v2 / DID Core

DIDComm v2 treats DID Core (DID documents, service endpoints) as a foundation
layer it resolves against, and is explicit that the relationship between
DIDComm and the "subprotocols" built on it (trust-ping, issue-credential,
present-proof, etc.) mirrors HTTP versus the APIs built on top of HTTP - an
upgrade to the secure-channel layer should not break subprotocols riding it.
This is a close conceptual match for how ADR-030 already frames P2: RPC
requests/responses are a payload *profile* riding P1's §5.7 DR session
unchanged, not a new independent wire. It supports treating P2 as "a
subprotocol of P1" in the DIDComm sense rather than "a fully independent
protocol that happens to share a transport."

### C.6 KERI vs ACDC

KERI (key-event/identity infrastructure) and ACDC (Authentic Chained Data
Containers, a verifiable-credential-shaped construct) are published as two
separate ToIP specifications with a strictly one-directional dependency: ACDC
normatively depends on KERI (plus CESR, SAID), and KERI has no dependency back
on ACDC. This is the cleanest available precedent for extracting identity
into its own foundation document that P1 (and transitively P2/P3) sit on top
of without creating a cycle, and it directly supports the "fourth identity
core" resolution to hard case §A.3 item 1 as a well-precedented choice, not a
novel one - notably the same ecosystem Heterodyne's own KERI profile already
cites (ADR-032, AGENTS.md).

### C.7 IETF layering and downref practice

QUIC/HTTP3 and TLS/application-layer separations are the general IETF
precedent for "a lower transport layer stabilizes independently of the
application layers riding it." The sharper, directly load-bearing rule is the
downref precedent (RFC 3967, RFC 4897/BCP 97, and the newer
`draft-kucherawy-bcp97bis`): a Standards-Track document normally MUST NOT
carry a normative reference to a document at a lower maturity level, with only
a narrow "note and move on" exception for already-published (not
in-progress-draft) lower-maturity RFCs deemed stable by the community; a
normative reference to a live, unpublished Internet-Draft is explicitly not
covered by that exception at all. Applied to Heterodyne: if P1/P2 want to
reach a 1.0-equivalent maturity claim while P3 remains a 0.x draft, neither P1
nor P2 can hold a MUST-level normative dependency on anything still owned and
churned by P3 - which is exactly the shared kind-registry and reason-code
problem in §B.4. The registries must either freeze their P1/P2-relevant
entries before those protocols claim 1.0, or be pulled entirely into whichever
document(s) are stabilizing.

### C.8 Versioning implications synthesis

Every precedent surveyed lets a core/foundation layer mature ahead of an
application layer built on it (atproto core vs app.bsky; KERI vs ACDC; TLS vs
application protocols), and none of them require the application layer to
freeze before the core can. None of them, however, show a core layer holding a
load-bearing normative dependency on the still-churning application layer -
which maps directly onto the requirement that P1's normative text (and any
registry it owns) must not need P3's cooperation to stop changing. Matrix's
per-endpoint versioning is the best precedent for keeping everything in one
repository while still making credible independent maturity claims, if
packaging option 1 or 3 is preferred over separate repositories.

## D. Packaging options

No option is recommended here; all four are enumerated with tradeoffs per the
task's instruction.

### D.1 Three separate spec documents, one repo, shared vectors

`docs/spec/p1-persona-comms.md`, `p2-command-control.md`, `p3-social.md` (plus,
depending on the resolution of hard case §A.3.1, a `p0-identity-core.md` or
equivalent), one repo, one `docs/spec/vectors/` tree tagged by protocol per
§A.4.

- Pros: lowest migration cost (mechanical section move from the current single
  file); single CI/vector-generator project; FOUNDATION concepts (kind
  registry, `nip01_raw`, `kel_head`) can be referenced by relative path/anchor
  without duplication; ADR history and tooling stay unified.
- Cons: does not force real interface discipline - a P1-document edit can
  silently assume P3 vocabulary since everything is one repo/PR; one ADR
  numbering sequence and one CHANGELOG unless explicitly partitioned (which
  protocol does the next sequential ADR number "belong" to becomes an ongoing
  question); a credible external "P1 hit 1.0" claim is harder to make when P3
  draft churn lands in the same repository and release cadence.

### D.2 Three repos under the HeterodyneNetwork org

Separate `heterodyne-p1`, `heterodyne-p2`, `heterodyne-p3` (and possibly a
`heterodyne-core`) repositories, each with its own tags, CHANGELOG, and issue
tracker.

- Pros: the strongest external signal of independent maturity (separate git
  tags mean a P1 v1.0.0 release is not diluted by a P3 commit landing the same
  day); forces explicit, visible normative cross-references (a P3 repo citing
  "P1 spec v1.0.0 §5.7" the way an ActivityPub spec cites AS2, or ACDC cites
  KERI), which surfaces hidden foundation-layer dependencies immediately
  instead of silently; cleanest possible 1.0 story for P1/P2.
- Cons: heaviest overhead - 3x (or 4x, with a core repo) CI and vector-
  generator plumbing unless FOUNDATION vectors/fixtures are factored into a
  shared package; any change touching a shared registry (kind numbers, reason
  codes) now spans repositories and needs cross-repo coordination; ADR history
  fragments unless a core repo hosts identity/foundation ADRs; the shared
  `fixtures.json`/`reason-codes.json` (test epoch, keys, vocabulary) needs to
  become either a duplicated artifact or a published shared package.

### D.3 One document, three normatively-partitioned parts, plus conformance classes

Keep `heterodyne.md` as a single file, but organize it into explicit Part
1/Part 2/Part 3 sections with per-part conformance classes (extending the
existing CORE-vs-OPTIONAL-Matrix split pattern in §14 to a three-way split).

- Pros: lowest editing friction, matching current single-file practice
  exactly; a reader gets the whole picture with no cross-document navigation;
  `spec_version` could in principle be scoped per Part header rather than per
  document.
- Cons: this option does not actually let P1/P2 "release and stabilize first"
  in any way legible to an outside implementer or tool - a single
  `Version: 1.0.0` banner at the top of one file misrepresents the document if
  Part 3 inside it is still explicitly a 0.x draft; anyone (human or CI)
  wanting to know "is this stable" has to parse internal part boundaries
  rather than read a document-level version, which is a materially weaker
  signal than a separately-tagged document. Of the four options this is the
  weakest fit for the user's stated goal, though it is included here
  neutrally per the task's instruction not to pick a winner.

### D.4 Core-plus-extensions model (NIP-style)

P1 (plus, per §A.3.1, possibly a fourth identity-core document) as "core";
P2 and P3 as extension families, reusing and extending the existing
`docs/spec/extensions/nips/` and `docs/spec/extensions/mscs/` scaffolding.

- Pros: reuses infrastructure the repo already has (those two README indexes
  already establish a "core spec + graduated extraction" pattern, today aimed
  at upstreaming Heterodyne pieces to Nostr/Matrix rather than at an internal
  P1/P2/P3 split); matches the closest prior-art fits most directly (AT
  Protocol's core/app split, ActivityStreams' Core+Vocabulary+FEP graduation
  gate); naturally supports "P1/P2 hit 1.0, P3 stays draft," since every
  surveyed ecosystem treats extensions as allowed to be less mature than core
  by convention.
- Cons: "extension" framing undersells P2 and P3 if they are meant to be
  co-equal, independently-branded protocols rather than optional add-ons to
  P1, which is a naming/positioning mismatch with the user's stated 3-protocol
  vision; the existing `extensions/` directories are scoped today to
  upstream-facing NIP/MSC candidates (things Heterodyne might propose *to*
  Nostr or Matrix), not to sibling Heterodyne-native protocols, so reusing
  them literally would need a disambiguating rename or a second, parallel tier
  (e.g., a new `docs/spec/protocols/` alongside the existing
  `docs/spec/extensions/`).

### D.5 Vector generator/corpus implications per option

Today: one TypeScript project (`docs/spec/vectors/generator/`, `fixtures.ts`,
`reason-codes.ts`, `topics.ts`/`topics-v04.ts`/`topics-v04b.ts`) emitting every
category under one `vectors/` tree via `npm run author`/`verify`/`check`.

- Under D.1 (one repo): no file movement needed - tag each existing
  `vectors/<category>/` directory in the README table per §A.4's mapping;
  `fixtures.json` and `schema/reason-codes.json` stay single shared files,
  matching their status as the cross-cutting registries identified in §B.4.
- Under D.2 (three repos): the FOUNDATION categories (`identity/`, `keri/`,
  `keri-authority/`, `repo-relay/`, `routing-node/`, `node-advert/`,
  `light-node/`, `nid-binding/`, `identity-doc/`, `config-backup/`,
  `relay-interop/`, `transport/`, `relay-profile/`, `redundancy/`,
  `versioning/`) either move into a fourth shared/core repo that P1, P2, and
  P3 all depend on for CI, or `fixtures.ts`/`reason-codes.ts` become a
  published shared npm package consumed by three otherwise-independent
  corpora - directly mirroring how ACDC's spec depends on KERI's already-
  published primitives rather than re-deriving them.
- Under D.3/D.4: no forced move; the existing single project and README table
  simply gain an explicit protocol-tag column, same as D.1.

### D.6 CHANGELOG / semver-0.x per-document implications

Today there is exactly one `CHANGELOG.md`, one `spec_version` string
(`"0.4.0"`) stamped into every event's content field (§12.1) and into every
vector file's `spec_version` field. A three-way split surfaces a genuine,
currently-open wire-format question, not merely a documentation-organization
one: does a single event still carry one `spec_version`, or does an event
that straddles protocols (an ADR-030 RPC rumor, which rides P1's DR envelope
but carries P2 payload semantics) need to stamp *both* a P1 and a P2 version?
The current design has never had to answer this because everything is one
`spec_version` today. Whichever packaging option is chosen, this should be
treated as a required design decision for the split, not an incidental
consequence of it - and it interacts directly with the D.5 vector-fixture
question, since `fixtures.json`'s shared `test_epoch`/keys would need a
consistent per-protocol version story too.

## E. Standard research-doc fields

### E.1 Current stable versions of relevant libraries (verified 2026-07-15)

| Library | Current stable | Repo-pinned (generator `package.json`) | Note |
|---|---|---|---|
| `nostr-tools` | 2.23.8 | `^2.17.0` | Same major line, several minors behind; worth a refresh pass, not urgent. |
| `@noble/curves` | 2.2.0 | `^1.9.7` | A full MAJOR behind. |
| `@noble/hashes` | 2.2.0 | `^1.8.0` | A full MAJOR behind. |
| `@noble/ciphers` | 2.2.0 | `^1.3.0` | A full MAJOR behind. |
| `nostr-double-ratchet` | (repo intentionally exact-pins) | `0.0.138` | Upstream is still pre-1.0 (0.0.x); the vectors/README documents this as a deliberate exact-pin for determinism, and it is itself a real-world instance of the IETF-downref tension in §C.7 - a stabilizing DM/P1 spec has a normative reference to an inherently unstable upstream library. |
| `ajv` | (not independently re-verified this pass) | `^8.17.1` | No action flagged. |
| Radicle / Heartwood | 1.9.1 (official site build 2026-05-21) | 1.9.x, empirically verified against 1.9.1 | Consistent with the repo's ADR-026/027 verification addenda; no action needed. |
| KERI | No numbered release; ToIP KSWG draft + arXiv 1907.02143 (primary citation per AGENTS.md) | same | Unchanged. |
| keripy / keriox | keripy "current stable" (unpinned exact version in ADR-032); keriox (THCLab) 0.17.x | same, as cited | Gap: unlike Heartwood's pinned-and-verified-against-1.9.1 discipline, keripy is cited without an exact tag/commit in ADR-032 - worth pinning with the same "verify, don't guess" rigor applied elsewhere in this repo. |
| MCP (Model Context Protocol) | Revision 2025-11-25 | same, pinned in AGENTS.md 2026-07-07 | Current; already follows the repo's own citation-hygiene norm and needs no update. |

### E.2 Deprecated / withdrawn constructs to avoid

- **NIP-04** (encrypted DM) - explicitly marked "NOT USED - deprecated
  upstream" in the §3.0 kind-allocation table.
- **NIP-59 gift-wrap for broadcast/private-index use** - considered, then
  withdrawn in v0.2.0 per ADR-005; still valid and used for the NIP-17
  vanilla-DM fallback, just not for broadcast confidentiality.
- **Matrix-Megolm-session-derived `"room_key.v1"` Tier-3 index-key
  construction** - explicitly superseded by v0.4.0's `kind:31011` per-recipient
  audience-key-wrap; the spec states the retired construction "MUST NOT be
  honored."
- **v0.1.4 single-key successor/predecessor identity chain** - retired in
  v0.2.0 in favor of KERI (vulnerable to fork-freezing attacks); the
  corresponding "successor chain" vector category was removed from the
  corpus accordingly.
- **The v0.2.0-v0.3.0 room-taxonomy kinds as primary substrate**
  (`public_broadcast`/`private_broadcast`/`public_discussion`/
  `private_discussion`) - superseded by the repo-visibility tier model in
  v0.4.0; all four kinds survive only inside the OPTIONAL Matrix discussion
  layer now.
- **radicle-keri's code** (not its design ideas) - explicitly flagged as not
  reusable in ADR-032 and AGENTS.md: KEL write path unimplemented (`todo!()`),
  and its vendored keriox 0.8.2 dependency carries advisory RUSTSEC-2022-0093.
  AGENTS.md directs any future Rust KERI work to keriox 0.17.x (THCLab fork)
  instead.

### E.3 Idiomatic patterns in this repo

- **ADR conventions.** Filenames `YYYY-MM-DD-NNN-<slug>.md`, globally
  sequential `NNN` (check the highest existing number before authoring a new
  one, per AGENTS.md); a `Status` line that tracks review provenance
  (Proposed -> codex review rounds -> Accepted) and explicit
  supersession/amendment cross-references to other ADR numbers (e.g. ADR-027's
  status line: "partially superseded by ADR-032"); a "Council Input" section
  recording exactly which review mechanism ran (star-chamber vs
  `/codex:rescue`) and what it found; ADRs are kept close to a roughly
  500-line budget (consistent with the user's global tooling convention "keep
  files under 500 lines," and explicitly visible in ADR-030's own note about a
  "line-count trim" during its review).
- **Vectors are generated artifacts, not hand-written.** The TypeScript
  sources under `docs/spec/vectors/generator/` (`fixtures.ts`,
  `reason-codes.ts`, `topics*.ts`) are explicitly non-normative tooling; the
  committed JSON is the normative artifact ("implementations do not need the
  generator... to claim conformance," per `vectors/README.md`).
- **RFC 2119 plus a closed reason-code vocabulary.** Every consume-vector
  reject uses a fixed `reason_code` from `schema/reason-codes.json` /
  `reason-codes.md` - even informal verification outcomes are
  registry-controlled, the same discipline applied to the kind-number
  registry.
- **"Verification addendum" sections appended after empirical checks.**
  ADR-026 and ADR-027 both carry a dated addendum ("Verification addendum
  (2026-07-05)") that closes previously-UNVERIFIED assumptions against a
  pinned Heartwood tag, rather than silently editing the original decision
  text - a repo-specific practice for tracking what has actually been
  confirmed versus assumed.
- **Dated external citations.** Every external-standard reference in
  AGENTS.md carries a "verified <date>" note; this research document follows
  the same norm for its own external claims (§E.1).

### E.4 Prior art links

- [Nostr NIPs](https://github.com/nostr-protocol/nips)
- [Matrix Specification](https://spec.matrix.org/latest/)
- [Matrix Client-Server API](https://spec.matrix.org/latest/client-server-api/)
- [Matrix Application Service API](https://spec.matrix.org/v1.7/application-service-api/)
- [Activity Streams 2.0 Core](https://www.w3.org/TR/activitystreams-core/)
- [Activity Vocabulary](https://www.w3.org/TR/activitystreams-vocabulary/)
- [ActivityPub](https://www.w3.org/TR/activitypub/)
- [Process for Including Extensions in Activity Streams 2.0 (FEP-style gate)](https://swicg.github.io/extensions-policy/)
- [AT Protocol](https://atproto.com/) / [AT Protocol roadmap, Spring 2026](https://atproto.com/blog/2026-spring-roadmap)
- [AT Protocol on Wikipedia](https://en.wikipedia.org/wiki/AT_Protocol)
- [DIDComm Messaging Specification v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/)
- [DIDComm v2 Guidebook / What's new](https://didcomm.org/book/v2/whatsnew/)
- [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/)
- [KERI, arXiv 1907.02143](https://arxiv.org/abs/1907.02143)
- [Authentic Chained Data Containers (ACDC), IETF draft](https://www.ietf.org/archive/id/draft-ssmith-acdc-02.html)
- [ACDC ToIP KSWG specification](https://trustoverip.github.io/kswg-acdc-specification/)
- [RFC 3967 - Clarifying Standards-Track downward references](https://datatracker.ietf.org/doc/html/draft-ymbk-downref)
- [RFC 4897 / BCP 97 - Handling Normative References to Standards-Track Documents](https://datatracker.ietf.org/doc/html/rfc4897)
- [draft-kucherawy-bcp97bis - updated downref procedures](https://datatracker.ietf.org/doc/draft-kucherawy-bcp97bis/)
- [Radicle 1.9.0 "Hawthorn" release notes](https://radicle.dev/2026/05/19/radicle-1.9.0)
- [nostr-tools on npm](https://www.npmjs.com/package/nostr-tools)
- [@noble/curves on npm](https://www.npmjs.com/package/@noble/curves)
- [@noble/hashes on npm](https://www.npmjs.com/package/@noble/hashes)
- [@noble/ciphers on npm](https://www.npmjs.com/package/@noble/ciphers)
