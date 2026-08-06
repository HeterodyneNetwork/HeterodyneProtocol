# Plan: Four-document protocol family split (ADR-033)

**Slug:** four-document-protocol-family-split
**ADRs:** docs/adr/archive/2026-07-16-033-four-document-protocol-family-split.md
**Research:** docs/research/2026-07-15-three-protocol-split-research.md
**Mode:** --parallel
**Autopilot:** true
**Accept-ADRs:** false
**Lean:** false
**Bullets:** false
**Skills:** false
**Teammate-model:**
**Branch:** brains/three-protocol-split

## Overview
Execute ADR-033: first land the in-flight ADR-032 integration in the monolith
(seven parked review findings, regeneration, review, commit - req 35 step 1),
then split docs/spec/heterodyne.md into four sibling normative documents
(heterodyne-core.md, heterodyne-comms.md, heterodyne-control.md,
heterodyne-social.md) with a Core-owned registry artifact, qualified
version grammar, Thin-P1 closure, conformance classes, strict-mode profiles,
threat-model decomposition, companion-doc updates, a per-vector corpus rework
with a generator-emitted coverage manifest, and finally the cutover that
archives the 0.4.x monolith behind an anchor map and preps the four v0.5.0
first releases. The monolith remains the sole normative document until the
explicit cutover task in Phase 9; every new document carries a "pre-release
draft, monolith remains authoritative until cutover" banner until then.
ADR-030/031 acceptance and the v0.5.0 release decision are needs-human gates.

### Phase 1: Land the ADR-032 integration in the monolith (req 35 step 1)
- [ ] **T-1.1**: Fix verification-algorithm review findings in heterodyne.md (findings 2, 3, 4: test seq_ahead_of_accepted_head before off_accepted_kel plus refresh re-resolves identity and re-runs head checks; key_state_final deny-until-repo policy branch returning provisional_not_final; same kel_head/policy handling in verify_bare_with_sig)
  - Depends on: none
  - Acceptance: grep of heterodyne.md §4.5 shows seq_ahead_of_accepted_head tested before off_accepted_kel and provisional_not_final present in both verify paths
- [ ] **T-1.2**: Fix matrix, vocabulary, and state review findings in heterodyne.md (findings 1, 6, 7: §3.0 kel_head row for §5.7.2 device-key DM invites MAY -> MUST NOT; §14.2 consume-verdict vocabulary gains accept_provisional and equivocation_flagged; §10.1.2 state.json empty-witness-config -> witnesses [] / threshold 0 rule)
  - Depends on: none
  - Acceptance: grep confirms all three edits present in heterodyne.md (§3.0 MUST NOT row, both §14.2 verdicts, §10.1.2 witnesses-[] rule)
- [ ] **T-1.3**: Fix light-node/001 in the generator (topics-v04.ts ~line 432: carry kel_head via withKelHead(..., fixtures.kel.alice.head)) and regenerate the corpus wholesale
  - Depends on: none
  - Acceptance: `cd docs/spec/vectors/generator && npm run author && npm run check` exits 0 and docs/spec/vectors/light-node/001*.json contains kel_head
- [ ] **T-1.4**: Run a codex review round over the full ADR-032 integration diff (spec + threat-model + vectors); fix findings and regenerate as needed
  - Depends on: T-1.1, T-1.2, T-1.3
  - Acceptance: codex review verdict "accept" (zero BLOCKING findings) recorded against the final diff
- [ ] **T-1.5**: Commit and push the ADR-032 monolith integration on brains/three-protocol-split
  - Depends on: T-1.4
  - Acceptance: `git status --porcelain` is empty and the integration commit exists on origin/brains/three-protocol-split

Phase 1 testability: generator `npm run check` green (all vectors verified), working tree clean, codex accept on record; monolith is the only normative spec document.

### Phase 2: Registry artifact and version-grammar groundwork (reqs 18-29)
- [ ] **T-2.1**: Create the Core-owned registry artifact with its own monotonic revision and the kind-registry schema (allocation authority, base-schema owner document, stability status draft|stable|frozen, per-profile owners with immutable discriminators), seeded from monolith §3.0 including the dual-use entries of req 19 (reqs 18-20)
  - Depends on: T-1.5
  - Acceptance: registry artifact file exists under docs/spec/ and every kind allocated in monolith §3.0 appears with owner and status; a documented check command validates the schema
- [ ] **T-2.2**: Move the reason-code vocabulary and the namespaced security-invariant identifier allocation (CORE-I*, COMMS-I*, CONTROL-I*, SOCIAL-I*) into the registry artifact with per-entry owner and status (reqs 18, 33 groundwork, 42 groundwork)
  - Depends on: T-2.1
  - Acceptance: registry artifact lists all 42 reason codes with owners plus an invariant-ID namespace table
- [ ] **T-2.3**: Define registry-revision pinning mechanics: the revision/entry-set-digest rule and the pin fields required in releases, release manifests, capability advertisements, vectors, and coverage manifests (req 18)
  - Depends on: T-2.1
  - Acceptance: pinning rule and field names present in the registry artifact and a digest is computable by a single documented command
- [ ] **T-2.4**: Draft the Core-destined qualified version grammar and wire-stamping rules: `<doc-id>/<semver>` grammar (not bare semver), per-event-class stamp placement, owner-stamp/single-stamp rule, stamping vs non-stamping profiles, DR-outer-wire no-marker rule (reqs 22-25)
  - Depends on: T-2.1
  - Acceptance: draft text covers all req-23 event classes and the req-24 single-stamp rule, filed for Phase 3 absorption
- [ ] **T-2.5**: Draft the 0.4-history migration and unknown-version rules: unqualified-0.4.0 mapping, legacy-inference scope exclusions, no-restamp rule, capability-advertisement Core bootstrap and per-document version sets, broadcast unknown-version handling (reqs 27, 29)
  - Depends on: T-2.4
  - Acceptance: draft covers every req-27 exclusion and the req-29 reject-or-degrade broadcast behavior

Phase 2 testability: registry artifact validates by its check command; `git diff docs/spec/heterodyne.md` empty since T-1.5 (monolith untouched); generator `npm run check` still green.

### Phase 3: Core document (reqs 5-6, 10-13)
- [ ] **T-3.1**: Scaffold docs/spec/heterodyne-core.md: doc-id core, permanent-anchor scheme (req 34), table of contents, and the "pre-release draft, monolith remains authoritative until cutover" banner
  - Depends on: T-2.5
  - Acceptance: file exists with banner, doc-id, and stated anchor scheme
- [ ] **T-3.2**: Move identity material into Core: KERI cold-root/epoch (KEL, rotation, compromise windows, replay), npub canonicality, nip01_raw canonical serialization, root attestation, kind:31005 pointer, kind:31001 NID delegations, with RFC 2119 language kept intact and per-section provenance recorded for the anchor map (req 5)
  - Depends on: T-3.1
  - Acceptance: all listed monolith sections present in Core and each carries a recorded source-section marker
- [ ] **T-3.3**: Move the verification algorithm into Core: §4.5 with kel_head accelerator, provisional acceptance, and repo authority exactly as landed in Phase 1 (req 5)
  - Depends on: T-3.2
  - Acceptance: Core §4.5 text contains the Phase-1 fixes (grep for seq_ahead_of_accepted_head-before-off_accepted_kel and provisional_not_final)
- [ ] **T-3.4**: Move substrate and topology into Core: node roles, repo-relay substrate + NIP-01 adapter + materialized KEL refs, kind:31010 node ads, Tor reachability, relay interop and relay profile, and the Core half of multi-homing (KERI/Radicle reconciliation, pointer resolution, multi-full-node seeding) without the unqualified "multi-homing" label (reqs 5, 10)
  - Depends on: T-3.3
  - Acceptance: sections present in Core and grep finds no unqualified "multi-homing" label in Core
- [ ] **T-3.5**: Define the Core generic encrypted-repository primitive (parameterized by a higher-document encryption profile), the complete Core keys-repository protection profile (at-rest, NIP-49) with no Comms dependency, and the req-6 payload-allocation table (Core/Comms/Social ownership)
  - Depends on: T-3.4
  - Acceptance: Core contains the primitive, the keys-repo profile with zero Comms references (grep), and the three-way allocation table
- [ ] **T-3.6**: Define generic delegate-threshold authority as an identity primitive, recast social recovery in social-neutral terms (recovery peers, declared witnesses, cached identity material, cold-root re-anchor), and state the Core discovery boundary npub -> RID -> serving node -> authoritative key material (reqs 11-13)
  - Depends on: T-3.5
  - Acceptance: Core recovery section contains no follow/friend/Matrix terms (grep) and the discovery-boundary statement exists
- [ ] **T-3.7**: Add Core versioning/capability negotiation (absorbing the Phase-2 grammar, stamping, migration, and unknown-version drafts), conformance/vector methodology, did:webs export, KERI social witnesses, and the Core security-model section with CORE-I* invariants (reqs 5, 22-24, 27, 29)
  - Depends on: T-3.6, T-2.4, T-2.5
  - Acceptance: Core contains the qualified-version grammar from the Phase-2 draft and all Core invariants carry CORE-I* IDs

Phase 3 testability: heterodyne-core.md exists with banner; grep shows zero normative references from Core to heterodyne-comms/-control/-social; monolith diff empty; style scan (plain hyphens/straight quotes) passes.

### Phase 4: Comms document (reqs 7, 9, 16-17)
- [ ] **T-4.1**: Scaffold docs/spec/heterodyne-comms.md with the draft banner and a version-bound normative dependency on Core (document id + version + anchor form, req 34)
  - Depends on: T-3.7
  - Acceptance: file exists with banner, doc-id comms, and a version-bound Core dependency statement
- [ ] **T-4.2**: Move the Nostr-native canonical event envelope, repo-visibility privacy tiers (public repo, private repo, Tier-3 encrypted blobs with kind:31011/31012 audience keys and enc/<key_id> rotation), and the confidentiality/forward-secrecy posture (req 7)
  - Depends on: T-4.1
  - Acceptance: all listed sections present in Comms with source-section markers recorded
- [ ] **T-4.3**: Move publishing flow (destination set, fan-out, idempotency), kind:31007 feed index as generic outbox canonical ordering, event retrieval/backfill, outbox advertisement, and generic feed/outbox location discovery; apply Core delegate-threshold authority to all org-owned Comms posts and feed indexes preserving the §6.7.0 invariant (reqs 7, 11, 12)
  - Depends on: T-4.2
  - Acceptance: Comms contains a normative org threshold-authority clause covering posts and feed indexes
- [ ] **T-4.4**: Move double-ratchet DMs (invites kind:30078, kind:1060 wire, NIP-17 fallback, no-repo/no-backfill) and define the normative acceptance-gating hook contract: authentication precedes policy, enumerated inputs and outcomes (at minimum accept, hold-as-message-request, reject), Comms-native default policy, no sender-observable signals before acceptance, and separate contexts for ordinary DMs, credential-plane sync, and Control enrollment (reqs 7, 16)
  - Depends on: T-4.3
  - Acceptance: hook-contract section enumerates all three outcomes and all three gating contexts (grep)
- [ ] **T-4.5**: Specify credential-plane device sync: durable NID-bearing kind:31001 delegation requirement, rejection of NID-less session devices, and the signed, target-NID- and purpose-bound, KEL-validated, revocable credential-sync authorization schema (req 17)
  - Depends on: T-4.4
  - Acceptance: Comms defines the credential-sync authorization schema with all five req-17 properties stated normatively
- [ ] **T-4.6**: Specify the subprotocol-negotiation frame (protocol id + supported Control versions, run in-session before any session-carried subprotocol payload, negotiated version retained in local audit records) and the Comms-owned generic subprotocol-carrier rumor kinds stamping comms/<semver> inside ciphertext (reqs 23-25)
  - Depends on: T-4.5
  - Acceptance: Comms defines the negotiation frame and carrier kinds; carrier kinds registered in the registry artifact as Comms-owned
- [ ] **T-4.7**: Execute the Comms-side Thin-P1 closure items: §5.7.4 follow/reply/web-of-trust DM gate replaced by the req-16 hook, the NIP-51-lists-are-core declaration retracted, and the config-repository encryption profile (Tier-3 audience-key + enc/<key_id> rotation) bound to the Core primitive by Comms (reqs 6, 9)
  - Depends on: T-4.6
  - Acceptance: Comms text contains no follow/web-of-trust admission policy (grep) and contains the config-repo profile binding clause

Phase 4 testability: heterodyne-comms.md exists with banner and version-bound Core dep; grep shows zero normative references to Control or Social; monolith diff empty; style scan passes.

### Phase 5: Social document (req 8)
- [ ] **T-5.1**: Scaffold docs/spec/heterodyne-social.md with the draft banner, version-bound deps on Core and Comms, and the explicit exact-version 0.x instability statement (reqs 8, 30, 34)
  - Depends on: T-4.7
  - Acceptance: file exists with banner, doc-id social, both version-bound deps, and the instability statement
- [ ] **T-5.2**: Move interaction semantics: replies/reactions/threading, following/social-graph semantics, transitive social discovery, cross-persona advertisement, reply inboxes, mixed-tier fan-out (reqs 8, 11)
  - Depends on: T-5.1
  - Acceptance: all listed sections present in Social with source-section markers recorded
- [ ] **T-5.3**: Move moderation and curation: NIP-72 approvals, Radicle editorial gating, personal mute lists and NIP-51 sets and community policy lists as a stamping Social profile with an in-band marker, NIP-32 labels, web-of-trust, starter packs (reqs 8, 24)
  - Depends on: T-5.2
  - Acceptance: Social defines the NIP-51 profile marker and the profile is registered on the upstream kinds in the registry artifact
- [ ] **T-5.4**: Move org community/editorial/feed-presentation semantics and the ATProto attached outbox; define Social-owned payloads (mute, feed-preference, followed-repositories) over the Core storage primitive per the req-6 allocation (reqs 6, 8, 9)
  - Depends on: T-5.3
  - Acceptance: Social payload definitions match the Core req-6 allocation table entries one-for-one
- [ ] **T-5.5**: Move the entire Matrix layer into Social as an optional feature: MXID delegation plus election/leases/failover, wrapped/bare envelopes, discussion rooms, Megolm/MLS, config room, homeserver exit, personal headless bridge, homeserver requirements, vanilla-Matrix interop, fallback rendering; state Social vs Social+Matrix as distinct conformance claims (reqs 8, 10)
  - Depends on: T-5.4
  - Acceptance: Social states that a Matrix-free client can be fully Social-conformant and names both claims (grep)
- [ ] **T-5.6**: Define Social's pluggable req-16 hook policy (mute-list/web-of-trust; MAY tighten, MUST NOT loosen or bypass Comms checks) and Social's bindings of the Core recovery roles to follows, mutual follows, friends, and Matrix identity-room caches (reqs 13, 16)
  - Depends on: T-5.5
  - Acceptance: Social hook-policy section cites the Comms hook contract by version-bound reference and states the tighten-only rule

Phase 5 testability: heterodyne-social.md exists with banner; grep shows zero normative references to heterodyne-control.md; Matrix optional inside Social verified by claim text; monolith diff empty; style scan passes.

### Phase 6: Control draft and ADR-030/031 amendment prep (reqs 3, 14-15, 25-26, 40)
- [ ] **T-6.1**: Scaffold docs/spec/heterodyne-control.md as an explicitly incomplete 0.5 draft: profile-of-Comms conformance claim ("Core + Comms conformant + Control profile"), no-transport/no-wire-stamping rules, exact supported-Comms-version set plus required DR feature, scope placeholders for enrollment/RPC/grants/tokens/MCP, and an explicit no-vector-conformance-claim statement (reqs 3, 25-26, 40)
  - Depends on: T-4.7
  - Acceptance: file exists with incomplete-draft banner, the composed conformance-claim wording, the exact Comms version set, and the no-vector-claim statement
- [ ] **T-6.2**: Prepare the ADR-030 amendment: session-device delegation subtype as Core registry/delegation extensibility; epoch-key invite, undelegated enrollment initiator, DR contexts, and subprotocol negotiation reallocated to Comms; key-custody rule scoped per req 17; integration target changed from monolith to Control (reqs 15, 17, 25)
  - Depends on: T-6.1, T-2.1
  - Acceptance: amended ADR-030 file contains all four reallocation edits and no longer targets the monolith (grep)
- [ ] **T-6.3**: Prepare the ADR-031 amendment: breadcrumb production and verification exclusion land in Core; following-vanilla-users behavior and UI land in Social; kind:0/kind:1 breadcrumb profiles registered as non-stamping in the registry artifact (reqs 14, 19, 24)
  - Depends on: T-6.1, T-2.1
  - Acceptance: amended ADR-031 file contains the Core/Social reallocation and the registry artifact carries both non-stamping profile entries
- [ ] **T-6.4**: needs-human: ADR-030 acceptance decision (gates its later integration into Control plus bounded lower-document amendments; the integration itself is out of this plan's scope per req 35 step 3)
  - Depends on: T-6.2
  - Acceptance: user decision recorded on the tracker ticket (accept, revise, or defer)
- [ ] **T-6.5**: needs-human: ADR-031 acceptance decision (gates its later integration into Core; integration out of this plan's scope per req 35 step 3)
  - Depends on: T-6.3
  - Acceptance: user decision recorded on the tracker ticket (accept, revise, or defer)

Phase 6 testability: heterodyne-control.md exists with incomplete-draft banner and zero vector claims; both amended ADR files contain the required reallocations; both needs-human tickets exist; monolith diff empty.

### Phase 7: Conformance classes, strict mode, threat-model split, companion docs (reqs 30-34, 36)
- [ ] **T-7.1**: Define the conformance classes across the four documents: Core (every implementation), Core+Comms "Heterodyne persona", feature-qualified Control profile (DR feature mandatory), Social exact-version 0.x claims, Social+Matrix; claims MUST name required features, not only documents (req 30)
  - Depends on: T-5.6, T-6.1
  - Acceptance: each document states its class and the composed-claim rules; Control's claim requires the Comms DR feature (grep)
- [ ] **T-7.2**: Retire the legacy uppercase "CORE" conformance label across the four documents and companion prose, renaming to avoid collision with the Core document name (req 31)
  - Depends on: T-7.1
  - Acceptance: grep for the uppercase "CORE" label in docs/spec/*.md and docs/*.md returns only archived/historical uses
- [ ] **T-7.3**: Split strict mode into per-document profiles with stable profile IDs and explicit composition rules, surfaced in capability advertisements and conformance reports (req 32)
  - Depends on: T-7.1
  - Acceptance: each document defines its strict-mode profile ID and the composition-rule table exists in Core
- [ ] **T-7.4**: Split monolith §13 and docs/security/threat-model.md by owner document with namespaced invariant IDs; decompose mixed invariants I1, I3, I6, I7; ensure Control's encrypted-audit requirement depends on no Social invariant (req 33)
  - Depends on: T-7.1, T-2.2
  - Acceptance: threat-model.md sections are owner-split, every invariant carries a namespaced ID, and I1/I3/I6/I7 no longer exist undecomposed
- [ ] **T-7.5**: Audit and enforce version-bound cross-document referencing: stable document IDs, permanent section anchors, no bare relative normative links between the four documents (req 34)
  - Depends on: T-7.1
  - Acceptance: scripted link audit over docs/spec/heterodyne-{core,comms,control,social}.md finds zero bare relative normative cross-doc links
- [ ] **T-7.6**: Update companion documents for the family: docs/architecture.md (non-normative family architecture with the four-layer dependency graph), README.md, CLAUDE.md, AGENTS.md, docs/glossary.md (shared normative terms into Core, local terms into owners, glossary stays a non-normative index), research/INDEX.md, and re-qualify stale monolith anchors in docs/spec/extensions/{nips,mscs}/ (req 36)
  - Depends on: T-7.2, T-7.4
  - Acceptance: none of the listed companion files describes a single normative specification (grep for the retired framing) and the extensions indexes carry re-qualified anchors

Phase 7 testability: label grep clean, link audit passes, threat-model IDs namespaced, companion docs family-framed; monolith text still untouched since T-1.5 and still bannered as authoritative.

### Phase 8: Vector corpus rework and coverage manifest (reqs 37-42)
- [ ] **T-8.1**: Make the fixture schema version-neutral: fixtures.json carries a document-version map replacing the single spec_version, generator SPEC_VERSION replaced, vector.schema.json and generator emit owner_document, owner_version, dependency_versions where applicable, and the registry-revision pin (reqs 18, 37)
  - Depends on: T-7.6
  - Acceptance: `npm run check` green with the new schema and no vector or fixture carries a bare single spec_version
- [ ] **T-8.2**: Assign per-vector owners across the whole corpus in the generator, applying the req-38 corrections (envelope/ -> Social; interop/ split Social vs Core kind:31005; org/001-003 Core vs org/004 Comms; redundancy/ -> Social; social-recovery/ split per req 13; config-backup/ split per the req-6 allocation); allocate new vector ids wherever behavior changes, never reusing existing ids (req 38)
  - Depends on: T-8.1
  - Acceptance: every generated vector carries owner metadata and a diff against the pre-split corpus shows no reused id with changed behavior
- [ ] **T-8.3**: Author the new-coverage vectors req 38 demands: Comms Nostr-native envelope vectors and Core Radicle multi-host redundancy vectors
  - Depends on: T-8.2
  - Acceptance: new comms-envelope and core-redundancy vector files exist and `npm run check` verifies them
- [ ] **T-8.4**: Author acceptance-gating vectors: Comms hook ordering, outcomes, and no-receipt message requests; Social mute/web-of-trust policy; record Control enrollment-gating coverage as deferred pending ADR-030 acceptance in the coverage manifest (reqs 40-41)
  - Depends on: T-8.2
  - Acceptance: Comms and Social gating vectors verify green and the coverage manifest marks Control gating coverage deferred
- [ ] **T-8.5**: Rework the reason-code artifact as a pure container in reason-codes.ts: per-code owner, status, and first-version metadata; per-document conformance subsets; qualified document anchors replacing bare section references; aligned with the Phase-2 registry entries (req 42)
  - Depends on: T-8.1, T-2.2
  - Acceptance: regenerated reason-codes.json carries owner/status/first-version per code and zero bare section references (scripted check)
- [ ] **T-8.6**: Emit the machine-readable coverage manifest (vector id, owner, profile, qualified spec references, dependency versions, registry pin) from the generator; derive four filtered per-document coverage maps plus one family aggregate; remove all hand-maintained parallel maps; update the vectors README for the family and the retired "CORE" label (reqs 31, 36, 39)
  - Depends on: T-8.3, T-8.4, T-8.5
  - Acceptance: manifest file is generator-emitted, the four derived maps regenerate byte-identically from it, and no hand-maintained map remains
- [ ] **T-8.7**: Full corpus regeneration and verification pass over the reworked suite
  - Depends on: T-8.6
  - Acceptance: `cd docs/spec/vectors/generator && npm run author && npm run check` exits 0 with the committed JSON matching the regenerated output

Phase 8 testability: `npm run check` green end-to-end; schema validation proves every vector has owner_document/owner_version; coverage manifest present and authoritative; monolith still authoritative and untouched.

### Phase 9: Cutover, archive, anchor map, release prep (reqs 4, 27, 28)
- [ ] **T-9.1**: Archive the final 0.4.x monolith at a frozen path and publish the old-section-to-new-anchor map so ADRs and external links remain resolvable (reqs 4, 27)
  - Depends on: T-8.7
  - Acceptance: archived file is byte-identical to pre-cutover heterodyne.md and a scripted check resolves every monolith section heading to an existing new-document anchor
- [ ] **T-9.2**: Cutover: replace docs/spec/heterodyne.md with a short non-normative family overview and document map; remove the "monolith remains authoritative" banners from all four documents (req 4)
  - Depends on: T-9.1
  - Acceptance: heterodyne.md contains no RFC 2119 normative requirements and no document still carries the draft banner (grep)
- [ ] **T-9.3**: Restructure CHANGELOG.md with per-document sections and define the release-manifest format recording the exact cross-document dependency combination and registry-revision pin per tag (reqs 18, 28)
  - Depends on: T-9.2, T-2.3
  - Acceptance: CHANGELOG.md has four per-document sections plus family history, and a release-manifest template exists
- [ ] **T-9.4**: needs-human: v0.5.0 release decision - four first releases descended from monolith 0.4.x with per-document git tags (core/v0.5.0, comms/v0.5.0, control/v0.5.0, social/v0.5.0) and release manifests (req 28)
  - Depends on: T-9.3
  - Acceptance: user decision recorded on the tracker ticket (release now, hold, or revise)
- [ ] **T-9.5**: Verify the req-2 dependency DAG across the released family: scripted audit that no lower document normatively references a higher one, Social has no normative Control dependency, and the local downref rule holds for every registry entry each document requires
  - Depends on: T-9.2
  - Acceptance: DAG/downref audit script exits 0 over the four documents and the registry artifact

Phase 9 testability: anchor-map resolution script passes; heterodyne.md non-normative; archived monolith byte-identical; DAG audit green; repo coherent for the v0.5.0 gate.
