# Security Review Remediation Design

- **Date:** 2026-08-26
- **Status:** Draft for review
- **Scope:** Remediation of the seven structural findings from the 2026-08 external model review (Opus 4.8) of the `heterodyne/0.5.0` specification family
- **Target release:** `heterodyne/0.6.0`

## 1. Context

An external review of the six normative documents plus the threat model identified
seven structural findings. This design records the accepted remediation for each,
as agreed during brainstorming on 2026-08-26.

| # | Finding (abridged) | Disposition |
|---|---|---|
| 1a | Hot active key concentrates all authority; no post-compromise adjudication for bare-key personas | Workspace governance MUST be Assurance-enrolled; other high-authority roles SHOULD (§4) |
| 1b | Assurance enrollment is a TOFU upgrade race a key thief can win | Contest window + scoped OTS tiebreak (§5) |
| 2 | Replaceable-state selection trusts unbounded self-asserted `created_at`; compromise cutoff is attacker-chosen | Verifier-time bound + optional OpenTimestamps anchoring profile (§2); cutoff selection accepted as a bounded recovery-holder power with OTS anchors as dispute evidence (§10) |
| 3 | Privacy-tier semantics diverged from intent; membership metadata public for Tier 3 audiences | Tier model re-cut; Tier 3 metadata confined to private repositories (§3) |
| 4 | Carrier withholding/equivocation is a reliable denial-of-authority lever; fail-closed stalls have no recovery path | Accepted as inherited (Nostr carrier model) with bounded-staleness disclosure (§7, §8); stall recovery for enrolled personas via §5 tiebreak |
| 5 | Execute-once/confused-deputy prose too subtle for uniform implementation | Out of scope this round (conformance-vector work tracked separately) |
| 6 | SHA-1 digests appear in security bindings; blanket dismissal insufficient | Explicit per-binding analysis; SHA-1 forbidden for authority bindings; SHA-1 replacement out of scope (§6) |
| 7 | OIDC host is a DNS/TLS chokepoint; 300 s freshness fragile; reason-code coarsening ambiguous | OIDC non-goals section; declared freshness bound; coarsening registry flag (§7, §8) |

Decisions fixed during brainstorming:

- Timestamp anchoring uses **OpenTimestamps** (Bitcoin-anchored proofs, NIP-03 / kind `1040`).
- Assurance requirement is **MUST for workspace governance, SHOULD for repository
  owners and claim-ledger authorities**.
- The enrollment race is **mitigated** (not merely documented).
- The tier model is **re-cut** to: public plaintext / public ciphertext / private
  ciphertext, with plaintext-in-private-repo demoted to a repository-visibility
  setting.
- The 300 s authorization-view window becomes a **deployment-declared bound with a
  hard ceiling**, defaulting to 300 s.

## 2. `created_at` bounds and the OTS anchoring profile

### 2.1 Baseline verifier-time bound (Core §6, normative, MUST)

A candidate for a replaceable coordinate whose `created_at` exceeds
`verifier_time + 900 s` does not enter the source-neutral selection union. The
candidate is **quarantined**, not invalidated: it stays cached, is reported with
new reason code `core-created-at-premature`, and re-enters selection automatically
if it is still a candidate when its `created_at` comes within bound. A verifier
whose known clock uncertainty exceeds 900 s fails closed, mirroring the existing
kind-31010 advert language.

Rationale for 900 s rather than the advert's 300 s: this rule gates every
replaceable event including vanilla Nostr events from arbitrary clients, so it
must tolerate ordinary cross-client clock skew. The Core §5.4 seven-day refresh
duty is unchanged and becomes the recovery mechanism: a quarantined future-dated
event that later activates is outbid by the owner's next refresh, capping any
residual capture at one refresh interval.

### 2.2 OTS anchoring profile (new optional extension `heterodyne:0.6.0#core-ots-anchor`)

Adopts NIP-03: a kind `1040` event carries the OpenTimestamps proof for a target
event ID.

- Any event MAY be anchored. Publishers of security-relevant replaceable state
  (kinds `0`, `10002`, mute/policy lists, Assurance records, Workspace heads)
  SHOULD anchor.
- A matured, validated OTS proof yields an attestation time `T_ots`: an upper
  bound on the event's true creation time, verified against Bitcoin block
  headers. Calendar servers are untrusted hints; header validation follows the
  carrier-neutrality doctrine.
- **Disqualification (MUST):** if `created_at > T_ots + 900 s`, the event's
  timestamp is proven false. The event is permanently excluded from replaceable
  selection and from every enhanced claim, with reason code
  `core-created-at-refuted`. This defuses future-dated "time bombs" even for
  verifiers that first synchronize long after publication.
- **Precedence (enhanced claim only):** where two candidates compete at one
  replaceable coordinate, an anchored, non-refuted candidate outranks an
  unanchored one only for an explicitly requested enhanced claim. Baseline
  NIP-01 selection is untouched, following the Assurance §12 layering
  discipline.
- Absence of a proof is never an error. A proof pending Bitcoin confirmation is
  `pending` and contributes nothing. No proof requirement may gate baseline
  interoperability (preserves ADR-047).

**Honesty note (normative in the profile):** OTS bounds only pastward existence.
It cannot prove an event was created recently and cannot refute backdating; it
complements, never replaces, the verifier-time bound.

## 3. Privacy-tier re-cut (Comms §3 and dependents)

### 3.1 New tier table

| Tier | Stored form | Nostr analogue | Trust boundary |
|---|---|---|---|
| 1 | plaintext in a public repository and on ordinary relays | plaintext post on a public relay (directly cross-compatible) | confidential against no one |
| 2 | NIP-44-v2-profile ciphertext in a public repository and/or on ordinary relays | encrypted post on a public relay (directly cross-compatible) | content confidential against everyone without the audience key; distribution graph, membership, timing, and volume public |
| 3 | NIP-44-v2-profile ciphertext carried only via authorized private-repository interfaces | encrypted post on a members-only relay (no direct Nostr equivalent) | content confidential as Tier 2, and ciphertext, audience wraps, rosters, and fetch patterns visible only to allowed nodes |

The Nostr-analogue column is normative interoperability documentation consistent
with ADR-047: Tier 1 and Tier 2 objects are valid Nostr events publishable to
ordinary relays; Tier 3 is defined by Heterodyne private-repository mechanics and
has no direct Nostr equivalent.

### 3.2 Plaintext private repositories

The 0.5.0 "Tier 2" (plaintext in a private repository) is removed as a
confidentiality tier and re-expressed as an orthogonal repository-visibility
setting (`visibility.allow` on any repository, mechanics unchanged). Its honesty
rules survive verbatim: it MUST NOT be described as encrypted, end-to-end
encrypted, or confidential against members; adding an NID to `visibility.allow`
grants plaintext read and replication and SHOULD require explicit user
confirmation; `visibility.allow` MUST NOT be conflated with `delegates`.

### 3.3 Tier 3 metadata confinement (the substantive fix)

For a Tier 3 audience, the kind `31011` audience wraps, kind `31012` roster,
rotation records, and the Tier 3 posts themselves MUST be carried only via the
private repository's authorized interfaces — never on ordinary public relays.
This confines the clear recipient `p` tags, `key_id` linkage, and roster deltas
to allowed nodes. Recipients must be allowed on the private repository before
they can receive wraps; the design accepts this, since they are audience members.

### 3.4 Revised disclosure duties

- Tier 2 keeps the full 0.5.0 Tier 3 disclosure: content-only confidentiality;
  sender, recipients, membership, generation linkage, timing, and volume are
  public; MUST NOT be labeled membership-private.
- Tier 3's disclosure becomes: membership, timing, and volume are visible to
  every allowed node and seeder of the repository; the protocol defines no
  membership privacy within the audience's carrier set; Tier 3 has no forward
  secrecy (one leaked audience key decrypts every retained post under its
  `key_id`; rotation protects only later generations). A client MUST NOT label
  Tier 3 membership-private beyond the allowed-node boundary.
- Threat model addition: new Tier 3 improves membership privacy against global
  observers but concentrates metadata at the private repository's allowed nodes;
  a compromised or compelled allowed node yields the audience graph.

### 3.5 Unchanged

The Tier 3 cryptographic profile (HKDF-SHA256 post-key derivation, stamping
profile, outer post shape, receiver order) is untouched. This is a
carrier-confinement change, not a cryptographic one.

## 4. Assurance requirement for workspace governance

### 4.1 The MUST (Workspace §2)

The rule "a bare key with no Assurance state is complete baseline authority" is
replaced for workspace personas:

- A workspace persona MUST have a window-complete (per §5), `verified` Assurance
  enrollment. Workspace inception binds the exact `inception_event_id` into the
  genesis policy object.
- Every operation in the existing authority-mutation class (grants, invitations,
  policy changes, key issuance, publicization, federation, governance, archive)
  additionally requires the workspace's Assurance evaluation to be `verified` at
  effect time.
- `stalled`, `unavailable`, or `downgraded` fails closed **for governance
  operations only**. Ordinary code, content, and discussion writes keep the
  existing 86,400 s window and continue working. This bounds the blast radius of
  equivocation denial-of-service: forking a workspace's Assurance chain freezes
  policy changes, not the repository.

### 4.2 Post-compromise adjudication

For workspace personas, the `active-account` compromise-reset class is
forbidden; `assurance-recovery` (cold-root-signed) is the only reset path. The
hot key can no longer authorize its own succession, so a thief holding it cannot
run a valid reset. Control §8.1 already requires the assurance-recovery class
whenever a pinned Assurance head exists; this is a tightening, not new
machinery.

### 4.3 The SHOULD tier

Repository owners/delegates and claim-ledger authorities (private persona ledger
and OIDC issuer roots) SHOULD be Assurance-enrolled. Clients MUST surface an
"unenrolled high-authority persona" warning when they are not. No conformance
gate: bare keys remain valid in these roles.

### 4.4 Migration and bootstrap

Existing workspaces get one release cycle to enroll; new workspaces require
enrollment at inception. Because of the §5 contest window, creating a workspace
requires having enrolled its cold root at least seven days prior. This is
accepted and documented as "enroll before you incorporate."

## 5. Enrollment contest window with scoped OTS tiebreak

### 5.1 Pin-eligibility window

A reciprocal enrollment (kind `31002` inception + kind `31000` acceptance) is
not pin-eligible until it has been observably public and conflict-free for
`W = 604,800 s` (seven days). Either satisfies W:

1. the verifier's own conflict-free observation for W (default for online
   verifiers); or
2. conflict-free witness receipts spanning at least W and satisfying the
   enrollment's configured witness thresholds, reusing existing Assurance
   witness machinery, so a late-synchronizing verifier need not wait a week to
   pin a long-established enrollment.

The window is observation-based, never `created_at`-based: a thief can backdate
freely, and the existing "never backdated" rule constrains only
acceptance-versus-inception ordering. Verifiers that TOFU before W has elapsed
report the new evaluation state `pending` (added alongside the existing seven),
which contributes no enhanced claim.

### 5.2 Owner alarm and contest

A client holding a persona's key MUST alarm when it observes any enrollment for
that key it did not initiate, and MAY publish a contest event signed by the same
active key. A contest or competing enrollment during any verifier's window makes
the enrollment non-pin-eligible wherever observed (`assurance-enrollment-contested`);
the persona remains baseline.

Documented consequence: a key thief can permanently deny Assurance, but denial
is bounded harm — a bare-key holder can already fully impersonate at baseline.
What the window removes is the thief gaining cold-root supremacy over the owner,
which was the takeover in finding 1b.

### 5.3 Scoped OTS tiebreak

A conflict between enrollments E1 and E2 resolves to E1 (instead of stalling)
only when **both** hold:

1. E1 carries a matured OTS anchor proving it existed at least W before E2's
   earliest provable existence (E2's own anchor time, else its first witnessed
   observation); and
2. E1 carries conflict-free witness receipts covering that same period.

Condition 1 alone defeats fabricated backdated competitors (they are unanchored)
but is vulnerable to a hidden-anchor attack (a thief anchors an enrollment
secretly and publishes it later). Condition 2 defeats the hidden anchor, because
a withheld enrollment has no observation trail. Net effect: an established,
anchored, witnessed enrollment cannot be stalled by a late competitor — the
denial-of-assurance lever is removed for everyone who enrolled properly — while
genuine races (two enrollments within one window of each other) still fail
closed to stall, never to the thief.

### 5.4 New vocabulary

Reason codes `assurance-enrollment-pending-window` and
`assurance-enrollment-contested`; evaluation state `pending`.

## 6. SHA-1 binding analysis (Core §12 rewrite)

The blanket sentence "a RID collision cannot authorize a forged event or writer
ref" is replaced by a per-binding analysis:

| Value | Where | Classification | Analysis |
|---|---|---|---|
| RID (20-byte Git OID) | Core §4, `rad:z…` | Locator | A collision yields two repositories claiming one name; neither gains event authorship (SHA-256/BIP-340) or ref authority (Ed25519) |
| `repo_head` | kind `31010` seed advert (Ed25519-bound) | Possession snapshot | Signature-bound but grants nothing; advert expiry ≤ 86,400 s limits exposure |
| `repository_head` | every signed Workspace object | Carrier context | Signature-bound but explicitly non-authority; heads not reachable from the accepted authority branch are rejected |

The section states explicitly that the genesis manifest digest is already
SHA-256 (`genesis_manifest_sha256`), correcting the review's assumption. For
each signature-bound SHA-1 value it states the concrete attack requirement — a
chosen-prefix collision against repository state the attacker can influence
**and** a consumer that treats the digest as more than a locator — and why
current rules break the second half.

Two normative additions:

1. No current or future Heterodyne document may bind authority, policy, or key
   material to a SHA-1 digest; authority bindings require SHA-256 or stronger.
   (Already de facto true; the rule prevents regression.)
2. Implementations SHOULD prefer Radicle's `sha256` object format where the
   substrate supports it. The credential-ledger schemas already carry
   dual-format `sha1`/`sha256` patterns, so this is pre-plumbed.

Replacing SHA-1 in the Radicle substrate remains out of scope.

## 7. Declared authorization-freshness bound (Comms §9.2 rewrite)

The 300 s constant becomes a deployment-declared parameter with a hard ceiling:

- Default `authorization_view_max_age` is 300 s.
- A deployment MAY declare a larger value in its signed continuity
  manifest/policy, up to an absolute ceiling of 86,400 s (aligned with the
  Workspace ordinary-write window, so "declared" can never mean unbounded).
- Local policy and composing documents may still only shorten, never lengthen
  beyond the declared value.
- Relying parties MUST be able to read the declared bound before trusting a
  deployment, and clients surface it.

The declaration channel already exists: the continuity manifest bound that
"MUST NOT exceed the window in §9.2." The invariants `COMMS-I-MINT-FRESHNESS`
and `WORKSPACE-I-FRESHNESS-BOUNDED` are reworded to test against the declared
value ("no older than the declared bound, ≤ 86,400 s, default 300 s"), keeping
them falsifiable. The threat model states plainly that revocation latency at
honest nodes is bounded by the declared value: choosing a long window is
choosing slow revocation, disclosed rather than hidden. This addresses the
partition-fragility finding (deep claim chains in private networks declare a
realistic window) without making freshness untestable.

## 8. Scope notes, threat-model honesty, and hygiene

- **OIDC non-goals (Comms §12):** a new subsection consolidating scattered
  statements — the issuer projection is for private-network and workload/agent
  authentication and ordinary third-party relying-party verification; it is not
  censorship-resistant; the host is an availability/correlation chokepoint; and
  issuer or NIP-05 metadata never creates identity authority.
- **Withholding/equivocation (threat model):** a new accepted-risk entry:
  carriers can withhold revocations and monotonic state; defenses are multiple
  independent carriers plus the declared freshness bound (§7), which converts a
  withheld revocation from indefinite into bounded staleness at any honest
  minting node. Residual risk for pure-relay reading clients is inherited from
  the Nostr carrier model and accepted.
- **Stall recovery:** the §5.3 witnessed-anchor tiebreak is the specified
  recovery from equivocation-induced `assurance-duplicity` stall for properly
  enrolled personas, closing the "no recovery path" gap.
- **Reason-code coarsening (Core §13.2):** the registry gains an
  `intentionally_coarse: true` flag on codes §13.2 requires to stay coarse, and
  the Workspace vocabulary preamble ("MUST preserve distinct outcomes") gains a
  cross-reference deferring to §13.2 where the two collide.

## 9. Cross-cutting changes

- **Version:** all changes land as `heterodyne/0.6.0` with an ADR superseding
  the tier language of ADR-028/ADR-037 and recording the created_at, Assurance,
  and freshness decisions.
- **New reason codes:** `core-created-at-premature`, `core-created-at-refuted`,
  `assurance-enrollment-pending-window`, `assurance-enrollment-contested`, plus
  workspace codes for governance-requires-assurance rejections.
- **New registry entries:** `core-ots-anchor` extension; `intentionally_coarse`
  flag; `authorization_view_max_age` manifest member.
- **Migration:** tier mapping (old Tier 2 → repository-visibility setting; old
  Tier 3 → new Tier 2 or 3 by repository visibility); one-release enrollment
  window for existing workspaces.

## 10. Explicitly accepted risks and non-goals

- Carrier withholding for pure-relay readers: inherited from Nostr, accepted
  with disclosure (§8).
- SHA-1 in the Radicle substrate: analyzed and constrained, not replaced (§6).
- OIDC censorship resistance: a non-goal (§8).
- Tier 3 forward secrecy: still absent; disclosed (§3.4). Users needing forward
  secrecy use the Marmot/MLS path.
- Enrollment denial by a key thief: possible but bounded (§5.2).
- Compromise-cutoff selection: `compromise_time` remains chooseable by the
  recovery holder within `[current_head.created_at, succession.created_at]`.
  This is a recovery-holder power by design; OTS anchors on a victim's
  legitimate events give third parties objective existence evidence when a
  cutoff is disputed, but the protocol does not adjudicate the choice.
- Execute-once/confused-deputy specification subtlety (finding 5): out of scope
  this round; tracked for conformance-vector coverage in a later revision.

## 11. Testing and conformance

- Vectors: future-dated quarantine and re-entry; OTS refutation
  (`created_at > T_ots + 900 s`); anchored-vs-unanchored enhanced-claim
  precedence; enrollment window elapse, contest, duplicity stall, and both
  tiebreak conditions (including hidden-anchor rejection); Tier 3 wrap/roster
  confinement rejection on public carriers; declared-bound minting at default,
  declared, and above-ceiling values; workspace governance rejection for
  `pending`/`stalled`/`unavailable` Assurance states with ordinary writes still
  accepted.
- Conformance: `intentionally_coarse` registry linting; SHA-1-authority-binding
  lint over schemas (no new 40-hex authority members).
