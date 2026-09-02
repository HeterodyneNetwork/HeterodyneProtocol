# Security Review Remediation (heterodyne/0.6.0) Implementation Plan

> **Superseded before merge:** The approved closure design and implementation
> plan dated 2026-08-27 replace this artifact where they differ. In particular,
> vectors are required, Workspace Assurance is optional, NIP-03 is advisory,
> and existing registry `first_version` values retain their history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the approved security-review remediation as `heterodyne/0.6.0` normative text, registry, schemas, ADR, and threat-model changes — without touching `docs/spec/vectors`.

**Architecture:** This is a specification repo; the deliverables are normative markdown, registry JSON, and JSON schemas. Each task edits one coherent surface and is gated by the conformance vitest suite (anchor-based, version-agnostic, outside the vectors tree), which MUST stay green after every task. The vector-generator lane (`draft:check`) pins `FAMILY_VERSION = "0.5.0"` inside `docs/spec/vectors/generator` and will be red after the version cutover; that is expected and documented, and is resolved by the separate vectors step.

**Tech Stack:** Markdown (CommonMark, linted), JSON Schema (draft — match existing schema style), Node/vitest conformance harness at `docs/spec/conformance`.

**Spec:** `docs/superpowers/specs/2026-08-26-security-review-remediation-design.md`

## Global Constraints

- Do NOT create, modify, or delete anything under `docs/spec/vectors/` (generator included). Running its scripts read-only is allowed.
- Uniform family version: every version string outside `docs/spec/vectors/` and `docs/adr/archive/` becomes `heterodyne/0.6.0` (wire form) / `heterodyne:0.6.0#…` (reference form). ADR archive files are historical records and keep their original strings.
- Green gate after every task: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`. Run `npm --prefix docs/spec/conformance ci` once before Task 1.
- Expected-red lane: `npm --prefix docs/spec/vectors/generator run draft:check` fails after Task 1 with version-mismatch lint errors. Do not "fix" this by editing the generator.
- The threat-model `## Registry-bound invariants` list mirrors `security-invariants.json` descriptions **byte-for-byte**. Any invariant edit updates both.
- New registry entries use `"first_version": "heterodyne/0.6.0"`, `"status": "draft"`. Existing entries' `first_version` becomes `heterodyne/0.6.0` as part of the uniform cutover (precedent: commit `147a92d` rewrote all version strings in one pass; the repo is pre-1.0 with a single live version).
- `docs/spec/registry/manifest.json` `entry_set_sha256` is recomputed once, in Task 10, after the last registry edit. Interim tasks leave it stale (the conformance vitest suite does not check it; only the vectors-side lint does, and that lane is already expected-red).
- Numeric constants come from the design spec verbatim: 900 s premature slack, W = 604,800 s enrollment window, 300 s default / 86,400 s ceiling freshness, seven-day refresh unchanged.
- Commit per task with a `spec:`/`docs:`/`registry:` prefix; work happens on branch `feat/security-review-remediation-0.6.0`.

---

### Task 1: Version cutover to 0.6.0 (outside vectors)

**Files:**
- Modify: `docs/spec/heterodyne.md`, `docs/spec/heterodyne-core.md`, `docs/spec/heterodyne-assurance.md`, `docs/spec/heterodyne-comms.md`, `docs/spec/heterodyne-control.md`, `docs/spec/heterodyne-social.md`, `docs/spec/heterodyne-workspace.md`
- Modify: `docs/spec/registry/*.json` (all six data files; NOT manifest.json digest — only if it contains version strings, which it does not)
- Modify: every schema under `docs/spec/schemas/**` (38 files, one `"const": "heterodyne/0.5.0"` each)
- Modify: `docs/spec/conformance/src/subjects/types.ts:75` (type literal), `docs/spec/conformance/src/test-support.ts`, `docs/spec/conformance/src/gates/subject-gates.test.ts`, `docs/spec/conformance/src/subjects/reference-checker.test.ts`, `docs/spec/conformance/src/ratchet.test.ts` (fixture strings)
- Modify: `docs/spec/extensions/nips/README.md` (6 `heterodyne:0.5.0#…` rows)
- Modify: `docs/security/threat-model.md` (any version strings)
- Modify: `CHANGELOG.md` (new `heterodyne/0.6.0` section header: "Security review remediation — see docs/superpowers/specs/2026-08-26-security-review-remediation-design.md and ADR-048")

**Interfaces:**
- Produces: the string forms `heterodyne/0.6.0` and `heterodyne:0.6.0#<anchor>` that every later task uses in new registry entries, schema consts, and spec references.

- [ ] **Step 1: Baseline the green gate**

Run: `npm --prefix docs/spec/conformance ci && npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS (record baseline; if this fails before any edit, stop and report).

- [ ] **Step 2: Enumerate every 0.5.0 occurrence outside vectors and ADR archive**

Run: `grep -rln "heterodyne[:/]0\.5\.0" --exclude-dir=vectors docs CHANGELOG.md | grep -v "docs/adr/archive" | grep -v "docs/superpowers"`
Expected: exactly the file set listed above (spec docs, registry JSON, schemas, conformance src, extensions README, threat model, possibly CHANGELOG). Investigate any surprise file before replacing.

- [ ] **Step 3: Replace both string forms in that file set**

For each file from Step 2: replace `heterodyne/0.5.0` → `heterodyne/0.6.0` and `heterodyne:0.5.0#` → `heterodyne:0.6.0#`. Use per-file `sed -i ''` or scripted replacement; do not hand-edit 400 registry lines.

- [ ] **Step 4: Add the CHANGELOG section**

At the top of the existing entries in `CHANGELOG.md`, add:

```markdown
## heterodyne/0.6.0 (draft)

Security review remediation: verifier-time bound and optional OpenTimestamps
anchoring for replaceable state, privacy-tier re-cut with Tier 3 metadata
confinement, mandatory Assurance for workspace governance, enrollment contest
window, per-binding SHA-1 analysis, declared authorization-freshness bound.
Design: docs/superpowers/specs/2026-08-26-security-review-remediation-design.md.
ADR-048. Vectors intentionally not regenerated in this change; the current
vector lane remains pinned at 0.5.0 until the follow-up vectors step.
```

- [ ] **Step 5: Verify zero stragglers and green gate**

Run: `grep -rn "heterodyne[:/]0\.5\.0" --exclude-dir=vectors docs CHANGELOG.md | grep -v "docs/adr/archive" | grep -v "docs/superpowers" | wc -l`
Expected: `0`
Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS. If a conformance test still pins 0.5.0, it is in-scope src/fixtures — fix it (never vector data).

- [ ] **Step 6: Confirm the expected-red lane and commit**

Run: `npm --prefix docs/spec/vectors/generator ci >/dev/null 2>&1; npm --prefix docs/spec/vectors/generator run draft:check 2>&1 | tail -5 || true`
Expected: FAIL mentioning version mismatch vs `heterodyne/0.5.0` — record the tail in the commit body.

```bash
git add -A ':!docs/spec/vectors' && git commit -m "spec: cut family version over to heterodyne/0.6.0 outside vectors"
```

---

### Task 2: Core §6 verifier-time bound + quarantine reason code

**Files:**
- Modify: `docs/spec/heterodyne-core.md` (§6, the source-neutral selection rules; current text near the sentence "within one replaceable coordinate, greatest `created_at` wins, with lowest lexicographic event ID winning a tie.")
- Modify: `docs/spec/registry/reason-codes.json` (one new entry)

**Interfaces:**
- Produces: reason code `core-created-at-premature`; the normative anchor `<a id="core-created-at-bound"></a>` that Tasks 3 and 9 reference.

- [ ] **Step 1: Add the normative bound to Core §6**

Read the §6 selection subsection, then insert a new paragraph (with anchor) immediately after the selection-rule list:

```markdown
<a id="core-created-at-bound"></a>
Selection additionally applies a premature-candidate bound. A candidate whose
`created_at` exceeds the verifier's trusted current time by more than 900
seconds MUST NOT enter the selection union. The candidate is quarantined, not
invalidated: the verifier retains it, reports `core-created-at-premature`, and
the candidate re-enters selection automatically once its `created_at` is
within bound, if it is still a candidate then. A verifier whose known clock
uncertainty exceeds 900 seconds fails closed for selection that this bound
would decide. Quarantine changes candidate admission only; it does not alter
NIP-01 cryptographic validity, and the kind `0`/`10002` seven-day refresh duty
is unchanged and caps the residual effect of a later-activating quarantined
candidate at one refresh interval.
```

- [ ] **Step 2: Register the reason code**

Add to `reason_codes` in `docs/spec/registry/reason-codes.json`, matching the existing entry shape exactly:

```json
{
  "code": "core-created-at-premature",
  "owner": "core",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Replaceable-selection candidate quarantined because its created_at exceeds trusted verifier time by more than the 900 second premature bound.",
  "spec_refs": [
    "heterodyne:0.6.0#core-created-at-bound"
  ]
}
```

- [ ] **Step 3: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS (the dead-vocabulary gate sees the code referenced from the new anchor; if it flags the new code, confirm the spec text cites the code string literally — it does, in backticks).

```bash
git add docs/spec/heterodyne-core.md docs/spec/registry/reason-codes.json
git commit -m "spec: bound replaceable selection against premature created_at"
```

---

### Task 3: OTS anchoring profile (Core), kind 1040, feature, refutation code

**Files:**
- Modify: `docs/spec/heterodyne-core.md` (new optional-extension section after the seed-advert/discovery material; heading `## NN. Optional OpenTimestamps anchoring` with anchors `core-ots-anchor`, `core-ots-refutation`)
- Modify: `docs/spec/registry/kinds.json` (kind `1040`), `docs/spec/registry/features.json` (`core.ots-anchor.v1`), `docs/spec/registry/reason-codes.json` (`core-created-at-refuted`), `docs/spec/registry/security-invariants.json` (`CORE-I-CREATED-AT-REFUTATION`)
- Modify: `docs/security/threat-model.md` (append the new invariant line to the registry mirror, byte-for-byte)
- Modify: `docs/spec/extensions/nips/README.md` (one new extraction row)

**Interfaces:**
- Consumes: `core-created-at-premature` bound and anchor from Task 2 (the 900 s slack constant is shared).
- Produces: feature id `core.ots-anchor.v1`; anchors `core-ots-anchor`, `core-ots-refutation`; attestation-time concept `T_ots` used by Task 6's enrollment tiebreak.

- [ ] **Step 1: Write the Core section**

```markdown
## NN. Optional OpenTimestamps anchoring

<a id="core-ots-anchor"></a>
`core.ots-anchor.v1` is optional. It adopts NIP-03: a kind `1040` event whose
`e` tag names a target event ID and whose content carries the OpenTimestamps
proof for that ID. Any event MAY be anchored. Publishers of security-relevant
replaceable state — kinds `0` and `10002`, mute and policy lists, Assurance
records, and Workspace heads — SHOULD anchor.

A matured, validated proof yields an attestation time `T_ots`: an upper bound
on the target event's true creation time, verified against Bitcoin block
headers that the verifier obtains and validates itself. Calendar servers are
untrusted hints and MUST NOT be treated as attestation authorities. A proof
that has not matured to a Bitcoin attestation is `pending` and contributes
nothing. Absence of a proof is never an error, and no proof requirement may
gate baseline interoperability.

<a id="core-ots-refutation"></a>
If a validated attestation satisfies `created_at > T_ots + 900` seconds, the
target event's timestamp is proven false. The event MUST be permanently
excluded from replaceable selection and from every enhanced claim, with reason
code `core-created-at-refuted`. Refutation survives restarts and carrier
changes once evidence is validated.

Where two candidates compete at one replaceable coordinate under the baseline
rules, an anchored, non-refuted candidate outranks an unanchored one only for
an explicitly requested enhanced claim; baseline NIP-01 selection is
unchanged, following the Assurance layering discipline.

OpenTimestamps bounds only pastward existence. It cannot prove that an event
was created recently and cannot refute backdating. It complements the
premature-candidate bound in `heterodyne:0.6.0#core-created-at-bound` and
never replaces it.
```

Number `NN` = next free top-level section number in heterodyne-core.md; renumber nothing.

- [ ] **Step 2: Registry entries**

`kinds.json` — add, following the existing kind-0 entry shape:

```json
{
  "kind": 1040,
  "allocation_authority": "nostr",
  "base_schema_owner": "nostr",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "profiles": [
    {
      "profile_id": "heterodyne-core-ots-attestation-profile-v1",
      "owner": "core",
      "discriminator": "production-rule:ots-attestation-kind1040-v1",
      "stamping": false,
      "first_version": "heterodyne/0.6.0",
      "status": "draft"
    }
  ]
}
```

`features.json` — add (single-line style):

```json
{"id":"core.ots-anchor.v1","owner":"core","first_version":"heterodyne/0.6.0","status":"draft","description":"Optional NIP-03 OpenTimestamps anchoring: kind 1040 attestations, premature-bound composition, permanent refutation of provably future-dated state, and enhanced-claim precedence for anchored candidates.","spec_ref":"heterodyne:0.6.0#core-ots-anchor","prerequisites":[]}
```

`reason-codes.json` — add:

```json
{
  "code": "core-created-at-refuted",
  "owner": "core",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Event permanently excluded because a matured OpenTimestamps attestation proves its created_at exceeds its true existence time by more than the 900 second bound.",
  "spec_refs": [
    "heterodyne:0.6.0#core-ots-refutation"
  ]
}
```

`security-invariants.json` — add:

```json
{
  "id": "CORE-I-CREATED-AT-REFUTATION",
  "owner": "core",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "feature": "core.ots-anchor.v1",
  "description": "A matured OpenTimestamps attestation proving created_at materially exceeds true existence time permanently excludes the event from replaceable selection and every enhanced claim, and no proof requirement gates baseline interoperability."
}
```

- [ ] **Step 3: Mirror and index**

Append to the threat-model `## Registry-bound invariants` list, copying the description byte-for-byte:

```markdown
- **CORE-I-CREATED-AT-REFUTATION:** A matured OpenTimestamps attestation proving created_at materially exceeds true existence time permanently excludes the event from replaceable selection and every enhanced claim, and no proof requirement gates baseline interoperability.
```

Add to `docs/spec/extensions/nips/README.md` table:

```markdown
| `heterodyne:0.6.0#core-ots-anchor` | NIP-03 anchoring for replaceable-state selection | Optional OpenTimestamps attestation of Nostr events with permanent refutation of provably future-dated replaceable state. |
```

- [ ] **Step 4: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS.

```bash
git add docs/spec/heterodyne-core.md docs/spec/registry docs/security/threat-model.md docs/spec/extensions/nips/README.md
git commit -m "spec: add optional OpenTimestamps anchoring profile (core.ots-anchor.v1)"
```

---

### Task 4: Privacy-tier re-cut (Comms §3) and dependent restatements

**Files:**
- Modify: `docs/spec/heterodyne-comms.md` §3 (tier table at the text beginning "Every repository-carried publication declares one of three trust boundaries"; disclosure paragraphs; the encrypt-before-carrier paragraph; filter-routing lines "Tier 1 filters may query ordinary public relays…" and persistence-warning lines "Clients MUST warn that Tier 1 and Tier 2 plaintext may persist…")
- Modify: `docs/spec/heterodyne-social.md` (tier restatements near "public-reader confinement" language)
- Modify: `docs/security/threat-model.md` (Confidentiality and topology leakage section)
- Modify: `docs/spec/registry/security-invariants.json` (`COMMS-I-TIER3-CONFINED`) + threat-model mirror line

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: new tier semantics (T1 public plaintext / T2 public ciphertext / T3 private-repo ciphertext) and anchor `comms-tier3-confinement`, referenced by Task 8 (ADR) and the threat model.

- [ ] **Step 1: Replace the §3 tier table and framing**

New table (keep the section heading; replace table + immediate framing sentence):

```markdown
Every repository-carried publication declares one of three confidentiality
tiers, which clients MUST present without ambiguity. Tier 1 and Tier 2 objects
are valid Nostr events and are directly cross-compatible with ordinary public
relays; Tier 3 is defined by Heterodyne private-repository mechanics and has
no direct Nostr equivalent.

| Tier | Stored form | Nostr analogue | Trust boundary |
|---|---|---|---|
| Tier 1 | plaintext in a public repository and on ordinary relays | plaintext post on a public relay | confidential against no one |
| Tier 2 | NIP-44-v2-profile ciphertext in a public repository and/or on ordinary relays | encrypted post on a public relay | content confidential against everyone without the audience key; distribution graph, membership, timing, and volume public |
| Tier 3 | NIP-44-v2-profile ciphertext carried only via authorized private-repository interfaces | encrypted post on a members-only relay (no direct equivalent) | content confidential as Tier 2, and ciphertext, audience wraps, rosters, and fetch patterns visible only to allowed nodes |
```

- [ ] **Step 2: Demote plaintext private repositories**

Immediately after the table, add:

```markdown
Plaintext in a private repository is a repository-visibility setting, not a
confidentiality tier. `visibility.allow` mechanics are unchanged: it MUST NOT
be described as encrypted, end-to-end encrypted, or confidential against
members; adding an NID to `visibility.allow` grants that node plaintext read
and replication access and SHOULD require explicit user confirmation; and
`visibility.allow` MUST NOT be conflated with the repository `delegates`
governance set.
```

Then sweep §3 and the filter/persistence sections: every rule that governed old-Tier-2 (plaintext private repo) is re-targeted at "plaintext private-repository visibility"; every rule that governed old-Tier-3 ciphertext splits by carrier: public-carrier ciphertext rules → Tier 2, private-only rules → Tier 3. Update "Tier 1 and Tier 2 plaintext may persist" to "Tier 1 plaintext and private-repository plaintext may persist"; update tier filter-routing lines to: Tier 1 and Tier 2 filters may query ordinary public relays and public repo relays; Tier 3 filters may query only authorized private-repository interfaces.

- [ ] **Step 3: Add the confinement rule**

```markdown
<a id="comms-tier3-confinement"></a>
For a Tier 3 audience, the kind `31011` audience wraps, the kind `31012`
roster, rotation records, and the Tier 3 posts themselves MUST be carried only
via the private repository's authorized interfaces and MUST NOT be published
to ordinary public relays. This confines the clear recipient `p` tags,
`key_id` linkage, and roster changes to allowed nodes. A recipient MUST be an
allowed node of the private repository before wraps addressed to it are
published there.
```

- [ ] **Step 4: Rewrite the disclosure duties**

Tier 2 takes the old Tier 3 disclosure verbatim (content-only confidentiality; sender, recipients, membership and changes, generation linkage, timing, volume all public; MUST NOT label membership-private). Tier 3's becomes:

```markdown
Before a user relies on a Tier 3 audience, the client MUST disclose that
membership, timing, and volume are visible to every allowed node and seeder of
the repository; that the protocol defines no membership privacy within the
audience's carrier set; and that Tier 3 has no forward secrecy — a compromised
audience key decrypts every retained post under its `key_id`, and rotation
protects only later generations. A client MUST NOT label Tier 3
membership-private beyond the allowed-node boundary.
```

Keep the existing sentence "This release defines no membership-private audience-key distribution profile." — it is still true within the carrier set.

- [ ] **Step 5: Registry invariant + mirrors**

`security-invariants.json`:

```json
{
  "id": "COMMS-I-TIER3-CONFINED",
  "owner": "comms",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Tier 3 posts, audience wraps, rosters, and rotation records are carried only via the private repository's authorized interfaces, never ordinary public relays, confining audience membership metadata to allowed nodes."
}
```

Threat-model: append the mirror line byte-for-byte, and in the Confidentiality and topology leakage section add:

```markdown
Tier 3 improves membership privacy against global observers but concentrates
audience metadata at the private repository's allowed nodes; a compromised or
compelled allowed node yields the audience graph. Tier 2 ciphertext on public
carriers exposes the full distribution graph by design.
```

Update Social's tier restatements to the new semantics (read the quoted lines first; the change is mechanical relabeling).

- [ ] **Step 6: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS.
Run: `grep -n "plaintext in a private repository" docs/spec/heterodyne-comms.md`
Expected: appears only in the visibility-setting paragraph, not in any tier row.

```bash
git add docs/spec/heterodyne-comms.md docs/spec/heterodyne-social.md docs/security/threat-model.md docs/spec/registry/security-invariants.json
git commit -m "spec: re-cut privacy tiers and confine Tier 3 audience metadata"
```

---

### Task 5: Declared authorization-freshness bound (Comms §9.2, Workspace composition, invariants)

**Files:**
- Modify: `docs/spec/heterodyne-comms.md` §9.2 (paragraph beginning "Token minting and every privileged use require an authenticated, non-conflicted private authorization view no more than 300 seconds old") and §12's minting-bound sentence ("That bound MUST NOT exceed the window in §9.2")
- Modify: `docs/spec/heterodyne-workspace.md` freshness-composition section ("Authority mutations … use the authorization-view window defined by `heterodyne:0.6.0#comms-authorization-freshness`")
- Modify: `docs/spec/registry/security-invariants.json` (`COMMS-I-MINT-FRESHNESS`, `WORKSPACE-I-FRESHNESS-BOUNDED` descriptions)
- Modify: `docs/security/threat-model.md` (both mirror lines, byte-for-byte)

**Interfaces:**
- Produces: manifest member name `authorization_view_max_age` (declared bound), constants default 300 s / ceiling 86,400 s, used by Task 8's ADR and Task 9's threat-model prose.

- [ ] **Step 1: Rewrite Comms §9.2**

Replace the 300 s paragraph with:

```markdown
Token minting and every privileged use require an authenticated,
non-conflicted private authorization view no older than the deployment's
declared bound. The declared bound is the signed continuity-manifest member
`authorization_view_max_age`, in seconds; when absent it is 300, and it MUST
NOT exceed 86,400. A mutation additionally performs an immediate
synchronization attempt against the canonical private ledger before
authorizing, and fails closed unless it establishes that fresh view. A fresh
token cannot extend a stale authorization view. A composing document or a
local policy MAY shorten the effective bound and MUST NOT lengthen it beyond
the declared value. A relying party MUST be able to read the declared bound
before trusting a deployment, and clients surface it. Revocation latency at
honest nodes is bounded by the declared value: declaring a long window is
declaring slow revocation.
```

- [ ] **Step 2: Update the two invariant descriptions (registry + threat-model mirror, byte-for-byte)**

`COMMS-I-MINT-FRESHNESS` description becomes:

```text
A node mints only from a synchronized canonical checkpoint no older than the declared authorization_view_max_age bound, which defaults to 300 seconds and cannot exceed 86400 seconds.
```

`WORKSPACE-I-FRESHNESS-BOUNDED` description: replace the phrase "authority mutations no older than 300 seconds" with "authority mutations no older than the declared authorization-view bound (default 300 seconds, ceiling 86400 seconds)"; leave the remainder of the sentence untouched.

- [ ] **Step 3: Sweep dependent 300 s references**

Run: `grep -n "300 second\|300 s\b\|300s" docs/spec/heterodyne-comms.md docs/spec/heterodyne-workspace.md docs/spec/heterodyne-control.md docs/spec/heterodyne-social.md`
For each authorization-view hit, reword to "the declared authorization-view bound". Leave the Core kind-31010 ±300 s advert clock check untouched — it is a different clock and stays hard.

- [ ] **Step 4: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS.
Run: `diff <(grep -o 'COMMS-I-MINT-FRESHNESS.*' docs/security/threat-model.md) <(python3 -c "import json;print('COMMS-I-MINT-FRESHNESS:** '+[e['description'] for e in json.load(open('docs/spec/registry/security-invariants.json'))['security_invariants'] if e['id']=='COMMS-I-MINT-FRESHNESS'][0])")`
Expected: no output (byte-for-byte mirror; adjust the extraction to the mirror's exact `- **ID:** desc` shape when running).

```bash
git add docs/spec/heterodyne-comms.md docs/spec/heterodyne-workspace.md docs/spec/heterodyne-control.md docs/spec/heterodyne-social.md docs/spec/registry/security-invariants.json docs/security/threat-model.md
git commit -m "spec: make the authorization-freshness window a declared bound with a hard ceiling"
```

---

### Task 6: Assurance enrollment contest window, pending state, scoped tiebreak

**Files:**
- Modify: `docs/spec/heterodyne-assurance.md` (§3 enrollment, §8 TOFU pinning, the duplicity rules near "Competing individually valid successors", §12 evaluation states)
- Create: `docs/spec/schemas/assurance/enrollment-contest-v1.schema.json`
- Modify: `docs/spec/registry/kinds.json` (kind `31005`), `docs/spec/registry/reason-codes.json` (2 codes), `docs/spec/registry/security-invariants.json` (`ASSURANCE-I-ENROLLMENT-WINDOWED`), `docs/spec/registry/objects.json` if enrollment-contest is a registered object (match how other assurance events are registered — check whether 31000/31002 have objects.json entries and mirror that)
- Modify: `docs/security/threat-model.md` (mirror line; Identity substitution section note)

**Interfaces:**
- Consumes: `T_ots` and `core.ots-anchor.v1` from Task 3.
- Produces: kind `31005` enrollment contest; evaluation state `pending`; reason codes `assurance-enrollment-pending-window`, `assurance-enrollment-contested`; window constant W = 604,800 s; anchors `assurance-enrollment-window`, `assurance-enrollment-tiebreak`.

- [ ] **Step 1: Add the window to §8 (TOFU pinning)**

Insert before the existing pin rules:

```markdown
<a id="assurance-enrollment-window"></a>
A reciprocal enrollment is pin-eligible only after it has been observably
public and conflict-free for 604,800 seconds. Either satisfies the window: the
verifier's own conflict-free observation for that duration, or conflict-free
witness receipts spanning at least that duration and satisfying the
enrollment's configured witness thresholds. The window is observation-based;
`created_at` values MUST NOT satisfy it. A verifier evaluating an enrollment
whose window has not elapsed returns `pending` with reason
`assurance-enrollment-pending-window`; `pending` contributes no enhanced
claim.

A client holding a persona's active key MUST alarm when it observes any
enrollment for that key that it did not initiate, and MAY publish a kind
`31005` enrollment contest signed by the same active key. A contest or a
competing enrollment observed during any verifier's window makes the
enrollment non-pin-eligible wherever observed, with reason
`assurance-enrollment-contested`; the persona remains baseline. A key thief
can therefore deny Assurance but cannot gain recovery authority over the
owner: denial is bounded harm, because a bare-key holder can already
impersonate at baseline.
```

- [ ] **Step 2: Add the scoped tiebreak to the duplicity rules**

After the existing "Competing individually valid successors … stall" rules, add:

```markdown
<a id="assurance-enrollment-tiebreak"></a>
A conflict between two individually valid enrollments E1 and E2 for one active
key resolves to E1 instead of stalling only when both hold: E1 carries a
matured OpenTimestamps attestation under `core.ots-anchor.v1` proving it
existed at least 604,800 seconds before E2's earliest provable existence —
E2's own attestation time if anchored, otherwise E2's earliest witnessed
observation — and E1 carries conflict-free witness receipts covering that same
period. Existence evidence without the observation trail MUST NOT resolve a
conflict: a withheld enrollment has no receipts, so a secretly anchored
enrollment published later cannot displace an established one. Conflicts
meeting neither condition stall exactly as above. Arrival order, relay count,
and `created_at` still select nothing.
```

- [ ] **Step 3: Add `pending` to §12 evaluation states**

The state list "verified, unassured, predated, unavailable, stalled, downgraded, invalid" gains `pending` with the definition: "`pending` reports a validated enrollment whose observation window has not yet elapsed; it contributes no enhanced claim and preserves the Core verdict."

- [ ] **Step 4: Contest event schema**

Create `docs/spec/schemas/assurance/enrollment-contest-v1.schema.json`, copying the structural conventions of `docs/spec/schemas/assurance/enrollment-inception-v1.schema.json` (read it first; reuse its `$schema`, spec_version const pattern — now `heterodyne/0.6.0` — and tag-array style). Semantics to encode: kind `31005`; parameterized replaceable with `d` = the contested inception event ID; `p` = the contested cold root; outer `pubkey` = the active key being enrolled; a `heterodyne` discriminator tag `"enrollment_contest"`; content empty or a human-readable reason.

- [ ] **Step 5: Registry entries + mirrors**

`kinds.json`:

```json
{
  "kind": 31005,
  "allocation_authority": "heterodyne",
  "base_schema_owner": "assurance",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "profiles": [
    {
      "profile_id": "heterodyne-assurance-enrollment-contest-profile-v1",
      "owner": "assurance",
      "discriminator": "enrollment_contest",
      "stamping": false,
      "first_version": "heterodyne/0.6.0",
      "status": "draft"
    }
  ]
}
```

(Verify `allocation_authority`/`base_schema_owner` vocabulary against the existing 31000/31002 entries and match them exactly.)

`reason-codes.json` — two entries:

```json
{
  "code": "assurance-enrollment-pending-window",
  "owner": "assurance",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Reciprocal enrollment is valid but its 604800 second conflict-free observation window has not elapsed, so it is not pin-eligible.",
  "spec_refs": ["heterodyne:0.6.0#assurance-enrollment-window"]
},
{
  "code": "assurance-enrollment-contested",
  "owner": "assurance",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "A same-key contest or competing enrollment was observed during the observation window; the enrollment is not pin-eligible and the persona remains baseline.",
  "spec_refs": ["heterodyne:0.6.0#assurance-enrollment-window"]
}
```

`security-invariants.json`:

```json
{
  "id": "ASSURANCE-I-ENROLLMENT-WINDOWED",
  "owner": "assurance",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "No enrollment is pin-eligible before 604800 seconds of observably public, conflict-free existence; contests and competing enrollments fail closed to baseline, and a conflict resolves only to an enrollment with both materially earlier proven existence and witness receipts spanning the gap."
}
```

Threat-model: mirror line byte-for-byte; in the Identity substitution and downgrade section add one sentence: "Pre-enrollment key theft can no longer silently attach an attacker cold root: enrollment requires a seven-day observably public, conflict-free window, and contested enrollments fail closed to baseline."

- [ ] **Step 6: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS (orphan-schemas gate: the new schema must be referenced from the assurance doc — cite `schemas/assurance/enrollment-contest-v1.schema.json` in the §8 text the way §3 cites the inception schema; add that citation if the gate flags it).

```bash
git add docs/spec/heterodyne-assurance.md docs/spec/schemas/assurance/enrollment-contest-v1.schema.json docs/spec/registry docs/security/threat-model.md
git commit -m "spec: add enrollment contest window with scoped OTS tiebreak"
```

---

### Task 7: Workspace governance requires Assurance; reset-class restriction; SHOULD tier

**Files:**
- Modify: `docs/spec/heterodyne-workspace.md` (§2 sentence "A bare key with no Assurance state is complete baseline authority."; the freshness/authority-mutation section; migration note at the end of §2 or the document's compatibility section)
- Modify: `docs/spec/heterodyne-control.md` (§8.1 area: the `active-account` class paragraph gains the workspace exclusion)
- Modify: `docs/spec/heterodyne-comms.md` (claim-ledger SHOULD, one sentence near the private-ledger authority definitions in §9) and `docs/spec/heterodyne-core.md` (repository-owner SHOULD, one sentence in the repository-governance section)
- Modify: `docs/spec/registry/reason-codes.json` (`workspace-governance-assurance-required`), `docs/spec/registry/security-invariants.json` (`WORKSPACE-I-GOVERNANCE-ASSURED`)
- Modify: `docs/security/threat-model.md` (mirror line; Compromise section sentence)

**Interfaces:**
- Consumes: window semantics and `pending` state from Task 6 ("window-complete, `verified` enrollment").
- Produces: reason code `workspace-governance-assurance-required`; anchor `workspace-governance-assurance`.

- [ ] **Step 1: Replace the Workspace §2 bare-key sentence**

Replace `A bare key with no Assurance state is complete baseline authority.` with:

```markdown
<a id="workspace-governance-assurance"></a>
A workspace persona MUST have a window-complete, `verified` Assurance
enrollment under `heterodyne:0.6.0#assurance-enrollment-window`; workspace
inception binds the exact `inception_event_id` into the genesis policy object.
Every authority mutation — grants, invitations, policy changes, key issuance,
publicization, federation, governance, and archive — additionally requires the
workspace's Assurance evaluation to be `verified` at effect time, rejected
otherwise with `workspace-governance-assurance-required`. An Assurance
evaluation of `pending`, `stalled`, `unavailable`, or `downgraded` fails
closed for authority mutations only: ordinary code, content, and discussion
writes keep the 86,400-second window and continue. For a workspace persona the
`active-account` compromise-reset class is forbidden; `assurance-recovery` is
the only reset path.
```

Add a migration note in the document's compatibility/migration location: "Workspaces existing before heterodyne/0.6.0 have one release cycle to enroll; new workspaces require a window-complete enrollment at inception, which in practice means enrolling the cold root at least seven days before incorporation."

- [ ] **Step 2: Control §8.1 exclusion**

In the paragraph defining the `active-account` baseline class, append: "A workspace persona MUST NOT use the `active-account` class; `heterodyne:0.6.0#workspace-governance-assurance` requires `assurance-recovery` for workspaces."

- [ ] **Step 3: The SHOULD tier (two one-sentence edits)**

Core repository-governance section: "A persona holding repository-owner policy authority SHOULD attach a window-complete Assurance enrollment; a client MUST surface an unenrolled high-authority persona distinctly." Comms private-ledger section: the same sentence pattern for claim-ledger and OIDC-issuer authority personas.

- [ ] **Step 4: Registry + mirrors**

```json
{
  "code": "workspace-governance-assurance-required",
  "owner": "workspace",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Workspace authority mutation rejected because the workspace persona lacks a window-complete verified Assurance enrollment at effect time.",
  "spec_refs": ["heterodyne:0.6.0#workspace-governance-assurance"]
}
```

```json
{
  "id": "WORKSPACE-I-GOVERNANCE-ASSURED",
  "owner": "workspace",
  "status": "draft",
  "first_version": "heterodyne/0.6.0",
  "description": "Workspace authority mutations execute only under a window-complete verified Assurance enrollment bound at inception, compromise reset for a workspace uses only the assurance-recovery class, and ordinary writes continue under their own window when governance fails closed."
}
```

Threat-model: mirror byte-for-byte; Compromise section adds: "A workspace's hot key can no longer authorize its own succession; recovery authority rests with the cold root bound at inception."

- [ ] **Step 5: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS.

```bash
git add docs/spec/heterodyne-workspace.md docs/spec/heterodyne-control.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-core.md docs/spec/registry docs/security/threat-model.md
git commit -m "spec: require Assurance for workspace governance, recommend for other authorities"
```

---

### Task 8: SHA-1 per-binding analysis (Core §12) and coarsening flag (Core §13.2 + registry)

**Files:**
- Modify: `docs/spec/heterodyne-core.md` §12 (replace the sentence block "RID and Git object identifiers use SHA-1 in the applicable Radicle version, but Nostr event integrity independently uses SHA-256/BIP-340 and Radicle refs use Ed25519. A RID collision cannot authorize a forged event or writer ref.") and §13.2 (one added sentence)
- Modify: `docs/spec/heterodyne-workspace.md` (vocabulary preamble "Wire protocols MAY map them to local or upstream errors, but MUST preserve distinct outcomes where disclosure or retry behavior differs.")
- Modify: `docs/spec/registry/registry.schema.json` (allow optional boolean `intentionally_coarse` on reason-code entries), `docs/spec/registry/reason-codes.json` (set the flag on the one existing deliberately-coarse code — the enrollment-refusal code whose description says "indistinguishable to the requester")

**Interfaces:**
- Produces: registry field `intentionally_coarse`; anchor `core-sha1-bindings`.

- [ ] **Step 1: Replace the Core §12 SHA-1 block**

```markdown
<a id="core-sha1-bindings"></a>
SHA-1 appears in exactly three places, each analyzed individually rather than
dismissed wholesale. The genesis-manifest digest is already SHA-256 and is not
in this list.

| Value | Where | Classification | Analysis |
|---|---|---|---|
| RID (20-byte Git object ID) | `rad:z…` repository identifier | locator | a collision yields two repositories claiming one name; neither gains event authorship (SHA-256/BIP-340) or ref authority (Ed25519) |
| `repo_head` | kind `31010` seed advert, Ed25519-bound | possession snapshot | signature-bound but grants nothing; advert expiry of at most 86,400 seconds limits exposure |
| `repository_head` | every signed Workspace object | carrier context | signature-bound but explicitly non-authority; a head not reachable from the accepted authority branch is rejected |

For each signature-bound SHA-1 value the concrete attack requires both a
chosen-prefix collision against repository state the attacker can influence
and a consumer that treats the digest as more than a locator; the rules above
remove the second half. Two requirements follow. No Heterodyne document may
bind authority, policy, or key material to a SHA-1 digest; authority bindings
require SHA-256 or stronger. Implementations SHOULD prefer the Radicle
`sha256` object format where the substrate supports it; the credential-ledger
schemas already accept both formats.
```

- [ ] **Step 2: Coarsening flag**

In `registry.schema.json`, add to the reason-code entry properties: `"intentionally_coarse": { "type": "boolean" }` (keep `additionalProperties: false` satisfied by adding it to the allowed set). In `reason-codes.json`, find the code whose description contains "indistinguishable to the requester" and add `"intentionally_coarse": true`. In Core §13.2 append: "The registry marks such codes `intentionally_coarse`; a document MUST NOT allocate a finer code where a flagged code covers the refusal." In the Workspace vocabulary preamble, append: "…except where `heterodyne:0.6.0#core-conformance` reason-code granularity rules flag a code `intentionally_coarse`, which governs."

- [ ] **Step 3: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS (if a registry-schema gate validates entries strictly, the schema change in this task is what keeps it green — make the schema edit before the data edit).

```bash
git add docs/spec/heterodyne-core.md docs/spec/heterodyne-workspace.md docs/spec/registry
git commit -m "spec: per-binding SHA-1 analysis and intentionally-coarse reason-code flag"
```

---

### Task 9: OIDC non-goals, withholding/equivocation risk entry, stall-recovery note

**Files:**
- Modify: `docs/spec/heterodyne-comms.md` §12 (new short subsection after the issuer definition)
- Modify: `docs/security/threat-model.md` (Carrier authority confusion or Replay/races section — add the withholding entry where it reads most naturally; plus one sentence in Identity substitution referencing the tiebreak)

**Interfaces:**
- Consumes: declared bound from Task 5; tiebreak anchor from Task 6.

- [ ] **Step 1: OIDC non-goals subsection**

```markdown
### 12.1 Non-goals and trust limits

The issuer projection exists for private-network and workload agent
authentication and for ordinary third-party relying-party verification. It is
not censorship-resistant: the HTTPS host is an availability and correlation
chokepoint, accepted as such. Issuer metadata, NIP-05 records, and launcher
hosts never create identity authority; a client that treats them as more than
hints reintroduces a central authority and is non-conformant.
```

(Renumber nothing; if §12 already has subsections, use the next free number.)

- [ ] **Step 2: Threat-model withholding entry**

```markdown
Carriers can withhold revocations and other monotonic state. The defenses are
multiple independent carriers and the declared authorization-view bound, which
converts a withheld revocation from indefinite into bounded staleness at any
honest minting node. Residual exposure for pure-relay reading clients is
inherited from the Nostr carrier model and accepted. Equivocation-induced
Assurance stalls now have a specified recovery for properly enrolled personas:
the witnessed-anchor tiebreak in the Assurance enrollment rules.
```

- [ ] **Step 3: Verify and commit**

Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test`
Expected: PASS.

```bash
git add docs/spec/heterodyne-comms.md docs/security/threat-model.md
git commit -m "docs: OIDC non-goals and carrier-withholding accepted-risk entries"
```

---

### Task 10: ADR-048, registry manifest revision, family index, final sweep

**Files:**
- Create: `docs/adr/archive/2026-08-26-048-security-review-remediation.md`
- Modify: `docs/spec/registry/manifest.json` (revision 15, recomputed `entry_set_sha256`)
- Modify: `docs/spec/heterodyne.md` (version prose "All six documents carry `heterodyne/0.6.0`" — already cut over in Task 1; verify the vector-snapshot caveat paragraph still reads correctly and add one sentence: "The frozen vector snapshot predates 0.6.0 and is regenerated in a follow-up change.")
- Modify: `docs/adr/archive/2026-07-01-028-privacy-tiers-repo-visibility-encrypted-blobs.md` (append one line to its supersession note: "Tier definitions superseded by ADR-048 (2026-08-26).")

**Interfaces:**
- Consumes: everything; the ADR records all decisions by their task anchors.

- [ ] **Step 1: Write ADR-048**

Follow the ADR-047 template exactly (`# ADR-048: …`, `**Status:** Accepted`, `**Date:** 2026-08-26`, the standard non-canonicality disclaimer paragraph, `## Decision`). Body: one paragraph per remediation summarizing the normative anchors added (`core-created-at-bound`, `core-ots-anchor`, `comms-tier3-confinement`, `assurance-enrollment-window`, `assurance-enrollment-tiebreak`, `workspace-governance-assurance`, `core-sha1-bindings`, the declared `authorization_view_max_age`), one paragraph on accepted risks (compromise-time cutoff selection, carrier withholding for relay-only readers, Tier 3 forward secrecy absent, enrollment denial bounded), and one paragraph stating vectors are deliberately untouched and the current vector lane remains 0.5.0-pinned until the follow-up regeneration. Note supersession: "Supersedes the tier definitions of ADR-028 as amended by ADR-037."

- [ ] **Step 2: Recompute the registry digest**

Read `computeRegistryDigest`/`loadRegistry` in `docs/spec/vectors/generator/src/docs-lint.ts` and `registry.ts` (read-only) to get the exact algorithm (which files, ordering, canonicalization). Replicate it in a scratchpad script (NOT in the repo), run it against `docs/spec/registry/`, and write the resulting hex into `manifest.json` `entry_set_sha256`; bump `"revision"` to `15`. Sanity check: the script run against the pre-change git state (`git stash` or `git show`) must reproduce the old digest `be4074dca2ce1a1cbd6cff7d7c5c7dfff460fff6c09395ba3f2434b0be14655f` — if it does not, the replication is wrong; fix the script, never the vectors tree.

- [ ] **Step 3: Full-repo consistency sweep**

Run: `grep -rn "heterodyne[:/]0\.5\.0" --exclude-dir=vectors docs CHANGELOG.md | grep -v "docs/adr/archive" | grep -v "docs/superpowers" | wc -l` → expected `0`.
Run: `grep -rn "Tier 2" docs/spec/heterodyne-comms.md | grep -i plaintext` → expected: no line describing Tier 2 as plaintext.
Run: `npm --prefix docs/spec/conformance run build && npm --prefix docs/spec/conformance test` → expected PASS.
Run: `npm --prefix docs/spec/vectors/generator run draft:check 2>&1 | tail -3 || true` → expected FAIL only on version-pin/vector-coupled checks; if it fails on anything else (e.g., a malformed table or broken anchor in the new text), fix the spec text.

- [ ] **Step 4: Commit**

```bash
git add docs/adr docs/spec/registry/manifest.json docs/spec/heterodyne.md
git commit -m "docs: ADR-048 security review remediation; registry revision 15"
```

---

### Task 11: Push branch and open PR

- [ ] **Step 1:** `git push -u origin feat/security-review-remediation-0.6.0`
- [ ] **Step 2:** `gh pr create` — title "spec: heterodyne/0.6.0 security review remediation"; body summarizes the eight remediations with anchors, links the design spec and ADR-048, and states explicitly: conformance vitest suite green; vector lane (`draft:check`) expectedly red pending the separate vectors regeneration step; `docs/spec/vectors` untouched.
- [ ] **Step 3:** Report the PR URL.

---

## Self-Review Notes

- Spec coverage: design §2→Tasks 2-3; §3→Task 4; §4→Task 7; §5→Task 6; §6→Task 8; §7→Task 5; §8→Tasks 8-9; §9 (version, ADR, reason codes, migration)→Tasks 1, 10; §10 accepted risks→Tasks 9, 10 (ADR); §11 vectors/conformance→explicitly deferred per constraint, recorded in ADR and CHANGELOG.
- The design's `intentionally_coarse` flag, `authorization_view_max_age` member, and all four new invariants have owning tasks. New reason codes: `core-created-at-premature` (T2), `core-created-at-refuted` (T3), `assurance-enrollment-pending-window` + `assurance-enrollment-contested` (T6), `workspace-governance-assurance-required` (T7) — matches design §9 plus the two Assurance codes named in design §5.4.
- Names used across tasks are identical strings; anchors are defined in the task that owns them and only consumed afterward.
