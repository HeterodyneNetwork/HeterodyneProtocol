# Heterodyne 0.6 PR 28 Closure Design

**Status:** Approved design

**Date:** 2026-08-27

**Scope:** Repair GitHub PR #28 in place so that `heterodyne/0.6.0` is a
complete, internally coherent, reproducible protocol release rather than an
accepted specification with deferred normative artifacts.

## 1. Purpose

PR #28 contains useful security analysis and privacy-tier changes, but it is
not mergeable in its current form. Its specifications identify themselves as
`heterodyne/0.6.0` while the current semantic generator and committed vectors
remain at 0.5, required CI is red, and several newly introduced rules
contradict the Nostr-first identity model or their own schemas.

This design preserves the useful parts of the pull request and closes the
release as one atomic change. It does not split a normative design from its
implementation, merge a knowingly red release, or discard the existing work
and restart from main.

## 2. Release and authority boundaries

ADR-048 returns to `Status: Proposed` while the repair is in progress. The
live specification family, registry, schemas, semantic evaluators, strict
profiles, and conformance vectors are the protocol authority; ADR-048 records
the decision but cannot supply a missing requirement.

The branch may use focused intermediate tests while work is in progress, but
it MUST NOT claim an accepted 0.6 release until all normative artifacts agree
and all required gates pass. At final integration:

1. every family dependency is valid;
2. every new baseline rule has prose, machine artifacts, executable semantics,
   and conformance coverage;
3. current generators and release metadata identify 0.6 consistently;
4. one latest-only 0.6 vector snapshot is tied to the exact final authoring
   source commit and reproduces byte-for-byte; and
5. ADR-048 is accepted and archived only after the complete matrix is green.

No live normative document or machine artifact may depend on ADR text.

## 3. Nostr-first identity and optional Assurance

The active Nostr key remains the baseline network identity. Core, Comms,
Control, Social, and Workspace MUST accept a bare active key as a first-class
identity. Assurance adds optional governance, recovery, and succession; it is
not a prerequisite for baseline participation.

### 3.1 Family dependency direction

Workspace has no mandatory dependency on Assurance. Control defines generic
authorization, signing, enrollment, and recovery contracts without referring
to Workspace. Workspace MAY compose and specialize those Control contracts
for organization roles, resources, and governance. This preserves the family
dependency direction instead of introducing Control-to-Workspace or mandatory
Workspace-to-Assurance edges.

### 3.2 Workspace Assurance profile

A Workspace policy MAY omit Assurance entirely. Such a Workspace can be
created and operated with its active Nostr persona key.

A Workspace MAY later activate a closed optional object named `assurance`:

```json
{
  "profile": "heterodyne.workspace.assurance.v1",
  "inception_event_id": "<64 lowercase hex>",
  "required_state": "verified"
}
```

Activation requires both an ordinary valid Workspace governance transition
and a window-complete `verified` Assurance enrollment for the Workspace's
current active persona key. When present, the profile gates the
security-sensitive Workspace authority mutations enumerated by the Workspace
specification. Baseline publication and identity recognition remain Nostr
compatible.

Once activated, ordinary active-key governance alone cannot weaken or remove
the profile. Removal requires:

1. the normal current Workspace governance authorization; and
2. authorization by the current Assurance authority over the same canonical
   policy-transition digest.

Compromise recovery continues through Assurance succession and revocation
rather than through a Workspace downgrade.

## 4. Enrollment eligibility and contest finality

Initial reciprocal Assurance enrollment has three relevant states:

- `pending`: its eligibility window has not completed;
- `verified`: the window completed with qualifying observation evidence and no
  timely conflict; and
- `contested`: a qualifying contest or competing enrollment was observed
  during the window, so that attempted enrollment can never become verified.

The eligibility window is `W = 604800` seconds. It is based on durable
observation, never the event's author-controlled `created_at`. A verifier MAY
establish the window through its own durable conflict-free observation or
through witness receipts spanning at least `W` and satisfying the enrollment's
configured witness threshold.

### 4.1 Contest event

Kind `31006` is an absorbing active-key alarm with this exact outer contract:

- `pubkey`: the active persona key whose enrollment is contested;
- `kind`: `31006`;
- one exact `d` tag whose value is the contested inception event ID;
- one exact `p` tag whose value is the proposed cold-root key; and
- no generic Heterodyne stamping tags.

Its closed JSON content is:

```json
{
  "profile": "heterodyne.assurance.enrollment-contest.v1",
  "spec_version": "heterodyne/0.6.0",
  "inception_event_id": "<same value as d>",
  "cold_root": "<same value as p>"
}
```

The registry discriminator is
`content.profile=heterodyne.assurance.enrollment-contest.v1` and stamping is
disabled. A valid later event at the same address remains a contest; there is
no withdrawal form.

A contest affects only Assurance eligibility. It never disables the active
Nostr identity or its baseline events.

### 4.2 Conflict and finality rules

A valid contest or competing initial enrollment durably observed during the
candidate's eligibility window permanently stalls that candidate. No
timestamp-based rule chooses a winner between conflicting initial enrollments.

Once an enrollment has validly completed its conflict-free window and been
pinned, a later contest or competing initial enrollment cannot retroactively
unpin it. Late evidence remains visible as an alarm and audit record. An
established enrollment changes only through the existing Assurance succession
or revocation mechanisms.

## 5. Timestamp evidence

NIP-03/OpenTimestamps evidence is optional and advisory in 0.6. It establishes
only that the unsigned NIP-01 event commitment existed no later than a
confirmed Bitcoin block.

It MUST NOT establish or decide:

- when the event was signed;
- when it was published or observed by a relay;
- whether its `created_at` value is truthful;
- whether an undiscovered competing event exists;
- an enrollment winner;
- permanent event invalidity; or
- a precise wall-clock time derived from a Bitcoin block header.

The proposed enrollment OTS tiebreak and the permanent
`created_at > T_ots + 900` rejection are removed. Version 0.6 introduces no
Heterodyne-specific timestamp authority profile. A future proposal may define
one only after separately specifying signature binding, confirmation depth,
reorganization handling, conservative clock bounds, withholding, and the
known NIP-03 weakness.

## 6. Authorization freshness

The signed continuity manifest carries two separate limits:

- `max_checkpoint_age_seconds`: the maximum age of checkpoint or continuity
  evidence, retaining its 300-second ceiling; and
- `authorization_view_max_age`: the maximum age of authorization state used
  for an operation, defaulting to 300 seconds and accepting closed integer
  values from 1 through 86400.

Both fields are members of the closed schema and the manifest's canonical
signed bytes. An evaluator uses a trusted local clock and enforces every
applicable limit independently. Passing one limit never compensates for
failing another.

Authorization-consuming operations re-resolve and revalidate the current view
immediately before effect or durable commit. A caller cannot supply evaluation
time, freshness success, or an already-validated boolean. Historical 0.5
manifest behavior remains available through Git history and does not constrain
the current 0.6 schema.

## 7. Normative artifact closure

Every 0.6 rule follows one traceable chain:

```text
specification anchor
  -> registry invariant, reason, kind, or profile
  -> closed schema where applicable
  -> current semantic evaluator
  -> positive and negative tests
  -> strict-profile vectors
```

The following rules are mandatory:

1. Existing registry entries retain their historical `first_version`.
   `0.6.0` is used only for genuinely new entries.
2. Every new baseline invariant appears in the corresponding strict profile.
3. Every new rejection reason is produced by an evaluator and exercised by a
   negative conformance case.
4. Contest kind metadata, schema, prose, evaluator, and vectors use the same
   JSON-content discriminator and exact tags.
5. Workspace policy and OIDC continuity schemas exactly match their normative
   prose and reject undeclared members.
6. Current generators, semantic tests, release metadata, and specifications
   advance to 0.6 together.

Malformed, stale, conflicting, or unverifiable inputs fail closed with a
registered reason. Defensive negative tests use local synthetic fixtures in
the authorized repository environment; they do not contact live relays or
produce deployable attack tooling.

## 8. Vector transition

The existing 0.5 snapshot remains unchanged while current semantics are still
moving. After the 0.6 source and semantic matrix is stable, the authoring flow
replaces it with one latest-only 0.6 snapshot tied to the exact final source
commit.

The repository does not retain parallel committed 0.5 and 0.6 snapshot trees
before 1.0. Git history preserves the 0.5 corpus. The replacement snapshot
must reproduce byte-for-byte and pass package/conformance checks from its
pinned source.

## 9. Workstreams and review boundaries

The repair is executed as independently reviewable workstreams that converge
into one atomic PR:

1. reopen ADR-048 and restore an honest proposed-release lifecycle;
2. repair family dependencies and optional Workspace Assurance;
3. complete enrollment contest semantics and make timestamp evidence
   advisory-only;
4. align continuity freshness across prose, schemas, evaluators, and tests;
5. close registry invariants, strict profiles, reasons, and version history;
6. advance current semantics to 0.6 and author the replacement vector snapshot;
7. perform an independent holistic security and specification review; and
8. accept ADR-048 only after all required gates are green.

Each workstream receives focused test-driven implementation and a review
checkpoint. A workstream may be rejected independently, but PR #28 is not
mergeable until all workstreams are complete.

## 10. Acceptance criteria

Final acceptance requires all of the following on the exact candidate commit:

- `npm --prefix docs/spec/vectors/generator run family:check`;
- `npm --prefix docs/spec/vectors/generator run check`;
- exact 0.6 snapshot reproduction and package verification;
- conformance build and complete conformance tests;
- the shared CI script;
- `git diff --check` and a clean worktree;
- a protected-artifact audit showing only the intentional 0.6 snapshot
  replacement;
- an independent holistic review with no unresolved Critical or Important
  findings; and
- green required GitHub checks.

Only after this evidence exists may ADR-048 become Accepted and move to the
archive in the final lifecycle commit.

## 11. Rejected approaches

### Split design and implementation across mergeable PRs

Rejected because it would either merge a normative 0.6 specification without
its required artifacts or leave the active protocol in an intentionally
inconsistent state.

### Close PR #28 and rebuild from main

Rejected because the pull request contains useful analysis and improvements
that can be repaired more safely than recreated.

### Keep mandatory Workspace Assurance

Rejected because it contradicts the active-key-first Nostr interoperability
model and turns optional cold-root/KERI protection into a baseline identity
requirement.

### Use NIP-03 as protocol authority

Rejected because its proof does not bind the Nostr signature, publication,
completeness, or precise wall-clock time and therefore cannot safely decide
enrollment or permanent invalidity.
