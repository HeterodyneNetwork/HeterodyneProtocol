# Conformance Harness Independence Design

**Date:** 2026-08-15
**Status:** Approved for implementation planning
**Protocol owners:** Core (registry and reason codes only)
**Registry target:** revision 9
**Decision record:** ADR-045

## Goal

Give the specification family an executable conformance harness that is
independent of the vector generator, that fails closed on the classes of drift
a 2026-08-14 manual review found, and that runs as an acceptance gate on every
inbound patch.

This is track 4 of a four-track remediation. It ships first because it
converts the remaining findings from prose into enforced, counted debt. Tracks
1 through 3 then burn that debt down against a harness that cannot silently
lose ground.

## Motivation

Both existing verification commands pass on the current tree. Neither detects
any of the following, all confirmed by hand:

- three vectors expect reason codes absent from the registry and from every
  specification document;
- three vectors cite specification anchors that no longer exist;
- `vectors/fixtures.json` declares `registry_revision: 1`, omits `workspace`
  from `document_versions`, and still carries `matrix_rooms` from the retired
  room architecture;
- twelve registered security invariants belong to no strict profile, including
  the two Control invariants that keep automated principals away from persona
  keys;
- 83 of 184 normative anchors have no vector, while Core §14 asserts the
  minimum set covers version negotiation and every Core invariant;
- 94 of the 99 vector files that embed signed events omit the sibling
  `nip01_raw` that Core §3.1 makes mandatory.

The decisive evidence is historical. The ADR-037 design of 2026-07-31 already
recorded "Verifier independence: regeneration compares the generator with
itself" and "Stale Matrix artifacts: remove them from the current corpus." The
first was resolved as an either/or that produced the `evidence_classification`
escape hatch now used by seven KERI vectors. The second was applied to the
vector corpus but never to `fixtures.json`, which still carries `matrix_rooms`
after seven subsequent decision cycles, ADR-038 through ADR-044, none of which
noticed. An accepted remediation eroded because nothing was watching. Fixes
without gates do not hold.

A second motivation is forward-looking. The intended end state is a reference
client plus forkable Radicle repositories that third parties use to
demonstrate interoperability. That requires a runner which consumes only
published artifacts and accepts a pluggable subject under test. Building it now
means the gates and the future interoperability kit are the same program.

## Scope

In scope: a new independent conformance package, its gate suite, the ratchet
mechanism, registry revision 9 for four reason codes, the minimal Core prose
edits that revision requires, the data corrections needed to keep day-one
baselines small, and the patch-time CI gate on both intake paths.

Out of scope and deferred, with the track that owns each:

| Deferred finding | Track |
|---|---|
| Registry-revision drift in Core §3 and §12.1; duplicate §6.1.3; three semantic cross-references; `workspace` missing from Core's version grammar; "five feature IDs"; strict-fixture shape inconsistency | 1 |
| kind:10000 double allocation; twelve orphan invariants; Comms/Control token-status contradiction; the undefined "Comms deletion points" obligation; Social npub-versus-hex `p` tags; reason-code naming convention | 2 |
| Device sign/ECDH key separation; Tier 3 opaque `d` derivation; Workspace `actor`/`kel_head` ambiguity; SHA-256 authority digest alongside SHA-1 `repository_head` | 3 |

Track 4 detects and counts all of these. It fixes only what it must to keep
its own baselines honest.

## Architecture

A new package at `docs/spec/conformance/` with its own `package.json` and no
import path to `docs/spec/vectors/generator/`. Two layers.

### Corpus gates

Pure static analysis over repository artifacts: vectors, registry, schemas,
release manifests, and specification markdown. No subject, no cryptography, no
network. Each gate is a module exporting a single function from artifact paths
to a sorted array of stable failure keys.

### Runner

Executes vectors against a subject:

```ts
type Verdict = { verdict: string; reason_code?: string };

interface Subject {
  readonly name: string;
  consume(vector: Vector): Promise<Verdict>;
  produce(vector: Vector): Promise<{ bytes: Uint8Array } | { refused: Verdict }>;
}
```

One implementation ships now: `ReferenceCheckerSubject`, a spec-derived
implementation of Core §9's ordered pipeline — canonical NIP-01 serialization,
SHA-256 identifier, BIP-340 verification, `nip01_raw` binding, version-stamp and
`kel_head` classes, epoch authority — written from the prose and importing only
`@noble/*` and `ajv`. Later subjects, `ReferenceClientSubject` and
`RadicleRepoSubject`, implement the same interface without changing vectors or
gates.

Independence is structural rather than asserted. The generator authors bytes,
the conformance package validates them from a separate reading, and agreement
across the whole corpus is the differential Core §4.4 requires. A test resolves
every import under `conformance/` and fails if any path reaches the generator.

### Existing lint relocation

`docs-lint.ts` is 903 lines and already contains registry and profile lints
that belong in the gate layer. `findInvariantEvidenceIssues`,
`findStrictProfileClosureIssues`, and the release-manifest pin validators move
to `conformance/`, bringing the file under the 500-line limit and consolidating
conformance checks in one place.

## Gate catalogue

Structural gates over repository artifacts:

| Gate | Rule | Day-one baseline |
|---|---|---|
| G1 anchor-resolution | every vector `spec_ref` resolves to a real `<a id>` in that document at that version | 3 |
| G2 reason-code closure | every `expected_output.reason_code` is registered, unconditionally | 0 after this track |
| G3 invariant completeness | every registered invariant appears in at least one strict profile | 12 |
| G4 anchor coverage | every normative anchor has at least one vector | 83 |
| G5 fixtures consistency | `registry_revision` matches `manifest.json`; `document_versions` matches `family.ts`; no key outside a declared allowlist | 0 after this track |
| G6 dead vocabulary | registered reason codes exercised by no vector | 54 |
| G7 orphan schemas | every schema file bound by specification prose or a vector | 36 |

Cryptographic gates through `ReferenceCheckerSubject`:

| Gate | Rule | Day-one baseline |
|---|---|---|
| G8 identifier integrity | recomputed SHA-256 of the canonical serialization equals the declared `id` | 0 |
| G9 signature | BIP-340 verifies over that identifier | 0 |
| G10 `nip01_raw` | present, byte-equal to re-serialization, every parsed field matching | 94 |
| G11 negative-vector hygiene | a vector expecting failure at step *N* of Core §9 passes steps 1 through *N*-1 | 2 |

G6's baseline is 54 rather than the 53 currently unexercised codes, because
`nip01_raw_mismatch` is allocated by this track but has no vector until track 1
or 2 adds one. The three breadcrumb codes are exercised the moment they are
registered and so never enter the baseline.

G8 and G9 evaluate "fails exactly where expected," not "fails." An independent
check of the current corpus confirms 341 of 343 embedded event identifiers and
340 of 343 signatures verify, with every exception an intentional negative
case, so these two gates start clean.

G11 generalises a real defect. `vectors/repo-relay/002-invalid-signature-rejected.json`
and `vectors/verification/001-bad-signature-rejects.json` both zero the event
`id` and corrupt the signature, so a conforming verifier rejects at identifier
mismatch and never reaches BIP-340, while each vector's own `decision_trace`
claims both steps run. `vectors/node-advert/002-outer-sig-invalid-rejected.json`
is the correct pattern: valid identifier, corrupted signature only.

### Root cause to fix in G2

`schema.ts` lines 83 to 110 already constrain `reason_code` to the registry
enum, but the enclosing `if` requires `direction === "consume"`. The corpus
contains exactly three `direction: "produce"` reject vectors, and those three
carry the unregistered codes. G2 removes the `direction` condition so the
constraint applies to every rejecting vector regardless of direction.

## Ratchet mechanism

One baseline per gate at `conformance/baselines/<gate-id>.json`, a sorted array
of stable failure keys. Keys never reference line numbers or array indices, so
unrelated edits do not churn them:

| Gate | Key form |
|---|---|
| G1 | `<vector_id> :: <spec_ref>` |
| G2 | `<vector_id> :: <reason_code>` |
| G3 | `<invariant_id>` |
| G4 | `heterodyne:<document>/<version>#<anchor>` |
| G5 | `<json pointer>` |
| G6 | `<reason_code>` |
| G7 | `<repository-relative schema path>` |
| G10 | `<vector file> :: <json pointer to event>` |
| G11 | `<vector_id>` |

Two assertions per gate, both failing the build:

1. **No new failures.** Actual failures must be a subset of the baseline. New
   entries are reported individually.
2. **No stale entries.** A baseline entry that no longer fails is reported for
   deletion. Baselines shrink only, so the debt count stays honest and progress
   cannot be masked by an unrelated regression.

`npm run conformance:baseline` regenerates baselines canonically sorted, so
diffs are reviewable and the burn-down is legible in history. Two generated
projections are byte-compared in the build exactly as `coverage/*.md` are
today: `conformance/report.json`, which later becomes the report a third party
submits, and `conformance/DEBT.md`, a human-readable table of outstanding debt
per gate.

## Registry revision 9

Four Core-owned reason codes, snake_case to match Core's existing convention:

| Code | Purpose |
|---|---|
| `nip01_raw_mismatch` | Core §3.1 makes a `nip01_raw` absence or mismatch a mandatory rejection, and Core §9 requires a closed registry code. None exists. |
| `successor_persona_mismatch` | breadcrumb pair naming a successor outside the accepted rotation, Core §4.3.1 |
| `retiring_key_nip05_invalid` | retiring profile carrying a NIP-05 identifier already repointed to the successor, Core §4.3.1 |
| `compromise_rotation_breadcrumb_forbidden` | compromise-driven rotation must produce no v1 breadcrumb, Core §4.3.1 |

The last is renamed from the bare `compromise_rotation` used by
`vectors/breadcrumbs/002`, which reads as a state rather than a rejection
reason. Core §14 permits changing an unreleased vector in place during 0.x.

### Coupled specification edits

AGENTS.md requires complete specification integration in the same patch, so
the bump carries prose. All edits are in Core:

- §3.1 names `nip01_raw_mismatch` as the rejection code.
- §4.3.1 names the three breadcrumb codes in the sentence already enumerating
  those refusal conditions.
- The registry revision becomes `9` at the document header, §3, the §12.1
  capability example, and §14. This pulls track 1's registry-drift finding
  forward, because those four sites currently read `8`, `6`, `7`, and `8`, and
  bumping one while leaving the others would worsen the contradiction.

### Mechanical sweep

`registry/history/9.json`; `registry/manifest.json` revision and recomputed
`entry_set_sha256`; the registry-revision header of all five documents; all
five release manifests; the `registry_revision` field of every vector;
`vectors/fixtures.json`; and the coverage manifest. G5 and the vector-metadata
gate police this sweep from then on.

## Data corrections

`fixtures.ts`, which produces `fixtures.json`: set `registry_revision` to 9,
add `workspace: "0.1.0"` to `document_versions`, and delete `matrix_rooms`.
Within `category_keysets`, delete only provably dead entries — `config_room`
appears retired, `discussion` is likely still consumed by `vectors/discussion/*`
— confirming each by reference search before removal. G5's allowlist enforces
the boundary afterward.

The three dangling anchors are decided per vector, repointing where the
behaviour still exists and retiring where the vector only tested the deleted
room architecture. Expected outcome: `discussion/reaction-reply-bare-not-indexed`
repoints to `social-interactions`; `versioning/unknown-room-kind-tolerance`
repoints to `core-versioning`; `identity/identity-room-full-state` retires.

## Patch acceptance gate

### How Radicle CI works

A broker subscribes to node events and dispatches an adapter that performs the
run. Broker configuration is node-side YAML — `default_adapter`, `db`,
`report_dir`, `adapters`, and filters such as `!Repository`, `!Branch`,
`!AnyPatchRef`, `!And`, `!Or` — and is not part of the repository. The only
repository-side artifact is `.radicle/native.yaml`.

### Adapter choice

The native adapter runs without isolation; its own documentation warns against
using it for code that is not trusted. That is disqualifying here, because the
purpose is acceptance-testing patches from unknown contributors. `node_modules`
is gitignored, so any job must run `npm ci`, and this toolchain installs
`esbuild`, `rolldown`, `lightningcss`, and `fsevents`, all with install-time
native-binary steps. A hostile patch editing `package.json` would obtain code
execution on a delegate's seed node.

The podman-container adapter is therefore the target. It provides per-run
container isolation and reads `.radicle/native.yaml` for compatibility, so the
repository file remains valid if an operator later moves to Ambient CI.

### One definition, two intake paths

The job body lives in `scripts/conformance-ci.sh`: pinned `npm ci` from the
committed lockfiles, then `family:check`, the generator `check`, and the
conformance `check` including ratchet assertions. Both entry points invoke that
script and nothing else.

```yaml
# .radicle/native.yaml
shell: |
  scripts/conformance-ci.sh
```

A GitHub Actions workflow invokes the same script. The repository is
dual-homed and recent merges arrived as GitHub pull requests, so gating only
the Radicle path would leave the more-used path open. GitHub additionally
offers enforceable required checks, which Radicle cannot provide.

### Limitation to record

Radicle has no server-side required checks. The broker posts a run result to
the patch and delegates decide whether to merge, and CI runs only on nodes
whose operators configured a broker. Enforcement is therefore delegate policy,
so AGENTS.md gains an explicit rule: no patch merges without a green
conformance run on a delegate-operated node.

## Testing strategy

Each gate is built test-first. Before a gate is written against real data it
gets a synthetic fixture that must trip it: a vector citing a nonexistent
anchor, one carrying an unregistered code, one omitting `nip01_raw`, one whose
declared failure step is later than its actual failure step. Only once that
test fails for the right reason is the gate implemented.

Beyond per-gate unit tests:

- a full-corpus integration run producing `report.json` and `DEBT.md`;
- ratchet tests covering both directions, a newly introduced failure and a
  baseline entry that has been fixed;
- the import-boundary test forbidding any resolution from `conformance/` into
  the generator;
- a differential test asserting `ReferenceCheckerSubject` agrees with every
  committed expectation across the corpus.

## Deliverables

| Path | Contents |
|---|---|
| `docs/adr/2026-08-15-045-conformance-harness-independence.md` | decision record, archived before merge |
| `docs/spec/conformance/` | package, gates, runner, subjects, baselines, tests |
| `docs/spec/conformance/DEBT.md`, `report.json` | generated projections |
| `scripts/conformance-ci.sh` | single gate definition |
| `.radicle/native.yaml` | Radicle entry point |
| `.github/workflows/conformance.yml` | GitHub entry point |
| `docs/spec/registry/` | revision 9, four new reason codes, history snapshot |
| `docs/spec/heterodyne-core.md` | §3.1, §4.3.1, and four revision sites |
| `AGENTS.md` | third verification command, delegate merge rule |

## Non-goals

This track does not add vectors for the 83 uncovered anchors, add `nip01_raw`
to the 94 affected vector files, resolve the twelve orphan invariants, or
change any wire format. It records each as counted debt and leaves the work to
the tracks that own it.

It does not build the reference client or the forkable Radicle conformance
repositories. It establishes the `Subject` boundary those will implement.

It does not introduce a second deliberately divergent checker. The
authoring-versus-checking split already provides the differential property.
