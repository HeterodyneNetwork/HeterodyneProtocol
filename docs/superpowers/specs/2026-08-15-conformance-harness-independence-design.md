# Conformance Harness Independence and CI Design

**Date:** 2026-08-15<br>
**Reconciled:** 2026-08-19<br>
**Status:** Approved for implementation planning<br>
**Protocol owners:** Core for registry reason codes, vector metadata, and the
verification contract<br>
**Registry transition:** revision 12 to revision 13<br>
**Decision record:** ADR-045, proposed during implementation and archived only
after the integrated patch passes

## Goal

Build an executable conformance harness that is independent of the vector
generator, fails closed on specification/artifact drift, ratchets known debt
without allowing silent growth, and runs as the same acceptance gate for
GitHub and Radicle patches.

This is continuous-delivery readiness, not deployment. The implementation does
not publish packages or reports, create a release, push a tag, or mutate a
remote repository setting.

## Current baseline

The repository now has one family version, `heterodyne/0.5.0`; one registry
manifest at revision 12; one family release manifest; and 498 normative vector
files. The generator package authors and byte-compares those vectors, validates
the family and release manifest, and runs 540 tests. It still checks generated
output largely against itself and has no independent subject boundary.

The prior design predated the single-family stabilization. Its revision-10
target, per-document release assumptions, old vector count, and fixed debt
counts are obsolete. Its proposed data corrections have already landed, and
several structural checks are already present in the generator's
`docs-lint.ts`. No `docs/spec/conformance/`, shared CI script, GitHub workflow,
or Radicle job exists on the reconciled baseline.

## Scope

In scope:

- a standalone TypeScript conformance package with no imports to or from the
  vector generator;
- corpus-wide static gates over committed specifications, registry entries,
  schemas, fixtures, release metadata, and all normative vectors;
- explicit per-vector declarations for the Core signed-event cases executed by
  the initial reference subject;
- ratcheted baselines and deterministic report projections;
- registry revision 13 and its coupled Core/vector changes;
- one shared CI job used by GitHub Actions and Radicle; and
- repository guidance requiring green CI before integration.

Out of scope:

- full semantic execution of Control, Comms, Social, Workspace, OIDC,
  recovery, or other topic-specific behavior;
- a reference client or Radicle repository subject;
- publishing, deployment, release creation, or tag creation;
- GitHub branch-protection changes; and
- Radicle broker, node, container-runtime, or delegate-host configuration.

## Architecture

### Independent package

`docs/spec/conformance/` is a standalone package with its own `package.json`,
lockfile, TypeScript configuration, source, tests, baselines, and generated
reports. It may read committed repository artifacts. It must not import any
source, build output, package export, test helper, fixture builder, or runtime
value from `docs/spec/vectors/generator/`. The generator likewise must not
import the conformance package.

The package has these focused units:

| Unit | Responsibility |
|---|---|
| `src/artifacts.ts` | Resolve repository-relative paths safely, parse committed artifacts, and expose a deterministic read model. |
| `src/json-pointer.ts` | Parse and resolve RFC 6901 pointers without prototype traversal or path inference. |
| `src/gates/` | One pure module per G1-G11 gate, each returning sorted stable failure keys. |
| `src/ratchet.ts` | Compare actual failures with committed baselines in both directions. |
| `src/subjects/reference-checker.ts` | Execute the declared Core signed-event verification stages. |
| `src/report.ts` | Build canonical `report.json` and `DEBT.md` projections. |
| `src/cli.ts` | Provide read-only `check` and explicit authoring commands. |

The existing generator and its checks remain intact. Overlapping rules are
independently implemented from the normative artifacts instead of being moved
or shared. This duplication is intentional evidence of checker independence.

### Artifact intake

The artifact loader starts from the repository root and the single family
release manifest. Every manifest path must be relative, normalized, free of
`..`, and resolve inside the repository after symlink resolution. The loader
also reads non-normative authoring inputs needed by specific gates, such as
`vectors/fixtures.json`, but does not classify those files as release
artifacts.

Parse and shape errors are accumulated. One malformed file does not hide
problems in other readable files. Duplicate vector IDs, duplicate registry
entries, unsafe paths, and missing required roots are explicit failures.

The conformance package, baselines, and reports are non-normative tooling and
are excluded from the family release manifest. The registry, vector schema,
and vector JSON changes made for this feature are normative and remain covered
by the family manifest.

## Explicit checker applicability

The vector schema advances from `1.0.0` to `1.1.0` and gains an optional
closed `conformance_checks` array. The minor version reflects a
backward-compatible optional envelope member; every unreleased current vector
is regenerated with the new schema version. An entry has exactly these
members:

```json
{
  "profile": "core-signed-event-v1",
  "event_pointer": "/input/event",
  "nip01_raw_pointer": "/input/nip01_raw",
  "context_pointer": "/input/vector_context",
  "expected_terminal_stage": "signature"
}
```

`profile` is exactly `core-signed-event-v1` in this release.
`event_pointer` and `nip01_raw_pointer` are required RFC 6901 pointers.
`context_pointer` is optional for cases that terminate before persona
resolution and required when execution reaches persona resolution or a later
stage.

`expected_terminal_stage` is one of:

- `event_structure`
- `nip01_raw`
- `identifier`
- `signature`
- `persona_resolution`
- `version_stamp`
- `kel_head`
- `epoch_authority`
- `subtype_nid`
- `accept`

Unknown profiles, unknown members, malformed pointers, duplicate declarations,
and a missing event target or declared context target are schema or
conformance failures. A missing raw target is reported by G10 rather than
treated as an invalid declaration, so existing raw-byte debt can be ratcheted.
Context is required only when the ordered checker reaches a stage that consumes
it.

The initial `ReferenceCheckerSubject` runs only vectors carrying this explicit
profile. It never infers applicability from topic names, descriptions, object
shape, or `decision_trace`. Static gates still inspect all 499 vectors.

### Checker context

When `context_pointer` is present, it resolves to one closed
`CoreVerificationContextV1` object validated by
`schema/core-verification-context-v1.schema.json` in the conformance package:

```json
{
  "persona": "<64-lowercase-hex>",
  "evaluation_time": 0,
  "nid_clock_skew_allowance": 0,
  "clock_uncertainty": 0,
  "retired_key_evidence": {
    "first_observed_at": 0,
    "prior_anchor": null
  },
  "pointer": {
    "persona": "<64-lowercase-hex>",
    "kel_head": { "event_id": "<64-lowercase-hex>", "sequence": 0 }
  },
  "kel": [
    {
      "event_id": "<64-lowercase-hex>",
      "sequence": 0,
      "prior_event_id": null,
      "epoch_pubkey": "<64-lowercase-hex>",
      "effective_from": 0,
      "effective_until": null,
      "compromise_since": null
    }
  ],
  "kel_refresh": { "status": "not-needed" },
  "signer": {
    "type": "epoch",
    "pubkey": "<64-lowercase-hex>",
    "delegation": null
  },
  "version_policy": {
    "mode": "required",
    "value": "heterodyne/0.5.0"
  },
  "kel_head_policy": { "mode": "required" },
  "subtype_policy": { "mode": "generic", "nid_pubkey": null }
}
```

All objects reject unknown members. `pointer.persona` equals `persona`, and its
head identifies one exact `kel` entry. KEL entries are sequence-contiguous,
link through `prior_event_id`, and define the epoch key's inclusive lower and
exclusive upper authority bounds. The final array entry is the accepted head;
the pointer may name an older on-KEL entry without redefining that head. A
non-null `compromise_since` truncates authority at
`effective_compromise_since - 300`, including the exact boundary.

`kel_refresh.status` is closed evidence with value `not-needed`, `succeeded`,
`pending`, or `failed`. Sequence-ahead classification precedes off-KEL
classification. Pending or failed refresh continues the ordered checks but
caps a successful result at `accept_provisional`; a completed refresh that
still leaves the named head off the accepted KEL produces
`equivocation_flagged`. A stale head that names any accepted KEL entry remains
a normal success. A sequence-ahead head paired with `not-needed` is
contradictory evidence and rejects as `kel_head_mismatch`.

`retired_key_evidence.first_observed_at` records the verifier's explicit first
observation time. Its nullable `prior_anchor` is a closed object with `type`
equal to `repository-checkpoint`, `local-receipt`, or `local-checkpoint`, plus
`established_at`. The repository type represents an already verified
introducing-commit ancestry proof under Core §9.1 and is timely no later than
routine retirement; either local type is timely only before retirement. A
post-retirement observation without a timely anchor caps a successful result
at `accept_provisional` with state `provisional-retired-key`. Compromise
rejection remains absorbing. Observation and anchor times later than
`evaluation_time` are contradictory verifier evidence and reject at
`persona_resolution`.

Every v1 context carries explicit verifier-clock evidence. `evaluation_time`
is the JSON-safe non-negative Unix second used as the verification clock.
`nid_clock_skew_allowance` is an explicit non-negative allowance capped at 300
seconds; there is no implicit or unbounded NID grace period.
`clock_uncertainty` is a JSON-safe non-negative number of seconds. NID
delegation expiry is evaluated strictly against
`evaluation_time - nid_clock_skew_allowance`. A first-accepted node
advertisement must have `created_at` within plus or minus 300 seconds of
`evaluation_time`, `evaluation_time` must be strictly before its `expiry`, and
`clock_uncertainty` greater than 300 seconds fails closed. Intrinsic node-ad
rules (`expiry > created_at` and lifetime at most 86,400 seconds) still apply.

`signer.type` is `epoch` or `delegated`. An epoch signer has a null
`delegation` and must equal the authoritative KEL entry's `epoch_pubkey`. A
delegated signer carries an object with exact `persona`, `publisher_pubkey`,
`valid_from`, nullable `valid_until`, and nullable `revoked_at` members; the
event key must equal `publisher_pubkey`, and all identity and time bounds must
hold.

`version_policy.mode` and `kel_head_policy.mode` are each `required`,
`optional`, or `forbidden`. The only version value in this release is
`heterodyne/0.5.0`. `subtype_policy.mode` is `generic`, `nid-delegation`, or
`node-advertisement`; `nid_pubkey` is null for `generic` and a lowercase
Ed25519 public-key hex string for the two NID-proof modes. This context is test
evidence, not a protocol wire object.

## Reference checker

The subject implements the ordered Core verification prefix from the
specification rather than calling generator evaluators:

1. validate the signed-event structure;
2. bind and parse exact `nip01_raw` bytes;
3. recompute the SHA-256 NIP-01 identifier;
4. verify the BIP-340 signature;
5. resolve the persona through supplied pointer, KEL, and delegation evidence;
6. enforce the version stamp;
7. classify and validate `kel_head`;
8. establish epoch authority at `created_at`, including compromise windows,
   classify retired epoch or delegated-key observation evidence, and for
   `kind:31001` establish the same epoch signer's authority again at
   `evaluation_time`;
9. enforce subtype and NID proof rules; and
10. return the exact vector verdict.

For a negative case, every stage before `expected_terminal_stage` must pass and
that exact stage must produce the vector's expected rejection. For an accepted
case, every stage must pass. A case that rejects earlier than claimed is a G11
failure even when its final verdict happens to match.

The implementation depends only on its own code, `ajv`, and the required
`@noble/*` primitives. Future subjects implement the same declared-check
dispatch boundary without changing existing vectors or gates.

## Gate catalogue

Every gate returns a canonically sorted array of stable keys. No key contains a
line number, filesystem-dependent absolute path, or array index that can move
after an unrelated edit.

| Gate | Rule | Stable key |
|---|---|---|
| G1 anchor-resolution | Every vector `spec_ref` resolves to an anchor owned by the referenced family document. | `<vector_id> :: <spec_ref>` |
| G2 reason-code closure | Every rejecting vector in every direction carries a registered reason code. | `<vector_id> :: <reason_code>` |
| G3 invariant completeness | Every registered invariant belongs to at least one applicable strict-profile closure. | `<invariant_id>` |
| G4 anchor coverage | Every normative anchor has at least one vector. | `heterodyne:<version>#<anchor>` |
| G5 fixtures consistency | Fixture metadata matches the family and contains only its closed allowlist. | `<json-pointer>` |
| G6 dead vocabulary | Every registered reason code is exercised by a vector. | `<reason_code>` |
| G7 orphan schemas | Every normative schema is bound by specification prose or a vector. | `<repository-relative-schema-path>` |
| G8 identifier integrity | Each declared case has the correct identifier unless `identifier` is its expected terminal stage. | `<vector_id> :: <event_pointer>` |
| G9 signature integrity | Each declared case has a valid BIP-340 signature unless `signature` is its expected terminal stage. | `<vector_id> :: <event_pointer>` |
| G10 `nip01_raw` binding | Every signed Nostr event discovered anywhere in the corpus has required exact raw bytes, and declared raw pointers bind byte-for-byte. | `<vector-file> :: event-sha256:<digest>` |
| G11 negative-vector hygiene | A declared negative case passes every stage before its expected terminal stage. | `<vector_id> :: <event_pointer>` |

G10 discovers signed Nostr events structurally by the complete NIP-01 event
member set, retains exact JSON pointers internally, and cross-checks explicit
declarations where present. Its stable suffix is SHA-256 over the UTF-8 JSON
serialization of `[id,pubkey,created_at,kind,tags,content,sig]`; array indexes
never enter the key and identical events may collapse. New event-shaped
objects therefore cannot evade the raw-byte gate merely by omitting
`conformance_checks`.

The implementation computes current failure sets before authoring baselines.
The obsolete counts from the earlier design are not copied forward. A gate
that is clean receives an empty baseline; a gate with known current debt
receives exactly the measured stable keys.

## Ratchet and projections

Each `baselines/G<n>-<name>.json` contains the gate ID and its sorted failure
keys. Default checking is read-only and enforces both conditions:

1. an actual key absent from the baseline is new debt and fails; and
2. a baseline key absent from actual results is stale debt and fails until the
   baseline is reduced.

`npm run baseline-author` is the only command that writes baselines. It
recomputes all gates and writes deterministic two-space JSON plus one final LF.
It is never called by `check` or CI.

`report.json` records family version, registry revision and digest, gate counts,
failure keys, and aggregate totals. `DEBT.md` renders the same information as a
review table. `npm run report-author` writes both projections. `npm run check`
rebuilds them in memory and byte-compares them with the committed files.

The CLI uses exit code 0 for success, 1 for validation or ratchet failures, and
2 for invalid invocation. It prints every issue in stable gate/key order.

## Registry revision 13

Revision 13 adds four Core-owned reason codes:

| Code | Purpose |
|---|---|
| `nip01_raw_mismatch` | Missing or non-byte-equal raw NIP-01 input. |
| `successor_persona_mismatch` | A rotation breadcrumb names a successor outside the accepted rotation. |
| `retiring_key_nip05_invalid` | A retiring profile carries a NIP-05 identifier already repointed to the successor. |
| `compromise_rotation_breadcrumb_forbidden` | A compromise-driven rotation attempts to produce a v1 breadcrumb. |

The existing breadcrumb vector reason `compromise_rotation` is replaced by
`compromise_rotation_breadcrumb_forbidden`. Core names all four refusal codes
at their owning requirements. Vector rejection-schema enforcement is widened
from consume-only to every rejecting `consume`, `produce`, or `round-trip`
vector.

Registry authoring advances from revision 12 to 13, recomputes the entry-set
digest, updates the Core capability example, regenerates registry-derived
vector projections, and refreshes the single family release manifest only
after all normative edits are final.

ADR-045 is proposed with this integration. Once the complete protocol,
artifact, harness, and CI patch passes and is accepted, the ADR is marked
accepted and moved to `docs/adr/archive/`. The live specification and
machine-readable artifacts remain authoritative.

## CI and delivery-readiness gate

`scripts/conformance-ci.sh` is the sole job body. It resolves the repository
root from its own path, enables `set -euo pipefail`, performs `npm ci` from both
committed lockfiles, and runs in this order:

1. generator `family:check`;
2. generator `check`;
3. conformance package `check`.

The script accepts no command fragments or artifact paths from environment
variables. Any command failure stops the run and preserves that exit status.

`.github/workflows/conformance.yml` runs on every pull request and every push
to `main`. Its stable job/check name is `conformance`. It uses Node 22,
`contents: read`, no repository secrets, no `pull_request_target`, and
concurrency cancellation by workflow and ref. The workflow only checks out the
submitted commit and invokes `scripts/conformance-ci.sh`.

`.radicle/native.yaml` invokes the same script and contains no duplicated job
logic. The intended Radicle execution adapter is a podman container because
dependency installation executes code from untrusted patches. Broker,
container, database, report-directory, and filter configuration remain
delegate-node concerns rather than repository files.

Radicle does not provide a server-side required-check mechanism. `AGENTS.md`
therefore requires a green isolated conformance run on a delegate-operated node
before a Radicle patch is merged. GitHub branch protection should require the
stable `conformance` check, but applying that remote setting is an explicit
repository-administrator action outside this patch.

## Testing strategy

Every gate is developed against a synthetic failing corpus before being run on
the real repository. Unit tests cover malformed JSON, unsafe paths, invalid
JSON pointers, duplicate IDs, unknown profiles, deterministic ordering, and
the exact stable-key form.

Reference-checker tests use known-answer BIP-340 cases and isolate one mutation
at each terminal stage. A regression test proves a signature-negative vector
retains a valid identifier; another proves an identifier-negative vector is
not mislabeled as a signature failure.

Ratchet tests cover new failure keys, stale baseline keys, clean empty
baselines, and canonical authoring. Projection tests compare in-memory output
with committed `report.json` and `DEBT.md` bytes.

An import-boundary test resolves every local import reachable from the
conformance package and rejects any path under the generator. A reciprocal
test over generator source rejects imports under conformance.

Integration tests run all gates and declared subject cases over the full
current corpus. Script tests assert installation/check order and failure
propagation, followed by an end-to-end run of the real shared script.

## Acceptance

The implementation is complete only when all of these pass from the repository
root:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run check
scripts/conformance-ci.sh
git diff --check
```

The final review also confirms:

- every G1-G11 requirement has a direct test;
- baseline files equal the measured current failure sets;
- no read-only `check` or CI command writes tracked files;
- the conformance and generator import graphs remain disjoint;
- registry revision 13, its digest, vectors, Core prose, and family release
  manifest agree;
- GitHub and Radicle contain no job logic beyond invoking the shared script;
  and
- no publish, deploy, release, tag, push, branch-protection, or Radicle-node
  mutation occurred.

## Deliverables

| Path | Contents |
|---|---|
| `docs/adr/2026-08-15-045-conformance-harness-independence.md`, then `docs/adr/archive/2026-08-15-045-conformance-harness-independence.md` | Proposed decision record, archived only after acceptance. |
| `docs/spec/conformance/` | Independent package, gates, runner, tests, baselines, and projections. |
| `docs/spec/vectors/schema/vector.schema.json` and affected vectors | Closed checker applicability and corrected rejection metadata. |
| `docs/spec/registry/` | Revision 13 and four Core reason codes. |
| `docs/spec/heterodyne-core.md` | Checker metadata contract and reason-code ownership. |
| `docs/spec/releases/family/0.5.0.json` | Refreshed normative corpus digests. |
| `scripts/conformance-ci.sh` | Shared read-only delivery-readiness gate. |
| `.github/workflows/conformance.yml` | GitHub intake wrapper. |
| `.radicle/native.yaml` | Radicle intake wrapper. |
| `AGENTS.md`, `README.md`, `CHANGELOG.md` | Contributor workflow, package navigation, and change record. |
