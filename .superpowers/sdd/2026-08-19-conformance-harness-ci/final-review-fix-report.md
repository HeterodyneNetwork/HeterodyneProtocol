# Final whole-branch review fix report

## Outcome and scope

Status: **DONE**

Fix base: `96734b576166134b7d8440bf501dfc9b4304b43e`

Implementation commit: `f2c24bc556161b60cf702b5a0eac204538f53010`

The implementation commit resolves all six Important and both Minor findings
from `final-review-findings.md` as one coherent wave. The report itself is a
report-only follow-up commit; its SHA is necessarily recorded in the final
handoff because a commit cannot contain its own SHA.

The live Core specification, registry revision 13/schema 3.0.0, vector schema
1.1.0, the 499-vector corpus, and the unreleased `heterodyne/0.5.0` family
release were treated as binding. Dependency versions, remote configuration,
registry-author bootstrap architecture, unrelated deferred debt, and all
publish/tag/deploy operations remained out of scope.

## Finding-by-finding diagnosis and TDD evidence

### Important 1: exact raw NIP-01 lexical bytes

Root cause: both the subject binder and G10 parsed `nip01_raw`, reconstructed
the tuple with `JSON.stringify`, and compared the reconstruction to the input.
That made one JavaScript spelling the de facto format and rejected compact,
semantically identical RFC 8259 spellings such as `fi\u0078ture`. It also made
the gate reason about reconstructed text instead of the bytes that NIP-01
actually hashes.

RED command:

```bash
npm --prefix docs/spec/conformance test -- \
  src/subjects/reference-checker.test.ts src/gates/subject-gates.test.ts
```

Recorded RED: 2 failures. The G11 known-answer event rejected at `nip01_raw`,
and G10 returned the event's stable failure key for the same alternate-escape
raw string.

Minimal fix: lexically reject RFC 8259 whitespace outside strings, parse and
validate the exact six-member tuple, compare parsed field and tag values to the
exposed event, retain the supplied string, and hash that supplied UTF-8 string.
G10 now uses the same exact-byte binder.

Focused GREEN: the same command passed 72/72 tests at the finding checkpoint;
`npm --prefix docs/spec/conformance run build` also exited 0. The final combined
affected conformance suite passed 134/134.

Changed files:

- `docs/spec/conformance/src/subjects/nip01.ts`
- `docs/spec/conformance/src/gates/nip01-raw.ts`
- `docs/spec/conformance/src/subjects/reference-checker.test.ts`
- `docs/spec/conformance/src/gates/subject-gates.test.ts`

### Important 2: normative vector schema was not enforced

Root cause: intake stored `vector.schema.json` as a released schema but sent
vectors directly to a partial handwritten parser. That parser did not enforce
the committed schema's closed members or exact `spec_refs` cardinality.

RED command:

```bash
npm --prefix docs/spec/conformance test -- src/artifacts.test.ts
```

Recorded RED: the five vector-schema behavior cases failed: one unknown-member
case, zero- and two-item `spec_refs` cases, a non-object schema case, and an
uncompilable object-shaped schema case. The invalid vectors were accepted or
the invalid schema failed to close corpus intake.

Minimal fix: compile the committed vector schema with a dedicated AJV instance
before vector parsing, apply it to every released vector, and leave custom
declaration/pointer checks as a second independent layer. A missing, non-object,
or uncompilable vector schema now prevents any vector from entering the corpus,
while intake continues accumulating readable issues.

Focused GREEN: `src/artifacts.test.ts` passed 35/35 after the schema and registry
compiler fixes, and 38/38 after the inventory safety regressions were added.
The G2 integration fixture now extends its temporary vector-schema enum so it
still tests registry closure rather than being stopped by the preceding schema
gate.

Changed files:

- `docs/spec/conformance/src/artifacts.ts`
- `docs/spec/conformance/src/artifacts.test.ts`
- `docs/spec/conformance/src/integration.test.ts`

### Important 3: registry schema compilation escaped intake

Root cause: registry-schema AJV compilation happened outside a catch boundary.
An object-shaped schema with an unresolved `$ref` threw `MissingRefError` and
prevented later diagnostics from being returned.

RED command:

```bash
npm --prefix docs/spec/conformance test -- src/artifacts.test.ts
```

Recorded RED: the malformed-registry-schema case threw while compiling
`{"$ref":"missing.json"}` instead of returning issues, thereby hiding the
separate malformed-vector JSON issue in the same repository.

Minimal fix: catch only registry-schema compilation, emit the stable
`invalid-document-shape` issue against `registry.schema.json`, and continue the
remaining intake pass. Vector and registry schema compilers remain independent.

Focused GREEN: `src/artifacts.test.ts` passed 35/35 at the compiler-fix
checkpoint and returned both the registry-schema and malformed-vector issues.

Changed files:

- `docs/spec/conformance/src/artifacts.ts`
- `docs/spec/conformance/src/artifacts.test.ts`

### Important 4: invalid stamping on normative vector 005

Root cause: vector 005 used adopted Nostr kind 1 with `spec_version` and
`kel_head` but without the registry's only kind-1 stamping discriminator,
`heterodyne_wrap=room_key.v2`. Its context incorrectly declared both policies
required even though the plain Core kind-1 profile is non-stamping.

RED commands:

```bash
npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts
npm --prefix docs/spec/vectors/generator test -- src/author.test.ts
```

Recorded RED: the checker accepted the old stamped/discriminator-free
combination instead of rejecting `version_stamp_invalid`; the author suite
also failed its hand-derived expectation for an unstamped replacement.

Minimal fix: enforce kind-1 policy/discriminator coherence in the independent
checker and author vector 005 as a plain unstamped kind-1 event with forbidden
version/head policies. The checker regression proves both the old combination's
rejection and the replacement's acceptance.

Focused GREEN: the checker passed 56/56 at this checkpoint and the author suite
passed 3/3. Approved authoring regenerated these exact values:

- `nip01_raw`: `[0,"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",1767225660,1,[],"valid-core-signed-event"]`
- event id: `87205a88f5d332b9556faf13347575ed8b71baaa9e7a58596ad3618b974a9b65`
- signature: `6fa07764015c24bc03ec439225b6c0647f1050029b24f5c3fa5f880cacfd8fbd52371327913877caf5cdbccdcbab079773b84813bdc803b66d2664675406379c`

Changed files:

- `docs/spec/conformance/src/subjects/reference-checker.ts`
- `docs/spec/conformance/src/subjects/reference-checker.test.ts`
- `docs/spec/vectors/generator/src/topics.ts`
- `docs/spec/vectors/generator/src/author.test.ts`
- `docs/spec/vectors/verification/005-valid-core-signed-event-accepts.json`
- `docs/spec/releases/family/0.5.0.json`

### Important 5: refresh finality did not cap every success

Root cause: provisional refresh state was derived only from the sequence-ahead
branch. An on-KEL event with `pending` or `failed` refresh therefore returned a
final accept, and the contradictory sequence-ahead/`not-needed` pair was
silently provisional.

RED command:

```bash
npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts
```

Recorded RED: 3 failures. On-KEL `pending` and `failed` each returned `accept`
instead of `accept_provisional`; ahead plus `not-needed` returned provisional
instead of rejecting `kel_head_mismatch`.

Minimal fix: classify the ahead contradiction explicitly, then make pending or
failed refresh a global cap on every otherwise successful path. Ordered later
rejections remain stronger and are not hidden.

Focused GREEN: the checker passed 59/59 at this checkpoint.

Changed files:

- `docs/spec/conformance/src/subjects/reference-checker.ts`
- `docs/spec/conformance/src/subjects/reference-checker.test.ts`
- `docs/spec/heterodyne-core.md`
- `docs/superpowers/specs/2026-08-15-conformance-harness-independence-design.md`

### Important 6: retired-key observation evidence was implicit

Root cause: authority was checked only against the event's claimed
`created_at`. The closed verifier context could not say when the exact event
was first observed or whether a repository/receipt/checkpoint already proved
pre-retirement existence, so historical epoch and delegated-key events could
be reported finally after retirement without the evidence Core 9.1 requires.

RED command:

```bash
npm --prefix docs/spec/conformance test -- src/subjects/reference-checker.test.ts
```

Recorded initial RED: 9 failures across required-context, pre/post-retirement,
anchor, delegated-retirement, and compromise-boundary cases. After the minimal
implementation, one existing NID evaluation-time fixture correctly failed
because its observation evidence was now later than its shifted verifier
clock; the fixture was made internally coherent. That checkpoint then passed
67/67.

Self-review added a second behavior-level boundary before tightening context
semantics. Its RED was exact:

```text
1 failed | 67 passed
expected terminalStage "persona_resolution", received "accept"
```

The failing cases supplied `first_observed_at=101` or anchor
`established_at=101` with `evaluation_time=100`.

Minimal fix: add required closed `retired_key_evidence` with explicit
`first_observed_at` and nullable, closed prior anchors. Routine epoch retirement
uses `effective_until`; delegated retirement uses the earliest non-null
`valid_until`/`revoked_at`. Observation at or after retirement without a timely
anchor caps acceptance at `accept_provisional` with state
`provisional-retired-key`. Repository anchors permit the inclusive retirement
boundary; local receipt/checkpoint anchors remain strictly pre-retirement. The
compromise cutoff and kind-31001 current-at-evaluation rule remain stronger.
Evidence later than `evaluation_time` rejects at `persona_resolution`.

Focused GREEN: the checker passed 68/68 and the conformance build exited 0.

Changed files:

- `docs/spec/conformance/schema/core-verification-context-v1.schema.json`
- `docs/spec/conformance/src/subjects/types.ts`
- `docs/spec/conformance/src/subjects/reference-checker.ts`
- `docs/spec/conformance/src/subjects/reference-checker.test.ts`
- `docs/spec/vectors/generator/src/topics.ts`
- `docs/spec/vectors/generator/src/author.test.ts`
- `docs/spec/vectors/verification/005-valid-core-signed-event-accepts.json`
- `docs/spec/heterodyne-core.md`
- `docs/spec/vectors/README.md`
- `docs/superpowers/specs/2026-08-15-conformance-harness-independence-design.md`
- `docs/spec/releases/family/0.5.0.json`

### Minor 7: normative inventory silently skipped special entries

Root cause: recursive inventory returned only entries for which `Dirent.isFile`
or `Dirent.isDirectory` was true and silently dropped everything else,
including in-root and escaping JSON symlinks.

RED command:

```bash
npm --prefix docs/spec/conformance test -- src/artifacts.test.ts
```

Recorded RED: 2 symlink tests failed because no stable issue was emitted. A
follow-up exclusion regression was also RED once recursion reported package
manager `.bin` links inside the explicitly non-normative generator subtree.

Minimal fix: report every special entry reached under a normative inventory as
`unsafe-artifact-path`, never follow it, and prune the existing excluded
registry-history/vector coverage/generator/schema subtrees before recursion.
The in-root and escaping targets are never read.

Focused GREEN: 37/37 after the two symlink cases and 38/38 after the explicit
non-normative-subtree regression.

Changed files:

- `docs/spec/conformance/src/artifacts.ts`
- `docs/spec/conformance/src/artifacts.test.ts`

### Minor 8: archived Accepted ADR used proposed tense

Root cause: the ADR was moved and marked Accepted, but its acceptance section
still described itself in present/future proposed tense.

Exact base RED/current GREEN evidence:

```text
ADR RED (expected): base line was This ADR remains proposed while the integrated implementation is reviewed.
ADR GREEN: archived Accepted tense is historical
```

Minimal fix: rewrite only that section in historical past tense without adding
any protocol requirement.

Changed file:

- `docs/adr/archive/2026-08-15-045-conformance-harness-independence.md`

## Approved regeneration

The coupled artifacts were regenerated only with the approved author commands:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-author -- "$PWD"
```

Results:

- author mode wrote 499 vectors;
- coverage generation completed and produced no tracked coverage byte change;
- release authoring updated the Core specification digest and vector 005 digest;
- release verification subsequently proved every released artifact digest;
- no conformance baseline, `report.json`, or `DEBT.md` changed because measured
  gate state did not change;
- registry artifacts and their entry-set digest did not change.

## Final verification

All commands below ran against the final implementation bytes.

| Verification | Result |
| --- | --- |
| Affected conformance suites (`artifacts`, `subject-gates`, `integration`, `reference-checker`) | 4 files, 134/134 tests passed |
| Affected generator suites (`author`, `schema`, `docs-lint`, `release`) | 4 files, 67/67 tests passed |
| Standalone conformance build | `tsc --noEmit`, exit 0 |
| Standalone full conformance tests | 16 files, 197/197 tests passed |
| `family:check` | protocol document family validated |
| Full generator `check` | 43 files, 548/548 tests; 499 vectors verified; family release manifest validated |
| Full conformance `check` | build plus 16 files, 197/197 tests; checker exited 0 |
| Post-commit `scripts/conformance-ci.sh` | generator 548/548, 499 vectors, release valid; conformance 197/197; exit 0 |
| Task 11 hard boundaries | all exact assertions passed |
| `git diff --check` | exit 0 |

The post-implementation-commit shared-CI read-only guard started and ended with
an empty tracked diff and empty status, both hashing to:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The hard-boundary audit proved:

- no generator import from conformance and no conformance import from the
  vector generator;
- registry revision `13`, registry schema `3.0.0`, and vector schema `1.1.0`;
- family `heterodyne/0.5.0` remains `unreleased`;
- exactly 499 released vector artifacts and no conformance implementation
  artifact in the family release;
- registry entry-set digest equals the fixture pin;
- the exact registry manifest, Core, and vector-005 bytes equal their release
  digests;
- vector 005 is unstamped with forbidden version/head policies;
- ADR-045 exists only at its archived Accepted path;
- no baseline/report/debt file was changed.

## Full-diff self-review

- Exact bytes: both G10 and G11 retain and hash supplied `nip01_raw`; compact
  alternate RFC 8259 escapes are accepted, whitespace and non-tuple shapes are
  rejected, and reconstructed bytes are never hashed.
- False-cleans: vector schema validation precedes handwritten checks; invalid
  schema documents fail closed without suppressing other intake issues; only
  schema compilation exceptions are caught.
- Stage/reason order: structural/context checks still precede version, head,
  authority, subtype, and accept. Pending/failed refresh caps only otherwise
  successful paths. The ahead/`not-needed` contradiction uses the registered
  `kel_head_mismatch` outcome.
- Authority: compromise rejection is absorbing; kind 31001 remains current-key
  constrained; retired evidence can make an event final only at boundaries
  permitted by Core; future-dated verifier evidence fails closed.
- Inventory: special entries are deterministic stable issues, symlinks are not
  followed, and excluded non-normative subtrees are pruned before traversal.
- Release coherence: author tools produced all normative bytes; stable vector
  IDs and the 499 count were preserved; only the expected Core/vector digests
  changed.
- Boundaries and scope: no dependency, workflow, remote, registry revision,
  bootstrap architecture, baseline, or unrelated artifact changed. No push,
  tag, publish, deploy, or remote configuration occurred.

## Concerns

No task-blocking concerns remain. The shared CI install continues to report the
accepted/deferred inherited generator audit result of 5 advisories (1 low,
4 high); dependency changes were explicitly outside this fix wave. The
conformance package reports 0 vulnerabilities.
