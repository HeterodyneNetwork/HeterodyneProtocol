# Task 7 report: ordinary vanilla-compatible Nostr Social

## Phase and status

Task 7 is implemented with the requested commit message
`spec: make Social vanilla Nostr compatible`. The final focused semantic,
schema, and registry suites, generator build, family check, and history-bound
snapshot check pass.

## Implemented scope

- Rebased ordinary Social behavior on actual NIP-01 authorship and ordinary
  NIP-10 replies, NIP-25 reactions, NIP-51 lists, and NIP-72 communities. A
  bare active Nostr key with no Assurance or KEL context is a first-class
  Social author.
- Added executable Social authorship validation. Direct events retain their
  signing `pubkey`; delegated organization publication requires the complete
  signed Comms attribution profile plus an exact authorized signer and
  association tuple. A key association must equal the actual signer, while an
  explicitly absent optional association remains supported.
- Added executable source-neutral replaceable-event validation and selection.
  Relay and authorized-repository candidates are verified identically,
  deduplicated by event id, constrained to the requested standard coordinate,
  and selected by greatest `created_at` then lowest event id. Carrier never
  enters the comparison. Seven-day age is a warning and not invalidity.
- Removed live kind `31007`, the separate organization-feed identity, retired
  canonical-branch/feed-index refusal codes, cold-root/KEL Social validity
  gates, and repository-priority moderation/list behavior. Organization
  personas now use the same active-key/profile/relay-list pattern as humans.
- Reworked agent-policy receipts and corrections around the actual signed
  offending event, actual event author, explicitly verified Comms association
  or null, closed policy id/version, decision/evidence, and exact correction
  relationship. Corrections must be signed by the original policy issuer.
- Kept moderation advisory and subscriber-local. A source-neutrally selected
  current list mutes only the listed actual event author; a different signer
  is evaluated independently, and no moderator, association, organization,
  relay, repository, or Assurance state rewrites authorship.
- Made continuity vouches and ATProto continuity explicitly optional-Assurance
  evidence while binding the ATProto attachment itself to the current active
  Nostr key.

The live registry remains revision `14`. The supported registry authoring
command produced final digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`.
No vector, coverage, snapshot, baseline, report/debt, or release authoring
command was invoked against the repository.

No vector topic source, topic metadata, vector payload/fixture/schema/coverage
projection, `snapshot.json`, conformance baseline/report/debt, or release
metadata artifact was edited.

## RED evidence

The pre-change focused baseline passed:

```text
npm --prefix docs/spec/vectors/generator test -- \
  src/registry.test.ts src/schema.test.ts src/agent-moderation.test.ts
Test Files  3 passed (3)
Tests       89 passed (89)
```

The initial test-only Task 7 patch produced the expected broad focused RED:

```text
npm --prefix docs/spec/vectors/generator test -- \
  src/social-events.test.ts src/agent-moderation.test.ts \
  src/registry.test.ts src/schema.test.ts
exit 1

Test Files  4 failed (4)
Tests       11 failed | 11 skipped | 79 passed

- 7 missing executable Social NIP-01 authorship, source-neutral selection,
  coordinate validation, and warning-only freshness behaviors
- 3 live-registry failures for kind 31007, retired prerequisites/reasons, and
  replacement Social invariants/reasons
- 1 old Social agent-policy schema failure
- the old receipt schema also failed agent-moderation suite setup
```

Subsequent review-driven RED boundaries were observed before each production
change:

```text
key association not equal to actual signer:          1 failed | 11 passed
source-biased current correction-list field:          1 failed | 11 passed
retired org-feed/feed-index reason codes:              1 failed | 22 passed
unbound optional correction reason accepted:           1 failed | 59 skipped
exact delegated signer/association API absent:         1 failed | 7 passed
replaceable-candidate refusal evaluator absent:        1 failed | 8 skipped
```

Concrete observations included accepting a claimed key association for a
different event signer, retaining a `canonical_list_binding_removed` current
API, keeping `not_canonical_branch_reachable` and `page_chain_broken` live,
accepting a correction member not bound to the original receipt, lacking an
exact signer-plus-association authorization path, and lacking executable
registered coordinate/signature refusal outcomes.

## GREEN and final verification

Fresh final commands against the completed Task 7 content:

```text
npm --prefix docs/spec/vectors/generator test -- \
  src/social-events.test.ts src/agent-moderation.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  4 passed (4)
Tests       104 passed (104)

npm --prefix docs/spec/vectors/generator run build
tsc --noEmit (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

Snapshot-check authored only into its disposable temporary raw directory and
verified the packaged historical snapshot read-only.

## Exact ownership expansion

In addition to the brief's named Social specification, schemas, registry, and
focused tests, Task 7 directly required:

- `docs/spec/vectors/generator/src/social-events.ts` and
  `social-events.test.ts`: new current executable NIP-01 authorship,
  exact delegated signer/association, replaceable-coordinate,
  source-neutral selection, and freshness-warning behavior.
- `docs/spec/vectors/generator/src/agent-moderation.ts` and
  `agent-moderation.test.ts`: directly affected current Social receipt,
  correction, list, and subscriber-local enforcement semantics.
- `docs/spec/vectors/generator/src/legacy-agent-moderation.ts`: quarantined
  structural compatibility used only through overloads required by the
  explicitly frozen pre-redesign agent-moderation topic source. The live
  two-argument receipt/correction path requires actual signed target evidence;
  the frozen topic source itself remains byte-unchanged.

No other ownership expansion occurred.

## Full self-review and concerns

The complete diff was reviewed for actual event-id/signature verification,
author-versus-represented-persona separation, exact delegated signer and
association authorization, optional association handling, standard
replaceable coordinates and tie-breaking, carrier neutrality, warning-only
age, receipt/correction issuer and body/tag binding, subscriber locality,
closed schema/runtime equality, retired kind/reason removal, registry digest
and revision, normative fixture signatures, and forbidden-artifact scope.

The completion-review skill requested an independent reviewer, but dispatch
failed with `agent thread limit reached`; the brief-required complete
self-review was performed and the parent integration review was notified.

A one-time broad `draft:check` diagnostic reported 5 maintained-guide/
threat-model cases, 17 frozen token-status cases, and 3 cases each in
coverage, versioning, and current authoring projections. Those are the brief's
explicit Task 8/9 and frozen-current projection exclusions. Authoring helpers
ran only inside disposable test temporary directories. No excluded repository
artifact changed, and there is no scoped Task 7 blocker.

## Commit

Commit message: `spec: make Social vanilla Nostr compatible`.

## Fix round 1/5

### Implemented review findings

- Added one shared strict signed-event validator that closes the NIP-01 event
  object, requires lowercase fixed-width hex `pubkey`/`id`/`sig`, safe ranged
  integer `created_at`/`kind`, string content, and non-empty tags containing
  only strings before verifying the recomputed id and BIP-340 signature.
  Current Social authorship/selection, NIP-72, ATProto, and moderation receipt,
  target, list, and correction validation all consume that validator.
- Corrected parameterized replaceable-event handling to take `d` from the
  tag's second member while permitting upstream trailing tag members.
- Removed every live moderation overload and value-shape dispatch to the
  legacy device-key model. Live receipt and correction validation now require
  the current signed target/receipt argument, list validation cannot select a
  validator from the map's first value, and live application APIs reject
  legacy device-key inputs.
- Preserved the byte-frozen pre-redesign moderation topic through an explicit
  snapshot-only adapter. The generator compiler host remaps only that frozen
  topic's relative moderation import to legacy aliases; all other imports
  resolve to the current-only module. No topic source or topic metadata was
  modified.
- Added executable NIP-72 live-curated-view evaluation. It source-neutrally
  selects the current kind `34550` declaration, counts distinct approvals only
  from that declaration's current moderator keys, retains removed-moderator
  approvals as audit-only evidence, and holds the candidate until a current
  moderator reapproves.
- Removed the public-byline authorization bypass. Every non-active-key Social
  signer must carry the complete signed Comms attribution profile and match a
  current Comms-authorized signer-plus-association tuple.
- Renamed the raw 64-lowercase-hex ATProto attachment member and tag from
  `npub` to `pubkey`. Bindings now carry a consecutive generation and fresh
  nonce, both signature sides bind the exact payload hash, and verified
  Nostr-side or ATProto-side revocations remain independently durable. A
  replacement after revocation requires a fresh mutually signed generation
  and nonce, so an old countersignature cannot replay.
- Corrected the ordinary direct-reply NIP-10 fixture to use the `root` marker.

Registry revision `14` and digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No authoring command was run.

### Fix-round RED evidence

Each finding had an observed test-only RED before its production change:

```text
shared strict validator export absent:                         1 failed
Social empty-tag acceptance / trailing d rejection:            2 failed
moderation receipt/target/list/correction structure acceptance: 4 failed
renamed complete-Comms authorization input absent:             2 failed
ATProto executable attachment validator absent:                1 failed
NIP-72 current-moderator evaluator absent:                     2 failed
ATProto durable revocation/generation/replay cases absent:      3 failed
legacy live moderation dispatch still accepted:                4 failed
```

After live legacy dispatch was removed, the ordinary compiler produced the
expected compatibility RED exclusively in the unchanged frozen topic:

```text
npm --prefix docs/spec/vectors/generator run build
exit 1
topics-agent-moderation.ts: 10 type errors against current-only APIs
```

The explicit snapshot-only adapter/build surface then restored compilation
without changing frozen topic bytes.

### Fix-round GREEN and full verification

Fresh completed-patch evidence:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/nostr.test.ts src/social-events.test.ts src/social-nip72.test.ts \
  src/social-atproto.test.ts src/agent-moderation.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  7 passed (7)
Tests       122 passed (122)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

The snapshot command authored only into its disposable temporary raw root and
performed a read-only comparison with the pinned historical package.

### Fix-round ownership expansion and self-review

The review findings directly required these additional current executable
surfaces beyond the original Task 7 ownership:

- `nostr.ts` / `nostr.test.ts` for the shared strict event validator;
- `social-nip72.ts` / `social-nip72.test.ts` for current-moderator-set live
  approval semantics;
- `social-atproto.ts` / `social-atproto.test.ts` for exact mutual binding,
  independently durable revocation, generation, nonce, and replay semantics;
- `snapshot-agent-moderation-adapter.ts`, `scripts/typecheck.mjs`, and the
  generator build script for the explicitly isolated frozen-topic bridge.

The whole fix-round diff was reviewed for strict structure before
cryptography, id recomputation, target/receipt/list/correction binding,
addressable-tag handling, source-neutral declaration selection, approval
deduplication and audit classification, exact current Comms authorization,
ATProto closed payloads and proof hashes, either-side durable revocation,
generation/nonce replay resistance, frozen-topic isolation, registry
revision/digest stability, and forbidden-artifact scope. `git diff --check`
was clean. No vector payload, fixture, vector schema/coverage projection,
snapshot, baseline/report/debt, topic source/metadata, or release artifact was
modified.

The completion-review skill requested an independent reviewer, but dispatch
again returned `agent thread limit reached`; this full self-review and the
parent integration review remain the available review gates. No approved-
design ambiguity or legacy-adapter blocker remains.

Fix-round commit message: `fix: harden Social Nostr interoperability`.
