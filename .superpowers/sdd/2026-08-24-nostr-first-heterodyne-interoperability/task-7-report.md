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

## Fix round 2/5

### Implemented review findings

- Replaced the compiler-only legacy bridge as the execution mechanism with a
  real snapshot-only runtime. It emits a disposable repository-shaped
  TypeScript build, rewrites only the copied frozen moderation topic's single
  import to the explicit legacy adapter, links the locked dependencies and
  current registry, copies current schemas required by emitted and dynamic
  imports, loads the emitted JavaScript, and removes the disposable tree.
  Current author and coverage execution enter through this runtime. Live
  moderation exports stay current-only and direct frozen-topic execution
  through them fails closed.
- Updated NIP-72 reference handling to accept upstream trailing relay hints as
  tag prefixes. Only approvals at or after the deterministically selected
  kind `34550` declaration revision count, so removal/re-addition cannot
  resurrect an old approval. Strict signed, non-backdated NIP-09 requests
  exclude only the same author's targeted approval; malformed and wrong-author
  requests have no effect.
- Replaced caller signer/association arrays with an opaque Comms authorization
  capability. Its producer runs the existing workload-registration,
  access-token, and attribution validators, then exact-checks represented
  persona, signer, optional association, event kind, publication scope, event
  time, current registration/grant bounds, content size, canonical tags, and
  actual author. A module-private WeakMap authenticates the frozen capability;
  plain lookalikes and use on another signed event reject.
- Defined one explicit ATProto binding/revocation serialization order. Binding
  verification requires canonical `did:web` or `did:plc`, an optional
  canonical 20-byte Base58btc RID, and a direct Ed25519 proof using the exact
  named verification method of the resolved DID document. Boolean validity or
  claimed hash inputs no longer exist.
- Added authenticated ATProto lineage. Generation 1 carries
  `predecessor:null`; every later generation binds the prior Nostr event id and
  canonical binding hash. A fresh verifier walks signed repository-history or
  relay evidence to generation 1 and checks every event, DID proof,
  consecutive generation, time, nonce, event reference, and hash. Missing or
  forged history and an old countersignature fail.
- Revocations now enter only as a strict signed Nostr event or a direct DID
  signature over canonical revocation bytes. Forged bodies do not revoke.
  Either valid side revokes the current chain; recovery requires the next
  fresh mutually signed generation after the revocation with the revoked
  binding as authenticated predecessor.

Registry revision `14` and entry-set digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No registry, schema, frozen vector, snapshot, baseline,
report/debt, topic source/metadata, or release artifact was modified, and no
repository authoring command was run.

### Fix-round-2 RED evidence

Every review area began with executable exploit probes before production
changes:

```text
snapshot runtime:
  direct frozen topic through live API threw agent-policy-receipt-invalid;
  isolated runtime vector result was undefined                    1 failed / 1

NIP-72 relay hints, set revision, and signed deletion:
  exact tags rejected hints; pre-revision approval counted;
  valid same-author NIP-09 was ignored                             3 failed / 5

Comms-to-Social authorization:
  capability producer absent; fabricated tuple accepted           2 failed / 28

ATProto canonical DID evidence:
  after boolean/hash removal, canonical proof inputs rejected     4 failed / 4

ATProto signed lineage and revocation:
  predecessor/revocation evidence interface absent and
  generation-1 predecessor shape rejected                         4 failed / 4

self-review lineage pair continuity:
  valid same-DID predecessor permitted a different Nostr pubkey   1 failed / 1
```

An initial broad current-author probe reached an unrelated current Comms
continuity-schema projection before the moderation topic. The focused runtime
probe was therefore narrowed to execute the actual frozen moderation builder;
it first proves direct live failure and then requires the real emitted adapter
runtime to produce `agent-moderation/receipt-valid`.

A final broad author integration probe first exposed absent disposable
registry and dynamically loaded schema assets. After linking/copying those
read-only inputs into the disposable repository shape, both snapshot-runtime
author calls and the direct live author call reached the same unrelated Comms
continuity-schema projection (`claim-schema-invalid`) with no runtime path or
module-resolution failure. The focused moderation runtime stayed green.

### Fix-round-2 GREEN and full verification

Fresh completed-patch evidence:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/snapshot-topic-runtime.test.ts src/agent-moderation.test.ts \
  src/agent-authorship.test.ts src/nostr.test.ts \
  src/social-events.test.ts src/social-nip72.test.ts \
  src/social-atproto.test.ts src/registry.test.ts src/schema.test.ts
Test Files  9 passed (9)
Tests       145 passed (145)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

Snapshot verification authored only into its disposable temporary raw root
and compared read-only with the pinned historical package.

### Ownership expansion, cost, and self-review

The parent explicitly expanded Task 7 ownership to
`agent-authorship.ts`/tests for the Comms-to-Social capability. That cost is a
new non-wire capability producer and consumer contract in the shared Comms
module, plus focused Comms prose, tests, and exact reuse of three existing
validators. No second authorization implementation or serializable receipt
was introduced.

The real snapshot runtime additionally required `author.ts`, `coverage.ts`,
`snapshot-topic-runtime.ts`, and its integration test. These are execution
surfaces, not frozen topic or vector artifacts. The approved design and plan
are recorded beside this report.

The complete diff was reviewed for a single transformed import, disposable
cleanup, no legacy live dispatch, NIP-72 prefix/reference/author/time rules,
WeakMap capability provenance and event replay, exact existing Comms validator
reuse, canonical identifier/serialization rules, resolved-DID method
selection and Ed25519 verification, predecessor event/hash traversal, carrier
neutrality, same DID/Nostr-key pair continuity, unique nonce and monotonic
time, forged revocation handling,
post-revocation recovery, deterministic fixture signatures, registry
revision/digest stability, and prohibited paths. `git diff --check` was clean.

Independent review dispatch remained unavailable because the root thread's
existing completed reviewers still consumed the agent thread limit. The
complete self-review and parent integration review are the available gates.
No approved-design contradiction or blocker remains.

Fix-round-2 commit message: `fix: authenticate Social moderation and lineage`.

## Fix round 3/5

### Implemented review findings

- Cross-bound Comms authorization to the registration's exact audience and
  subject proof, the token audience/confirmation/sender proof, requested feed
  and resource allow lists, and exact registration/token identity, generation,
  version, status, and grant state. Minting targets an unsigned exact event.
  One-use pre-sign consumption burns the authorization before returning,
  re-runs all current validation, and yields a separate one-use opaque
  authorship proof. Social burns that proof against the exact signed event.
- Added an opaque resolver-authenticated DID capability. Its only producer
  validates a closed domain-separated envelope and a local configured
  Ed25519/BIP340 resolver attestation. The envelope binds exact canonical
  `did:web` URL or PLC log evidence, canonical document bytes/hash, selected
  method, time/expiry, and resolver policy/version. Binding and revocation code
  receive no caller DID document or validity boolean. This is a client-chosen
  embedding transport trust boundary, never protocol identity authority; no
  resolver key was added to the registry.
- Replaced single-candidate ATProto validation with a carrier-tagged
  repository/relay union. Strict valid candidates are deduplicated and the
  current event is selected by greatest `created_at`, then lowest id, with no
  carrier preference. Only that event follows full lineage. DID-side
  revocation verifies with the current fresh resolution capability's selected
  method, allowing legitimate DID-key rotation; Nostr-side revocation remains
  bound to the linked pubkey.
- Hardened the snapshot-only runtime by using `fileURLToPath`, copying both
  registry and schemas into disposable output, and deleting the temporary tree
  when construction fails before the runtime path can be returned. The copied
  frozen moderation topic remains the sole transformed source.

Registry revision `14` and entry-set digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No registry, schema, frozen topic/vector, snapshot,
projection, baseline/report/debt, or release artifact was modified, and no
repository authoring command was run.

### Fix-round-3 RED evidence

Each finding began with an executable exploit probe:

```text
Comms audience/JKT/destination/current-state binding:
  mismatched registration audience still minted authorization              1 failed / 1

Social authorization one-use consumption:
  the second consume of the same capability still accepted                 1 failed / 1

resolver-attested opaque DID authority:
  resolver producer and verification boundary were absent                  2 failed / 2

ATProto current candidate and rotated revocation authority:
  union interface rejected valid candidates; rotated current method failed 4 failed / 5

snapshot runtime construction cleanup:
  missing-tsconfig construction left its prefixed temporary tree            1 failed / 1

self-review pre-sign boundary:
  unsigned exact event could not mint authorization                         1 failed / 1
  Social could not consume the resulting post-sign authorship proof         1 failed / 1
  post-sign proof could be replayed at a different destination              1 failed / 1

self-review DID method binding:
  signed did:web envelope mislabeled did:plc still minted capability        1 failed / 1
```

The resolver ambiguity was escalated before implementation. The parent
approved a local configured resolver-attestation key and closed signed
envelope, explicitly ruling that it is an embedding trust boundary rather
than protocol identity authority. The approved design and implementation plan
are recorded beside this report.

### Fix-round-3 GREEN and full verification

Fresh completed-patch evidence:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/snapshot-topic-runtime.test.ts src/agent-moderation.test.ts \
  src/agent-authorship.test.ts src/nostr.test.ts \
  src/social-events.test.ts src/social-nip72.test.ts \
  src/atproto-did-resolution.test.ts src/social-atproto.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  10 passed (10)
Tests       148 passed (148)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

Snapshot verification authored only into its disposable temporary raw root
and compared read-only with the pinned historical package.

### Ownership expansion, costs, and self-review

The new `atproto-did-resolution.ts`/test module is directly required to keep
caller DID documents outside Social authority. It adds no wire object and no
global key. The existing approved `agent-authorship.ts` ownership expanded to
the pre-sign authorization / post-sign authorship capability pair. Loader work
remained confined to its current snapshot-only runtime and test.

The complete diff was reviewed for pre-sign unsigned-event binding,
burn-before-decision semantics, exact current state and destination checks,
post-sign proof replay, resolver-envelope closure/domain separation,
configured-anchor Ed25519/BIP340 verification, fake/stale/wrong-DID/wrong-
method rejection, carrier-neutral deterministic selection, selected-only
lineage, current rotated DID revocation method, linked Nostr revocation key,
copied normative runtime inputs, construction cleanup, frozen-topic isolation,
registry revision/digest stability, and prohibited paths. `git diff --check`
was clean. No unresolved design contradiction remains.

Fix-round-3 commit message: `fix: authenticate Social current authority`.

## Fix round 4/5

### Implemented review findings

- Replaced the split pre-sign/post-sign Comms capability flow with one atomic
  embedding authority. It samples embedding-owned trusted time once, validates
  complete current registration/token/ledger/status/grant/destination state,
  injects attribution, freezes the exact unsigned bytes, invokes the
  structural durable `executeOnce` signer contract, strict-verifies its exact
  signed result, and returns a one-use opaque signed-publication proof. Signed
  inputs cannot mint proofs. Social consumes the exact returned event without
  retroactively consulting later mutable state.
- Added configured opaque resolver-authority instances. Each instance
  deep-clones and freezes its anchor set, policy allow list, minimum semantic
  version, and maximum TTL. Evidence supplies none of that configuration.
  Resolution capabilities carry exact authority-instance provenance; forged,
  attacker-authority, cross-authority, mutable-envelope, policy/version
  downgrade, excessive-TTL, and stale use fail closed.
- Replaced ephemeral carried resolution capabilities with durable signed
  `{envelope,signature}` attestations. Fresh verifiers reauthenticate current
  candidates at trusted current time and historical lineage at each binding
  event's `created_at`, preserving verification of expired or rotated
  historical methods without restoring current authority.
- Expanded durable revocation evaluation to the independently authenticated
  candidate/history universe. Every valid target for the identity must occur
  on the selected chain and have a strictly later consecutive recovery.
  Selected siblings, generation resets/lower forks, and incompatible revoked
  branches reject even when deterministic current selection chooses another
  branch.

Registry revision `14` and entry-set digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No registry, schema, frozen topic/vector, snapshot,
projection, baseline/report/debt, or release artifact was modified, and no
repository authoring command was run.

### Fix-round-4 RED evidence

Every production change followed an executable exploit failure:

```text
atomic trusted-time Comms signing boundary:
  new authority/sign API absent; valid, stale, signed-input, and substituted
  signer-result probes all failed                                      4 failed / 20

Social signed-publication consumption:
  old Social consumer could not burn the new exact signed proof         1 failed / 11
  (one test-helper rename error in the same run was corrected before GREEN)

configured resolver authority instance:
  configured authority producer absent; all authority probes failed     3 failed / 3

persistable historical resolution:
  durable evidence/current authority interface rejected valid bindings,
  including expired generation-one history for a fresh verifier         5 failed / 6

branch-independent durable revocation:
  a newer selected sibling hid the valid revoked branch and accepted    1 failed / 1
```

The parent approved preserving family layering: Comms defines and consumes
only the structural durable execute-once capability contract. It does not
import Control. The embedding owns the durable signer implementation and
trusted clock. The parent also approved the configured resolver instance and
authenticated revocation-universe design. The design and implementation plan
are recorded beside this report.

### Fix-round-4 GREEN and full verification

Fresh completed-patch evidence:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/snapshot-topic-runtime.test.ts src/agent-moderation.test.ts \
  src/agent-authorship.test.ts src/nostr.test.ts \
  src/social-events.test.ts src/social-nip72.test.ts \
  src/atproto-did-resolution.test.ts src/social-atproto.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  10 passed (10)
Tests       154 passed (154)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

Snapshot verification authored only into its disposable temporary raw root
and compared read-only with the pinned historical package.

The broader generator suite was also attempted as a non-gating integration
diagnostic: 50/56 files and 731/769 tests passed. Its 38 failures are outside
Task 7 ownership and arise in the concurrently unfinished OIDC continuity
schema/persona migration, maintained guides/Control wording, and dependent
author/coverage/versioning projections. None reported a Task 7 source or
focused-test failure; the requested family and exact-482 lanes above remain
the Task 7 gates.

### Ownership expansion, costs, and self-review

Existing approved Task 7 ownership of `agent-authorship.ts`/tests expanded
from the superseded two-stage proof to the atomic signed-publication authority.
The structural contract deliberately duplicates no Control policy or state;
the cost is a small family-layer-safe interface plus immutable signed-result
verification. Existing `atproto-did-resolution.ts` ownership expanded to the
configured authority and durable evidence reconstruction; it adds local
embedding configuration/evidence, not a global resolver key or registry wire
authority.

The complete diff was reviewed for one trusted-time sample, final state before
signing, attribution before the immutable snapshot, one execute-once call,
strict NIP-01 equality, signed-input rejection, post-sign non-retroactivity,
proof burning, authority-instance identity, deep cloning/freezing, closed
evidence/config separation, anchor/policy/version/TTL enforcement, historical
validation time, current freshness, authenticated-universe coverage,
sibling/reset/incompatible revocation rejection, registry revision/digest
stability, and prohibited paths. `git diff --check` was clean. No approved-
design contradiction or blocker remains.

Fix-round-4 commit message: `fix: bind Social authority instances`.

## Fix round 5/5

The final security round closes publication-authority replay, mutable signer
outcomes, unobserved backdated ATProto history, and cross-pubkey lineage
influence:

- Comms signed-publication proofs now bind their exact issuing authority.
  `createSocialAuthorshipValidator` creates the embedding's authority-bound
  Social validation closure; the authority-agnostic Social entry point cannot
  consume automation proofs. The Comms authority captures its trusted clock
  and bound `executeOnce` function at construction, so later caller mutation
  cannot replace the signer boundary. A backdated attacker authority cannot
  mint a proof accepted by the expected validator.
- The execute-once outcome is read once through own property descriptors into
  one independent closed plain-data snapshot. Accessors, symbols, sparse
  arrays, extra members, nonordinary prototypes, and cycles reject. All strict
  NIP-01 validation, exact unsigned comparison, proof state, and return use the
  same deeply frozen event snapshot. The implementation makes no generic claim
  that JavaScript can detect every Proxy; a Proxy can participate only in the
  single descriptor capture and cannot substitute afterward.
- The configured resolver authority now authenticates a separate durable,
  domain-separated binding-observation envelope. It commits the exact binding
  event id/hash, DID, pubkey, generation, observation time, canonical
  checkpoint reference, referenced resolution-envelope hash, policy, and
  version. The observation must be at or after event creation and inside the
  authenticated resolution interval. Historical-only lineage and revocation
  targets require this evidence; only the single selected current event may
  rely on a resolution fresh at trusted current time.
- Resolver and observation evidence themselves cross a one-descriptor-read
  closed-data snapshot boundary before parsing and signature verification.
  This was an additional Critical issue found during the required full
  security self-review: accessor-backed resolution evidence could previously
  be accepted and reread.
- Binding validation now receives the exact expected canonical DID and raw
  lowercase pubkey before selection. Candidates, history, and revocation
  authority are confined to that coordinate. Another pubkey's same-DID
  lineage and revocation are independent and cannot suppress the expected
  coordinate. Raw carrier enums were removed from binding evidence.

Registry revision `14` and entry-set digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No registry, schema, frozen topic/vector, snapshot,
projection, baseline/report/debt, or release artifact was modified, and no
repository authoring command was run.

### Fix-round-5 RED evidence

Every production behavior change followed an executable exploit failure:

```text
exact Comms/Social authority instance and immutable executeOnce capture:
  replacement method was invoked; configured Social validator absent       2 failed / 33

one-read signer-result snapshot:
  accessor showed valid event A for seven checks then returned event B;
  open signer result was accepted                                           2 failed / 23

durable resolver-signed observation API:
  authenticated observation producer/validator absent                       1 failed / 4

historical existence:
  expired generation-one history without prior observation was accepted     1 failed / 1

exact DID/pubkey coordinate:
  another pubkey's newer same-DID revoked branch rejected this coordinate   1 failed / 1

security-audit accessor boundary:
  accessor-backed resolver evidence was accepted and reread                  1 failed / 1

selected-current observation exception:
  unobserved non-selected sibling gained historical revocation authority    1 failed / 1
```

The written design records the parent's adjustment that JavaScript cannot
generally prove Proxy absence. It therefore specifies a single descriptor
capture and independent snapshot rather than a false proxy-rejection claim.
The parent approved reuse of the configured resolver authority anchors and
policy/version boundary for the separate observation domain; no global
resolver or observation key was introduced.

### Fix-round-5 GREEN and full verification

Fresh completed-patch evidence after the final security-audit fixes:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/snapshot-topic-runtime.test.ts src/agent-moderation.test.ts \
  src/agent-authorship.test.ts src/nostr.test.ts \
  src/social-events.test.ts src/social-nip72.test.ts \
  src/atproto-did-resolution.test.ts src/social-atproto.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  10 passed (10)
Tests       163 passed (163)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

Snapshot verification authored only into its disposable temporary raw root
and compared read-only with the pinned historical package.

### Ownership expansion, costs, and final security self-review

Approved Task 7 ownership of `agent-authorship.ts`, `social-events.ts`,
`atproto-did-resolution.ts`, `social-atproto.ts`, their focused tests, and the
two affected normative specifications expanded only along their existing
Comms-to-Social and local resolver boundaries. Two small descriptor snapshot
implementations remain local to those boundaries to avoid importing Social or
resolver policy into Comms; the cost is deliberate structural duplication,
while family layering remains intact and Comms imports no Control module.

The complete final diff was reviewed for exact proof-authority identity,
wrong-authority non-consumption, one-use burning, immutable function capture,
one trusted-time sample, no post-sign retroactive denial, a single signer-
result descriptor capture, no source reread, strict snapshot/event equality,
closed observation fields and domain, resolver anchor/policy/version/TTL,
observation timing and resolution hash, selected-current-only exception,
persistable fresh-verifier history, exact DID/pubkey preselection, independent
other-pubkey lineages, authenticated revocation universe, sibling/reset/fork
behavior, current DID-key revocation, family layering, prohibited paths,
registry revision/digest stability, and frozen artifacts. `git diff --check`
was clean. No approved-design contradiction or remaining Critical/Important
Task 7 concern was found.

The required independent-review dispatch was attempted at the final boundary,
but the collaboration service reported its agent thread limit. The complete
security review above was therefore performed inline; the parent already has
the prior broad-suite diagnostic for concurrent non-Task-7 failures.

Fix-round-5 commit message: `fix: close Social authority replay`.

## Post-round boundary correction

This integration-safety correction closes caller-controlled aliasing across
the complete Comms publication request, the complete ATProto binding and
revocation input universe, and the durable historical observation. It is not
a sixth fix round. The parent approved module-local schema-specific capture
helpers and observation domain `heterodyne-atproto-binding-observation-v2`
with field `did_signature_digest`.

Comms now captures the top-level publication request's exact own data
descriptors before any semantic read. One captured authority identity is used
unchanged for its WeakMap lookup, trusted clock, execute-once signer, and proof
branding. Registration, token, unsigned event, content, feed, resource,
destination, execution token, and digest are independently copied into closed
deep-frozen data. The current token has an exact member set; no caller object
is spread or reread. The authority itself remains opaque and is not traversed
or frozen by the capture path.

ATProto binding and direct-revocation entry points likewise capture the
complete input once, retain only the exact resolver-authority reference, and
deep-freeze the candidate, lineage, revocation, binding, resolution,
observation, and Nostr-event trees. Selection retains the exact checked
record and seeds it directly into the historical/revocation universe instead
of rereading selected evidence during a second pass. Direct revocation also
canonical-parses the captured target binding before verification.

Durable binding observations use v2 and commit SHA-256 of the exact 64-byte
DID signature. Observation authentication re-verifies the exact strict Nostr
event, author, kind, time, canonical content, coordinate tags, binding hash,
named DID method, DID signature, signed resolution interval, checkpoint,
policy, version, resolution hash, and resolver observation signature. Social
captures one resolution evidence value and reuses it for the DID proof and
observation proof. A valid alternative DID signature cannot be substituted
after an observation for another signature, and a resolution accessor cannot
present different documents to the two proof paths.

### RED evidence

Every production boundary had an observed exploit-first failure:

```text
npm --prefix docs/spec/vectors/generator test -- src/agent-authorship.test.ts
Test Files  1 failed (1)
Tests       3 failed | 23 passed (26)

authority A -> B:
  current code signed under authority A and returned a proof branded to B
small -> 5000-byte content:
  current code authorized the small value and signed the later oversized value
allowed -> different destination:
  current code authorized the first feed value and stored the later value;
  that failing first loop case stopped RED before the equivalent resource case,
  while the final GREEN run executes and rejects both feed and resource cases

npm --prefix docs/spec/vectors/generator test -- src/social-atproto.test.ts
Test Files  1 failed (1)
Tests       1 failed | 10 passed (11)

candidate A -> B:
  current selection retained revoked binding A, the second history pass read B,
  and the valid revocation of A disappeared from the universe and was accepted

npm --prefix docs/spec/vectors/generator test -- src/social-atproto.test.ts
Test Files  1 failed (1)
Tests       4 failed | 8 passed (12)

observation v2 and exact DID-signature proof:
  the v1-only validator rejected valid v2 historical evidence and did not bind
  the observation to the newly required DID-signature digest/dual-proof input
```

The first draft of the signature-substitution probe placed an observation on
the fresh selected current candidate. That candidate intentionally may rely
on current resolution and omit historical observation, so the probe was
corrected before GREEN to place the substituted observation in required
historical lineage. The final executable test uses two independently valid DID
keys/signatures: history attested for signature A rejects when evidence
substitutes valid signature B. The resolution A-to-B accessor probe is also on
required historical lineage.

### GREEN and verification evidence

Fresh focused and required lane results:

```text
npm --prefix docs/spec/vectors/generator test -- --run \
  src/snapshot-topic-runtime.test.ts src/agent-moderation.test.ts \
  src/agent-authorship.test.ts src/nostr.test.ts \
  src/social-events.test.ts src/social-nip72.test.ts \
  src/atproto-did-resolution.test.ts src/social-atproto.test.ts \
  src/registry.test.ts src/schema.test.ts
Test Files  10 passed (10)
Tests       168 passed (168)

npm --prefix docs/spec/vectors/generator run build
node scripts/typecheck.mjs (exit 0)

npm --prefix docs/spec/vectors/generator run family:check -- "$PWD"
validated protocol document family (exit 0)

npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
verified 482 vectors from source
2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43 at snapshot
5d4bb5fb58b35c88d8a9db120a09f1087237f35c (exit 0)
```

The broader `draft:check` integration diagnostic completed build and then
reported the pre-existing/concurrently owned result of 50/56 test files and
745/783 tests passing. Its 38 failures remain in OIDC continuity schema/topic
migration, maintained guide/Control assertions, author/coverage/versioning
projections, and their verify dependents. None names a changed Task 7 source or
focused test. Family validation and the exact-482 history-bound snapshot lane
passed independently.

### Ownership expansion, costs, and security self-review

Approved Task 7 ownership expanded only within `agent-authorship.ts`,
`social-atproto.ts`, `atproto-did-resolution.ts`, their focused tests, the two
affected normative paragraphs, and this SDD design/plan/report. Keeping the
capture helpers module-local deliberately duplicates a small structural
routine so Comms never imports Social/resolver policy and opaque authority
identity is handled by each exact embedding boundary.

The complete correction diff was reviewed for one top-level descriptor
capture, data-descriptor-only nested copies, no caller spread/reread, no
authority traversal, exact authority reuse, trusted-time/sign/proof identity,
content and destination immutability, dense arrays, exact token and evidence
members, candidate/history/revocation snapshot coverage, exact selected-record
seeding, source-neutral coordinate selection, current-candidate observation
exception, historical observation requirement, strict NIP-01 verification,
DID signature/method verification, v2 canonical field order and digest,
single resolution reuse, malformed-input fail-closed behavior, family
layering, and frozen/prohibited paths. Registry revision `14` and digest
`9839393f2e11430ce9c19bde009228b71dc7f5c7268215960d39ecab0461a6fc`
remain unchanged. No frozen topic, vector, snapshot, projection, baseline,
debt, release artifact, or authoring output was modified.

Correction commit message: `fix: snapshot Social trust inputs`.
