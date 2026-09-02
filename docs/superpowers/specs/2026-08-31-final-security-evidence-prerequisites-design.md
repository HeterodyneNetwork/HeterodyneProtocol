# Executable security-evidence prerequisites design

**Status:** Approved architectural addendum for implementation planning

**Approved:** 2026-08-31

**Parent design:**
`docs/superpowers/specs/2026-08-29-heterodyne-0.6-final-security-closure-design.md`

**Registry transition:** immutable revision 16 to immutable revision 17

**Lifecycle constraint:** ADR-048 remains `Proposed` throughout this work.

## 1. Decision and purpose

Task 10 exposed a real evidence gap. Forty-six current cases reached their
terminal result through policy shims whose security-relevant inputs were
caller-supplied booleans or caller-selected state. Removing those labels from
semantic coverage correctly leaves six live security invariants and forty
registry reasons without executable evidence. The partially completed Task-10
dispatcher and certificate hardening is retained, but it cannot turn those
terminal shapes into security proof.

The approved repair is **mixed retirement plus real authority boundaries**:

1. retire only obsolete, duplicate, or contradictory diagnostics and retain
   their history as explicit non-wire exclusions;
2. keep current diagnostics that do not claim a protocol security fact clearly
   classified as diagnostic-only;
3. replace every remaining live caller-controlled shim with an opaque verifier-
   minted authority or state view backed by actual signatures, authenticated
   current state, and durable replay/effect control; and
4. resume semantic certificates only after those prerequisites exist.

This addendum does not restore static contract labels, accept a boolean as
evidence, or weaken complete coverage. It adds no network service and does not
make a Heterodyne-aware relay, modified Radicle node, modified Marmot
implementation, directory, or identity provider mandatory.

## 2. Exact evidence deficit

The following six registry invariants are live and presently uncovered after
the caller-shim claims are removed. They remain normative and must receive real
executable evidence:

- `COMMS-I-MARMOT-ACCOUNT-IDENTITY`
- `COMMS-I-MARMOT-SECRET-CONFINEMENT`
- `COMMS-I-RADICLE-NON-ERASURE`
- `WORKSPACE-I-CARRIER-NOT-AUTHORITY`
- `WORKSPACE-I-INHERITANCE-NARROWS`
- `WORKSPACE-I-NO-AMBIENT-AUTHORITY`

The forty uncovered reason codes have the following exact dispositions.

### 2.1 Retired semantics retained as non-wire history

These eleven reasons no longer describe current executable protocol behavior.
Revision 17 retains their identifiers and `first_version`, points them to
explicit retired-semantics anchors, and adds precise entries to
`NON_WIRE_REASON_EXCLUSIONS`. Their current cases are removed; Git history is
the executable record of the old behavior.

| Owner | Retired cases | Retained non-wire reasons |
|---|---|---|
| Assurance | `assurance/retired-key-post-compromise` | `revoked_key_post_compromise` |
| Core | `core/retired-key-authority-window-invalid` | `retired-key-authority-window-invalid` |
| Comms | `comms/dm-invite-revoked-device`, `comms/dm-invite-unbound-device` | `dm_invite_revoked_device`, `dm_invite_unbound_device` |
| Control | `control/agent-attribution-bypass-prohibited`, `control/agent-human-profile-prohibited`, `control/agent-key-access-prohibited`, `control/agent-method-prohibited`, `control/agent-resource-denied`, `control/request-id-conflict`, `control/signed-event-invalid` | `agent-attribution-bypass-prohibited`, `agent-human-profile-prohibited`, `agent-key-access-prohibited`, `agent-method-prohibited`, `agent-resource-denied`, `control-request-id-conflict`, `control-signed-event-invalid` |

Retiring the Assurance duplicate does not retire
`ASSURANCE-I-COMPROMISE-CUTOFF`. Its live evidence remains
`assurance/authority-at-compromise-cutoff` through the real
`evaluateAssuranceAuthorityAt` boundary. Retiring the Control diagnostics does
not relax attribution-before-signing, exact grants, or at-most-once execution;
those invariants remain covered by the existing real publication, grant, and
signer-fence boundaries.

### 2.2 Diagnostic-only current classification

`comms/auth-rejected-permanent` and `auth_rejected_permanent` remain a useful
local classification of a relay write failure. They do not establish
`COMMS-I-MARMOT-UPSTREAM-AUTHORITY` or any other security invariant, and a
relay-provided outcome is not cryptographic authority. Revision 17 classifies
the reason as diagnostic/non-wire for semantic-coverage purposes with a
specific justification. The case may remain a terminal-output test, but it
cannot mint a semantic certificate or satisfy reason closure.

### 2.3 Live reasons requiring real evaluators

The following twenty-eight reasons remain current. None may be excluded or
certified through a caller boolean.

| Workstream | Live reasons |
|---|---|
| Comms Marmot and agent authority | `agent-sender-proof-invalid`, `conversation-rejected`, `invite-authentication-invalid`, `marmot-agent-scope-denied`, `marmot-keypackage-replayed`, `marmot-premature-ack`, `marmot-private-inbox-nid-required` |
| Control existing and new authority | `control-compromise-reset-evidence-invalid`, `control-compromise-reset-inventory-mismatch`, `control-compromise-reset-unauthenticated`, `control-subordinate-reauthorization-required`, `control-device-code-display-mismatch`, `control-device-code-invalid`, `control-device-code-rate-limited`, `control-enrollment-unavailable`, `control-frame-invalid`, `invite-preauthorization-invalid`, `control-keypackage-invalid`, `control-keypackage-replenishment-paused`, `control-signer-effect-indeterminate`, `control-token-invalid` |
| Workspace current state and replay | `capability_escalation`, `policy_denied`, `workspace_replay` |
| Core selection and operational state | `profile-repository-selection-required`, `relay_profile_mutation`, `strict_mode_tor_disabled`, `unauthorized_cache_content` |

The exact current negative or indeterminate cases to replace with those live
boundaries are:

- Comms: `comms/agent-sender-proof-invalid`,
  `comms/conversation-rejected`, `comms/invite-authentication-invalid`,
  `comms/marmot-agent-scope-denied`, `comms/marmot-keypackage-replayed`,
  `comms/marmot-premature-ack`, and
  `comms/marmot-private-inbox-nid-required`;
- Control: `control/compromise-reset-evidence-invalid`,
  `control/compromise-reset-inventory-mismatch`,
  `control/compromise-reset-unauthenticated`,
  `control/subordinate-reauthorization-required`,
  `control/device-code-display-mismatch`, `control/device-code-invalid`,
  `control/device-code-rate-limited`, `control/enrollment-unavailable`,
  `control/frame-invalid`, `control/invite-preauthorization-invalid`,
  `control/keypackage-invalid`, `control/keypackage-replenishment-paused`,
  `control/signer-effect-indeterminate`, and `control/token-invalid`;
- Workspace: `workspace/carrier-not-ambient-authority`,
  `workspace/inheritance-escalation-rejected`,
  `workspace/invitation-replay`, and
  `workspace/revocation-blocks-future-effect`; and
- Core: `core/friend-cache-unsigned`,
  `core/profile-repository-selection-required`, `core/relay-profile-mutated`,
  and `core/strict-mode-without-tor`.

Five live positive cases also require real evidence even though they carry no
reject reason: `comms/agent-workload-token-accepted`,
`comms/marmot-exact-bytes-durable`,
`comms/marmot-expiration-not-erasure`,
`comms/marmot-ordinary-welcome-held`, and
`workspace/current-capability-intersection`. The indeterminate
`control/signer-effect-indeterminate` case must carry its registered semantic
reason only from the real signer fence.

## 3. Common authority rule

Every new or rebound security boundary follows one flow:

```text
untrusted bytes or host observation
  -> bounded capture of an exact closed input
  -> cryptographic and schema verification
  -> authenticated current-state resolution
  -> opaque authority-minted artifact or view
  -> durable acquire/CAS when use is consuming
  -> effect or decision
  -> committed, rejected, or indeterminate terminal
  -> boundary-specific semantic certificate
```

Opaque artifacts are frozen empty public objects backed by module-private
records. A record binds the minting authority instance, immutable captured
input, exact verification result, current-state checkpoint/revision, purpose,
and a canonical binding digest. Plain lookalikes, clones, proxies, accessors,
post-validation mutations, artifacts from another authority, and stale views
fail closed. Authority constructors capture embedding callbacks and trust roots
once; callers cannot replace them per operation.

The authorities are local interfaces over standard protocol inputs. They do
not become wire objects unless a live specification already defines the signed
object or token. No new public boolean such as `valid`, `authorized`,
`canonical`, `current`, `unused`, `durable`, `subscribed`, or `effect_applied`
may cross an authority boundary.

## 4. Comms prerequisites

### 4.1 Marmot admission, archive retention, inbox, and invites

`VerifiedMarmotWelcome` is minted only after exact Marmot account, Welcome,
KeyPackage, group, member, and capability checks over captured bytes.
`MarmotAdmissionAuthority` consumes that artifact plus its own authenticated
local acceptance and current conversation state. This proves standard active-
key account identity, independent leaf/secret confinement, ordinary-Welcome
holding, and `conversation-rejected` without caller assertions.

`MarmotArchiveRetentionAuthority` accepts exact signed Marmot event bytes or
encrypted media ciphertext and returns an opaque append receipt only after the
same bytes are durably reachable from the authorized repository ref. The
receipt binds repository RID, ref, object digest, source-event digest, and
commit identity. Acknowledgement is forbidden before that receipt exists.
Expiration removes current presentation or authorization but does not erase
retained ciphertext or history, which gives real evidence for exact-byte
durability, non-erasure, and `marmot-premature-ack`.

`PersonaInboxAdmissionAuthority` captures the recipient inbox policy, current
NID-bearing authorization, one selected unconsumed KeyPackage, sender-specific
ref, purpose, and group transition. It decides
`marmot-agent-scope-denied`, `marmot-keypackage-replayed`, and
`marmot-private-inbox-nid-required` from authenticated state.

`OneTimeInviteAuthority` verifies the signed purpose-bound invite and response,
secret proof, recipient binding, expiry, and current revocation state. It uses
a restart-stable reservation/terminal store. The exact same completed retry
returns the cached result; a different purpose, transcript, recipient, or
secret conflicts; unknown post-effect state is indeterminate and never grants
admission. This boundary owns `invite-authentication-invalid`.

The obsolete device-state DM invite reasons are not recreated inside these
authorities.

### 4.2 Agent workload JWT and publication authorization

`AgentPublicationAuthorizationAuthority` consumes:

- a cryptographically verified workload JWT with exact issuer, audience,
  subject, persona, agent, signer, scope, expiry, status, and ledger-generation
  bindings;
- proof of possession verified from exact DPoP bytes or the configured mTLS
  peer identity, including method/target/nonce binding and replay state;
- current opaque claim-ledger authorization artifacts; and
- the exact proposed publication and registered attribution profile.

It returns an opaque one-use `VerifiedAgentPublicationAuthorization`. The
publication signer consumes that artifact under the existing durable signing
fence. The agent never receives a persona, human-device, agent-service, or
repository private key. A reused proof, different publication, stale token,
changed claim view, or wrong signer fails closed and supplies real evidence for
`agent-sender-proof-invalid`; a genuine accepted path supplies evidence for
`comms/agent-workload-token-accepted`.

## 5. Control prerequisites

### 5.1 Rebind existing real boundaries

The current policy wrappers are removed from semantic authority. Current cases
call the already implemented boundaries directly:

- `validateCompromiseReset` owns the three compromise-reset rejection reasons
  and `control-subordinate-reauthorization-required` from signed grants,
  authoritative inventory/evidence, current Assurance authority, and exact
  completion state;
- `executePersistedAutomatedSigning` owns
  `control-signer-effect-indeterminate` and its restart-stable no-duplicate-
  signing terminal; and
- the real Control frame/profile parser, signature verification, request
  binding, and version negotiation own `control-frame-invalid`.

Fixture adapters may project those results, but may not summarize them into
booleans before execution.

### 5.2 New device, enrollment, invite, and token authorities

`ControlDeviceAuthorizationAuthority` owns RFC 8628 transaction creation and
polling state. It binds high-entropy device/user codes, client and persona,
displayed verification information, polling interval, failure budget, expiry,
and invalidation. Its durable state machine produces the three
`control-device-code-*` reasons from actual state transitions.

`ControlEnrollmentAdmissionAuthority` owns pending-group capacity, reserved
slots, invite purpose, exact KeyPackage verification, replenishment state,
expiry, rate limits, and current enrollment state. Its authenticated snapshot
produces `control-enrollment-unavailable`, `control-keypackage-invalid`, and
`control-keypackage-replenishment-paused` without accepting precomputed
capacity or validity flags.

`verifyControlInvitePreauthorization` verifies the signed fragment envelope,
non-convertible purpose, exact client-key binding, current revocation and
expiry, and the rule forbidding prompt-free KERI-authorized devices. It returns
an opaque `VerifiedControlInvitePreauthorization` or
`invite-preauthorization-invalid`.

`ControlTokenVerifier` validates the actual node-scoped OIDC JWT, issuer and
audience, token class, sender key, Marmot group, grant, generation, status,
expiry, and per-use proof against a current opaque grant view. It returns an
opaque one-use `VerifiedControlToken`; structural token summaries and token-
valid booleans are rejected. Failure maps to the existing confidentiality-
preserving `control-token-invalid` reason.

## 6. Workspace prerequisite and capability ceiling

Workspace uses the existing real state machinery:
`createWorkspaceRepositoryResolverAuthority`,
`authenticateWorkspaceRepositoryView`,
`resolveWorkspaceEffectiveAuthorization`,
`consumeWorkspaceInvitationAcceptance`, and `evaluateGrantActivation`.
Fixtures contain real signed role, grant, revocation, relationship, and
invitation objects. Function-bearing resolver authority remains private and
never crosses a serialized vector boundary.

The root role's `allowed_capabilities` is the workspace-wide ceiling. Effective
authorization is the intersection of:

1. the authenticated root role ceiling;
2. every authenticated ancestor role's narrowing set;
3. the selected current grant and relationship state;
4. subject, resource, action, and hosting constraints; and
5. all current revocations and expiries.

No descendant, grant, relationship, carrier, host, repository location, or
transport can add a capability absent from the root ceiling. An attempted
increase returns `capability_escalation`; absent or revoked authority returns
`policy_denied`. This supplies real evidence for the three uncovered Workspace
invariants and the current-capability-intersection positive case.

Invitation acceptance is a consuming transition. The exact invitation,
workspace, recipient, role, capability ceiling, state checkpoint, and nonce
are reserved by durable CAS before activation. Exact committed retries return
the cached acceptance; mismatched or already-consumed attempts return
`workspace_replay`; an unknown post-effect outcome is indeterminate and cannot
activate a grant until reconciled.

## 7. Social signed-subscription prerequisite

The current Social moderation result must not depend on caller-provided
`subscribed`, `canonical`, `receipt_valid`, or authorship booleans.
`SocialSubscriptionAuthority` verifies real signed agent-policy receipts and
policy-list events, applies source-neutral replaceable selection, resolves the
client's explicit local subscription, and binds each selected receipt to the
exact offending author/device key. It returns an opaque
`SubscribedAgentPolicyView` consumed by the existing authorship and moderation
evaluators.

An unsubscribed, invalid, stale, relay-only, unmerged, corrected, or removed
list grants no moderation authority. A default subscription remains visible
and removable. Policy authority stays subscriber-local; no registry entry,
moderator, carrier, or repository gains global power. This task replaces the
remaining structural Social subscription path even though the current
forty-six-case removal does not create a new registry-closure count for it.

## 8. Core and Assurance prerequisites

`CanonicalProfileSelectionAuthority` captures valid signed kind `0`
candidates from relays and authorized repository refs, applies exact NIP-01
replaceable selection without carrier priority, authenticates the repository
writer where applicable, and returns an opaque current profile view. Missing
authenticated repository state when the selected profile requires it produces
`profile-repository-selection-required`.

`CoreOperationalAssuranceAuthority` replaces the catch-all operational boolean
shim with three exact adapter views:

- a verified cache-candidate view whose content must be signed by the actual
  persona author, otherwise `unauthorized_cache_content`;
- an exact raw-event/carrier view that recomputes the NIP-01 ID and signature
  over retained bytes, otherwise `relay_profile_mutation`; and
- a captured client-role and transport-configuration view that proves the
  strict profile's Tor requirement, otherwise `strict_mode_tor_disabled`.

These are local conformance authorities, not new relay or Tor protocols.
Outside the strict profile, absence of Tor remains conforming when disclosed by
the existing reduced-assurance rules.

The retired-key classification shims are removed from Core and Assurance.
Current compromise cutoff, associated-key revocation, and source-neutral
profile selection remain governed by their existing real evaluators.

## 9. Durability, replay, and failure behavior

Every consuming authority uses a caller-independent store with atomic
acquire/CAS and restart-stable integrity protection. Its key includes every
security-relevant binding, not merely a nonce or event ID. The common states
are `available`, `executing`, `committed`, and `indeterminate`:

- persistence failure before acquisition performs no effect and returns a
  retriable fail-closed result;
- only an exact persisted `executing` record authorizes one effect;
- a successful effect is not exposed as accepted until its terminal commit is
  readable and binding-equal;
- an effect timeout, thrown effect after possible execution, unknown store
  response, or terminal-write failure becomes absorbing `indeterminate`;
- exact committed retries return byte-identical cached output;
- exact indeterminate retries reconcile boundedly and never repeat the effect;
  and
- mismatched retries, cross-authority artifacts, stale checkpoints, malformed
  callbacks, and callback exceptions never authorize.

Public errors preserve the specification's existing confidentiality
granularity. Detailed internal failure conditions may enter protected audit
state but do not create a side channel or an unregistered public reason.

## 10. Registry revision 17

Revision 16 and all earlier history remain byte-identical. After every live
semantic boundary and specification anchor is settled, one registry task:

1. retargets the eleven retired reason entries to explicit owner-document
   retired-semantics anchors while preserving identifier, owner, status, and
   `first_version`;
2. keeps `auth_rejected_permanent` current but anchors its diagnostic-only,
   non-authoritative meaning;
3. preserves all live reason and invariant identities, updating descriptions
   or anchors only where the real authority contract requires precision;
4. adds only concrete allocations required by the completed implementations,
   with their full schemas, proof domains, descriptions, and spec anchors in
   the same patch; this design anticipates no new wire object for a local
   opaque authority; and
5. authors immutable revision 17 exactly once and verifies its digest and full
   revision-history identity preservation.

No task before this one edits registry entry JSON. The non-wire exclusion table
is updated with exact, individually justified entries in the same closure
task, so the registry and coverage policy cannot disagree between commits.

## 11. Resume Task 10

The unbypassable evaluator dispatcher, exact invocation receipt, and opaque
certificate work already produced for Task 10 is paused, not discarded. After
revision 17:

- current cases invoke only the real authorities above;
- retired cases disappear and diagnostic-only cases carry no invariant or
  semantic-reason allocation;
- each live allocation names a boundary-specific predicate over the exact
  fixture, evaluator invocation transcript, opaque result identity, terminal
  state, and postcondition;
- no `terminal-output-only`, generic-shape, same-verdict, or copied-label path
  may satisfy invariant or reason coverage; and
- invariant, reason, profile, owner, and spec-reference closure must all be
  empty before Task 10 commits.

The certificate dispatcher remains evidence plumbing. It does not implement or
substitute for Comms, Control, Workspace, Social, Core, or Assurance authority.

## 12. Implementation order and gates

The prerequisite wave is sequential because later certificate and registry
work consumes stabilized semantics:

1. retire obsolete Assurance, Core, Comms, and Control diagnostics;
2. add Marmot admission, archive/retention, inbox, and invite authorities;
3. add agent workload JWT and DPoP/mTLS publication authorization;
4. rebind existing real Control frame, reset, and signer boundaries;
5. add Control device, enrollment, invite, and token authorities;
6. migrate Workspace cases to real signed resolver state and invitation replay,
   with root `allowed_capabilities` as the workspace ceiling;
7. add signed Social subscribed-policy composition;
8. add real Core profile-selection and operational authorities;
9. author immutable registry revision 17 once; and
10. resume Task 10's dispatcher, fixtures, predicates, and certificates.

Each semantic task starts with a focused failing test, implements only its
owned boundary and live artifacts, runs its focused tests plus
`build:current`, and lands as one independently reviewable commit. A fresh
reviewer audits the exact task diff for specification fidelity, trust-boundary
closure, durability/replay behavior, fixture realism, and scope. Critical or
Important findings return to the owning worker for a bounded fix commit and
fresh re-review. Registry 17 and resumed Task 10 each receive their own commit
and independent review.

Final source closure requires focused suites, registry/schema/profile/
invariant/reason closure, `build:current`, `draft:check`, family checks,
docs-lint, `git diff --check`, and the repository's shared conformance gate.
Generated rolling-snapshot files, `snapshot.json`, snapshot metadata,
projections, counts, and digests remain untouched; reconciliation stays
deferred to the dedicated later snapshot task.

## 13. Defensive assurance and scope limits

Every hostile-boundary test is a **BLUE TEAM VALIDATION: synthetic/local**
defensive assurance exercise. It uses only the smallest deterministic,
non-deployable repository fixture and isolated local process needed to prove
rejection, no unauthorized state or effect, no disclosure, bounded work,
replay resistance, or correct reconciliation.

No test or implementation step may contact or target a live relay, Radicle
node, Marmot deployment, identity provider, account, credential, user data,
third-party system, or external service. The work creates no functional
exploit, reusable payload, scanning, persistence, evasion, destructive action,
or control-weakening instruction. If validation would require any such action,
the task stops at a non-operational vulnerability assessment and requests
maintainer direction.

ADR-048 remains `Proposed`. This wave does not accept or archive it, merge the
branch, create or update a pull request, tag a version, publish a release,
deploy software, alter repository-host settings, or mutate live infrastructure.
