# Heterodyne Assurance Protocol Specification

Document ID: `assurance`

Assurance is an optional section of the Heterodyne specification and is
governed by
[`heterodyne:0.6.0#core-document-conventions`](heterodyne-core.md#core-document-conventions),
which fixes the family version, registry pin, BCP 14 usage, canonical key and
JSON forms, and conformance rules.

Normative dependencies:

- [`heterodyne:0.6.0#core-active-key-persona`](heterodyne-core.md#core-active-key-persona)
  supplies the active-key persona and baseline NIP-01 identity.
- [`heterodyne:0.6.0#core-verification`](heterodyne-core.md#core-verification)
  supplies exact NIP-01 event verification.
- [`heterodyne:0.6.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes)
  supplies domain-separated proof bytes.

Assurance has no other normative dependency.

<a id="assurance-scope"></a>
## 1. Scope and optionality

Assurance defines an optional continuity layer for a Core active-key persona:
reciprocal cold-root enrollment, KERI-style pre-rotation and witnesses,
active-key succession and recovery, associated-key state, pinning and
downgrade resistance, and lossless KERI export.

A bare active Nostr key is a complete, first-class Heterodyne persona. Core,
Comms, Control, Social, Workspace, ordinary Nostr, and ordinary Marmot
baseline validity MUST NOT depend on Assurance enrollment, a cold root, an
epoch policy, a witness, a threshold, a chain head, or an associated key.
Implementations MAY report that enhanced assurance is present, absent,
predated, unavailable, or invalid, but MUST NOT call an unassured Core-valid
persona invalid or incomplete.

Assurance proves a relationship among distinct signed events and keys. It
MUST NOT alter NIP-01 identifier, signature, author, address, filter,
replaceable-event, or relay semantics. It MUST NOT alias two Nostr public
keys, rewrite an old event, or turn one key's signature into authorship by
another. It likewise MUST NOT alter the active Nostr key used as a Marmot
account identity, alias two Marmot accounts, select MLS state, or transfer an
MLS leaf.

<a id="assurance-record-envelope"></a>
## 2. Record envelope and common contract

The four current Assurance records are addressable Nostr events. Their exact
contents are the closed schemas below:

| Kind | Profile | Schema |
|---|---|---|
| `31002` | `heterodyne.assurance.enrollment-inception.v1` | [`enrollment-inception-v1.schema.json`](schemas/assurance/enrollment-inception-v1.schema.json) |
| `31000` | `heterodyne.assurance.active-key-acceptance.v1` | [`active-key-acceptance-v1.schema.json`](schemas/assurance/active-key-acceptance-v1.schema.json) |
| `31003` | `heterodyne.assurance.succession.v1` | [`succession-v1.schema.json`](schemas/assurance/succession-v1.schema.json) |
| `31001` | `heterodyne.assurance.associated-key.v1` | [`associated-key-v1.schema.json`](schemas/assurance/associated-key-v1.schema.json) |

Every content object contains exactly its schema members, including
`profile`, `spec_version`, `active_key`, `created_at`, and `predecessor`.
`spec_version` is exactly `heterodyne/0.6.0`. `active_key`, event IDs,
commitments, and Nostr keys are 64 lowercase hexadecimal characters.
Signatures are 128 lowercase hexadecimal characters. `created_at` equals the
outer event's integer `created_at`. `predecessor` is `null` only in an
inception; every other record requires a 64-hex predecessor event ID.

The outer NIP-01 `pubkey` is always the key that actually signed the event.
The `active_key`, `cold_root`, `issuer`, `subject_key`, and proof keys inside
content do not replace it. A verifier MUST first complete Core NIP-01
identifier and BIP-340 verification, then validate the decoded content
against its registered schema, and only then evaluate Assurance authority.
An invalid Assurance object cannot make that same event or persona invalid
for an unrequested Core baseline claim.

The content string is the RFC 8785 JCS serialization of the closed content
object. Each event has exactly one `d` tag and one
`["profile","<profile>"]` tag matching content. Producers use these exact
identifiers:

- inception: `d = assurance-inception:<active_key>`;
- acceptance/head: `d = assurance-head`;
- succession: `d = assurance-succession:<previous_head>`; and
- associated key: `d = assurance-associated:<active_key>:<role>:<subject_key>`.

Inception, succession, and associated-key events carry exactly one `p` tag
for `active_key`; succession additionally carries one `p` tag for
`new_active_key`. Unknown or duplicate binding tags, a content/tag mismatch,
or a non-canonical identifier is `assurance-schema-invalid`.

Relays and repositories carry the same complete NIP-01 event unchanged.
Repository storage does not add authority and a repository copy does not
outrank a different valid relay candidate. A consumer unions events by Nostr
event ID and applies ordinary NIP-01 addressable-event selection only within
one exact author/kind/`d` coordinate. Assurance chain validation then applies
the explicit predecessor and authority rules below; carrier order is never a
tie-breaker.

<a id="assurance-reciprocal-enrollment"></a>
## 3. Reciprocal enrollment

An existing active-key persona MAY attach Assurance without changing its
active key, npub, profile coordinate, Marmot account, or prior event history.
Enrollment is complete only after both records below validate.

### 3.1 Cold-root inception

The kind `31002` inception has `predecessor:null`. Its outer `pubkey` and
content `cold_root` are identical. The record binds the target `active_key`,
the cold recovery root, an optional `succession_authority` represented by a
64-hex key or `null`, one `epoch_policy`, a duplicate-free witness array, and
the epoch and witness thresholds. It also fixes one closed
`associated_key_policy`. That policy has separate `active_key` and
`epoch_threshold` arrays of exact role-and-scope grant ceilings; either array
may be empty, and absence of a ceiling grants nothing.

The inception's event ID and outer signature are called the
`inception_event_id` and `cold_root_signature`. The cold-root secret SHOULD
remain offline except for enrollment, recovery, or an explicit downgrade
ceremony. It does not routinely author persona events.

### 3.2 Active-key acceptance and head

The active key publishes kind `31000`. Its outer `pubkey` equals
`active_key`. On initial enrollment, `predecessor`, `inception_event_id`, and
`assurance_head` all equal the exact inception event ID, `cold_root` equals
the inception cold root, and `cold_root_signature` byte-for-byte equals that
inception's outer signature. `state` is `assured` and
`downgrade_consent` is absent. Its outer and content `created_at` MUST be equal
and MUST be greater than or equal to the inception event's outer and content
`created_at`. Equality is valid; an acceptance before inception is
`assurance-reciprocal-proof-invalid`.

After an accepted succession, the new active key publishes the same profile
with the original inception binding retained and with `predecessor` and
`assurance_head` equal to the accepted succession event ID. The new
acceptance event ID becomes the current Assurance head. This required
active-key event makes enrollment and every successor reciprocal; embedded
new-key proof alone does not create a head.

A verifier rejects missing or mismatched halves with
`assurance-reciprocal-proof-invalid`. Events authored before the initial
acceptance remain valid Nostr events but are described as predating enhanced
assurance. Enrollment is never backdated.

<a id="assurance-keri-policy"></a>
## 4. KERI-style epoch and witness policy

`epoch_policy.mode` is `none` or `pre-rotation`. Under `none`,
`current_keys` and `next_key_commitments` are empty and the epoch threshold
is zero. Under `pre-rotation`, both arrays are non-empty and duplicate-free,
the epoch threshold is at least one and no greater than the number of current
keys, and every next-key commitment is SHA-256 over one exact 32-byte future
epoch public key. The committed key is not authoritative until a valid
succession reveals it and makes it current in `next_epoch_policy`.

Each witness entry contains one distinct BIP-340 witness key and a positive
integer weight. The witness threshold is zero only when the witness array is
empty; otherwise it is positive and no greater than the sum of configured
weights. A succession counts at most one valid receipt per configured witness
key and only from the witness set fixed by its predecessor. Informal vouches,
duplicate receipts, unconfigured keys, malformed signatures, and receipts
over a different claim contribute zero weight. If the required weight is not
reached, evaluation fails with
`assurance-witness-threshold-unsatisfied`.

An epoch-threshold authorization contains distinct `authority_proofs` from
keys in the predecessor's `current_keys`; their count reaches the predecessor
epoch threshold. When pre-rotation is in use, every key newly placed in
`next_epoch_policy.current_keys` has a matching predecessor commitment.
`next_epoch_policy`, `witnesses`, and `thresholds` become the exact policy for
the next accepted head. This is KERI-style pre-rotation and first-seen
witness evidence expressed in Heterodyne's Nostr event records; KERI wire
encodings are export formats, not Heterodyne transport objects.

`associated_key_policy.active_key` and
`associated_key_policy.epoch_threshold` are distinct authority classes. Each
entry binds one exact `role` and a duplicate-free scope ceiling. An issued
scope is authorized only when every requested member is contained in one
entry for that same role and authority class; verifiers MUST NOT union
ceilings from multiple entries or infer a broader namespace. The inception
policy applies to the initial accepted head. A succession carries the complete
replacement as `next_associated_key_policy`; it becomes effective only after
the new active key accepts that exact succession.

<a id="assurance-chain-validation"></a>
## 5. Chain validation and heads

A verifier starts from a reciprocally accepted inception and replays exact
event bytes. For every next record it MUST:

1. require `predecessor` to equal the current accepted head;
2. require every repeated active key, prior head, inception ID, cold root,
   and signature to equal the state it claims to continue;
3. validate all authority, acceptance, witness, threshold, and commitment
   evidence against the predecessor policy;
4. reject a cycle, skipped head, unknown profile, or carrier-derived
   authority; and
5. advance only after the new active-key kind `31000` acceptance confirms the
   exact succession.

A wrong predecessor is `assurance-predecessor-mismatch`; a wrong explicit
head is `assurance-head-mismatch`. Competing individually valid successors of
one head are `assurance-duplicity` and stall continuity unless the
predecessor's witness evidence uniquely satisfies one branch. Arrival time,
relay count, repository location, and a later Nostr timestamp MUST NOT select
an otherwise ambiguous branch.

<a id="assurance-enrollment-tiebreak"></a>
A conflict between two individually valid enrollments E1 and E2 for one active
key resolves to E1 instead of stalling only when both hold: E1 carries a
matured OpenTimestamps attestation under
[`heterodyne:0.6.0#core-ots-anchor`](heterodyne-core.md#core-ots-anchor)
proving it existed at least 604,800 seconds before E2's earliest provable
existence — E2's own attestation time if anchored, otherwise E2's earliest
witnessed observation — and E1 carries conflict-free witness receipts covering
that same period. Existence evidence without the observation trail MUST NOT
resolve a conflict: a withheld enrollment has no receipts, so a secretly
anchored enrollment published later cannot displace an established one.
Conflicts meeting neither condition stall exactly as above. Arrival order,
relay count, and `created_at` still select nothing.

<a id="assurance-succession"></a>
## 6. Active-key succession and cold-root recovery

A kind `31003` succession has `active_key === previous_active_key` and
`predecessor === previous_head`, where both name the accepted state being
replaced. It binds the distinct `new_active_key`, closed
`authorizing_evidence`, a `new_key_acceptance`, transition `class`, the next
succession authority, epoch and witness policy, associated-key issuance
policy, and an explicit `subordinate_reauthorizations` array.

All `authority_proofs`, the `new_key_acceptance`, and every witness receipt
MUST sign the same 32-byte transition digest for proof domain
`heterodyne-assurance-succession-transition-v1`. The digest input is the
entire closed succession content object with exactly these signature-value
locations deleted:

- `authorizing_evidence.authority_proofs[*].signature`;
- `authorizing_evidence.witness_receipts[*].signature`; and
- `new_key_acceptance.signature`.

The corresponding authority keys, witness keys, acceptance key, profile,
version, old and new active keys, predecessor and previous head, creation
time, class and optional compromise time, `next_succession_authority`, entire
next epoch, witness, threshold, and associated-key policies, and every
subordinate reauthorization remain in the JCS object. The transition digest
is the Core domain-separated JCS SHA-256 digest of that object. No producer or
verifier may omit another member, substitute a per-proof claim, or accept a
proof made over a different digest. Thus changing any security-relevant
transition member invalidates every copied authority, acceptance, and witness
proof.

`new_key_acceptance.key` equals `new_active_key` and its signature verifies
under that key. A mismatch is `assurance-new-key-acceptance-invalid`.
For a routine succession, the outer event MUST be signed by the old
`active_key`. Its authority class is either `succession`, using the exact
designated succession authority, or `epoch-threshold`, using distinct current
epoch keys that reach the predecessor threshold. `recovery` is forbidden on
a routine transition. The record explicitly fixes the nullable
`next_succession_authority`; an old authority never transfers implicitly.
Missing, duplicate, insufficient, stale, or wrong-purpose proof is
`assurance-authority-invalid`.

Any succession made without the old active key is a compromise/recovery
transition: `class` is `compromise`, `authority_class` is `recovery`, the
outer signer is the current cold root, `compromise_time` is present, and
`subordinate_reauthorizations` is empty. The new key supplies its acceptance
proof. The
outer event `pubkey` equals the cold root because it is the actual event
signer; this does not make the event a Nostr event by the old or new active
key. The new active key becomes the Core persona only for its own future
events and only after it publishes its head acceptance.

A successor is a new Nostr identity and a new Marmot account. Assurance MAY
present a verified continuity history, but follows, moderation, repositories,
Marmot groups and leaves, financial permission, delegates, clients, agents,
and application authorization do not move merely because succession
validated. Historical events remain authored by their original public keys.

<a id="assurance-associated-keys"></a>
## 7. Associated keys

Kind `31001` records the complete current grant or revocation for one
associated Nostr key. Its outer `pubkey` equals `issuer`. `active_key` names
the persona and `assurance_head` equals the accepted Assurance head. On the
first record for one issuer/active-key/role/subject coordinate, `predecessor`
equals that head; afterward it equals the prior record for that same
coordinate. The record binds exact `role`, duplicate-free
`scope`, `issuer`, `subject_key`, creation time, optional exclusive
`expires_at`, `visibility`, and `state`.

The record contains closed `issuer_authority` with class `active-key` or
`epoch-threshold`. For `active-key`, `issuer` and the outer `pubkey` both equal
the current active key, `authority_proofs` is empty, and the requested role
and scope narrow one `associated_key_policy.active_key` ceiling. For
`epoch-threshold`, `issuer` and the outer `pubkey` equal one key in the current
epoch set, distinct proof keys are all in that set and reach the current epoch
threshold, and the role and scope narrow one
`associated_key_policy.epoch_threshold` ceiling. A subordinate associated key
is never itself an issuer merely because it is associated or reauthorized.

Epoch-threshold issuer proofs and an active public-agent subject proof use the
same Core domain-separated JCS digest for domain
`heterodyne-assurance-associated-key-record-v1`. Its input is the entire
closed associated-key content object with exactly
`issuer_authority.authority_proofs[*].signature` and `subject_proof` deleted;
the proof keys and every other member remain bound. The active-key authority
class uses only its outer NIP-01 signature and carries no embedded authority
proof.

An associated key is active only while its
selected record has `state:"active"`, verifier time is before `expires_at`
when present, the head is still accepted, and the use is inside every scope
dimension. Expiry returns `assurance-associated-key-expired`. A selected
`state:"revoked"` record contains the closed `revocation` object and returns
`assurance-associated-key-revoked`; revocation is absorbing for that
predecessor chain and cannot be undone by replaying an earlier grant.

A public `role:"agent"`, `visibility:"public"`, `state:"active"` grant
requires `subject_proof` by `subject_key` over that exact record digest.
Absence and invalidity yield
`assurance-associated-key-subject-proof-required` and
`assurance-associated-key-subject-proof-invalid`, respectively. A revocation
MUST omit `subject_proof`: the currently authorized issuer can revoke a
compromised, unavailable, or unwilling subject without its cooperation. The
issuer authorization and outer signature still bind the entire revocation,
and a valid revocation remains absorbing. Private
client and human-delegate associations SHOULD remain in protected
repositories unless policy explicitly requires publication; private records
may omit subject proof. Association never changes the NIP-01 author: when the
subject key signs an event, that subject key is the author.

<a id="assurance-pinning"></a>
## 8. TOFU, pinning, and discovery loss

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
`31006` enrollment contest conforming to
`schemas/assurance/enrollment-contest-v1.schema.json`, signed by the same
active key. A contest or a competing enrollment observed during any verifier's
window makes the enrollment non-pin-eligible wherever observed, with reason
`assurance-enrollment-contested`; the persona remains baseline. A key thief
can therefore deny Assurance but cannot gain recovery authority over the
owner: denial is bounded harm, because a bare-key holder can already
impersonate at baseline.

A client with no prior Assurance state MAY use trust on first use only after
validating reciprocal enrollment and its completed window. It pins at least
the active key,
inception event ID, cold root, accepted head event ID, state, and observation
time. A stronger local trust source MAY replace TOFU before the first pin.

Once pinned, state is advanced only by a valid descendant or explicit
downgrade. Removing `identity_chain`, `cold_root`, or
`succession_authority` from kind `0`, editing the profile in a vanilla client,
losing a relay or repository, receiving a stale head, or seeing a conflicting
hint MUST NOT erase or weaken the pin. The client retains the last valid pin,
reports unavailable or conflicting enhanced assurance, and continues to
evaluate ordinary Core events independently. A non-descendant conflict is
`assurance-pin-conflict`.

Pins SHOULD be stored in local rollback-resistant state and MAY be exported
with their observed event IDs. Backup or synchronization of a pin MUST
preserve its full value and provenance; a partial hint is not a pin.

<a id="assurance-downgrade-resistance"></a>
## 9. Explicit downgrade

A pinned persona cannot remove or weaken Assurance with the active key alone.
Downgrade is a kind `31000` record with `state:"downgraded"`, outer
`pubkey === active_key`, `predecessor` and `assurance_head` equal to the
current accepted head, and the original inception binding retained.
`downgrade_consent.recovery_authority` equals the current cold root.

The recovery authority signs Core domain-separated bytes for domain
`heterodyne-assurance-downgrade-v1` over exactly:

```json
{
  "active_key": "<current active key>",
  "assurance_head": "<current accepted head>",
  "created_at": 0,
  "inception_event_id": "<original inception event id>",
  "predecessor": "<current accepted head>"
}
```

The outer active-key NIP-01 signature and that recovery-authority proof are
both required. Missing either is `assurance-downgrade-consent-required`.
Profile-field disappearance, an active-key-only tombstone, an unsigned local
request, and a server policy change are not consent. If the active key is
unavailable, the recovery authority performs succession to a fresh active
key; it does not silently downgrade the old pin.

A valid downgrade becomes the retained terminal pin for that enrollment. It
does not invalidate older events or claim that enhanced assurance never
existed. Reattachment requires a new reciprocal inception and acceptance;
clients retain the prior downgraded pin as history.

<a id="assurance-compromise"></a>
## 10. Compromise behavior

A succession with `class:"compromise"` requires `compromise_time`; a routine
succession forbids it. The cutoff is ordered
`current_head.created_at <= compromise_time <= succession.created_at`. A
compromise succession uses `authority_class` equal to `recovery`, is
outer-signed by the cold root, and otherwise follows the recovery rules
above. The effective cutoff is `compromise_time`. Assurance
does not retroactively change NIP-01 cryptographic validity: events by the old
key remain valid signatures by that key. For an explicitly requested
Assurance claim, however, old-key and subordinate authority whose `created_at`
is at or after the cutoff is rejected with `assurance-compromise-cutoff`. The
equality case is rejected; only material strictly before the cutoff can
retain an enhanced claim.

`subordinate_reauthorizations` is exactly empty for compromise. Every agent,
delegate, client, node, repository writer, application grant, and other
subordinate relationship requires a fresh post-compromise record. A non-empty
array or attempted implicit continuation is
`assurance-subordinate-continuation-forbidden`.

The operator MUST separately revoke old NIP-46 and OIDC sessions, remove old
Marmot leaves, advance reachable groups to fresh cryptographic state, publish
fresh KeyPackages for the successor account, and mark groups unable to move
as compromised or stalled. Those are explicit Control, Comms, or application
operations. Assurance evidence cannot perform them or alias the old and new
Marmot accounts.

<a id="assurance-keri-export"></a>
## 11. KERI export

`assurance.keri-export.v1` exports the accepted exact-byte Assurance chain,
epoch commitments, controller proofs, witnesses, weights, thresholds, and
receipts into a canonical KERI representation. Export is a derived view. It
MUST NOT replace the Nostr events, active npub, event IDs, pin, or validation
source.

Before emitting an export, the implementation maps every security-relevant
source construct and verifies that the target cryptographic suites are
available. A construct with no semantics-preserving mapping fails with
`export_unmappable_feature`; an unavailable suite fails with
`export_unsupported_crypto_suite`; missing accepted source events or
attachments fail with `export_incomplete`. The exporter MUST NOT omit,
weaken, approximate, or silently translate the failed construct. A derived
KERI AID or DID is not a Nostr alias and substituting it for the active npub
is `export_aid_substituted_for_npub`.

KERI10JSON and CESR MAY be emitted as export artifacts. They are not accepted
as Heterodyne relay or repository records; presenting them in place of the
registered Nostr events is `keri_wire_format_rejected`.

<a id="assurance-failure-outcomes"></a>
## 12. Failure outcomes

Assurance evaluation returns one of `verified`, `unassured`, `pending`,
`predated`,
`unavailable`, `stalled`, `downgraded`, or `invalid`, plus the applicable
registered reason code for a rejection. `unassured` is a factual absence, not
a failure. `pending` reports a validated enrollment whose observation window
has not yet elapsed; it contributes no enhanced claim and preserves the Core
verdict. `predated` means the Nostr event precedes reciprocal enrollment.
`unavailable` retains an established pin while evidence sources cannot be
reached. `stalled` retains the last unique head while a fork or missing
threshold prevents advancement. `downgraded` records valid dual consent.

An Assurance failure changes only the requested enhanced claim. The caller
MUST preserve the independently computed Core verdict. It MUST NOT translate
`assurance-pin-conflict`, `assurance-duplicity`, missing evidence, expiry, or
any other Assurance result into a bad NIP-01 signature, invalid Marmot
account, or missing Core persona.

<a id="assurance-retired-wire-profiles"></a>
## 13. Retired pre-redesign allocations

Kinds `31005` and `31007` remain allocated only so historical material can be
recognized and decoded. This specification defines no current identity
pointer, feed-index profile, feature, discovery requirement, publication
requirement, or conformance behavior for either kind. The live registry has
no profile on them.

Historical refusal names such as `successor_persona_mismatch`,
`retiring_key_nip05_invalid`, `compromise_rotation_breadcrumb_forbidden`,
`nid_binding_missing_signature`, and `kel_revoked_nid` remain registered for
decoding already-authored pre-redesign material. They do not activate a live
profile or make legacy state authoritative. Current discovery uses Core kind
`0`, NIP-05, kind `10002`, ordinary relay filters, and optional repository
access.

The historical domains `heterodyne-nid-binding-v1` and
`heterodyne-agent-signing-binding-v1` likewise remain allocated for their
exact pre-redesign proof bytes. They grant no current associated-key,
repository-writer, agent, or persona authority by themselves.

<a id="assurance-security"></a>
## 14. Security invariants

Assurance implementations preserve these registered invariants:

- **ASSURANCE-I-CORE-OPTIONALITY:** Absent, invalid, stale, or withdrawn Assurance cannot invalidate a Core-valid active-key persona or alter NIP-01 or Marmot identity semantics.
- **ASSURANCE-I-RECIPROCAL-ENROLLMENT:** Assurance attaches only when a cold-root inception and no-earlier active-key acceptance bind the same exact active key, inception event, and cold-root signature.
- **ASSURANCE-I-ENROLLMENT-WINDOWED:** No enrollment is pin-eligible before 604800 seconds of observably public, conflict-free existence; contests and competing enrollments fail closed to baseline, and a conflict resolves only to an enrollment with both materially earlier proven existence and witness receipts spanning the gap.
- **ASSURANCE-I-TRANSITION-PROOF-BINDING:** Every succession authority proof, new-key acceptance, and witness receipt binds one identical digest containing every closed transition member except the proof signature values themselves.
- **ASSURANCE-I-PIN-DOWNGRADE:** A pinned Assurance state survives disappearing or conflicting hints and can be downgraded only by the active key plus current recovery authority.
- **ASSURANCE-I-SUCCESSION-NON-ALIASING:** A verified successor proves continuity but remains a distinct Nostr author and Marmot account whose authority does not silently inherit.
- **ASSURANCE-I-COMPROMISE-CUTOFF:** A compromise succession rejects Assurance authority at or after its effective cutoff and carries no subordinate continuation.
- **ASSURANCE-I-NO-IMPLICIT-CONTINUATION:** Succession transfers no succession authority, associated-key issuance policy, subordinate key, repository, group, delegate, financial, or application authority unless the record explicitly reauthorizes it.
- **ASSURANCE-I-ASSOCIATED-KEY-BOUNDS:** Associated keys are accepted only for their exact head, active-key or epoch-threshold issuance ceiling, narrowed role and scope, issuer, subject, time bounds, active-grant proof requirements, and non-revoked state.
- **ASSURANCE-I-EXPORT-LOSSLESS:** KERI export either preserves every security-relevant accepted Assurance semantic or fails without emitting a misleading partial identity.

<a id="assurance-continuity-conformance"></a>
## 15. Optional conformance claims

An implementation that does not implement Assurance claims Core and any
other implemented documents normally and makes no Assurance claim. No warning
or reduced baseline label is required.

An implementation claiming `assurance.continuity.v1` MUST implement the four
record-envelope checks relevant to continuity, reciprocal enrollment, chain
and head validation, KERI-style epoch and witness policy, routine and
compromise succession, pin retention, cold-root recovery, and dual-consent
downgrade. Succession validation includes the one exact transition digest,
old-active routine participation, recovery-only compromise transitions,
cutoff ordering, current-policy authority and witness proof, and new-key head
acceptance before policy advancement. It claims the Assurance document and
its applicable registered invariants.

`assurance.associated-keys.v1` additionally requires the full kind `31001`
grant/revocation contract, exact active-key and epoch-threshold issuer-policy
evaluation, narrowed scope, active public-agent proof, issuer-only
revocation, expiry, and absorbing revocation.
`assurance.keri-export.v1` additionally requires
lossless export or the exact defined failures. Both features require
`assurance.continuity.v1`.

Minimum Assurance validation coverage includes a first-class persona with no
Assurance; later reciprocal enrollment; invalid and mismatched enrollment;
TOFU and retained pins after hint disappearance; routine, recovery, forked,
and compromise succession; cutoff enforcement; empty compromise
continuations; explicit routine reauthorization; public-agent subject proof;
associated-key expiry and revocation; active-key-only downgrade rejection;
dual-consent downgrade acceptance; and lossless and failed KERI export.
