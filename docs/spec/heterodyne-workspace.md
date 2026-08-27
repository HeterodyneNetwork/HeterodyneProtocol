# Heterodyne Workspace Protocol Specification

Document ID: `workspace`

Workspace is a section of the Heterodyne specification and is governed by
[`heterodyne:0.6.0#core-document-conventions`](heterodyne-core.md#core-document-conventions), which fixes the family version,
the registry pin, release status, BCP 14 usage, and the anchor and reference
forms.

<a id="workspace-scope"></a>
## 1. Scope and non-goals

Workspace defines the organizational control plane for independently
governed public and private collaboration. It specifies:

- workspace identity and threshold governance;
- roles, concealed subroles, inheritance, grants, and revocations;
- explicit invitations and bilateral affiliation allowances;
- resource, host, relay, project, group, artifact, and service discovery;
- Marmot/MLS carriage for private role control and resource-key delivery;
- Radicle-backed durable authority and transport;
- bounded offline authorization and deterministic conflict handling; and
- host-owned and jointly governed cross-workspace resources.

Workspace does not define source-forge objects, package or artifact formats,
workflow execution, search, notifications, presence, user interfaces, a new
messaging protocol, MLS cryptography, or Radicle replication. Native resource
protocols retain their own state, keys, and lifecycle rules. Vanilla Nostr
relays and ordinary Radicle nodes do not interpret Workspace objects.

<a id="workspace-conventions"></a>
## 2. Conventions and data model

Workspace JSON objects follow [`heterodyne:0.6.0#core-canonical-json`](heterodyne-core.md#core-canonical-json).

`workspace_key`, account identifiers, device keys, and signing keys are
lowercase 64-character hexadecimal secp256k1 x-only public keys. Human-facing
NIP-19 strings are presentation encodings and MUST be decoded before inclusion
in a Workspace object. `policy_head`, `authority_checkpoint`, `checkpoint_id`,
`relationship_id`, `grant_id`, `revocation_id`, `resource_id`, `predecessor`,
and envelope digests are lowercase 64-character SHA-256 values. Radicle
repository identifiers begin with `rad:`. Git object IDs are lowercase 40-character
SHA-1 values because the adopted Radicle substrate uses that object format;
[`heterodyne:0.6.0#core-security`](heterodyne-core.md#core-security) bounds what that format is trusted for.

Every signed object contains `spec_version:"heterodyne/0.6.0"`, its exact
`object_type`, `workspace_key`, `policy_head`, nullable `predecessor`,
`authority_checkpoint`, `repository_rid`, `repository_head`, and `issued_at`.
`workspace_key` is the workspace's current active Nostr public key and the
exact BIP-340 verification key for `signature`. A bare key with no Assurance
state is complete baseline authority.

The signature covers the
[`heterodyne:0.6.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes) bytes for domain
`heterodyne-workspace-object-v1`. Its bound members are
`authority_checkpoint`, `body`, `issued_at`, `object_type`, `policy_head`,
`predecessor`, `repository_head`, `repository_rid`, `spec_version`, and
`workspace_key`. `body` is every remaining schema-defined member except
`signature`; for `workspace-relationship-v1`, it also excludes
`receiving_signature` so both active workspace keys sign identical terms.
`signature` and `receiving_signature` are lowercase 128-character BIP-340
signatures.

`repository_head` is a git object ID and therefore the one 40-character value
in a signed object; every other digest-shaped member is 64-character SHA-256.
Every Workspace timestamp, age, epoch, sequence, threshold, priority, and
count is a finite nonnegative JSON integer no greater than
`9007199254740991`; narrower limits stated below still apply. Producers and
consumers MUST reject fractional, negative, non-finite, unsafe, overflowed,
or ill-ordered numeric values before evaluating authority.

`policy_head`, `predecessor`, and `authority_checkpoint` bind the object to one
exact, unambiguous current authorization view. `repository_rid` and
`repository_head` bind its durable carrier context but grant no authority.

A consumer MUST obtain that view through a locally configured repository
verification boundary; a caller-supplied head, ancestry, fork flag,
checkpoint, object list, revocation assertion, or freshness claim has no
authority. The boundary authenticates one closed
`heterodyne.workspace-repository-view.v1` record containing exactly `profile`,
`spec_version`, `resolver_policy`, `resolver_version`, `workspace_key`,
`repository_rid`, `canonical_head`, `canonical_ancestry`, `observed_heads`,
`fork_status`, `policy_head`, nullable `predecessor`, `authority_checkpoint`,
`object_ids`, `object_set_digest`, `observed_at`, `expires_at`, and
`signature`. `signature` is made by a locally configured trusted repository
verification key over proof bytes for domain
`heterodyne-workspace-repository-view-v1`. The configured policy and minimum
resolver version MUST establish the Radicle repository boundary's canonical
RID, reachable current head, complete fork observation, checkpoint, trusted
observation time, and complete signed object set.

`object_ids` is the unique, strictly increasing byte-sorted array of SHA-256
JCS object identifiers; set-equivalent reordering is invalid.
`object_set_digest` is SHA-256 of proof bytes for domain
`heterodyne-workspace-object-set-v1` over exactly that array. A consumer MUST
strictly validate the complete current policy, role, grant, revocation,
resource, relationship, receiving relationship-receipt, joint-relationship,
checkpoint, and resource-key-envelope objects, their active-key signatures,
cross-references, and common authority tuple before deriving any effective
authorization or relationship. A missing or extra object, untrusted resolver,
unreachable or rolled-back head, incomplete or competing fork observation,
stale observation, digest mismatch, or later use under another configured
resolver instance or repository view fails closed.

For each workspace/RID pair, the resolver retains one latest accepted
generation and head. Every operation that consumes a current-state or opaque
authorization, relationship, invitation, successor, or joint-governance
handle MUST require that exact latest generation, read trusted time, and
revalidate the complete signed object set at effect time. Superseded,
not-yet-observed, expired, or over-age views fail with `checkpoint_stale`.
The effect-time pass rechecks signatures, policy and role parent chains,
per-role checkpoints, grants, relationships, resources, effective/expiry
times, and every revocation whose transition time has arrived. A previously
valid opaque handle is not a capability token that survives newer state.
For each accepted workspace/RID ancestry, the resolver also retains an
immutable map from every observed `envelope_id` to that envelope's canonical
JCS object identity. A later generation MAY retain or reintroduce the same
identity, including after an intervening omission, but any conflicting reuse
of that ID fails closed before the generation becomes current.

The SHA-256 digest of the complete JCS object including `signature` is its
object identifier unless a field-specific identifier is defined. Consumers
MUST reject a digest mismatch, invalid signature, active-key mismatch,
predecessor discontinuity, stale checkpoint, repository head not reachable
from the accepted authority branch, or conflicting valid heads. Git commit
authorship, repository ownership or write permission, trusted-seed status,
relay acceptance, Marmot membership or administration, custody, and hosting
status are carriers or service roles, not Workspace governance authority.

<a id="workspace-identity"></a>
## 3. Workspace identity and governance

A workspace is an independently governed Core active-key account under
[`heterodyne:0.6.0#core-active-key-persona`](heterodyne-core.md#core-active-key-persona).
Human and organization accounts use the same wire model. The current
`workspace_key` is the workspace npub and Marmot account identity. Multiple
workspaces operated by one organization use distinct active keys when they
are intended to remain independently governed. They MAY publish signed
parent, peer, or joint relationships, but no relationship merges or aliases
their Nostr identities.

The stable workspace repository contains exactly one current
`workspace-manifest-v1`, the root `workspace-policy-v1`, and the append-only
history from which both are derived. Its canonical authority branch is the one
unambiguous policy-approved predecessor and checkpoint chain. A public
workspace MAY advertise this repository
from its public account profile. A private workspace has no required public
projection; an invitation or relationship conveys the active workspace key,
private locator, current policy/checkpoint context, and exact Marmot account,
device, and leaf binding needed by the recipient.

Human delegates and agents request organization-key actions through an exact
current Workspace policy decision and, where remote signing is used, the
account-specific NIP-46/OIDC authorization in
[`heterodyne:0.6.0#control-signer-grants`](heterodyne-control.md#control-signer-grants)
and current Comms authorization state. The public Workspace proof remains a
signature by `workspace_key`; private requester identity remains in protected
audit state unless policy requires disclosure. A signer MUST NOT use
cross-account fallback, a broader grant, or stale policy state.

Optional Assurance may prove continuity to a successor active key, but it
does not alias the old and new workspaces. Succession transfers no role,
relationship, resource, repository, seed, host, custody, delegate, or
group-administrator authority automatically. Every surviving subordinate
authority MUST be explicitly reauthorized under the successor key and current
policy.

Such transfer is represented by one closed
`heterodyne.workspace-successor-reauthorization.v1` record containing exactly
`profile`, `spec_version`, `workspace_key`, `prior_account`, `new_account`,
`prior_key`, `new_key`, `prior_device`, `prior_leaf`, `new_device`, `new_leaf`,
`role_id`, nullable `resource_id`, `scope`, `prior_grant_id`,
`pending_grant_id`, nullable `pending_envelope_id`, nullable
`pending_key_epoch`, nullable `pending_custody_host_id`, nullable
`pending_checkpoint_id`, `policy_head`, nullable `predecessor`,
`authority_checkpoint`, `repository_view_id`, `issued_at`, `effective_at`,
`expires_at`, `workspace_signature`, and `new_account_signature`. Both
signatures cover every other member with proof bytes for domain
`heterodyne-workspace-successor-reauthorization-v1`; the current workspace key
and new account key sign independently. The prior and new keys MUST equal
their named active accounts. The current view MUST prove the prior account's
unrevoked exact active grant, device, and leaf. The new device and leaf MUST be
distinct from the prior ones, absent from active prior-view membership, and
bound to the named pending grant. `scope` MUST be exactly `role-membership`
with null resource and envelope IDs, or `resource-key` with the exact current
resource and a pending signed envelope bound by ID to the exact pending grant,
new account, device, leaf, role, resource, key epoch, custody host, and
checkpoint. The prior leaf proves only former authority;
it is never a recipient for successor delivery. An ID, continuity boolean,
ambient account transfer, stale record, or record bound to another current
view cannot reauthorize membership or key delivery. Every use rechecks both
grants, the envelope when applicable, freshness, effective/expiry time, and
current revocation state.

Workspace membership is affiliation only. It MUST NOT grant ambient access to
any role or resource. Every resource access decision is evaluated through an
explicit effective role path.

`workspace-policy-v1` establishes governance thresholds, role-creation and
resource-creation ceilings, permitted visibility, allowed relationship types,
default hosts, maximum freshness, and which operations require approval,
acceptance, or waiting periods. Threshold-changing, root-policy, publicization,
federation, joint-governance, and workspace-archive operations require the
root policy's governance approvals.

<a id="workspace-privacy"></a>
## 4. Visibility and non-disclosure

A workspace or role has visibility `public`, `selective`, or `private`.
`public` is a role with explicit policy, never an authorization bypass.
Public directories list only deliberately public roles and resources.

Private role identifiers MUST be uniformly random 256-bit values. Private
role names, identifiers, policy, membership, counts, locators, MLS group IDs,
host advertisements, relationships, and subordinate resources MAY be
disclosed only to:

1. workspace governance with explicit discovery authority;
2. an authorized parent-role administrator;
3. a direct member or explicit invitee; or
4. a subject qualifying under a valid bilateral allowance.

Ordinary parent-role members do not learn that a private child exists. Public
objects MUST NOT contain a private object's identifier, digest, member count,
encrypted placeholder, stable blinded value, or other correlatable projection.
A producer detecting such a projection MUST reject it with
`private_topology_disclosed` before publication.

Private repositories MUST combine Radicle replication authorization with
application encryption. Radicle authorization limits enumeration and
replication; encryption protects repository contents and implements explicit
key epochs. Neither substitutes for the other.

<a id="workspace-role-repositories"></a>
## 5. Role repositories

Every role has a stable role authority repository. The role is a subordinate
authority object of its workspace, not an independent KERI identity. The
repository contains the role manifest, applicable policies, grants,
revocations, materialized checkpoints, advertisements, private child
references visible to the reader, its role-control-group binding, and active
and archived event-repository locators.

The stable role repository is an independently keyed resource. Its current
materialized state is encrypted with its current repository key; historical
Git objects remain encrypted under their historical key epochs. A private
role's active and archived event repositories are private Radicle
repositories as well.

High-volume Marmot traffic MUST NOT accumulate in the stable authority
repository. It uses the [`heterodyne:0.6.0#comms-marmot-event-repository`](heterodyne-comms.md#comms-marmot-event-repository)
layout and rotates to a fresh repository when either:

- a membership-changing MLS commit establishes a new group epoch; or
- the active repository reaches the maximum size that
  [`heterodyne:0.6.0#comms-marmot-event-repository`](heterodyne-comms.md#comms-marmot-event-repository) fixes.

The stable role repository records the new active locator, the immediately
prior overlap locator, and retained archives. At most one active repository
is selected for a given role MLS epoch. Conflicting valid selections are an
authority conflict and fail closed.

Every effective role configuration MUST retain at least one authorized
Radicle locator and one eligible Radicle-backed relay host. A role or resource
MAY replace or supplement inherited hosts, but cannot remove that transport
backstop. Public roles may expose it openly; private roles restrict it to
authorized peers. Optional Nostr relays carry the exact same signed Marmot
event bytes and MUST NOT alter, re-sign, translate, or synthesize them.

A private repository-backed relay composes
[`heterodyne:0.6.0#comms-trusted-seed-private-relay`](heterodyne-comms.md#comms-trusted-seed-private-relay).
Its current ACL `administrator_account` is the active `workspace_key`; the ACL
MUST exactly bind the authenticated member account, read/write role, Marmot
`h`, private RID, seed NID and writer ref, predecessor, group transition, and
expiry. The Workspace embedding captures the expected Comms admission authority
configured with that active key and passes only its opaque one-request
capability to the composed evaluator; request fields cannot select an
administrator, seed, ACL, authenticated account, transition, or clock.
Missing, stale, expired, conflicting, replayed, revoked, unauthorized,
ambiguous, or route-mismatched state fails closed. An admitted seed writes
only its authorized ref and gains no repository-owner, workspace, role,
custody, signer, or Marmot-administrator authority.

<a id="workspace-role-policy"></a>
## 6. Roles, capabilities, and inheritance

The common capability vocabulary is `read`, `write`, `triage`, `moderate`,
`admin`, and `invite`. Resource profiles define their operational meaning.
`invite` is independently delegable. `admin` does not imply any of these
governance capabilities:

- `govern-policy`;
- `govern-subroles`;
- `govern-thresholds`;
- `govern-publicize`;
- `govern-federation`;
- `govern-delegation`; or
- `govern-lifecycle`.

Effective authorization is the intersection of the current workspace ceiling,
each role policy on one unambiguous parent path, current account membership or
qualifying allowance, current device authorization, resource-local policy,
and time/key-epoch state. A child role or resource MAY narrow inherited
authority. It MUST NOT widen authority beyond the workspace ceiling. An
explicit denial, expiry, suspension, or revocation at any level wins.

If a client cannot construct one unambiguous current path, or encounters
conflicting or incomparable valid heads, it MUST reject the operation with
`authority_conflict`. Resource-local exceptions are effective only where the
workspace policy expressly permits their type and maximum capability set.

Role membership is evaluated continuously. Signed role checkpoints provide a
deterministic materialization for bounded offline decisions; they do not copy
role membership into resource ACLs. A checkpoint sorts policy heads, active
grants, revocations, relationships, hosts, trusted-seed NIDs, and resources by
their binary identifier bytes, then hashes the JCS materialization.
Every current role has exactly one current checkpoint. The authenticated
object set may contain multiple roles, but every non-root role MUST resolve a
complete acyclic parent chain and every grant, resource, relationship, and
checkpoint MUST bind the role to which it applies. Missing parents, duplicate
checkpoints, cross-role materializations, or a child that widens capability,
visibility, delegation, history, or selected-snapshot authority fail closed.
Each checkpoint's `role_policy_heads` is the exact unique byte-sorted set of
JCS object identifiers for every role manifest on that role's complete
root-to-leaf path; a missing, stale, extra, or phantom head fails closed. Role
visibility MUST narrow the workspace `visibility_ceiling`, each child MUST
narrow its parent, and each resource MUST narrow every role in its path.
`visibility:"public"` additionally requires
`workspace-policy-v1.allow_public_resources:true`.

<a id="workspace-grants"></a>
## 7. Grants, revocations, and invitations

A `role-grant-v1` names one active account subject, exact capabilities,
resource scope, delegability, activation, expiry, invitation evidence, and
required approval object IDs. The authenticated requester MUST possess
`invite` or the explicit grant capability for the target scope, and the
active-key signer MUST evaluate that request against the exact current policy
and checkpoint. Neither may grant broader or more delegable authority than
the requester holds. That evaluation MUST first produce one closed current
effective-authorization result bound to the actor account, workspace key,
policy head, predecessor, unique authority checkpoint, and grant-operation
digest. The grant's capabilities, resource scope, and delegability MUST each
be a subset of every applicable workspace, role-path, resource, and actor
ceiling; intersecting only a selected ceiling or accepting caller-asserted
capability strings is invalid. Denial, effective revocation, inactive device
state, a conflicting checkpoint, or any tuple mismatch prevents activation.
Separate grants MUST NOT be unioned to manufacture a capability/resource/
delegability combination that no one current unrevoked grant permits; the
effective result binds one deterministic qualifying grant ID, the ordered IDs
of every role on its complete parent path, and every broader current ceiling.
Every later effect re-resolves those exact objects under the resolver's latest
generation and rechecks account, device, resource, activation, expiry,
earliest transition, and revocation state.

The grant-operation digest is SHA-256 of
[`heterodyne:0.6.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes)
for domain `heterodyne-workspace-grant-operation-v1` over the complete
closed grant except `signature` and `approval_ids`. This breaks the circular
dependency while binding every operation term that approvals authorize.

A routine valid grant becomes effective immediately unless policy requires
additional approvals, subject acceptance, a waiting period, or an approving
role. `approval_ids` are the SHA-256 JCS identifiers of distinct closed
`heterodyne.workspace-grant-approval.v1` records. Each record contains exactly
`profile`, `spec_version`, `workspace_key`, `policy_head`, nullable
`predecessor`, `authority_checkpoint`, `operation_digest`, `approver_key`,
`issued_at`, `expires_at`, and `signature`. `approver_key` signs every other
member with BIP-340 proof bytes for domain
`heterodyne-workspace-grant-approval-v1`.
Every counted approval MUST have the same workspace, current
policy/predecessor/checkpoint, and grant-operation digest, be current at
trusted evaluation time, name a distinct authorized approver, and appear by
exact identifier in `approval_ids`; names, booleans, or unsigned counts are
not approvals. The finalized grant carries the workspace active-key signature.
The grant activates only when the deterministic approval set satisfies policy.
Replayed approvals, duplicate controllers, approvals bound to another
workspace or broader policy, and approvals lacking current authority at their
own checkpoints do not count.

Explicit invitation is the default external onboarding path. Every grant's
top-level `subject_account`, `target_device`, and exact `marmot-mls-leaf`
`recipient` members bind it to one active account and device-local KeyPackage.
An invitation is such a grant with `activation:"subject-acceptance"`, an
unguessable one-time nonce commitment, expiry, disclosed role locator, and
history mode. `invitation` MUST be non-null if and only if activation is
`subject-acceptance`.

Acceptance is one closed
`heterodyne.workspace-invitation-acceptance.v1` record containing exactly
`profile`, `spec_version`, `grant_id`, `grant_operation_digest`,
`workspace_key`, `subject_account`, `target_device`, `target_leaf`,
`policy_head`, nullable `predecessor`, `authority_checkpoint`,
`repository_view_id`, `nonce_opening`, `nonce_commitment`, `issued_at`,
`expires_at`, and `signature`. The subject active account signs every other
member with BIP-340 proof bytes for domain
`heterodyne-workspace-invitation-acceptance-v1`. `nonce_commitment` is SHA-256
of proof bytes for domain `heterodyne-workspace-invitation-nonce-v1` over the
grant ID, workspace key, subject account, exact device and leaf, and nonce
opening. Every binding MUST equal the current signed grant and authenticated
repository view. A configured authoritative atomic replay store reserves that
workspace/grant/commitment tuple while activation is evaluated. It commits
the reservation atomically only after sampling its configured trusted clock
inside the commit operation and rerunning one complete pure activation
validation over the immutable request and exact latest view at that new time.
That validation rechecks signed policy freshness, effective authorization,
membership and exact successor bindings, grant activation and expiry,
grant/account/device/resource/host revocations, capability/resource/
delegability intersections, and every approval's time, signature, signer, and
threshold. Only then does the store confirm the exact reserved holder and
perform the atomic transition. Any failure releases the reservation so a
still-valid acceptance is not permanently consumed; no partial activation
takes effect. The store also releases or aborts an uncommitted reservation at
its signed expiry and never commits after that expiry. The committed
acceptance is executable exactly once; a caller-supplied acceptance ID,
consumed-ID list, replay boolean, or cached time has no authority. Invitation
material for a private role is delivered through an authenticated two-member
conversation under
[`heterodyne:0.6.0#comms-direct-messages`](heterodyne-comms.md#comms-direct-messages) or an existing authorized private
repository.

A `role-revocation-v1` may revoke a grant, account, device, relationship, host,
or resource. A valid revocation is effective at its declared effective time,
subject to any stronger emergency rule in policy, and always wins over an
otherwise valid grant. Removing an account removes all its device leaves;
removing one device leaves other authorized devices intact.

<a id="workspace-relationships"></a>
## 8. Workspace relationships and joint governance

Two workspaces MAY establish a bilateral automatic role allowance. The source
active key supplies the common `signature`; the receiving active key supplies
`receiving_signature` over the same proof bytes. The object names both active
workspace keys, both exact current policy/predecessor/checkpoint contexts,
qualifying source role, exact receiving role, local capability ceiling, proof
maximum age, grace period, expiry, and independent revocation terms. A
one-sided, cross-key, stale-context, predecessor-mismatched, or otherwise
mismatched object does not activate an allowance.

The receiving repository materializes acceptance as one closed signed
`workspace-relationship-receipt-v1`. Its current receiving-workspace tuple
binds a unique `receipt_id`, the relationship and receiving-role IDs, the
source workspace key, the exact source relationship object identifier,
source policy/predecessor/checkpoint, accepted source repository RID and
head, and trusted `received_at`. The receiving role checkpoint lists the
receipt ID. A source relationship not matched by that exact current receipt,
or a receipt referring to another source view or relationship object, does
not activate an allowance. Exactly one semantic receipt may exist for a
relationship, receiving role, and exact current-source tuple; zero matching
receipts at use or multiple matching receipts in a complete view fail closed.
Source revocations target the source relationship ID; independent receiving
revocations target the receipt ID.

An allowance continuously depends on a closed
`heterodyne.workspace-affiliation-evidence.v1` record signed by the source
workspace active key with BIP-340 proof bytes for domain
`heterodyne-workspace-affiliation-evidence-v1`. It contains exactly `profile`,
`spec_version`, `relationship_id`,
`source_workspace_key`, `source_role_id`, `source_account`, `policy_head`,
nullable `predecessor`, `authority_checkpoint`, `repository_rid`,
`repository_head`, `observed_at`, `expires_at`, and `signature`. The evidence
MUST bind the relationship's source workspace, role, and qualifying account,
the exact current source authority tuple, and the accepted repository RID and
exact current head at the start of its canonical ancestry. A fork, competing
checkpoint, older ancestral head, rollback, stale
source state, non-current receiving policy, or effective bilateral revocation
rejects the allowance. The consumer derives proof age as trusted `now` minus
signed `observed_at`; a caller-supplied age, freshness boolean, policy boolean,
or affiliation assertion has no authority. The receiving workspace MAY accept
a previously valid proof only through the relationship's signed grace period,
after which access suspends with `affiliation_stale`. The receiving workspace
may revoke independently. An automatic allowance MUST NOT confer a governance
capability unless the receiving root policy explicitly permits that exact
mapping.

Every allowance use re-resolves the signed relationship from both latest
repository states. Its effective capabilities are the intersection of the
relationship ceiling, one current unrevoked source grant and its subject
account and device, every source-role parent ceiling, every receiving-role
parent ceiling, and both current
workspace policies. Separate grants are not unioned and no raw head, age,
fork, currentness, or revocation assertion participates.

Shared resources use one of two models. In the default host-owned model, one
workspace governs the resource and partner accounts receive bounded guest
roles. In the jointly governed model, a separate active-key workspace account
is created; `joint-workspace-relationship-v1` names the joint key,
participating active keys, explicitly authorized delegates, threshold, and
scope. Its inherited `workspace_key` MUST exactly equal `joint_workspace_key`,
its threshold is an integer from one through the number of signed distinct
delegates, and its active-key signature and complete latest resolver-derived
policy/predecessor/checkpoint/repository tuple MUST validate normally. The
delegate set is the signed `delegate_keys` set; callers do not configure or
assert a second delegate set, threshold, time, or current tuple.

Each counted delegate supplies one closed
`heterodyne.workspace-joint-delegate.v1` record containing exactly `profile`,
`spec_version`, `joint_workspace_key`, `relationship_id`, `delegate_key`,
`policy_head`, nullable `predecessor`, `authority_checkpoint`,
`operation_digest`, `resource_scope`, `issued_at`, `expires_at`, and
`signature`. The named delegate signs every other member with BIP-340 proof
bytes for domain `heterodyne-workspace-joint-delegate-v1`. Its tuple, scope,
validity interval, and operation digest MUST equal the evaluated joint
operation, and only distinct delegate keys in latest signed state count. The operation
digest is SHA-256 of proof bytes for domain
`heterodyne-workspace-joint-operation-v1` over
the relationship ID, joint workspace key, exact authority tuple, and requested
resource scope. A boolean threshold claim, unsigned count, participant
signature, or host signature has no joint authority. The joint workspace key
and current policy, not any participant, host, or relationship claim, governs
the resource.

<a id="workspace-advertisements"></a>
## 9. Resources, services, and hosts

`resource-advertisement-v1` connects a role to a native resource. It names the
resource type and stable ID, native locators, effective policy head, required
capabilities, current key epoch, history and retention policy, host set, and
whether listed hosts are key-custody hosts. It separately names the repository
owner key, authorized repository-writer NIDs, and trusted-seed NIDs.
Advertisements do not replace the native resource's signatures or state
machine, and none of those service roles implies another.

`host-advertisement-v1` advertises a host NID, separately authorized trusted
seed NIDs, Radicle and optional onion or clearnet endpoints, supported feature
IDs, custody scope, priority, and expiry. `service-advertisement-v1` names its
operator account separately from workspace governance and advertises the
higher-level service and native profile. Endpoint strings are data, not
authorization; consumers apply Core repository and seed trust under
[`heterodyne:0.6.0#core-seed-nid-trust`](heterodyne-core.md#core-seed-nid-trust) and MUST NOT fetch a locator before its
containing private object is authorized and decrypted.

Organization-default hosts are ordered in workspace policy. Roles inherit
them and resources inherit the effective role set. A signed override may
replace or supplement inherited hosts while retaining the mandatory Radicle
backstop. Clients SHOULD try the last responsive eligible host first, then the
remaining ordered hosts, then authorized Radicle peers. Failover MUST NOT
change the authorization decision.

Hosting grants no invitation, grant, policy, federation, or governance power.
A host that can unwrap or rewrap resource keys is an explicit confidentiality
custodian and MUST be disclosed in the resource advertisement. Compromise of
such a host can disclose keys in its custody; clients MUST revoke that host
and rotate affected resource keys. Hosting or seeding cannot forge an active
workspace-key proof, grant, or checkpoint.

<a id="workspace-role-control"></a>
## 10. Marmot role control groups

Every private role has one non-chat Marmot MLS control group. It carries
membership changes, repository-key epochs, resource-key envelopes, and
recovery coordination. The stable role repository is the durable authority.
MLS membership alone does not create a role grant, and a role grant without a
current admitted device leaf does not disclose MLS application secrets.
The role manifest's `administrator_account` identifies the explicit Marmot
administrator account and `marmot_h` identifies the exact private routing
commit. Neither value grants Workspace governance or repository ownership.

A grant belongs to an active account. Each authorized device is a separate,
device-local MLS leaf bound to that account through standard Marmot account
proofs under [`heterodyne:0.6.0#comms-marmot-participation`](heterodyne-comms.md#comms-marmot-participation).
Devices MUST NOT share leaf private keys. Removing a device advances the role
MLS epoch; removing an account removes all its leaves and advances the epoch.
Implementers MUST apply the same section's KeyPackage admission,
replenishment, pending-group, retention, and resource limits.

Compromise of the active Nostr account key is treated as compromise of every
Workspace Marmot leaf admitted under that account. Recovery removes all old
leaves, advances every reachable role group, publishes fresh KeyPackages, and
explicitly reauthorizes successor-account devices, delegates, repositories,
seeds, hosts, and custodians. A stalled group remains compromised or stalled;
continuity evidence alone MUST NOT admit an old or successor leaf.

Public roles MAY omit the private role control group when they distribute no
private key material. Their signed authority state still uses the stable role
repository.

<a id="workspace-key-delivery"></a>
## 11. Resource keys, recovery, and history

Every encrypted repository or resource has an independent stable resource ID
and monotonically increasing key epoch. A role MLS epoch authorizes delivery;
it MUST NOT be used as a universal content key. A resource qualifying through
multiple roles may deliver the same current resource key independently
through each role.

A `resource-key-envelope-v1` is one
[`heterodyne:0.6.0#core-key-envelope`](heterodyne-core.md#core-key-envelope)
key envelope. Workspace supplies the five instantiation choices:

| Choice | Workspace value |
|---|---|
| Recipient set | every device leaf currently eligible through a qualifying role |
| Reference and wrapping | `marmot-mls-leaf`, under wrapping profile `marmot-mls-application-v1` |
| Carrier | the role Marmot control group, committed to the active event repository |
| Generation identifier | `key_epoch`, scoped to `resource_id` |
| Extra rotation triggers | `none` |

The envelope's `target_account` is the currently authorized Marmot account,
and `target_device` is the Workspace policy device identifier. Its separate
`recipient` member is the exact device-local cryptographic
`marmot-mls-leaf` that receives the envelope in the authenticated role-group
epoch. All three values MUST equal current grant and group state; no
cross-account, successor, other-device, or other-leaf fallback is permitted.

Key distribution is push-first. After a key change, signed authority state
records the epoch, each eligible device leaf receives its envelope in the role
control group, and the exact Marmot carrier event is committed to the active
event repository directly or through an eligible relay. Beyond the members
Core requires, each envelope has a globally unique `envelope_id` and binds
the qualifying `grant_id`, its signed `admission_epoch`, the role, the
authority checkpoint, and the custody host. Duplicate envelope IDs,
inconsistent admission epochs for one grant/account/device/leaf path, or a
grant/envelope/resource mismatch fail closed. A raw unprotected resource key
MUST NOT be returned.
Complete-view validation groups envelopes by the exact grant, account,
device, leaf, resource, and complete role path and requires one and only one
signed `admission_epoch` for each group before the view is accepted.
Workspace does not re-protect existing objects on rotation: each affected
resource rotates forward independently and prior ciphertext is left as it
stands.

For pull recovery, a client sends an authenticated request over a standard
two-member Marmot DM to a resource host, role host, or inherited workspace
host. The request names the resource, desired key epoch, role checkpoint, and
requesting device. Before expensive history or envelope work, the responder
MUST authenticate the device and revalidate current membership or allowance,
device/leaf state, resource policy, checkpoint freshness, revocation, and
history eligibility.

Every one of those values is derived from the same authenticated current
repository view. A pull request may name the desired resource and key epoch,
custody host, target account, device, and leaf, but MUST NOT supply authoritative
membership, device-active, host-authorized, checkpoint-age, current-epoch,
history-mode, revocation, or successor booleans. Cross-account delivery
requires the exact current `resource-key` successor-reauthorization record
defined in Section 3; role admission across the same transition requires a
separate exact `role-membership` record. Neither proof is interchangeable or
usable under another resolver instance, repository view, role, resource,
device, or leaf.
At effect time, a `target_type:"host"` revocation denies both ordinary
delivery and successor delivery through that custody host from and including
its signed `effective_at`; it has no effect before that instant.

Before delivery, the responder derives a fresh opaque effective authorization
for the authenticated account, device, and leaf over the exact request digest:
SHA-256 of proof bytes for domain `heterodyne-workspace-key-request-v1` over
`authenticated_account`, `custody_host_id`, `recipient`, `requested_epoch`,
nullable `requested_snapshot_id`, `resource_id`, `target_account`, and
`target_device`. Delivery rechecks its qualifying grant and complete role
path, then intersects their capabilities with
`resource-advertisement-v1.required_capabilities` and scope. The exact history
start is derived only from current signed state: no earlier than the resource
epoch boundary, the qualifying grant's signed admission epoch, and that
grant/account/device/leaf path's first signed envelope epoch.
`selected-snapshots` additionally requires the named
signed envelope identifier in every applicable selected-snapshot ceiling.

The response is idempotent for the tuple `(request_id, resource_id, key_epoch,
account, device, leaf)` and is either a device-bound envelope or one exact denial:
`resource_unknown`, `checkpoint_stale`, `device_revoked`, `history_denied`,
`policy_denied`, or `host_unauthorized`. A responder MUST NOT turn an unknown
or denied request into an indistinguishable success.

If a device lacks the current role epoch, it submits a fresh KeyPackage and is
re-admitted only after current authorization succeeds. It receives current
keys plus historical keys permitted by one history mode:

- `full`: all retained key epochs;
- `from-admission`: epochs current at or created after the grant's activation;
- `selected-snapshots`: only explicitly listed snapshots or key epochs.

Removing an account or device always advances the role MLS membership epoch and
is a Core removal rotation for every resource that device could reach.
Unrelated resources do not rotate. Revocation prevents future delivery and
acceptance but cannot erase plaintext or keys already copied by a former
member.

<a id="workspace-lifecycle"></a>
## 12. Resource creation, publication, and retention

Resource creation requires a signed proposal naming type, visibility, native
policy, qualifying role, hosts, and initial advertisement. Validators apply
the workspace ceiling, creator capability, and required approvals before the
native protocol creates the resource. A signed advertisement activates it in
the role directory.

Creation or hosting never implies public visibility. Publicization is a
separate governance-sensitive operation requiring `govern-publicize` and all
policy approvals. Archiving removes the resource from active advertisements
and applies retention. Conforming hosts MAY remove expired archives when the
signed policy allows, but MUST NOT claim deletion from peers or former
members. Cryptographic erasure means withholding future keys, not guaranteed
global deletion.

<a id="workspace-freshness"></a>
## 13. Freshness, offline work, and conflicts

Authority mutations - grants, invitations, policy changes, key issuance,
publicization, federation, and governance - use the authorization-view window
defined by [`heterodyne:0.6.0#comms-authorization-freshness`](heterodyne-comms.md#comms-authorization-freshness). Workspace adds one
relaxed window for ordinary code, content, and discussion writes: 86,400
seconds.

A workspace, role, or resource policy MAY shorten or disable either window
and MUST NOT lengthen it. At every effect, the effective maximum age is the
minimum of the locally configured resolver maximum and the signed
`ordinary_write_max_age` for ordinary writes or
`authority_mutation_max_age` for activation, invitations, successor
reauthorization, joint governance, and other authority effects. Bilateral
allowance evaluation and resource-key delivery use the ordinary-operation
bound while still rechecking current signed authority. The operation must
reach a conforming validator while its referenced signed checkpoint is within
the effective window. A
self-declared event time does not extend freshness. A resource-specific
profile MAY define separately vectored durable acceptance evidence; Workspace
defines no universal trusted timestamp or transferable acceptance receipt.

An offline write rejected for stale or changed authority remains a local
proposal that may be re-proposed under current authority. It MUST NOT be
silently relabeled as previously authorized. Previously decrypted local reads
cannot be revoked.

Clients compare signed heads from hosts and authorized Radicle peers. A head
that is an ancestor of the accepted head is a rollback and is rejected. Two
valid incomparable heads are surfaced as `authority_conflict`; a client MUST
NOT select one merely because its host answered first.

<a id="workspace-object-types"></a>
## 14. Normative object types

The closed schemas under `docs/spec/schemas/workspace/` are normative. Their
object types have these responsibilities:

| Object type | Stable purpose |
|---|---|
| `workspace-manifest-v1` | Active workspace-key binding, root-policy locator, visibility, and intentional public role locators. |
| `workspace-policy-v1` | Governance thresholds, ceilings, creation/federation rules, default hosts, and freshness maxima. |
| `role-manifest-v1` | Opaque role ID, parent, visibility, allowed capabilities, history mode, MLS binding, and event repositories. |
| `role-grant-v1` | Active-account grant, approvals, delegation, scope, activation, expiry, device/leaf-bound invitation, and evidence. |
| `role-revocation-v1` | Targeted revocation, effective time, authority evidence, and reason. |
| `role-checkpoint-v1` | Deterministic effective policy, membership, host, relationship, and resource state. |
| `resource-advertisement-v1` | Native resource locators, capabilities, policy, key epoch, history, retention, and hosts. |
| `host-advertisement-v1` | Separate host and trusted-seed NIDs, endpoints, profiles, inheritance, key custody, priority, and expiry. |
| `service-advertisement-v1` | Separate operator account, service profile, endpoints, policy, audience role, and expiry. |
| `workspace-relationship-v1` | Dual-active-key bilateral allowance, exact policy/predecessor chains, and continuous-proof terms. |
| `workspace-relationship-receipt-v1` | Receiving-side current-state materialization of one exact dual-signed source relationship object and repository view. |
| `joint-workspace-relationship-v1` | Participant active keys, independent joint active key, explicit delegates, threshold, and scope. |
| `resource-key-envelope-v1` | Exact grant/admission, active-account, device, leaf, role, checkpoint, host, and resource-key-epoch-bound authenticated wrapping. |

No new Nostr kind is allocated. These objects are files in authority
repositories or Marmot application payloads as specified above. When carried
inside Marmot, their exact bytes remain application data under the pinned
Comms profile.

<a id="workspace-errors"></a>
## 15. Failure vocabulary

Conformance vectors use the registry-allocated reason codes below. Wire
protocols MAY map them to local or upstream errors, but MUST preserve distinct
outcomes where disclosure or retry behavior differs.

| Reason code | Meaning |
|---|---|
| `workspace_schema_invalid` | The closed object or canonical encoding is invalid. |
| `workspace_signature_invalid` | Active-key signature or exact policy, predecessor, checkpoint, or repository binding is invalid. |
| `workspace_repository_invalid` | The configured repository verification boundary did not authenticate one complete exact current Workspace view. |
| `authority_conflict` | Required heads or authority paths conflict or are incomparable. |
| `capability_escalation` | Inheritance, grant, or delegation attempts to widen authority. |
| `policy_denied` | Current effective policy denies the operation. |
| `checkpoint_stale` | The configured resolver handle is superseded, not yet observed, expired, over-age, or otherwise not the latest applicable checkpoint view. |
| `affiliation_stale` | A bilateral source affiliation exceeded its proof/grace bound. |
| `device_revoked` | The target or requester device is not currently authorized. |
| `history_denied` | The requested historical key is outside the grant's history mode. |
| `resource_unknown` | The authorized responder has no such resource. |
| `host_unauthorized` | The responder is not an authorized custodian for the resource/checkpoint. |
| `private_topology_disclosed` | A public projection correlates concealed topology. |
| `workspace_replay` | A nonce, approval, relationship, grant, or envelope was replayed. |

<a id="workspace-security"></a>
## 16. Security invariants

The registry binds these exact Workspace invariants. An entry the registry binds to a feature is owed only by an implementation
claiming that feature, under
[`heterodyne:0.6.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).
The list below is descriptive:

- **WORKSPACE-I-NO-AMBIENT-AUTHORITY:** Workspace affiliation, Assurance continuity, or active-key succession alone grants no role, relationship, delegate, seed, or resource capability; every subordinate authority requires explicit current-key reauthorization.
- **WORKSPACE-I-INHERITANCE-NARROWS:** Child roles, resources, grants, and bilateral allowances cannot widen an applicable workspace or parent-role ceiling.
- **WORKSPACE-I-PRIVATE-TOPOLOGY:** Public state reveals no stable identifier, digest, count, locator, or correlation for a concealed workspace, role, relationship, repository, or resource.
- **WORKSPACE-I-CARRIER-NOT-AUTHORITY:** Git authorship, repository-writer permission, trusted-seed or host status, relay acceptance, custody, and Marmot membership or administration are never sufficient Workspace authorization evidence.
- **WORKSPACE-I-AUTHENTICATED-CURRENT-STATE:** Every authority effect consumes only the resolver instance's latest accepted generation and revalidates complete signed Workspace state, transitions, and revocations at effect time.
- **WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS:** Role MLS state authorizes delivery but never serves as one universal content key for subordinate resources.
- **WORKSPACE-I-REVOCATION-FUTURE-ONLY:** Revocation blocks future authorization and key delivery without claiming erasure of data or keys already obtained.
- **WORKSPACE-I-FRESHNESS-BOUNDED:** Ordinary writes use checkpoints no older than 86400 seconds and authority mutations no older than the declared authorization-view bound (default 300 seconds, ceiling 86400 seconds), with policy able only to shorten those bounds.
- **WORKSPACE-I-HOST-AUTHORITY-SEPARATION:** Hosting or trusted-seed availability does not grant governance authority, while key-custody hosts remain explicit confidentiality trust boundaries.
- **WORKSPACE-I-RADICLE-BACKSTOP:** Every effective role retains an authorized Radicle locator and eligible Radicle-backed relay host independent of optional Nostr relays.
- **WORKSPACE-I-DEVICE-LEAF-SEPARATION:** Each active-account device has an independently revocable Marmot leaf and receives only envelopes bound to that exact account, device, and leaf.

Implementations MUST bound private invitation and KeyPackage processing,
repository and relay storage, history requests, key-envelope work, and failed
authorization attempts. Private relays SHOULD default to allowlisted
publishers. Implementations MUST treat host rollback, equivocation, selective
withholding, relationship replay, cross-role confused-deputy behavior,
inheritance escalation, and joint-governance capture as explicit threats.

<a id="workspace-profiles"></a>
## 17. Features and conformance profiles

Workspace feature IDs are allocated in
[`registry/features.json`](registry/features.json), which is the sole
authority for the set and for each feature's Core and Comms prerequisites.
Claimed features resolve under [`heterodyne:0.6.0#core-conformance`](heterodyne-core.md#core-conformance).

A Workspace claim that also names Control permits an authorized light device
to request Workspace operations through Control; Control tokens and RPC
carriage do not replace Workspace grants or checkpoints. A Workspace claim
that also names Social permits verified affiliation presentation and advisory
moderation signals; Social follows, labels, or lists do not create Workspace
authority. Neither composition is required for base Workspace conformance.

Assurance is also optional composition. A Workspace implementation MUST
accept a bare active key and MUST NOT require cold-root, succession, epoch, or
witness state for any baseline Workspace feature. An Assurance claim can prove
continuity, but every Workspace authority remains an explicit object under the
current active key.

The Workspace strict profile composes the Comms strict closure, which
transitively includes Core, and adds the baseline Workspace invariants. The
invariants bound to `workspace.private-role-control.v1`,
`workspace.resource-key-delivery.v1`, and
`workspace.radicle-transport-backstop.v1` are owed under
[`heterodyne:0.6.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope) whenever those
features are claimed, so the profile does not restate them.

<!-- fixture:workspace-strict-profile -->
```json
{
  "profile_id": "heterodyne-workspace-strict-v1",
  "conformance_class": "Workspace",
  "state": "active",
  "requires_profiles": [
    "heterodyne-comms-strict-v1"
  ],
  "adds_invariants": [
    "WORKSPACE-I-NO-AMBIENT-AUTHORITY",
    "WORKSPACE-I-INHERITANCE-NARROWS",
    "WORKSPACE-I-PRIVATE-TOPOLOGY",
    "WORKSPACE-I-CARRIER-NOT-AUTHORITY",
    "WORKSPACE-I-REVOCATION-FUTURE-ONLY",
    "WORKSPACE-I-FRESHNESS-BOUNDED",
    "WORKSPACE-I-HOST-AUTHORITY-SEPARATION"
  ]
}
```

The computed closure is active and claimable only when every base Workspace
feature and applicable vector is satisfied.

<a id="workspace-conformance"></a>
## 18. Conformance

A Workspace implementation claims the exact `heterodyne/0.6.0` release,
registry revision and digest, dependencies, provided and required feature IDs,
and applicable profile IDs. Base conformance requires successful processing
of every Workspace-owned vector. Optional Control or Social composition is
claimed separately.

Workspace vectors test Heterodyne's authorization and transport composition.
They do not duplicate upstream MLS cryptography, Marmot event validation, Git
replication, or Radicle COB behavior. A standard Nostr relay remains
conforming by carrying exact events without Workspace awareness. A standard
Radicle node remains conforming by replicating repositories it is authorized
to access without interpreting Workspace state.
