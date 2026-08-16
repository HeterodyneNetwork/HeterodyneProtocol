# Heterodyne Workspace Protocol Specification

Document ID: `workspace`

Workspace is a section of the Heterodyne specification and is governed by
[`heterodyne:0.5.0#core-document-conventions`](heterodyne-core.md#core-document-conventions), which fixes the family version,
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

Workspace JSON objects follow [`heterodyne:0.5.0#core-canonical-json`](heterodyne-core.md#core-canonical-json).

`workspace_id`, persona identifiers, device keys, and signing keys are
lowercase 64-character hexadecimal secp256k1 x-only public keys. Human-facing
NIP-19 strings are presentation encodings and MUST be decoded before inclusion
in a Workspace object. `kel_head`, `policy_head`, `checkpoint_id`,
`relationship_id`, `grant_id`, `revocation_id`, `resource_id`, and envelope
digests are lowercase 64-character SHA-256 values. Radicle repository
identifiers begin with `rad:`. Git object IDs are lowercase 40-character
SHA-1 values because the adopted Radicle substrate uses that object format;
[`heterodyne:0.5.0#core-security`](heterodyne-core.md#core-security) bounds what that format is trusted for.

Every signed object contains `spec_version:"heterodyne/0.5.0"`, its exact
`object_type`, `workspace_id`, `actor`, `kel_head`, `authority_sequence`,
`repository_rid`, `repository_head`, and `issued_at`. The signature covers the
[`heterodyne:0.5.0#core-proof-bytes`](heterodyne-core.md#core-proof-bytes) bytes for domain
`heterodyne-workspace-object-v1`, whose sole bound member `object` is the
object without its `signature` member. `signature` is a lowercase
128-character BIP-340 signature.

Three identifiers in that set are distinct and MUST NOT be conflated:

- `workspace_id` is the workspace's own cold root, and its KEL is not
  referenced by a signed object.
- `actor` is the exact secp256k1 x-only public key that produced `signature`.
  It is an epoch key or a delegated device publishing key, never a cold root
  and never a Radicle NID.
- `kel_head` is the accepted KEL head of the persona that authorizes `actor`,
  not the workspace's. A verifier resolves `actor` against that KEL under
  [`heterodyne:0.5.0#core-kel-verification`](heterodyne-core.md#core-kel-verification).

`repository_head` is a git object ID and therefore the one 40-character value
in a signed object; every other digest-shaped member is 64-character SHA-256.

The actor MUST be authoritative at the stated KEL head and MUST possess the
capability and approval set required by the effective policy at the referenced
repository head.

The SHA-256 digest of the complete JCS object including `signature` is its
object identifier unless a field-specific identifier is defined. Consumers
MUST reject a digest mismatch, invalid signature, KEL rollback, repository
head not reachable from the accepted authority branch, or object whose actor
was not authorized at that point. Git commit authorship, Radicle delegate or
write permission, relay acceptance, MLS membership, and hosting status are
carriers or availability signals, not Workspace authority.

<a id="workspace-identity"></a>
## 3. Workspace identity and governance

A workspace is an independently governed Heterodyne identity. Its
`workspace_id` is the cold-root public key of a separately accepted KEL under
[`heterodyne:0.5.0#core-identity-model`](heterodyne-core.md#core-identity-model).
Multiple workspaces operated by one organization remain distinct identities.
They MAY publish signed parent, peer, or joint relationships, but no
relationship changes either identity's KEL authority.

The stable workspace repository contains exactly one current
`workspace-manifest-v1`, the root `workspace-policy-v1`, and the append-only
history from which both are derived. Its canonical authority branch follows
[`heterodyne:0.5.0#core-threshold-authority`](heterodyne-core.md#core-threshold-authority). A public workspace MAY advertise this repository
from its public persona profile. A private workspace has no required public
projection; an invitation or relationship conveys the KEL verification
material and private locator needed by the recipient.

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
repository. It uses the [`heterodyne:0.5.0#comms-marmot-event-repository`](heterodyne-comms.md#comms-marmot-event-repository)
layout and rotates to a fresh repository when either:

- a membership-changing MLS commit establishes a new group epoch; or
- the active repository reaches the maximum size that
  [`heterodyne:0.5.0#comms-marmot-event-repository`](heterodyne-comms.md#comms-marmot-event-repository) fixes.

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
each role policy on one unambiguous parent path, current persona membership or
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
grants, revocations, relationships, hosts, and resources by their binary
identifier bytes, then hashes the JCS materialization.

<a id="workspace-grants"></a>
## 7. Grants, revocations, and invitations

A `role-grant-v1` names one persona subject, exact capabilities, resource
scope, delegability, activation, expiry, invitation evidence, and required
approval object IDs. A grant actor MUST possess `invite` or the explicit
grant capability for the target scope and cannot grant broader or more
delegable authority than it holds.

A routine valid grant becomes effective immediately unless policy requires
additional approvals, subject acceptance, a waiting period, or an approving
role. Required approvals are distinct signed grant-approval records carried
as `role-grant-v1` objects with the same `grant_id` and unique actors. The
grant activates only when the deterministic approval set satisfies policy.
Replayed approvals, duplicate actors, or approvals from actors lacking
authority at their own checkpoints do not count.

Explicit invitation is the default external onboarding path. An invitation
is a grant with `activation:"subject-acceptance"`, an unguessable one-time
nonce commitment, expiry, target persona, disclosed role locator, and history
mode. Acceptance consumes the nonce exactly once and binds the accepted grant
to the recipient's device KeyPackage. Invitation material for a private role
is delivered through an authenticated two-member conversation under
[`heterodyne:0.5.0#comms-direct-messages`](heterodyne-comms.md#comms-direct-messages) or an existing authorized private
repository.

A `role-revocation-v1` may revoke a grant, persona, device, relationship, host,
or resource. A valid revocation is effective at its declared effective time,
subject to any stronger emergency rule in policy, and always wins over an
otherwise valid grant. Removing a persona removes all its device leaves;
removing one device leaves other authorized devices intact.

<a id="workspace-relationships"></a>
## 8. Workspace relationships and joint governance

Two workspaces MAY establish a bilateral automatic role allowance. Both sides
MUST sign byte-identical `workspace-relationship-v1` objects naming the two
workspace IDs, qualifying source role, exact receiving role, local capability
ceiling, proof maximum age, grace period, expiry, and independent revocation
terms. One-sided or mismatched objects do not activate an allowance.

An allowance continuously depends on a current source affiliation proof. The
receiving workspace MAY accept a previously valid proof only through the
signed grace period, after which access suspends with `affiliation_stale`.
The receiving workspace may revoke independently. An automatic allowance
MUST NOT confer a governance capability unless the receiving root policy
explicitly permits that exact mapping.

Shared resources use one of two models. In the default host-owned model, one
workspace governs the resource and partner personas receive bounded guest
roles. In the jointly governed model, a separate workspace KERI identity is
created; `joint-workspace-relationship-v1` names participating workspaces,
delegates, threshold, and scope. The joint identity, not any participant's
relationship claim, governs the resource.

<a id="workspace-advertisements"></a>
## 9. Resources, services, and hosts

`resource-advertisement-v1` connects a role to a native resource. It names the
resource type and stable ID, native locators, effective policy head, required
capabilities, current key epoch, history and retention policy, host set, and
whether listed hosts are key-custody hosts. Advertisements do not replace the
native resource's signatures or state machine.

`host-advertisement-v1` advertises a node's NID, Radicle and optional onion or
clearnet endpoints, supported feature IDs, custody scope, priority, and
expiry. `service-advertisement-v1` advertises a higher-level service and its
native profile. Endpoint strings are data, not authorization; consumers MUST
apply the locator validation in
[`heterodyne:0.5.0#core-identity-pointer`](heterodyne-core.md#core-identity-pointer) and MUST NOT fetch a locator before its
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
and rotate affected resource keys. Hosting cannot forge a KERI proof, grant,
or checkpoint.

<a id="workspace-role-control"></a>
## 10. Marmot role control groups

Every private role has one non-chat Marmot MLS control group. It carries
membership changes, repository-key epochs, resource-key envelopes, and
recovery coordination. The stable role repository is the durable authority.
MLS membership alone does not create a role grant, and a role grant without a
current admitted device leaf does not disclose MLS application secrets.

A grant belongs to a persona. Each authorized device is a separate MLS leaf
bound to that persona and its current device entry under
[`heterodyne:0.5.0#core-nid-delegation`](heterodyne-core.md#core-nid-delegation). Devices MUST
NOT share leaf private keys. Removing a device advances the role MLS epoch;
removing a persona removes all its leaves and advances the epoch. Implementers
MUST apply the [`heterodyne:0.5.0#comms-marmot-participation`](heterodyne-comms.md#comms-marmot-participation)
KeyPackage admission, replenishment, pending-group,
retention, and resource limits.

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
[`heterodyne:0.5.0#core-key-envelope`](heterodyne-core.md#core-key-envelope)
key envelope. Workspace supplies the four instantiation choices:

| Choice | Workspace value |
|---|---|
| Recipient set | every device leaf currently eligible through a qualifying role |
| Reference and wrapping | the device leaf under wrapping profile `marmot-mls-application-v1` |
| Carrier | the role Marmot control group, committed to the active event repository |
| Generation identifier | `key_epoch`, scoped to `resource_id` |

Key distribution is push-first. After a key change, signed authority state
records the epoch, each eligible device leaf receives its envelope in the role
control group, and the exact Marmot carrier event is committed to the active
event repository directly or through an eligible relay. Beyond the members
Core requires, the envelope binds the qualifying role, the authority
checkpoint, and the host. A raw unprotected resource key MUST NOT be returned.
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

The response is idempotent for the tuple `(request_id, resource_id, key_epoch,
persona, device)` and is either a device-bound envelope or one exact denial:
`resource_unknown`, `checkpoint_stale`, `device_revoked`, `history_denied`,
`policy_denied`, or `host_unauthorized`. A responder MUST NOT turn an unknown
or denied request into an indistinguishable success.

If a device lacks the current role epoch, it submits a fresh KeyPackage and is
re-admitted only after current authorization succeeds. It receives current
keys plus historical keys permitted by one history mode:

- `full`: all retained key epochs;
- `from-admission`: epochs current at or created after the grant's activation;
- `selected-snapshots`: only explicitly listed snapshots or key epochs.

Removing a persona or device always advances the role MLS membership epoch and
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
defined by [`heterodyne:0.5.0#comms-authorization-freshness`](heterodyne-comms.md#comms-authorization-freshness). Workspace adds one
relaxed window for ordinary code, content, and discussion writes: 86,400
seconds.

A workspace, role, or resource policy MAY shorten or disable either window
and MUST NOT lengthen it. The operation must reach a conforming validator
while its referenced signed checkpoint is within the effective window. A
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
| `workspace-manifest-v1` | Workspace/KERI binding, root-policy locator, visibility, and intentional public role locators. |
| `workspace-policy-v1` | Governance thresholds, ceilings, creation/federation rules, default hosts, and freshness maxima. |
| `role-manifest-v1` | Opaque role ID, parent, visibility, allowed capabilities, history mode, MLS binding, and event repositories. |
| `role-grant-v1` | Persona grant, approvals, delegation, scope, activation, expiry, invitation, and evidence. |
| `role-revocation-v1` | Targeted revocation, effective time, authority evidence, and reason. |
| `role-checkpoint-v1` | Deterministic effective policy, membership, host, relationship, and resource state. |
| `resource-advertisement-v1` | Native resource locators, capabilities, policy, key epoch, history, retention, and hosts. |
| `host-advertisement-v1` | Node endpoints, profiles, inheritance, key custody, priority, and expiry. |
| `service-advertisement-v1` | Service profile, endpoints, policy, audience role, and expiry. |
| `workspace-relationship-v1` | Bilateral affiliation-to-role allowance and continuous-proof terms. |
| `joint-workspace-relationship-v1` | Participant workspaces, independent joint identity, delegates, threshold, and scope. |
| `resource-key-envelope-v1` | Device-bound authenticated wrapping of one resource key epoch. |

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
| `workspace_signature_invalid` | Signature, actor, KEL, or repository binding is invalid. |
| `authority_conflict` | Required heads or authority paths conflict or are incomparable. |
| `capability_escalation` | Inheritance, grant, or delegation attempts to widen authority. |
| `policy_denied` | Current effective policy denies the operation. |
| `checkpoint_stale` | The applicable authorization checkpoint is too old. |
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
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).
The list below is descriptive:

- **WORKSPACE-I-NO-AMBIENT-AUTHORITY:** Workspace affiliation alone grants no role or resource capability.
- **WORKSPACE-I-INHERITANCE-NARROWS:** Child roles, resources, grants, and bilateral allowances cannot widen an applicable workspace or parent-role ceiling.
- **WORKSPACE-I-PRIVATE-TOPOLOGY:** Public state reveals no stable identifier, digest, count, locator, or correlation for a concealed workspace, role, relationship, repository, or resource.
- **WORKSPACE-I-CARRIER-NOT-AUTHORITY:** Git authorship, Radicle permission, relay acceptance, MLS membership, and host status are never sufficient Workspace authorization evidence.
- **WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS:** Role MLS state authorizes delivery but never serves as one universal content key for subordinate resources.
- **WORKSPACE-I-REVOCATION-FUTURE-ONLY:** Revocation blocks future authorization and key delivery without claiming erasure of data or keys already obtained.
- **WORKSPACE-I-FRESHNESS-BOUNDED:** Ordinary writes use checkpoints no older than 86400 seconds and authority mutations no older than 300 seconds, with policy able only to shorten those bounds.
- **WORKSPACE-I-HOST-AUTHORITY-SEPARATION:** Hosting does not grant governance authority, while key-custody hosts remain explicit confidentiality trust boundaries.
- **WORKSPACE-I-RADICLE-BACKSTOP:** Every effective role retains an authorized Radicle locator and eligible Radicle-backed relay host independent of optional Nostr relays.
- **WORKSPACE-I-DEVICE-LEAF-SEPARATION:** Each authorized device has an independently revocable MLS leaf and receives only device-bound resource-key envelopes.

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
Claimed features resolve under [`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance).

A Workspace claim that also names Control permits an authorized light device
to request Workspace operations through Control; Control tokens and RPC
carriage do not replace Workspace grants or checkpoints. A Workspace claim
that also names Social permits verified affiliation presentation and advisory
moderation signals; Social follows, labels, or lists do not create Workspace
authority. Neither composition is required for base Workspace conformance.

The Workspace strict profile composes the Comms strict closure, which
transitively includes Core, and adds the baseline Workspace invariants. The
invariants bound to `workspace.private-role-control.v1`,
`workspace.resource-key-delivery.v1`, and
`workspace.radicle-transport-backstop.v1` are owed under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope) whenever those
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

A Workspace implementation claims the exact `heterodyne/0.5.0` release,
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
