# Workspace Role Control-Plane Design

**Date:** 2026-08-13

**Status:** Approved for implementation planning

**Protocol owner:** new independently versioned Workspace family document

## Goal

Add the organizational control plane needed for Heterodyne workspaces to host
social and software collaboration across companies without making one company,
relay, server, or repository authoritative over every participant.

This is the first protocol subsystem in the broader effort to support a
Buzz-like experience: a full social graph alongside source code, artifacts,
direct messages, group discussions, communities, and automation. It defines
workspace identity, roles, authorization, private discovery, federation,
hosting, and key distribution. Later designs will add forge conventions,
artifacts, workflows, search, notifications, and realtime presence on top of
these contracts.

## Design principles

1. Every workspace is an independently governed Heterodyne identity. Multiple
   workspaces owned by one company remain independently verifiable and may
   publish signed parent-organization or peer-workspace relationships.
2. Workspace membership is an affiliation, not ambient access. A resource is
   accessible only through its effective role and resource policy.
3. The organization sets policy ceilings and defaults. Child roles and
   resources may narrow inherited authority but cannot widen it.
4. Public is a role, not a special bypass. Private roles are concealed
   capability domains with their own encrypted repositories.
5. Radicle is both the durable repository layer and the default transport
   backstop. Marmot/MLS supplies encrypted group membership and key delivery.
   Standard Nostr relays may be added without becoming dependencies.
6. Resource protocols remain native. Radicle repositories, Marmot groups,
   artifact stores, and services retain independent keys, state, and lifecycle
   rules.
7. Hosting and authority are separate. A node gains no grant or governance
   power merely by storing data, relaying events, or serving key envelopes.
8. Revocation prevents future access; it cannot erase data a former member
   already downloaded or decrypted.

## Scope and document boundary

The normative implementation will add an independently versioned Workspace
family document at `docs/spec/heterodyne-workspace.md`. Workspace
composes existing profiles rather than restating their primitives:

- Core supplies KERI identity, threshold authority, device registration,
  signatures, registries, and repository authority.
- Comms supplies Marmot events, MLS groups, Radicle-backed relays, exact-byte
  preservation, encrypted carriers, and claim verification.
- Control supplies light-device and node-mediated operations.
- Social supplies persona relationships, moderation, and affiliation
  presentation where those optional behaviors are used.

The implementation must preserve an acyclic profile dependency graph. The
base Workspace profile should require only the lowest existing profiles needed
for identity and transport. Optional Workspace-Control and Workspace-Social
profiles may add the corresponding higher-layer behavior instead of making the
base profile depend circularly on them.

The implementation patch will include the accepted ADR and the complete
canonical specification change together. The specification, registries,
schemas, release metadata, and vectors must stand on their own after merge.

## Architecture

The selected architecture is a role-repository control plane with a
resource-native data plane:

```text
 independent workspace KERI identity
                |
                v
 stable workspace manifest + root policy
                |
      inherited ceilings and defaults
                |
       +--------+---------+
       |                  |
       v                  v
 public role repo   private role repo ---- private subrole repo
                           |
                    Marmot MLS control group
                           |
              stable role authority repository
                           |
              active/archive event-repository locators
                           |
          Radicle-backed relay + optional Nostr relays
                           |
         +-----------------+-----------------+
         |                 |                 |
         v                 v                 v
   Radicle project    Marmot group     artifact/service
    native state       native MLS       native state
    and key epoch      and key epoch    and key epoch
```

The workspace manifest and root policy describe the workspace's current KERI
authority, governance thresholds, role-creation rules, visibility limits,
federation policy, and default host advertisements. A role repository contains
only that role's policy, membership, capabilities, advertisements,
checkpoints, and audit history. A resource advertisement connects the role
control plane to the resource's native locator and policy.

A role is a subordinate authority object of its workspace, not an independent
KERI identity. Workspace governance can revoke or replace it within the root
policy. A durable project jointly controlled by multiple organizations is
different: it uses a separate threshold-governed workspace identity whose
delegates and thresholds represent the participating organizations.

## Workspace and role privacy

A workspace may be public, selectively disclosed, or entirely
non-discoverable. A private workspace has no mandatory public projection. An
invitation or trusted relationship conveys enough signed KERI verification
material and repository location information for an authorized recipient to
verify it locally.

Public workspaces may advertise their manifest and public-role directory from
their public profile. A public directory lists only intentionally public roles
and resources.

Private role identifiers are random and non-enumerable. Their names,
identifiers, membership, policy, repository locators, MLS group identifiers,
host advertisements, and subordinate resources are disclosed only through:

- an authorized parent-role administrative view;
- direct membership or an explicit invitation;
- a valid bilateral role allowance; or
- workspace governance with explicit discovery authority.

Ordinary members of a parent role do not learn that a private subrole exists.
Public objects must not contain hashes, counts, encrypted placeholders, or
other stable correlations that reveal concealed workspaces, roles,
relationships, repositories, or resources.

Private repositories use both Radicle access control and Heterodyne
encryption. Radicle access control limits replication and enumeration;
application encryption protects repository contents and supports explicit key
epochs. Neither layer is treated as a substitute for the other.

The stable role repository is itself an independently keyed resource. Its
current materialized state is encrypted under the current repository key;
earlier Git objects remain under their historical key epochs. Admission and
removal therefore follow the selected history policy without requiring one
role-wide content key to encrypt every subordinate resource.

## Policy inheritance and effective authorization

An authorization decision is the intersection of:

1. the current workspace policy and its maximum authority;
2. every role and subrole policy on the selected role path;
3. current persona membership or a qualifying bilateral allowance;
4. the device's current, non-revoked authorization;
5. the resource-local policy and explicit exceptions; and
6. expiry, revocation, freshness, and key-epoch state.

Any applicable denial, expiry, or revocation wins. A client rejects access if
it cannot construct one unambiguous current path or if required authority heads
are conflicting or incomparable.

The common capability vocabulary is:

- `read`
- `write`
- `triage`
- `moderate`
- `admin`
- `invite`

Resource profiles define the exact behavior each capability authorizes. Code
and project resources normally use read, write, triage, and admin. Discussion
resources normally use read, write, moderate, and admin. `invite` is separately
delegable so a non-admin may onboard members without receiving unrelated
administrative power.

Governance-sensitive powers are separate explicit capabilities. They include:

- changing workspace or role policy;
- creating or disclosing subroles;
- changing governance thresholds;
- making a private resource public;
- establishing or changing federation relationships;
- delegating invitation or grant authority; and
- deleting or archiving resources.

`admin` does not silently imply those powers.

An authorized actor's signed grant becomes effective immediately unless the
applicable policy requires additional approvals, an acceptance step, a waiting
period, or a distinct approving role. A grant cannot confer broader or more
delegable authority than the actor possesses. The durable role state records
the grant, its scope, approval evidence, activation, expiry, and revocation.

Role membership is evaluated continuously rather than copied into every
resource ACL. Signed role checkpoints permit bounded offline evaluation.
Resource-local grants and denials may narrow or add an explicitly permitted
exception, but cannot exceed the workspace ceiling.

## Invitations, affiliations, and workspace federation

Explicit local invitation is the default path for external participation.
The receiving workspace creates a bounded guest role or subrole for the
external persona. The persona retains its home identity and affiliation; the
receiving workspace grants no authority over the home workspace.

Two workspaces may opt into bilateral automatic role allowances. A matching,
signed relationship can express a rule such as:

> Current members of PartnerCo's support role automatically receive our
> vendor-support guest role.

An automatic allowance is never ambient federation. It names the two
workspace identities, the qualifying source affiliation, the exact local role
and capability ceiling, proof freshness, expiry, and independent revocation
terms. It cannot automatically grant governance-sensitive capabilities unless
the receiving workspace explicitly authorizes that exceptional mapping.

Automatically granted access remains continuously dependent on a current
source affiliation proof. A receiving workspace may configure a short grace
period for temporarily stale or unreachable proof state. After that period,
future access is suspended. The receiving workspace may also revoke access
independently. Loss of access does not rewrite historical authorship or audit
records.

Shared resources use one of two models:

- **Host-owned:** one workspace governs the resource and partner members
  receive bounded guest roles. This is the default.
- **Jointly governed:** a separate workspace identity has delegates from the
  participating organizations and a policy-defined threshold. This is used for
  durable work that must not be controlled unilaterally by one participant.

## Role repositories and Radicle-backed transport

Each role has a stable role repository containing:

- the role manifest and parent reference;
- effective policy and governance requirements;
- signed grants and revocations;
- materialized role checkpoints;
- host, relay, policy, project, group, artifact, and service advertisements;
- private child-role advertisements visible to authorized readers;
- the Marmot role-control-group reference; and
- active and archived event-repository locators.

High-volume Marmot traffic does not accumulate in the stable authority
repository. The role uses rotating event repositories following the existing
Comms Radicle-backed Marmot layout. A new active event repository is selected
when membership changes create a new MLS membership epoch or when the
applicable Comms size policy requires rotation. The stable role repository
records the active locator and retained archives.

Authorized clients may submit exact Marmot/Nostr event bytes directly through
Radicle or through an advertised Radicle-backed relay. Optional standard Nostr
relays may carry the same exact events. Direct commits and relay ingestion
converge on the same event identities and reuse the Comms branch,
deduplication, retention, quota, and exact-byte rules rather than defining a
second transport profile.

Every role inherits one or more organization-default host nodes and a
Radicle-backed relay path. Role and resource policy may replace or supplement
the inherited hosts, but the effective configuration must retain at least one
authorized Radicle locator and one eligible Radicle-backed relay host as the
transport backstop. Public roles may expose that repository and relay openly;
private roles restrict both. Clients may try any eligible host, prefer the
last responsive host, and fall back to authorized Radicle peers. Optional
Nostr relays improve availability but are not required for recovery or
continued synchronization when Radicle remains reachable.

Private active and archived event repositories are themselves private Radicle
repositories. Marmot protects event content; private Radicle authorization
also conceals repository topology and limits who may replicate the carrier.

## Marmot/MLS role control groups

Every private role has a non-chat Marmot MLS control group. The MLS group is
the live confidential carrier for membership changes, repository-key epochs,
resource-key envelopes, and recovery coordination. Signed state in the stable
role repository remains the durable authorization record. MLS membership by
itself does not create a role grant, and repository write access by itself does
not create authority.

A role grant belongs to a persona. Each currently authorized device is
admitted as an independent MLS leaf bound to that persona and the Core device
registry. Leaf secrets are not shared among devices. Removing one device can
therefore rotate the MLS epoch and stop future delivery without revoking every
other device belonging to the persona. Removing the persona removes all of its
leaves.

Resource keys remain independent. Role MLS epochs authorize delivery of
resource-key envelopes; they do not become one universal key for every
subordinate resource. If multiple roles qualify for a resource, its current
key may be delivered independently through each qualifying role. A narrower
audience should normally be modeled as a private subrole rather than an ad hoc
partial broadcast within a broader role.

Megolm and Matrix are useful implementation prior art for epoch-oriented key
delivery but are not Workspace dependencies. Marmot/MLS is the protocol
mechanism.

## Key delivery, recovery, and history

Every repository or subordinate resource has a stable resource identifier and
a monotonically increasing key epoch. Key distribution is push-first and
recoverable by pull.

### Push path

When a key changes:

1. signed role or resource state records the new key epoch;
2. eligible device leaves receive versioned encrypted key envelopes through
   the role's Marmot control group; and
3. the exact carrier events are committed to the active role event repository
   directly or through relay ingestion.

The envelope is bound to the resource, key epoch, authorized persona, target
device, and authority checkpoint. The protocol never returns an unprotected
raw key.

### Pull recovery

A client detects a missing key epoch from signed role or resource state. It
contacts the resource-specific host set or the inherited role and organization
hosts over an authenticated two-member Marmot DM. The request identifies the
resource and desired key epoch and proves the current requesting device.

The responder revalidates:

- current persona membership or bilateral allowance;
- the requesting device and MLS leaf;
- resource-local policy;
- checkpoint freshness and revocation state; and
- the role's history policy.

It returns an idempotent, device-bound encrypted envelope or a distinct
machine-readable denial. Unknown resources, stale authorization, revoked
devices, disallowed history, and policy denial must not collapse into an
ambiguous success or generic key response.

If the device cannot reach the current role MLS epoch, it submits a fresh
KeyPackage and is re-admitted after current authorization is verified. The
device then receives current keys and only the historical keys permitted by
policy.

Role and resource history access is configurable:

- **Full history:** the normal collaborative default.
- **From admission:** only content keys current at or created after admission.
- **Selected snapshots:** an explicit set of earlier snapshots or key epochs
  used for controlled onboarding.

Removing a persona or device always advances the role's MLS membership epoch.
Every affected resource rotates independently; unrelated resources do not.
Compromise or policy changes may force immediate targeted rotation. Removal
does not claim to revoke keys or plaintext already obtained.

## Host authority and failover

Organization policy advertises an ordered default set of eligible host nodes.
Roles inherit it, and resources inherit the effective role set, unless a
signed narrower policy overrides or supplements it.

Hosts replicate authorized repositories, expose the Radicle-backed relay,
serve current signed state, and deliver encrypted key envelopes. They do not
gain invitation, grant, policy, or governance power by hosting. A host may
initiate such an operation only when its acting device identity separately
holds the required capability.

A host configured to generate recovery envelopes is nevertheless an explicit
confidentiality custodian for the resource keys it can unwrap or rewrap. That
custody must be visible in the resource advertisement and may be narrowed to a
resource-specific host set. Hosting and authorization remain distinct, but a
compromised key-custody host can disclose the keys in its custody and triggers
resource-key rotation and host revocation.

Clients fail over across equivalent hosts and authorized Radicle peers without
changing the authorization decision. A host outage may delay a mutation that
requires current state, but it cannot justify stale keys, weaker roles,
unauthenticated channels, or a different authority path.

A compromised host may withhold data, return stale state, or leak key material
for which it is an authorized custodian, but it cannot forge a valid grant,
role checkpoint, or KERI authority proof. A key envelope is accepted only when
its declared host was authorized for that resource and checkpoint; this limits
who may serve keys but cannot make a compromised custodian preserve
confidentiality. Clients compare signed heads across available hosts and
Radicle peers, reject rollback, and surface incomparable valid heads as a
governance conflict rather than choosing one opportunistically.

## Repository object model

The Workspace document defines this small closed object vocabulary:

- **`workspace-manifest-v1`:** stable workspace identifier, KERI authority
  binding, root-policy locator, visibility mode, and public-role locators where
  applicable.
- **`workspace-policy-v1`:** governance thresholds, creation rules, visibility
  ceilings, role types, federation limits, default hosts, and freshness
  defaults.
- **`role-manifest-v1`:** opaque role identifier, parent reference, visibility,
  capability vocabulary, history policy, MLS group binding, and current event
  repository.
- **`role-grant-v1` and `role-revocation-v1`:** subject, role, capabilities,
  scope, delegability, approvals, activation, expiry, evidence, and reason.
- **`role-checkpoint-v1`:** deterministic effective policy and membership state
  used for bounded offline validation.
- **`resource-advertisement-v1`:** resource type and stable identifier, native
  locator or locators, effective policy head, required capabilities, key
  epoch, history and retention rules, and host override.
- **`host-advertisement-v1` and `service-advertisement-v1`:** Radicle, relay,
  onion, or clearnet endpoints, supported profiles, inheritance behavior, and
  expiry.
- **`workspace-relationship-v1`:** matching workspace identities, source
  affiliation, local role mapping, automatic capability ceiling, proof
  freshness, expiry, and independent revocation.
- **`joint-workspace-relationship-v1`:** participating organizations and the
  independently governed workspace identity they jointly control.
- **`resource-key-envelope-v1`:** resource and key epoch, target persona and
  device, wrapping profile, authority checkpoint, and authenticated
  ciphertext.

Every object binds its schema/profile revision, workspace, role or resource
scope, acting identity, KERI authority state, and repository checkpoint as
applicable. Closed schemas and deterministic canonical encoding are required.

Git commits, Radicle write permission, relay acceptance, and hosting status are
carriers and availability signals. They are not authorization evidence unless
the relevant signed Workspace object and authority chain validate.

Routine authorized operations may be appended independently by their actors.
Governance-sensitive changes become effective only after their policy-required
approvals are collected and a deterministic effective checkpoint is
materialized.

## Resource creation and lifecycle

Resource creation follows four steps:

1. An authorized actor proposes the resource type, visibility, native policy,
   qualifying role, hosts, and initial advertisement.
2. Validators apply the current workspace ceiling, the creator's capability,
   and any required approval procedure.
3. The applicable native protocol creates the Radicle repository, Marmot
   group, artifact namespace, or service.
4. A signed resource advertisement activates the resource in the qualifying
   role directory.

Creating or hosting a resource never makes it public. Publicization is a
separate governance-sensitive operation checked against workspace policy.

Archiving removes a resource from active advertisements and applies its
retention policy. Conforming hosts may remove expired archives when policy
allows. Cryptographic erasure removes future key access where possible, but
the protocol does not promise deletion from peers or former members.

## Freshness and offline behavior

Workspace defines two default authorization-freshness classes:

- **Ordinary collaboration writes:** code, content, and discussion operations
  may use a cached signed authorization checkpoint for up to 24 hours. A
  workspace or resource may shorten or disable this window.
- **Authority mutations:** grants, invitations, policy changes, key issuance,
  publicization, federation changes, and governance operations require a
  checkpoint no older than five minutes by default. Policy may require a
  shorter window.

An ordinary operation must reach a conforming validator while its referenced
checkpoint remains within the permitted window. A self-declared creation time
does not extend the window. This design does not create a universal trusted
timestamp or transferable acceptance receipt. A resource profile that needs
durable early-acceptance evidence must define and vector that evidence within
its own authority model.

Previously decrypted local reads cannot be revoked. Freshness rules govern new
synchronization, accepted writes, key delivery, and authority mutations.

If a source affiliation cannot be refreshed, an automatic bilateral grant may
continue only through its signed grace period and then suspends. Conflicting
or incomparable checkpoints fail closed. A rejected offline write remains a
local proposal and may be re-proposed under current authority; it is never
silently relabeled as authorized.

## Security considerations

The Workspace threat model must cover at least:

- private workspace, role, relationship, and locator correlation;
- unauthorized Radicle replication and relay enumeration;
- MLS KeyPackage or group-state exhaustion;
- event-repository and relay disk-fill attacks;
- stale affiliation proofs and delayed revocation;
- host rollback, equivocation, and selective withholding;
- compromised role hosts issuing unauthorized key responses;
- replayed grants, invitations, key envelopes, and bilateral relationships;
- cross-role confused-deputy errors;
- capability escalation through inheritance or delegation;
- governance capture in joint workspaces; and
- the unavoidable persistence of previously replicated or decrypted data.

The implementation must reuse existing Comms admission, quota, retention,
repository-rotation, exact-byte, and relay controls. Private role relays should
default to allowlisted publishers and bounded repository growth. A host must
authenticate and authorize a key request before performing expensive history
or envelope work.

## Conformance strategy

Workspace will allocate feature and invariant identifiers through Core's
registry authority and publish release/profile metadata with complete
dependency closure. It will add closed schemas and positive and negative
vectors for:

- canonical Workspace object encoding, signature, KERI binding, and locator
  validation;
- policy inheritance, narrowing, explicit denial, and capability separation;
- single-actor and multi-approval grants, expiry, and revocation precedence;
- explicit invitation and continuously conditional bilateral allowance flows;
- private discovery and non-leakage;
- host inheritance, resource overrides, deterministic failover, and rollback
  rejection;
- persona-level membership and independent device MLS leaves;
- key push, pull recovery, re-admission, rotation, and the three history modes;
- ordinary-write and authority-mutation freshness boundaries;
- host-owned and threshold-governed joint resources;
- active event-repository rotation and retention; and
- exact-byte equivalence across direct Radicle ingestion, the Radicle-backed
  relay, and optional standard Nostr relays.

Marmot/MLS remains authoritative for MLS cryptographic mechanics. Radicle
remains authoritative for Git replication and COB behavior. Workspace vectors
test Heterodyne's authorization and transport composition rather than copying
upstream cryptographic or repository vectors.

Standard Nostr relays may carry Workspace Marmot events without
Heterodyne-specific changes. Ordinary Radicle nodes may replicate authorized
repositories without Workspace-specific server behavior. Only nodes claiming
the existing Radicle-backed-relay profile or a Workspace host profile interpret
the repository layout and serve protocol-specific indexes or key-recovery
operations. Each effective role configuration must include an eligible node
for the mandatory Radicle transport backstop, but any particular node may
decline those optional service roles.

## Planned normative artifacts

The eventual implementation patch should include:

- the accepted and archived Workspace ADR;
- `docs/spec/heterodyne-workspace.md`;
- Workspace feature, invariant, kind, reason, and object allocations required
  by the final wire design;
- closed JSON schemas for every Workspace object;
- positive and negative conformance vectors;
- Workspace release and profile metadata with complete dependency closure;
- family-map, architecture, threat-model, and changelog updates; and
- only the minimum dependency or integration changes required in Core, Comms,
  Control, and Social.

The implementation should not change Marmot or MLS cryptography, create a new
messaging engine, restore Matrix, duplicate Radicle COBs, or make vanilla
Nostr relays and Radicle nodes Heterodyne-aware.

## Deferred follow-up designs

The following independent surfaces are intentionally outside this first
design:

1. Radicle project conventions connecting repositories, branches, issues,
   patches, reviews, and discussions to Workspace advertisements.
2. Artifact, package, release, provenance, and retention manifests.
3. Workflow execution, approvals, status projection, and workspace-scoped
   automated agents.
4. Cross-workspace search, local indexes, notifications, and inbox routing.
5. Ephemeral presence, typing, and realtime collaborative state.
6. User-interface and product conventions.
7. A future Marmot Improvement Document adding KERI credential support using
   Heterodyne's identity design.

Each follow-up composes Workspace roles and advertisements instead of
redefining organization authority.

## Success criteria

The design is successfully implemented when:

- a public or private workspace can be independently verified and governed;
- roles and concealed subroles distribute policy and resource access without
  creating ambient workspace-wide authorization;
- explicit invitation is the default while bilateral affiliation rules can
  safely auto-provision bounded guest roles;
- host-owned and jointly governed cross-company resources are both possible;
- authorized devices receive and recover independent resource keys through
  Marmot/MLS and Radicle-backed transport;
- Radicle remains a usable transport backstop when optional Nostr relays are
  unavailable;
- compromised or unavailable hosts cannot widen authority;
- offline collaboration and authority mutation use distinct, bounded
  freshness policies;
- private topology is not exposed through public indexes; and
- the canonical Workspace document and normative artifacts are sufficient to
  implement and test the protocol without consulting this design or its ADR.
