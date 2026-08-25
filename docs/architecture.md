# Heterodyne architecture

This document is an implementation-facing, non-normative view of the current
draft. Normative behavior lives in the six specification documents, registry,
and schemas under [`docs/spec/`](spec/).

## Family shape

All six documents share `heterodyne/0.5.0` and the one registry manifest.

```text
Core <- Assurance (optional)
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace (optional composition)
Social <- Workspace (optional composition)
```

Core defines active-key identity, Nostr event verification, repositories,
discovery, versioning, and base conformance. Assurance is an opt-in layer for
continuity, recovery authority, associated keys, and KERI export. Comms owns
public and private delivery, Marmot conversations, claims, OIDC/JWT, automation
attribution, archives, and trusted seeds. Control owns device enrollment and
signing. Social owns public interaction and moderation behavior. Workspace owns
roles, private topology, federation, hosting, and resource-key delivery.

Every implementation starts with Core. Comms builds on Core; Control, Social,
and Workspace build on Comms. Assurance can be combined with any family member
but is never a prerequisite for baseline Core or Marmot operation.

## Identity and discovery

The active Nostr public key is the persona identifier and the corresponding
private key is its signing authority. A bare active key is a first-class
persona. Its valid NIP-01 signature decides authorship; display names,
repositories, relays, caches, continuity records, and automation metadata are
hints or independently scoped evidence, not substitute authors.

Baseline discovery uses ordinary Nostr mechanisms:

- kind `0` carries active-key-signed profile metadata;
- NIP-05 can map an Internet name to the active key;
- NIP-65 advertises relay preferences;
- Core registry entries advertise persona-owned Radicle repositories and
  full-node capabilities without converting them into identity authorities.

Clients union byte-exact valid observations from repositories and relays, then
apply the relevant NIP-01 selection rule. Selection is source-neutral: carrier
location does not outrank signature, event coordinates, or recency. A cached
kind `0` profile or kind `10002` relay list older than seven days produces a
warning and refresh attempt, not an automatic invalidation. Every other state
retains its applicable freshness and expiry rules and fails closed where those
rules require.

Optional Assurance attaches only after reciprocal enrollment between the
active key and recovery authority. A successor remains a different Nostr
author and a different Marmot account. Applications must explicitly reissue
any continuing repository, group, delegate, financial, or application
authority.

## Storage and transport

A persona may own one or more Radicle repositories. An authorized NID writer
gets a namespaced ref only after the persona and NID prove the exact binding.
Repositories are durable signed-object carriers; Git authorship, hosting,
replication, and repository membership do not create application authority.

Relays and repositories are interchangeable carriers only where an owning
specification says they carry the same exact object. A reader verifies the
object locally before rendering, storage, or authorization. Invalid bytes from
one carrier do not taint an independently valid copy from another.

Privacy has three deployment tiers:

| Tier | Treatment | Trust boundary |
|---|---|---|
| 1 | Public signed Nostr content | Integrity depends on local verification. |
| 2 | Plaintext in selectively replicated private repositories | Every repository reader can observe plaintext. |
| 3 | Audience- or group-encrypted content | Repositories, relays, seeds, and full nodes remain blind carriers. |

Marmot owns MLS, account and device-leaf identity, conversation events,
encrypted media, and Nostr transport semantics. Heterodyne stores and routes
exact signed Marmot bytes. The active persona key is the standard Marmot
account; each device has an independent leaf. No custom relay or Marmot fork is
required.

## Full nodes, light clients, and trusted seeds

A full node is a user-controlled service that can host repositories, enforce
policy, coordinate device operations, and provide a NIP-46 signer. It is not
required to be a Nostr relay. Hosting, signing, relay service, and authority are
separate capabilities, and registry advertisements describe them separately.

A light client authenticates to the selected full-node capability and receives
no persona, NID, repository, OIDC issuer, trusted-seed, or Marmot leaf secret.
Every request selects exactly one persona vault. Missing or ambiguous vault,
grant, policy, or signer state fails closed rather than falling through to
another persona or key class.

Trusted seeds are availability helpers for encrypted Marmot event bytes. A
group can authorize multiple concurrent trusted seeds, and no seed is
canonical. Each seed writes only its own authorized NID ref and gains no
persona, repository-owner, group-administrator, full-node, or MLS authority.
Private reads and writes require current NIP-42 authentication plus the unique
current administrator-signed ACL head.

## Automation and signing

Automation does not weaken NIP-01. The public key on an event is the author
that produced its signature. A registered agent key is preferred. Use of the
persona key requires an explicit, narrow OIDC persona-signing scope.

Before signing, Control durably reserves the request and Comms derives the
canonical attribution block from authenticated current policy. Attribution is
placed in the tier-appropriate protected location and is part of the exact
intent presented to the selected signer. Callers cannot suppress or broaden
it.

Signer grants bind the persona, NIP-46 client, audience, key and class,
methods, event kinds, limits, issue and expiry times, and revocation state.
OIDC activates standard NIP-46 only after the matching one-use secret and exact
approved grant are atomically consumed. The signer-side execute-once fence is
acquired before an effect; ambiguous terminal persistence remains poisoned for
reconciliation rather than becoming retryable.

## Compromise and recovery

Baseline Core treats a compromised active key as a new-account event. A
complete reset revokes NIP-46 and OIDC grants, invalidates subordinate
authorities and trusted seeds, removes old Marmot leaves, advances every
reachable group, publishes fresh successor KeyPackages, and explicitly issues
fresh distinct authorizations for anything that continues.

Assurance may prove continuity from an old active key to a successor, but it
does not turn the successor into the old Nostr author or silently preserve any
subordinate authority. A compromise succession cuts off prior Assurance
authority at the declared effective point.

## Current draft and frozen validation history

The draft checker reads current specifications, registry entries, schemas, and
current generator reference code. It does not execute the historical topic
projection used to author the rolling snapshot.

The independent snapshot checker instead materializes the snapshot source
commit `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43` and checks the 482 frozen
vectors bound by snapshot commit
`5d4bb5fb58b35c88d8a9db120a09f1087237f35c`. Those vectors are
non-normative validation history and do not define the current draft.

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

The two lanes are deliberately independent: a live-draft edit neither rewrites
frozen vectors nor imports their pre-redesign assumptions into current checks.
