# Heterodyne Control Profile Specification

Document ID: `control`

Version: `control/0.5.0`

Status: **incomplete 0.5.0 draft**

Registry revision: `2`

Normative dependencies:

- `heterodyne:comms/0.5.0#comms-conformance`

This document prepares Control's first 0.5.0 release, descended independently
from the archived Heterodyne 0.4.x monolith. It is current normative authority
for this incomplete profile at this repository path, but remains unreleased
pending claims/OIDC completion and explicit release approval. It is not a
synchronized family version. Its conformance expression is **Core + Comms
conformant + Control profile**, but this incomplete draft makes no Control
conformance claim.

<!-- fixture:control-profile-metadata -->
```json
{
  "document_id": "control",
  "version": "control/0.5.0",
  "status": "incomplete 0.5.0 draft",
  "conformance_expression": "Core + Comms conformant + Control profile",
  "direct_dependencies": ["heterodyne:comms/0.5.0#comms-conformance"],
  "supported_comms_versions": ["comms/0.5.0"],
  "required_comms_features": ["double-ratchet"],
  "transport_owner": "comms",
  "wire_stamp_owner": null
}
```

<a id="control-scope"></a>
## 1. Scope and status

Control is a profile of Comms, not an independent transport. It reserves the
application semantics for light-client and agentic device enrollment, RPC
requests and responses, permission grants, one-time enrollment tokens, and
the Model Context Protocol (MCP) data-layer profile described by ADR-030.
It also reserves session lifecycle, revocation, replay protection,
object-level authorization, side-effect audit, and inbound-execution policy.

Those areas are enumerated so ownership is unambiguous; their complete wire
schemas, state machines, rejection rules, vector corpus, and conformance
requirements have not yet been integrated. An implementation MUST NOT infer
missing behavior from ADR prose or advertise Control conformance from this
document.

Control has no transport and no wire-stamp authority. Session-carried Control
payloads use accepted Comms double-ratchet sessions, Comms negotiation, and
Comms carrier rumors. The registry's session-device entry is only a reserved,
inactive allocation; this draft activates no relay-published Control profile.

<a id="control-comms-contract"></a>
## 2. Exact Comms contract

The exact supported Comms-version set for this 0.x draft is
`{comms/0.5.0}`. It is a set containing exactly one version, not a range.
Control requires the `double-ratchet` Comms feature and all of the following
version-qualified anchors:

- the double-ratchet feature and the exact registry profiles
  `heterodyne-comms-double-ratchet-invite-v1`,
  `heterodyne-comms-double-ratchet-invite-response-v1`, and
  `heterodyne-comms-double-ratchet-message-v1`, including their retention and
  no-backfill rules at `heterodyne:comms/0.5.0#comms-direct-messages`;
- the authenticated `control-enrollment` acceptance context, including
  cryptographic checks before policy and message-request signal suppression,
  at `heterodyne:comms/0.5.0#comms-acceptance-hook`; and
- mutual subprotocol negotiation plus the `kind:31015` negotiation and
  `kind:31016` payload carriers at
  `heterodyne:comms/0.5.0#comms-subprotocol-negotiation`.

A Control implementation MUST NOT interpret a Control payload until the
Comms acceptance hook has returned `accept`, both peers have completed mutual
negotiation for the same Control version and required feature set, and the
payload has passed all Comms carrier checks. Control MUST NOT weaken or bypass
any Comms cryptographic or acceptance failure.

The stable Control protocol identifier, closed Control payload schemas, and
method-specific state machines remain to be integrated from an accepted
ADR-030. A generic Comms carrier does not itself establish Control semantics
or conformance.

<a id="control-claim-consumption"></a>
### 2.1 Consumption of Comms authorization decisions

Control is a policy consumer of the complete Comms verification result at
`heterodyne:comms/0.5.0#comms-claim-verification` and canonical repository
state at `heterodyne:comms/0.5.0#comms-claim-ledger`. Enrollment, RPC, agent,
tool, resource, and side-effect checks may authorize with only `active` state
from a Comms claim whose namespace, name, subject, audience, resource,
operation, validity interval, chain, proof, and current repository state cover
the exact request. Control MUST retain the source claim IDs, Comms checkpoint,
decision state, and reason code in its encrypted audit record.

`provisional`, `untrusted`, and `conflicted` claims never establish Control
authority. The same is true of `invalid`, `expired`, and `revoked`. Control
MUST NOT reinterpret one of those states, cache an earlier active result past
its validity/checkpoint conditions, weaken a Comms proof or reduction, or infer
permission from delivery, session establishment, or a projected JWT alone.
Every privileged operation re-evaluates its applicable active decision or a
bounded decision artifact tied to the current request and checkpoint.

Durable NID devices may separately qualify as Comms claim-ledger readers.
NID-less session devices receive only filtered authorization decisions and
filtered session-device views; they never receive ledger decryption keys or
direct repository access, claim-ledger audience keys, issuer signing keys, or
unfiltered private claim records. A Control grant cannot turn such a session
principal into a durable reader or issuer.

This section defines no claim event, proof, repository-record, discovery, JWT,
or token-status wire format. Those remain exclusively Comms-owned. Future
Control schemas name qualified Comms anchors and carry only Control method
inputs and decisions inside the existing Comms carriers.

<a id="control-session-device-profile"></a>
## 3. Session-device delegation profile

Registry revision 2 contains the draft reservation
`heterodyne-control-session-device-v1` on Core `kind:31001`, with immutable
discriminator
`tags:heterodyne=delegation,binding_nonce,key_proof;radicle_nid=absent`.
The reservation is explicitly **reserved-inactive** in `control/0.5.0`.

The current Core NID-delegation event requires an NID-addressed `d` tag,
`radicle_nid`, and `nid_proof`. It does not accept this NID-less discriminator
or its `binding_nonce`/`key_proof` shape. Current Core verification therefore
rejects that proposed shape, and no event may claim conformance to this
profile under `control/0.5.0`.

The registry entry's `owner: control`, `stamping: false`, and draft status
record its future ownership and stamp intention; that reservation does not
make it active, change current Core verification, or authorize production.
Activation requires all of the following in order:

1. ADR-030 is accepted;
2. a future Core amendment defines the common `kind:31001` envelope and the
   NID-less subtype's complete verification rules; and
3. Control vectors plus the registry integration gate prove the resulting
   schema, discriminator, owner-stamp behavior, and rejection cases.

<!-- fixture:control-session-device-reservation -->
```json
{
  "profile_id": "heterodyne-control-session-device-v1",
  "registry_status": "draft",
  "profile_state": "reserved-inactive",
  "current_core_compatible": false,
  "conforming_events_allowed": false,
  "activation_requires": [
    "adr-030-accepted",
    "future-core-kind-31001-subtype-amendment",
    "control-vectors-and-registry-integration-gate"
  ]
}
```

Session devices are distinct from authorized durable NID devices. The former
are confined Control principals; the latter may separately qualify for Comms
credential-plane synchronization. A Control grant cannot convert a session
device into a durable credential-sync device.

<a id="control-wire-ownership"></a>
## 4. Wire ownership and audit binding

Control MUST NOT own or add a wire stamp. If a future accepted amendment
activates a relay-published session-device subtype, Core remains the intended
base-schema and stamp owner; the current reservation itself permits no such
event. Encrypted session traffic rides the Comms `kind:31015` and `kind:31016`
inner-rumor carriers; their `comms/0.5.0` stamp identifies only the carrier
and never a Control conformance level.

The Control version is bound by the mutually confirmed Comms negotiation,
not by another event marker. Every side-effect audit record MUST retain the
negotiated Control version, negotiated Comms carrier version, protocol id,
required feature set, DR session identity, peer identity, request identity,
authorization decision, and result for as long as the recorded decision is
retained. Audit material MUST be encrypted at rest.

<a id="control-reserved-scope"></a>
## 5. Reserved integration scope

Acceptance and integration of ADR-030 must complete at least these areas:

1. enrollment bootstrap, active-invite validation, session-device binding,
   finality, expiration, and revocation;
2. closed RPC request, response, replay-cache, expiry, and error schemas;
3. grant tiers, object-level authorization, security-policy state, and
   privileged mutation ceremonies;
4. single-use enrollment-token issuance, redemption, issuer binding,
   idempotency, revocation, expiry, and grant ceilings;
5. MCP JSON-RPC lifecycle, bidirectional capabilities, tool-schema
   enforcement, cancellation, timeout, and default-deny inbound execution;
6. encrypted local audit semantics and restart-safe state; and
7. minimum positive and negative conformance vectors for each required path.

Until that work lands, these labels describe allocation, not interoperable
wire behavior.

<a id="control-security"></a>
## 6. Security invariants

Registry revision 2 assigns exactly these Control invariants:

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests, grants, tokens, or side effects are encrypted at rest under Core, Comms, and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never receives persona epoch, NID, audience, repository-decryption, or ratchet secrets.

These invariants allocate the security boundary. Full conformance tests for
them are part of the integration gate below.

<a id="control-strict-profile"></a>
### 6.1 Reserved Control strict profile

The stable identifier `heterodyne-control-strict-v1` is defined now so a later
activation cannot silently change its composition. The profile remains
reserved and inactive with the rest of Control 0.5.0:

<!-- fixture:control-strict-profile -->
```json
{
  "profile_id": "heterodyne-control-strict-v1",
  "conformance_class": "Core+Comms+Control profile",
  "state": "reserved-inactive",
  "requires_profiles": [
    "heterodyne-core-strict-v1",
    "heterodyne-comms-strict-v1"
  ],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "CONTROL-I-AUDIT-AT-REST",
    "CONTROL-I-SESSION-KEY-CONFINEMENT"
  ]
}
```

`CONTROL-I-AUDIT-AT-REST` depends only on the listed Core, Comms, and Control
rules. An implementation MUST NOT make it depend on any `SOCIAL-I-*`
invariant, Social feature, or Matrix feature. This preserves a usable Control
profile for a client that implements no Social document.

Because Control conformance is closed, an implementation MUST NOT place
`heterodyne-control-strict-v1` in `strict_profiles`, claim the profile in a
conformance report, or treat its stable identifier as evidence of activation.
Activation requires the same accepted-ADR, integrated-schema, and vector gates
as baseline Control conformance, plus all prerequisite strict-profile results.

<a id="control-conformance"></a>
## 7. Incomplete conformance gate

There is **no Control conformance claim** for this incomplete draft. ADR-030
must first be accepted, its normative schemas and state machines must be
integrated into this document and the required lower-layer extension points,
and a minimum Control vector corpus must cover the integrated behavior.

<!-- fixture:control-conformance-gate -->
```json
{
  "can_claim_control_conformance": false,
  "blockers": [
    "adr-030-accepted",
    "adr-030-integrated",
    "minimum-control-vectors"
  ]
}
```

Implementations MAY experiment with the reserved profile identifiers, but
MUST label that work non-conformant and incomplete. Removing this gate
requires a later reviewed change that supplies all three listed conditions;
version metadata alone cannot open it.
