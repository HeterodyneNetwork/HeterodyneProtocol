# Heterodyne Control Profile Specification

Document ID: `control`

Version: `control/0.5.0`

Status: **incomplete 0.5.0 draft**

Registry revision: `1`

Normative dependencies:

- `heterodyne:comms/0.5.0#comms-conformance`

This document is descended independently from the archived Heterodyne 0.4.x
monolith. It is not a synchronized family version. Its conformance expression
is **Core + Comms conformant + Control profile**, but this incomplete draft
makes no Control conformance claim.

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
Comms carrier rumors. Relay-published Control-profiled delegations retain
their Core base schema and Core owner stamp.

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

<a id="control-session-device-profile"></a>
## 3. Session-device delegation profile

Registry revision 1 reserves
`heterodyne-control-session-device-v1` on Core `kind:31001`. The Core base
schema, verification algorithm, and Core stamp remain authoritative. The
Control profile adds session-device semantics only and MUST NOT change the
Core event shape or owner stamp.

The profile's immutable discriminator is
`tags:heterodyne=delegation,binding_nonce,key_proof;radicle_nid=absent`.
It selects a NID-less session-device interpretation only when all of those
conditions hold. The profile is non-stamping: it adds no `control/0.5.0`
marker and does not override the Core stamp. A verifier applies the base
delegation requirements at
`heterodyne:core/0.5.0#core-nid-delegation` before any Control-specific
enrollment or grant decision.

Session devices are distinct from authorized durable NID devices. The former
are confined Control principals; the latter may separately qualify for Comms
credential-plane synchronization. A Control grant cannot convert a session
device into a durable credential-sync device.

<a id="control-wire-ownership"></a>
## 4. Wire ownership and audit binding

Control MUST NOT own or add a wire stamp. A relay-published session-device
`kind:31001` carries only the Core base-schema version placement. Encrypted
session traffic rides the Comms `kind:31015` and `kind:31016` inner-rumor
carriers; their `comms/0.5.0` stamp identifies only the carrier and never a
Control conformance level.

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

Registry revision 1 assigns exactly these Control invariants:

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests,
  grants, tokens, or side effects are encrypted at rest under Core, Comms,
  and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never
  receives persona epoch, NID, audience, repository-decryption, or ratchet
  secrets.

These invariants allocate the security boundary. Full conformance tests for
them are part of the integration gate below.

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
