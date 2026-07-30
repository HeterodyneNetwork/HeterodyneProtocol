# Heterodyne Control Profile Specification

Document ID: `control`

Version: `control/0.5.0`

Status: **incomplete 0.5.0 draft**

Registry revision: `3`

Normative dependencies:

- `heterodyne:comms/0.5.0#comms-conformance`

This document prepares Control's first 0.5.0 release, descended independently
from the archived Heterodyne 0.4.x monolith. It is current normative authority
for this incomplete profile at this repository path, but remains unreleased pending explicit release approval.
It is not a
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
requirements have not yet been integrated from ADR-030. The relay-affinity and
automated-agent subsets defined in §§5-6 are normative and vectored under
accepted ADR-035 and ADR-036, but they do not by themselves activate the
incomplete session-device, enrollment, grant, or MCP profile. An
implementation MUST NOT infer missing ADR-030 behavior from ADR prose or
advertise Control conformance from this document.

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

Registry revision 3 contains the draft reservation
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

<a id="control-relay-affinity"></a>
## 5. Ingress-relay affinity and restart-safe replay

Every authenticated Control request MUST validate against
`docs/spec/schemas/control/control-rpc-request-v1.schema.json` and bind exact
Control version, DR session ID, request ID, method, closed payload, canonical
payload digest, expiry, and the normalized relay URL on which the valid
encrypted carrier was received. `reply_relay` and every other
request-selected response URL are forbidden.

Before dispatch, the full node MUST atomically reserve:

```text
(session ID, request ID, method, payload digest, first ingress relay)
```

The first cryptographically valid arrival controls execution. Concurrent
identical arrivals join that reservation and MUST NOT dispatch another
operation. A request ID reused with another session, method, or payload digest
MUST fail with `control-request-id-conflict`; an expired request fails with
`control-request-expired`.

The final response MUST validate against
`docs/spec/schemas/control/control-rpc-response-v1.schema.json` and MUST be
persisted atomically before it becomes replayable. The full node publishes the
response first and only to the authenticated request's ingress relay and MUST
NOT fan it out across configured relays.

If a response is lost, the client MAY retry the byte-identical logical request
with the same request ID and expiry through another advertised relay. The full
node MUST return the one persisted in-progress or final result through that
retry's authenticated ingress relay without re-execution. After restart it
MUST recover or resume the reserved operation through the same idempotency
boundary and MUST NOT repeat a committed side effect.

<a id="control-agent-requirements"></a>
## 6. Requirements for automated agents

An AI or programmatic principal MUST use the negotiated agentic Control/DR
profile, obtain a current scoped workload token from the persona's built-in
OIDC issuer, and invoke only `heterodyne.agent.publish`. It MUST refuse an
instruction to obtain or use any persona, epoch, NID, human-device, or agent
role private key; invoke `sign_event` or another raw signing method; select a
human publication profile; remove, alter, or falsify mandatory agent
attribution; impersonate a human author; or bypass token, sender-proof, scope,
kind, resource, size, rate, or burst enforcement.

The full node MUST independently enforce the same boundary. Agentic capability
and tool advertisements MUST NOT expose `sign_event`, private-key operations,
a human-profile publication fallback, or an attribution-bypass option. A
rejected automated request MUST fail closed without signing and without an
unlabeled or human-key fallback.

<a id="control-agent-token"></a>
### 6.1 Token issuance over Control/DR

After mutual MCP initialization, the token request MUST validate against
`docs/spec/schemas/control/control-agent-token-request-v1.schema.json`. It
binds the authenticated session and request, fresh issuer challenge, exact
requested scopes and resource, requested expiry, and a workload-JWK proof. The
proof MUST cover the session, request ID, issuer, client ID, scope, resource,
challenge, issue time, and expiry.

The full node MUST replay canonical Comms private-ledger state, require its
current OIDC mint authority, and apply
`heterodyne:comms/0.5.0#comms-agent-token`. The response contains the standard
sender-constrained access token and no refresh token. Control/DR issuance does
not expose the private claim ledger or require a direct HTTPS connection.

<a id="control-agent-publish"></a>
### 6.2 Intent-only publication and finite limits

The `heterodyne.agent.publish` payload MUST validate against
`docs/spec/schemas/control/control-agent-publish-v1.schema.json`. It contains
only token and sender-proof presentation, content, requested kind, resource,
feed, and permitted options. The closed schema forbids `sig`, `pubkey`, private
key material, authoritative attribution tags, and a caller-selected human
profile.

For every side effect the full node MUST revalidate token type, time, status,
audience, scope, ledger binding, role, and fresh sender proof; then enforce the
registered kind, feed, resource, maximum content bytes, rate window/count, and
burst. It passes only an accepted intent to
`heterodyne:comms/0.5.0#comms-agent-attribution`. Raw signing returns
`agent-method-prohibited`; key access, human-profile use, and attribution
bypass return their exact registered reason codes. Resource, size, rate, and
burst excesses return `agent-resource-denied`, `agent-size-exceeded`, or
`agent-rate-limited`.

<a id="control-agent-audit"></a>
### 6.3 Encrypted audit

Every automated decision MUST produce a record conforming to
`docs/spec/schemas/control/control-audit-record-v1.schema.json` inside the
encrypted Control audit boundary. It retains the negotiated versions, agent
identity/class, token `jti`, source claim IDs, ledger checkpoint, session and
request IDs, method, payload digest, proof result, role and current key,
injected attribution, event ID, destinations, decision, result, and verified
review evidence when applicable.

The raw access token MUST NOT be retained by this record or exposed in public
events. A separately bounded encrypted diagnostic policy MAY retain it only
for a declared shorter interval. Audit persistence MUST precede replay of a
final side-effect result.

<a id="control-reserved-scope"></a>
## 7. Remaining ADR-030 integration scope

Acceptance and integration of ADR-030 must complete at least these areas:

1. enrollment bootstrap, active-invite validation, session-device binding,
   finality, expiration, and revocation;
2. the remaining general RPC method/error schemas beyond the normative
   relay-affinity and agent subsets in §§5-6;
3. grant tiers, object-level authorization, security-policy state, and
   privileged mutation ceremonies;
4. single-use enrollment-token issuance, redemption, issuer binding,
   idempotency, revocation, expiry, and grant ceilings;
5. MCP JSON-RPC lifecycle, bidirectional capabilities, tool-schema
   enforcement, cancellation, timeout, and default-deny inbound execution;
6. general encrypted local audit semantics beyond the agent subset and
   restart-safe enrollment/grant state; and
7. minimum positive and negative conformance vectors for each required path.

Until that work lands, these labels describe allocation, not interoperable
wire behavior.

<a id="control-security"></a>
## 8. Security invariants

Registry revision 3 assigns exactly these Control invariants:

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests, grants, tokens, or side effects are encrypted at rest under Core, Comms, and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never receives persona epoch, NID, audience, repository-decryption, or ratchet secrets.
- **CONTROL-I-INGRESS-RELAY-AFFINITY:** A Control response is published first and only to the authenticated request ingress relay, while identical cross-relay retries reuse one restart-safe execution result.
- **CONTROL-I-AGENT-NO-KEY-RELEASE:** An automated principal never receives or directly exercises a persona, epoch, NID, human-device, or agent-role private key.
- **CONTROL-I-AGENT-INTENT-ONLY:** An automated principal publishes only through the intent-level agent method, and raw signing, human-profile fallback, and attribution bypass fail closed.
- **CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS:** Every automated side effect requires a current scoped token, sender proof, canonical authorization state, and finite kind, resource, size, rate, and burst limits.

These invariants allocate the security boundary. Full conformance tests for
them are part of the integration gate below.

<a id="control-strict-profile"></a>
### 8.1 Reserved Control strict profiles

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

The revision-3 subsets require a distinct reserved profile. The v1 declaration
above remains unchanged:

<!-- fixture:control-strict-profile-v2 -->
```json
{
  "profile_id": "heterodyne-control-strict-v2",
  "conformance_class": "Core+Comms+Control profile",
  "state": "reserved-inactive",
  "requires_profiles": [
    "heterodyne-comms-strict-v2"
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
    "COMMS-I-PUBLIC-READER-TIER1-ONLY",
    "COMMS-I-AGENT-ROLE-BINDING",
    "COMMS-I-AGENT-ATTRIBUTION",
    "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
    "CONTROL-I-AUDIT-AT-REST",
    "CONTROL-I-SESSION-KEY-CONFINEMENT",
    "CONTROL-I-INGRESS-RELAY-AFFINITY",
    "CONTROL-I-AGENT-NO-KEY-RELEASE",
    "CONTROL-I-AGENT-INTENT-ONLY",
    "CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS"
  ]
}
```

Because baseline Control conformance is closed, an implementation MUST NOT
advertise `heterodyne-control-strict-v2`. Its normative subset results may be
reported only as partial ADR-035/ADR-036 evidence.

<a id="control-conformance"></a>
## 9. Incomplete conformance gate

There is **no Control conformance claim** for this incomplete draft. The
ADR-035 relay-affinity subset and ADR-036 automated-agent subset are normative,
schema-closed, and vectored, but do not fill the remaining ADR-030
session-device, enrollment, grant, MCP lifecycle, and general RPC requirements.

<!-- fixture:control-conformance-gate -->
```json
{
  "can_claim_control_conformance": false,
  "blockers": [
    "adr-030-accepted",
    "adr-030-session-device-and-enrollment-integrated",
    "adr-030-grants-and-mcp-lifecycle-integrated",
    "adr-030-minimum-general-control-vectors"
  ],
  "integrated_normative_subsets": [
    "adr-035-relay-affinity",
    "adr-036-agent-workload-publication"
  ]
}
```

Implementations MAY experiment with the reserved profile identifiers, but
MUST label that work non-conformant and incomplete. Removing this gate
requires a later reviewed change that supplies every listed blocker; version
metadata or passing only the integrated subset vectors cannot open it.
