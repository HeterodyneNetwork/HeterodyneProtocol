# Heterodyne Control Profile Specification

Document ID: `control`

Version: `control/0.5.0`

Status: **incomplete 0.5.0 draft**

Registry revision: `4`

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
the Model Context Protocol (MCP) data-layer profile in §§5-7. It also reserves
session lifecycle, revocation, replay protection, object-level authorization,
side-effect audit, and inbound-execution policy.

The closed draft schemas, state machines, rejection rules, and draft vector
corpus in §§5-7 include ingress-relay affinity and automated-agent
requirements. This is an interoperable draft definition, but not an active
conformance feature: registry revision 4 still leaves the session-device
profile reserved-inactive, and the credential-continuity and recovery
activation batch has not been issued. An implementation MAY exercise
these rules only as visibly non-conformant draft behavior and MUST NOT
advertise Control conformance.

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

Mutual Comms negotiation selects exactly one of
`heterodyne-control-human-v1` or `heterodyne-control-agent-mcp-v1`. Those
identifiers select the closed Control schemas and method state machines in
this document. A generic Comms carrier, an unconfirmed negotiation, or a
different protocol identifier does not establish Control semantics or
conformance.

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
Control revisions name qualified Comms anchors, and the schemas below carry only Control method
inputs and decisions inside the existing Comms carriers.

<a id="control-session-device-profile"></a>
## 3. Session-device delegation profile

The registry contains the draft reservation
`heterodyne-control-session-device-v1` on Core `kind:31001`, with immutable
discriminator
`tags:heterodyne=delegation,binding_nonce,key_proof;radicle_nid=absent`.
The reservation is explicitly **reserved-inactive** in `control/0.5.0`.

Core §6.1 now defines the common NID-less candidate shape, exact tag order,
`pubkey:<key>` address, nonzero expiry, owner stamp, epoch-key/KEL checks, and
the BIP-340 publishing-key proof over
`heterodyne-light-binding-v1|<cold-root>|<publishing-key>|session-device|<binding-nonce>`.
That definition permits deterministic structural diagnostics; it does not
activate the higher-layer profile. A candidate containing `radicle_nid` or
`nid_proof` is invalid for this discriminator and cannot inherit durable NID
authority.

The registry entry's `owner: control`, `stamping: false`, and draft status
record its future ownership and stamp intention; that reservation does not
make it active, change current Core verification, or authorize production.
Relay-valid evidence remains provisional. Canonical repository reachability
can make the candidate delegation final, but even a final candidate with
otherwise active Comms authorization grants no Control authority while this
profile gate is closed.

Activation now requires all of the following in one atomic artifact batch:

1. the complete closed enrollment, grant, token, RPC, MCP, lifecycle, and
   audit schemas and state machines in this document;
2. every minimum positive and negative vector required by the gated Control,
   ingress-relay-affinity, automated-agent, credential-continuity, and
   recovery profiles;
3. the complete recovery feature and schema allocations, with no placeholder,
   wildcard, omission, or unbound prerequisite; and
4. a future registry revision plus matching family/release manifests that explicitly
   change the profile and Control feature gates from inactive to active.

<!-- fixture:control-session-device-reservation -->
```json
{
  "profile_id": "heterodyne-control-session-device-v1",
  "registry_status": "draft",
  "profile_state": "reserved-inactive",
  "core_candidate_shape_defined": true,
  "conforming_events_allowed": false,
  "activation_requires": [
    "closed-control-profile",
    "complete-credential-continuity-and-recovery-vector-batch",
    "atomic-future-registry-feature-and-schema-allocation",
    "matching-family-and-release-manifests"
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
`docs/spec/schemas/control/control-rpc-request-v1.schema.json`. Its complete
caller-supplied shape is `{id, method, params, expires_at}`. The negotiated
Control version, accepted DR session ID, canonical payload digest, and
normalized relay URL on which the valid encrypted carrier was received are
receiver-observed execution context, not request members. `spec_version`,
`session_id`, `payload_digest`, `ingress_relay`, `reply_relay`, and every other
caller-selected response URL are therefore forbidden by the closed request
schema.

Before dispatch, the full node MUST atomically reserve:

```text
(session ID, request ID, method, payload digest, expiry, first ingress relay)
```

The first cryptographically valid arrival controls execution. Concurrent
identical arrivals join that reservation and MUST NOT dispatch another
operation. A request ID reused with another session, method, payload digest,
or expiry MUST fail with `control-request-id-conflict`; an expired request
fails with `control-request-expired`.

The final NIP-46-shaped `{id, result}` or `{id, error}` response MUST validate
against `docs/spec/schemas/control/control-rpc-response-v1.schema.json` and
MUST be persisted atomically in the reservation before it becomes
publishable or replayable. The full node publishes the response first and
only to the authenticated request's actual ingress relay and MUST NOT fan it
out across configured relays.

If a response is lost, the client MAY retry the byte-identical logical request
with the same request ID and expiry through another advertised relay. The full
node MUST return the one persisted in-progress or final result only through
that retry's actual authenticated ingress relay without re-execution. After
restart it MUST recover or resume the reserved operation through the same
idempotency boundary and MUST NOT repeat a committed side effect. If durable
evidence cannot prove whether the effect committed, the executor MUST fail
closed for explicit repair rather than dispatch it again.

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
## 7. Closed draft state machines

This section defines Control's closed draft behavior. It does not activate the
registry reservation or open the conformance gate in §9. Every JSON
payload named here is the plaintext of a Comms generic subprotocol inner rumor
after successful Comms authentication and mutual negotiation. Control defines
no event kind, outer wrapper, transport, or wire stamp.

<a id="control-enrollment"></a>
### 7.1 Enrollment

An enrollment request MUST validate against
`docs/spec/schemas/control/control-enrollment-request-v1.schema.json`. It
names the exact active epoch-invite event, enrollee publishing key, on-wire
binding nonce, Core-defined BIP-340 `key_proof`, one bootstrap credential,
the requested grant, and any requested inbound-execution capability. Omission
of `inbound_execution` means disabled. The request MUST NOT carry a Control
version stamp, ingress relay, response route, epoch secret, or persona secret.

The executor applies this state machine in order:

1. Comms has already authenticated the `control-enrollment` carrier and
   transcript and returned its non-oracular hold. Control rejects any request
   whose named `kind:30078`, `d = double-ratchet/invites/epoch` invite is not
   the exact currently active event, is tombstoned, lacks the current
   `kel_head`, or is not signed by the current KERI-authoritative epoch key.
2. Control reconstructs the Core binding transcript from the candidate
   publishing key and on-wire nonce, verifies `key_proof`, and requires that
   the nonce is the live challenge or the presented unspent enrollment-token
   ID. It binds the invite ID, enrollee key, accepted DR transcript/session,
   future delegation address/event ID, grant subject, enrolling full-node NID
   and device key, and negotiated protocol/version tuple. Substitution at any
   join fails closed.
3. The pending request expires at its recorded deadline (RECOMMENDED default:
   two minutes). Remote interactive enrollment validates challenge-response
   before showing any local prompt. Interactive and co-located enrollment then
   require a fresh epoch-key unlock ceremony displaying the enrollee
   fingerprint. Token enrollment uses the already-authorized token ceremony
   in §7.2. Organization-persona enrollment is prohibited until a later
   delegate-threshold artifact is specified.
4. The executor issues the exact Core-owned
   `heterodyne-control-session-device-v1` candidate. A relay-valid candidate
   yields only visibly labeled `provisional` state and no authority.
   `deny-until-repo` treats it as absent. The device becomes `active` only
   when that exact delegation is canonical-repository-final and every
   applicable grant decision from the Comms private claim ledger is
   repository-final `active`.

The default grant for a successful enrollment is `regular`. Delivery,
accepted DR state, a final delegation alone, a filtered device view, or an
OIDC/JWT projection never substitutes for active ledger authority. A strict
light client uses outbound Tor. A browser without Tor MAY use an authenticated
shared clearnet relay only in visibly declared reduced-assurance mode.
Optional Tor access to an advertised onion repo relay may obtain repository
finality or content, but is not a Control transport.

<a id="control-enrollment-token"></a>
### 7.2 Enrollment-token ledger

An enrollment token MUST validate against
`docs/spec/schemas/control/control-enrollment-token-v1.schema.json`. Its
`token_class` is exactly `control-enrollment`; its epoch-key signature binds
the persona, current epoch key and `kel_head`, unique token ID, minting device,
issue and expiry times, non-full grant, and optional expected enrollee key.
Minting requires the §7.1 fresh-authorization ceremony. A token with a `full`
grant is semantically invalid even if its nested grant is structurally valid.

The sole authoritative token state is a Comms private-claim-ledger record with
one of `unspent`, `spent`, or `revoked`. Only the minting device may redeem.
Redemption requires that record to be repository-final `active` and requires
its signed persona, epoch key, and complete `kel_head` to equal the executor's
current KERI-authoritative state. Before delegation publication the executor
determines the exact delegation event ID, atomically changes `unspent` to
`spent`, and records both the enrolling key and that delegation ID. A
same-token, same-key retry returns the recorded delegation idempotently; a
different-key retry conflicts. Expired, revoked, wrong-issuer, wrong-key,
invalid-signature, stale-persona, stale-epoch, stale-`kel_head`, non-final, and
already-spent-for-another-key presentations fail closed. Redemption is shown
in the filtered device inventory.

A Control enrollment token is not a Comms/OIDC agent workload access token.
Neither is a recovery transfer/bootstrap grant. Implementations MUST
type-separate the three classes and MUST NOT accept one for another class's
operation.

<a id="control-grants"></a>
### 7.3 Grants and protected policy state

A filtered grant MUST validate against
`docs/spec/schemas/control/control-grant-v1.schema.json`. The tier and exact
repository, configuration-namespace, and session sets are an
object-authorization intersection, not hints:

- `baseline` permits `ping`, `get_public_key`, `dm.read`, `dm.write`,
  `dm.sign`, `nip44_encrypt`, `nip44_decrypt`, `decrypt`, and
  `session.self_revoke`;
- `regular` is the default and adds human-profile `sign_event`, `publish`,
  `repo.write`, `feed.update`, `config.get`, and `config.put`;
- `full` adds only the ability to request `device.activate`,
  `device.cross_sign`, `token.mint`, and `session.unlock`; activation,
  cross-signing, and token minting still require a fresh local ceremony; and
- `media.upload` requires the independent `media_upload` flag at any tier.

Every method has one fixed object class. `ping` and `get_public_key` alone use
`none` and require an empty object ID. DM, encryption/decryption, signing,
publishing, self-revocation, media upload, activation, cross-signing, token
minting, and unlock methods use the current granted `session`; `repo.write`
and `feed.update` use a granted `repository`; and `config.get` and
`config.put` use a granted `config_namespace`. The caller cannot choose
`none` for an object-bearing method or substitute another object class. A
method/object-class mismatch fails before object-set intersection.

The agentic profile never inherits those human methods. It exposes only its
closed advertised tools and the §6 intent-only publication path.

The Comms private claim ledger is the sole authority for the grant table,
token registry, device inventory, and revocation records. Only
repository-final `active` decisions grant positive authority. Authenticated
reductions and revocations take effect immediately and are then committed for
finality. `provisional`, `untrusted`, `conflicted`, `invalid`, `expired`, and
`revoked` decisions fail closed. Every invocation rechecks the method and
exact object against current state.

Those four security-policy data sets are not configuration. `config.put`
MUST reject any path reaching them, regardless of tier. Their only mutation
paths are a fresh-authorized enrollment, activation, or token-mint ceremony;
caller self-revocation of its own record; automatic inactivity lapse; and a
fresh-authorized local full-node administration action. No grant may edit
itself, resurrect a token, clear revocation, or turn a NID-less session device
into a claim-ledger reader.

<a id="control-rpc"></a>
### 7.4 General RPC dispatch

Human requests use `heterodyne-control-human-v1` and validate against the
closed request schema in §5. Agentic JSON-RPC uses
`heterodyne-control-agent-mcp-v1` and §7.7. The negotiated profile determines
the permitted method vocabulary. A full node MUST validate `params` against
the method or tool schema, apply §7.3 object authorization, and then pass
every side-effect through §5's durable reservation before execution.
Destructive or exfiltrating methods SHOULD require explicit confirmation, and
bulk decrypt-on-behalf behavior SHOULD be rate-limited and surfaced.

Key-operation methods run only on the authenticated epoch endpoint after
enrollment; other methods run on the accepted device session. Vanilla NIP-46,
if separately offered, has separate grants and MUST NOT be an automatic
fallback. A client must visibly identify its reduced forward-secrecy and
lifecycle guarantees.

<a id="control-configuration"></a>
### 7.5 Filtered configuration

After activation the full node sends the complete grant-filtered live
configuration, followed by authorized updates, through the accepted DR
session. The view includes every setting needed to render the permitted UI,
but excludes security-policy state, private claim records, claim-ledger
decryption keys, issuer keys, epoch/NID/audience/repository-decryption keys,
and ratchet secrets. Configuration writes validate their closed namespace and
object scope and cannot use a generic path to reach an excluded record.

<a id="control-marmot-operations"></a>
### 7.6 Node-mediated Marmot operations

A grant MAY authorize a `node-mediated` conversation view without granting an
MLS leaf or any group secret. The designated full or recovery node owns the
Marmot leaf and MUST expose only the exact group and methods permitted by the
current repository-final grant.

The closed conversation method families are:

- `marmot.group.list`, `marmot.group.read`, and `marmot.group.subscribe`;
- `marmot.message.send`, `marmot.message.reply`, `marmot.message.react`, and
  `marmot.message.edit`;
- `marmot.media.put` and `marmot.media.get`; and
- the administrative `marmot.member.add`, `marmot.member.remove`,
  `marmot.routing.rotate`, `marmot.host.authorize`,
  `marmot.host.remove`, `marmot.nid.admit`, and `marmot.nid.remove`.

Every request MUST bind the exact Marmot group, requested application kind,
object or message target, media type and size when applicable, and an
idempotency key. Read and subscription responses MUST be filtered to the
grant's group, history boundary, and retention policy. The node MUST construct
and validate the Marmot application event; a caller MUST NOT supply a signed
outer `kind:445`, MLS secret, account private key, or leaf private key.

Administration additionally requires a current Core-bound
`marmot:group-admin` role, current Marmot administrator status, and an exact
object grant for the operation. A host or Radicle delegate without those
authorities MUST be rejected. NID admission and removal MUST apply the Core
Radicle admission rules and MUST NOT be treated as MLS membership on their
own.

Membership and operational routing follow
`heterodyne:comms/0.5.0#comms-marmot-routing-generation` and
`heterodyne:comms/0.5.0#comms-marmot-rotation`. An addition prepares the new
repository and routing state for the Add transition. A removal becomes
canonical before a remaining administrator performs the privacy-preserving
routing rotation. A size or repair rotation preserves membership. The
executor MUST NOT apply a new epoch or expose its directory binding before the
old-route publication receives the required durable acknowledgement.

An exclusive leaf restore is a separately confirmed key operation. The node
MUST fence the prior instance before activating the restored leaf. Creating an
independent new device uses a KeyPackage, Add, and Welcome and MUST NOT receive
prior epoch secrets through this method family.

<a id="control-marmot-agent-operations"></a>
### 7.7 Automated Marmot operations

An automated principal always uses the node-mediated path. Its five-minute
sender-constrained workload token MUST scope the exact Marmot group,
application kinds, media types, maximum object and aggregate media size, rate
window, count, and burst. A generic feed or public-resource scope does not
authorize a group message.

After validating the token, sender proof, current ledger, group role, and
limits, the full node constructs the unsigned inner Marmot application event,
inserts the canonical protected automation attribution, and sends through the
authorized full-node-held `agent:<role-id>` account and leaf. Verification
MUST bind the inner application-event pubkey, Marmot MLS sender account,
current KERI agent role, workload role and scope, and automation attribution.
The agent receives no account key, leaf secret, repository credential, or raw
signing method.

Unsupported Marmot application kinds, a group mismatch, unavailable role,
missing attribution profile, or exhausted size/rate/burst authority MUST fail
closed without a human-account fallback. The encrypted audit record MUST bind
the Marmot group, routing generation, inner event ID, resulting outer event ID,
durable publication target, and exact token scope.

<a id="control-session-lifecycle"></a>
### 7.8 Session lifecycle and termination

A session-device delegation SHOULD carry a short `valid_until`, refreshed
only while authorized activity continues. The RECOMMENDED configurable
inactivity timeout is 15 minutes. At expiry the executor drops the grant,
invalidates the session locally, and records `lapsed`. Logout performs
self-revocation and local key deletion; a self-revocation is accepted from
every tier without ceremony because it only reduces authority.

Self-revocation, logout, inactivity, ledger revocation/reduction, or an
applicable credential transition stops Control immediately and invalidates
affected DR sessions locally. The separately authenticated persistent NIP-59
peer tombstone binds the old session and both delivery identities and is sent
after transition acceptance; acknowledgement cannot delay local invalidation.
It is neither an RPC response nor a transcript.

Before any received Control plaintext is released, Comms DR receive-state
advancement, durable state persistence, and consumed-message-key erasure MUST
complete atomically. Recovery never restores active DR state, message keys,
temporary workload tokens, sender proofs, or a live Control session; restored
peers negotiate fresh sessions.

<a id="control-mcp"></a>
### 7.9 Agentic MCP data layer

Agentic peers use the MCP 2025-11-25 data layer only; MCP transports are not
used. Frames MUST validate against
`docs/spec/schemas/control/control-mcp-frame-v1.schema.json`, and each
capability set MUST validate against
`docs/spec/schemas/control/control-capability-set-v1.schema.json`. The
Heterodyne set is the value at
`capabilities.experimental["network.heterodyne.control"]`; it does not replace
MCP's capability object.

An `initialize` request carries exactly the pinned `protocolVersion`,
`capabilities`, and `clientInfo` members required by MCP. Its result carries
`protocolVersion`, `capabilities`, and `serverInfo`, after which the client
sends `notifications/initialized`. Request IDs are non-empty strings or safe
integers. A `tools/call` carries the advertised `name` and optional
`arguments`; its finite timeout comes from the negotiated Heterodyne
capability and is not an invented MCP request member. Tool responses contain
exactly one JSON-RPC `result` or `error`. Within this closed profile,
successful tool content uses MCP `TextContent` blocks plus optional
`structuredContent`; no Heterodyne-specific content-block type exists. No
tool runs before both initialization directions complete: both peers MUST
complete `initialize` before any tool call. A tool the peer did not advertise
MUST be rejected, as must arguments outside that schema or a method from the
other Control profile.

`notifications/cancelled` carries MCP's `requestId` and optional `reason`;
`request_id` is not an alias. Cancellation notifications are honored only when
the negotiated capability permits them; they never undo a committed side effect.
An in-progress request may stop; a notification received after
side-effect commit or completion is ignored and never rolls the effect back.
Every call terminates at its negotiated timeout. For full-node-to-light use,
inbound execution is absent by default and requires matching opt-in in both the
enrollment request and the light client's capability set. If enabled, it
remains sandboxed and allowlisted, has no ambient filesystem, network, or
secrets access without a separate object grant, visibly surfaces the active
session, and SHOULD request local consent for each newly exercised tool.

Only after mutual initialization may an agent request a workload token through
the §6.1 issuance tool. Every publication then uses
`heterodyne.agent.publish`, a sender-constrained token valid for at most five
minutes, and a fresh per-use proof. Issuance and use bind the exact issuer,
pairwise subject, `client_id`, role ID, Control session, request ID, method,
canonical payload digest, and current credential-ledger persona, generation,
checkpoint, and status. A generation reset purges prior-generation pending
issuance and authority and requires reissuance. The per-use proof is signed by
the token's sender-constrained key, has an unused nonce, is live at use time,
expires no later than the token, and repeats the exact request and
credential-ledger bindings. A changed checkpoint or non-`active` status also
invalidates authority. Raw signing, key access, human-profile publication,
unlabeled output, and human-key fallback remain prohibited.

<a id="control-audit-retention"></a>
### 7.10 Audit, ordering, and retention

For every side effect the executor first obtains a current Comms
authorization decision, then creates the §5 reservation, executes or
reconciles the operation once, atomically persists commit evidence and the
encrypted `CONTROL-I-AUDIT-AT-REST` record, and only then persists and
publishes the final response. The audit binds negotiated versions/profile,
session and request IDs, method, canonical payload digest, expiry, actual
ingress, source claim IDs/checkpoint/decision, object authorization, result,
and side-effect evidence. Agent records additionally satisfy §6.3.

Relay-carried requests and responses, DR state, message keys, sender proofs,
and temporary workload tokens are never repository-committed or backfilled.
A bounded encrypted side-effect audit MAY be included in protected recovery
material, but is not a replayable RPC transcript. It contains no message key
and no raw workload token except under a separately declared, shorter,
protected diagnostic retention policy.

<a id="control-security"></a>
## 8. Security invariants

The registry assigns exactly these Control invariants:

- **CONTROL-I-AUDIT-AT-REST:** Control audit records containing requests, grants, tokens, or side effects are encrypted at rest under Core, Comms, and Control-owned protection rules without a Social dependency.
- **CONTROL-I-SESSION-KEY-CONFINEMENT:** A Control session device never receives persona epoch, NID, audience, repository-decryption, or ratchet secrets.
- **CONTROL-I-INGRESS-RELAY-AFFINITY:** A Control response is published first and only to the authenticated request ingress relay, while identical cross-relay retries reuse one restart-safe execution result.
- **CONTROL-I-AGENT-NO-KEY-RELEASE:** An automated principal never receives or directly exercises a persona, epoch, NID, human-device, or agent-role private key.
- **CONTROL-I-AGENT-INTENT-ONLY:** An automated principal publishes only through the intent-level agent method, and raw signing, human-profile fallback, and attribution bypass fail closed.
- **CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS:** Every automated side effect requires a current scoped token, sender proof, canonical authorization state, and finite kind, resource, size, rate, and burst limits.
- **CONTROL-I-MARMOT-GRANT-CONFINEMENT:** Node-mediated Marmot operations expose only grant-filtered content and actions while all account, MLS leaf, epoch, and repository secrets remain on the designated node.

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
invariant or Social feature. This preserves a usable Control
profile for a client that implements no Social document.

Because Control conformance is closed, an implementation MUST NOT place
`heterodyne-control-strict-v1` in `strict_profiles`, claim the profile in a
conformance report, or treat its stable identifier as evidence of activation.
Activation requires the same atomic future-registry
credential-continuity/recovery feature, schema, vector, and manifest gates as
baseline Control conformance, plus all prerequisite strict-profile results.

The newer subsets require a distinct reserved profile. The v1 declaration
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
reported only as non-conformant gated-Control, ingress-relay-affinity, and
automated-agent draft evidence.

<a id="control-conformance"></a>
## 9. Incomplete conformance gate

There is **no Control conformance claim** for this incomplete draft. The
session-device, enrollment, grant, MCP lifecycle, general RPC, audit,
relay-affinity, and automated-agent behavior is closed and draft-vectored.
That integration is necessary but insufficient: a future activating registry revision and the
complete credential-continuity and recovery feature, schema, prerequisite,
vector, family-manifest, and release-manifest artifact set must land
atomically.

<!-- fixture:control-conformance-gate -->
```json
{
  "can_claim_control_conformance": false,
  "blockers": [
    "activating-registry-revision-not-published",
    "recovery-feature-and-core-schemas-not-integrated",
    "credential-continuity-and-recovery-vector-batch-incomplete",
    "matching-family-and-release-manifests-not-issued"
  ],
  "integrated_normative_subsets": [
    "gated-control-profile",
    "ingress-relay-affinity",
    "agent-workload-publication",
    "node-mediated-marmot"
  ]
}
```

Implementations MAY experiment with the reserved profile identifiers, but
MUST label that work non-conformant and incomplete. Removing this gate
requires one later reviewed atomic change that supplies every listed blocker;
version metadata, draft schema validity, or passing the integrated draft
vectors cannot open it.
