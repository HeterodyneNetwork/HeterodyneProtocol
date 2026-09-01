# Heterodyne Control Profile Specification

Document ID: `control`

Control is a section of the Heterodyne specification and is governed by
[`heterodyne:0.6.0#core-document-conventions`](heterodyne-core.md#core-document-conventions),
which fixes the family version, registry pin, release status, BCP 14 usage,
and anchor and reference forms. Its conformance expression is **Core + Comms
conformant + Control profile**. Optional Assurance can strengthen succession
and recovery but is not a Control prerequisite.

<!-- fixture:control-profile-metadata -->
```json
{
  "document_id": "control",
  "spec_version": "heterodyne/0.6.0",
  "conformance_expression": "Core + Comms conformant + Control profile",
  "direct_dependencies": [
    "heterodyne:0.6.0#core-conformance",
    "heterodyne:0.6.0#comms-conformance",
    "heterodyne:0.6.0#comms-marmot",
    "heterodyne:0.6.0#comms-agent-authorship"
  ],
  "required_features": [
    "comms.marmot-conversations.v1",
    "comms.oidc-jwt-projection.v1"
  ],
  "transport_owner": "marmot",
  "wire_stamp_owner": null
}
```

<a id="control-scope"></a>
## 1. Scope

Control defines how a full node safely manages remote requests for zero or
more human or organization personas. It composes standard NIP-46 remote
signing, Comms OIDC authorization, Comms automation attribution, Marmot
account and device-leaf state, and optional trusted-seed provisioning. It does
not change Nostr event, NIP-46, OIDC, OAuth, or Marmot wire formats.

Control covers:

- full-node and light-client modes;
- isolated persona vaults and custody choices;
- OIDC activation of standard NIP-46 connections with one-use secrets;
- exact, finite, revocable server-side signer grants;
- fail-closed vault lookup and signer selection;
- automated attribution before signing;
- active-account-bound, device-local Marmot leaves;
- persona-specific trusted-seed provisioning; and
- complete subordinate-authority and Marmot reset after active-key
  compromise.

A full node is an authorization and signing service, not an identity. A bare
active Nostr key is a complete Control persona. Cold roots, KERI state, epoch
keys, succession policy, and Assurance are optional additional protection and
MUST NOT be required for baseline enrollment or signing.

<a id="control-comms-contract"></a>
## 2. Core, Comms, NIP-46, and Marmot contract

Core supplies the active persona key and source-neutral repository semantics.
Comms supplies OIDC authorization, private authorization state, standard
Marmot accounts and leaves, automation attribution, and trusted-seed ACLs.
Control consumes those results and MUST NOT reinterpret a non-current Comms
grant, invalid Marmot account proof, or optional Assurance failure as baseline
authority.

NIP-46 owns connection negotiation and request/response wire syntax. OIDC is
the authorization and activation layer around it. Control adds no custom
NIP-46 method, permission grammar, event signature, bunker URL member, or
relay requirement. Client-requested permissions and NIP-46 metadata are
untrusted hints; the current server-side Control grant is authoritative.

Marmot owns KeyPackages, account proofs, MLS leaf credentials and secrets,
group operations, application encryption, routing, and Nostr transport. The
active persona key is the Marmot account identity. Each device creates and
retains its own leaf secrets. Control MUST NOT alias a successor account or
copy one device's leaf secret to another device.

<a id="control-authority"></a>
## 3. Node modes and authority

<a id="control-light-key"></a>
### 3.1 Light-client mode

A light client MAY hold its persona key locally, use a standard NIP-46 signer,
or use both under explicit user policy. Its NIP-46 client public key identifies
the remote-signing connection; it is not the persona and does not acquire
persona authority merely by connecting. Its Marmot leaf is independent and
device-local.

A light client receives only authorized results. A full node MUST NOT export a
persona, agent, NID, repository, OIDC-issuer, trusted-seed, or Marmot-leaf
private key through Control. If a light client holds a local persona key, that
is the client's own custody choice rather than authority received from a full
node.

<a id="control-discovery"></a>
### 3.2 Full-node discovery

A full node MAY advertise supported Control versions, standard NIP-46
endpoint information, OIDC issuer information, node mode, supported custody
modes and NIP-46 methods, Marmot Control KeyPackage slots, NIP-65/NIP-17 relay
metadata, and optional trusted-seed or compromise-reset features. The closed
capability object conforms to
`docs/spec/schemas/control/control-capability-set-v1.schema.json`.

Advertisements are hints only. They MUST NOT disclose vault membership,
connection secrets, grants, signer keys not already public, pending activation
state, or private seed relationships. An advertisement neither proves
liveness nor authorizes a request.

<a id="control-persona-vaults"></a>
### 3.3 Isolated persona vaults

A full node manages zero or more isolated persona vaults. A vault binds one
exact active persona public key and has its own:

- local or remote persona and agent signers;
- NIP-46 clients and OIDC authorization context;
- repositories, relay configuration, and trusted-seed grants;
- Marmot account proof and device inventory;
- delegates, subordinate nodes, agents, revocations, operations, and audit;
  and
- optional Assurance state.

A node MAY hold persona keys, agent keys, both, or neither. Remote custody may
chain to another standard NIP-46 signer without changing the selected signing
public key. Local and remote custody are operational choices, not distinct
wire identities.

Vault identifiers are local/private selectors. A request MUST resolve exactly
one vault whose active key equals the grant's `persona_active_key`. Missing,
duplicate, ambiguous, or mismatched lookup fails with
`control-vault-isolation-failed`. No lookup, cache, default account, or error
path may consult another persona vault.

<a id="control-invitation-policy"></a>
## 4. Control channel establishment

A full node MAY carry Control application messages in standard two-member
Marmot groups. An unsolicited Control KeyPackage or valid Welcome creates only
an enrollment context; it grants no signer authority. Implementations MUST
enforce finite pending-group counts, a finite lifetime, and rate and burst
limits before durable admission.

Invitation and pending-group evaluation is preparation, not durable admission.
The durable enrollment commit accepts a closed enrollment identifier, group,
client key, and Comms opaque current-authorization-view capability; it accepts
no caller clock, freshness/conflict value, authorization age, checkpoint, or
entitlement state. The consumer snapshots and freezes the closed enrollment
input before it immediately revalidates the capability at the effect boundary.
Only that effect-time result supplies commit time, repository/persona/manifest
binding, issuer, and private-state checkpoint. A failed reload, changed
manifest or checkpoint, conflict, stale transition, or forged capability
commits nothing. An accepted commit still creates only `enrollment-only` state
with no signer authority.

<a id="control-one-time-invites"></a>
Purpose-bound invites use the provider-independent Comms one-time-invite
format. An invite can authenticate rendezvous with a full node but cannot
replace OIDC approval, the exact signer grant, or current revocation state.
Preauthorization MUST bind the expected NIP-46 client public key, persona,
signer audience, selected key and class, methods, kinds, limits, and expiry.

<a id="control-frame"></a>
### 4.1 Marmot Control frame

Registry profile `heterodyne-control-marmot-frame-v1` allocates inner
application `kind:31017`. It is a signed NIP-01 application event inside MLS
and MUST NOT be published as a standalone event. The exact UTF-8 frame bytes
encode only the closed NIP-01 event members; the event ID and BIP-340
signature MUST verify, tags are empty, and `pubkey` MUST equal the Marmot
sender account authenticated for the MLS leaf. Its `content` is JCS-canonical
compact JSON conforming to
`docs/spec/schemas/control/control-frame-v1.schema.json`.

For a request, `payload` is the closed object
`{group_id,request_digest,body}`. `group_id` MUST equal the authenticated
Marmot group and `request_digest` MUST equal the server-derived digest of the
exact bound request. That digest is SHA-256 over
`UTF-8("heterodyne-control-frame-request-v1") || 0x00 ||
UTF-8(JCS({profile,version,group_id,sender,request_id,expires_at,body}))`.
For `human-jsonrpc`, `body` MUST be the exact closed
`control-rpc-request-v1` request and its `id` and `expires_at` MUST equal the
outer frame members. For `agent-mcp`, `body` MUST be a closed request form of
`control-mcp-frame-v1`, with a string `id` equal to the outer `request_id`.

Before dispatch, the receiver captures the exact bytes, duplicate-aware
decodes the outer event once, rejects duplicate or non-closed outer members,
and verifies its identifier, signature, `kind`, empty tags, sender, and
non-future `created_at`. It then parses the JCS-canonical closed Control
content, selects the body schema from the authenticated profile, recomputes
the request digest, and requires the expected profile, version, non-expired
request, authenticated group, and expected digest. A signed frame replayed
into another group, request, profile, version, sender, or time context fails
as `control-frame-invalid`; transport authentication or a caller-supplied
validity summary cannot replace those checks.

The existing closed frame members and JSON-RPC/MCP payload distinction remain
in force. A valid frame proves transport authenticity only. It MUST NOT be
dispatched until the exact current signer grant, request limits, and operation
state have also passed.

<a id="control-enrollment"></a>
## 5. OIDC activation and exact signer grants

<a id="control-device-authorization"></a>
### 5.1 OIDC authorization

The full node uses the applicable Comms OIDC/OAuth flow, including
Authorization Code with PKCE or Device Authorization when appropriate. The
authorization surface MUST display the exact persona active key, NIP-46 client
public key, signer audience, selected signing public key, key class, methods,
event kinds, finite limits, issue time, and exclusive expiry. Persona-key
signing requires an explicit approval; agent-key signing is the preferred
automation default.

Pending state conforms to
`docs/spec/schemas/control/control-device-authorization-state-v1.schema.json`.
It is node-local and contains only hashes of device codes, user codes, and the
NIP-46 connection secret together with their non-secret entropy,
normalization, display-fingerprint, retry, and lifetime controls. Device codes
provide at least 128 bits of entropy; normalized user codes provide at least
34.5 bits, allow at most five failed guesses, and use rate-limited polling.
The record MUST NOT be placed in a public event, URL query, portable backup,
or replicated credential.

The device-authorization authority fixes its authority identifier, trusted
clock, cryptographic entropy source, and all durable-store method identities
when it is constructed. The public authority value is an implementation-local
opaque capability. Transaction creation and polling accept only closed data;
they accept no caller-selected clock, entropy, current-state assertion,
validity boolean, callback, or persistence result. Accessor-backed, proxied,
extended, malformed, or post-capture-mutated inputs grant no authority.

Transaction creation draws at least 128 independent device-code bits and 40
independent user-code bits. It derives the transaction identifier from the
authority and normalized device-code hash, and atomically creates the durable
record with hashes rather than either plaintext code. The record binds the
authority, transaction, client, persona, verification URI, displayed client
fingerprint, issue and exclusive expiry times, initial and current poll
intervals, next permitted poll time, failure budget and count, rate/slow-down
state, and terminal state. A code collision retries with fresh entropy a
bounded number of times; exhaustion or invalid entropy creates no transaction.

A poll derives the durable lookup key from the normalized device code and
loads that record as the only current-state authority. A malformed or unknown
device code is `control-device-code-invalid`. A wrong or malformed user code
increments the durable failure count by compare-and-swap; the fifth failed
guess atomically commits a denied terminal before returning the same reason.
A correct poll before the stored interval atomically increases the interval by
five seconds for that transaction, records its next permitted time, and is
`control-device-code-rate-limited`. A correct code shown with a different
client fingerprint atomically commits denial and is
`control-device-code-display-mismatch`. Reaching the stored expiry atomically
commits an expired terminal and is `control-device-code-invalid`.

Only the locally approved stored state can produce an `approved` result. A
pending or approved result is exposed only after the corresponding atomic
transition is read back with the exact authority, binding, revision, and
output. A terminal transition uses durable acquire and commit; an exact
binding-equal committed retry returns the cached result without repeating the
transition. A conflicting or unknown store result, malformed record, or an
`executing` or `indeterminate` record fails closed with a stable reconciliation
digest and MUST NOT repeat or reopen the transition. These internal failures
do not mint any additional public `control-device-code-*` reason.

Approval binds the pending record's `transaction_id`, `grant_id`,
`oidc_authorization_id`, persona, NIP-46 client, audience, selected signer and
class, exact methods, kinds and limits, secret digest, issue and expiry times,
approval state, and monotonic `revision`. These values are authoritative
stored state, not activation-request parameters.

<a id="control-oidc-activation"></a>
### 5.2 One-use NIP-46 activation

After successful OIDC approval, the signer creates a uniformly random
connection secret and returns or activates it through the standard NIP-46
connection mechanism. The pending record stores only its SHA-256 digest.
Successful comparison produces an exact compare-and-swap transition from the
stored revision's `approved/pending` authorization and secret states to the
next revision's `consumed/consumed` states. The host MUST atomically persist
that transition before activating the connection. The activation request MUST
equal the approved transaction, grant, OIDC authorization, persona, NIP-46
client, audience, selected signer and class, and both the pending record and
the authenticated current grant MUST be live at `now`. A wrong, denied,
expired, altered, or already consumed secret fails
with `control-connection-secret-invalid` or
`control-connection-secret-reused`. Retrying with a consumed secret never
reactivates an earlier or broader grant.

Access tokens, private claims, connection secrets, authorization IDs, and
audit IDs MUST NOT appear in public Nostr events or public bunker URLs.

<a id="control-nip46-signing"></a>
### 5.3 Standard NIP-46 under server-side authority

After activation, standard NIP-46 requests operate only under the exact
current server-side grant. A client-supplied permission string, metadata
document, requested kind set, or cached token can narrow a request but cannot
widen the grant. Any requested method, kind, audience, or limit outside the
grant fails with `control-client-metadata-widening` or
`control-signing-grant-invalid` before signer selection.

<a id="control-entitlement"></a>
<a id="control-signer-grants"></a>
### 5.4 Exact signer grant

The authoritative private record conforms to
`docs/spec/schemas/control/control-client-authorization-v1.schema.json`. It is
closed and binds all of these values:

- `grant_id`, private `vault_id`, and the exact `persona_active_key`;
- exact `nip46_client_pubkey` and `signer_audience`;
- exact `selected_signing_pubkey` and `key_class` `persona|agent`;
- explicit `persona_signing_authorized` state;
- exact allowed NIP-46 methods and Nostr event kinds;
- finite request window, request count, event-byte, and value limits;
- OIDC authorization and one-use connection-secret digests;
- issuance, exclusive expiry, predecessor, and active/revoked state; and
- the active persona authorizer and record signature.

Every authority-bearing member is integrity-bound. A consumer compares the
complete presented projection with the current stored record; changing any
binding rejects with `control-signer-binding-mismatch`. `expires_at` MUST be
strictly after `issued_at`, `now < expires_at`, and active state requires
`revoked_at = null`. Revocation is absorbing. Forked, ambiguous, unavailable,
or stale private state fails closed.

The `signature` is a BIP-340 signature by `authorizing_pubkey` in domain
`heterodyne-control-signer-grant-v1` over
`UTF-8("heterodyne-control-signer-grant-v1") || 0x00 ||
UTF-8(JCS(unsigned-grant))`, where `unsigned-grant` is the complete closed
record with only `signature` removed. A validator MUST verify every candidate
before using it. Candidate records form one linear predecessor chain; the
current grant is its unique authenticated head, including a revoked head.
Missing predecessors, forks, duplicate identifiers, invalid signatures, and a
presented non-head grant fail closed. Every candidate requires
`authorizing_pubkey = persona_active_key`; a predecessor edge remains within
one exact persona and vault, so a self-signed record from another persona
cannot graft itself onto the chain.

When `automation_policy` is present, its workload ID, agent class, explicit
nullable key-or-role association, tier, and OIDC scopes are part of those same
signed bytes. They are the current workload policy; caller fields can only be
equality-checked hints.

The active persona key directly authorizes the baseline grant. Optional
Assurance can constrain or reinforce issuance but MUST NOT be required to
authorize a first-class bare-key persona.

<a id="control-signer-selection"></a>
### 5.5 Fail-closed signer selection

After grant validation, the node selects exactly the named vault, public key,
and key class. Persona class is valid only when the selected key equals the
persona active key and `persona_signing_authorized` is true. Agent class is a
separate Nostr author and MUST NOT silently use the persona key.

If the exact signer is absent, offline, locked, revoked, or of the wrong key
class, the request fails with `control-signer-unavailable`. The implementation
MUST NOT fall through to another persona, another key class, another local
key, a remote signer with a different public key, or a broader grant. A remote
custody failure is not permission to use local custody.

<a id="control-token"></a>
### 5.6 Node-scoped token projection

A node MAY project the exact current grant into a short-lived RFC 9068
`at+jwt` for its own Control resource. Its protected type, signature, issuer,
sender constraint, exact single audience, times, grant ID, persona, client,
selected signer and class, methods, kinds, limits, and current private-state
checkpoint MUST validate on every request. It grants nothing beyond the
stored signer record, is rejected by another node, and has no refresh token.
The default is five minutes. Sixty minutes is an absolute maximum.

Token issuance and token-protected effects consume only Comms' opaque current
authorization view. Control does not accept a caller-provided clock,
freshness/conflict boolean, or checkpoint/view age. Immediately before minting
or authorizing an effect, the node uses the view's captured trusted clock and
current-ledger loader to re-run continuity and freshness and to require the
exact bound manifest and checkpoint. Token `iat` and private-state checkpoint
come from that effect-time result. Passing one of Comms' independent
checkpoint and authorization-view bounds never excuses failing the other.
This baseline composition depends on Core and Comms only; Workspace is not an
authorization prerequisite.

<a id="control-request-processing"></a>
## 6. Request and operation processing

Before a signature or other side effect, the full node validates in order:

1. Marmot sender and group state or the applicable standard NIP-46 transport;
2. the closed request and its exact OIDC/NIP-46 client binding;
3. one unambiguous vault for the active persona key;
4. the complete current signer grant and absorbing revocation state;
5. exact audience, selected key, key class, method, event kind, and limits;
6. client metadata as an equal-or-narrower hint;
7. the exact signer availability with no fallback;
8. Comms automation attribution when the request is automated; and
9. a durable operation reservation before any side effect.

The current-authorization-view reload defined by Comms occurs immediately
before the durable reservation or effect that consumes the decision. A view
prepared earlier is not evidence that the same manifest, checkpoint, conflict
state, or age remains current at effect time.

The operation record conforms to
`docs/spec/schemas/control/control-operation-record-v1.schema.json`. It binds
the collision-resistant digest of the complete signed grant, vault, persona,
NIP-46 client, audience, selected signer and class, the closed standard NIP-46
`{id,method,params}` request, kind, value, canonical request digest, window,
attribution state, signature state, event ID when produced, durable
`reserved|claimed|executing|committed|indeterminate` state, nullable
signer-bound execution token, result or failure digest, commit evidence, and
timestamps. A `produced` signature state is forbidden while attribution
remains `required`; reserved, claimed, and executing operations have no
signature or result. Executing and indeterminate states require attribution
`not-applicable|applied`, never `required`; committed and indeterminate
operations carry their terminal evidence.

A request ID or operation ID reused for different bound bytes fails closed.
A node may replay a previously committed result but MUST NOT repeat an
unproven non-idempotent effect.

The rate boundary consumes an authenticated authoritative per-grant usage
record containing `grant_id`, the digest and full authority tuple of the
complete authenticated grant, window start, consumed count, monotonic
`revision`, and unique request-ID reservations. Every reservation repeats the
closed RPC request, value, window, lifecycle timestamps, internal operation
ID, canonical request digest, and execution token and has
`reserved|claimed|executing|committed|indeterminate` state. The current
window count MUST equal its reservation history; older-window history remains
distinguishable by its stored window timestamp. The caller supplies neither
the window nor the count. A new request produces an exact compare-and-swap
transition from the stored revision to the next revision, increments the
applicable window count, and adds its reservation. Before the signer can be
invoked, compare-and-swap transitions MUST atomically persist `reserved ->
claimed` and then `claimed -> executing`. Only reloaded authoritative
`executing` state permits invocation. The latter transition carries a
collision-resistant execution token derived from the grant digest, full
authority tuple, and request digest. The operation processor MUST NOT accept
or invoke a raw signing callback. Its only signing capability is the signer-side
`executeOnce(execution_token, unsigned_event, request_digest)` boundary. That
boundary first takes a deep serialized snapshot of the authoritative unsigned
event and freezes that snapshot. It atomically and durably acquires a
previously unseen token together with a domain-separated digest of the exact
request digest and immutable snapshot before the underlying key operation.
The acquired record is irreversible and already poisoned against another key
operation. The key adapter receives only an isolated deep copy, never the
snapshot or caller object. The boundary durably stores a deep serialized copy
of the resulting signed event or indeterminate failure before returning
`executed`; every returned terminal is another isolated deep copy. A repeated
exact binding returns the cached terminal result with disposition `cached`
and performs no key operation. The same token with a different event or
request digest fails as `control-operation-conflict` and performs no key
operation.

The execute-once store MUST be durable and shared across every process or node
that can reach that signer. Concurrent callers join or wait for the first
execution and receive its cached terminal result; only the atomic winner may
invoke the key operation. Acquisition has the explicit outcomes `acquired`,
`cached`, `reconciliation`, or `conflict`. If terminal persistence fails after
any possible key effect, the boundary returns `reconciliation`, never
`executed`, and retains the acquired record as non-reacquirable. Every later
exact retry also returns `reconciliation` without another key operation;
different bytes still conflict. After a crash, an incomplete token is
reconciled at that same signer-side boundary and MUST NOT be blindly executed
again. This atomic acquire and terminal protocol is a cross-process storage
contract, not an in-memory mutex or object-identity promise. A
process-local reference store is suitable only for exercising the pure
contract, never for production durability. A compare-and-swap performed by
the operation processor after signing cannot prevent a duplicate signature
and MUST NOT be presented as the execution fence. A valid result produces
`executing -> committed`; a thrown, invalid, timed-out, or otherwise uncertain
signer-side effect produces durable `executing -> indeterminate`
and MUST NOT become reusable `reserved` state. A matching committed
reservation may replay its stored event ID; any other existing nonterminal or
indeterminate reservation MUST NOT repeat the effect. The same request ID
with different bound bytes is a conflict. Exhaustion is computed only from
authoritative state.

Executable conformance evidence for an uncertain signer effect invokes this
same persisted execute-once boundary with an authoritative `executing`
reservation. A reconstructed fence over the same durable store MUST return
the cached terminal without invoking the key operation again. The evidence
adapter descriptor-captures and privately deep-freezes the exact security
input and returned result, and binds their canonical digests, object
identities, signer-capability identity, and real boundary identity to a fresh
opaque terminal. Before any semantic read, it also descriptor-captures the
closed outer evidence fixture exactly once; accessors, proxies, extra or
symbol members, and substituted signer capabilities are rejected without
invocation. Mutation, cloning, or substitution across inputs or boundaries
invalidates that terminal. The registered
`control-signer-effect-indeterminate` result cannot be supplied by a
caller-selected effect-state or validity flag.

The server derives the request digest; a caller never supplies it. The digest
is SHA-256 over `UTF-8("heterodyne-control-nip46-request-v1") || 0x00 ||
UTF-8(JCS({grant_digest,authority,rpc_request,normalized_event,value_msats}))`, where
`grant_digest` is SHA-256 over
`UTF-8("heterodyne-control-signer-grant-state-v1") || 0x00 ||
UTF-8(JCS(complete-signed-grant))` and `authority` is the exact vault, persona,
client, audience, signer, and key-class tuple. The standard wire `id` MUST be a
string of 1–128 printable ASCII characters (`U+0020..U+007E`), including
nostr-tools `<random>-<serial>` IDs; null, boolean, numeric, array, and object
values fail closed without coercion. The server derives a separate hex
operation ID using domain-separated SHA-256
over the grant digest, authority, and exact wire ID. For `sign_event`, `params`
has exactly one JSON string with
only the standard EventTemplate members `kind`, `tags`, `content`, and
`created_at`. `pubkey` is not a wire member and is derived from the selected
signer. Duplicate and extra members are invalid. The digest binds both the
exact original wire request and `normalized_event`, the parsed template plus
the server-selected `pubkey`. OIDC changes no NIP-46 wire member. Method,
kind, and byte limits are derived from those bound bytes, never caller counters.

Reference validators in this specification family are pure boundaries: their
stored grant, revocation head, pending activation, usage, inventory, and
transition-evidence inputs are assertions that the host has authenticated and
loaded the current authoritative records. Returned revisioned transitions are
instructions for an atomic compare-and-swap, not evidence that persistence
already occurred. A host MUST NOT sign, activate, publish, or report reset
completion until the applicable transition has been durably committed.

<a id="control-human-rpc"></a>
### 6.1 Human requests

Human requests use the selected local or NIP-46 custody path. Decryption,
encryption, signing, publishing, configuration, repository, seed, and Marmot
methods each require their exact registered method and object scope. A user
interface choice cannot substitute for the server-side grant. Persona signing
always requires explicit persona authority.

<a id="control-agent-requirements"></a>
### 6.2 Automated publication

An automated request conforms to
`docs/spec/schemas/control/control-agent-publish-v1.schema.json`. It is an
unsigned, closed intent and MUST NOT contain an event ID or signature.
`agent_association` is always present and is either null or one closed key/role
association; `tier` is always present and is `1|2|3`, and `kind` is restricted
to a Comms automation-attribution profile kind. This intent is an
equality-checked construction input, not an alternate wire request or digest
contract. After attribution, the resulting exact unsigned event MUST equal
the canonical `sign_event` parameter. A canonical request copied from a
different intent is a request conflict.

The node validates the closed intent and derived request digest, the authenticated current
grant and signer, and exact equality of every grant, vault, persona, client,
audience, signer, class, kind, value, and signed automation-policy binding.
It derives agent class, association, tier, and scopes only from the signed
grant; caller values never select policy. The node then invokes the Comms automation
attribution transform at
[`heterodyne:0.6.0#comms-agent-authorship`](heterodyne-comms.md#comms-agent-authorship),
then verifies the resulting attribution, and only then passes the unsigned
event to the signer-side execute-once capability; it never receives or invokes
a raw signer. Before that invocation it MUST also reload authoritative
usage state and verify that the exact request ID and canonical digest are
already durably executing after persisted `reserved -> claimed` and `claimed
-> executing` compare-and-swap transitions. The signer receives the persisted
execution token as its idempotency key. The capability returns exact
`executed|cached|reconciliation` disposition. Only a durably stored terminal
returns `executed|cached`; unresolved acquired state returns `reconciliation`
and cannot be invoked again. After the capability returns, the node MUST
recompute the canonical NIP-01 event ID and verify the returned BIP-340 signature and
the exact closed NIP-01 event member set and every unsigned event field against
the immutable pre-adapter snapshot before accepting or committing the result.
A valid result produces a compare-and-swap transition from that exact executing
revision to `committed`, binding the request ID, canonical digest, and verified
event ID. An invalid or uncertain signer effect instead becomes durably
`indeterminate`. The host MUST persist the terminal transition before
publishing or returning success and MUST never retry an indeterminate effect.

Agent-key signing is preferred. Persona-key signing requires the explicit
persona grant and the Comms persona-signing OIDC scope. The caller cannot
remove, replace, reorder into ambiguity, or falsify the mandatory
NIP-32-compatible attribution. Attribution failure returns
`control-attribution-required` and the signer MUST NOT be invoked. Public
events MUST NOT reveal OIDC subjects, client IDs, grant IDs, token IDs,
connection secrets, or private audit identifiers.

<a id="control-marmot-operations"></a>
<a id="control-node-mediated-marmot"></a>
### 6.3 Node-mediated Marmot

The active persona key is the Marmot account. Each client leaf is independently
generated, stored, and rotated on that device and bound with a standard Marmot
account proof. A full node may produce account-level proofs with the exact
active-account signer, but it MUST NOT request, store, export, or substitute a
client's leaf secret.

Node-mediated reads and writes bind one vault, account key, exact group,
method, object, application kind, and operation ID. Group administration also
requires current Marmot administrator authority. There is no cross-vault,
cross-account, or human-account fallback for automated operations.

<a id="control-trusted-seeds"></a>
### 6.4 Trusted-seed provisioning

A vault MAY provision several concurrent trusted seeds using the Comms
private-relay ACL. Each authorization binds one Radicle NID, endpoint, writer
ref, route, roles, and expiry. A seed remains an availability provider. Control
MUST NOT confer persona signing, vault access, repository ownership, group
administration, or MLS plaintext merely because the seed is configured.

Revoking a seed removes its future ACL authority and accepted writer ref from
the vault's current view. Provisioning or revocation in one vault MUST NOT
change any other vault.

<a id="control-failover"></a>
## 7. Failover, retention, and audit

<a id="control-failover-rules"></a>
### 7.1 Sequential node failover

Failover is client-driven and sequential. A second full node independently
loads the exact current grant, resolves the exact persona vault, and selects
the same public signing key and key class. It cannot reuse another node's
token or infer authority from another node's success. If the selected signer
is unavailable, failover fails; it does not select a substitute.

Every mutation has a stable operation ID. Retrying at another node is allowed
only when the method is inherently idempotent under that ID or a committed
result is proven. Otherwise the result is indeterminate and no signature or
side effect is repeated.

<a id="control-retention"></a>
### 7.2 Retention and logout

Raw Control frames, access tokens, connection secrets, device/user codes,
Marmot MLS state, leaf secrets, and replayable transcripts MUST NOT enter a
repository or portable backup. Durable private state contains only grants,
revocations, minimal operation records, and encrypted audit.

Logout consumes or revokes the connection, invalidates node-local tokens, and
terminates the affected Control group without changing another grant. Loss of
a Control group permits a fresh group only after current grant and connection
authorization are revalidated.

<a id="control-audit"></a>
### 7.3 Encrypted audit

Every privileged decision records a closed object conforming to
`docs/spec/schemas/control/control-audit-record-v1.schema.json`. It binds the
grant, vault, persona, NIP-46 client, audience, selected signer and class,
request, method, kind, payload digest, attribution state, result, and time.
It records no access token, connection secret, raw frame, private signing key,
or replayable transcript. Audit persistence precedes a final response.

<a id="control-recovery"></a>
## 8. Active-key compromise reset

Device-local Marmot leaves are bound to the active account. A compromise of
the active Nostr key MUST be treated as possible compromise of every old leaf,
even when some device appears unaffected.

<a id="control-compromise-reset"></a>
### 8.1 Required reset closure

A compromise reset grant conforms to
`docs/spec/schemas/control/control-recovery-grant-v1.schema.json`. It binds the
old and successor active accounts, authorization class, compromise time,
exclusive lifetime, and the identifier, revision, and digest of one
authoritative pre-reset persona-vault inventory. The inventory digest is
SHA-256 over
`UTF-8("heterodyne-control-compromise-reset-inventory-v1") || 0x00 ||
UTF-8(JCS(inventory))`. The signed `required_reset` is exact set equality with
that inventory's:

- NIP-46/OIDC grants to revoke;
- clients, repositories, delegates, nodes, agents, and trusted seeds to invalidate;
- Marmot leaf identifiers to remove, defined exactly as authoritative prior
  leaves whose `account_key` equals the inventory `persona_active_key`;
- reachable groups with their current epochs to advance, and unreachable
  groups to stall; and
- subordinate authorities that require explicit new authorization.

Completion conforms to
`docs/spec/schemas/control/control-recovery-completion-v1.schema.json` and
MUST prove exact set equality with that inventory. The reset-grant signature
is BIP-340 in domain `heterodyne-control-compromise-reset-grant-v1` over
`UTF-8("heterodyne-control-compromise-reset-grant-v1") || 0x00 ||
UTF-8(JCS(unsigned-grant))`. `active-account` requires the exact old active
key and no Assurance head. `assurance-recovery` requires the exact locally
pinned Assurance authority public key and head. The completion signature is
BIP-340 by the successor key in domain
`heterodyne-control-compromise-reset-completion-v1` over
`UTF-8("heterodyne-control-compromise-reset-completion-v1") || 0x00 ||
UTF-8(JCS(unsigned-completion))`. The successor signature never substitutes
for grant authority, and grant authority never substitutes for successor
acceptance.

Before completion the
implementation MUST:

1. revoke every NIP-46 connection and OIDC signer grant;
2. invalidate every listed client, repository, delegate, full/recovery node,
   agent, and trusted seed;
3. remove every old-account Marmot leaf from every reachable group;
4. advance each reachable group to fresh cryptographic state;
5. publish at least one fresh KeyPackage bound to the successor account;
6. mark an unreachable group compromised or stalled rather than claiming it
   advanced; and
7. create a fresh explicit authorization for every continuing subordinate
   authority.

Missing, altered, duplicate, or extra authority does not satisfy the exact
completion. A subordinate may cease to exist; if it continues, its old grant
never carries forward and the completion names the fresh authorization.

The authoritative evidence record MUST equal the signed completion's
inventory binding, next consecutive evidence revision, transition evidence,
fresh KeyPackages, subordinate reauthorizations, and
`evidence_bundle_digest`. That digest is SHA-256 over
`UTF-8("heterodyne-control-compromise-reset-evidence-bundle-v1") || 0x00 ||
UTF-8(JCS(evidence_bundle))`. Evidence observation is not before completion
and not after validation time. A completion signature is not evidence that
any invalidation, MLS transition, or KeyPackage verification occurred.

Each grant, client, repository, delegate, node, agent, trusted-seed, and
stalled-group carrier is a closed state-transition record. It binds a fresh
evidence ID, class, exact subject, authoritative prior-authorization digest,
`revoked|invalidated|stalled` action, its own effective time, recovery ID, and
reset-grant `authorizing_pubkey`; in Assurance recovery the compromised old
key is never an acceptable evidence signer. Its BIP-340 signature in domain
`heterodyne-control-reset-state-evidence-v1` covers
`UTF-8("heterodyne-control-reset-state-evidence-v1") || 0x00 ||
UTF-8(JCS(record-without-signature))`. The validator compares every carrier
with the authoritative pre-reset authorization inventory and rejects opaque
identifiers or caller-invented prior state.

Each reachable-group carrier contains the raw standard MLS Commit bytes,
their SHA-256 digest, exact prior and successor state digests, consecutive
epochs, exact removed and continuing prior leaves, fresh successor leaves,
individual verification time, and the verifier public key pinned in the
authoritative prior group state. The pinned verifier signs JCS proof bytes in
domain `heterodyne-control-mls-commit-evidence-v1`. Before issuing
that carrier, the host MUST use a conforming MLS implementation to parse and
cryptographically verify the Commit against the authoritative prior group,
verify its Remove proposals remove exactly the prior leaves whose
`account_key` equals the compromised inventory persona, preserve every other
prior leaf, and verify the accepted successor tree equals the carrier. Each
per-leaf transition summary uses the exact evidence ID of its containing
group's Commit carrier; it is not independent opaque evidence. The pure reference validator
checks the authenticated parser boundary, raw-byte digest, prior state, exact
leaf sets, successor leaves, and signature; it does not pretend to implement
an MLS database or substitute the carrier signature for MLS verification.

Every fresh successor KeyPackage is a signed canonical NIP-01 kind `30443`
event with the exact singleton tags `d`, `mls_protocol_version=1.0`, and `i`,
plus the exact nonempty duplicate-free id-list tags `mls_ciphersuite`,
`mls_extensions`, `mls_proposals`, and `app_components`. List IDs use `0x`
plus four lowercase hexadecimal digits, `app_components` includes `0x8009`,
and nonstandard tags such as `encoding` are forbidden. The validator
recomputes the event ID, verifies its BIP-340 signature by the successor
account, decodes the base64 MLS KeyPackage bytes, checks their digest and exact
KeyPackageRef/account carrier, and verifies the prior-group MLS verifier's
signature in domain `heterodyne-control-mls-keypackage-evidence-v1`. The host MUST parse
and validate the standard KeyPackage before that verifier signs. The
authoritative inventory derives every prior KeyPackageRef directly from its
authoritative group leaves and separately tracks prior event IDs; fresh
packages and fresh successor leaves MUST reuse neither. Every continuing
subordinate contract binds its exact prior
authority, fresh authorization ID, authority class, successor key, lifetime,
permissions digest, and `contract_digest`; its lifetime MUST include
`completed_at`. `contract_digest` is SHA-256
over `UTF-8("heterodyne-control-subordinate-authorization-v1") || 0x00 ||
UTF-8(JCS(contract-without-contract_digest))`.

All replacement authorization, transition, KeyPackage, and event IDs MUST be
mutually distinct where their namespaces can authorize or evidence the same
reset, MUST differ from their predecessor subject IDs, and MUST not occur in
the authoritative inventory's existing transition or KeyPackage-event IDs.
Successful validation produces a compare-and-swap from the inventory revision
to the consecutive evidence revision and binds a domain-separated completion
state digest. The host MUST atomically persist that reset transition and its
authoritative evidence before reporting completion or allowing successor
authority.

Executable conformance evidence for reset rejection invokes this validator
with the actual signed grant and successor-signed completion plus the complete
authoritative inventory, transition evidence, and optional pinned Assurance
authority. Evidence adapters descriptor-capture and privately deep-freeze
those exact inputs and the validator result, then bind their canonical
digests and object and boundary identities to an opaque terminal. The closed
outer fixture is descriptor-captured exactly once before any semantic read,
so accessors, proxies, extra members, and symbol members reject without
invocation. Post-mint mutation, cloning, or cross-input or cross-boundary
substitution invalidates the terminal; adapters cannot replace signature,
inventory, evidence, or subordinate-reauthorization checks with
caller-supplied booleans.

The baseline authorization class is `active-account`. Optional Assurance may
authorize or reinforce succession and reset, including when the old key is
unavailable, through `assurance-recovery`. Assurance evidence does not alias
the successor npub, rewrite old events, preserve old Marmot membership, or
replace the baseline rule that the active Nostr account is the persona and
Marmot account.

<a id="control-epoch-bootstrap"></a>
<a id="control-radicle-recovery"></a>
<a id="control-sftp-recovery"></a>
### 8.2 Retired recovery prerequisites

Locked epoch inboxes, KERI device enrollment, cold-root bootstrap, mandatory
private-Radicle recovery, and SFTP transfer are not current baseline Control
features. An implementation may use transport or optional Assurance recovery
mechanisms outside this baseline only if it still produces the complete reset
closure above. None can authorize a signer grant or omit an active-account,
Marmot-leaf, grant, seed, or subordinate-authority reset obligation.

<a id="control-security"></a>
## 9. Security invariants and failure behavior

The registry assigns these Control invariants. An invariant with a feature is
owed whenever that feature is claimed:

- **CONTROL-I-AUDIT-AT-REST:** signer and attribution audit is encrypted and
  contains no replayable credential.
- **CONTROL-I-BASELINE-ACTIVE-KEY:** an active Nostr account is sufficient for
  baseline Control.
- **CONTROL-I-CLIENT-KEY-CONFINEMENT:** a light client receives no unrelated
  private key.
- **CONTROL-I-PERSONA-VAULT-ISOLATION:** authority and state never cross vaults.
- **CONTROL-I-EXACT-SIGNER-GRANT:** every signer authority dimension is exact,
  finite, current, and revocable.
- **CONTROL-I-NIP46-OIDC-ACTIVATION:** OIDC activates standard NIP-46 with a
  one-use secret and server-side authority.
- **CONTROL-I-NO-SIGNER-FALLBACK:** an unavailable exact signer fails closed.
- **CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING:** Comms attribution is
  valid before any automated signature.
- **CONTROL-I-MARMOT-GRANT-CONFINEMENT:** node-mediated Marmot remains bound to
  one account, leaf, group, and grant.
- **CONTROL-I-OPERATION-AT-MOST-ONCE:** a durable signer-side execute-once
  token fence, not a post-signing CAS, prevents repeated key effects.
- **CONTROL-I-MARMOT-LEAF-COMPROMISE:** active-key compromise assumes old
  account leaves are compromised.
- **CONTROL-I-COMPROMISE-RESET:** every grant, subordinate authority, seed,
  leaf, reachable group, and fresh KeyPackage obligation closes exactly.

Errors returned to an unauthorized requester MUST NOT reveal whether another
persona, vault, signer, grant, group, or seed exists. The implementation MAY
collapse those conditions to a coarse external denial while preserving the
registered internal reason in encrypted audit.

<a id="control-strict-profile"></a>
### 9.1 Strict profile

<!-- fixture:control-strict-profile -->
```json
{
  "profile_id": "heterodyne-control-strict-v1",
  "conformance_class": "Core+Comms+Control profile",
  "state": "active",
  "requires_profiles": [
    "heterodyne-comms-strict-v1"
  ],
  "adds_invariants": [
    "CONTROL-I-AUDIT-AT-REST",
    "CONTROL-I-CLIENT-KEY-CONFINEMENT",
    "CONTROL-I-OPERATION-AT-MOST-ONCE"
  ]
}
```

<a id="control-conformance"></a>
## 10. Conformance

A Control 0.6.0 implementation may claim conformance only when it is Core and
Comms conformant and passes the applicable executable checks for:

- zero, one, and multiple isolated human or organization persona vaults;
- local custody, standard NIP-46 custody, and nodes holding both or neither
  persona and agent keys;
- OIDC approval and exactly-once connection-secret activation;
- complete signer-grant binding and every single-binding mutation;
- metadata attenuation, revocation, expiry, and finite limits;
- explicit persona-key authority and preferred agent-key automation;
- attribution-before-signing and no signer invocation on attribution failure;
- active-account Marmot proofs and independent device leaves;
- trusted-seed grant isolation and revocation; and
- complete compromise reset with explicit subordinate reauthorization.

Claiming Control does not imply optional Assurance. A conforming bare-key
persona has no lower baseline status.

<!-- fixture:control-conformance-gate -->
```json
{
  "can_claim_control_conformance": true,
  "blockers": [],
  "integrated_normative_subsets": [
    "marmot-control",
    "multi-persona-vaults",
    "oidc-nip46-activation",
    "exact-signer-grants",
    "node-scoped-token",
    "automation-attribution-before-signing",
    "node-mediated-marmot",
    "trusted-seed-provisioning",
    "compromise-reset"
  ],
  "optional_profiles": [
    "assurance-recovery"
  ]
}
```

<a id="control-retired-semantics"></a>
## 11. Retired diagnostic semantics

`agent-attribution-bypass-prohibited`, `agent-human-profile-prohibited`,
`agent-key-access-prohibited`, `agent-method-prohibited`,
`agent-resource-denied`, `control-request-id-conflict`, and
`control-signed-event-invalid` are retained as non-wire history, not current
executable authority. They MUST NOT provide normative executable evidence or
current protocol refusals. Their retirement does not relax attribution before
signing, exact grants, or at-most-once execution: those live invariants remain
covered by the existing publication, grant, and signer-fence boundaries.
