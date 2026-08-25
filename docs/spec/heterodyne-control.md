# Heterodyne Control Profile Specification

Document ID: `control`

Control is a section of the Heterodyne specification and is governed by
[`heterodyne:0.5.0#core-document-conventions`](heterodyne-core.md#core-document-conventions),
which fixes the family version, registry pin, release status, BCP 14 usage,
and anchor and reference forms. Its conformance expression is **Core + Comms
conformant + Control profile**. Optional Assurance can strengthen succession
and recovery but is not a Control prerequisite.

<!-- fixture:control-profile-metadata -->
```json
{
  "document_id": "control",
  "spec_version": "heterodyne/0.5.0",
  "conformance_expression": "Core + Comms conformant + Control profile",
  "direct_dependencies": [
    "heterodyne:0.5.0#core-conformance",
    "heterodyne:0.5.0#comms-conformance",
    "heterodyne:0.5.0#comms-marmot",
    "heterodyne:0.5.0#comms-agent-authorship"
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

<a id="control-one-time-invites"></a>
Purpose-bound invites use the provider-independent Comms one-time-invite
format. An invite can authenticate rendezvous with a full node but cannot
replace OIDC approval, the exact signer grant, or current revocation state.
Preauthorization MUST bind the expected NIP-46 client public key, persona,
signer audience, selected key and class, methods, kinds, limits, and expiry.

<a id="control-frame"></a>
### 4.1 Marmot Control frame

Registry profile `heterodyne-control-marmot-frame-v1` allocates inner
application `kind:31017`. It remains an unsigned Nostr-shaped application
event inside MLS and MUST NOT be published as a standalone Nostr event. Its
content is JCS-canonical compact JSON conforming to
`docs/spec/schemas/control/control-frame-v1.schema.json`; tags are empty and
the inner `pubkey` equals the Marmot sender account authenticated for the MLS
leaf.

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

<a id="control-oidc-activation"></a>
### 5.2 One-use NIP-46 activation

After successful OIDC approval, the signer creates a uniformly random
connection secret and returns or activates it through the standard NIP-46
connection mechanism. The pending record stores only its SHA-256 digest.
Successful comparison atomically marks the secret consumed before activating
the connection. A wrong, denied, expired, or already consumed secret fails
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

The operation record conforms to
`docs/spec/schemas/control/control-operation-record-v1.schema.json`. It binds
the grant, vault, persona, NIP-46 client, audience, selected signer and class,
method, kind, canonical request digest, attribution state, signature state,
event ID when produced, durable `reserved|committed|indeterminate` state,
result and commit evidence, and timestamps. A `produced` signature state is
forbidden while attribution remains `required`; a reservation has no result
or commit evidence, while a committed operation has both.

A request ID or operation ID reused for different bound bytes fails closed.
A node may replay a previously committed result but MUST NOT repeat an
unproven non-idempotent effect.

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
unsigned intent and MUST NOT contain an event ID or signature. The node first
validates the exact grant and signer, then invokes the Comms automation
attribution transform at
[`heterodyne:0.5.0#comms-agent-authorship`](heterodyne-comms.md#comms-agent-authorship),
then verifies the resulting attribution, and only then exposes the unsigned
event to the signer.

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
exclusive lifetime, and exact inventories of:

- NIP-46/OIDC grants to revoke;
- clients, delegates, nodes, agents, and trusted seeds to invalidate;
- old Marmot leaf identifiers to remove;
- reachable groups to advance; and
- subordinate authorities that require explicit new authorization.

Completion conforms to
`docs/spec/schemas/control/control-recovery-completion-v1.schema.json` and
MUST prove exact set equality with that inventory. Before completion the
implementation MUST:

1. revoke every NIP-46 connection and OIDC signer grant;
2. invalidate every listed client, delegate, full/recovery node, agent, and
   trusted seed;
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
- **CONTROL-I-OPERATION-AT-MOST-ONCE:** reservation precedes a side effect.
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

A Control 0.5.0 implementation may claim conformance only when it is Core and
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
