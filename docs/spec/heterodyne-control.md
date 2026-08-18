# Heterodyne Control Profile Specification

Document ID: `control`

Control is a section of the Heterodyne specification and is governed by
[`heterodyne:0.5.0#core-document-conventions`](heterodyne-core.md#core-document-conventions), which fixes the family version,
the registry pin, release status, BCP 14 usage, and the anchor and reference
forms. Its conformance expression is **Core + Comms conformant + Control
profile**. Recovery capabilities are separately advertised optional profiles
and are not prerequisites for baseline Control conformance.

<!-- fixture:control-profile-metadata -->
```json
{
  "document_id": "control",
  "spec_version": "heterodyne/0.5.0",
  "conformance_expression": "Core + Comms conformant + Control profile",
  "direct_dependencies": [
    "heterodyne:0.5.0#core-conformance",
    "heterodyne:0.5.0#comms-conformance",
    "heterodyne:0.5.0#comms-marmot"
  ],
  "required_features": ["comms.marmot-conversations.v1"],
  "transport_owner": "marmot",
  "wire_stamp_owner": null
}
```

<a id="control-scope"></a>
## 1. Scope

Control lets a light client or automated principal ask a persona's full node
to perform narrowly authorized work without receiving a persona publishing,
device, epoch, NID, repository, MLS-leaf, or agent-role private key. Routine
Control uses standard two-member Marmot groups. Heterodyne defines only the
application payload, authorization, execution, audit, and failover rules.

Control covers:

- full-node discovery and Control invitation policy;
- Marmot group initialization and enrollment-only admission;
- OAuth Device Authorization projected over Marmot;
- persona-wide private client entitlements and absorbing revocation;
- node-scoped, short-lived, Marmot-bound JWT access tokens;
- human JSON-RPC and the pinned MCP data layer for automated principals;
- exact method, object, rate, size, media, and role authorization;
- restart-safe operation reservation and conservative cross-node failover;
- node-mediated Marmot conversation operations and agent publication; and
- encrypted audit, bounded relay retention, logout, and state loss.

Portable recovery, recovery-node activation, private-Radicle recovery, and
SFTP overflow are specified in §10 as optional capabilities. They are not
required for baseline Control.

<a id="control-comms-contract"></a>
## 2. Exact Core, Comms, and Marmot contract

Control requires the standard Marmot group and transport rules at
[`heterodyne:0.5.0#comms-marmot`](heterodyne-comms.md#comms-marmot), the Core full-node metadata at
[`heterodyne:0.5.0#core-full-node-control`](heterodyne-core.md#core-full-node-control), and Comms authorization and
freshness rules at [`heterodyne:0.5.0#comms-control-registry`](heterodyne-comms.md#comms-control-registry) and
[`heterodyne:0.5.0#comms-authorization-freshness`](heterodyne-comms.md#comms-authorization-freshness).
The standards-facing OAuth enrollment feature additionally composes the
third-party OIDC/JWT projection at
[`heterodyne:0.5.0#comms-oidc-endpoints`](heterodyne-comms.md#comms-oidc-endpoints).

Marmot owns KeyPackages, Welcome processing, MLS membership and epochs,
sender authentication, application encryption, `kind:445` transport,
duplicate transport delivery, routing, relay fanout, and NIP-40 expiration.
Control MUST NOT add an outer envelope, relay-only signature, response URL,
or Heterodyne transport acknowledgement. A Control implementation MUST reject
an application frame unless the Marmot event, group state, and sender account
are valid under the pinned Marmot profile.

Registry profile `heterodyne-control-marmot-frame-v1` allocates inner
application `kind:31017`. It is an unsigned Nostr-shaped application event
inside MLS and MUST NOT be published or interpreted as a standalone Nostr
event. Its content is the [`heterodyne:0.5.0#core-canonical-json`](heterodyne-core.md#core-canonical-json) object
defined in §5.

<a id="control-authority"></a>
## 3. Authority and discovery

<a id="control-light-key"></a>
### 3.1 Light-client Control key

An authenticated light client generates and retains one Nostr-compatible
secp256k1 keypair. Its public key identifies the client's Marmot account,
proves possession during enrollment, and confirms node-issued tokens. It is
not a public KERI device delegation and has no authority to publish for the
persona. Events signed directly by it MUST be treated as ordinary
non-delegated Nostr events, never persona-authored events.

The key and its authorization state appear only in the encrypted private
Control registry. The light client never receives a persona epoch key, NID
key, full-node device key, human publishing key, agent-role key, repository
decryption key, or another member's MLS leaf private key.

<a id="control-discovery"></a>
### 3.2 Full-node discovery

Every Core/KERI-authorized device record states whether the device is a full
node and may advertise:

- exact supported Control versions;
- supported Control invitation modes, without disclosing temporary activation
  state or claiming current liveness;
- Marmot Control KeyPackage slots and their expiry;
- standard NIP-65 and NIP-17 relay metadata required by Marmot;
- outbound-Tor, onion-only, and reduced-assurance clearnet reachability;
- optional `control.recovery.radicle.v1`,
  `control.recovery.epoch-inbox.v1`, and `control.recovery.sftp.v1`; and
- an epoch-inbox relay set only for recovery bootstrap under §10.1.

A full node reuses its authorized device Nostr account as its Marmot Control
account. Every pairwise Control group has an independent MLS leaf. Account
private keys, leaf private keys, issuer keys, and issued tokens MUST NOT be
shared between full nodes.

Advertisements are hints, not liveness or authorization evidence. A client
tries nodes sequentially and records its most recently responsive node as the
next default. An ordinary light-client key does not appear in the public
device list.

<a id="control-invitation-policy"></a>
## 4. Invitation policy and group establishment

Each full node has exactly one local unsolicited invitation mode: `off`, the
default; `temporary`, with an authenticated expiry after which it becomes
`off`; or `permanent`, until explicitly changed. An open mode may accept an
unsolicited two-member group created from an advertised, unexpired Control
KeyPackage. Acceptance creates an untrusted enrollment-only context; it grants
no Control authority. Changing mode never terminates an existing authorized
group.

Open modes MAY advertise Marmot's standard `last_resort_key_package` for the
public Control slot. A last-resort KeyPackage may be reused according to
Marmot until replacement or expiry; it does not remove the following
application-state bounds. Before durable Welcome acceptance or KeyPackage
state mutation, the node MUST enforce all of these limits during Marmot's
tentative Welcome validation:

- at most one pending enrollment-only group per authenticated account;
- a finite configured global pending-enrollment cap;
- a hard 30-minute lifetime for every enrollment-only group;
- finite Welcome-processing and KeyPackage-replenishment rate and burst
  limits;
- no public-pool replenishment while the global pending cap is full; and
- at least one separately classified invitation slot reserved for an active
  entitled client or explicitly approved enrollment.

Malformed, unsupported, expired, disabled, duplicate, over-quota, or
rate-limited attempts fail before durable group creation or KeyPackage
consumption. Expired enrollment-only groups are removed. The exact local
policy object conforms to
`docs/spec/schemas/control/control-invitation-policy-v1.schema.json`.

Before entitlement activation, the node permits only:

- `control.initialize` and capability discovery;
- `control.enrollment.start` and `control.enrollment.status`;
- `control.token.status` when required to finish the pending device grant; and
- `control.close` or cancellation.

Every other method MUST fail with `control-enrollment-required` before
application dispatch. A valid Welcome, group membership, application event,
or transport delivery MUST NOT be treated as authorization.

In `off` mode the node rejects or ignores new unsolicited Control groups and
stops advertising fresh public invitation-ready KeyPackages. A valid
purpose-bound invite or explicit approval may still use its separately
classified slot. Stale public advertisements are not a promise of acceptance.

To establish a group, the client resolves current full-node metadata, selects
a compatible node, fetches and validates a Control KeyPackage, creates an
ordinary two-member Marmot group, completes the standard Add/Commit and
Welcome obligations, and sends `control.initialize`. No epoch-key interaction
or direct node address is required.

<a id="control-one-time-invites"></a>
### 4.1 Purpose-bound Control and device invites

Control consumes the provider-independent format at
[`heterodyne:0.5.0#comms-one-time-invites`](heterodyne-comms.md#comms-one-time-invites). A
`control-enrollment` redemption creates a standard pairwise Control group and
bypasses only unsolicited-invitation admission by default. Explicit approval
and a durable private entitlement remain required.

A node MAY be explicitly configured to issue a `preauthorized` invite for a
private `human-light` or `automated` principal. The signed descriptor MUST
bind its exact client class, methods, objects, finite limits, agent role,
token-lifetime ceiling, and optional expected client public key. Automated
enrollment is expected-key bound by default. An unbound bearer template is
valid only when separately enabled by node policy and MUST be reported as
higher risk. Redemption can activate only that exact entitlement and still
uses the full-node-held signing and mandatory automation-attribution path.

Prompt-free preauthorization is forbidden for every KERI-authorized persona
device. A `device-enrollment` invite may request any Core device class, but
the joining device generates and retains its own keys and redemption provides
only an authenticated rendezvous. Explicit approval, epoch authorization,
KERI delegation, repository verification, and the applicable full/recovery
completion ceremony remain mandatory. Control and device-enrollment invites
default to ten minutes and have an absolute one-hour maximum.

<a id="control-frame"></a>
## 5. Control application frame

The `kind:31017` application event has the ordinary Marmot unsigned-event
shape. Its `content` MUST validate byte-for-byte as the JCS-canonical compact
JSON representation of
`docs/spec/schemas/control/control-frame-v1.schema.json`. Its `tags` MUST be
empty. The inner `pubkey` MUST equal the Marmot sender account authenticated
for the MLS leaf; `created_at` is the sender time and is not an authorization
clock.

The closed frame members are:

```text
version, profile, frame_type, request_id, operation_id,
expires_at, access_token, payload
```

`version` is exactly `heterodyne/0.5.0`. `profile` is exactly `human-jsonrpc` or
`agent-mcp`. `frame_type` is one of `initialize`, `request`, `response`,
`notification`, or `close`. A request has a non-empty `request_id` and an
application expiry. A mutation also has a stable non-empty `operation_id`.
Responses repeat the request identity; notifications and initialization omit
an operation identity unless their own method requires it. Privileged
requests carry one access token. Unknown members, a standalone event, a
nonempty tag set, noncanonical content, or a profile/frame mismatch fails with
`control-frame-invalid`.

The first successful exchange is `control.initialize`. It selects exactly one
Control version and profile. Human payloads use JSON-RPC 2.0. Agent payloads
use the MCP 2025-11-25 data layer inside the same frame; MCP HTTP, SSE, and
stdio transports are out of scope. A node may advertise compatibility before
group creation but MUST NOT dispatch a privileged method before initialization
finishes in both directions.

Responses use the current Marmot routing state of the same group. They are
not bound to the relay that delivered the request.

<a id="control-enrollment"></a>
## 6. Enrollment and durable entitlement

<a id="control-device-authorization"></a>
### 6.1 OAuth Device Authorization projection

Ordinary enrollment uses the contacted full node's built-in OAuth/OIDC issuer
and RFC 8628 state machine. Marmot methods initiate and poll the transaction
so an onion-only node remains usable through public Nostr relays. These
messages are an application projection of issuer behavior and MUST NOT be
advertised as an HTTP-conformant token endpoint. A node MAY additionally
expose the standards-defined HTTP endpoints.

The client proves possession through its authenticated Marmot account-to-leaf
binding and an enrollment challenge. The user-facing approval surface MUST
show the client fingerprint, client class, requested methods and objects,
finite limits, inbound-execution request, and requested token-duration
capability. Approval occurs locally on a full node or through an already
authorized device whose active entitlement permits `control.approve`.

The `device_code` contains at least 128 bits of uniformly random entropy. The
human `user_code` contains at least 34.5 bits of entropy. Its declared
normalization is applied before a constant-time comparison, and no active code
permits more than five failed guesses. Guessing is subject to both per-code
and node-wide rate limits. The initiating and approving displays MUST show the
identical normalized code and client fingerprint.

Polling obeys the RFC 8628 interval and `slow_down` behavior. Success, denial,
expiry, or attempt exhaustion atomically invalidates both codes. Pending code
state conforms to
`docs/spec/schemas/control/control-device-authorization-state-v1.schema.json`,
is node-local, one-use, and short-lived, and MUST NOT be replicated as a
credential or included in a backup.

<a id="control-entitlement"></a>
### 6.2 Private client authorization

Approval commits a record conforming to
`docs/spec/schemas/control/control-client-authorization-v1.schema.json` in the
persona's encrypted private Radicle Control registry. The signed record binds:

- persona and client Control public key;
- client class `human-light` or `automated`;
- approving full-node device and active approving authority;
- exact methods, object classes and IDs, agent role where applicable;
- rate, burst, object, content, aggregate-media, and other finite limits;
- default and maximum token lifetimes;
- inbound-execution consent, defaulting to disabled;
- predecessor/lineage, creation, optional expiry, and active/revoked state;
- signing algorithm, signer, signature, and record digest.

Entitlement records replicate as evidence under
[`heterodyne:0.5.0#comms-control-registry`](heterodyne-comms.md#comms-control-registry).

Records are append-only. A valid grant reduction takes effect immediately at
an observing node. A valid revocation is absorbing and wins over every active
ancestor or concurrent expansion. Unresolved forks, an unauthorized writer,
or conflicting expansion fail with `control-entitlement-conflict`. Grant
expansion requires a new explicit consent ceremony. Self-revocation by the
exact authenticated client key is always allowed because it only reduces
authority. No public KERI device event is emitted for an ordinary light
client.

<a id="control-token"></a>
## 7. Node-scoped Marmot-bound access tokens

This section is `control.node-scoped-token.v1` and is the sole definition of
the node-local Control `at+jwt` contract. It requires no HTTPS discovery,
published JWKS, continuity manifest, or distributed status list when the
issuing node is the only resource that consumes the token.

Each full node is an independent RFC 9068 issuer with its own node-local
issuer signing key and exact Control resource audience. Issuer keys and tokens
MUST NOT be copied to another node. Authenticated public issuer state in the
private Control registry binds the issuer URL, current JWKs, node device key,
exact resource audience, validity interval, and predecessor.

After validating the current entitlement and group, the node issues an RFC
9068 JWT access token whose protected `typ` is exactly `at+jwt` and whose
signature and required `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`,
and `scope` claims validate. It additionally binds:

- an audience naming only the issuing node's Control resource;
- `cnf.jkt`, the RFC 7638 thumbprint of the client's full secp256k1 JWK;
- the exact Marmot Control group identifier;
- the exact client identifier, entitlement/authorization-record identifier,
  and client class;
- exact methods, objects, finite limits, and an optional agent role; and
- the current private-registry generation or checkpoint.

The Nostr x-only public key maps to the unique even-Y secp256k1 point defined
by BIP-340. Its uncompressed `x` and `y` form the RFC 8812 JWK used for the
thumbprint.

Marmot Control does not synthesize DPoP HTTP values. For every privileged
frame the receiver verifies that the application event and sender leaf are
valid, the authenticated sender account's JWK thumbprint equals `cnf.jkt`,
the frame arrived in the token-bound group, and the token type, signature,
issuer, exact node audience, times, token ID, client, scope, entitlement, and
limits remain valid. Another full node MUST reject the token and issue its own
only after independently validating the same persona-wide entitlement. A
separately exposed HTTPS API MAY use ordinary RFC 9449 DPoP with
registered `ES256K`; that API is not baseline Control.

The effective token lifetime is:

```text
min(requested lifetime, entitlement maximum, node-policy maximum, 60 minutes)
```

The default is five minutes. A lifetime above five minutes requires the
separately consented `control.token.extended` capability. Sixty minutes is an
absolute maximum. The issuer MUST NOT issue a refresh token. An entitled
client obtains a new node-local token over its established group, including
after failover. A token is checked when a request is accepted; expiry does not
interrupt an already accepted side effect, but every later request or MCP tool
call requires a current token.

Nodes revalidate the current entitlement on every request rather than
requiring a distributed Token Status List. A projected token never replaces
private-registry authority. Minting and every privileged request are bound by
[`heterodyne:0.5.0#comms-authorization-freshness`](heterodyne-comms.md#comms-authorization-freshness). Once a node observes
revocation, it rejects all associated tokens regardless of remaining `exp` and
terminates the affected group locally.

<a id="control-request-processing"></a>
## 8. Request processing and execution

Before dispatch, the full node validates in order:

1. Marmot event, group state, sender identity, and initialized profile;
2. closed Control frame and human/MCP payload schema;
3. request expiry and request/operation identifiers;
4. node-scoped token and sender/group binding;
5. current private entitlement and exact method/object grant;
6. finite size, rate, burst, media, and other method limits;
7. an existing operation reservation or committed result; and
8. method-specific confirmation and local policy.

The node then durably reserves the logical operation before any side effect,
executes or reconciles it, persists the result and encrypted audit evidence,
and only then emits the final response. A request ID reused with different
canonical bytes fails with `control-request-id-conflict`. An operation ID
reused for a different method, object, or canonical payload fails with
`control-operation-conflict`. Expired frames fail with
`control-request-expired`.

The operation record MUST validate against
`docs/spec/schemas/control/control-operation-record-v1.schema.json`. It binds
the persona, client, node, group, request and operation IDs, profile, method,
object, canonical request digest, reservation/result state, commit evidence,
and timestamps. It contains no access token or raw Control frame.

<a id="control-human-rpc"></a>
### 8.1 Human JSON-RPC

Human payloads are closed JSON-RPC 2.0 request, response, or notification
objects. The entitlement is an intersection, not a hint. `ping` and public
metadata reads may use object class `none`; signing, publishing, DMs,
encryption, configuration, repositories, media, device administration, and
Marmot operations require their exact registered object class and ID.

Security policy, private entitlements, issuer keys, epoch/NID keys,
repository-decryption keys, and MLS secrets are never generic configuration.
`config.put` MUST reject a path reaching them regardless of grant tier.
Destructive, exfiltrating, full-device activation, key-operation, and grant
expansion methods require their specified fresh local confirmation.

<a id="control-agent-requirements"></a>
### 8.2 Automated principals and MCP

An AI or programmatic principal uses profile `agent-mcp` and the MCP
2025-11-25 data layer. It uses the node-scoped Control access token defined in
§7. If its identity originated in the optional third-party OIDC workload
projection, the node maps the current issuer, subject, client, and role tuple
to the entitlement during enrollment; that projected token neither authorizes
Control frames nor replaces the §7 token. The entitlement and Control token
identify the automated client class, exact `agent:<role-id>`, tools, methods,
kinds, objects, media, rate, size, burst, and expiry.

MCP `initialize`, `notifications/initialized`, `tools/list`, `tools/call`,
`notifications/cancelled`, result, and error objects MUST validate against
`docs/spec/schemas/control/control-mcp-frame-v1.schema.json`. Heterodyne
capabilities remain under
`capabilities.experimental["network.heterodyne.control"]`. No tool runs before
mutual initialization; unknown tools and invalid arguments fail closed.
Cancellation never reverses a committed side effect. Inbound execution is
disabled unless both the entitlement and current light-client capability set
opt in, and it remains sandboxed, allowlisted, visible, and without ambient
filesystem, network, or secret access.

An automated principal MUST NOT request, receive, use, or simulate direct
access to a persona, epoch, NID, human-device, or agent-role private key. It
MUST NOT invoke raw signing, select a human publishing profile, remove
automation attribution, or fall back after denial. The full node validates
the current token and entitlement, constructs the authorized output, injects
the canonical Comms automation attribution, and signs with the full-node-held
role key. Failure is closed and never produces an unlabeled or human-key event.

<a id="control-marmot-operations"></a>
### 8.3 Node-mediated Marmot operations

An entitlement MAY authorize a `node-mediated` conversation view without
granting an MLS leaf. Closed method families include group list/read/subscribe,
message send/reply/react/edit, media put/get, and separately authorized member,
routing, host, and NID administration.

Every request binds the exact group, application kind, object/message target,
media type and size where applicable, and operation ID. The node constructs
the Marmot application event; a caller MUST NOT provide a signed outer event,
account key, leaf key, or MLS secret. Administration additionally requires the
current Core-bound group-admin role, current Marmot administrator status, and
the exact object grant. NID admission remains distinct from MLS membership.

Automated Marmot operations additionally bind the inner event account,
authenticated MLS sender account, current KERI agent role, token role/scope,
and protected automation attribution. There is no human-account fallback.

<a id="control-failover"></a>
## 9. Failover, retention, revocation, and audit

<a id="control-failover-rules"></a>
### 9.1 Sequential node failover

Failover is client-driven and sequential. The client uses its most recently
responsive node first and, if unavailable, creates or resumes a pairwise
group with another known full node. The second node validates the same
persona-wide entitlement and issues its own node-audience token. Consent is
repeated only for broader authority.

Reads, status, token issuance, and subscriptions may be retried automatically.
Every mutation has a stable operation ID and may be retried at another node
only when the method is inherently idempotent under that ID or the second node
can prove and return the first node's committed result. If the first node may
have committed and no result is provable, the result is `indeterminate`; the
client MUST reconcile or obtain explicit user direction and MUST NOT repeat
the effect blindly. Public output carries the logical operation ID in its
canonical Heterodyne attribution where that output profile permits it.

The private Radicle operation journal improves duplicate detection and
recovery but is not a distributed lock, leader election, or consensus system.

<a id="control-retention"></a>
### 9.2 Retention and state loss

Control application messages use Marmot retention with NIP-40 expiration.
The default delivery window is one hour. A high-latency local policy may
increase it to at most twenty-four hours. A request's earlier application
expiry always wins.

The following MUST NOT be committed to Radicle or portable backups:

- raw Control frames;
- access tokens, device codes, or enrollment codes;
- Control-group MLS state or epoch secrets; and
- replayable request/response transcripts.

The private registry retains only durable authorization records, minimal
operation reservations/results, and encrypted audit evidence. Audit records
contain no raw access token. Loss of a Control group is not a recovery event:
the client creates a new group with the same entitled account and obtains a
new token.

Revocation terminates affected local groups and blocks re-enrollment of the
same key unless a future version defines an explicit recovery ceremony.
Offline nodes cannot provide instantaneous revocation; freshness policy and
short token expiry bound that limitation.

<a id="control-audit"></a>
### 9.3 Encrypted audit

Every privileged decision records the Control version/profile, client class,
node and group, request/operation IDs, canonical payload digest, entitlement
record/checkpoint, token `jti` but not token bytes, method/object authorization,
finite-limit result, commit evidence, result, and applicable agent role and
attribution. A refusal additionally records the exact internal condition behind
the coarse reason code returned to the requester; that record is the only place
the distinction exists. Audit persistence precedes final response publication.
Audit material is encrypted at rest and cannot itself replay an operation.

<a id="control-recovery"></a>
## 10. Optional recovery profiles

Baseline Control does not require an epoch key or recovery service. A node
advertises each optional recovery profile separately and MUST NOT imply that
one profile supplies another.

<a id="control-epoch-bootstrap"></a>
### 10.1 Locked-epoch full-node bootstrap

The epoch network path is reserved for adding a new full/recovery node when no
existing authorized device Control channel can conduct the ceremony. A
prospective node sends a NIP-59 gift wrap to the epoch public key at a
configured inbox relay. The encrypted registration rumor MUST validate against
`docs/spec/schemas/control/control-epoch-registration-v1.schema.json` and bind
the prospective device account, Radicle NID, Control KeyPackage reference,
recovery-wrapping key, SSH authentication key, Tor client-authorization key,
requested capabilities, nonce, expiration, and proof of possession for every
private key.

A recovery-capable node keeps the epoch key encrypted and absent from memory.
Only an explicit local user ceremony unlocks it and scans the inbox. During
that short window the node validates one candidate and prepares signed public
device artifacts, private recovery/repository authorization, a finite transfer
grant, and an epoch activation envelope encrypted to the prospective recovery
key. The prepared record MUST validate against
`docs/spec/schemas/control/control-prepared-activation-v1.schema.json`.

The node erases epoch plaintext and relocks before repository sync, onion
service startup, SFTP, or other bulk network activity. It then creates a
normal pairwise Marmot Control group with the prospective device. Failure,
denial, or expiry destroys pending activation material and releases no persona
authority.

After recovery, the prospective node reports exact repository heads,
portable-manifest identity, and required object digests using
`docs/spec/schemas/control/control-recovery-completion-v1.schema.json`. Only an
exact verified match permits publication of the prepared full-node metadata,
commitment of the recovery role and permanent repository membership, and
release of the already wrapped epoch envelope. The epoch scalar is never sent
in plaintext. Offline restore from a portable encrypted backup uses the same
integrity and activation checks; possession of bytes alone grants no public
device authority.

<a id="control-radicle-recovery"></a>
### 10.2 Private-Radicle recovery

Network recovery uses native private-Radicle synchronization for repositories
and eligible objects. A temporary authorization conforming to
`docs/spec/schemas/control/control-recovery-grant-v1.schema.json` binds the
prospective NID, exact repositories and heads, direction, byte ceiling,
expiry, activation ID, and completion condition. Temporary access does not
make the NID a delegate or writer unless final activation separately grants
that role.

Heterodyne application encryption remains the at-rest boundary. Radicle
selective replication and encrypted peer links do not replace it. Small
protected records, wrapped keys, progress, and completion receipts use the
pairwise Control group.

<a id="control-sftp-recovery"></a>
### 10.3 SFTP overflow

SFTP is optional overflow for immutable archives, media, logs, observability
bundles, or other objects unsuitable for Radicle. Every grant uses a separate
onion service and separate operating-system process, with a fresh
onion-service identity and process boundary distinct from the full node's
Radicle onion. The grant MUST validate against
`docs/spec/schemas/control/control-sftp-grant-v1.schema.json` and bind the
onion address, SSH host key, Tor v3 client-authorization key, SSH client key,
exact resources, direction, byte ceiling, issue time, and expiry.

Tor client authorization gates access before SSH. SFTP independently requires
the bound client key and pinned host key. The service exposes a rooted view of
only the immutable authorized resources, supports offset resumption and exact
reads, and permits bounded writes only when the grant explicitly names an
existing authorized recovery peer and write resources. It MUST prohibit
interactive shell, arbitrary commands, traversal outside the root, PTY,
TCP/Unix/X11/agent forwarding, unlisted resources, and bytes beyond the grant.

Artifact manifests and digests provide end-to-end integrity. Completion and
activation receipts use Control, not a custom SSH subprotocol. A grant lasts
at most eight hours and shuts down on completion, revocation, or expiry.
Renewal creates a new grant and onion identity. The prior endpoint may remain
read-only for at most five minutes for already-open transfers. The virtual SSH
port may remain stable and is not a security boundary.

<a id="control-security"></a>
## 11. Security invariants and failure behavior

The registry assigns these Control invariants. An entry the registry binds to a feature is owed only by an implementation
claiming that feature, under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).
The list below is descriptive:

- **CONTROL-I-AUDIT-AT-REST:** authorization and side-effect audit is encrypted and contains no replayable token or transcript.
- **CONTROL-I-CLIENT-KEY-CONFINEMENT:** a light client receives no persona, device, epoch, NID, repository, MLS-leaf, or agent-role private key.
- **CONTROL-I-MARMOT-SENDER-BINDING:** every privileged token is bound to the authenticated Marmot account and exact group.
- **CONTROL-I-ENTITLEMENT-FRESHNESS:** every privileged request uses current, non-conflicted private entitlement state and absorbing revocation.
- **CONTROL-I-NODE-AUDIENCE:** a node-issued Control token is accepted only when its protected typ is exactly at+jwt, signature and issuer validate, time bounds hold, and audience is the exact issuing-node resource.
- **CONTROL-I-OPERATION-AT-MOST-ONCE:** mutation reservation precedes effects and cross-node retry is limited to provably safe cases.
- **CONTROL-I-AGENT-NO-KEY-RELEASE:** an automated principal never receives or directly exercises a persona, epoch, NID, human-device, or agent-role private key.
- **CONTROL-I-AGENT-INTENT-ONLY:** an automated principal publishes only through the intent-level agent method, and raw signing, human-profile fallback, and attribution bypass fail closed.
- **CONTROL-I-MARMOT-GRANT-CONFINEMENT:** node-mediated Marmot operations expose only grant-filtered content and actions.
- **CONTROL-I-EPOCH-LOCKED-DURING-TRANSFER:** epoch plaintext is erased and relocked before network or bulk-transfer activity.
- **CONTROL-I-RECOVERY-GRANT-CONFINEMENT:** recovery access is finite and bound to exact identities, resources, direction, bytes, time, and completion.
- **CONTROL-I-SFTP-PROCESS-SEPARATION:** overflow SFTP uses a per-grant onion and isolated rooted process with Tor and SSH authentication.

Implementations fail closed for invitation disabled, unsupported KeyPackage,
pre-enrollment method, invalid frame, invalid/mismatched/expired token, stale or
conflicted entitlement, scope or limit mismatch, request/operation conflict,
indeterminate mutation, locked epoch inbox, registration or activation
mismatch, unauthorized repository access, SFTP identity/resource/time
mismatch, and incomplete recovery proof. Errors MUST NOT reveal whether an
unauthorized private object, entitlement, or recovery resource exists. The
registered vocabulary enforces that under
[`heterodyne:0.5.0#core-reason-codes`](heterodyne-core.md#core-reason-codes) rather than leaving it
to implementer discretion: `control-token-invalid` covers every unusable
Control token, `control-enrollment-unavailable` covers every refused
enrollment, and `control-sftp-denied` covers every refused overflow transfer.
A responder MUST NOT reconstruct the finer distinction through a status code,
timing difference, message string, or retry hint. It records the specific
condition in the [§9.3](#control-audit) encrypted audit and nowhere else.

<a id="control-strict-profile"></a>
### 11.1 Strict profiles

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
    "CONTROL-I-MARMOT-SENDER-BINDING",
    "CONTROL-I-ENTITLEMENT-FRESHNESS",
    "CONTROL-I-NODE-AUDIENCE",
    "CONTROL-I-OPERATION-AT-MOST-ONCE"
  ]
}
```

The agent, node-mediated-Marmot, and recovery invariants are bound to their
features and are owed under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope) whenever those
features are claimed, so the profile does not restate them. A baseline-only
implementation is not penalized for omitting them.

<a id="control-conformance"></a>
## 12. Conformance

A Control 0.5.0 implementation may claim baseline conformance only when it is
Core and Comms conformant and passes every applicable Control vector for:

- discovery, invitations, group initialization, and enrollment-only state;
- OAuth Device Authorization projection and private entitlement convergence;
- token schema, lifetime, node audience, sender thumbprint, group, and scope;
- frame canonicalization, human JSON-RPC, MCP, grants, limits, and agents;
- operation reservation, duplicate handling, failover, retention, and audit;
- revocation, group loss, and state freshness; and
- every security invariant its claim scopes in under
  [`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).

Optional recovery claims additionally require every vector for the exact
advertised recovery feature. Claiming baseline Control does not imply portable
backup, epoch custody, recovery-node authorization, private-Radicle recovery,
or SFTP.

<!-- fixture:control-conformance-gate -->
```json
{
  "can_claim_control_conformance": true,
  "blockers": [],
  "integrated_normative_subsets": [
    "marmot-control",
    "oauth-device-enrollment",
    "private-entitlement",
    "node-scoped-token",
    "human-jsonrpc",
    "agent-mcp",
    "restart-safe-operations",
    "sequential-failover",
    "node-mediated-marmot"
  ],
  "optional_profiles": [
    "control.recovery.radicle.v1",
    "control.recovery.epoch-inbox.v1",
    "control.recovery.sftp.v1"
  ]
}
```
