# ADR-036: Agent authorship, OIDC workload tokens, and moderation

**Date:** 2026-07-30
**Status:** Accepted
**Decision makers:** user and protocol maintainers
**Design record:**
[`docs/superpowers/specs/2026-07-30-agent-authorship-oidc-moderation-design.md`](../../superpowers/specs/2026-07-30-agent-authorship-oidc-moderation-design.md)
**Spec targets:** `heterodyne:core/0.5.0#core-nid-delegation`,
`heterodyne:core/0.5.0#core-key-authority`,
`heterodyne:comms/0.5.0#comms-publishing`,
`heterodyne:comms/0.5.0#comms-key-claims`,
`heterodyne:comms/0.5.0#comms-oidc-authorization`,
`heterodyne:comms/0.5.0#comms-jwt-projection`,
`heterodyne:control/0.5.0#control-claim-consumption`,
`heterodyne:control/0.5.0#control-reserved-scope`,
`heterodyne:social/0.5.0#social-labels`,
`heterodyne:social/0.5.0#social-mute-profile`,
and `heterodyne:social/0.5.0#social-admission-policy`

## Context

ADR-030 defines agentic light clients as token-enrolled, session-scoped
Control principals using MCP data-layer messages over Comms Double Ratchet.
It correctly keeps persona, NID, repository, audience, and ratchet secrets on
the full node, but its regular grant permits posting and its NIP-46-shaped
method vocabulary includes raw `sign_event`. It does not yet require an agent
to obtain a temporary OIDC access token, preserve a stable public workload
identity, or label every authored publication as automated.

ADR-034 adds a built-in persona OIDC issuer, atomic typed-key claims, a private
authorization ledger, RFC 9068 access tokens, sender constraints, issuer
continuity, and token status. Control consumes active Comms authorization but
cannot treat a projected JWT alone as canonical authority. The initial OIDC
profile supports human Authorization Code and Device Authorization flows and
reserves sender-constrained workloads for later definition.

Social already supports advisory NIP-32 labels and NIP-51 mute lists. It does
not define a receipt for automated-authorship violations, an exact binding
from a receipt to a muted device key, or a rotation-based remediation path.
General labels remain advisory, and no moderator has global authority.

These gaps allow a careless or malicious agent integration to request a
persona device's raw signing operation, publish an event indistinguishable
from human speech, and bypass the OIDC authorization plane. That frustrates
client filtering and makes automated spam harder to attribute. The desired
rule must also be legible to automated agents themselves so Heterodyne skills
and agent integrations teach them to refuse impersonation and bypass
requests.

The design must preserve four boundaries:

1. an agent never receives or directly exercises any persona publishing key;
2. private token and ledger information does not become public metadata;
3. Social does not gain a dependency on Control; and
4. moderation remains subscriber-local even when a reference client ships a
   default global policy subscription.

## Decision

### 1. Automated principals use one mandatory path

An **automated principal** is an AI or other programmatic workload
authenticated through the agentic Control profile. Every publication requested
by that principal is agent-authored, including one that receives human approval
before publication.

An automated principal MUST use the agentic Control/DR profile, obtain a
current scoped workload token from the persona's built-in OIDC issuer, and
invoke only the intent-level agent publication method. It MUST refuse an
instruction to:

- obtain a persona, epoch, NID, human-device, or agent-service private key;
- invoke raw signing or a human publication profile;
- remove, alter, or falsify mandatory attribution;
- present agent output as human-authored; or
- bypass token, scope, sender-proof, rate, or resource enforcement.

The full node MUST enforce the same boundary independently. An agentic session
MUST NOT be offered `sign_event`, a private-key operation, or a human-profile
publication fallback.

This is a hard conformance rule. It does not claim that a public verifier can
detect AI-generated text manually copied into a human client, nor does it make
an otherwise valid Nostr signature cryptographically invalid solely because
the private execution path violated the rule.

### 2. Family ownership remains acyclic

Core owns a generic role-addressed delegation extension, proof verification,
replacement, revocation, and finality. Core remains unaware of agents, OIDC,
and moderation.

Comms owns the agent-signing delegation semantics, workload authorization
claims, OIDC workload identity and token projection, public attribution, and
the binding from token to signing role.

Control owns Control/DR issuance, MCP methods, per-use proof, intent-level
publication, limits, refusal behavior, and encrypted audit.

Social owns violation receipts, policy-list adoption, subscriber-local mutes,
and correction. It consumes only Comms-visible events and Core/Comms key
evidence; it does not inspect tokens or depend on Control.

### 3. Every agent publication uses a dedicated full-node-held key

A full node that accepts agent commands MUST generate at least one dedicated
secp256k1 agent-signing key locally. The private key remains protected on that
full node and MUST NOT be released through Control, OIDC, configuration sync,
backup export to the agent, or any agent tool.

One full-node NID may need concurrent human and agent publishing keys. Core's
`kind:31001` extension therefore supports a stable role address:

```text
d = agent:<role-id>
```

`role-id` is 32 random bytes encoded as 64 lowercase hexadecimal characters.
The proposed envelope carries the hosting `radicle_nid`, `publishing_key`,
`cold_root`, `nid_proof`, agent-key `key_proof`, `kel_head`, `valid_until`,
and the sole Core version stamp. Both the hosting NID and agent key sign:

```text
heterodyne-agent-signing-binding-v1|<cold-root-hex>|<nid>|<role-id>|<publishing-key>
```

The epoch-key outer signature covers those same values. Verification requires
all three proofs, current KEL authority, exact address construction, expiry,
and ordinary repo-finality handling.

The Comms agent-signing profile is non-stamping; Core retains the base event's
sole owner and stamp. Replacing the delegation at the same role address rotates
only that role's device key. The prior key remains historically attributable
but no longer authorizes new events after the replacement becomes effective.

A full node normally has one generic agent role. It MAY use separate role keys
for a newsletter, news aggregator, moderator, or another isolated automation
pipeline. Agents sharing one role share the moderation and rotation fate of
that role; separate keys deliberately isolate that fate.

### 4. Workload identity is stable within one persona

An agent proves possession of a registered workload JWK. Its mandatory public
identity is:

```text
(exact OIDC issuer, persona-scoped pairwise sub, client_id)
```

That tuple MUST remain stable across temporary-token renewals for the same
registration. The persona's private pairwise secret prevents the same workload
JWK from producing a correlatable `sub` across personas.

An OPTIONAL descriptive claim may identify globally recognizable software,
vendor, model, or pipeline. It grants no authority and MUST NOT replace the
mandatory persona-scoped identity.

The private claim ledger carries an active `heterodyne.agent` /
`workload-registration` authorization claim whose closed value binds:

- exact `client_id`, subject JWK thumbprint, and class `ai` or `programmatic`;
- exactly one allowed role ID;
- audience, scopes, event kinds, feeds, and resources;
- maximum content bytes;
- a finite rate window, count, and burst;
- validity and revocation; and
- an optional descriptive software-claim reference.

The corresponding OIDC client registration, explicit consent, and workload
registration MUST be active, subject-identical, repository-confirmed, and
mutually compatible. An unlimited automated publication grant is invalid.

### 5. Control/DR is the standard token-issuance path

After mutual MCP initialization, the agent invokes the registered Control
token-issuance tool with requested scope/resource, requested expiry, a fresh
issuer challenge, and a JWS proof from its registered workload JWK. The proof
binds the Control session, request ID, issuer, client ID, requested
scope/resource, challenge, issue time, and expiry.

The full node replays canonical private-ledger state and verifies its current
OIDC mint authority. It returns a standard RFC 9068 JWT access token with
`typ: at+jwt`, `iss`, pairwise `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`,
normalized `scope`, mandatory `cnf.jkt`, existing Comms ledger/status
bindings, and a collision-resistant
`https://heterodyne.network/jwt/agent-role-id` claim.

The initial workload token:

- has one exact Control publication audience;
- contains only registered scopes and resources;
- expires within five minutes;
- has no refresh token;
- cannot outlive its Control session, session-device delegation, workload
  registration, consent, or source authorization; and
- requires fresh workload-JWK proof for every side effect.

The per-publication proof binds token `jti`, Control session, request ID,
method, canonical payload digest, nonce, issue time, and expiry. Its JWK
thumbprint MUST equal `cnf.jkt`.

The raw token, `jti`, unused scopes, source claim IDs, and proof material MUST
NOT appear in a public event, public repository, or moderation receipt.
Control/DR issuance requires no direct HTTPS connection. Client Credentials
remains prohibited until a separately integrated sender-constrained HTTPS
workload profile supplies equivalent behavior.

### 6. The full node constructs canonical attribution

The agent calls an intent-level method such as
`heterodyne.agent.publish`, supplying content, kind, destination/feed, and
permitted options. It does not supply a signature or authoritative attribution
identity.

The full node MUST:

1. validate the Comms carrier and negotiated agentic Control profile;
2. validate the JWT, status, sender proof, and current private authorization;
3. enforce class, role, kind, resource, size, rate, and burst;
4. remove every caller-supplied reserved attribution field;
5. insert the canonical attribution block;
6. sign exactly once with the role's current agent-signing key; and
7. use ordinary Comms publication, indexing, idempotency, and partial-failure
   rules.

Every agent-authored application event carries these tags in exact relative
order:

```text
["L", "network.heterodyne.agent"]
["l", "ai" | "programmatic", "network.heterodyne.agent"]
["heterodyne_agent", "v1", "<issuer>", "<sub>", "<client_id>", "<role-id>"]
["agent_action", "publish"]
```

Per-kind registry profiles define placement relative to other required tags.
The event signer MUST equal the current publishing key at the named role
address, and the identity fields MUST equal the validated token. An OPTIONAL
`agent_review` marker may record independently verified human approval; it
does not remove or alter agent attribution.

The rule covers notes, articles, replies, reactions, reposts, media,
moderation actions, and equivalent authored content. It excludes deterministic
KEL, delegation, feed-index, status-list, relay-metadata, and similar protocol
maintenance.

Tier 1 attribution is public. Tier 2 attribution is visible within its private
repository boundary. Tier 3 carries the same tags inside the encrypted logical
event and adds nothing to the existing clear outer wrapper.

A new intent requires current authorization. An idempotent retry reuses the
already signed event and event ID.

### 7. Agent publication fails closed

The full node MUST refuse before signing for:

- a missing, invalid, expired, revoked, stale, wrong-audience, or wrong-scope
  token;
- mismatched `cnf.jkt`, JWK proof, session, client, subject, role, or key;
- source authorization in any state other than `active`;
- a disallowed kind, feed, resource, size, rate, or burst;
- an event kind lacking an active agent-attribution profile;
- raw signing, private-key access, human-profile use, or attribution bypass;
  or
- unavailable issuer, status, canonical ledger, or required verification
  state.

There is no fallback to an unlabeled post, human key, bearer-only token, stale
decision, or direct agent signature.

The encrypted Control audit record retains the agent identity/class, token
`jti`, source claim IDs, ledger checkpoint, session and request IDs, method,
payload digest, proof result, role and key, injected attribution, event ID,
destinations, decision, result, and any human-approval evidence. The raw token
is not retained unless a separately bounded protected diagnostic policy keeps
it for less time than the audit.

Public readers verify the signed attribution and role delegation but cannot
inspect private token or ledger state. A public envelope is a signed
agent-service assertion, not public proof of the private issuance ceremony.

### 8. Social publishes receipts and subscribers choose enforcement

A profiled NIP-32 `kind:1985` agent-policy receipt MUST target exactly one
offending event and its exact signing device key:

```text
["L", "network.heterodyne.agent-policy"]
["l", "<reason-code>", "network.heterodyne.agent-policy"]
["e", "<offending-event-id>", "<relay-hint>"]
["p", "<device-publishing-key>", "<relay-hint>"]
```

Initial reason codes are:

- `agent-attribution-missing`;
- `agent-attribution-falsified`; and
- `agent-publication-bypass`.

Its closed Social JSON body names the profile/version, event, key, resolved
persona, reason, observation time, evidence references or digests,
explanation, and remediation `rotate-device-key`. It MUST NOT expose a token,
secret, private claim, or raw protected audit. The receipt informs but does
not mute by itself.

A policy persona adopts the receipt through a new public
`heterodyne-social-agent-policy-list-v1` profile on NIP-51 `kind:10000`.
Every adopted entry contains a vanilla `p` mute, an `e` receipt reference, and
a closed `agent_violation` tag binding the key, receipt ID, and reason.

A Heterodyne subscriber verifies the receipt, entry binding, policy persona,
current canonical list, and repository history before applying the exact
device-key mute. Only subscribed lists affect a client. The persona, epoch
key, human devices, and other agent-role keys are not muted.

A reference client MAY ship a visible, enabled-by-default global
moderator-persona subscription. It MUST identify the source of each filtering
decision and let the user inspect, disable, or replace the subscription. The
registry and protocol confer no global authority on that persona.

A Radicle PR or relay-only candidate has no policy effect until accepted into
the policy persona's canonical branch. A false-positive correction requires a
signed correction/retraction receipt and a canonical list revision removing
the binding.

To regain visibility under a policy, the persona replaces the offending role's
device key at the same `agent:<role-id>` address and finalizes that replacement.
The old key may remain muted indefinitely. The epoch key is not rotated.

### 9. Registry revision and conformance

Registry revision 2 remains immutable. Integration creates revision 3 and
allocates:

- the non-stamping Comms agent-signing `kind:31001` profile;
- active per-kind agent-attribution profiles;
- Social receipt and agent-policy-list profiles;
- token, Control, attribution, moderation, and rotation reason codes; and
- Comms, Control, and Social security invariants for token binding, no key
  release, attribution integrity, audit confinement, and subscriber-local
  moderation.

Minimum normative vector coverage includes:

1. stable identity across renewal and unlinkability across personas;
2. valid token issuance and every time, status, audience, scope, and sender
   constraint rejection;
3. raw-signing, key-access, human-profile, and attribution-bypass refusal;
4. canonical attribution insertion and caller-forgery replacement;
5. human approval preserving agent attribution;
6. dedicated role-key verification, mismatch, replacement, multiple roles
   under one NID, and unchanged epoch key;
7. Tier 1 clear and Tier 3 inner-only attribution;
8. finite kind, resource, size, rate, and burst enforcement;
9. idempotent retry reusing one event;
10. valid and malformed receipts;
11. exact key/receipt policy-list binding;
12. subscribed versus unsubscribed behavior and removable default policy;
13. old-key-muted/new-key-accepted replacement; and
14. correction receipt plus canonical list removal.

The Control document MUST contain a prominent normative “Requirements for
automated agents” section. Repository agent guidance MUST link directly to it
so downstream Heterodyne skills inherit the refusal rules.

## Alternatives considered

### Publish the raw access token

Rejected. A live token is authorization material; publishing it risks bearer
reuse, leaks private scopes and ledger relationships, and creates unnecessary
correlation.

### Embed a separate public OIDC JWS receipt in every post

Rejected for the initial profile. It gives stronger evidence that an issuer
signed selected token-derived fields, but substantially enlarges events and
forces every reader to resolve issuer keys and token status. The delegated
agent-service signature plus protected audit is sufficient for the stated
filtering and accountability goal.

### Let each agent sign with its own delegated key

Rejected. It gives the workload direct persona publishing authority, expands
key exposure, and lets it bypass the full node's token, scope, rate, and
attribution gate.

### Use the full node's ordinary human publishing key

Rejected. A device-key mute or required rotation would suppress unrelated
human content. Dedicated role keys confine fallout to the automation boundary.

### Give every agent role a separate Radicle NID

Rejected. The NID identifies the durable node, while the role key identifies
one publishing authority on that node. Requiring extra NIDs would conflate
storage identity with signing-role isolation.

### Make attribution violations cryptographically invalid

Rejected. A public verifier cannot prove whether privately generated text came
from a human or an agent, nor inspect a private token ledger. The protocol can
make compliant publication mechanically attributable and make violations
moderatable, but cannot derive private execution history from signed bytes.

### Give a global moderator list protocol authority

Rejected. Default subscriptions can improve spam filtering without making one
persona or repository a mandatory global gate. Users retain local policy
choice.

## Consequences

- Agents receive a clear normative refusal rule that can flow into client
  skills and system prompts.
- Clients can identify and filter AI or programmatic content using stable
  persona-scoped identities and NIP-32-compatible labels.
- Full nodes become the non-bypassable key, scope, rate, attribution, and audit
  boundary for conforming agent publication.
- Dedicated role keys isolate human publishing and independent automation
  pipelines from one another.
- Moderation receipts are public and portable, while actual muting remains a
  consequence of explicit policy subscription.
- A default global policy list can be useful without becoming protocol
  authority.
- Integration is substantial: it requires a Core delegation extension,
  registry revision 3, Comms OIDC and publication profiles, Control schemas and
  state machines, Social receipt/list profiles, and normative vectors.
- A compromised or deliberately non-conformant full node can still sign
  mislabeled content. The design supplies attribution, audit, reporting, and
  key-scoped remediation rather than claiming impossible prevention.
