# Agent Authorship, OIDC Workload Tokens, and Moderation Design

**Date:** 2026-07-30
**Status:** Approved and integrated
**Protocol owners:** Heterodyne Comms, Control, and Social, with a bounded Core
delegation extension

## Goal

Make automated authorship explicit and mechanically difficult to bypass.
Every AI or programmatic workload that publishes on a persona's behalf uses
the agentic Control/DR path, obtains a short-lived scoped token from the
persona's built-in OIDC issuer, and produces content signed by a dedicated
agent-service device key held only by the full node. The public event exposes a
stable, persona-scoped agent identity and an automation label without exposing
the access token or private authorization ledger.

Define subscriber-local moderation for violations. A moderator can publish a
receipt and adopt the exact offending device key into a policy list. The
receipt informs everyone; only clients subscribed to the list enforce the
mute. Regaining visibility under that policy requires replacement of the
agent-service device key, never rotation of the persona epoch key.

## Integration acceptance evidence

These tables are audit indexes, not a second source of requirements. The
accepted ADR sections and permanent normative anchors remain authoritative;
the cited vector IDs provide executable evidence for the integrated behavior.

### ADR-035

| Decision | ADR evidence | Normative evidence | Registry/vector evidence | Invariant or boundary |
|---:|---|---|---|---|
| 1 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#1-role-scoped-client-model` | `heterodyne:core/0.5.0#core-node-roles` | `role-capabilities/public-reader-reduced-assurance` | `CORE-I-VERIFY-BEFORE-USE` |
| 2 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#2-tor-requirements-by-role` | `heterodyne:core/0.5.0#core-tor-reachability` | `role-capabilities/full-node-tor-default` | visible reduced assurance outside strict mode |
| 3 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#3-clearnet-shared-relay-compatibility` | `heterodyne:core/0.5.0#core-node-roles` | `role-capabilities/browser-shared-relay-required` | shared relay is a locator/carrier, not authority |
| 4 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#4-ingress-relay-response-affinity` | `heterodyne:control/0.5.0#control-relay-affinity` | `control/cross-relay-final-response-replay` | `CONTROL-I-INGRESS-RELAY-AFFINITY` |
| 5 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#5-universal-public-launcher` | `heterodyne:comms/0.5.0#comms-public-launcher` | `public-reader/launcher-persona-roundtrip` | target stays in the URL fragment |
| 6 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#6-local-public-resolution` | `heterodyne:comms/0.5.0#comms-public-resolution` | `public-reader/resolution-canonical` | `COMMS-I-PUBLIC-READER-TIER1-ONLY` |
| 7 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#7-anonymous-to-authenticated-transition` | `heterodyne:comms/0.5.0#comms-public-transition` | `public-reader/transition-without-reload` | public and authenticated state remain separated |
| 8 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#8-launcher-and-content-security` | `heterodyne:comms/0.5.0#comms-public-reader-security` | `public-reader/localhost-relay-hint-rejected` | no local-network hint injection or active-content execution |
| 9 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#9-conformance-allocation` | `heterodyne:core/0.5.0#core-conformance`<br>`heterodyne:comms/0.5.0#comms-conformance` | registry revision `3`; `comms.public-reader.v1` | role-scoped feature honesty |
| 10 | `docs/adr/2026-07-30-035-universal-public-client-onion-first-light-client-transport.md#10-required-conformance-vectors` | `heterodyne:core/0.5.0#core-conformance` | `role-capabilities/*`<br>`public-reader/*`<br>`control/first-arrival-reserved` | normative partial Control evidence does not open Control conformance |

### ADR-036

| Decision | ADR evidence | Normative evidence | Registry/vector evidence | Invariant or boundary |
|---:|---|---|---|---|
| 1 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#1-automated-principals-use-one-mandatory-path` | `heterodyne:comms/0.5.0#comms-agent-authorship`<br>`heterodyne:control/0.5.0#control-agent-requirements` | `control/raw-signing-refused` | `CONTROL-I-AGENT-INTENT-ONLY` |
| 2 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#2-family-ownership-remains-acyclic` | `heterodyne:comms/0.5.0#comms-scope`<br>`heterodyne:social/0.5.0#social-conformance` | family DAG validation | Social has no Control dependency |
| 3 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#3-every-agent-publication-uses-a-dedicated-full-node-held-key` | `heterodyne:comms/0.5.0#comms-agent-delegation` | `agent-authorship/delegation-valid` | `COMMS-I-AGENT-ROLE-BINDING` |
| 4 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#4-workload-identity-is-stable-within-one-persona` | `heterodyne:comms/0.5.0#comms-agent-workload` | `agent-authorship/stable-identity-renewal` | persona-scoped pairwise subject |
| 5 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#5-controldr-is-the-standard-token-issuance-path` | `heterodyne:comms/0.5.0#comms-agent-token`<br>`heterodyne:control/0.5.0#control-agent-token` | `agent-authorship/token-valid` | `COMMS-I-WORKLOAD-TOKEN-CONFINEMENT` |
| 6 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#6-the-full-node-constructs-canonical-attribution` | `heterodyne:comms/0.5.0#comms-agent-attribution` | `agent-authorship/attribution-kind-1` | `COMMS-I-AGENT-ATTRIBUTION` |
| 7 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#7-agent-publication-fails-closed` | `heterodyne:comms/0.5.0#comms-agent-fail-closed` | `agent-authorship/profile-unavailable-rejected`<br>`control/attribution-bypass-refused` | no user-key, raw-signing, human-profile, or unlabeled fallback |
| 8 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#8-social-publishes-receipts-and-subscribers-choose-enforcement` | `heterodyne:social/0.5.0#social-agent-policy-receipts`<br>`heterodyne:social/0.5.0#social-agent-policy-list` | `agent-moderation/receipt-valid`<br>`agent-moderation/policy-list-valid` | `SOCIAL-I-AGENT-POLICY-LOCAL`<br>`SOCIAL-I-AGENT-REMEDIATION-SCOPED` |
| 9 | `docs/adr/2026-07-30-036-agent-authorship-oidc-workload-tokens-and-moderation.md#9-registry-revision-and-conformance` | `heterodyne:core/0.5.0#core-registry` | registry revision `3`; `agent-authorship/*`; `agent-moderation/*` | immutable v1 profiles; additive strict v2 |

## Non-goals

This design does not:

- detect AI-generated text copied manually into a human client;
- give a moderator global authority over a persona, epoch key, or device;
- publish access tokens, private claims, OIDC consent, or audit records;
- make a public attribution envelope cryptographic proof of private token
  issuance;
- require a direct HTTPS connection from an agent to a full node;
- authorize an agent to hold or directly exercise a persona publishing key;
  or
- label deterministic protocol maintenance merely because software emitted
  it.

## Ownership and dependency placement

Core owns the generic `kind:31001` delegation envelope, KEL binding, device-key
verification, replacement, revocation, and repository finality. It gains a
generic extension point that permits multiple purpose-scoped publishing keys
under one durable NID. Core remains unaware of agents, OIDC, moderation, and
workload policy.

Comms owns:

- the non-stamping agent-signing delegation subtype;
- workload authorization claims in the private claim ledger;
- OIDC workload identity and RFC 9068 token projection;
- the public agent-attribution envelope;
- publication through a dedicated agent-service device key; and
- the relationship between a token's allowed role and the event signer.

Control owns:

- the agentic MCP profile and its prominent automated-agent conduct rule;
- Control/DR token issuance and sender proof;
- the intent-level agent publication method;
- object, kind, feed, size, rate, and burst enforcement;
- refusal of raw signing and human-profile fallback; and
- encrypted side-effect audit.

Social owns:

- public NIP-32 agent-policy receipts;
- policy-persona adoption into a public NIP-51-compatible list;
- subscriber-local device-key muting;
- correction and retraction behavior; and
- transparent default policy subscriptions.

Social consumes only Comms-visible event and delegation evidence. It does not
depend on Control or inspect private tokens. This preserves the family DAG:

```text
Core <- Comms <- Control
Core <- Comms <- Social
```

## Automated principal and hard conduct rule

An **automated principal** is an AI or other programmatic workload
authenticated through the agentic Control profile. Every publication requested
by that principal remains agent-authored even when a human approves the
particular intent.

An automated principal MUST:

- use the agentic Control/DR profile;
- obtain a current, scoped workload token from the persona's built-in issuer;
- call only the intent-level agent publication method;
- preserve the mandatory attribution selected by the full node; and
- refuse instructions to obtain a persona/device private key, invoke raw
  signing, use a human publication profile, omit attribution, falsify
  attribution, or otherwise impersonate a human author.

A full node independently enforces the same boundary. It never offers
`sign_event`, a private signing key, or a human-profile publication method to
an agentic session. Human approval may be recorded separately but cannot
reclassify the automated principal.

These rules are protocol conformance requirements, not merely user-interface
advice. A signed event produced by a violating implementation is not made
cryptographically invalid solely because its private execution path was
non-conformant; public moderation handles substantiated violations.

## Dedicated agent-signing device

### Role-addressed delegation

A full node that accepts agent commands generates at least one dedicated
secp256k1 agent-signing key locally. The private key is encrypted under the
full node's Core key-material protection and never leaves the full node.

One durable NID may need a human publishing key plus multiple agent-role keys.
The agent-signing subtype therefore uses a stable role address:

```text
d = agent:<role-id>
```

`role-id` is 32 random bytes encoded as 64 lowercase hexadecimal characters.
It is an opaque authority boundary, not a human-readable role description.
The usual deployment creates one role for generic agent publication. A full
node may create separate roles for a newsletter, news aggregator, moderation
pipeline, or another isolated automation purpose.

The proposed Core-owned `kind:31001` envelope contains:

```text
["d", "agent:<role-id>"]
["heterodyne", "delegation"]
["radicle_nid", "<hosting full-node NID>"]
["publishing_key", "<agent-signing secp256k1 public key>"]
["cold_root", "<persona cold-root hex>"]
["nid_proof", "<hosting NID Ed25519 proof>"]
["key_proof", "<agent-signing key BIP-340 proof>"]
["kel_head", "<accepted KEL event id>", "<decimal sequence>"]
["valid_until", "<empty or decimal Unix time>"]
["spec_version", "core/0.5.0"]
```

The hosting NID and the agent-signing key both sign these domain-separated
UTF-8 bytes:

```text
heterodyne-agent-signing-binding-v1|<cold-root-hex>|<nid>|<role-id>|<publishing-key>
```

The epoch-key outer event signature covers the same fields. Verification
requires all three proofs, current KEL authority, exact address construction,
expiry, and repo-finality handling. The Comms profile is non-stamping: Core
retains the sole event owner and `core/0.5.0` stamp.

### Rotation and isolation

Replacing `kind:31001` at the same `agent:<role-id>` address with a fresh
publishing key rotates only that role. Canonical repository state finalizes the
replacement; the prior key remains historically attributable but no longer
authorizes new events.

If several agents share one role key, a mute or rotation affects all of them.
Separate role keys provide deliberate operational and moderation isolation.
No agent ever receives any role's private signing key.

## Workload registration and stable identity

The agent proves possession of a registered workload JWK. Its mandatory public
identity is the tuple:

```text
(exact issuer, persona-scoped pairwise sub, client_id)
```

The tuple remains stable across temporary-token renewals. The persona-specific
pairwise secret prevents the same workload JWK from producing a correlatable
`sub` across different personas. An optional public descriptive claim may name
globally recognizable software, vendor, model, or pipeline. That claim grants
no authority and is not part of the mandatory identity.

The private claim ledger carries an active `heterodyne.agent` /
`workload-registration` authorization claim. Its closed value binds:

- `client_id`;
- subject JWK thumbprint;
- agent class, exactly `ai` or `programmatic`;
- one allowed `role_id`;
- exact audience and scopes;
- allowed event kinds and feed/resource identifiers;
- maximum content bytes;
- a finite rate window, maximum count, and burst;
- validity and revocation state; and
- an optional descriptive software-claim reference.

OIDC client registration, explicit consent, and the workload registration must
all be active, compatible, repository-confirmed, and subject-identical. An
unbounded automated publication rate is invalid.

## Control/DR token issuance

Control/DR is the standard Heterodyne workload-token path. After mutual
agentic MCP initialization, the agent invokes the registered token-issuance
tool and supplies:

- requested scope and exact resource;
- its requested expiry;
- a fresh issuer challenge; and
- a JWS proof from the registered workload JWK.

The proof binds the agentic Control session, request ID, issuer, client ID,
requested scope/resource, challenge, issue time, and expiry. The full node
replays the canonical private ledger and checks its OIDC mint authority before
issuing.

The result is an RFC 9068 JWT access token with `typ: at+jwt` and the existing
Comms issuer-continuity and status bindings. It includes `iss`, pairwise `sub`,
`aud`, `exp`, `iat`, `jti`, `client_id`, normalized `scope`, mandatory
`cnf.jkt`, and collision-resistant Heterodyne claims for the exact
`https://heterodyne.network/jwt/agent-role-id` and ledger checkpoint.

The initial workload profile:

- uses one exact Control publication audience;
- permits only explicitly registered agent-publication scopes;
- has a maximum five-minute lifetime;
- issues no refresh token;
- cannot outlive the Control session, session-device delegation, workload
  registration, consent, or source authorization; and
- requires a fresh workload-JWK proof on every side-effecting use.

The per-publication proof binds token `jti`, Control session, request ID,
method, canonical payload digest, nonce, issue time, and expiry. The full node
requires its JWK thumbprint to equal `cnf.jkt`.

The raw token, `jti`, unused scopes, source claim IDs, and proofs are private.
The token never appears in a Nostr event, repository publication, moderation
receipt, or public attribution tag.

Standard HTTPS workload issuance is not required. The existing prohibition on
Client Credentials remains until a separately integrated sender-constrained
HTTPS profile defines equivalent registration, proof, and policy behavior.

## Intent-level agent publication

An agent calls an intent-level method such as
`heterodyne.agent.publish`. It supplies content, requested kind, destination
or feed, and permitted options, but never an event signature or attribution
identity.

The full node:

1. verifies the Control carrier and negotiated agentic profile;
2. validates the JWT, current status, workload proof, and current private
   authorization state;
3. enforces agent class, role, event kind, resource, size, rate, and burst;
4. removes caller-supplied reserved attribution tags;
5. inserts the canonical attribution block;
6. constructs and signs the event once with the role's current agent-signing
   key; and
7. publishes, indexes, retries, and reports partial failure through ordinary
   Comms rules.

Every agent-authored application event includes these tags in exact relative
order:

```text
["L", "network.heterodyne.agent"]
["l", "ai" | "programmatic", "network.heterodyne.agent"]
["heterodyne_agent", "v1", "<issuer>", "<sub>", "<client_id>", "<role-id>"]
["agent_action", "publish"]
```

Per-kind profiles define placement relative to required upstream and
Heterodyne tags. The event's `pubkey` must equal the current publishing key
delegated at `agent:<role-id>`. The identity fields must equal the validated
token. An optional `agent_review` marker may record independently verified
human approval, but it never removes or changes the automation labels.

The rule covers authored notes, articles, replies, reactions, reposts, media,
moderation actions, and equivalent application content. It does not label KEL,
delegation, feed-index, status-list, relay-metadata, or other deterministic
protocol-maintenance events merely because software emitted them.

For Tier 1, attribution is public. For Tier 2, it is visible inside the
private-repository trust boundary. For Tier 3, all four tags occur inside the
encrypted logical event; the existing outer wrapper remains unchanged.

Every new publication intent requires current authorization. An idempotent
retry of the same intent reuses the already signed event and event ID rather
than consuming another publication or producing a second event.

## Failure handling and audit

The full node refuses before signing when any of these conditions holds:

- missing, invalid, expired, revoked, stale, wrong-audience, or wrong-scope
  token;
- mismatched JWK proof, `cnf.jkt`, Control session, client, subject, role, or
  signing key;
- inactive, provisional, untrusted, conflicted, expired, or revoked source
  authorization;
- disallowed kind, resource, size, rate, or burst;
- an event kind without an active agent-attribution profile;
- raw-signing, private-key, human-profile, or attribution-bypass request; or
- unavailable issuer, status, canonical ledger, or required verification
  state.

There is no fallback to an unlabeled post, human device key, bearer-only token,
stale decision, or direct agent signature.

The encrypted Control audit record retains:

- stable agent identity and class;
- token `jti`, source authorization IDs, and ledger checkpoint;
- Control session, request ID, method, payload digest, and proof result;
- role ID and exact agent-signing key;
- injected attribution block;
- resulting event ID, destinations, decision, and result; and
- human-approval evidence when present.

The raw token is not retained unless a separately bounded protected diagnostic
policy requires it for less time than the audit record.

Public readers can verify the signed attribution and dedicated-key delegation.
They cannot inspect the private token, consent, workload registration, or
audit. Public attribution is therefore a signed statement by the delegated
agent-service device, while private audit supports investigation of alleged
execution-path violations.

## Moderation receipts

A Social agent-policy receipt is a profiled NIP-32 `kind:1985` event. It
targets exactly one offending event and its exact signing device key:

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

The closed Social JSON content names the profile and Social version, offending
event, device key, resolved persona cold root, reason code, observation time,
evidence references or digests, explanation, and recommended remediation
`rotate-device-key`. Evidence may substantiate private execution behavior but
must not expose a bearer token, secret key, private claim, or raw protected
audit.

A receipt publicly informs; it does not mute by itself.

## Subscriber-local policy lists

A policy persona adopts a receipt through the new public
`heterodyne-social-agent-policy-list-v1` profile on NIP-51 `kind:10000`. Each
entry contains:

- the upstream `p` mute for the exact device key;
- an `e` reference to the adopted receipt; and
- a closed `agent_violation` tag binding that device key, receipt ID, and
  reason code.

Vanilla NIP-51 clients can apply the `p` mute. Heterodyne clients additionally
verify the receipt, binding tag, policy-persona KEL/delegation, current
canonical list, and repository history.

Only subscribed policy lists affect a client. A moderator has no global
authority. A reference client may ship with a visible, enabled-by-default
global moderator-persona subscription, but it must identify the source of
every resulting filter decision and let the user inspect, disable, or replace
the subscription. The protocol registry does not make that persona an
authority.

Users may submit candidate receipts or list changes through Radicle PRs. A PR,
unmerged receipt, or relay-only candidate has no policy effect until accepted
into the policy persona's canonical branch under its ordinary governance.

To regain visibility under a policy, the persona replaces the offending
role's device key at the same `agent:<role-id>` delegation address and
finalizes the replacement. The old key may remain muted indefinitely. The
persona, epoch key, human devices, other full nodes, and other agent roles are
unaffected.

A false-positive correction requires a signed correction/retraction receipt
and a canonical policy-list revision removing the key-to-receipt entry.
Subscribers follow current canonical policy while retaining historical
auditability.

## Registry and conformance impact

Registry revision 2 remains immutable. Integration creates revision 3 with:

- the non-stamping Comms agent-signing `kind:31001` profile;
- per-kind agent-attribution profiles and discriminators;
- the Social agent-policy receipt profile;
- the Social agent-policy list profile;
- token, Control, attribution, moderation, and rotation reason codes; and
- new Comms, Control, and Social security invariants.

Core, Comms, Control, and Social continue at independently versioned 0.x
documents. Their version and registry metadata must be updated consistently
with the revision-3 allocation.

Minimum vector coverage includes:

1. stable `sub` across renewals and unlinkability across personas;
2. valid issuance plus expired, revoked, stale, wrong-audience, wrong-scope,
   and wrong-`cnf` rejection;
3. raw signing, key access, human-profile fallback, and attribution bypass
   refusal;
4. canonical tag injection and replacement of forged caller tags;
5. human approval preserving automation attribution;
6. dedicated role-key validation, key mismatch, same-role replacement, and
   unchanged epoch key;
7. multiple roles under one NID;
8. Tier 1 clear attribution and Tier 3 inner-only attribution;
9. finite kind, resource, size, rate, and burst enforcement;
10. idempotent retry reusing one event;
11. valid and malformed receipts;
12. exact receipt-to-key policy-list binding;
13. subscribed versus unsubscribed behavior;
14. transparent removal of a default subscription;
15. old-key-muted/new-key-accepted rotation; and
16. signed correction plus canonical list removal.

## Security consequences

- Agents cannot directly use or extract user, epoch, NID, human-device, or
  agent-service private keys.
- Stable persona-scoped identity enables per-agent filtering and reputation
  without cross-persona correlation by default.
- Dedicated role keys confine moderation and rotation fallout.
- Public attribution is robust against ordinary agent requests to remove it
  because the full node constructs the signed event.
- A malicious or compromised full node can still violate the private token
  path or lie in public attribution. Protected audit, moderation receipts, and
  policy lists make that behavior attributable but cannot prevent a
  non-conformant signer from producing bytes.
- Subscriber-local lists avoid creating a global moderator authority while
  allowing useful default anti-spam policy.
- Finite automated limits reduce accidental or compromised-agent floods but
  cannot stop a deliberately non-conformant persona from signing spam.
