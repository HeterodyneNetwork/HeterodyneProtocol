# Public Client and Agent Authorship Protocol Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate accepted ADR-035 and ADR-036 into the four normative protocol documents, immutable registry revision 3, closed schemas, security model, and byte-exact conformance corpus.

**Architecture:** Core gains role-scoped network capabilities and a generic role-addressed delegation extension. Comms instantiates public-reader and agent-authorship profiles; Control defines relay-affine request handling and the agent-only token/publication surface while remaining non-claimable because ADR-030 is still Proposed; Social defines advisory receipts and subscriber-local policy-list enforcement. Registry revision 3 records every profile, reason code, and invariant, and generator modules provide executable semantic models plus authored vectors.

**Tech Stack:** Markdown normative specifications, JSON Schema draft-07, Nostr/NIP-01 events, TypeScript, Vitest, `@noble/*`, `nostr-tools`, RFC 8785 JCS, RFC 9068 JWT access tokens, RFC 9449-style JWK confirmation, NIP-19, NIP-32, NIP-51, and NIP-65.

## Global Constraints

- Preserve the dependency DAG exactly: `Core <- Comms <- Control` and `Core <- Comms <- Social`; Social MUST NOT reference Control normatively.
- Keep all four documents at their independent `0.5.0` versions and update their registry pin from revision 2 to revision 3 without claiming a synchronized family version.
- Preserve `docs/spec/registry/history/1.json` and `history/2.json` byte-identically; create `history/3.json` from the exact revision-3 entry set.
- Keep Control `incomplete-draft` and non-claimable because ADR-030 remains Proposed; activate only the ADR-035 relay-affinity and ADR-036 agent subsets as integrated reserved behavior.
- Use these exact Core feature IDs: `core.nostr-relay-read.v1`, `core.outbound-tor.v1`, `core.repo-relay-client.v1`, `core.onion-service-host.v1`, and `core.browser-shared-relay.v1`.
- Use the exact Comms receive-only feature ID `comms.public-reader.v1`.
- Baseline public-reader and light-client roles SHOULD implement outbound Tor but may omit it with a visible reduced-assurance disclosure; `heterodyne-core-strict-v1` and every full node require `core.outbound-tor.v1`.
- Full nodes host a persistent v3 onion-service repo relay by default and do not silently optimize to clearnet peer-to-peer or WebRTC.
- The reference launcher grammar remains fragment-only: `#/v1/p/<nprofile>`, optional `/e/<nevent>`, or optional `/a/<naddr>`; the cold-root `nprofile` is authoritative.
- Public-reader resolution accepts only Tier 1 and returns exactly `canonical`, `provisional-canonical`, `unindexed-signed-event`, `conflicted`, `unavailable`, or `private`.
- Agent identity is exactly `(issuer, persona-scoped pairwise sub, client_id)` and the role address is exactly `agent:<64-lowercase-hex-role-id>`.
- Agent workload tokens use `typ: at+jwt`, mandatory `cnf.jkt`, a maximum five-minute lifetime, no refresh token, one exact Control publication audience, and `https://heterodyne.network/jwt/agent-role-id`.
- The full node holds every agent-role private key and MUST NOT expose raw signing, private-key access, human-profile publication, or attribution bypass to an automated principal.
- Canonical agent attribution order is `L`, `l`, `heterodyne_agent`, `agent_action`; Tier 3 places it only inside the encrypted logical event.
- Active baseline attribution profiles cover kinds `1`, `6`, `7`, `16`, `1063`, `1985`, `4550`, and `30023`; another kind fails closed until a registry profile is added.
- Social moderation is advisory and subscriber-local; no registry entry or default subscription confers global moderator authority.
- Preserve every existing `*-strict-v1` membership declaration. Add `heterodyne-comms-strict-v2`, reserved-inactive `heterodyne-control-strict-v2`, `heterodyne-social-strict-v2`, and `heterodyne-social-matrix-strict-v2` for the revision-3 invariants; stable v1 IDs MUST NOT acquire new members.
- Use TDD for generator behavior: write a focused test, observe the expected failure, implement the smallest semantic model, then author the vector.
- Do not edit `research/sources/`.

---

### Task 1: Registry Revision 3 and Family Pins

**Files:**
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/registry/kinds.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Create: `docs/spec/registry/history/3.json`
- Modify: `docs/spec/releases/release-manifest.schema.json`
- Modify: `docs/spec/releases/{core,comms,control,social}/0.5.0.json`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-social.md`

**Interfaces:**
- Consumes: immutable revision-2 entry set and `computeRegistryDigest()` from `src/registry.ts`.
- Produces: revision-3 profile IDs, reason codes, invariant IDs, and one registry digest used by every later task and vector.

- [ ] **Step 1: Write failing revision-3 registry tests**

Change the current revision expectation to `3`, require history revisions `1`, `2`, and `3`, and assert that `history/2.json` still equals the previous revision-2 snapshot. Add literal profile assertions for:

```ts
const agentProfiles = [
  [31001, "heterodyne-comms-agent-signing-delegation-v1", "comms", false],
  [1, "heterodyne-comms-agent-attribution-kind-1-v1", "comms", false],
  [6, "heterodyne-comms-agent-attribution-kind-6-v1", "comms", false],
  [7, "heterodyne-comms-agent-attribution-kind-7-v1", "comms", false],
  [16, "heterodyne-comms-agent-attribution-kind-16-v1", "comms", false],
  [1063, "heterodyne-comms-agent-attribution-kind-1063-v1", "comms", false],
  [1985, "heterodyne-comms-agent-attribution-kind-1985-v1", "comms", false],
  [4550, "heterodyne-comms-agent-attribution-kind-4550-v1", "comms", false],
  [30023, "heterodyne-comms-agent-attribution-kind-30023-v1", "comms", false],
  [1985, "heterodyne-social-agent-policy-receipt-v1", "social", true],
  [10000, "heterodyne-social-agent-policy-list-v1", "social", true],
] as const;
```

The `31001` discriminator is `tag:d=agent:<role-id>;tags:key_proof,radicle_nid,nid_proof`; each attribution discriminator is `tags:L=network.heterodyne.agent,l=<class>@network.heterodyne.agent,heterodyne_agent=v1,agent_action=publish;order=v1`; the receipt discriminator is `tags:L=network.heterodyne.agent-policy,l=<reason>@network.heterodyne.agent-policy`; the list discriminator is `tag:heterodyne=social-agent-policy-list-v1`.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/docs-lint.test.ts
```

Expected: FAIL because the manifest is revision 2 and the new profiles, reasons, invariants, history snapshot, and release pins do not exist.

- [ ] **Step 3: Add the revision-3 allocation**

Add the profiles above, with `first_version` equal to the owning document’s `0.5.0`, `status: "draft"`, and exact stamping booleans.

Add closed reason-code families:

```text
role-delegation-address-invalid
role-delegation-key-proof-invalid
public-reader-route-invalid
public-reader-relay-hint-invalid
public-reader-private-content
agent-workload-registration-invalid
agent-token-invalid
agent-token-expired
agent-token-revoked
agent-token-stale
agent-token-audience-invalid
agent-token-scope-invalid
agent-sender-proof-invalid
agent-role-mismatch
agent-attribution-invalid
agent-attribution-profile-unavailable
control-request-expired
control-request-id-conflict
control-ingress-relay-invalid
agent-method-prohibited
agent-key-access-prohibited
agent-human-profile-prohibited
agent-attribution-bypass-prohibited
agent-resource-denied
agent-size-exceeded
agent-rate-limited
agent-attribution-missing
agent-attribution-falsified
agent-publication-bypass
agent-policy-receipt-invalid
agent-policy-binding-invalid
agent-role-key-rotation-required
```

Add these invariant IDs with their owning documents:

```text
COMMS-I-PUBLIC-READER-TIER1-ONLY
COMMS-I-AGENT-ROLE-BINDING
COMMS-I-AGENT-ATTRIBUTION
COMMS-I-WORKLOAD-TOKEN-CONFINEMENT
CONTROL-I-INGRESS-RELAY-AFFINITY
CONTROL-I-AGENT-NO-KEY-RELEASE
CONTROL-I-AGENT-INTENT-ONLY
CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS
SOCIAL-I-AGENT-POLICY-LOCAL
SOCIAL-I-AGENT-REMEDIATION-SCOPED
```

Use qualified permanent anchors in every reason-code `spec_refs`.

- [ ] **Step 4: Stage profile coverage explicitly**

Rename `ADR034_PENDING_PROFILE_IDS` to `PENDING_PROFILE_IDS` and temporarily list every new revision-3 profile. Preserve `heterodyne-control-session-device-v1` as inactive. Later tasks remove each pending ID only when its vector exists.

- [ ] **Step 5: Compute and pin the revision-3 digest**

Copy the complete active entry set to `history/3.json`, compute `computeRegistryDigest(currentEntrySet)`, write that digest and revision `3` to `manifest.json`, the release schema constants, and all four release manifests. Mechanically update active registry-pin prose and machine-readable fixtures in all four normative documents to revision 3. Add the new Core and Comms features to their manifests; keep Control `incomplete-draft`.

- [ ] **Step 6: Verify GREEN**

Run the focused registry tests. Expected: PASS with revision 3 loaded, revisions 1 and 2 preserved, and all release pins equal.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/registry docs/spec/releases docs/spec/heterodyne-*.md docs/spec/vectors/generator/src/registry.test.ts docs/spec/vectors/generator/src/docs-lint.test.ts docs/spec/vectors/generator/src/coverage.ts
git commit -m "spec: allocate registry revision 3"
```

### Task 2: Core Role Capabilities, Onion Defaults, and Role Delegation

**Files:**
- Create: `docs/spec/vectors/generator/src/role-capabilities.ts`
- Create: `docs/spec/vectors/generator/src/role-capabilities.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-role-capabilities.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/releases/core/0.5.0.json`

**Interfaces:**
- Consumes: revision-3 feature IDs and the Core `kind:31001` base owner.
- Produces:

```ts
export type CoreRole = "public-reader" | "authenticated-light" | "full-node";
export type CapabilityVerdict = { verdict: "accept" | "reject"; reduced_assurance: boolean; warnings: string[] };
export function evaluateRoleCapabilities(role: CoreRole, features: readonly string[], strict: boolean): CapabilityVerdict;
export function validateRoleDelegationAddress(address: string): { verdict: "accept" | "reject"; role_id?: string };
export function validateFullNodeReachability(input: FullNodeReachabilityInput): CapabilityVerdict;
```

- [ ] **Step 1: Write failing role tests**

Test literal outcomes for a browser public reader with only `core.nostr-relay-read.v1`, a strict client missing Tor, a full node missing onion hosting, a browser-compatible full node missing a clearnet shared relay, and a complete Tor-default full node. Test `agent:<64-lowercase-hex>` acceptance and uppercase, short, non-hex, or alternate-prefix rejection.

- [ ] **Step 2: Run RED**

Run `npm --prefix docs/spec/vectors/generator test -- src/role-capabilities.test.ts`. Expected: module-not-found failure.

- [ ] **Step 3: Implement the semantic model**

`evaluateRoleCapabilities` MUST:

- require `core.nostr-relay-read.v1` for every public reader;
- mark missing Tor reduced assurance only for non-strict public/light clients;
- require `core.outbound-tor.v1`, `core.repo-relay-client.v1`, and `core.onion-service-host.v1` for full nodes;
- require `core.browser-shared-relay.v1` only when browser compatibility is claimed; and
- reject any advertisement that claims an unimplemented feature.

`validateFullNodeReachability` additionally requires a persistent v3 onion service, Tor-default outbound backends, and at least one normalized clearnet `wss://` shared relay for browser compatibility.

- [ ] **Step 4: Run GREEN**

Run the focused test. Expected: all role, downgrade, address, and full-node cases pass.

- [ ] **Step 5: Amend Core**

Replace the universal repo-relay/Tor client requirement with the three declared roles and exact feature IDs. Define the generic role-addressed `kind:31001` extension interface without importing Comms semantics; registered higher-layer profiles supply their namespace, proof domain, and additional proof. Require full-node v3 onion hosting and Tor-default outbound behavior, clarify that a full node is not a public Tor relay, and prohibit silent WebRTC/clearnet direct downgrade. Keep the existing Core invariant set and stable `heterodyne-core-strict-v1` membership unchanged; its already-defined Tor-default obligation now requires the exact `core.outbound-tor.v1` feature.

- [ ] **Step 6: Author Core vectors**

Add vectors for role feature honesty, missing-Tor reduced assurance, strict missing-Tor rejection, full-node onion advertisement, Tor-default routing, browser shared-relay minimum, and role-address validation. Remove the Core-related pending profile only when covered.

- [ ] **Step 7: Run Core checks and commit**

Run the focused tests, `npm run author`, `npm run coverage`, and `npm run verify`; then commit:

```bash
git add docs/spec/heterodyne-core.md docs/spec/releases/core docs/spec/vectors
git commit -m "spec: make Core transport requirements role scoped"
```

### Task 3: Comms Public Reader and Universal Launcher

**Files:**
- Create: `docs/spec/vectors/generator/src/public-reader.ts`
- Create: `docs/spec/vectors/generator/src/public-reader.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-public-reader.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/releases/comms/0.5.0.json`

**Interfaces:**
- Consumes: Core role capability result, NIP-19 entities, NIP-65 relay refresh, and current Comms envelope/feed/retrieval rules.
- Produces:

```ts
export type LauncherRoute =
  | { type: "persona"; nprofile: string }
  | { type: "event"; nprofile: string; nevent: string }
  | { type: "address"; nprofile: string; naddr: string };
export type PublicOutcome =
  | "canonical" | "provisional-canonical" | "unindexed-signed-event"
  | "conflicted" | "unavailable" | "private";
export function parseLauncherFragment(fragment: string): LauncherParseResult;
export function validateBootstrapRelay(url: string, resolvedAddress?: string): RelayHintResult;
export function resolvePublicAsset(input: PublicResolutionInput): PublicOutcome;
```

- [ ] **Step 1: Write failing parser, relay, and resolution tests**

Cover all three round trips; unknown version, malformed entity, 16,385-character fragment, and over-5,000-character entity rejection before network activity; maximum eight distinct normalized hints; credentials/query/fragment rejection; localhost, single-label, `.local`, `.internal`, private/link-local/loopback/documentation/benchmark/multicast IP rejection; onion-only-through-Tor; and all six terminal outcomes.

- [ ] **Step 2: Run RED**

Run the new test file. Expected: module-not-found failure.

- [ ] **Step 3: Implement parser and resolution semantics**

Parse the complete fragment before returning any network plan. Strip the origin entirely from the semantic input so tests can prove that persona/event/address identifiers are absent from the HTTP request path. Refresh NIP-65 after hints, require canonical Tier 1 feed reachability for canonical presentation, allow explicitly labeled unindexed signed events, and return `private` for Tier 2 or Tier 3.

- [ ] **Step 4: Run GREEN**

Expected: every boundary and terminal outcome passes with hand-authored literals.

- [ ] **Step 5: Amend Comms**

Add permanent anchors for `comms.public-reader.v1`, universal launcher grammar, local public resolution, anonymous-to-authenticated transition, launcher/content security, and public-reader conformance. State that the static host is never authority and that a non-Tor browser is account-anonymous but not network-anonymous. Add `COMMS-I-PUBLIC-READER-TIER1-ONLY`.

- [ ] **Step 6: Author vectors and commit**

Generate launcher, SSRF, NIP-65 refresh, resolution, Tier refusal, external-media disclosure, transition-without-reload, logout cleanup, and failed-revocation expiry vectors. Commit after focused and verify checks:

```bash
git add docs/spec/heterodyne-comms.md docs/spec/releases/comms docs/spec/vectors
git commit -m "spec: define the public reader and universal launcher"
```

### Task 4: Comms Agent Delegation, Workload Claims, Tokens, and Attribution

**Files:**
- Create: `docs/spec/schemas/comms/agent-workload-registration-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Create: `docs/spec/vectors/generator/src/agent-authorship.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-agent-authorship.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.test.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Consumes: Core role delegation, active claim-ledger replay, RFC 9068 projection, token status, and normal Comms publication.
- Produces:

```ts
export function validateAgentDelegation(input: AgentDelegationInput): AgentDelegationResult;
export function validateWorkloadRegistration(value: unknown): WorkloadRegistration;
export function deriveAgentIdentity(localSubject: string, sectorIdentifier: string, pairwiseSecretHex: string, issuer: string, clientId: string): { issuer: string; sub: string; client_id: string };
export function validateAgentAccessToken(input: AgentTokenValidationInput): AgentTokenDecision;
export function injectAgentAttribution(input: AgentPublicationInput): AgentPublicationResult;
```

- [ ] **Step 1: Add failing schema and behavior tests**

Test the exact dual proof bytes:

```text
heterodyne-agent-signing-binding-v1|<cold-root-hex>|<nid>|<role-id>|<publishing-key>
```

Require the outer epoch signature, NID Ed25519 proof, agent-key BIP-340 proof, current KEL authority, valid role address, expiry, and repo finality. Test stable subject renewal, cross-persona unlinkability, one-role registration, finite limits, exact audience/scope, five-minute maximum, `cnf.jkt`, status, and role-claim mismatch.

- [ ] **Step 2: Run RED**

Run the agent and OIDC focused tests. Expected: missing schema/functions and absent agent-role claim support.

- [ ] **Step 3: Implement schema and semantic model**

The workload schema is closed and requires `client_id`, `subject_jkt`, class `ai|programmatic`, `role_id`, one audience, non-empty scopes, allowed kinds/feeds/resources, `max_content_bytes`, positive finite rate window/count/burst, validity interval, and optional software-claim reference. Reject an empty or unlimited bound. `deriveAgentIdentity` MUST call the existing `derivePairwiseSubject(localSubject, sectorIdentifier, pairwiseSecretHex)` algorithm rather than defining a second subject formula.

Token validation requires `typ: at+jwt`, all RFC 9068 claims, one exact audience, normalized scope, current status, ledger/status bindings, `cnf.jkt`, and `https://heterodyne.network/jwt/agent-role-id`. It cannot outlive session, delegation, registration, consent, or source authorization and never returns a refresh token.

Attribution injection removes all caller-provided reserved tags, inserts:

```ts
[
  ["L", "network.heterodyne.agent"],
  ["l", agentClass, "network.heterodyne.agent"],
  ["heterodyne_agent", "v1", issuer, subject, clientId, roleId],
  ["agent_action", "publish"],
]
```

and optionally appends a verified `agent_review` marker. It rejects kinds outside the eight active profiles. Tier 3 returns the tags only in the encrypted logical event.

- [ ] **Step 4: Run GREEN**

Expected: delegation, registration, token, attribution, tier placement, multiple-role, same-role replacement, and unchanged-epoch tests pass.

- [ ] **Step 5: Amend Comms**

Define the non-stamping agent-signing profile, private workload claim, stable identity tuple, Control/DR token projection, token-to-role binding, public attribution, maintenance exclusions, and fail-closed verification. Add the four Comms agent invariants without making Comms depend on Control. Preserve `heterodyne-comms-strict-v1` byte-for-byte and add `heterodyne-comms-strict-v2`, which composes Core strict v1 and includes every revision-3 Comms invariant.

- [ ] **Step 6: Author vectors and commit**

Cover every ADR-036 Comms requirement, remove covered pending profile IDs, author/verify the corpus, and commit:

```bash
git add docs/spec/schemas/comms docs/spec/heterodyne-comms.md docs/spec/vectors
git commit -m "spec: define scoped agent authorship in Comms"
```

### Task 5: Control Relay Affinity and Automated-Agent Requirements

**Files:**
- Create: `docs/spec/schemas/control/control-rpc-request-v1.schema.json`
- Create: `docs/spec/schemas/control/control-rpc-response-v1.schema.json`
- Create: `docs/spec/schemas/control/control-agent-token-request-v1.schema.json`
- Create: `docs/spec/schemas/control/control-agent-publish-v1.schema.json`
- Create: `docs/spec/schemas/control/control-audit-record-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/control-profile.ts`
- Create: `docs/spec/vectors/generator/src/control-profile.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-control.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Consumes: authenticated Comms DR session, active Comms authorization decision, valid agent token decision, and Comms publication intent.
- Produces:

```ts
export type RequestReservation = {
  session_id: string; request_id: string; method: string;
  payload_digest: string; first_ingress_relay: string;
  state: "reserved" | "complete"; response?: unknown;
};
export function acceptControlRequest(input: ControlRequestInput, prior?: RequestReservation): ControlRequestDecision;
export function routeControlResponse(decision: ControlRequestDecision): string;
export function authorizeAgentMethod(input: AgentMethodInput): AgentMethodDecision;
```

- [ ] **Step 1: Write failing replay/affinity and refusal tests**

Test atomic first arrival, concurrent identical join, response-first-and-only to canonical ingress relay, identical retry through a new relay returning the cached result without re-execution, changed method/payload rejection, final-response persistence before replay, and restart recovery. Test refusal of `sign_event`, key access, human publication, missing/expired/wrong token, proof mismatch, forbidden kind/resource/size/rate/burst, and attribution bypass.

- [ ] **Step 2: Run RED**

Expected: missing Control module and schemas.

- [ ] **Step 3: Implement closed schemas and semantic model**

Every request binds version, session, request ID, method, payload, payload digest, expiry, and authenticated ingress relay. `reply_relay` is forbidden. Agent token requests bind challenge, workload proof, requested scope/resource/expiry. Agent publication accepts intent fields only and forbids signature/pubkey/attribution authority fields. Audit records retain token `jti` but not the raw token.

- [ ] **Step 4: Run GREEN**

Expected: all idempotency, routing, restart, expiry, and automated-agent refusal paths pass.

- [ ] **Step 5: Amend Control**

Add a prominent permanent anchor titled “Requirements for automated agents” with the mandatory refusal language. Define ingress-relay affinity, restart-safe replay, token issuance over DR, per-use sender proof, intent-only publication, limit enforcement, and encrypted audit. Add the four new Control invariants.

Keep the document’s overall status and `can_claim_control_conformance: false`; replace the generic blocker list with explicit remaining ADR-030 integration blockers while stating that ADR-035/036 subsets are normative and vectored. Preserve reserved `heterodyne-control-strict-v1` and add reserved-inactive `heterodyne-control-strict-v2`, composing Comms strict v2 and the new Control invariants.

- [ ] **Step 6: Author Control vectors and commit**

Update coverage rendering so Control lists the integrated ADR-035/036 subset vectors while retaining the incomplete-draft banner. Commit:

```bash
git add docs/spec/schemas/control docs/spec/heterodyne-control.md docs/spec/vectors
git commit -m "spec: integrate relay-affine agent Control subsets"
```

### Task 6: Social Receipts, Policy Lists, and Key-Scoped Remediation

**Files:**
- Create: `docs/spec/schemas/social/agent-policy-receipt-v1.schema.json`
- Create: `docs/spec/schemas/social/agent-policy-correction-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/agent-moderation.ts`
- Create: `docs/spec/vectors/generator/src/agent-moderation.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-agent-moderation.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/heterodyne-social.md`

**Interfaces:**
- Consumes: Core/Comms verification of offending event, device key, role delegation, and policy persona; no Control input.
- Produces:

```ts
export function validateAgentPolicyReceipt(event: NostrSignedEvent): AgentPolicyReceipt;
export function validateAgentPolicyList(event: NostrSignedEvent, receipts: ReadonlyMap<string, AgentPolicyReceipt>): AgentPolicyList;
export function applySubscribedAgentPolicy(input: AgentPolicyInput): AgentPolicyDecision;
export function applyAgentPolicyCorrection(input: AgentCorrectionInput): AgentPolicyDecision;
```

- [ ] **Step 1: Write failing receipt/list tests**

Test exact `L`, `l`, one `e`, and one `p`; the closed content schema; all three reason codes; token/secret/private-claim leakage rejection; exact `p` + `e` + `agent_violation` binding; subscribed versus unsubscribed behavior; visible/removable default subscription; relay-only/PR candidate no-effect; old-key mute/new-key acceptance; and correction receipt plus canonical list removal.

- [ ] **Step 2: Run RED**

Expected: missing Social module and schemas.

- [ ] **Step 3: Implement receipt and policy semantics**

Receipt content requires profile/version, event, device key, cold root, reason, observation time, evidence references/digests, explanation, and remediation `rotate-device-key`. Policy application verifies current canonical repo history and mutes exactly the listed device key. Rotation accepts a replacement at the same role address without epoch rotation. Correction requires a signed correction/retraction receipt and current canonical list removal.

- [ ] **Step 4: Run GREEN**

Expected: exact binding, local-policy, rotation, and correction cases pass.

- [ ] **Step 5: Amend Social**

Add agent-policy receipt and list anchors, state that receipts inform but do not mute, define subscriber-local enforcement and transparent default subscriptions, and prohibit global authority. Add the two Social invariants. Preserve both Social v1 strict profiles and add `heterodyne-social-strict-v2` plus `heterodyne-social-matrix-strict-v2` with the revision-3 invariant membership.

- [ ] **Step 6: Author vectors and commit**

Cover both Social registry profiles, remove their pending IDs, author/verify, and commit:

```bash
git add docs/spec/schemas/social docs/spec/heterodyne-social.md docs/spec/vectors
git commit -m "spec: define subscriber-local agent moderation"
```

### Task 7: Companion Guidance, Threat Model, and Acceptance Evidence

**Files:**
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `docs/spec/heterodyne.md`
- Modify: `docs/architecture.md`
- Modify: `docs/glossary.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/superpowers/specs/2026-07-30-agent-authorship-oidc-moderation-design.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.ts`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: permanent anchors, registry digest, vector IDs, and invariant IDs from Tasks 1–6.
- Produces: agent-facing refusal guidance and auditable ADR-035/036 acceptance-evidence tables.

- [ ] **Step 1: Write failing family-document tests**

Add structural tests that parse acceptance-evidence tables for ADR-035 and ADR-036, verify every cited anchor/profile/vector/invariant exists, verify every document and release manifest pins revision 3, and verify AGENTS links to `heterodyne:control/0.5.0#control-automated-agents`.

- [ ] **Step 2: Run RED**

Expected: missing evidence tables, stale design status, and absent agent-guidance link.

- [ ] **Step 3: Update companion documents**

Change the design record status to `Approved`. Add the direct automated-agent requirements link and one concise hard rule to AGENTS. Update the family map, architecture, and glossary for role-scoped clients, launcher addresses, outbound Tor, agent identity, role keys, workload tokens, attribution, receipts, and subscriber-local policy lists.

Extend the threat model with browser clearnet metadata, malicious relay hints, hosted-JavaScript supply chain, onion downgrade, ingress-relay correlation, workload token theft, full-node attribution lies, agent spam, false moderation receipts, default-list capture, and scoped role-key remediation.

- [ ] **Step 4: Add acceptance evidence**

Create separate ADR-035 and ADR-036 tables mapping each accepted criterion to the ADR section, permanent normative anchor, revision-3 allocation, vector, and invariant. Keep them as audit indexes, not a second normative source.

- [ ] **Step 5: Run GREEN and commit**

Run the focused docs lint and `family:check`, then commit:

```bash
git add AGENTS.md CLAUDE.md docs
git commit -m "docs: connect public-client and agent security guidance"
```

### Task 8: Close Coverage, Regenerate Artifacts, and Verify the Family

**Files:**
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: generated files under `docs/spec/vectors/`
- Modify: `docs/spec/releases/{core,comms,control,social}/0.5.0.json`
- Modify: `docs/spec/registry/history/3.json`
- Modify: `docs/spec/registry/manifest.json`

**Interfaces:**
- Consumes: all implemented profiles and authored vectors.
- Produces: zero pending active profiles, consistent generated artifacts, clean conformance checks, and review-ready commits.

- [ ] **Step 1: Remove completed pending-profile exceptions**

Make `PENDING_PROFILE_IDS` empty. Keep only the still-inactive `heterodyne-control-session-device-v1` exception unless this patch’s accepted lower-layer amendments and vectors are sufficient to activate that exact profile; because ADR-030 remains Proposed, default to keeping it inactive.

- [ ] **Step 2: Run the coverage gate**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/coverage.test.ts
```

Expected: PASS with no uncovered active revision-3 profile.

- [ ] **Step 3: Regenerate all artifacts**

Run:

```bash
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run release-manifests
```

Recompute the registry digest after the final entry set, refresh `history/3.json`, manifest, schema pin, and release manifests, then rerun generation once so every vector and manifest carries the final revision/digest.

- [ ] **Step 4: Run complete verification**

Run:

```bash
git diff --check
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

Expected: TypeScript build passes, every test passes, every authored vector verifies, all anchors and dependency edges validate, and no generated file differs from a fresh generation.

- [ ] **Step 5: Review requirements and commit**

Re-read ADR-035 §9–§10 and ADR-036 §9 line by line; map each requirement to a normative anchor and vector or implementation-evidence statement. Confirm Social has no Control dependency, Core contains no OIDC/agent/moderation semantics, no raw token appears in a public fixture, and no Tor downgrade is silent.

```bash
git add .
git commit -m "test: complete ADR-035 and ADR-036 conformance"
```

- [ ] **Step 6: Publish for ADR implementation review**

Push `agent/integrate-adrs-035-036`, open a draft PR against latest `main`, and post the PR URL. Do not merge the implementation PR without explicit review approval.
