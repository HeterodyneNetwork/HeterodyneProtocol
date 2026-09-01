# Final Security Evidence Prerequisites Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace caller-asserted security evidence with real opaque authority boundaries, retire obsolete diagnostics, author registry revision 17 once, and finish the paused Task 10 semantic-certificate closure.

**Architecture:** Each protocol family receives narrowly scoped verifier-minted authorities over exact captured bytes, authenticated current state, and durable consuming stores. Prerequisite tasks land runtime boundaries, normative prose, and focused tests without touching the five paused Task 10 files; after semantics stabilize, one registry task authors immutable revision 17, and one final Task 10 task performs all current-vector, dispatcher, predicate, and certificate wiring.

**Tech Stack:** TypeScript, Vitest, Node.js `crypto`, existing Nostr/NIP-44/OIDC/Workspace evaluators, JSON Schema, JCS-authored registry manifests.

**Spec:** `docs/superpowers/specs/2026-08-31-final-security-evidence-prerequisites-design.md`

## Global Constraints

- Work only in `.worktrees/pr28-protocol-closure` on `fix/pr28-protocol-closure`; preserve unrelated and untracked files.
- Preserve the uncommitted Task 10 work in `current-vectors/{boundary-runners.ts,case-contracts.ts,index.ts,semantic-certificates.test.ts,semantic-certificates.ts}`. Tasks 1–14 must neither modify nor stage these files; Task 15 owns their integration and commit.
- Every behavior change follows strict RED → observed expected failure → minimal GREEN → focused regression → `build:current`.
- Every hostile test is labeled `BLUE TEAM VALIDATION: synthetic/local`, uses deterministic non-deployable fixtures, and contacts no live relay, Radicle node, Marmot deployment, identity provider, account, credential, user data, third-party system, or external service.
- `AuthorityDecision`, durable-store state, binding-digest helpers, and the reference consuming algorithm are defined only in `security-authority-support.ts`; Tasks 3–13 import them instead of declaring family-local variants. `MarmotAdmissionDecision` is `AuthorityDecision<"conversation-rejected", VerifiedMarmotAdmission>`.
- Opaque public handles are frozen empty objects backed by module-private `WeakMap` records. Plain objects, clones, proxies, accessors, cross-authority handles, stale views, and post-capture mutations fail closed.
- Consuming boundaries use caller-independent durable acquire/CAS state with `available`, `executing`, `committed`, and `indeterminate` behavior; exact committed retries return byte-identical cached output and unknown post-effect outcomes never repeat the effect.
- No public security input may be a caller assertion named `valid`, `authorized`, `canonical`, `current`, `unused`, `durable`, `subscribed`, or `effect_applied`.
- Agent publication authorization and signing are one exported atomic operation; no caller-consumable authorize-now/sign-later capability is permitted.
- The root Workspace role's `allowed_capabilities` is the workspace-wide ceiling.
- The six live invariant gaps are exactly `COMMS-I-MARMOT-ACCOUNT-IDENTITY`, `COMMS-I-MARMOT-SECRET-CONFINEMENT`, `COMMS-I-RADICLE-NON-ERASURE`, `WORKSPACE-I-CARRIER-NOT-AUTHORITY`, `WORKSPACE-I-INHERITANCE-NARROWS`, and `WORKSPACE-I-NO-AMBIENT-AUTHORITY`.
- The 11 retired reasons are exactly `revoked_key_post_compromise`, `retired-key-authority-window-invalid`, `dm_invite_revoked_device`, `dm_invite_unbound_device`, `agent-attribution-bypass-prohibited`, `agent-human-profile-prohibited`, `agent-key-access-prohibited`, `agent-method-prohibited`, `agent-resource-denied`, `control-request-id-conflict`, and `control-signed-event-invalid`.
- The one diagnostic-only reason is exactly `auth_rejected_permanent`.
- The 28 live reasons that require real evidence are exactly `agent-sender-proof-invalid`, `conversation-rejected`, `invite-authentication-invalid`, `marmot-agent-scope-denied`, `marmot-keypackage-replayed`, `marmot-premature-ack`, `marmot-private-inbox-nid-required`, `control-compromise-reset-evidence-invalid`, `control-compromise-reset-inventory-mismatch`, `control-compromise-reset-unauthenticated`, `control-subordinate-reauthorization-required`, `control-device-code-display-mismatch`, `control-device-code-invalid`, `control-device-code-rate-limited`, `control-enrollment-unavailable`, `control-frame-invalid`, `invite-preauthorization-invalid`, `control-keypackage-invalid`, `control-keypackage-replenishment-paused`, `control-signer-effect-indeterminate`, `control-token-invalid`, `capability_escalation`, `policy_denied`, `workspace_replay`, `profile-repository-selection-required`, `relay_profile_mutation`, `strict_mode_tor_disabled`, and `unauthorized_cache_content`.
- The five positive replacements are exactly `comms/agent-workload-token-accepted`, `comms/marmot-exact-bytes-durable`, `comms/marmot-expiration-not-erasure`, `comms/marmot-ordinary-welcome-held`, and `workspace/current-capability-intersection`.
- Registry revision 16 and older history remain byte-identical. Tasks 1–13 do not edit registry JSON; Task 14 authors immutable revision 17 exactly once after all semantics and anchors settle.
- Generated rolling snapshot files, `snapshot.json`, projections, counts, baselines, and digests remain untouched. Snapshot reconciliation is deferred.
- ADR-048 remains `Proposed`. Do not merge, push, create/update a PR, tag, publish, release, deploy, alter repository-host settings, or mutate live infrastructure.

---

## Exact local authority contracts and RED patterns

Task 2 creates the only shared authority support surface. Use these exact types;
all later authority modules import them from `./security-authority-support.js`:

```ts
export type IndeterminateDecision<I extends string = never> = Readonly<
  [I] extends [never]
    ? { verdict: "indeterminate"; reconciliation_digest: string }
    : { verdict: "indeterminate"; reason_code: I; reconciliation_digest: string }
>;
export type AuthorityDecision<R extends string, O, I extends string = never> = Readonly<
  | { verdict: "accept"; output: O }
  | { verdict: "reject"; reason_code: R }
  | IndeterminateDecision<I>
>;

export type DurableAuthorityRecord<O> = Readonly<
  | { state: "available"; revision: number; binding_digest: string; output: O }
  | { state: "executing"; revision: number; binding_digest: string; execution_token: string }
  | { state: "committed"; revision: number; binding_digest: string; execution_token: string;
      output_digest: string; output: O }
  | { state: "indeterminate"; revision: number; binding_digest: string; execution_token: string;
      reconciliation_digest: string }
>;

export interface DurableAuthorityStore<O> {
  load(key: string): Promise<DurableAuthorityRecord<O> | null>;
  acquire(input: Readonly<{
    key: string; expected_revision: number | null;
    binding_digest: string; execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable">;
  compareAndSwap(input: Readonly<{
    key: string; expected_revision: number | null; next: DurableAuthorityRecord<O>;
  }>): Promise<"committed" | "conflict" | "unknown">;
  commit(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    output_digest: string; output: O;
  }>): Promise<"committed" | "conflict" | "unknown">;
  markIndeterminate(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown">;
}

export function authorityBindingDigest(
  domain: string,
  value: Readonly<Record<string, unknown>>,
): string;
export function captureAuthorityInput<T>(value: T): Readonly<T>;
```

`captureAuthorityInput` accepts only closed data trees with ordinary data
properties, arrays, byte arrays, and `null`; it descriptor-walks before reading,
copies bytes, deep-freezes the copy, and throws on proxies, accessors, symbols,
cycles, non-finite numbers, or unsupported prototypes. Each constructor reads
and binds callback descriptors once. Each consuming function follows this exact
order: capture, verify, load current state, derive full binding/key/token,
`acquire`, perform one effect, `commit`, re-read binding-equal terminal, return.
Thrown effects, unknown effect outcomes, or unknown/conflicting terminal writes
call `markIndeterminate`; they never retry the effect.

The following contracts and RED bodies are normative implementation details for
Tasks 2–13. Fixture constants use deterministic local keys/bytes from the
owning test file; no fixture performs network I/O.
Each new test file begins with
`import { describe, expect, it } from "vitest";` and imports the exact symbols
shown in its contract block from the adjacent `.js` production module.

### Task 2 exact contract and RED

```ts
export type MarmotAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<VerifiedMarmotAdmission>;
  load_conversation: (account: string, group_id: string) => Promise<Readonly<{
    checkpoint: string; state: "unseen" | "held" | "accepted" | "rejected";
  }>>;
  verify_key_package: (bytes: Uint8Array) => Readonly<{
    account: string; leaf_key: string; capabilities: readonly string[];
  }> | null;
}>;
export type MarmotWelcomeInput = Readonly<{
  welcome_bytes: Uint8Array; key_package_bytes: Uint8Array;
  inviter_account: string; recipient_account: string; group_id: string;
  member_accounts: readonly [string, string]; required_capabilities: readonly string[];
}>;
export type MarmotAdmissionAcceptance = Readonly<{
  decision: "accept" | "hold" | "reject"; expected_checkpoint: string;
}>;
export type VerifiedMarmotAdmission = Readonly<{
  group_id: string; checkpoint: string; terminal: "accepted" | "held";
}>;
export type VerifiedMarmotWelcome = Readonly<Record<never, never>>;
export type MarmotAdmissionDecision = AuthorityDecision<
  "conversation-rejected", VerifiedMarmotAdmission
>;
export type MarmotWelcomeDecision = AuthorityDecision<
  "conversation-rejected", VerifiedMarmotWelcome
>;
export function createMarmotAdmissionAuthority(
  config: MarmotAdmissionAuthorityConfig,
): MarmotAdmissionAuthority;
export function verifyMarmotWelcome(
  authority: MarmotAdmissionAuthority,
  input: MarmotWelcomeInput,
): MarmotWelcomeDecision;
export function admitOrdinaryMarmotWelcome(
  authority: MarmotAdmissionAuthority,
  welcome: VerifiedMarmotWelcome,
  acceptance: MarmotAdmissionAcceptance,
): Promise<MarmotAdmissionDecision>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local rejects a caller-shaped Welcome", async () => {
  const authority = createMarmotAdmissionAuthority(admissionConfig());
  const fake = Object.freeze({});
  await expect(admitOrdinaryMarmotWelcome(
    authority, fake as VerifiedMarmotWelcome,
    { decision: "accept", expected_checkpoint: CHECKPOINT },
  )).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  expect(admissionStore.effectCalls).toBe(0);
});
```

`verifyMarmotWelcome` captures both byte arrays, verifies their cryptographic
and schema bindings, then mints `Object.freeze({})` into a private `WeakMap`.
`admitOrdinaryMarmotWelcome` accepts only that exact handle and returns accept
only after a binding-equal committed record is readable.

### Task 3 exact contract and RED

```ts
export type MarmotArchiveRetentionAuthorityConfig = Readonly<{
  authority_id: string;
  store: DurableAuthorityStore<Readonly<{
    repository_rid: string; ref: string; object_digest: string;
    source_digest: string; commit: string;
  }>>;
  resolve_writer: (rid: string, ref: string) => Promise<CurrentRepositoryWriterBinding>;
  append_and_resolve: (input: Readonly<{
    repository_rid: string; ref: string; bytes: Uint8Array;
  }>) => Promise<Readonly<{ object_digest: string; commit: string; reachable: boolean }>>;
}>;
export type MarmotArchiveInput = Readonly<{
  repository_rid: string; ref: string;
  source: Readonly<{ kind: "signed-event"; event: NostrSignedEvent;
      event_bytes: Uint8Array } |
    { kind: "encrypted-media"; ciphertext: Uint8Array;
      authorization_event: NostrSignedEvent }>;
}>;
export type MarmotArchiveAppendReceipt = Readonly<Record<never, never>>;
export type MarmotArchiveReceiptData = Readonly<{
  repository_rid: string; ref: string; object_digest: string;
  source_digest: string; commit: string;
}>;
export type MarmotArchiveDecision = AuthorityDecision<
  "marmot-premature-ack", MarmotArchiveAppendReceipt
>;
export function createMarmotArchiveRetentionAuthority(
  config: MarmotArchiveRetentionAuthorityConfig,
): MarmotArchiveRetentionAuthority;
export function appendExactMarmotArchive(
  authority: MarmotArchiveRetentionAuthority,
  input: MarmotArchiveInput,
): Promise<MarmotArchiveDecision>;
export function acknowledgeMarmotArchive(
  authority: MarmotArchiveRetentionAuthority,
  receipt: MarmotArchiveAppendReceipt,
): Promise<AuthorityDecision<"marmot-premature-ack", MarmotArchiveReceiptData>>;
export function expireMarmotPresentation(
  authority: MarmotArchiveRetentionAuthority,
  receipt: MarmotArchiveAppendReceipt,
): Promise<AuthorityDecision<"marmot-premature-ack", MarmotArchiveReceiptData>>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local forbids acknowledgement before durable reachability", async () => {
  const authority = createMarmotArchiveRetentionAuthority(archiveConfig({ reachable: false }));
  const appended = await appendExactMarmotArchive(authority, archiveInput());
  expect(appended).toMatchObject({ verdict: "indeterminate" });
  await expect(acknowledgeMarmotArchive(
    authority, Object.freeze({}) as MarmotArchiveAppendReceipt,
  )).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
  expect(archiveStore.ackCalls).toBe(0);
});
```

The append implementation recomputes signed-event ID/signature or binds media
ciphertext to its verified authorization event, checks the writer, appends the
captured bytes, compares returned object digest, and mints a receipt only for
`reachable: true`. Expiration changes presentation state and then reloads the
same object/commit; it never calls a delete operation.

### Task 4 exact contracts and RED

```ts
export type PersonaInboxAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ group_id: string; key_package_ref: string }>>;
  load_inbox: (recipient: string) => Promise<Readonly<{
    checkpoint: string; recipient_nid: string | null;
    consumed_key_packages: readonly string[]; allowed_agent_scopes: readonly string[];
  }>>;
}>;
export type PersonaInboxBundle = Readonly<{
  recipient: string; sender: string; sender_kind: "persona" | "agent";
  sender_ref: string; purpose: "marmot-first-contact";
  required_agent_scope: string | null; key_package_bytes: Uint8Array;
  key_package_ref: string; group_transition: Uint8Array;
}>;
export type OneTimeInviteAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ group_id: string; response_digest: string }>>;
  load_invite_state: (invite_id: string) => Promise<Readonly<{
    state: "active" | "revoked"; revision: number;
  }>>;
  establish_group: (bytes: Uint8Array, execution_token: string) => Promise<Readonly<{
    group_id: string; response_digest: string;
  }>>;
}>;
export type OneTimeInviteRedemption = Readonly<{
  envelope: InviteEnvelope; response_bytes: Uint8Array; response_purpose: InvitePurpose;
  recipient: string; key_package_bytes: Uint8Array; group_transition: Uint8Array;
}>;
export type PersonaInboxAdmission = Readonly<{ group_id: string; key_package_ref: string }>;
export function createPersonaInboxAdmissionAuthority(
  config: PersonaInboxAdmissionAuthorityConfig,
): PersonaInboxAdmissionAuthority;
export function admitPersonaInboxBundle(
  authority: PersonaInboxAdmissionAuthority,
  bundle: PersonaInboxBundle,
): Promise<AuthorityDecision<
  "marmot-agent-scope-denied" | "marmot-keypackage-replayed" |
    "marmot-private-inbox-nid-required",
  PersonaInboxAdmission
>>;
export function createOneTimeInviteAuthority(
  config: OneTimeInviteAuthorityConfig,
): OneTimeInviteAuthority;
export function redeemOneTimeInvite(
  authority: OneTimeInviteAuthority,
  input: OneTimeInviteRedemption,
): Promise<AuthorityDecision<"invite-authentication-invalid", Readonly<{
  group_id: string; response_digest: string;
}>>>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local burns one KeyPackage under concurrent admission", async () => {
  const authority = createPersonaInboxAdmissionAuthority(inboxConfig());
  const [left, right] = await Promise.all([
    admitPersonaInboxBundle(authority, inboxBundle()),
    admitPersonaInboxBundle(authority, inboxBundle()),
  ]);
  expect([left, right].filter((x) => x.verdict === "accept")).toHaveLength(1);
  expect([left, right].filter((x) => x.verdict === "reject"))
    .toEqual([{ verdict: "reject", reason_code: "marmot-keypackage-replayed" }]);
});
```

`redeemOneTimeInvite` independently verifies the descriptor signature, secret
commitment, response proof, recipient/purpose/expiry/revocation, KeyPackage,
and group bytes before acquire. Exact committed retries read cached output;
changed transcript, recipient, purpose, or secret returns
`invite-authentication-invalid`.

### Task 5 exact contract and RED

```ts
export type AgentPublicationAuthorizationAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  expected_issuer: string; expected_audience: string; jwks: JsonValue;
  load_claim_view: () => Promise<CurrentClaimAuthorizationView>;
  load_status: (subject: string) => Promise<Readonly<{
    generation: number; state: "active" | "revoked"; checkpoint: string;
  }>>;
  consume_dpop: (proof: Readonly<{
    compact: string; method: string; target: string; nonce: string;
  }>) => Promise<Readonly<{
    proof_digest: string; sender_key: string;
  }> | null>;
  read_mtls_peer_identity: () => string | null;
  store: DurableAuthorityStore<NostrSignedEvent>;
  sign_once: (execution_token: string, event: NostrUnsignedEvent) => Promise<NostrSignedEvent>;
}>;
export type AgentPublicationRequest = Readonly<{
  compact_jwt: string; represented_persona: string; agent_id: string;
  signer: string; scope: string; ledger_generation: number;
  publication: NostrUnsignedEvent; attribution_profile: "heterodyne-agent-v1";
  sender_proof: Readonly<{ kind: "dpop"; compact: string; method: string;
    target: string; nonce: string }> | Readonly<{ kind: "mtls" }>;
}>;
export type AgentPublicationDecision = AuthorityDecision<
  "agent-sender-proof-invalid" | "agent-signer-mismatch", NostrSignedEvent
>;
export function createAgentPublicationAuthorizationAuthority(
  config: AgentPublicationAuthorizationAuthorityConfig,
): AgentPublicationAuthorizationAuthority;
export function authorizeAndSignAgentPublication(
  authority: AgentPublicationAuthorizationAuthority,
  request: AgentPublicationRequest,
): Promise<AgentPublicationDecision>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local never exposes authorize-then-sign", async () => {
  expect(Object.keys(await import("./agent-publication-authorization.js")))
    .not.toContain("VerifiedAgentPublicationAuthorization");
  const result = await authorizeAndSignAgentPublication(
    createAgentPublicationAuthorizationAuthority(agentConfig()),
    agentRequest({ sender_proof: replayedDpop() }),
  );
  expect(result).toEqual({ verdict: "reject", reason_code: "agent-sender-proof-invalid" });
  expect(agentFixture.signerCalls).toBe(0);
});
```

The function validates the real compact JWT, proof, current status/generation,
claim view, exact publication, signer, and attribution in one call. Its internal
authorization handle is minted and consumed without crossing the exported API.

### Task 6 exact contract and RED

```ts
export type CurrentControlFrameVerificationContext = Readonly<{
  expected_profile: string; expected_version: string; expected_group_id: string;
  expected_sender: string; expected_request_digest: string; trusted_now: number;
}>;
export type CurrentControlFrameDecision = AuthorityDecision<"control-frame-invalid", Readonly<{
  event_id: string; request_id: string; request_digest: string;
}>>;
export function validateCurrentControlFrameProfile(
  frame_bytes: Uint8Array,
  context: CurrentControlFrameVerificationContext,
): CurrentControlFrameDecision;
export type ControlResetEvidenceFixture = Readonly<{
  input: Parameters<typeof validateCompromiseReset>[0];
  expected_reason: "control-compromise-reset-evidence-invalid" |
    "control-compromise-reset-inventory-mismatch" |
    "control-compromise-reset-unauthenticated" |
    "control-subordinate-reauthorization-required";
}>;
export type ControlSignerEvidenceFixture = Readonly<{
  input: Parameters<typeof executePersistedAutomatedSigning>[0];
  expected_reason: "control-signer-effect-indeterminate";
}>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local rejects a signed frame rebound to another request", () => {
  const bytes = signedControlFrameBytes({ request_digest: REQUEST_A });
  expect(validateCurrentControlFrameProfile(bytes, frameContext({
    expected_request_digest: REQUEST_B,
  }))).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
});
```

The function parses UTF-8 JSON once, requires a closed NIP-01 event and closed
Control payload, verifies ID/signature/profile/version/group/sender/time, and
compares the request digest. Reset and signer fixtures directly retain the
actual inputs/results of `validateCompromiseReset` and
`executePersistedAutomatedSigning`; their adapters contain no validity fields.

### Task 7 exact contract and RED

```ts
export type ControlDeviceAuthorizationAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  random_bytes: (length: number) => Uint8Array;
  store: DurableAuthorityStore<Readonly<{
    transaction_id: string; state: "pending" | "approved" | "denied" | "expired";
  }>>;
}>;
export type ControlDeviceTransactionRequest = Readonly<{
  client_id: string; persona: string; verification_uri: string;
  display_fingerprint: string; polling_interval_seconds: number;
  expires_in_seconds: number; failure_budget: 5;
}>;
export type ControlDevicePollRequest = Readonly<{
  device_code: string; user_code: string; displayed_fingerprint: string;
}>;
export type ControlDeviceTransaction = Readonly<{
  transaction_id: string; device_code: string; user_code: string;
  verification_uri: string; expires_at: number; interval_seconds: number;
}>;
export type ControlDeviceDecision = AuthorityDecision<
  "control-device-code-invalid" | "control-device-code-rate-limited" |
    "control-device-code-display-mismatch",
  Readonly<{ transaction_id: string; state: "pending" | "approved" }>
>;
export function createControlDeviceAuthorizationAuthority(
  config: ControlDeviceAuthorizationAuthorityConfig,
): ControlDeviceAuthorizationAuthority;
export function createControlDeviceTransaction(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDeviceTransactionRequest,
): Promise<AuthorityDecision<"control-device-code-invalid", ControlDeviceTransaction>>;
export function pollControlDeviceAuthorization(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDevicePollRequest,
): Promise<ControlDeviceDecision>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local atomically invalidates the fifth bad code", async () => {
  const authority = createControlDeviceAuthorizationAuthority(deviceConfig());
  const created = await createControlDeviceTransaction(authority, deviceRequest());
  expect(created.verdict).toBe("accept");
  if (created.verdict !== "accept") throw new Error("synthetic transaction rejected");
  const tx = created.output;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    expect(await pollControlDeviceAuthorization(authority, badPoll(tx)))
      .toMatchObject({ verdict: "reject", reason_code: "control-device-code-invalid" });
  }
  expect((await deviceStore.load(tx.transaction_id))?.state).toBe("committed");
  expect(deviceStore.output.state).toBe("denied");
});
```

Transaction creation hashes stored codes, enforces at least 128 device-code
bits and 34.5 user-code bits, and persists interval, rate, failure, display,
expiry, client, and persona bindings. Polling changes them only by atomic store
transition.

### Task 8 exact contract and RED

```ts
export type ControlEnrollmentAdmissionAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ enrollment_id: string; group_id: string }>>;
  load_inventory: (persona: string) => Promise<Readonly<{
    revision: number; pending_for_account: number; global_pending: number;
    global_pending_cap: number; reserved_slots: readonly string[];
    replenishment_state: "ready" | "paused"; current_clients: readonly string[];
    enrolled_accounts: readonly string[]; enrolled_devices: readonly string[];
    rate_window_started_at: number; attempts_in_window: number; attempt_budget: number;
  }>>;
  load_invite_state: (invite_id: string) => Promise<Readonly<{
    revision: number; purpose: "control-enrollment"; state: "active" | "revoked" | "consumed";
    account: string; client_key: string; expires_at: number;
  }>>;
  verify_key_package: (bytes: Uint8Array) => Readonly<{
    account: string; reference: string; expires_at: number;
  }> | null;
}>;
export type ControlEnrollmentAdmissionRequest = Readonly<{
  persona: string; account: string; device_id: string; client_key: string; group_id: string;
  invite_id: string; invite_purpose: "control-enrollment";
  key_package_bytes: Uint8Array; expected_key_package_ref: string;
  reserved_slot: string | null;
}>;
export type ControlEnrollmentAdmissionDecision = AuthorityDecision<
  "control-enrollment-unavailable" | "control-keypackage-invalid" |
    "control-keypackage-replenishment-paused",
  Readonly<{ enrollment_id: string; group_id: string }>
>;
export function createControlEnrollmentAdmissionAuthority(
  config: ControlEnrollmentAdmissionAuthorityConfig,
): ControlEnrollmentAdmissionAuthority;
export function admitControlEnrollment(
  authority: ControlEnrollmentAdmissionAuthority,
  request: ControlEnrollmentAdmissionRequest,
): Promise<ControlEnrollmentAdmissionDecision>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local reloads capacity before reservation", async () => {
  const fixture = enrollmentConfigWithInventoryChange();
  const result = await admitControlEnrollment(
    createControlEnrollmentAdmissionAuthority(fixture.config), enrollmentRequest(),
  );
  expect(result).toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
  expect(fixture.store.effectCalls).toBe(0);
});
```

The implementation verifies the exact KeyPackage first, reloads inventory
immediately before acquire, and derives unavailable, invalid, and replenishment
paused only from that authenticated state.

### Task 9 exact contract and RED

```ts
export type ControlInvitePreauthorizationAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  load_revocation: (invite_id: string) => Promise<Readonly<{
    revision: number; state: "active" | "revoked";
  }>>;
}>;
export type ControlInviteTemplate = Readonly<{
  persona: string; audience: string; client_key: string;
  client_class: "human-light" | "automated";
  methods: readonly string[]; event_kinds: readonly number[];
  limits: Readonly<Record<string, number>>; signer: string; expires_at: number;
}>;
export type ControlInviteRequest = Readonly<{
  purpose: "control-enrollment"; persona: string; audience: string;
  client_key: string; client_class: "human-light" | "automated";
  response: InviteResponseInput; secret_proof: string;
}>;
export type VerifiedControlInvitePreauthorization = Readonly<Record<never, never>>;
export function createControlInvitePreauthorizationAuthority(
  config: ControlInvitePreauthorizationAuthorityConfig,
): ControlInvitePreauthorizationAuthority;
export function verifyControlInvitePreauthorization(
  authority: ControlInvitePreauthorizationAuthority,
  envelope: InviteEnvelope,
  template: ControlInviteTemplate,
  request: ControlInviteRequest,
): Promise<AuthorityDecision<
  "invite-preauthorization-invalid", VerifiedControlInvitePreauthorization
>>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local forbids prompt-free KERI device conversion", async () => {
  const result = await verifyControlInvitePreauthorization(
    createControlInvitePreauthorizationAuthority(inviteConfig()),
    signedInviteEnvelope({ purpose: "device-enrollment" }),
    inviteTemplate(), inviteRequest(),
  );
  expect(result).toEqual({ verdict: "reject", reason_code: "invite-preauthorization-invalid" });
});
```

The implementation calls real invite signature/secret verification, requires
closed template/request equality and current active revocation state, then
mints an empty frozen handle bound to the authority and exact bytes.

### Task 10 exact contract and RED

```ts
export type ControlTokenVerifierConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  expected_issuer: string; expected_audience: string; jwks: JsonValue;
  load_grant_view: (authorization_id: string) => Promise<CurrentAuthorizationView>;
  consume_proof: (input: Readonly<{
    compact_proof: string; sender_key: string; operation_digest: string;
  }>) => Promise<string | null>;
  store: DurableAuthorityStore<Readonly<{ operation_id: string }>>;
}>;
export type ControlTokenUse = Readonly<{
  sender_key: string; marmot_group_id: string; authorization_id: string;
  grant_generation: number; required_scope: string; method: string;
  object: ControlAuthorizationObject; compact_proof: string;
}>;
export type ControlTokenOperation = Readonly<{
  operation_id: string; request_digest: string;
  execute: (execution_token: string) => Promise<Readonly<{ operation_id: string }>>;
}>;
export type VerifiedControlToken = Readonly<Record<never, never>>;
export function createControlTokenVerifier(
  config: ControlTokenVerifierConfig,
): ControlTokenVerifier;
export function verifyControlToken(
  verifier: ControlTokenVerifier,
  compact_jwt: string,
  use: ControlTokenUse,
): Promise<AuthorityDecision<"control-token-invalid", VerifiedControlToken>>;
export function consumeVerifiedControlToken(
  verifier: ControlTokenVerifier,
  token: VerifiedControlToken,
  operation: ControlTokenOperation,
): Promise<AuthorityDecision<"control-token-invalid", Readonly<{ operation_id: string }>>>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local consumes a verified token once", async () => {
  const verifier = createControlTokenVerifier(tokenConfig());
  const verified = await verifyControlToken(verifier, signedControlJwt(), tokenUse());
  expect(verified.verdict).toBe("accept");
  if (verified.verdict !== "accept") throw new Error("synthetic token rejected");
  const first = await consumeVerifiedControlToken(verifier, verified.output, operation());
  const second = await consumeVerifiedControlToken(verifier, verified.output, changedOperation());
  expect(first.verdict).toBe("accept");
  expect(second).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  expect(tokenEffect.calls).toBe(1);
});
```

JWT verification uses `validateProjectedJwt`; current grant, checkpoint,
generation, status, group, sender, scope, method, object, expiry, and per-use
proof are compared before the one-use handle is minted.

### Task 11 exact contract and RED

```ts
export type WorkspaceSecurityFixture = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  signed_repository_view: Readonly<Record<string, unknown>>;
  grant_id: string; subject: string; resource: string; action: string;
}>;
export function buildWorkspaceSecurityFixture(input: Readonly<{
  root_capabilities: readonly string[];
  ancestor_capabilities: readonly (readonly string[])[];
  grant_capabilities: readonly string[];
  revoked: boolean;
}>): WorkspaceSecurityFixture;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local rejects a child wider than the signed root", () => {
  const fixture = buildWorkspaceSecurityFixture({
    root_capabilities: ["read"], ancestor_capabilities: [["read", "write"]],
    grant_capabilities: ["read", "write"], revoked: false,
  });
  const current = authenticateWorkspaceRepositoryView(fixture.signed_repository_view);
  expect(current).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
});
```

The complete-state validator finds the unique root role, requires every role
and grant capability set to be a subset of root and every ancestor, and stores
the resulting ceiling in opaque current state. Resolution and activation use
only that stored intersection. Invitation tests use
`ReferenceWorkspaceInvitationAcceptanceStore` and assert one activation.

### Task 12 exact contract and RED

```ts
export type SocialSubscriptionAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  load_subscription: (policy_persona: string) => Promise<Readonly<{
    revision: number; subscribed: boolean; default_visible: boolean;
  }>>;
}>;
export type SocialSubscriptionInput = Readonly<{
  policy_persona: string; list_candidates: readonly NostrSignedEvent[];
  receipt_events: readonly NostrSignedEvent[]; target_events: readonly NostrSignedEvent[];
  correction_events: readonly NostrSignedEvent[];
}>;
export type SubscribedAgentPolicyView = Readonly<Record<never, never>>;
export function createSocialSubscriptionAuthority(
  config: SocialSubscriptionAuthorityConfig,
): SocialSubscriptionAuthority;
export function resolveSubscribedAgentPolicy(
  authority: SocialSubscriptionAuthority,
  input: SocialSubscriptionInput,
): Promise<SubscribedAgentPolicyView | null>;
export function applySubscribedAgentPolicy(
  view: SubscribedAgentPolicyView | null,
  event: NostrSignedEvent,
): AgentPolicyDecision;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local ignores an unsubscribed relay-selected list", async () => {
  const authority = createSocialSubscriptionAuthority(socialConfig({ subscribed: false }));
  const view = await resolveSubscribedAgentPolicy(authority, socialInput());
  expect(view).toBeNull();
  expect(applySubscribedAgentPolicy(view, TARGET_EVENT))
    .toEqual({ visible: true, muted: false });
});
```

Resolution verifies all signed events, performs source-neutral replaceable
selection, applies corrections/removals, then reads explicit local subscription
state. A view is minted only when subscribed and binds each receipt to the exact
verified offending author/device key.

### Task 13 exact contracts and RED

```ts
export type CanonicalProfileSelectionAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  authenticate_repository_candidate: (event: NostrSignedEvent, rid: string,
    ref: string) => Promise<CurrentRepositoryWriterBinding | null>;
}>;
export type CanonicalProfileSelectionInput = Readonly<{
  relay_candidates: readonly NostrSignedEvent[];
  repository_candidates: readonly Readonly<{
    event: NostrSignedEvent; repository_rid: string; ref: string;
  }>[];
  repository_state_required: boolean;
}>;
export type CoreOperationalAssuranceAuthorityConfig = Readonly<{
  authority_id: string; trusted_now: () => number;
  capture_transport: () => Readonly<{
    role: "public-reader" | "authenticated-light" | "full-node";
    strict_profile: boolean; route: "tor" | "clearnet";
  }>;
}>;
export type CanonicalProfileView = Readonly<Record<never, never>>;
export type VerifiedCoreOperationalView = Readonly<Record<never, never>>;
export function createCanonicalProfileSelectionAuthority(
  config: CanonicalProfileSelectionAuthorityConfig,
): CanonicalProfileSelectionAuthority;
export function selectCanonicalProfile(
  authority: CanonicalProfileSelectionAuthority,
  input: CanonicalProfileSelectionInput,
): Promise<AuthorityDecision<"profile-repository-selection-required", CanonicalProfileView>>;
export function createCoreOperationalAssuranceAuthority(
  config: CoreOperationalAssuranceAuthorityConfig,
): CoreOperationalAssuranceAuthority;
export function verifyCacheCandidate(
  authority: CoreOperationalAssuranceAuthority,
  input: Readonly<{ event: NostrSignedEvent; expected_persona: string }>,
): AuthorityDecision<"unauthorized_cache_content", VerifiedCoreOperationalView>;
export function verifyRelayProfileCarrier(
  authority: CoreOperationalAssuranceAuthority,
  input: Readonly<{ event: NostrSignedEvent; retained_bytes: Uint8Array }>,
): AuthorityDecision<"relay_profile_mutation", VerifiedCoreOperationalView>;
export function verifyStrictTransport(
  authority: CoreOperationalAssuranceAuthority,
): AuthorityDecision<"strict_mode_tor_disabled", VerifiedCoreOperationalView>;
```

```ts
it("BLUE TEAM VALIDATION: synthetic/local rejects mutated retained relay bytes", () => {
  const authority = createCoreOperationalAssuranceAuthority(coreOperationalConfig());
  const original = signedProfileEvent();
  const retained = new TextEncoder().encode(JSON.stringify({ ...original, content: "mutated" }));
  expect(verifyRelayProfileCarrier(authority, { event: original, retained_bytes: retained }))
    .toEqual({ verdict: "reject", reason_code: "relay_profile_mutation" });
});
```

Canonical selection verifies every kind-0 event and repository writer, unions
sources without carrier priority, then runs exact replaceable selection;
required missing repository authentication yields
`profile-repository-selection-required`. Operational functions return opaque
views only after verifying actual persona authorship/raw event bytes or the
constructor-captured role/transport snapshot; they derive the remaining three
Core reasons without booleans.

---

### Task 1: Establish retired and diagnostic-only normative anchors

**Files:**
- Modify: `docs/spec/heterodyne-assurance.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`

**Interfaces:**
- Consumes: the exact 11 retired reasons and one diagnostic-only reason in design §§2.1–2.2.
- Produces: explicit owner-document anchors for revision 17 and a lint assertion that none are normative executable evidence.

- [ ] **Step 1: Add the focused RED**

Add a `BLUE TEAM VALIDATION: synthetic/local — retired diagnostics cannot claim live semantic authority` test that loads the four current documents and asserts exact anchors for Assurance, Core, Comms, and Control plus diagnostic-only wording for `auth_rejected_permanent`.

- [ ] **Step 2: Observe the expected failure**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts -t "retired diagnostics cannot claim live semantic authority"
```

Expected: FAIL because the explicit anchors and diagnostic-only wording do not exist.

- [ ] **Step 3: Add the minimum normative text**

Add one explicit retired-semantics section per owner. List the exact retained IDs, state that they are non-wire history and not current executable authority, and preserve the current invariants through their named real boundaries. In Comms, state that `auth_rejected_permanent` is a local relay-write diagnostic and proves no cryptographic or upstream authority.

- [ ] **Step 4: Run GREEN and current build**

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit only Task 1 paths**

```bash
git add docs/spec/heterodyne-assurance.md docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: classify retired security diagnostics"
```

### Task 2: Verify Marmot Welcome and admission authority

**Files:**
- Create: `docs/spec/vectors/generator/src/security-authority-support.ts`
- Create: `docs/spec/vectors/generator/src/security-authority-support.test.ts`
- Create: `docs/spec/vectors/generator/src/marmot-admission-authority.ts`
- Create: `docs/spec/vectors/generator/src/marmot-admission-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/marmot-admission.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces in `security-authority-support.ts` the exact `AuthorityDecision`,
  `DurableAuthorityRecord`, `DurableAuthorityStore`,
  `authorityBindingDigest`, and `captureAuthorityInput` declarations in the
  preceding contract section; Tasks 3–13 import those declarations.

- Produces: `createMarmotAdmissionAuthority(config): MarmotAdmissionAuthority`,
  `verifyMarmotWelcome(authority, input): MarmotWelcomeDecision`, and
  `admitOrdinaryMarmotWelcome(authority, welcome, acceptance): Promise<MarmotAdmissionDecision>`.
- `VerifiedMarmotWelcome` is an opaque handle binding exact Welcome/KeyPackage bytes, account, group, members, capabilities, and current conversation checkpoint.

- [ ] **Step 1: Write the authority RED**

Add deterministic signed Welcome/KeyPackage fixtures and tests for exact acceptance, account mismatch, leaf reuse, wrong group/member/capability, stale conversation state, clone/cross-authority handle, source mutation, accessor/proxy zero-trap rejection, and a restart-stable consuming admission. Prefix hostile cases with `BLUE TEAM VALIDATION: synthetic/local`.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-admission-authority.test.ts
```

Expected: FAIL because the module and opaque authority do not exist.

- [ ] **Step 3: Implement the closed API**

Implement frozen empty handles backed by private records. Capture callback identity once, descriptor-snapshot every input before semantic reads, verify exact account/group/member/keypackage bindings, reload current conversation state, and reserve admission before returning accept. Keep `cryptographic_valid` and `one_time_dm_invite_valid` outside the new API.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-admission-authority.test.ts src/marmot-admission.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/security-authority-support.ts docs/spec/vectors/generator/src/security-authority-support.test.ts docs/spec/vectors/generator/src/marmot-admission-authority.ts docs/spec/vectors/generator/src/marmot-admission-authority.test.ts docs/spec/vectors/generator/src/marmot-admission.ts docs/spec/heterodyne-comms.md
git commit -m "fix: verify Marmot admission authority"
```

### Task 3: Bind exact Marmot archive retention and acknowledgement

**Files:**
- Create: `docs/spec/vectors/generator/src/marmot-archive-retention-authority.ts`
- Create: `docs/spec/vectors/generator/src/marmot-archive-retention-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/marmot-routing-policy.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces the exact `MarmotArchiveRetentionAuthorityConfig`,
  `MarmotArchiveInput`, `MarmotArchiveDecision`, and three function signatures
  in the preceding Task 3 contract block.
- The opaque receipt binds repository RID/ref, object digest, exact source-event/ciphertext digest, and durable commit identity.

- [ ] **Step 1: Write RED**

Test exact-byte append/ack, invalid signed-event ID/signature, unauthorized repository writer/ref, changed bytes/ref/RID, ciphertext without authenticated source-event/media authorization, acknowledgement before durable reachability, expiration preserving retained ciphertext/history, store conflict, unknown terminal write, exact committed retry, clone/cross-authority handle, and callback accessor/proxy zero-trap behavior. Use the mandated blue-team label on hostile cases.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-archive-retention-authority.test.ts
```

- [ ] **Step 3: Implement minimal durable boundary**

Capture exact bytes once, verify NIP-01 ID/signature for event inputs, authenticate the repository writer/RID/ref, bind ciphertext to an authenticated source-event or media authorization, then require durable repository reachability before receipt minting. Allow acknowledgement only from the genuine receipt and make terminal-write uncertainty absorbing `indeterminate`. Expiration changes current presentation/authorization only.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/marmot-archive-retention-authority.test.ts src/marmot-routing-policy.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/marmot-archive-retention-authority.ts docs/spec/vectors/generator/src/marmot-archive-retention-authority.test.ts docs/spec/vectors/generator/src/marmot-routing-policy.ts docs/spec/heterodyne-comms.md
git commit -m "fix: bind Marmot archival durability"
```

### Task 4: Authorize persona inbox admission and one-time invite redemption

**Files:**
- Create: `docs/spec/vectors/generator/src/persona-inbox-admission-authority.ts`
- Create: `docs/spec/vectors/generator/src/persona-inbox-admission-authority.test.ts`
- Create: `docs/spec/vectors/generator/src/one-time-invite-authority.ts`
- Create: `docs/spec/vectors/generator/src/one-time-invite-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/one-time-invite.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces: `createPersonaInboxAdmissionAuthority`, `admitPersonaInboxBundle`, `createOneTimeInviteAuthority`, and `redeemOneTimeInvite`.
- Inbox authority owns current NID authorization, sender scope, exact sender ref, selected KeyPackage, and group transition. Invite authority reuses real descriptor signature and `responseProof` validation but owns current revocation and durable reservation state.

- [ ] **Step 1: Write focused RED suites**

Cover exact accepts and the live reasons `marmot-agent-scope-denied`, `marmot-keypackage-replayed`, `marmot-private-inbox-nid-required`, and `invite-authentication-invalid`. Add wrong purpose/transcript/recipient/secret, expiry/revocation, replay, mismatched retry, unknown post-effect state, mutation, clone, proxy, and accessor cases using the blue-team label.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/persona-inbox-admission-authority.test.ts src/one-time-invite-authority.test.ts
```

- [ ] **Step 3: Implement the two opaque authorities**

Use separate module-private authority/handle records and separate durable store keys. Verify signed invite bytes with existing helpers, bind every security-relevant member into the reservation digest, cache exact committed outputs, and never recreate the retired DM device-state reasons.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/persona-inbox-admission-authority.test.ts src/one-time-invite-authority.test.ts src/one-time-invite.test.ts src/comms-policy.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/persona-inbox-admission-authority.ts docs/spec/vectors/generator/src/persona-inbox-admission-authority.test.ts docs/spec/vectors/generator/src/one-time-invite-authority.ts docs/spec/vectors/generator/src/one-time-invite-authority.test.ts docs/spec/vectors/generator/src/one-time-invite.ts docs/spec/heterodyne-comms.md
git commit -m "fix: authorize Marmot inbox and invite use"
```

### Task 5: Make workload publication authorization atomic with signing

**Files:**
- Create: `docs/spec/vectors/generator/src/agent-publication-authorization.ts`
- Create: `docs/spec/vectors/generator/src/agent-publication-authorization.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-authorship.ts`
- Modify: `docs/spec/heterodyne-comms.md`

**Interfaces:**
- Produces only the exact constructor and atomic
  `authorizeAndSignAgentPublication(...): Promise<AgentPublicationDecision>`
  signature in the preceding Task 5 contract block.
- The internal `VerifiedAgentPublicationAuthorization` is not exported. It binds verified JWT bytes, issuer/audience/subject/persona/agent/signer/scope/expiry/status/generation, DPoP or configured mTLS identity, current opaque claim view, exact publication, and attribution profile.

- [ ] **Step 1: Write RED**

Use real local JWT signing/verification, deterministic DPoP fixtures, and a synthetic constructor-captured mTLS peer identity. Test accepted DPoP and mTLS atomic publication, wrong/substituted mTLS peer, per-operation mTLS callback replacement, wrong signer/audience/scope/nonce/method/target, stale status/generation/claim view, proof replay, publication mutation, cross-authority/callback substitution, signer throw, terminal-write failure, exact retry, and the absence of any exported pre-sign capability. Label hostile cases as blue-team validation.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-publication-authorization.test.ts
```

- [ ] **Step 3: Implement atomic mint-and-consume**

Capture and verify the complete request before acquire, revalidate status/claim state immediately before the CAS, invoke the signer only from exact persisted `executing`, verify its returned NIP-01 event, and commit immutable output before returning accept. Do not export the internal authorization handle.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/agent-publication-authorization.test.ts src/agent-authorship.test.ts src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/agent-publication-authorization.ts docs/spec/vectors/generator/src/agent-publication-authorization.test.ts docs/spec/vectors/generator/src/agent-authorship.ts docs/spec/heterodyne-comms.md
git commit -m "fix: authorize and sign agent publications atomically"
```

### Task 6: Prepare real Control reset, frame, and signer evidence

**Files:**
- Create: `docs/spec/vectors/generator/src/control-security-evidence.ts`
- Create: `docs/spec/vectors/generator/src/control-security-evidence.test.ts`
- Modify: `docs/spec/vectors/generator/src/control-signing.ts`
- Modify: `docs/spec/vectors/generator/src/profile-negotiation.ts`
- Create: `docs/spec/vectors/generator/src/profile-negotiation.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces deterministic fixture constructors and result adapters that invoke `validateCompromiseReset`, `executePersistedAutomatedSigning`, and the exact hardened `validateCurrentControlFrameProfile(frame_bytes, context)` signature from the Task 6 contract block without boolean summaries. The frame function descriptor-captures the exact frame, verifies its signing event, binds request/profile/version/transport, and never supplies hard-coded validity booleans to `validateControlFrameBoundary`.
- Later Task 15 consumes these exact functions and fixtures through its dispatcher.

- [ ] **Step 1: Write RED over exact real paths**

Add signed reset/grant/completion fixtures for all four reset reasons, malformed closed frames for `control-frame-invalid`, and an executing signer reservation producing durable `control-signer-effect-indeterminate`. Assert exact function invocation and opaque terminal identity, not only reason strings.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-security-evidence.test.ts
```

- [ ] **Step 3: Add the minimal adapters**

Export narrowly typed fixture/result functions that retain signed bytes and opaque states. Do not create a new policy evaluator or accept boolean validity fields.

- [ ] **Step 4: Verify GREEN**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-security-evidence.test.ts src/control-signing.test.ts src/profile-negotiation.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 5: Commit**

```bash
git add docs/spec/vectors/generator/src/control-security-evidence.ts docs/spec/vectors/generator/src/control-security-evidence.test.ts docs/spec/vectors/generator/src/control-signing.ts docs/spec/vectors/generator/src/profile-negotiation.ts docs/spec/vectors/generator/src/profile-negotiation.test.ts docs/spec/heterodyne-control.md
git commit -m "test: bind Control evidence to real boundaries"
```

### Task 7: Implement durable Control device authorization

**Files:**
- Create: `docs/spec/vectors/generator/src/control-device-authorization.ts`
- Create: `docs/spec/vectors/generator/src/control-device-authorization.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlDeviceAuthorizationAuthority(config)`, `createControlDeviceTransaction(authority, request)`, and `pollControlDeviceAuthorization(authority, request)`.
- Authority owns high-entropy device/user codes, client/persona, display fingerprint, interval, rate buckets, failure budget, expiry, invalidation, and atomic transaction state.

- [ ] **Step 1: Write RED**

Cover generated device/user-code entropy and deterministic collision retry/exhaustion, a valid transaction, malformed/unknown code, display mismatch, poll-before-interval, rate limit/slow-down, fifth-failure atomic invalidation, expiry, concurrent poll/CAS conflict, exact committed retry, mutation, proxy/accessor, and cross-authority use. Use blue-team labels.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-device-authorization.test.ts
```

- [ ] **Step 3: Implement the authority**

Hash normalized codes internally, load authoritative transaction/rate state, perform all attempts and invalidation through one atomic store, and derive the three `control-device-code-*` reasons only from real state transitions.

- [ ] **Step 4: Verify GREEN and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-device-authorization.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-device-authorization.ts docs/spec/vectors/generator/src/control-device-authorization.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: authorize Control device transactions"
```

### Task 8: Implement Control enrollment admission

**Files:**
- Create: `docs/spec/vectors/generator/src/control-enrollment-admission.ts`
- Create: `docs/spec/vectors/generator/src/control-enrollment-admission.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces: `createControlEnrollmentAdmissionAuthority(config)` and `admitControlEnrollment(authority, request)`.
- Authority owns pending-group capacity, slot reservation, invite purpose, exact KeyPackage validation, public replenishment state, current enrollment, expiry, and rate state.

- [ ] **Step 1: Write RED**

Test exact admission plus malformed/unbound/expired/replayed KeyPackage, independently expired invite, enrollment rate-limit state, already/currently enrolled account or device, unavailable capacity, replenishment pause, changed inventory between validation/acquire, concurrent reservation, effect uncertainty, exact retry, clone, mutation, proxy, and callback substitution with blue-team labels.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-enrollment-admission.test.ts
```

- [ ] **Step 3: Implement and verify GREEN**

Use exact descriptor capture and a caller-independent slot store; reload authoritative inventory immediately before acquire. Derive only `control-enrollment-unavailable`, `control-keypackage-invalid`, and `control-keypackage-replenishment-paused`.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-enrollment-admission.test.ts src/marmot-admission.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
```

- [ ] **Step 4: Commit**

```bash
git add docs/spec/vectors/generator/src/control-enrollment-admission.ts docs/spec/vectors/generator/src/control-enrollment-admission.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: authorize Control enrollment admission"
```

### Task 9: Verify Control invite preauthorization

**Files:**
- Create: `docs/spec/vectors/generator/src/control-invite-preauthorization.ts`
- Create: `docs/spec/vectors/generator/src/control-invite-preauthorization.test.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces the exact constructor and
  `verifyControlInvitePreauthorization(...): Promise<AuthorityDecision<"invite-preauthorization-invalid", VerifiedControlInvitePreauthorization>>`
  signature in the preceding Task 9 contract block.
- The opaque result binds exact signed fragment, non-convertible purpose, client key, persona, audience, signer/class, methods, kinds, limits, expiry, and current revocation view.

- [ ] **Step 1: Write and observe RED**

Test exact accept; signature, purpose, client, signer, audience, methods/kinds/limits, expiry, revocation, KERI prompt-free device, mutation, clone, and proxy/accessor rejection.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-invite-preauthorization.test.ts
```

- [ ] **Step 2: Implement minimal composition**

Compose the real Comms signed invite verification with exact closed Control template equality and current revocation loading. Never accept a caller `valid` summary.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-invite-preauthorization.test.ts src/one-time-invite.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-invite-preauthorization.ts docs/spec/vectors/generator/src/control-invite-preauthorization.test.ts docs/spec/heterodyne-control.md
git commit -m "fix: verify Control invite preauthorization"
```

### Task 10: Verify current Control tokens

**Files:**
- Create: `docs/spec/vectors/generator/src/control-token-verifier.ts`
- Create: `docs/spec/vectors/generator/src/control-token-verifier.test.ts`
- Modify: `docs/spec/vectors/generator/src/token-status.ts`
- Modify: `docs/spec/heterodyne-control.md`

**Interfaces:**
- Produces the exact constructor, verifier, and consuming-operation signatures
  in the preceding Task 10 contract block.
- The opaque one-use result binds actual RS256 JWT verification, issuer/audience/token class, sender key, Marmot group, exact grant/checkpoint/generation/status, expiry, proof-of-possession, and current opaque grant view.

- [ ] **Step 1: Write and observe RED**

Use local deterministic signing keys. Test exact accept and consume; bad signature/type/issuer/audience/sender/time/group/grant/checkpoint/generation/status/proof; stale current view; replay; cross-authority consume; changed operation; exact committed retry; indeterminate terminal; mutation; clone; accessor/proxy; and cross-authority use.

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-token-verifier.test.ts
```

- [ ] **Step 2: Implement real verification**

Reuse actual projected-JWT validation, then resolve and bind the current Control grant view before minting a one-use token handle. Map all public failures to `control-token-invalid` without leaking internal mismatch detail.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/control-token-verifier.test.ts src/token-status.test.ts src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/control-token-verifier.ts docs/spec/vectors/generator/src/control-token-verifier.test.ts docs/spec/vectors/generator/src/token-status.ts docs/spec/heterodyne-control.md
git commit -m "fix: verify current Control tokens"
```

### Task 11: Migrate Workspace authority to signed current state

**Files:**
- Create: `docs/spec/vectors/generator/src/workspace-security-evidence.ts`
- Create: `docs/spec/vectors/generator/src/workspace-security-evidence.test.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.ts`
- Modify: `docs/spec/vectors/generator/src/workspace.test.ts`
- Modify: `docs/spec/heterodyne-workspace.md`

**Interfaces:**
- Produces signed deterministic fixture builders and exact calls through `createWorkspaceRepositoryResolverAuthority`, `authenticateWorkspaceRepositoryView`, `resolveWorkspaceEffectiveAuthorization`, `consumeWorkspaceInvitationAcceptance`, and `evaluateGrantActivation`.
- Root role `allowed_capabilities` is enforced as the ceiling at repository acceptance, resolution, activation, allowance, and key delivery.

- [ ] **Step 1: Write RED**

Test a carrier/host/repository writer with no signed grant, ambient affiliation without authority, child/grant capability widening, valid narrowing intersection, revoked future effect, first invitation acceptance, exact committed retry, changed/replayed invitation, effect-time state change, and proxy/accessor/mutation rejection. Label hostile tests as blue-team validation.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/workspace-security-evidence.test.ts src/workspace.test.ts -t "workspace-wide ceiling|signed current state|invitation replay"
```

- [ ] **Step 3: Implement the root ceiling and fixture harness**

Make complete-state validation reject any descendant widening beyond root `allowed_capabilities`. Preserve opaque resolver authority in private fixture state; serialize only signed objects and closed requests. Use the existing consuming invitation store for replay.

- [ ] **Step 4: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/workspace-security-evidence.test.ts src/workspace.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/workspace-security-evidence.ts docs/spec/vectors/generator/src/workspace-security-evidence.test.ts docs/spec/vectors/generator/src/workspace.ts docs/spec/vectors/generator/src/workspace.test.ts docs/spec/heterodyne-workspace.md
git commit -m "fix: enforce Workspace authority ceiling"
```

### Task 12: Compose signed subscriber-local Social policy

**Files:**
- Create: `docs/spec/vectors/generator/src/social-subscription-authority.ts`
- Create: `docs/spec/vectors/generator/src/social-subscription-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/agent-moderation.ts`
- Modify: `docs/spec/vectors/generator/src/agent-moderation.test.ts`
- Modify: `docs/spec/heterodyne-social.md`

**Interfaces:**
- Produces: `createSocialSubscriptionAuthority(config)`, `resolveSubscribedAgentPolicy(authority, input): SubscribedAgentPolicyView | null`, and `applySubscribedAgentPolicy(view, event): AgentPolicyDecision`.
- Local subscription state is captured by the authority; the view binds source-neutral selected signed list, exact signed receipts/targets/authorship, and muted author/device keys.

- [ ] **Step 1: Write and observe RED**

Test signed current list/receipt accept, unsubscribed, stale/replaced/removed/corrected list, invalid receipt, wrong author/device, relay-current candidate, default subscription visible/removable, clone/cross-authority view, mutation, and zero-trap proxy/accessor cases.

```bash
npm --prefix docs/spec/vectors/generator test -- src/social-subscription-authority.test.ts
```

- [ ] **Step 2: Implement signed composition**

Reuse `validateAgentPolicyReceipt`, `validateAgentPolicyList`, source-neutral replaceable selection, and real Social/Comms authorship evidence. Remove caller-provided `subscribed`, `policy_event_selected`, and `muted_event_authors` from the secure path.

- [ ] **Step 3: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/social-subscription-authority.test.ts src/agent-moderation.test.ts src/social-events.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/social-subscription-authority.ts docs/spec/vectors/generator/src/social-subscription-authority.test.ts docs/spec/vectors/generator/src/agent-moderation.ts docs/spec/vectors/generator/src/agent-moderation.test.ts docs/spec/heterodyne-social.md
git commit -m "fix: verify subscribed Social policy"
```

### Task 13: Implement Core profile and operational authorities

**Files:**
- Create: `docs/spec/vectors/generator/src/canonical-profile-selection-authority.ts`
- Create: `docs/spec/vectors/generator/src/canonical-profile-selection-authority.test.ts`
- Create: `docs/spec/vectors/generator/src/core-operational-assurance-authority.ts`
- Create: `docs/spec/vectors/generator/src/core-operational-assurance-authority.test.ts`
- Modify: `docs/spec/vectors/generator/src/core-policy.ts`
- Modify: `docs/spec/vectors/generator/src/follow-up-hardening.ts`
- Modify: `docs/spec/heterodyne-core.md`

**Interfaces:**
- Produces: `createCanonicalProfileSelectionAuthority`, `selectCanonicalProfile`, `createCoreOperationalAssuranceAuthority`, `verifyCacheCandidate`, `verifyRelayProfileCarrier`, and `verifyStrictTransport`.
- Profile selection reuses source-neutral opaque replaceable selection and authenticates repository writers; operational views bind verified NIP-01 bytes/author or captured strict-role transport configuration.

- [ ] **Step 1: Write RED**

Test source-neutral signed selection, required repository state, bad writer, unsigned/wrong-author cache entry, raw relay mutation with recomputed field mismatch, strict role without Tor, reduced-assurance non-strict accept, mutation, clone, proxy/accessor, and callback substitution.

- [ ] **Step 2: Observe RED**

```bash
npm --prefix docs/spec/vectors/generator test -- src/canonical-profile-selection-authority.test.ts src/core-operational-assurance-authority.test.ts
```

- [ ] **Step 3: Implement opaque views**

Use `snapshotAndVerifyNostrEvent` and `ReplaceableSelectionAuthority`; authenticate repository candidates without carrier priority; remove boolean security inputs from the secure Core path. Derive the four live Core reasons from exact state only.

- [ ] **Step 4: Verify and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/canonical-profile-selection-authority.test.ts src/core-operational-assurance-authority.test.ts src/core-policy.test.ts src/follow-up-hardening.test.ts
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/vectors/generator/src/canonical-profile-selection-authority.ts docs/spec/vectors/generator/src/canonical-profile-selection-authority.test.ts docs/spec/vectors/generator/src/core-operational-assurance-authority.ts docs/spec/vectors/generator/src/core-operational-assurance-authority.test.ts docs/spec/vectors/generator/src/core-policy.ts docs/spec/vectors/generator/src/follow-up-hardening.ts docs/spec/heterodyne-core.md
git commit -m "fix: verify Core operational authority"
```

### Task 14: Author immutable registry revision 17 exactly once

**Files:**
- Modify: `docs/spec/registry/manifest.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify only if concrete allocations require it: `docs/spec/registry/objects.json`
- Modify only if concrete allocations require it: `docs/spec/registry/proof-domains.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`
- Create: `docs/spec/vectors/generator/src/registry-revision17-preflight.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`

**Interfaces:**
- Consumes: settled anchors and authority contracts from Tasks 1–13.
- Produces: immutable revision 17, preserved revision-16 history, 11 exact retired exclusions, one exact diagnostic-only exclusion, and no exclusion for the 28 live reasons.

- [ ] **Step 1: Write registry-history RED**

Assert revision 17, the exact revision-16 baseline digest `5ff98ff2af3bcbb413918dc207dcfc5da7035e9751e9836680df9b56a2b2230f`, preserved entry IDs/owners/status/`first_version`, exact new anchors/descriptions, and exact sorted exclusions with individual justifications. Assert all 28 live reasons are absent from exclusions.

- [ ] **Step 2: Observe RED before any author call**

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/coverage.test.ts -t "revision 17|retired security diagnostics|live authority reasons"
```

Expected: FAIL on revision 16 and missing revised entries. Record author-call count as zero in the task report.

- [ ] **Step 3: Edit entry JSON and validate a synthetic no-write manifest**

Retarget the 11 retained reasons, classify `auth_rejected_permanent`, refine live descriptions/anchors only where required, and add only concrete object/proof allocations backed by completed Tasks 2–13. Preserve every prior identity and `first_version`. In the standalone `registry-revision17-preflight.test.ts`, read `manifest.json` and every entry JSON with `readFileSync`/`JSON.parse` rather than `loadRegistry`; assert that the raw manifest is still revision 16 with digest `5ff98ff2af3bcbb413918dc207dcfc5da7035e9751e9836680df9b56a2b2230f`, compute `const digest = computeRegistryDigest(entrySet)`, construct `{ ...revision16Manifest, revision: 17, entry_set_sha256: digest }`, and call `validateRegistry({ manifest: syntheticManifest, ...entrySet })`. Assert every prior identity/`first_version` before permitting the author step. After this preflight passes, entry JSON is frozen for the task; any further entry edit aborts the task before authoring.

Run the no-write preflight alone; it must pass while the checked-in manifest is still revision 16:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry-revision17-preflight.test.ts
```

- [ ] **Step 4: Invoke the registry author exactly once**

```bash
npm --prefix docs/spec/vectors/generator run registry-author -- "$PWD" 17
```

Do not invoke it again. Any failure after this call stops Task 14 for adjudication; no entry edit or second author invocation is permitted.

- [ ] **Step 5: Verify GREEN and commit**

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts src/coverage.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run build:current
git diff --check
git add docs/spec/registry/manifest.json docs/spec/registry/reason-codes.json docs/spec/registry/objects.json docs/spec/registry/proof-domains.json docs/spec/vectors/generator/src/registry.test.ts docs/spec/vectors/generator/src/registry-revision17-preflight.test.ts docs/spec/vectors/generator/src/coverage.ts docs/spec/vectors/generator/src/coverage.test.ts
git commit -m "spec: author security authority registry revision 17"
```

### Task 15: Resume Task 10 and close executable semantic certificates

**Files:**
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/index.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.test.ts`
- Modify and commit the preserved paused files: `docs/spec/vectors/generator/src/current-vectors/semantic-certificates.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/assurance.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/comms.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/control.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/core.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/social.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors/workspace.ts`
- Modify: `docs/spec/vectors/generator/src/current-vectors.test.ts`
- Modify: `docs/spec/vectors/generator/src/coverage.test.ts`

**Interfaces:**
- Consumes: every authority/result from Tasks 2–13 and revision 17 from Task 14.
- Produces: exact ordered invocation plans, unbypassable `InvocationContext.call(stepId, exactArgs)`, opaque execution receipts, boundary-specific proof witnesses, and complete invariant/reason/profile/owner/spec-reference closure.

The exact replacement map is:

| Case | Ordered canonical boundary plan | Allocation | Required terminal postcondition |
|---|---|---|---|
| `comms/agent-sender-proof-invalid` | `agent-publication-authorization.authorizeAndSignAgentPublication` | `COMMS-I-WORKLOAD-TOKEN-CONFINEMENT`; `agent-sender-proof-invalid` | real JWT accepted, exact DPoP/mTLS sender proof rejected before signer/effect |
| `comms/conversation-rejected` | `verifyMarmotWelcome` → `admitOrdinaryMarmotWelcome` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `conversation-rejected` | verified Welcome exists, authenticated current admission rejects |
| `comms/invite-authentication-invalid` | `one-time-invite-authority.redeemOneTimeInvite` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `invite-authentication-invalid` | exact signed invite/response proof rejects with no reservation/effect |
| `comms/marmot-agent-scope-denied` | `persona-inbox-admission-authority.admitPersonaInboxBundle` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-agent-scope-denied` | current inbox scope excludes the captured sender/request |
| `comms/marmot-keypackage-replayed` | same inbox boundary | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-keypackage-replayed` | exact KeyPackage is already durably consumed |
| `comms/marmot-premature-ack` | `appendExactMarmotArchive` → `acknowledgeMarmotArchive` | `COMMS-I-MARMOT-EXACT-BYTES`; `marmot-premature-ack` | no genuine durable append receipt exists at acknowledgement time |
| `comms/marmot-private-inbox-nid-required` | `persona-inbox-admission-authority.admitPersonaInboxBundle` | `COMMS-I-MARMOT-UPSTREAM-AUTHORITY`; `marmot-private-inbox-nid-required` | current authenticated recipient authorization lacks required NID binding |
| `control/compromise-reset-evidence-invalid` | `control-signing.validateCompromiseReset` | `CONTROL-I-COMPROMISE-RESET`; matching reason | signed grant/completion valid but exact consecutive reset evidence invalid |
| `control/compromise-reset-inventory-mismatch` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | authenticated required-reset inventory differs from completion |
| `control/compromise-reset-unauthenticated` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | grant/completion signature or Assurance binding rejects |
| `control/subordinate-reauthorization-required` | same reset boundary | `CONTROL-I-COMPROMISE-RESET`; matching reason | a required subordinate fresh authorization is absent |
| `control/device-code-display-mismatch` | `control-device-authorization.pollControlDeviceAuthorization` | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | stored and authenticated display fingerprints differ |
| `control/device-code-invalid` | same device boundary | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | normalized code is absent/invalid/atomically invalidated |
| `control/device-code-rate-limited` | same device boundary | `CONTROL-I-NIP46-OIDC-ACTIVATION`; matching reason | authoritative interval/rate state forbids this poll |
| `control/enrollment-unavailable` | `control-enrollment-admission.admitControlEnrollment` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | authenticated capacity/current enrollment forbids reservation |
| `control/frame-invalid` | `profile-negotiation.validateCurrentControlFrameProfile` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | exact captured signed frame/profile/request fails closed |
| `control/invite-preauthorization-invalid` | `control-invite-preauthorization.verifyControlInvitePreauthorization` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | signed invite/template/current revocation does not bind request |
| `control/keypackage-invalid` | `control-enrollment-admission.admitControlEnrollment` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | exact KeyPackage verification/binding fails |
| `control/keypackage-replenishment-paused` | same enrollment boundary | `CONTROL-I-MARMOT-GRANT-CONFINEMENT`; matching reason | authoritative public-pool pending state pauses replenishment |
| `control/signer-effect-indeterminate` | `control-signing.executePersistedAutomatedSigning` | `CONTROL-I-OPERATION-AT-MOST-ONCE`; `control-signer-effect-indeterminate` | persisted execution becomes absorbing indeterminate and signer is not repeated |
| `control/token-invalid` | `verifyControlToken` → `consumeVerifiedControlToken` | `CONTROL-I-CLIENT-KEY-CONFINEMENT`; matching reason | actual JWT/current grant/per-use proof rejects before operation |
| `workspace/carrier-not-ambient-authority` | authenticate view → `resolveWorkspaceEffectiveAuthorization` | `WORKSPACE-I-CARRIER-NOT-AUTHORITY`, `WORKSPACE-I-NO-AMBIENT-AUTHORITY`; `policy_denied` | carrier/host/writer principal has no qualifying signed grant |
| `workspace/inheritance-escalation-rejected` | authenticate view → resolve → `evaluateGrantActivation` | `WORKSPACE-I-INHERITANCE-NARROWS`; `capability_escalation` | child/grant request exceeds root/ancestor intersection |
| `workspace/invitation-replay` | `consumeWorkspaceInvitationAcceptance` → activation → identical second consume | `WORKSPACE-I-NO-AMBIENT-AUTHORITY`; `workspace_replay` | first terminal is committed; replay performs no second activation |
| `workspace/revocation-blocks-future-effect` | authenticate view → resolve → activation | `WORKSPACE-I-REVOCATION-FUTURE-ONLY`; `policy_denied` | current signed revocation excludes the future effect |
| `core/friend-cache-unsigned` | `core-operational-assurance-authority.verifyCacheCandidate` | `CORE-I-IDENTITY-INTEGRITY`; `unauthorized_cache_content` | cache candidate lacks exact verified persona authorship |
| `core/profile-repository-selection-required` | `canonical-profile-selection-authority.selectCanonicalProfile` | `CORE-I-IDENTITY-INTEGRITY`; matching reason | selected profile requires authenticated repository state that is absent |
| `core/relay-profile-mutated` | `core-operational-assurance-authority.verifyRelayProfileCarrier` | `CORE-I-IDENTITY-INTEGRITY`; `relay_profile_mutation` | retained raw event ID/signature/exposed fields do not match |
| `core/strict-mode-without-tor` | `core-operational-assurance-authority.verifyStrictTransport` | `CORE-I-VERIFY-BEFORE-USE`; `strict_mode_tor_disabled` | captured strict role requires Tor and current transport lacks it |
| `comms/agent-workload-token-accepted` | `agent-publication-authorization.authorizeAndSignAgentPublication` | `COMMS-I-AGENT-SIGNER-BINDING`, `COMMS-I-WORKLOAD-TOKEN-CONFINEMENT` | one durable effect yields an exactly attributed signed NIP-01 event |
| `comms/marmot-exact-bytes-durable` | `marmot-archive-retention-authority.appendExactMarmotArchive` | `COMMS-I-MARMOT-EXACT-BYTES` | genuine receipt binds identical authorized bytes and durable ref/object commit |
| `comms/marmot-expiration-not-erasure` | append → `expireMarmotPresentation` → archive reload | `COMMS-I-RADICLE-NON-ERASURE` | presentation expires while ciphertext/history remains reachable |
| `comms/marmot-ordinary-welcome-held` | `verifyMarmotWelcome` → `admitOrdinaryMarmotWelcome` | `COMMS-I-MARMOT-ACCOUNT-IDENTITY`, `COMMS-I-MARMOT-SECRET-CONFINEMENT`, `COMMS-I-MARMOT-UPSTREAM-AUTHORITY` | exact account/group/member/leaf bindings accept once under local authority |
| `workspace/current-capability-intersection` | authenticate view → resolve → activation | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE`, `WORKSPACE-I-INHERITANCE-NARROWS`, `WORKSPACE-I-NO-AMBIENT-AUTHORITY` | output equals root ∩ ancestors ∩ current grant/relationship/resource constraints |

- [ ] **Step 1: Preserve and re-run the dispatcher RED/GREEN evidence**

Confirm the existing test proves a same-ID substituted evaluator is actually called/throws and the AST guard reports zero branch calls outside canonical plan construction. Do not weaken the paused assertions.

- [ ] **Step 2: Add prerequisite-boundary REDs**

For each replaced case, assert that a fabricated same-terminal result, copied reason/invariant, cloned fixture, alternate evaluator wrapper, or omitted composite step cannot mint a certificate. Assert the five positive cases prove their real postconditions. All hostile tests use the exact blue-team label.

- [ ] **Step 3: Replace cases and remove retired cases**

Delete exactly `assurance/retired-key-post-compromise`, `core/retired-key-authority-window-invalid`, `comms/dm-invite-revoked-device`, `comms/dm-invite-unbound-device`, `control/agent-attribution-bypass-prohibited`, `control/agent-human-profile-prohibited`, `control/agent-key-access-prohibited`, `control/agent-method-prohibited`, `control/agent-resource-denied`, `control/request-id-conflict`, and `control/signed-event-invalid`. Keep `comms/auth-rejected-permanent` terminal-only with no semantic certificate. Replace every other shim fixture with closed data consumed by the real authorities; keep function-bearing authorities in private fixture registries. Do not serialize opaque handles or callbacks.

- [ ] **Step 4: Finish canonical invocation plans**

Every branch calls only through ordered `InvocationContext.call`. The receipt binds exact runner/plan/function references, argument identities/digests, return/throw identities/digests, fixture identity/digest, raw/projected result identity, durable state, and terminal postcondition. `finish()` rejects skipped, extra, or reordered occurrences.

- [ ] **Step 5: Implement exact boundary-specific proof predicates**

Each predicate derives its owned invariants/reasons from exact fixture plus inspected trace/raw result/private artifacts; it never accepts caller labels or expected output as evidence. Registry/profile prerequisites and semantic evaluators both appear in composite plans. Remove `NON_CERTIFIABLE_CALLER_SHIM_CASES` when the last replacement lands.

- [ ] **Step 6: Run focused closure**

```bash
npm --prefix docs/spec/vectors/generator test -- src/current-vectors/semantic-certificates.test.ts src/current-vectors.test.ts src/coverage.test.ts src/current-traceability.test.ts
npm --prefix docs/spec/vectors/generator run build:current
```

Expected: zero invariant, semantic-reason, profile, owner, case, graph, and specification-reference issues; dynamic counts are asserted from the catalog rather than copied historical literals.

- [ ] **Step 7: Run full source gates without snapshot mutation**

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run draft:check
npm --prefix docs/spec/vectors/generator run snapshot-check
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
scripts/conformance-ci.sh
git diff --check
```

The history-bound snapshot gate must reproduce its checked-in source/snapshot; it must not regenerate rolling snapshot files from this source.

- [ ] **Step 8: Audit protected scope and commit**

Confirm no generated vector, snapshot, projection, baseline, report, DEBT, package/lock, ADR lifecycle, or release path changed. Stage the five preserved Task 10 files plus the exact current-vector family/test integrations and commit:

```bash
git add docs/spec/vectors/generator/src/current-vectors/boundary-runners.ts docs/spec/vectors/generator/src/current-vectors/case-contracts.ts docs/spec/vectors/generator/src/current-vectors/index.ts docs/spec/vectors/generator/src/current-vectors/semantic-certificates.test.ts docs/spec/vectors/generator/src/current-vectors/semantic-certificates.ts docs/spec/vectors/generator/src/current-vectors/assurance.ts docs/spec/vectors/generator/src/current-vectors/comms.ts docs/spec/vectors/generator/src/current-vectors/control.ts docs/spec/vectors/generator/src/current-vectors/core.ts docs/spec/vectors/generator/src/current-vectors/social.ts docs/spec/vectors/generator/src/current-vectors/workspace.ts docs/spec/vectors/generator/src/current-vectors.test.ts docs/spec/vectors/generator/src/coverage.test.ts
git commit -m "fix: certify executable security authority"
```

- [ ] **Step 9: Request final independent review**

Review the complete addendum range for authority opacity, exact capture, cryptographic/state binding, durability/replay, no false semantic evidence, registry-history integrity, defensive-test framing, protected artifact scope, and all required gates. Fix every Critical/Important finding through the bounded review loop before returning to the parent plan's Task 11.
