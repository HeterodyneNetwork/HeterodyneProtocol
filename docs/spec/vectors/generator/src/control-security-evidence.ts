import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { injectAgentAttribution } from "./agent-authorship.js";
import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";
import {
  compromiseResetCompletionProofBytes,
  compromiseResetEvidenceBundleDigest,
  compromiseResetGrantProofBytes,
  compromiseResetInventoryDigest,
  executePersistedAutomatedSigning,
  nip46OperationId,
  nip46RequestDigest,
  ReferenceSignerExecutionFence,
  ReferenceSignerExecutionStore,
  signerGrantProofBytes,
  signerGrantStateDigest,
  signingExecutionToken,
  validateCompromiseReset,
  type AutomatedPublication,
  type CompromiseResetCompletion,
  type CompromiseResetEvidence,
  type CompromiseResetGrant,
  type CompromiseResetInventory,
  type Nip46SigningRequest,
  type SigningGrant,
} from "./control-signing.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  getEventId,
  getPublicKey,
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";
import {
  currentControlFrameRequestDigest,
  type CurrentControlFrameVerificationContext,
} from "./profile-negotiation.js";

type ResetReason =
  | "control-compromise-reset-evidence-invalid"
  | "control-compromise-reset-inventory-mismatch"
  | "control-compromise-reset-unauthenticated"
  | "control-subordinate-reauthorization-required";

const RESET_REASONS: readonly ResetReason[] = [
  "control-compromise-reset-evidence-invalid",
  "control-compromise-reset-inventory-mismatch",
  "control-compromise-reset-unauthenticated",
  "control-subordinate-reauthorization-required",
];

export type ControlResetEvidenceFixture = Readonly<{
  input: Parameters<typeof validateCompromiseReset>[0];
  expected_reason: ResetReason;
}>;

export type ControlSignerEvidenceFixture = Readonly<{
  input: Parameters<typeof executePersistedAutomatedSigning>[0];
  expected_reason: "control-signer-effect-indeterminate";
}>;

export type ControlSecurityEvidenceTerminal = Readonly<Record<never, never>>;

type ResetResult = ReturnType<typeof validateCompromiseReset>;
type SignerResult = ReturnType<typeof executePersistedAutomatedSigning>;

export type ControlResetEvidenceExecution = Readonly<{
  input: ControlResetEvidenceFixture["input"];
  result: ResetResult;
  terminal: ControlSecurityEvidenceTerminal;
}>;

export type ControlSignerEvidenceExecution = Readonly<{
  input: ControlSignerEvidenceFixture["input"];
  result: SignerResult;
  terminal: ControlSecurityEvidenceTerminal;
}>;

function captureResetEvidenceFixture(
  fixture: ControlResetEvidenceFixture,
): ControlResetEvidenceFixture {
  const captured = captureExactDataObject(fixture, [["expected_reason", "input"]],
    "Control reset evidence fixture");
  if (
    captured.input === null
    || typeof captured.input !== "object"
    || typeof captured.expected_reason !== "string"
    || !RESET_REASONS.includes(captured.expected_reason as ResetReason)
  ) throw new Error("Control reset evidence fixture is invalid");
  return captured as ControlResetEvidenceFixture;
}

function captureSignerEvidenceFixture(
  fixture: ControlSignerEvidenceFixture,
): ControlSignerEvidenceFixture {
  const captured = captureExactDataObject(fixture, [["expected_reason", "input"]],
    "Control signer evidence fixture");
  if (
    captured.input === null
    || typeof captured.input !== "object"
    || captured.expected_reason !== "control-signer-effect-indeterminate"
  ) throw new Error("Control signer evidence fixture is invalid");
  return captured as ControlSignerEvidenceFixture;
}

type EvidenceBoundary = typeof validateCompromiseReset
  | typeof executePersistedAutomatedSigning;

type BoundaryInputCapture = Readonly<{
  snapshot: unknown;
  signer_execution: object | null;
}>;

type SignerSecurityInputSnapshot = Readonly<{
  authorization: Parameters<typeof executePersistedAutomatedSigning>[0]["authorization"];
  publication: Parameters<typeof executePersistedAutomatedSigning>[0]["publication"];
}>;

type EvidenceRecord = Readonly<{
  boundary: EvidenceBoundary;
  boundary_id: string;
  input: object;
  result: object;
  input_snapshot: unknown;
  result_snapshot: unknown;
  signer_execution: object | null;
  input_digest: string;
  result_digest: string;
  binding_digest: string;
}>;

const EVIDENCE_TERMINALS = new WeakMap<object, EvidenceRecord>();

function boundaryIdentifier(boundary: Function): string | undefined {
  if (boundary === validateCompromiseReset) {
    return "control-signing.validateCompromiseReset";
  }
  if (boundary === executePersistedAutomatedSigning) {
    return "control-signing.executePersistedAutomatedSigning";
  }
  return undefined;
}

function captureBoundaryInput(
  boundary: EvidenceBoundary,
  input: object,
): BoundaryInputCapture {
  if (boundary === validateCompromiseReset) {
    const captured = captureExactDataObject(input, [[
      "authoritative_evidence",
      "authoritative_inventory",
      "completion",
      "grant",
      "now",
      "pinned_assurance_authority",
    ]], "Control reset evidence input");
    return Object.freeze({
      snapshot: snapshotClosedDataTree(captured, "Control reset evidence input"),
      signer_execution: null,
    });
  }
  const captured = captureExactDataObject(input, [[
    "authorization",
    "publication",
    "signer_execution",
  ]], "Control signer evidence input");
  if (
    captured.signer_execution === null
    || typeof captured.signer_execution !== "object"
  ) throw new Error("Control signer evidence input requires a signer capability");
  return Object.freeze({
    snapshot: snapshotClosedDataTree({
      authorization: captured.authorization,
      publication: captured.publication,
    }, "Control signer evidence security input"),
    signer_execution: captured.signer_execution,
  });
}

function evidenceDigest(domain: string, value: unknown): string {
  return createHash("sha256").update(proofBytes(domain, value)).digest("hex");
}

function mintTerminal(
  boundary: EvidenceBoundary,
  input: object,
  inputCapture: BoundaryInputCapture,
  result: object,
): ControlSecurityEvidenceTerminal {
  const boundaryId = boundaryIdentifier(boundary);
  if (boundaryId === undefined) throw new Error("unsupported Control evidence boundary");
  const resultSnapshot = snapshotClosedDataTree(result, "Control evidence result");
  const inputDigest = evidenceDigest(
    "heterodyne-control-security-evidence-input-v1",
    { boundary_id: boundaryId, input: inputCapture.snapshot },
  );
  const resultDigest = evidenceDigest(
    "heterodyne-control-security-evidence-result-v1",
    { boundary_id: boundaryId, result: resultSnapshot },
  );
  const bindingDigest = evidenceDigest(
    "heterodyne-control-security-evidence-binding-v1",
    {
      boundary_id: boundaryId,
      input_digest: inputDigest,
      result_digest: resultDigest,
    },
  );
  const terminal = Object.freeze({});
  EVIDENCE_TERMINALS.set(terminal, Object.freeze({
    boundary,
    boundary_id: boundaryId,
    input,
    result,
    input_snapshot: inputCapture.snapshot,
    result_snapshot: resultSnapshot,
    signer_execution: inputCapture.signer_execution,
    input_digest: inputDigest,
    result_digest: resultDigest,
    binding_digest: bindingDigest,
  }));
  return terminal;
}

export function isControlSecurityEvidenceTerminal(
  terminal: ControlSecurityEvidenceTerminal,
  boundary: Function,
  input: object,
  result: object,
): boolean {
  const retained = EVIDENCE_TERMINALS.get(terminal);
  if (
    retained === undefined
    || retained.boundary !== boundary
    || retained.input !== input
    || retained.result !== result
  ) return false;
  try {
    const boundaryId = boundaryIdentifier(boundary);
    if (boundaryId === undefined || boundaryId !== retained.boundary_id) return false;
    const currentInput = captureBoundaryInput(retained.boundary, input);
    if (currentInput.signer_execution !== retained.signer_execution) return false;
    const currentResult = snapshotClosedDataTree(result, "Control evidence result");
    const inputDigest = evidenceDigest(
      "heterodyne-control-security-evidence-input-v1",
      { boundary_id: boundaryId, input: currentInput.snapshot },
    );
    const resultDigest = evidenceDigest(
      "heterodyne-control-security-evidence-result-v1",
      { boundary_id: boundaryId, result: currentResult },
    );
    const bindingDigest = evidenceDigest(
      "heterodyne-control-security-evidence-binding-v1",
      {
        boundary_id: boundaryId,
        input_digest: inputDigest,
        result_digest: resultDigest,
      },
    );
    return inputDigest === retained.input_digest
      && resultDigest === retained.result_digest
      && bindingDigest === retained.binding_digest
      && evidenceDigest("heterodyne-control-security-evidence-input-v1", {
        boundary_id: boundaryId,
        input: retained.input_snapshot,
      }) === retained.input_digest
      && evidenceDigest("heterodyne-control-security-evidence-result-v1", {
        boundary_id: boundaryId,
        result: retained.result_snapshot,
      }) === retained.result_digest;
  } catch {
    return false;
  }
}

const FRAME_SECRET = "21".repeat(32);
const FRAME_SENDER = getPublicKey(FRAME_SECRET);
const FRAME_GROUP = "31".repeat(32);
const FRAME_NOW = 1_800_000_000;
const FRAME_REQUEST_ID = "control-evidence-request";
const FRAME_EXPIRES_AT = FRAME_NOW + 60;
const FRAME_BODY = Object.freeze({
  id: FRAME_REQUEST_ID,
  method: "status",
  params: {},
  expires_at: FRAME_EXPIRES_AT,
});
const FRAME_REQUEST_DIGEST = currentControlFrameRequestDigest({
  profile: "human-jsonrpc",
  version: "heterodyne/0.6.0",
  group_id: FRAME_GROUP,
  sender: FRAME_SENDER,
  request_id: FRAME_REQUEST_ID,
  expires_at: FRAME_EXPIRES_AT,
  body: FRAME_BODY,
});

export function controlFrameContext(
  overrides: Partial<CurrentControlFrameVerificationContext> = {},
): CurrentControlFrameVerificationContext {
  return Object.freeze({
    expected_profile: "human-jsonrpc",
    expected_version: "heterodyne/0.6.0",
    expected_group_id: FRAME_GROUP,
    expected_sender: FRAME_SENDER,
    expected_request_digest: FRAME_REQUEST_DIGEST,
    trusted_now: FRAME_NOW,
    ...overrides,
  });
}

export function signedControlFrameBytes(overrides: Readonly<{
  profile?: string;
  version?: string;
  group_id?: string;
  request_id?: string;
  request_digest?: string;
  trusted_now?: number;
  body?: Readonly<Record<string, unknown>>;
}> = {}): Uint8Array {
  const now = overrides.trusted_now ?? FRAME_NOW;
  const profile = overrides.profile ?? "human-jsonrpc";
  const version = overrides.version ?? "heterodyne/0.6.0";
  const groupId = overrides.group_id ?? FRAME_GROUP;
  const requestId = overrides.request_id ?? FRAME_REQUEST_ID;
  const expiresAt = now + 60;
  const body = overrides.body ?? {
    id: requestId,
    method: "status",
    params: {},
    expires_at: expiresAt,
  };
  const requestDigest = currentControlFrameRequestDigest({
    profile,
    version,
    group_id: groupId,
    sender: FRAME_SENDER,
    request_id: requestId,
    expires_at: expiresAt,
    body,
  });
  const frame = {
    version,
    profile,
    frame_type: "request",
    request_id: requestId,
    expires_at: expiresAt,
    payload: {
      group_id: groupId,
      request_digest: overrides.request_digest ?? requestDigest,
      body,
    },
  };
  const unsigned: NostrUnsignedEvent = {
    pubkey: FRAME_SENDER,
    created_at: now,
    kind: 31017,
    tags: [],
    content: jcsCanonicalize(frame),
  };
  const event = signNostrEvent(unsigned, FRAME_SECRET);
  return new TextEncoder().encode(JSON.stringify(event));
}

const RESET_PERSONA_SECRET = "11".repeat(32);
const RESET_SUCCESSOR_SECRET = "12".repeat(32);
const RESET_PERSONA = getPublicKey(RESET_PERSONA_SECRET);
const RESET_SUCCESSOR = getPublicKey(RESET_SUCCESSOR_SECRET);

function hexId(value: number): string {
  return value.toString(16).padStart(64, "0");
}

function signResetGrant(
  unsigned: Omit<CompromiseResetGrant, "signature">,
): CompromiseResetGrant {
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      compromiseResetGrantProofBytes(unsigned),
      hexToBytes(RESET_PERSONA_SECRET),
      "00".repeat(32),
    )),
  };
}

function signResetCompletion(
  unsigned: Omit<CompromiseResetCompletion, "signature">,
): CompromiseResetCompletion {
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      compromiseResetCompletionProofBytes(unsigned),
      hexToBytes(RESET_SUCCESSOR_SECRET),
      "00".repeat(32),
    )),
  };
}

function signNostrEvent(
  unsigned: NostrUnsignedEvent,
  secret: string,
): VerifiedNostrEvent {
  const id = getEventId(unsigned);
  const event = snapshotAndVerifyNostrEvent({
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(secret), "00".repeat(32))),
  });
  if (event === null) throw new Error("synthetic Nostr fixture signing invariant failed");
  return event;
}

function buildResetInput(
  reason: ResetReason,
): Parameters<typeof validateCompromiseReset>[0] {
  const subordinateSubjectId = hexId(6);
  const subordinateId = hexId(7);
  const requiresSubordinate = reason === "control-subordinate-reauthorization-required";
  const subordinate_authority_ids = requiresSubordinate ? [subordinateId] : [];
  const requiredReset = {
    nip46_oidc_grant_ids: [],
    client_ids: requiresSubordinate ? [subordinateSubjectId] : [],
    repository_ids: [],
    delegate_ids: [],
    node_ids: [],
    agent_ids: [],
    trusted_seed_nids: [],
    marmot_leaf_ids: [],
    reachable_groups: [],
    unreachable_group_ids: [],
    subordinate_authority_ids,
  };
  const inventory: CompromiseResetInventory = {
    inventory_id: hexId(1),
    revision: 1,
    observed_at: 100,
    persona_active_key: RESET_PERSONA,
    ...structuredClone(requiredReset),
    reachable_groups: [],
    existing_transition_ids: [],
    existing_keypackage_event_ids: [],
    authorization_records: requiresSubordinate ? [{
      authority_class: "client" as const,
      subject_id: subordinateSubjectId,
      authorization_id: subordinateId,
      authorization_digest: hexId(11),
    }] : [],
  };
  const inventoryDigest = compromiseResetInventoryDigest(inventory);
  const grant = signResetGrant({
    profile: "heterodyne.control.compromise-reset-grant.v1",
    spec_version: "heterodyne/0.6.0",
    recovery_id: hexId(2),
    persona_active_key: RESET_PERSONA,
    successor_active_key: RESET_SUCCESSOR,
    authorization_class: reason === "control-compromise-reset-unauthenticated"
      ? "assurance-recovery"
      : "active-account",
    authorizing_pubkey: RESET_PERSONA,
    assurance_head: reason === "control-compromise-reset-unauthenticated"
      ? hexId(3)
      : null,
    inventory_id: inventory.inventory_id,
    inventory_revision: inventory.revision,
    inventory_digest: inventoryDigest,
    compromise_at: 100,
    required_reset: requiredReset,
    issued_at: 101,
    expires_at: 200,
    state: "active",
    revoked_at: null,
  });
  const keyPackageBytes = Buffer.from("synthetic-local-keypackage", "utf8");
  const keyPackageEvent = signNostrEvent({
    pubkey: RESET_SUCCESSOR,
    created_at: 109,
    kind: 30443,
    tags: [["d", hexId(8)], ["mls_protocol_version", "1.0"], ["i", hexId(9)]],
    content: keyPackageBytes.toString("base64"),
  }, RESET_SUCCESSOR_SECRET) as CompromiseResetCompletion["fresh_keypackages"][number]["event"];
  const freshKeyPackage: CompromiseResetCompletion["fresh_keypackages"][number] = {
    keypackage_id: hexId(9),
    account_key: RESET_SUCCESSOR,
    group_id: hexId(10),
    event_id: keyPackageEvent.id,
    event: keyPackageEvent,
    content_sha256: createHash("sha256").update(keyPackageBytes).digest("hex"),
    mls_verifier_pubkey: RESET_PERSONA,
    verification_signature: "00".repeat(64),
  };
  const transitionEvidence: CompromiseResetCompletion["transition_evidence"] = {
    nip46_oidc_grants: [],
    clients: [],
    repositories: [],
    delegates: [],
    nodes: [],
    agents: [],
    trusted_seeds: [],
    marmot_leaves: [],
    groups: [],
    stalled_groups: [],
  };
  const evidenceBundle: CompromiseResetEvidence["evidence_bundle"] = {
    state_transitions: [],
    group_commits: [],
  };
  const evidenceRevision = reason === "control-compromise-reset-evidence-invalid" ? 3 : 2;
  const completion = signResetCompletion({
    profile: "heterodyne.control.compromise-reset-completion.v1",
    spec_version: "heterodyne/0.6.0",
    recovery_id: grant.recovery_id,
    persona_active_key: grant.persona_active_key,
    successor_active_key: grant.successor_active_key,
    inventory_id: grant.inventory_id,
    inventory_revision: grant.inventory_revision,
    inventory_digest: grant.inventory_digest,
    evidence_revision: evidenceRevision,
    revoked_nip46_oidc_grant_ids: [],
    invalidated_client_ids: requiredReset.client_ids,
    invalidated_repository_ids: [],
    invalidated_delegate_ids: [],
    invalidated_node_ids: [],
    invalidated_agent_ids: [],
    invalidated_trusted_seed_nids: [],
    removed_marmot_leaf_ids: [],
    advanced_group_ids: [],
    stalled_group_ids: [],
    fresh_keypackages: [freshKeyPackage],
    subordinate_reauthorizations: [],
    transition_evidence: transitionEvidence,
    evidence_bundle_digest: compromiseResetEvidenceBundleDigest(evidenceBundle),
    completed_at: 110,
    signer: RESET_SUCCESSOR,
  });
  const evidence: CompromiseResetEvidence = {
    inventory_id: completion.inventory_id,
    inventory_revision: completion.inventory_revision,
    evidence_revision: completion.evidence_revision,
    observed_at: 110,
    transition_evidence: completion.transition_evidence,
    fresh_keypackages: completion.fresh_keypackages,
    subordinate_reauthorizations: completion.subordinate_reauthorizations,
    evidence_bundle: evidenceBundle,
  };
  return {
    grant,
    completion,
    authoritative_inventory: reason === "control-compromise-reset-inventory-mismatch"
      ? { ...inventory, inventory_id: hexId(4) }
      : inventory,
    authoritative_evidence: evidence,
    pinned_assurance_authority: null,
    now: 110,
  };
}

export function controlResetEvidenceFixtures(): readonly ControlResetEvidenceFixture[] {
  return [
    "control-compromise-reset-evidence-invalid",
    "control-compromise-reset-inventory-mismatch",
    "control-compromise-reset-unauthenticated",
    "control-subordinate-reauthorization-required",
  ].map((expected_reason) => Object.freeze({
    input: buildResetInput(expected_reason as ResetReason),
    expected_reason: expected_reason as ResetReason,
  }));
}

export function executeControlResetEvidenceFixture(
  fixture: ControlResetEvidenceFixture,
): ControlResetEvidenceExecution {
  const capturedFixture = captureResetEvidenceFixture(fixture);
  const input = capturedFixture.input;
  const inputCapture = captureBoundaryInput(validateCompromiseReset, input);
  const result = validateCompromiseReset(input);
  return Object.freeze({
    input,
    result,
    terminal: mintTerminal(
      validateCompromiseReset,
      input,
      inputCapture,
      result,
    ),
  });
}

const SIGNER_PERSONA_SECRET = "13".repeat(32);
const SIGNER_AGENT_SECRET = "14".repeat(32);
const SIGNER_PERSONA = getPublicKey(SIGNER_PERSONA_SECRET);
const SIGNER_AGENT = getPublicKey(SIGNER_AGENT_SECRET);

type SignerFixtureState = Readonly<{
  store: ReferenceSignerExecutionStore<NostrSignedEvent>;
  key_operation: (event: NostrUnsignedEvent) => NostrSignedEvent;
  invocation_count: () => number;
  signer_execution: object;
}>;

const SIGNER_FIXTURE_STATES = new WeakMap<object, SignerFixtureState>();

function requireSignerFixtureState(
  input: object,
  inputCapture: BoundaryInputCapture,
): SignerFixtureState {
  const state = SIGNER_FIXTURE_STATES.get(input);
  if (
    state === undefined
    || state.signer_execution !== inputCapture.signer_execution
  ) throw new Error("unknown Control signer evidence fixture");
  return state;
}

function buildSignerInput(): Parameters<typeof executePersistedAutomatedSigning>[0] {
  const automationPolicy = {
    workload_id: hexId(20),
    agent_class: "ai" as const,
    agent_association: { kind: "key" as const, value: SIGNER_AGENT },
    tier: 1 as const,
    oidc_scopes: [] as string[],
  };
  const unsignedGrant: Omit<SigningGrant, "signature"> = {
    profile: "heterodyne.control.signer-grant.v1",
    spec_version: "heterodyne/0.6.0",
    grant_id: hexId(21),
    vault_id: hexId(22),
    persona_active_key: SIGNER_PERSONA,
    nip46_client_pubkey: hexId(23),
    signer_audience: "https://node.invalid/nip46/synthetic-local",
    selected_signing_pubkey: SIGNER_AGENT,
    key_class: "agent",
    persona_signing_authorized: false,
    allowed_methods: ["sign_event"],
    allowed_event_kinds: [1],
    limits: {
      request_window_seconds: 60,
      request_count: 2,
      max_event_bytes: 4096,
      max_value_msats: 0,
    },
    oidc_authorization_id: hexId(24),
    connection_secret_sha256: hexId(25),
    automation_policy: automationPolicy,
    issued_at: 100,
    expires_at: 200,
    predecessor: null,
    state: "active",
    revoked_at: null,
    authorizing_pubkey: SIGNER_PERSONA,
  };
  const grant: SigningGrant = {
    ...unsignedGrant,
    signature: bytesToHex(schnorr.sign(
      signerGrantProofBytes(unsignedGrant),
      hexToBytes(SIGNER_PERSONA_SECRET),
      "00".repeat(32),
    )),
  };
  const publication: AutomatedPublication = {
    profile: "heterodyne.control.agent-publish-intent.v1",
    spec_version: "heterodyne/0.6.0",
    grant_id: grant.grant_id,
    vault_id: grant.vault_id,
    persona_active_key: grant.persona_active_key,
    nip46_client_pubkey: grant.nip46_client_pubkey,
    signer_audience: grant.signer_audience,
    selected_signing_pubkey: grant.selected_signing_pubkey,
    key_class: grant.key_class,
    created_at: 111,
    kind: 1,
    tags: [["t", "synthetic-local"]],
    content: "BLUE TEAM VALIDATION: synthetic/local",
    value_msats: 0,
    agent_class: automationPolicy.agent_class,
    agent_association: automationPolicy.agent_association,
    tier: automationPolicy.tier,
  };
  const attribution = injectAgentAttribution({
    kind: publication.kind,
    tags: publication.tags,
    agent_class: automationPolicy.agent_class,
    persona: grant.persona_active_key,
    signer: grant.selected_signing_pubkey,
    expected_signer: grant.selected_signing_pubkey,
    signer_key_class: grant.key_class,
    oidc_scopes: automationPolicy.oidc_scopes,
    agent_association: automationPolicy.agent_association,
    expected_agent_association: automationPolicy.agent_association,
    tier: automationPolicy.tier,
  });
  if (attribution.verdict !== "accept") throw new Error("synthetic signer fixture invalid");
  const request: Nip46SigningRequest = {
    grant_id: grant.grant_id,
    vault_id: grant.vault_id,
    persona_active_key: grant.persona_active_key,
    nip46_client_pubkey: grant.nip46_client_pubkey,
    signer_audience: grant.signer_audience,
    selected_signing_pubkey: grant.selected_signing_pubkey,
    key_class: grant.key_class,
    rpc_request: {
      id: "synthetic-local-request",
      method: "sign_event",
      params: [jcsCanonicalize({
        created_at: publication.created_at,
        kind: publication.kind,
        tags: attribution.tags,
        content: publication.content,
      })],
    },
    value_msats: 0,
    now: 110,
  };
  const requestDigest = nip46RequestDigest(grant, request);
  const authority = {
    vault_id: grant.vault_id,
    persona_active_key: grant.persona_active_key,
    nip46_client_pubkey: grant.nip46_client_pubkey,
    signer_audience: grant.signer_audience,
    selected_signing_pubkey: grant.selected_signing_pubkey,
    key_class: grant.key_class,
  };
  const usageState = {
    grant_id: grant.grant_id,
    grant_digest: signerGrantStateDigest(grant),
    authority,
    window_started_at: 100,
    consumed_request_count: 1,
    revision: 7,
    reservations: [{
      operation_id: nip46OperationId(grant, request.rpc_request.id),
      request_id: request.rpc_request.id,
      request_digest: requestDigest,
      rpc_request: request.rpc_request,
      value_msats: request.value_msats,
      window_started_at: 100,
      reserved_at: request.now,
      claimed_at: request.now,
      executing_at: request.now,
      completed_at: null,
      state: "executing" as const,
      execution_token: signingExecutionToken(grant, requestDigest),
      result_event_id: null,
      failure_digest: null,
    }],
  };
  const store = new ReferenceSignerExecutionStore<NostrSignedEvent>();
  let invocationCount = 0;
  const keyOperation = (_event: NostrUnsignedEvent): NostrSignedEvent => {
    invocationCount += 1;
    throw new Error("synthetic local signer outcome unknown");
  };
  const signerExecution = new ReferenceSignerExecutionFence<NostrSignedEvent>(
    store,
    keyOperation,
  );
  const input: Parameters<typeof executePersistedAutomatedSigning>[0] = {
    authorization: {
      grant_candidates: [grant],
      usage_state: usageState,
      presented_grant: structuredClone(grant),
      vaults: [{
        vault_id: grant.vault_id,
        persona_active_key: grant.persona_active_key,
        signers: [{
          public_key: grant.selected_signing_pubkey,
          key_class: grant.key_class,
          custody: "local",
        }],
      }],
      request,
      client_metadata: {
        requested_methods: ["sign_event"],
        requested_event_kinds: [1],
        requested_signer_audiences: [grant.signer_audience],
      },
    },
    publication,
    signer_execution: signerExecution,
  };
  SIGNER_FIXTURE_STATES.set(input, Object.freeze({
    store,
    key_operation: keyOperation,
    invocation_count: () => invocationCount,
    signer_execution: signerExecution,
  }));
  return input;
}

export function controlSignerEvidenceFixture(): ControlSignerEvidenceFixture {
  return Object.freeze({
    input: buildSignerInput(),
    expected_reason: "control-signer-effect-indeterminate",
  });
}

export function reconstructControlSignerEvidenceFixture(
  fixture: ControlSignerEvidenceFixture,
): ControlSignerEvidenceFixture {
  const capturedFixture = captureSignerEvidenceFixture(fixture);
  const input = capturedFixture.input;
  const inputCapture = captureBoundaryInput(executePersistedAutomatedSigning, input);
  const securityInput = inputCapture.snapshot as SignerSecurityInputSnapshot;
  const state = requireSignerFixtureState(input, inputCapture);
  const signerExecution = new ReferenceSignerExecutionFence<NostrSignedEvent>(
    state.store,
    state.key_operation,
  );
  const reconstructedInput = {
    authorization: securityInput.authorization,
    publication: securityInput.publication,
    signer_execution: signerExecution,
  };
  SIGNER_FIXTURE_STATES.set(reconstructedInput, Object.freeze({
    ...state,
    signer_execution: signerExecution,
  }));
  return Object.freeze({
    input: reconstructedInput,
    expected_reason: capturedFixture.expected_reason,
  });
}

export function controlSignerInvocationCount(
  fixture: ControlSignerEvidenceFixture,
): number {
  const capturedFixture = captureSignerEvidenceFixture(fixture);
  const input = capturedFixture.input;
  const inputCapture = captureBoundaryInput(executePersistedAutomatedSigning, input);
  const state = requireSignerFixtureState(input, inputCapture);
  return state.invocation_count();
}

export function executeControlSignerEvidenceFixture(
  fixture: ControlSignerEvidenceFixture,
): ControlSignerEvidenceExecution {
  const capturedFixture = captureSignerEvidenceFixture(fixture);
  const input = capturedFixture.input;
  const inputCapture = captureBoundaryInput(
    executePersistedAutomatedSigning,
    input,
  );
  requireSignerFixtureState(input, inputCapture);
  const result = executePersistedAutomatedSigning(input);
  const terminal = mintTerminal(
    executePersistedAutomatedSigning,
    input,
    inputCapture,
    result,
  );
  return Object.freeze({ input, result, terminal });
}
