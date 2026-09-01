import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { injectAgentAttribution } from "./agent-authorship.js";
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
  type NostrSignedEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";
import type { CurrentControlFrameVerificationContext } from "./profile-negotiation.js";

type ResetReason =
  | "control-compromise-reset-evidence-invalid"
  | "control-compromise-reset-inventory-mismatch"
  | "control-compromise-reset-unauthenticated"
  | "control-subordinate-reauthorization-required";

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

type EvidenceRecord = Readonly<{
  boundary: Function;
  input: object;
  results: WeakSet<object>;
}>;

const EVIDENCE_TERMINALS = new WeakMap<object, EvidenceRecord>();
const SIGNER_TERMINALS = new WeakMap<object, Map<string, ControlSecurityEvidenceTerminal>>();

function mintTerminal(
  boundary: Function,
  input: object,
  result: object,
): ControlSecurityEvidenceTerminal {
  const terminal = Object.freeze({});
  EVIDENCE_TERMINALS.set(terminal, {
    boundary,
    input,
    results: new WeakSet([result]),
  });
  return terminal;
}

export function isControlSecurityEvidenceTerminal(
  terminal: ControlSecurityEvidenceTerminal,
  boundary: Function,
  input: object,
  result: object,
): boolean {
  const retained = EVIDENCE_TERMINALS.get(terminal);
  return retained !== undefined
    && retained.boundary === boundary
    && retained.input === input
    && retained.results.has(result);
}

const FRAME_SECRET = "21".repeat(32);
const FRAME_SENDER = getPublicKey(FRAME_SECRET);
const FRAME_GROUP = "31".repeat(32);
const FRAME_REQUEST_DIGEST = "41".repeat(32);
const FRAME_NOW = 1_800_000_000;

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
  const frame = {
    version: overrides.version ?? "heterodyne/0.6.0",
    profile: overrides.profile ?? "human-jsonrpc",
    frame_type: "request",
    request_id: overrides.request_id ?? "control-evidence-request",
    expires_at: now + 60,
    payload: {
      group_id: overrides.group_id ?? FRAME_GROUP,
      request_digest: overrides.request_digest ?? FRAME_REQUEST_DIGEST,
      body: overrides.body ?? { method: "status" },
    },
  };
  const unsigned: NostrUnsignedEvent = {
    pubkey: FRAME_SENDER,
    created_at: now,
    kind: 31017,
    tags: [],
    content: jcsCanonicalize(frame),
  };
  const id = getEventId(unsigned);
  const event: NostrSignedEvent = {
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(FRAME_SECRET), "00".repeat(32))),
  };
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
): NostrSignedEvent {
  const id = getEventId(unsigned);
  return {
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(secret), "00".repeat(32))),
  };
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
  const result = validateCompromiseReset(fixture.input);
  return Object.freeze({
    input: fixture.input,
    result,
    terminal: mintTerminal(validateCompromiseReset, fixture.input, result),
  });
}

const SIGNER_PERSONA_SECRET = "13".repeat(32);
const SIGNER_AGENT_SECRET = "14".repeat(32);
const SIGNER_PERSONA = getPublicKey(SIGNER_PERSONA_SECRET);
const SIGNER_AGENT = getPublicKey(SIGNER_AGENT_SECRET);

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
  const signerExecution = new ReferenceSignerExecutionFence<NostrSignedEvent>(
    new ReferenceSignerExecutionStore<NostrSignedEvent>(),
    (_event: NostrUnsignedEvent): NostrSignedEvent => {
      throw new Error("synthetic local signer outcome unknown");
    },
  );
  return {
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
}

export function controlSignerEvidenceFixture(): ControlSignerEvidenceFixture {
  return Object.freeze({
    input: buildSignerInput(),
    expected_reason: "control-signer-effect-indeterminate",
  });
}

export function executeControlSignerEvidenceFixture(
  fixture: ControlSignerEvidenceFixture,
): ControlSignerEvidenceExecution {
  const result = executePersistedAutomatedSigning(fixture.input);
  let terminal: ControlSecurityEvidenceTerminal;
  if (result.verdict === "indeterminate") {
    let byDigest = SIGNER_TERMINALS.get(fixture.input);
    if (byDigest === undefined) {
      byDigest = new Map();
      SIGNER_TERMINALS.set(fixture.input, byDigest);
    }
    const digest = result.completion_transition.failure_digest;
    const retained = byDigest.get(digest);
    if (retained === undefined) {
      terminal = mintTerminal(
        executePersistedAutomatedSigning,
        fixture.input,
        result,
      );
      byDigest.set(digest, terminal);
    } else {
      terminal = retained;
      EVIDENCE_TERMINALS.get(terminal)?.results.add(result);
    }
  } else {
    terminal = mintTerminal(executePersistedAutomatedSigning, fixture.input, result);
  }
  return Object.freeze({ input: fixture.input, result, terminal });
}
