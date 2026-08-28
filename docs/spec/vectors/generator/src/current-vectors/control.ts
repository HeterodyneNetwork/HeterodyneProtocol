import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import {
  evaluateAuthorizationFreshness,
  revalidateAuthorizationViewAtEffect,
  type AuthorizationFreshnessAuthority,
} from "../authorization-freshness.js";
import {
  authorizeNip46Signing,
  consumeNip46ConnectionSecret,
  executePersistedAutomatedSigning,
  prepareAutomatedSigning,
  signerGrantProofBytes,
  signerGrantStateDigest,
  validateCompromiseReset,
  type AutomatedPublication,
  type SigningGrant,
} from "../control-signing.js";
import {
  evaluateAutomatedControlGrant,
  evaluateCompromiseResetBoundary,
  evaluateControlEnrollmentBoundary,
  evaluateControlOperationRequest,
  evaluateDeviceCodeBoundary,
  validateControlFrameBoundary,
  validateControlSignedEffect,
  validateInvitePreauthorizationBoundary,
} from "../control-policy.js";
import { injectAgentAttribution } from "../agent-authorship.js";
import { QUALIFIED_VERSION } from "../family.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { getPublicKey } from "../nostr.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const normalizeReason = <T extends Record<string, unknown>>(value: T): Record<string, unknown> =>
  "reason" in value ? (() => {
    const { reason, ...decision } = value;
    return { ...decision, reason_code: reason };
  })() : value;

function executedControlRejection(options: {
  id: string;
  boundary: string;
  anchor: string;
  invariant: string;
  reason: string;
  description: string;
  input: Readonly<Record<string, unknown>>;
  decision: Readonly<Record<string, unknown>>;
}): CurrentVectorCase {
  if (options.decision.reason_code !== options.reason) {
    throw new Error(`current Control evaluator mismatch for ${options.id}: ${String(options.decision.reason_code)}`);
  }
  const expectedOutput = options.decision.verdict === "reject"
    ? options.decision
    : {
        verdict: "reject",
        reason_code: options.reason,
        evaluator_output: options.decision,
      };
  return {
    relativePath: `control/${options.id}.json`,
    semantic_boundary: options.boundary,
    vector_id: `control/${options.id}`,
    owner_document: "control",
    spec_refs: [currentSpecRef(options.anchor)],
    invariants: [options.invariant],
    reason_codes: [options.reason],
    description: options.description,
    direction: "consume",
    input: options.input,
    expected_output: expectedOutput,
  };
}

export async function buildControlCases(): Promise<CurrentVectorCase[]> {
  const support = await buildAuthorizationFreshnessTestSupport();
  const state = support.scenario.issuerKeyEpochOneState;
  const manifest = support.signedManifest(state);
  const clock = { now: state.checkpoint.observed_at + 300 };
  const authority = support.authorityFor(manifest, state, clock);
  const prepared = evaluateAuthorizationFreshness(authority, manifest);
  if (prepared.verdict !== "accept") {
    throw new Error(`current authorization fixture rejected: ${prepared.reason}`);
  }
  const acceptedAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);
  const callerDecision = evaluateAuthorizationFreshness(
    {
      now: clock.now,
      checkpoint_fresh: true,
      authorization_view_authenticated: true,
    } as unknown as AuthorizationFreshnessAuthority,
    manifest,
  );
  clock.now += 1;
  const staleAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);

  const personaSecret = "01".repeat(32);
  const persona = getPublicKey(personaSecret);
  const agentSigner = getPublicKey("04".repeat(32));
  const client = "33".repeat(32);
  const vaultId = "66".repeat(32);
  const audience = "https://node.example/nip46/current-persona";
  const connectionSecret = "09".repeat(32);
  const unsignedGrant: Omit<SigningGrant, "signature"> = {
    profile: "heterodyne.control.signer-grant.v1",
    spec_version: QUALIFIED_VERSION,
    grant_id: "77".repeat(32),
    vault_id: vaultId,
    persona_active_key: persona,
    nip46_client_pubkey: client,
    signer_audience: audience,
    selected_signing_pubkey: agentSigner,
    key_class: "agent",
    persona_signing_authorized: false,
    allowed_methods: ["sign_event"],
    allowed_event_kinds: [1],
    limits: {
      request_window_seconds: 60,
      request_count: 20,
      max_event_bytes: 4096,
      max_value_msats: 0,
    },
    oidc_authorization_id: "88".repeat(32),
    connection_secret_sha256: createHash("sha256")
      .update(hexToBytes(connectionSecret))
      .digest("hex"),
    issued_at: 100,
    expires_at: 200,
    predecessor: null,
    state: "active",
    revoked_at: null,
    authorizing_pubkey: persona,
  };
  const signingGrant: SigningGrant = {
    ...unsignedGrant,
    signature: bytesToHex(schnorr.sign(
      signerGrantProofBytes(unsignedGrant),
      hexToBytes(personaSecret),
      "00".repeat(32),
    )),
  };
  const usageState = {
    grant_id: signingGrant.grant_id,
    grant_digest: signerGrantStateDigest(signingGrant),
    authority: {
      vault_id: signingGrant.vault_id,
      persona_active_key: signingGrant.persona_active_key,
      nip46_client_pubkey: signingGrant.nip46_client_pubkey,
      signer_audience: signingGrant.signer_audience,
      selected_signing_pubkey: signingGrant.selected_signing_pubkey,
      key_class: signingGrant.key_class,
    },
    window_started_at: 100,
    consumed_request_count: 0,
    revision: 4,
    reservations: [],
  };
  const rpcTemplate = {
    created_at: 111,
    kind: 1,
    tags: [] as string[][],
    content: "current canonical NIP-46 payload",
  };
  const signingRequest = {
    grant_id: signingGrant.grant_id,
    vault_id: vaultId,
    persona_active_key: persona,
    nip46_client_pubkey: client,
    signer_audience: audience,
    selected_signing_pubkey: agentSigner,
    key_class: "agent" as const,
    rpc_request: {
      id: "dd".repeat(32),
      method: "sign_event",
      params: [jcsCanonicalize(rpcTemplate)],
    },
    value_msats: 0,
    now: 110,
  };
  const signerAuthorization = authorizeNip46Signing({
    grant_candidates: [signingGrant],
    usage_state: usageState,
    presented_grant: structuredClone(signingGrant),
    vaults: [{
      vault_id: vaultId,
      persona_active_key: persona,
      signers: [{
        public_key: agentSigner,
        key_class: "agent" as const,
        custody: "local" as const,
      }],
    }],
    request: signingRequest,
    client_metadata: {
      requested_methods: ["sign_event"],
      requested_event_kinds: [1],
      requested_signer_audiences: [audience],
    },
  });

  const automationPolicy = {
    workload_id: "aa".repeat(32),
    agent_class: "ai" as const,
    agent_association: { kind: "key" as const, value: agentSigner },
    tier: 1 as const,
    oidc_scopes: [] as string[],
  };
  const automationGrantUnsigned: Omit<SigningGrant, "signature"> = {
    ...unsignedGrant,
    automation_policy: automationPolicy,
  };
  const automationGrant: SigningGrant = {
    ...automationGrantUnsigned,
    signature: bytesToHex(schnorr.sign(
      signerGrantProofBytes(automationGrantUnsigned),
      hexToBytes(personaSecret),
      "00".repeat(32),
    )),
  };
  const automatedPublication: AutomatedPublication = {
    profile: "heterodyne.control.agent-publish-intent.v1" as const,
    spec_version: QUALIFIED_VERSION as AutomatedPublication["spec_version"],
    grant_id: automationGrant.grant_id,
    vault_id: automationGrant.vault_id,
    persona_active_key: automationGrant.persona_active_key,
    nip46_client_pubkey: automationGrant.nip46_client_pubkey,
    signer_audience: automationGrant.signer_audience,
    selected_signing_pubkey: automationGrant.selected_signing_pubkey,
    key_class: automationGrant.key_class,
    created_at: 111,
    kind: 1,
    tags: [["t", "heterodyne"]],
    content: "current bounded automated publication",
    value_msats: 0,
    agent_class: automationPolicy.agent_class,
    agent_association: automationPolicy.agent_association,
    tier: automationPolicy.tier,
  };
  const automatedAttribution = injectAgentAttribution({
    kind: automatedPublication.kind,
    tags: automatedPublication.tags,
    agent_class: automationPolicy.agent_class,
    persona: automationGrant.persona_active_key,
    signer: automationGrant.selected_signing_pubkey,
    expected_signer: automationGrant.selected_signing_pubkey,
    signer_key_class: automationGrant.key_class,
    oidc_scopes: automationPolicy.oidc_scopes,
    agent_association: automationPolicy.agent_association,
    expected_agent_association: automationPolicy.agent_association,
    tier: automationPolicy.tier,
  });
  if (automatedAttribution.verdict !== "accept") {
    throw new Error(`current automation attribution rejected: ${automatedAttribution.reason_code}`);
  }
  const automationRequest = {
    ...signingRequest,
    grant_id: automationGrant.grant_id,
    rpc_request: {
      ...signingRequest.rpc_request,
      params: [jcsCanonicalize({
        created_at: automatedPublication.created_at,
        kind: automatedPublication.kind,
        tags: automatedAttribution.tags,
        content: automatedPublication.content,
      })],
    },
  };
  const automationUsage = {
    ...usageState,
    grant_digest: signerGrantStateDigest(automationGrant),
  };
  const automationAuthorizationInput = {
    grant_candidates: [automationGrant],
    usage_state: automationUsage,
    presented_grant: structuredClone(automationGrant),
    vaults: [{
      vault_id: vaultId,
      persona_active_key: persona,
      signers: [{
        public_key: agentSigner,
        key_class: "agent" as const,
        custody: "local" as const,
      }],
    }],
    request: automationRequest,
    client_metadata: {
      requested_methods: ["sign_event"],
      requested_event_kinds: [1],
      requested_signer_audiences: [audience],
    },
  };
  const automationReservation = authorizeNip46Signing(automationAuthorizationInput);
  if (automationReservation.verdict !== "accept") {
    throw new Error(`current automation reservation rejected: ${
      "reason_code" in automationReservation
        ? automationReservation.reason_code
        : automationReservation.verdict
    }`);
  }
  const reserved = automationReservation.usage_transition;
  const persistedAutomationUsage = {
    ...automationUsage,
    window_started_at: reserved.window_started_at,
    consumed_request_count: reserved.consumed_request_count,
    revision: reserved.next_revision,
    reservations: [{
      operation_id: reserved.operation_id,
      request_id: reserved.request_id,
      request_digest: reserved.request_digest,
      rpc_request: reserved.rpc_request,
      value_msats: reserved.value_msats,
      window_started_at: reserved.window_started_at,
      reserved_at: reserved.reserved_at,
      claimed_at: null,
      executing_at: null,
      completed_at: null,
      state: "reserved" as const,
      execution_token: null,
      result_event_id: null,
      failure_digest: null,
    }],
  };
  const automatedSigningDecision = prepareAutomatedSigning({
    authorization: {
      ...automationAuthorizationInput,
      usage_state: persistedAutomationUsage,
    },
    publication: automatedPublication,
  });
  const incompleteResetInput = {
    grant: {},
    completion: {},
    authoritative_inventory: {},
    authoritative_evidence: {},
    pinned_assurance_authority: null,
    now: 130,
  };
  const incompleteResetDecision = validateCompromiseReset(incompleteResetInput as never);

  const authorize = (patch: Record<string, unknown>) => authorizeNip46Signing({
    ...{
      grant_candidates: [signingGrant],
      usage_state: usageState,
      presented_grant: structuredClone(signingGrant),
      vaults: [{
        vault_id: vaultId,
        persona_active_key: persona,
        signers: [{ public_key: agentSigner, key_class: "agent" as const, custody: "local" as const }],
      }],
      request: signingRequest,
      client_metadata: {
        requested_methods: ["sign_event"],
        requested_event_kinds: [1],
        requested_signer_audiences: [audience],
      },
    },
    ...patch,
  } as Parameters<typeof authorizeNip46Signing>[0]);
  const unauthenticatedGrant = { ...signingGrant, signature: "00".repeat(64) };
  const invalidGrantDecision = authorize({ grant_candidates: [] });
  const unauthenticatedGrantDecision = authorize({
    grant_candidates: [unauthenticatedGrant],
    presented_grant: unauthenticatedGrant,
  });
  const staleGrantDecision = authorize({ grant_candidates: [signingGrant, signingGrant] });
  const inactiveGrantDecision = authorize({ request: { ...signingRequest, now: signingGrant.expires_at } });
  const vaultIsolationDecision = authorize({ vaults: [] });
  const signerBindingDecision = authorize({
    request: { ...signingRequest, selected_signing_pubkey: "55".repeat(32) },
  });
  const signerUnavailableDecision = authorize({
    vaults: [{ vault_id: vaultId, persona_active_key: persona, signers: [] }],
  });
  const metadataWideningDecision = authorize({
    client_metadata: {
      requested_methods: ["sign_event", "get_public_key"],
      requested_event_kinds: [1],
      requested_signer_audiences: [audience],
    },
  });
  const invalidNip46Decision = authorize({
    request: {
      ...signingRequest,
      rpc_request: { ...signingRequest.rpc_request, id: "invalid\nrequest" },
    },
  });
  const usageMismatchDecision = authorize({
    usage_state: { ...usageState, grant_digest: "00".repeat(32) },
  });
  const personaGrantUnsigned: Omit<SigningGrant, "signature"> = {
    ...unsignedGrant,
    selected_signing_pubkey: persona,
    key_class: "persona",
    persona_signing_authorized: true,
    automation_policy: {
      workload_id: "aa".repeat(32),
      agent_class: "ai",
      agent_association: null,
      tier: 1,
      oidc_scopes: [],
    },
  };
  const personaGrant: SigningGrant = {
    ...personaGrantUnsigned,
    signature: bytesToHex(schnorr.sign(
      signerGrantProofBytes(personaGrantUnsigned),
      hexToBytes(personaSecret),
      "00".repeat(32),
    )),
  };
  const personaAuthorityDecision = prepareAutomatedSigning({
    authorization: {
      grant_candidates: [personaGrant],
      usage_state: {
        ...usageState,
        grant_digest: signerGrantStateDigest(personaGrant),
        authority: {
          ...usageState.authority,
          selected_signing_pubkey: persona,
          key_class: "persona",
        },
      },
      presented_grant: structuredClone(personaGrant),
      vaults: [{
        vault_id: vaultId,
        persona_active_key: persona,
        signers: [{ public_key: persona, key_class: "persona", custody: "local" }],
      }],
      request: {
        ...signingRequest,
        selected_signing_pubkey: persona,
        key_class: "persona",
      },
      client_metadata: {
        requested_methods: ["sign_event"],
        requested_event_kinds: [1],
        requested_signer_audiences: [audience],
      },
    },
    publication: {
      ...automatedPublication,
      grant_id: personaGrant.grant_id,
      selected_signing_pubkey: persona,
      key_class: "persona",
      agent_association: null,
    },
  });
  const operationIndeterminateDecision = authorizeNip46Signing({
    ...automationAuthorizationInput,
    usage_state: persistedAutomationUsage,
  });
  const operationConflictRequest = {
    ...automationRequest,
    rpc_request: {
      ...automationRequest.rpc_request,
      params: [jcsCanonicalize({
        created_at: automatedPublication.created_at,
        kind: automatedPublication.kind,
        tags: automatedAttribution.tags,
        content: "different canonical request bytes",
      })],
    },
  };
  const operationConflictDecision = authorizeNip46Signing({
    ...automationAuthorizationInput,
    usage_state: persistedAutomationUsage,
    request: operationConflictRequest,
  });
  const oneRequestUnsigned: Omit<SigningGrant, "signature"> = {
    ...unsignedGrant,
    limits: { ...unsignedGrant.limits, request_count: 1 },
  };
  const oneRequestGrant: SigningGrant = {
    ...oneRequestUnsigned,
    signature: bytesToHex(schnorr.sign(
      signerGrantProofBytes(oneRequestUnsigned),
      hexToBytes(personaSecret),
      "00".repeat(32),
    )),
  };
  const oneRequestUsage = {
    ...usageState,
    grant_digest: signerGrantStateDigest(oneRequestGrant),
  };
  const oneRequestInput = {
    grant_candidates: [oneRequestGrant],
    usage_state: oneRequestUsage,
    presented_grant: structuredClone(oneRequestGrant),
    vaults: [{
      vault_id: vaultId,
      persona_active_key: persona,
      signers: [{ public_key: agentSigner, key_class: "agent" as const, custody: "local" as const }],
    }],
    request: signingRequest,
    client_metadata: {
      requested_methods: ["sign_event"],
      requested_event_kinds: [1],
      requested_signer_audiences: [audience],
    },
  };
  const oneReservation = authorizeNip46Signing(oneRequestInput);
  if (oneReservation.verdict !== "accept") throw new Error("one-request rate fixture rejected");
  const oneTransition = oneReservation.usage_transition;
  const saturatedUsage = {
    ...oneRequestUsage,
    window_started_at: oneTransition.window_started_at,
    consumed_request_count: oneTransition.consumed_request_count,
    revision: oneTransition.next_revision,
    reservations: [{
      operation_id: oneTransition.operation_id,
      request_id: oneTransition.request_id,
      request_digest: oneTransition.request_digest,
      rpc_request: oneTransition.rpc_request,
      value_msats: oneTransition.value_msats,
      window_started_at: oneTransition.window_started_at,
      reserved_at: oneTransition.reserved_at,
      claimed_at: null,
      executing_at: null,
      completed_at: null,
      state: "reserved" as const,
      execution_token: null,
      result_event_id: null,
      failure_digest: null,
    }],
  };
  const rateLimitedRequest = {
    ...signingRequest,
    now: signingRequest.now + 1,
    rpc_request: { ...signingRequest.rpc_request, id: "ee".repeat(32) },
  };
  const signingRateDecision = authorizeNip46Signing({
    ...oneRequestInput,
    usage_state: saturatedUsage,
    request: rateLimitedRequest,
  });

  const missingReservationDecision = prepareAutomatedSigning({
    authorization: automationAuthorizationInput,
    publication: automatedPublication,
  });
  const invalidIntentDecision = prepareAutomatedSigning({
    authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
    publication: { ...automatedPublication, extra: true } as never,
  });
  const missingAttributionDecision = prepareAutomatedSigning({
    authorization: {
      grant_candidates: [signingGrant],
      usage_state: usageState,
      presented_grant: structuredClone(signingGrant),
      vaults: oneRequestInput.vaults,
      request: signingRequest,
      client_metadata: oneRequestInput.client_metadata,
    },
    publication: automatedPublication,
  });
  const attributionBindingDecision = prepareAutomatedSigning({
    authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
    publication: { ...automatedPublication, agent_class: "programmatic" },
  });
  const executionFenceDecision = executePersistedAutomatedSigning({
    authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
    publication: automatedPublication,
    signer_execution: {
      executeOnce: () => ({ verdict: "conflict" as const }),
    },
  });

  const connectionState = {
    profile: "heterodyne.control.device-authorization-state.v1" as const,
    spec_version: QUALIFIED_VERSION as typeof QUALIFIED_VERSION,
    transaction_id: "10".repeat(32),
    grant_id: signingGrant.grant_id,
    oidc_authorization_id: signingGrant.oidc_authorization_id,
    persona_active_key: signingGrant.persona_active_key,
    nip46_client_pubkey: signingGrant.nip46_client_pubkey,
    signer_audience: signingGrant.signer_audience,
    selected_signing_pubkey: signingGrant.selected_signing_pubkey,
    key_class: signingGrant.key_class,
    requested_methods: [...signingGrant.allowed_methods],
    requested_event_kinds: [...signingGrant.allowed_event_kinds],
    requested_limits: { ...signingGrant.limits },
    connection_secret_sha256: signingGrant.connection_secret_sha256,
    connection_secret_state: "pending" as const,
    device_code_sha256: "11".repeat(32),
    device_code_entropy_bits: 128,
    user_code_sha256: "12".repeat(32),
    user_code_entropy_bits: 35,
    normalization: "uppercase-ascii-remove-hyphen" as const,
    client_fingerprint: "current-client-fingerprint",
    failed_guesses: 0,
    max_failed_guesses: 5 as const,
    interval_seconds: 5,
    issued_at: 100,
    expires_at: 200,
    state: "approved" as const,
    revision: 1,
  };
  const activation = {
    transaction_id: connectionState.transaction_id,
    grant_id: signingGrant.grant_id,
    oidc_authorization_id: signingGrant.oidc_authorization_id,
    persona_active_key: signingGrant.persona_active_key,
    nip46_client_pubkey: signingGrant.nip46_client_pubkey,
    signer_audience: signingGrant.signer_audience,
    selected_signing_pubkey: signingGrant.selected_signing_pubkey,
    key_class: signingGrant.key_class,
    presented_connection_secret: connectionSecret,
  };
  const invalidConnectionDecision = consumeNip46ConnectionSecret({
    current_state: connectionState,
    grant_candidates: [signingGrant],
    activation: { ...activation, presented_connection_secret: "08".repeat(32) },
    now: 110,
  });
  const activationMismatchDecision = consumeNip46ConnectionSecret({
    current_state: connectionState,
    grant_candidates: [signingGrant],
    activation: { ...activation, transaction_id: "13".repeat(32) },
    now: 110,
  });
  const reusedConnectionDecision = consumeNip46ConnectionSecret({
    current_state: {
      ...connectionState,
      connection_secret_state: "consumed",
      state: "consumed",
    },
    grant_candidates: [signingGrant],
    activation,
    now: 110,
  });

  const enrollmentBase = {
    keypackage_valid: true,
    member_count: 2,
    node_account_matches: true,
    entitlement_state: "none" as const,
    resource_available: true,
    welcome_rate_remaining: 1,
    replenishment_requested: false,
    replenishment_rate_remaining: 1,
    pending_at_cap: false,
    method: "control.enrollment.start",
  };
  const deviceBase = { entropy_valid: true, failed_guesses: 0, rate_allowed: true, display_binding_matches: true };
  const automatedBase = {
    method_allowed: true,
    private_key_requested: false,
    human_key_profile_selected: false,
    attribution_canonical: true,
    resource_allowed: true,
    event_bytes: 100,
    max_event_bytes: 200,
    rate_remaining: 1,
  };
  const resetBase = {
    authority_signature_valid: true,
    inventory_digest_matches: true,
    transition_evidence_valid: true,
    subordinate_reauthorized: true,
  };

  const reasonCases: CurrentVectorCase[] = [
    ...[
      ["signing-grant-invalid", "control-signing-grant-invalid", "control-signing.authorizeNip46Signing", "control-signer-grants", "CONTROL-I-EXACT-SIGNER-GRANT", { grant_candidates: [] }, invalidGrantDecision],
      ["signing-grant-unauthenticated", "control-signing-grant-unauthenticated", "control-signing.authorizeNip46Signing", "control-signer-grants", "CONTROL-I-EXACT-SIGNER-GRANT", { grant: unauthenticatedGrant }, unauthenticatedGrantDecision],
      ["signing-grant-stale", "control-signing-grant-stale", "control-signing.authorizeNip46Signing", "control-signer-grants", "CONTROL-I-EXACT-SIGNER-GRANT", { grant_ids: [signingGrant.grant_id, signingGrant.grant_id] }, staleGrantDecision],
      ["signing-grant-inactive", "control-signing-grant-inactive", "control-signing.authorizeNip46Signing", "control-signer-grants", "CONTROL-I-EXACT-SIGNER-GRANT", { now: signingGrant.expires_at }, inactiveGrantDecision],
      ["vault-isolation-failed", "control-vault-isolation-failed", "control-signing.authorizeNip46Signing", "control-persona-vaults", "CONTROL-I-PERSONA-VAULT-ISOLATION", { vaults: [] }, vaultIsolationDecision],
      ["signer-binding-mismatch", "control-signer-binding-mismatch", "control-signing.authorizeNip46Signing", "control-signer-grants", "CONTROL-I-EXACT-SIGNER-GRANT", { selected_signing_pubkey: "55".repeat(32) }, signerBindingDecision],
      ["persona-authority-required", "control-persona-authority-required", "control-signing.prepareAutomatedSigning", "control-signer-selection", "CONTROL-I-BASELINE-ACTIVE-KEY", { grant: personaGrant }, personaAuthorityDecision],
      ["signer-unavailable", "control-signer-unavailable", "control-signing.authorizeNip46Signing", "control-signer-selection", "CONTROL-I-NO-SIGNER-FALLBACK", { signers: [] }, signerUnavailableDecision],
      ["client-metadata-widening", "control-client-metadata-widening", "control-signing.authorizeNip46Signing", "control-nip46-signing", "CONTROL-I-CLIENT-KEY-CONFINEMENT", { requested_methods: ["sign_event", "get_public_key"] }, metadataWideningDecision],
      ["nip46-request-invalid", "control-nip46-request-invalid", "control-signing.authorizeNip46Signing", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { request_id: "invalid\\nrequest" }, invalidNip46Decision],
      ["usage-binding-mismatch", "control-usage-binding-mismatch", "control-signing.authorizeNip46Signing", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { grant_digest: "00".repeat(32) }, usageMismatchDecision],
      ["operation-conflict", "control-operation-conflict", "control-signing.authorizeNip46Signing", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { request: operationConflictRequest }, operationConflictDecision],
      ["operation-indeterminate", "control-operation-indeterminate", "control-signing.authorizeNip46Signing", "control-failover", "CONTROL-I-OPERATION-AT-MOST-ONCE", { reservation_state: "reserved" }, operationIndeterminateDecision],
      ["signing-rate-limited", "control-signing-rate-limited", "control-signing.authorizeNip46Signing", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { request_count: 1, consumed_request_count: 1 }, signingRateDecision],
      ["operation-reservation-required", "control-operation-reservation-required", "control-signing.prepareAutomatedSigning", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { reservations: [] }, missingReservationDecision],
      ["agent-intent-invalid", "control-agent-intent-invalid", "control-signing.prepareAutomatedSigning", "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING", { publication_extra_member: true }, invalidIntentDecision],
      ["attribution-required", "control-attribution-required", "control-signing.prepareAutomatedSigning", "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING", { automation_policy: null }, missingAttributionDecision],
      ["attribution-binding-mismatch", "control-attribution-binding-mismatch", "control-signing.prepareAutomatedSigning", "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING", { agent_class: "programmatic" }, attributionBindingDecision],
      ["operation-execution-fence-required", "control-operation-execution-fence-required", "control-signing.executePersistedAutomatedSigning", "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE", { reservation_state: "reserved" }, executionFenceDecision],
      ["connection-secret-invalid", "control-connection-secret-invalid", "control-signing.consumeNip46ConnectionSecret", "control-oidc-activation", "CONTROL-I-NIP46-OIDC-ACTIVATION", { presented_connection_secret: "08".repeat(32) }, invalidConnectionDecision],
      ["activation-binding-mismatch", "control-activation-binding-mismatch", "control-signing.consumeNip46ConnectionSecret", "control-oidc-activation", "CONTROL-I-NIP46-OIDC-ACTIVATION", { transaction_id: "13".repeat(32) }, activationMismatchDecision],
      ["connection-secret-reused", "control-connection-secret-reused", "control-signing.consumeNip46ConnectionSecret", "control-oidc-activation", "CONTROL-I-NIP46-OIDC-ACTIVATION", { connection_secret_state: "consumed" }, reusedConnectionDecision],
    ].map(([id, reason, boundary, anchor, invariant, input, decision]) => executedControlRejection({
      id: String(id), reason: String(reason), boundary: String(boundary), anchor: String(anchor), invariant: String(invariant),
      description: `The live Control authorization boundary rejects ${String(id).replaceAll("-", " ")}.`,
      input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
    })),
    ...[
      ["keypackage-invalid", "control-keypackage-invalid", { ...enrollmentBase, keypackage_valid: false }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, keypackage_valid: false }), "control-invitation-policy", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["entitlement-conflict", "control-entitlement-conflict", { ...enrollmentBase, entitlement_state: "revoked" as const }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, entitlement_state: "revoked" }), "control-entitlement", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["enrollment-unavailable", "control-enrollment-unavailable", { ...enrollmentBase, resource_available: false }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, resource_available: false }), "control-invitation-policy", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["keypackage-replenishment-paused", "control-keypackage-replenishment-paused", { ...enrollmentBase, replenishment_requested: true, pending_at_cap: true }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, replenishment_requested: true, pending_at_cap: true }), "control-invitation-policy", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["enrollment-rate-limited", "control-enrollment-rate-limited", { ...enrollmentBase, welcome_rate_remaining: 0 }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, welcome_rate_remaining: 0 }), "control-invitation-policy", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["enrollment-required", "control-enrollment-required", { ...enrollmentBase, method: "sign_event" }, evaluateControlEnrollmentBoundary({ ...enrollmentBase, method: "sign_event" }), "control-enrollment", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["device-code-invalid", "control-device-code-invalid", { ...deviceBase, entropy_valid: false }, evaluateDeviceCodeBoundary({ ...deviceBase, entropy_valid: false }), "control-device-authorization", "CONTROL-I-NIP46-OIDC-ACTIVATION"],
      ["device-code-rate-limited", "control-device-code-rate-limited", { ...deviceBase, rate_allowed: false }, evaluateDeviceCodeBoundary({ ...deviceBase, rate_allowed: false }), "control-device-authorization", "CONTROL-I-NIP46-OIDC-ACTIVATION"],
      ["device-code-display-mismatch", "control-device-code-display-mismatch", { ...deviceBase, display_binding_matches: false }, evaluateDeviceCodeBoundary({ ...deviceBase, display_binding_matches: false }), "control-device-authorization", "CONTROL-I-NIP46-OIDC-ACTIVATION"],
      ["invite-preauthorization-invalid", "invite-preauthorization-invalid", { purpose_bound: false, finite_template: true, client_bound: true }, validateInvitePreauthorizationBoundary({ purpose_bound: false, finite_template: true, client_bound: true }), "control-one-time-invites", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["frame-invalid", "control-frame-invalid", { closed_schema_valid: false, token_valid: true, refresh_requested: false }, validateControlFrameBoundary({ closed_schema_valid: false, token_valid: true, refresh_requested: false }), "control-frame", "CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
      ["refresh-prohibited", "control-refresh-prohibited", { closed_schema_valid: true, token_valid: true, refresh_requested: true }, validateControlFrameBoundary({ closed_schema_valid: true, token_valid: true, refresh_requested: true }), "control-token", "CONTROL-I-CLIENT-KEY-CONFINEMENT"],
      ["token-invalid", "control-token-invalid", { closed_schema_valid: true, token_valid: false, refresh_requested: false }, validateControlFrameBoundary({ closed_schema_valid: true, token_valid: false, refresh_requested: false }), "control-token", "CONTROL-I-CLIENT-KEY-CONFINEMENT"],
      ["request-expired", "control-request-expired", { now: 100, expires_at: 100, request_id_reused: false, request_digest_matches: true }, evaluateControlOperationRequest({ now: 100, expires_at: 100, request_id_reused: false, request_digest_matches: true }), "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE"],
      ["request-id-conflict", "control-request-id-conflict", { now: 100, expires_at: 101, request_id_reused: true, request_digest_matches: false }, evaluateControlOperationRequest({ now: 100, expires_at: 101, request_id_reused: true, request_digest_matches: false }), "control-request-processing", "CONTROL-I-OPERATION-AT-MOST-ONCE"],
      ["agent-method-prohibited", "agent-method-prohibited", { ...automatedBase, method_allowed: false }, evaluateAutomatedControlGrant({ ...automatedBase, method_allowed: false }), "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],
      ["agent-key-access-prohibited", "agent-key-access-prohibited", { ...automatedBase, private_key_requested: true }, evaluateAutomatedControlGrant({ ...automatedBase, private_key_requested: true }), "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],
      ["agent-human-profile-prohibited", "agent-human-profile-prohibited", { ...automatedBase, human_key_profile_selected: true }, evaluateAutomatedControlGrant({ ...automatedBase, human_key_profile_selected: true }), "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],
      ["agent-attribution-bypass-prohibited", "agent-attribution-bypass-prohibited", { ...automatedBase, attribution_canonical: false }, evaluateAutomatedControlGrant({ ...automatedBase, attribution_canonical: false }), "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],
      ["agent-resource-denied", "agent-resource-denied", { ...automatedBase, resource_allowed: false }, evaluateAutomatedControlGrant({ ...automatedBase, resource_allowed: false }), "control-agent-requirements", "CONTROL-I-EXACT-SIGNER-GRANT"],
      ["agent-size-exceeded", "agent-size-exceeded", { ...automatedBase, event_bytes: 201 }, evaluateAutomatedControlGrant({ ...automatedBase, event_bytes: 201 }), "control-agent-requirements", "CONTROL-I-EXACT-SIGNER-GRANT"],
      ["agent-rate-limited", "agent-rate-limited", { ...automatedBase, rate_remaining: 0 }, evaluateAutomatedControlGrant({ ...automatedBase, rate_remaining: 0 }), "control-agent-requirements", "CONTROL-I-OPERATION-AT-MOST-ONCE"],
      ["signed-event-invalid", "control-signed-event-invalid", { canonical_event_valid: false, fields_exact: true, effect_certain: true }, validateControlSignedEffect({ canonical_event_valid: false, fields_exact: true, effect_certain: true }), "control-agent-requirements", "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],
      ["signer-effect-indeterminate", "control-signer-effect-indeterminate", { canonical_event_valid: true, fields_exact: true, effect_certain: false }, validateControlSignedEffect({ canonical_event_valid: true, fields_exact: true, effect_certain: false }), "control-agent-requirements", "CONTROL-I-OPERATION-AT-MOST-ONCE"],
      ["compromise-reset-unauthenticated", "control-compromise-reset-unauthenticated", { ...resetBase, authority_signature_valid: false }, evaluateCompromiseResetBoundary({ ...resetBase, authority_signature_valid: false }), "control-compromise-reset", "CONTROL-I-COMPROMISE-RESET"],
      ["compromise-reset-inventory-mismatch", "control-compromise-reset-inventory-mismatch", { ...resetBase, inventory_digest_matches: false }, evaluateCompromiseResetBoundary({ ...resetBase, inventory_digest_matches: false }), "control-compromise-reset", "CONTROL-I-COMPROMISE-RESET"],
      ["compromise-reset-evidence-invalid", "control-compromise-reset-evidence-invalid", { ...resetBase, transition_evidence_valid: false }, evaluateCompromiseResetBoundary({ ...resetBase, transition_evidence_valid: false }), "control-compromise-reset", "CONTROL-I-COMPROMISE-RESET"],
      ["subordinate-reauthorization-required", "control-subordinate-reauthorization-required", { ...resetBase, subordinate_reauthorized: false }, evaluateCompromiseResetBoundary({ ...resetBase, subordinate_reauthorized: false }), "control-compromise-reset", "CONTROL-I-COMPROMISE-RESET"],
    ].map(([id, reason, input, decision, anchor, invariant]) => executedControlRejection({
      id: String(id), reason: String(reason), boundary: String(reason).startsWith("agent-")
        ? "control-policy.evaluateAutomatedControlGrant"
        : String(reason).startsWith("control-device-code")
          ? "control-policy.evaluateDeviceCodeBoundary"
          : String(reason).startsWith("control-compromise") || String(reason).startsWith("control-subordinate")
            ? "control-policy.evaluateCompromiseResetBoundary"
            : String(reason).startsWith("control-signed") || String(reason).startsWith("control-signer-effect")
              ? "control-policy.validateControlSignedEffect"
              : String(reason).startsWith("control-request")
                ? "control-policy.evaluateControlOperationRequest"
                : reason === "invite-preauthorization-invalid"
                  ? "control-policy.validateInvitePreauthorizationBoundary"
                  : ["control-frame-invalid", "control-refresh-prohibited", "control-token-invalid"].includes(String(reason))
                    ? "control-policy.validateControlFrameBoundary"
                    : "control-policy.evaluateControlEnrollmentBoundary",
      anchor: String(anchor), invariant: String(invariant),
      description: `The current Control policy boundary rejects ${String(id).replaceAll("-", " ")}.`,
      input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
    })),
  ];

  return [
    ...reasonCases,
    {
      relativePath: "control/opaque-authorization-view-accepted.json",
      semantic_boundary: "authorization-freshness.revalidateAuthorizationViewAtEffect",
      vector_id: "control/opaque-authorization-view-accepted",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: [],
      description: "An opaque view issued by the trusted freshness authority is accepted at mutation effect.",
      direction: "consume",
      input: {
        manifest,
        ledger_state: state,
        trusted_now: state.checkpoint.observed_at + 300,
        current_authorization_view: "opaque",
      },
      expected_output: acceptedAtEffect,
    },
    {
      relativePath: "control/caller-freshness-booleans-rejected.json",
      semantic_boundary: "authorization-freshness.evaluateAuthorizationFreshness",
      vector_id: "control/caller-freshness-booleans-rejected",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: ["control-authorization-view-stale"],
      description: "Caller-authored freshness booleans cannot substitute for an opaque authorization view.",
      direction: "consume",
      input: {
        manifest,
        now: state.checkpoint.observed_at + 300,
        checkpoint_fresh: true,
        authorization_view_authenticated: true,
      },
      expected_output: normalizeReason(callerDecision),
    },
    {
      relativePath: "control/authorization-view-stale-at-effect.json",
      semantic_boundary: "authorization-freshness.revalidateAuthorizationViewAtEffect",
      vector_id: "control/authorization-view-stale-at-effect",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: ["control-authorization-view-stale"],
      description: "A view prepared at its boundary is rejected when it becomes stale before mutation effect.",
      direction: "consume",
      input: {
        manifest,
        prepared_at: state.checkpoint.observed_at + 300,
        effected_at: state.checkpoint.observed_at + 301,
        current_authorization_view: "opaque",
      },
      expected_output: normalizeReason(staleAtEffect),
    },
    {
      relativePath: "control/exact-signer-grant-reserved.json",
      semantic_boundary: "control-signing.authorizeNip46Signing",
      vector_id: "control/exact-signer-grant-reserved",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-signer-grants")],
      invariants: [
        "CONTROL-I-AUDIT-AT-REST",
        "CONTROL-I-BASELINE-ACTIVE-KEY",
        "CONTROL-I-CLIENT-KEY-CONFINEMENT",
        "CONTROL-I-EXACT-SIGNER-GRANT",
        "CONTROL-I-NO-SIGNER-FALLBACK",
        "CONTROL-I-OPERATION-AT-MOST-ONCE",
        "CONTROL-I-PERSONA-VAULT-ISOLATION",
      ],
      reason_codes: [],
      description: "A domain-separated active-key grant resolves exactly one persona vault and signer, then durably reserves the canonical NIP-46 request before any key effect.",
      direction: "consume",
      input: {
        grant: signingGrant,
        usage_state: usageState,
        request: signingRequest,
      },
      expected_output: signerAuthorization,
    },
    {
      relativePath: "control/automation-attributed-before-signing.json",
      semantic_boundary: "control-signing.prepareAutomatedSigning",
      vector_id: "control/automation-attributed-before-signing",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-agent-requirements")],
      invariants: [
        "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING",
        "CONTROL-I-OPERATION-AT-MOST-ONCE",
      ],
      reason_codes: [],
      description: "A reserved automated intent is exact-grant bound, receives canonical Comms attribution, and advances to a durable claim transition before signer execution.",
      direction: "produce",
      input: {
        publication: automatedPublication,
        grant: automationGrant,
        usage_state: persistedAutomationUsage,
      },
      expected_output: automatedSigningDecision,
    },
    {
      relativePath: "control/compromise-reset-closure-required.json",
      semantic_boundary: "control-signing.validateCompromiseReset",
      vector_id: "control/compromise-reset-closure-required",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-compromise-reset")],
      invariants: ["CONTROL-I-COMPROMISE-RESET", "CONTROL-I-MARMOT-LEAF-COMPROMISE"],
      reason_codes: ["control-compromise-reset-incomplete"],
      description: "A reset without a signed authoritative inventory, successor completion, leaf removals, group advances, and fresh KeyPackages is rejected before state changes.",
      direction: "consume",
      input: incompleteResetInput,
      expected_output: incompleteResetDecision,
    },
  ];
}
