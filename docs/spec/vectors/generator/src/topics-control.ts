import {
  acceptControlRequest,
  authorizeControlMethod,
  authorizeAgentMethod,
  controlPayloadDigest,
  evaluateControlEnrollment,
  evaluateControlSessionLifecycle,
  evaluateMcpToolCall,
  redeemEnrollmentToken,
  type AgentMethodInput,
  type ControlGrant,
  type ControlRequestInput,
  type EnrollmentEvaluationInput,
  type EnrollmentTokenRecord,
  type RequestReservation,
} from "./control-profile.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const relayA = "wss://relay-a.example/";
const relayB = "wss://relay-b.example/";
const sessionId = "11".repeat(32);
const payload = { content: "hello", kind: 1 };
const payloadDigest = controlPayloadDigest(payload);
const request: ControlRequestInput = {
  authenticated: true,
  session_id: sessionId,
  request_id: "request-1",
  method: "heterodyne.agent.publish",
  payload,
  payload_digest: payloadDigest,
  ingress_relay: relayA,
  expires_at: 1_200,
  now: 1_000,
};
const reserved = acceptControlRequest(request);
if (reserved.verdict !== "accept") throw new Error("control fixture reservation failed");
const reservation = reserved.reservation;
const complete: RequestReservation = {
  ...reservation,
  state: "complete",
  response: { status: "ok", event_id: "22".repeat(32) },
};

const validAgentMethod: AgentMethodInput = {
  method: "heterodyne.agent.publish",
  token_decision: { verdict: "accept" },
  sender_proof_valid: true,
  kind: 1,
  allowed_kinds: [1, 30023],
  resource: "feed:main",
  allowed_resources: ["feed:main"],
  content_bytes: 100,
  max_content_bytes: 4096,
  rate_count: 1,
  rate_limit: 20,
  burst_count: 1,
  burst_limit: 5,
  requests_key_access: false,
  requests_human_profile: false,
  requests_attribution_bypass: false,
};

const validEnrollment: EnrollmentEvaluationInput = {
  profile_id: "heterodyne-control-session-device-v1",
  binding_proof_valid: true,
  binding_nonce_matches_bootstrap: true,
  active_invite: true,
  bootstrap_authorized: true,
  bootstrap_mode: "challenge",
  fresh_ceremony: true,
  pending_expires_at: 1_200,
  now: 1_000,
  organization_persona: false,
  delegation_state: "repository-final",
  authorization_state: "active",
};

const enrollmentToken: EnrollmentTokenRecord = {
  token_class: "control-enrollment",
  token_id: "aa".repeat(32),
  issuer_device: "bb".repeat(32),
  expires_at: 1_200,
  grant_tier: "regular",
  state: "unspent",
  signature_valid: true,
};

const regularGrant: ControlGrant = {
  tier: "regular",
  media_upload: false,
  repositories: ["rad:z3repo"],
  config_namespaces: ["ui"],
  sessions: [sessionId],
};

export function buildControlVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  for (const [number, name, input, prior] of [
    ["001", "first-arrival-reserved", request, undefined],
    ["002", "concurrent-identical-joins", request, reservation],
    ["003", "cross-relay-final-response-replay", { ...request, ingress_relay: relayB }, complete],
    ["004", "restart-reserved-operation-joins", { ...request, ingress_relay: relayB }, { ...reservation }],
    ["005", "expired-request-rejected", { ...request, now: request.expires_at }, undefined],
    ["006", "reply-relay-rejected", { ...request, reply_relay: relayB }, undefined],
    ["007", "changed-method-rejected", { ...request, method: "heterodyne.agent.token" }, reservation],
    ["008", "changed-payload-rejected", {
      ...request,
      payload: { ...payload, content: "changed" },
      payload_digest: controlPayloadDigest({ ...payload, content: "changed" }),
    }, reservation],
    ["009", "complete-without-response-rejected", request, { ...complete, response: undefined }],
  ] as const) {
    vectors.push(authored(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The relay-affine restart-safe request decision is ${name}.`,
      { request: input, ...(prior === undefined ? {} : { prior }) },
      acceptControlRequest(input, prior),
    ));
  }

  const methodCases: Array<[string, string, AgentMethodInput]> = [
    ["010", "agent-publish-authorized", validAgentMethod],
    ["011", "raw-signing-refused", { ...validAgentMethod, method: "sign_event" }],
    ["012", "key-access-refused", { ...validAgentMethod, requests_key_access: true }],
    ["013", "human-profile-refused", { ...validAgentMethod, requests_human_profile: true }],
    ["014", "attribution-bypass-refused", { ...validAgentMethod, requests_attribution_bypass: true }],
    ["015", "expired-token-refused", {
      ...validAgentMethod,
      token_decision: { verdict: "reject", reason_code: "agent-token-expired" },
    }],
    ["016", "sender-proof-refused", { ...validAgentMethod, sender_proof_valid: false }],
    ["017", "kind-resource-refused", { ...validAgentMethod, kind: 7 }],
    ["018", "content-size-refused", { ...validAgentMethod, content_bytes: 4097 }],
    ["019", "rate-refused", { ...validAgentMethod, rate_count: 21 }],
    ["020", "burst-refused", { ...validAgentMethod, burst_count: 6 }],
  ];
  for (const [number, name, input] of methodCases) {
    vectors.push(authored(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The automated-agent method boundary is ${name}.`,
      input,
      authorizeAgentMethod(input),
    ));
  }

  vectors.push(authored(
    "control/021-token-request-bounded.json",
    "control/token-request-bounded",
    "A Control/DR token request binds one session, challenge, workload proof, scope, resource, and expiry and yields no refresh token.",
    {
      spec_version: "control/0.5.0",
      session_id: sessionId,
      request_id: "token-request-1",
      challenge: "challenge-123456",
      workload_proof: "compact-jws",
      requested_scopes: ["heterodyne:agent:publish"],
      requested_resource: "feed:main",
      requested_expiry: 1_250,
    },
    {
      verdict: "accept",
      normalized: {
        access_token_issued: true,
        refresh_token_issued: false,
        expires_at: 1_250,
      },
    },
  ));
  vectors.push(authored(
    "control/022-agent-publish-schema-intent-only.json",
    "control/agent-publish-schema-intent-only",
    "The closed agent publication payload carries intent fields and rejects signature, pubkey, and authoritative attribution input.",
    {
      accepted_fields: [
        "spec_version",
        "token",
        "sender_proof",
        "content",
        "kind",
        "resource",
        "feed",
        "options",
      ],
      forbidden_fields: ["sig", "pubkey", "private_key", "attribution", "human_profile"],
    },
    {
      verdict: "accept",
      normalized: {
        caller_can_supply_signature: false,
        caller_can_supply_attribution_authority: false,
      },
    },
  ));
  vectors.push(authored(
    "control/023-audit-omits-raw-token.json",
    "control/audit-omits-raw-token",
    "The encrypted agent audit retains token jti and authorization evidence but not raw access-token bytes.",
    {
      token_jti: "token-1",
      raw_token_presented: true,
      source_claim_ids: ["claim-1"],
      payload_digest: payloadDigest,
    },
    {
      verdict: "accept",
      normalized: {
        retained_fields: ["token_jti", "source_claim_ids", "payload_digest"],
        raw_token_retained: false,
        encrypted_at_rest: true,
      },
    },
  ));
  const enrollmentCases: Array<
    [string, string, EnrollmentEvaluationInput]
  > = [
    ["024", "enrollment-binding-proof-rejected", {
      ...validEnrollment,
      binding_proof_valid: false,
    }],
    ["025", "enrollment-pending-expired", {
      ...validEnrollment,
      now: validEnrollment.pending_expires_at,
    }],
    ["026", "enrollment-relay-provisional", {
      ...validEnrollment,
      delegation_state: "relay-provisional",
    }],
    ["027", "enrollment-repository-final-active", validEnrollment],
    ["048", "enrollment-qr-ceremony-required", {
      ...validEnrollment,
      bootstrap_mode: "qr",
      fresh_ceremony: false,
    }],
    ["049", "enrollment-challenge-ceremony-required", {
      ...validEnrollment,
      bootstrap_mode: "challenge",
      fresh_ceremony: false,
    }],
  ];
  for (const [number, name, input] of enrollmentCases) {
    vectors.push(draftDecision(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The closed draft enrollment state machine yields ${name}.`,
      input,
      evaluateControlEnrollment(input),
    ));
  }

  const redeemingDevice = enrollmentToken.issuer_device;
  const enrollingKey = "cc".repeat(32);
  const spentToken: EnrollmentTokenRecord = {
    ...enrollmentToken,
    state: "spent",
    enrolling_key: enrollingKey,
  };
  for (const [number, name, token, key] of [
    ["028", "enrollment-token-redeemed", enrollmentToken, enrollingKey],
    ["029", "enrollment-token-same-key-replay", spentToken, enrollingKey],
    ["030", "enrollment-token-different-key-conflict", spentToken, "dd".repeat(32)],
    ["031", "enrollment-token-full-grant-rejected", {
      ...enrollmentToken,
      grant_tier: "full" as const,
    }, enrollingKey],
    ["032", "enrollment-token-workload-class-rejected", {
      ...enrollmentToken,
      token_class: "agent-workload" as const,
    }, enrollingKey],
  ] as const) {
    const input = {
      token,
      redeeming_device: redeemingDevice,
      enrolling_key: key,
      now: 1_000,
    };
    vectors.push(draftDecision(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The issuer-bound enrollment-token ledger yields ${name}.`,
      input,
      redeemEnrollmentToken(input),
    ));
  }

  for (const [number, name, input] of [
    ["033", "grant-regular-object-authorized", {
      grant: regularGrant,
      authorization_state: "active" as const,
      method: "config.put",
      object_type: "config_namespace" as const,
      object_id: "ui",
      fresh_ceremony: false,
    }],
    ["034", "grant-object-scope-refused", {
      grant: regularGrant,
      authorization_state: "active" as const,
      method: "repo.write",
      object_type: "repository" as const,
      object_id: "rad:z-other",
      fresh_ceremony: false,
    }],
    ["035", "grant-policy-state-write-refused", {
      grant: regularGrant,
      authorization_state: "active" as const,
      method: "config.put",
      object_type: "security_policy" as const,
      object_id: "grant-table",
      fresh_ceremony: false,
    }],
    ["036", "grant-full-ceremony-required", {
      grant: { ...regularGrant, tier: "full" as const },
      authorization_state: "active" as const,
      method: "device.activate",
      object_type: "session" as const,
      object_id: sessionId,
      fresh_ceremony: false,
    }],
    ["037", "grant-full-ceremony-authorized", {
      grant: { ...regularGrant, tier: "full" as const },
      authorization_state: "active" as const,
      method: "device.activate",
      object_type: "session" as const,
      object_id: sessionId,
      fresh_ceremony: true,
    }],
  ] as const) {
    vectors.push(draftDecision(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The closed grant and protected-policy decision yields ${name}.`,
      input,
      authorizeControlMethod(input),
    ));
  }

  for (const [number, name, input] of [
    ["038", "lifecycle-self-revocation", {
      now: 1_000,
      valid_until: 1_100,
      self_revoked: true,
      logout: false,
      authorization_state: "active" as const,
    }],
    ["039", "lifecycle-inactivity-lapse", {
      now: 1_100,
      valid_until: 1_100,
      self_revoked: false,
      logout: false,
      authorization_state: "active" as const,
    }],
  ] as const) {
    vectors.push(draftDecision(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The session lifecycle decision yields ${name}.`,
      input,
      evaluateControlSessionLifecycle(input),
    ));
  }

  const mcpCall = {
    initialized: true,
    advertised_tools: ["heterodyne.agent.publish"],
    tool: "heterodyne.agent.publish",
    direction: "light-to-full" as const,
    inbound_execution_advertised: false,
    cancellation_supported: true,
    cancel_requested: false,
    started_at: 1_000,
    timeout_ms: 1_000,
    now: 1_100,
  };
  for (const [number, name, input] of [
    ["040", "mcp-initialize-required", { ...mcpCall, initialized: false }],
    ["041", "mcp-unadvertised-tool-refused", {
      ...mcpCall,
      tool: "unknown.tool",
    }],
    ["042", "mcp-cancellation", { ...mcpCall, cancel_requested: true }],
    ["043", "mcp-timeout", {
      ...mcpCall,
      now: mcpCall.started_at + mcpCall.timeout_ms,
    }],
    ["044", "mcp-inbound-execution-default-deny", {
      ...mcpCall,
      direction: "full-to-light" as const,
    }],
  ] as const) {
    vectors.push(draftDecision(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The bidirectional MCP lifecycle yields ${name}.`,
      input,
      evaluateMcpToolCall(input),
    ));
  }

  vectors.push(authored(
    "control/045-rpc-schema-transport-context-excluded.json",
    "control/rpc-schema-transport-context-excluded",
    "The closed RPC request carries only id, method, params, and expiry; session, digest, ingress, reply route, and Control version are receiver context.",
    {
      request_members: ["id", "method", "params", "expires_at"],
      receiver_context: [
        "negotiated_control_version",
        "accepted_dr_session_id",
        "payload_digest",
        "actual_ingress_relay",
      ],
      forbidden_members: [
        "spec_version",
        "session_id",
        "payload_digest",
        "ingress_relay",
        "reply_relay",
      ],
    },
    {
      verdict: "accept",
      normalized: { control_owns_wire_stamp: false },
    },
  ));
  vectors.push(authored(
    "control/046-configuration-filter-excludes-policy.json",
    "control/configuration-filter-excludes-policy",
    "The live configuration view contains granted UI state but excludes policy, ledger, key, and ratchet secrets.",
    {
      grant: regularGrant,
      requested_namespaces: ["ui", "security-policy", "claim-ledger"],
    },
    {
      verdict: "accept",
      normalized: {
        included_namespaces: ["ui"],
        excluded_namespaces: ["security-policy", "claim-ledger"],
        secret_classes_released: [],
      },
    },
  ));
  vectors.push(draftDecision(
    "control/047-rpc-changed-expiry-conflict.json",
    "control/rpc-changed-expiry-conflict",
    "A retry that changes expiry conflicts with the durable logical request reservation.",
    {
      request: { ...request, expires_at: request.expires_at + 1 },
      prior: reservation,
    },
    acceptControlRequest(
      { ...request, expires_at: request.expires_at + 1 },
      reservation,
    ),
  ));
  vectors.push(draftDecision(
    "control/050-rpc-cross-session-conflict.json",
    "control/rpc-cross-session-conflict",
    "A request ID reserved in one accepted DR session cannot be replayed from another session.",
    {
      request: { ...request, session_id: "22".repeat(32) },
      prior: reservation,
    },
    acceptControlRequest(
      { ...request, session_id: "22".repeat(32) },
      reservation,
    ),
  ));
  const identityJoin = {
    invite_event_id: "31".repeat(32),
    enrollee_key: "32".repeat(32),
    dr_transcript_hash: "33".repeat(32),
    dr_session_id: sessionId,
    delegation_address: `pubkey:${"32".repeat(32)}`,
    delegation_event_id: "34".repeat(32),
    grant_subject: "32".repeat(32),
    executor_nid: "did:key:z6MkhExecutor",
    executor_device_key: "35".repeat(32),
    negotiated_protocol: "heterodyne-control-human-v1",
    negotiated_version: "control/0.5.0",
  };
  vectors.push(authored(
    "control/051-enrollment-identity-join-valid.json",
    "control/enrollment-identity-join-valid",
    "Enrollment activation binds the complete peer, executor, session, delegation, grant, and negotiated-profile join.",
    identityJoin,
    {
      verdict: "accept",
      normalized: {
        all_identity_joins_match: true,
        authority: "repository-final-active-only",
      },
    },
  ));
  vectors.push(draftDecision(
    "control/052-enrollment-identity-substitution-rejected.json",
    "control/enrollment-identity-substitution-rejected",
    "Substituting an executor device across the enrollment identity join fails closed.",
    {
      expected: identityJoin,
      presented: {
        ...identityJoin,
        executor_device_key: "36".repeat(32),
      },
    },
    {
      verdict: "reject",
      reason_code: "control-enrollment-identity-join-mismatch",
    },
  ));
  for (const [number, authorization_state] of [
    ["053", "provisional"],
    ["054", "untrusted"],
    ["055", "conflicted"],
    ["056", "invalid"],
    ["057", "expired"],
    ["058", "revoked"],
  ] as const) {
    const input: EnrollmentEvaluationInput = {
      ...validEnrollment,
      authorization_state,
    };
    vectors.push(draftDecision(
      `control/${number}-authorization-${authorization_state}.json`,
      `control/authorization-${authorization_state}`,
      `The Comms claim-ledger ${authorization_state} decision grants no positive Control authority.`,
      input,
      evaluateControlEnrollment(input),
    ));
  }
  vectors.push(authored(
    "control/059-agent-token-per-use-binding.json",
    "control/agent-token-per-use-binding",
    "Post-initialize workload issuance and publication proof bind the complete current request and credential generation.",
    {
      initialization_complete: true,
      token_ttl_seconds: 300,
      token_sender_constrained: true,
      per_use_proof_fresh: true,
      bindings: [
        "issuer",
        "pairwise_sub",
        "client_id",
        "role_id",
        "control_session",
        "request_id",
        "method",
        "payload_digest",
        "ledger_persona",
        "ledger_generation",
        "ledger_checkpoint",
        "ledger_status",
      ],
    },
    {
      verdict: "accept",
      normalized: {
        method: "heterodyne.agent.publish",
        token_max_seconds: 300,
        signer_class: "full-node-held-agent-role-key",
      },
    },
  ));
  vectors.push(authored(
    "control/060-agent-generation-reset.json",
    "control/agent-generation-reset",
    "A credential-ledger generation reset purges pending issuance and invalidates prior-generation authority.",
    {
      token_generation: 4,
      current_generation: 5,
      pending_issuance_generation: 4,
    },
    {
      verdict: "accept",
      normalized: {
        prior_token_authority: "invalid",
        pending_issuance: "purged",
        requires_current_generation_reissuance: true,
      },
    },
  ));
  vectors.push(authored(
    "control/061-transition-peer-tombstone.json",
    "control/transition-peer-tombstone",
    "A revocation transition invalidates locally before broadcasting a separately authenticated peer tombstone.",
    {
      transition_accepted: true,
      old_session_id: sessionId,
      old_sender_delivery_key: "41".repeat(32),
      old_recipient_delivery_key: "42".repeat(32),
      peer_acknowledged: false,
    },
    {
      verdict: "accept",
      normalized: {
        local_authority: "invalidated",
        peer_tombstone: "nip59-persistent-authenticated",
        acknowledgement_blocks_invalidation: false,
        control_response: false,
      },
    },
  ));
  vectors.push(authored(
    "control/062-transport-strict-tor.json",
    "control/transport-strict-tor",
    "Strict Control enrollment and RPC use outbound Tor while remaining relay-mediated.",
    {
      client_mode: "strict",
      outbound_tor: true,
      relay: "ws://strictcontrolrelayexample.onion/",
      direct_node_channel: false,
    },
    {
      verdict: "accept",
      normalized: {
        assurance: "strict",
        control_transport_owner: "comms",
      },
    },
  ));
  vectors.push(authored(
    "control/063-transport-browser-reduced-assurance.json",
    "control/transport-browser-reduced-assurance",
    "A browser without Tor may use one authenticated shared clearnet relay only with a visible reduced-assurance declaration.",
    {
      client_mode: "browser",
      outbound_tor: false,
      relay: relayA,
      relay_authenticated: true,
      reduced_assurance_visible: true,
    },
    {
      verdict: "accept",
      normalized: {
        assurance: "reduced",
        direct_node_channel: false,
      },
    },
  ));
  vectors.push(authored(
    "control/064-recovery-no-session-restore.json",
    "control/recovery-no-session-restore",
    "Recovery restores no active Control or double-ratchet execution authority.",
    {
      protected_recovery_material_available: true,
      requested_restore: [
        "dr_state",
        "message_keys",
        "workload_tokens",
        "sender_proofs",
        "control_session",
      ],
    },
    {
      verdict: "accept",
      normalized: {
        restored: [],
        fresh_session_required: true,
        recovery_opens_control: false,
      },
    },
  ));
  vectors.push(authored(
    "control/065-retention-no-backfill.json",
    "control/retention-no-backfill",
    "Control traffic is relay-only and non-backfillable while a bounded encrypted side-effect audit remains non-replayable.",
    {
      artifacts: [
        "rpc_request",
        "rpc_response",
        "dr_state",
        "side_effect_audit",
      ],
    },
    {
      verdict: "accept",
      normalized: {
        repository_committed: [],
        backfilled: [],
        recovery_optional: ["bounded-encrypted-side-effect-audit"],
        replayable_transcript: false,
        retained_message_keys: false,
        retained_raw_workload_tokens: false,
      },
    },
  ));
  return vectors;
}

function draftDecision(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  decision: unknown,
): AuthoredVector {
  return authored(relativePath, vectorId, description, input, {
    verdict: "accept",
    normalized: {
      draft_control_decision: decision,
      conformance_claimable: false,
    },
  });
}

function authored(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  expectedOutput: Record<string, unknown>,
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-control-subset-anchor"],
      description,
      direction: "consume",
      input,
      expected_output: expectedOutput,
    }),
  };
}
