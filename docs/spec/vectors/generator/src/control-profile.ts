import { createHash } from "node:crypto";
import { jcsCanonicalize } from "./jcs.js";
import { validateBootstrapRelay } from "./public-reader.js";

export type RequestReservation = {
  session_id: string;
  request_id: string;
  method: string;
  payload_digest: string;
  expires_at: number;
  first_ingress_relay: string;
  state: "reserved" | "complete";
  response?: unknown;
};

export type ControlRequestInput = {
  authenticated: boolean;
  session_id: string;
  request_id: string;
  method: string;
  payload: Record<string, unknown>;
  payload_digest: string;
  ingress_relay: string;
  expires_at: number;
  now: number;
  reply_relay?: string;
};

export type ControlRequestDecision =
  | {
      verdict: "accept";
      action: "execute" | "join" | "replay";
      execute: boolean;
      response_relay: string;
      reservation: RequestReservation;
      response?: unknown;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type AgentMethodInput = {
  method: string;
  token_decision:
    | { verdict: "accept" }
    | { verdict: "reject"; reason_code: string };
  sender_proof_valid: boolean;
  kind: number;
  allowed_kinds: number[];
  resource: string;
  allowed_resources: string[];
  content_bytes: number;
  max_content_bytes: number;
  rate_count: number;
  rate_limit: number;
  burst_count: number;
  burst_limit: number;
  requests_key_access: boolean;
  requests_human_profile: boolean;
  requests_attribution_bypass: boolean;
};

export type AgentMethodDecision =
  | {
      verdict: "accept";
      method: "heterodyne.agent.publish";
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type EnrollmentEvaluationInput = {
  profile_id: string;
  binding_proof_valid: boolean;
  binding_nonce_matches_bootstrap: boolean;
  active_invite: boolean;
  bootstrap_authorized: boolean;
  bootstrap_mode: "qr" | "challenge" | "token";
  fresh_ceremony: boolean;
  pending_expires_at: number;
  now: number;
  organization_persona: boolean;
  delegation_state: "relay-provisional" | "repository-final";
  authorization_state:
    | "active"
    | "provisional"
    | "untrusted"
    | "conflicted"
    | "invalid"
    | "expired"
    | "revoked";
};

export type EnrollmentEvaluationDecision =
  | {
      verdict: "accept";
      state: "active";
      authority: true;
      default_grant: "regular";
    }
  | {
      verdict: "hold";
      state: "provisional" | "authorization-pending";
      authority: false;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type EnrollmentTokenRecord = {
  token_class: "control-enrollment" | "agent-workload" | "recovery";
  token_id: string;
  issuer_device: string;
  enrolling_key?: string;
  expected_enrollee_key?: string;
  expires_at: number;
  grant_tier: "baseline" | "regular" | "full";
  state: "unspent" | "spent" | "revoked";
  signature_valid: boolean;
};

export type EnrollmentTokenRedemptionInput = {
  token: EnrollmentTokenRecord;
  redeeming_device: string;
  enrolling_key: string;
  now: number;
};

export type EnrollmentTokenRedemptionDecision =
  | {
      verdict: "accept";
      action: "redeem" | "replay";
      grant_tier: "baseline" | "regular";
      next: EnrollmentTokenRecord;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type ControlGrant = {
  tier: "baseline" | "regular" | "full";
  media_upload: boolean;
  repositories: string[];
  config_namespaces: string[];
  sessions: string[];
};

export type ControlMethodAuthorizationInput = {
  grant: ControlGrant;
  authorization_state:
    | "active"
    | "provisional"
    | "untrusted"
    | "conflicted"
    | "invalid"
    | "expired"
    | "revoked";
  method: string;
  object_type:
    | "none"
    | "repository"
    | "config_namespace"
    | "session"
    | "security_policy";
  object_id: string;
  fresh_ceremony: boolean;
};

export type ControlMethodAuthorizationDecision =
  | {
      verdict: "accept";
      method: string;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type ControlSessionLifecycleInput = {
  now: number;
  valid_until: number;
  self_revoked: boolean;
  logout: boolean;
  authorization_state:
    | "active"
    | "provisional"
    | "untrusted"
    | "conflicted"
    | "invalid"
    | "expired"
    | "revoked";
};

export type ControlSessionLifecycleDecision = {
  state: "active" | "revoked" | "lapsed";
  authority: boolean;
  terminate_dr: boolean;
  peer_tombstone: boolean;
};

export type McpToolCallInput = {
  initialized: boolean;
  advertised_tools: string[];
  tool: string;
  direction: "light-to-full" | "full-to-light";
  inbound_execution_advertised: boolean;
  cancellation_supported: boolean;
  cancel_requested: boolean;
  started_at: number;
  timeout_ms: number;
  now: number;
};

export type McpToolCallDecision =
  | {
      verdict: "accept";
      action: "execute" | "cancel";
      tool: string;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export function controlPayloadDigest(payload: Record<string, unknown>): string {
  return createHash("sha256")
    .update(jcsCanonicalize(payload as never), "utf8")
    .digest("hex");
}

export function acceptControlRequest(
  input: ControlRequestInput,
  prior?: RequestReservation,
): ControlRequestDecision {
  if (!input.authenticated) return denied("bad_signature");
  if (input.now >= input.expires_at) return denied("control-request-expired");
  if (
    input.reply_relay !== undefined
    || !/^[0-9a-f]{64}$/.test(input.session_id)
    || input.request_id.length === 0
    || input.method.length === 0
    || input.payload_digest !== controlPayloadDigest(input.payload)
  ) {
    return denied("control-ingress-relay-invalid");
  }
  const relay = validateBootstrapRelay(input.ingress_relay);
  if (
    relay.verdict === "reject"
    || relay.normalized !== input.ingress_relay
  ) {
    return denied("control-ingress-relay-invalid");
  }

  if (prior === undefined) {
    const reservation: RequestReservation = {
      session_id: input.session_id,
      request_id: input.request_id,
      method: input.method,
      payload_digest: input.payload_digest,
      expires_at: input.expires_at,
      first_ingress_relay: relay.normalized,
      state: "reserved",
    };
    return {
      verdict: "accept",
      action: "execute",
      execute: true,
      response_relay: relay.normalized,
      reservation,
    };
  }

  if (
    prior.session_id !== input.session_id
    || prior.request_id !== input.request_id
    || prior.method !== input.method
    || prior.payload_digest !== input.payload_digest
    || prior.expires_at !== input.expires_at
  ) {
    return denied("control-request-id-conflict");
  }
  if (prior.state === "complete") {
    if (prior.response === undefined) return denied("control-request-id-conflict");
    return {
      verdict: "accept",
      action: "replay",
      execute: false,
      response_relay: relay.normalized,
      reservation: prior,
      response: prior.response,
    };
  }
  return {
    verdict: "accept",
    action: "join",
    execute: false,
    response_relay: relay.normalized,
    reservation: prior,
  };
}

export function routeControlResponse(decision: ControlRequestDecision): string {
  if (decision.verdict === "reject") {
    throw new Error(decision.reason_code);
  }
  return decision.response_relay;
}

export function authorizeAgentMethod(
  input: AgentMethodInput,
): AgentMethodDecision {
  if (input.method !== "heterodyne.agent.publish") {
    return denied("agent-method-prohibited");
  }
  if (input.requests_key_access) return denied("agent-key-access-prohibited");
  if (input.requests_human_profile) return denied("agent-human-profile-prohibited");
  if (input.requests_attribution_bypass) {
    return denied("agent-attribution-bypass-prohibited");
  }
  if (input.token_decision.verdict === "reject") {
    return denied(input.token_decision.reason_code);
  }
  if (!input.sender_proof_valid) return denied("agent-sender-proof-invalid");
  if (
    !input.allowed_kinds.includes(input.kind)
    || !input.allowed_resources.includes(input.resource)
  ) {
    return denied("agent-resource-denied");
  }
  if (
    input.content_bytes < 0
    || input.max_content_bytes <= 0
    || input.content_bytes > input.max_content_bytes
  ) {
    return denied("agent-size-exceeded");
  }
  if (
    input.rate_limit <= 0
    || input.burst_limit <= 0
    || input.rate_count > input.rate_limit
    || input.burst_count > input.burst_limit
  ) {
    return denied("agent-rate-limited");
  }
  return {
    verdict: "accept",
    method: "heterodyne.agent.publish",
  };
}

export function evaluateControlEnrollment(
  input: EnrollmentEvaluationInput,
): EnrollmentEvaluationDecision {
  if (
    input.profile_id !== "heterodyne-control-session-device-v1"
    || !input.binding_proof_valid
    || !input.binding_nonce_matches_bootstrap
  ) {
    return denied("control-enrollment-binding-invalid");
  }
  if (input.organization_persona) {
    return denied("control-organization-enrollment-prohibited");
  }
  if (!input.active_invite || !input.bootstrap_authorized) {
    return denied("control-enrollment-bootstrap-invalid");
  }
  if (input.now >= input.pending_expires_at) {
    return denied("control-request-expired");
  }
  if (input.bootstrap_mode !== "token" && !input.fresh_ceremony) {
    return denied("control-fresh-authorization-required");
  }
  if (input.delegation_state === "relay-provisional") {
    return {
      verdict: "hold",
      state: "provisional",
      authority: false,
    };
  }
  if (input.authorization_state === "provisional") {
    return {
      verdict: "hold",
      state: "authorization-pending",
      authority: false,
    };
  }
  if (input.authorization_state !== "active") {
    return denied("control-authorization-not-active");
  }
  return {
    verdict: "accept",
    state: "active",
    authority: true,
    default_grant: "regular",
  };
}

export function redeemEnrollmentToken(
  input: EnrollmentTokenRedemptionInput,
): EnrollmentTokenRedemptionDecision {
  const { token } = input;
  if (token.token_class !== "control-enrollment") {
    return denied("control-enrollment-token-class-invalid");
  }
  if (!token.signature_valid) {
    return denied("control-enrollment-token-invalid");
  }
  if (input.redeeming_device !== token.issuer_device) {
    return denied("control-enrollment-token-issuer-mismatch");
  }
  if (input.now >= token.expires_at) {
    return denied("control-request-expired");
  }
  if (token.state === "revoked") {
    return denied("control-enrollment-token-revoked");
  }
  if (token.grant_tier === "full") {
    return denied("control-enrollment-token-grant-ceiling");
  }
  if (
    token.expected_enrollee_key !== undefined
    && token.expected_enrollee_key !== input.enrolling_key
  ) {
    return denied("control-enrollment-token-key-mismatch");
  }
  if (token.state === "spent") {
    if (token.enrolling_key !== input.enrolling_key) {
      return denied("control-enrollment-token-conflict");
    }
    return {
      verdict: "accept",
      action: "replay",
      grant_tier: token.grant_tier,
      next: token,
    };
  }
  return {
    verdict: "accept",
    action: "redeem",
    grant_tier: token.grant_tier,
    next: {
      ...token,
      state: "spent",
      enrolling_key: input.enrolling_key,
    },
  };
}

const BASELINE_METHODS = new Set([
  "ping",
  "get_public_key",
  "dm.read",
  "dm.write",
  "dm.sign",
  "nip44_encrypt",
  "nip44_decrypt",
  "decrypt",
  "session.self_revoke",
]);
const REGULAR_METHODS = new Set([
  ...BASELINE_METHODS,
  "sign_event",
  "publish",
  "repo.write",
  "feed.update",
  "config.get",
  "config.put",
]);
const FULL_METHODS = new Set([
  ...REGULAR_METHODS,
  "device.activate",
  "device.cross_sign",
  "token.mint",
  "session.unlock",
]);

export function authorizeControlMethod(
  input: ControlMethodAuthorizationInput,
): ControlMethodAuthorizationDecision {
  if (input.authorization_state !== "active") {
    return denied("control-authorization-not-active");
  }
  if (input.object_type === "security_policy") {
    return denied("control-policy-state-protected");
  }
  const methods = input.grant.tier === "full"
    ? FULL_METHODS
    : input.grant.tier === "regular"
      ? REGULAR_METHODS
      : BASELINE_METHODS;
  const methodAllowed = input.method === "media.upload"
    ? input.grant.media_upload
    : methods.has(input.method);
  if (!methodAllowed) return denied("control-method-not-granted");

  if (
    (input.method === "device.activate"
      || input.method === "device.cross_sign"
      || input.method === "token.mint")
    && !input.fresh_ceremony
  ) {
    return denied("control-fresh-authorization-required");
  }

  const objectAllowed = input.object_type === "none"
    || (
      input.object_type === "repository"
      && input.grant.repositories.includes(input.object_id)
    )
    || (
      input.object_type === "config_namespace"
      && input.grant.config_namespaces.includes(input.object_id)
    )
    || (
      input.object_type === "session"
      && input.grant.sessions.includes(input.object_id)
    );
  if (!objectAllowed) return denied("control-object-not-authorized");
  return { verdict: "accept", method: input.method };
}

export function evaluateControlSessionLifecycle(
  input: ControlSessionLifecycleInput,
): ControlSessionLifecycleDecision {
  if (
    input.self_revoked
    || input.logout
    || input.authorization_state !== "active"
  ) {
    return {
      state: "revoked",
      authority: false,
      terminate_dr: true,
      peer_tombstone: true,
    };
  }
  if (input.now >= input.valid_until) {
    return {
      state: "lapsed",
      authority: false,
      terminate_dr: true,
      peer_tombstone: true,
    };
  }
  return {
    state: "active",
    authority: true,
    terminate_dr: false,
    peer_tombstone: false,
  };
}

export function evaluateMcpToolCall(
  input: McpToolCallInput,
): McpToolCallDecision {
  if (!input.initialized) {
    return denied("control-mcp-not-initialized");
  }
  if (!input.advertised_tools.includes(input.tool)) {
    return denied("control-mcp-tool-unadvertised");
  }
  if (
    input.direction === "full-to-light"
    && !input.inbound_execution_advertised
  ) {
    return denied("control-mcp-inbound-default-deny");
  }
  if (input.cancel_requested) {
    if (!input.cancellation_supported) {
      return denied("control-mcp-cancellation-unsupported");
    }
    return {
      verdict: "accept",
      action: "cancel",
      tool: input.tool,
    };
  }
  if (
    input.timeout_ms <= 0
    || input.now >= input.started_at + input.timeout_ms
  ) {
    return denied("control-mcp-tool-timeout");
  }
  return {
    verdict: "accept",
    action: "execute",
    tool: input.tool,
  };
}

function denied(reason_code: string): { verdict: "reject"; reason_code: string } {
  return { verdict: "reject", reason_code };
}
