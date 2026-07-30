import { createHash } from "node:crypto";
import { jcsCanonicalize } from "./jcs.js";
import { validateBootstrapRelay } from "./public-reader.js";

export type RequestReservation = {
  session_id: string;
  request_id: string;
  method: string;
  payload_digest: string;
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

function denied(reason_code: string): { verdict: "reject"; reason_code: string } {
  return { verdict: "reject", reason_code };
}
