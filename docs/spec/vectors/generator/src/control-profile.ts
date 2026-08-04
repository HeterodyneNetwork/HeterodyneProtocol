import { createHash } from "node:crypto";
import {
  validateAgentAccessToken,
  type AgentTokenValidationInput,
} from "./agent-authorship.js";
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

export type AgentAuthorizationBinding = {
  issuer: string;
  pairwise_sub: string;
  client_id: string;
  role_id: string;
  role_key: string;
  source_claim_ids: string[];
  audience: string;
  scope: string;
  token_jti: string;
  control_session: string;
  request_id: string;
  method: string;
  payload_digest: string;
  feed: string;
  resource: string;
  ledger_persona: string;
  ledger_generation: number;
  ledger_checkpoint: {
    event_id: string;
    sequence: number;
  };
  ledger_status:
    | "active"
    | "provisional"
    | "untrusted"
    | "conflicted"
    | "invalid"
    | "expired"
    | "revoked";
};

export type AgentMethodInput = {
  method: string;
  initialization_complete: boolean;
  now: number;
  intended_audience: string;
  request_binding: AgentAuthorizationBinding;
  token: {
    token_class: "agent-workload" | "control-enrollment" | "recovery";
    signature_valid: boolean;
    typ: string;
    issued_at: number;
    expires_at: number;
    audience: string[];
    scope: string;
    jti: string;
    cnf_jkt: string;
    status: "VALID" | "INVALID" | "SUSPENDED";
    status_binding_valid: boolean;
    sender_key: string;
    binding: AgentAuthorizationBinding;
  };
  sender_proof: {
    signature_valid: boolean;
    signing_key: string;
    jkt: string;
    token_jti: string;
    issued_at: number;
    expires_at: number;
    nonce: string;
    nonce_state: "unused" | "used";
    binding: AgentAuthorizationBinding;
  };
  current_ledger: {
    persona: string;
    generation: number;
    checkpoint: {
      event_id: string;
      sequence: number;
    };
    status: AgentAuthorizationBinding["ledger_status"];
  };
  current_role_authority: {
    role_id: string;
    role_key: string;
    status: AgentAuthorizationBinding["ledger_status"];
    expires_at: number;
  };
  current_source_authority: {
    claim_ids: string[];
    status: AgentAuthorizationBinding["ledger_status"];
    expires_at: number;
  };
  session_expires_at: number;
  registration_expires_at: number;
  consent_expires_at: number;
  pending_issuance_generation: number;
  kind: number;
  allowed_kinds: number[];
  feed: string;
  allowed_feeds: string[];
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
      purge_pending_issuance?: true;
      requires_current_generation_reissuance?: true;
    };

export type AgentCredentialStateDecision =
  | {
      verdict: "accept";
      current_generation: number;
      purge_pending_issuance: false;
    }
  | {
      verdict: "reject";
      reason_code: "agent-token-stale-credential";
      purge_pending_issuance: boolean;
      requires_current_generation_reissuance: true;
    };

export type EnrollmentIdentityJoin = {
  invite_event_id: string;
  enrollee_key: string;
  dr_transcript_hash: string;
  dr_session_id: string;
  delegation_address: string;
  delegation_event_id: string;
  grant_subject: string;
  executor_nid: string;
  executor_device_key: string;
  negotiated_protocol: string;
  negotiated_version: string;
};

export type EnrollmentBootstrapEvidence =
  | {
      mode: "qr" | "challenge";
      credential_valid: boolean;
      credential_validated_at: number;
      ceremony_prompted_at: number;
      ceremony_completed_at: number;
      ceremony_authorized: boolean;
    }
  | {
      mode: "token";
      token_state: "unspent" | "spent" | "revoked";
      token_redeemed_at: number;
    };

export type EnrollmentEvaluationInput = {
  profile_id: string;
  binding_proof_valid: boolean;
  binding_nonce_matches_bootstrap: boolean;
  active_invite: boolean;
  pending_expires_at: number;
  now: number;
  organization_persona: boolean;
  delegation_state: "relay-provisional" | "repository-final";
  identity_join: {
    expected: EnrollmentIdentityJoin;
    presented: EnrollmentIdentityJoin;
  };
  bootstrap_evidence: EnrollmentBootstrapEvidence;
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

export type EnrollmentIdentityJoinDecision =
  | {
      verdict: "accept";
      normalized: {
        all_identity_joins_match: true;
      };
    }
  | {
      verdict: "reject";
      reason_code: "control-enrollment-identity-join-mismatch";
    };

export type EnrollmentTokenRecord = {
  token_class: "control-enrollment" | "agent-workload" | "recovery";
  token_id: string;
  persona: string;
  epoch_key: string;
  minting_device: string;
  kel_head: {
    event_id: string;
    sequence: number;
  };
  issued_at: number;
  enrolling_key?: string;
  expected_enrollee_key?: string;
  recorded_delegation_id?: string;
  expires_at: number;
  grant_tier: "baseline" | "regular" | "full";
  state: "unspent" | "spent" | "revoked";
  signature_valid: boolean;
  ledger_finality: "relay-provisional" | "repository-final";
  ledger_decision:
    | "active"
    | "provisional"
    | "untrusted"
    | "conflicted"
    | "invalid"
    | "expired"
    | "revoked";
};

export type EnrollmentTokenRedemptionInput = {
  token: EnrollmentTokenRecord;
  redeeming_device: string;
  enrolling_key: string;
  delegation_id?: string;
  current_persona: string;
  current_epoch_key: string;
  current_kel_head: {
    event_id: string;
    sequence: number;
  };
  now: number;
};

export type EnrollmentTokenRedemptionDecision =
  | {
      verdict: "accept";
      action: "redeem" | "replay";
      grant_tier: "baseline" | "regular";
      delegation_id: string;
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
  side_effect_state: "not-started" | "in-progress" | "committed" | "completed";
  started_at: number;
  timeout_ms: number;
  now: number;
};

export type McpToolCallDecision =
  | {
      verdict: "accept";
      action: "execute" | "cancel" | "ignore-cancellation";
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
  if (!input.initialization_complete) {
    return denied("control-mcp-not-initialized");
  }
  if (
    input.token.token_class !== "agent-workload"
    || !input.token.signature_valid
    || input.token.issued_at > input.now
    || input.token.expires_at <= input.now
    || input.token.expires_at <= input.token.issued_at
    || input.token.expires_at - input.token.issued_at > 300
  ) {
    return denied("agent-token-expired");
  }
  if (!agentBindingsEqual(input.token.binding, input.request_binding)) {
    return denied("agent-token-binding-mismatch");
  }
  const credentialState = evaluateAgentCredentialState({
    request_binding: input.request_binding,
    current_ledger: input.current_ledger,
    pending_issuance_generation: input.pending_issuance_generation,
  });
  if (
    input.request_binding.method !== input.method
    || credentialState.verdict === "reject"
  ) {
    return {
      verdict: "reject",
      reason_code: "agent-token-stale-credential",
      requires_current_generation_reissuance: true,
      ...(credentialState.verdict === "reject"
          && credentialState.purge_pending_issuance
        ? { purge_pending_issuance: true as const }
        : {}),
    };
  }
  if (
    input.current_role_authority.status !== "active"
    || input.current_role_authority.expires_at <= input.now
    || input.current_role_authority.role_id !== input.request_binding.role_id
    || input.current_role_authority.role_key !== input.request_binding.role_key
  ) {
    return denied("agent-role-mismatch");
  }
  if (
    input.current_source_authority.status !== "active"
    || input.current_source_authority.expires_at <= input.now
    || input.current_source_authority.claim_ids.length === 0
    || !exactStringArray(
      input.current_source_authority.claim_ids,
      input.request_binding.source_claim_ids,
    )
  ) {
    return denied("agent-token-stale");
  }
  if (
    input.intended_audience.length === 0
    || input.request_binding.audience !== input.intended_audience
    || input.request_binding.scope !== AGENT_PUBLICATION_SCOPE
    || input.request_binding.token_jti !== input.token.jti
    || input.request_binding.feed !== input.feed
    || input.request_binding.resource !== input.resource
  ) {
    return denied("agent-resource-denied");
  }
  const tokenDecision = validateAgentAccessToken({
    typ: input.token.typ,
    iss: input.token.binding.issuer,
    sub: input.token.binding.pairwise_sub,
    aud: input.token.audience,
    exp: input.token.expires_at,
    iat: input.token.issued_at,
    jti: input.token.jti,
    client_id: input.token.binding.client_id,
    scope: input.token.scope,
    cnf_jkt: input.token.cnf_jkt,
    sender_proof_jkt: input.sender_proof.jkt,
    sender_proof_valid: input.sender_proof.signature_valid,
    agent_role_id: input.token.binding.role_id,
    expected_issuer: input.request_binding.issuer,
    expected_subject: input.request_binding.pairwise_sub,
    expected_audience: input.intended_audience,
    expected_client_id: input.request_binding.client_id,
    expected_scope: AGENT_PUBLICATION_SCOPE,
    expected_role_id: input.request_binding.role_id,
    now: input.now,
    status: input.token.status,
    ledger_active: input.current_ledger.status === "active",
    ledger_binding_valid: credentialState.verdict === "accept",
    status_binding_valid: input.token.status_binding_valid,
    session_expires_at: input.session_expires_at,
    delegation_expires_at: input.current_role_authority.expires_at,
    registration_expires_at: input.registration_expires_at,
    consent_expires_at: input.consent_expires_at,
    source_authorization_expires_at:
      input.current_source_authority.expires_at,
  } satisfies AgentTokenValidationInput);
  if (tokenDecision.verdict === "reject") return tokenDecision;
  if (
    !input.sender_proof.signature_valid
    || input.sender_proof.signing_key !== input.token.sender_key
    || input.sender_proof.token_jti !== input.token.jti
    || input.sender_proof.issued_at > input.now
    || input.sender_proof.expires_at <= input.now
    || input.sender_proof.expires_at > input.token.expires_at
    || input.sender_proof.nonce.length === 0
    || input.sender_proof.nonce_state !== "unused"
    || !agentBindingsEqual(input.sender_proof.binding, input.request_binding)
  ) {
    return denied("agent-sender-proof-invalid");
  }
  if (
    !input.allowed_kinds.includes(input.kind)
    || !input.allowed_feeds.includes(input.feed)
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

export function evaluateAgentCredentialState(input: Pick<
  AgentMethodInput,
  "request_binding" | "current_ledger" | "pending_issuance_generation"
>): AgentCredentialStateDecision {
  const current = input.current_ledger;
  const expected = input.request_binding;
  if (
    current.persona !== expected.ledger_persona
    || current.generation !== expected.ledger_generation
    || current.checkpoint.event_id !== expected.ledger_checkpoint.event_id
    || current.checkpoint.sequence !== expected.ledger_checkpoint.sequence
    || current.status !== expected.ledger_status
    || current.status !== "active"
  ) {
    return {
      verdict: "reject",
      reason_code: "agent-token-stale-credential",
      purge_pending_issuance:
        input.pending_issuance_generation !== current.generation,
      requires_current_generation_reissuance: true,
    };
  }
  return {
    verdict: "accept",
    current_generation: current.generation,
    purge_pending_issuance: false,
  };
}

const AGENT_BINDING_FIELDS = [
  "issuer",
  "pairwise_sub",
  "client_id",
  "role_id",
  "role_key",
  "audience",
  "scope",
  "token_jti",
  "control_session",
  "request_id",
  "method",
  "payload_digest",
  "feed",
  "resource",
  "ledger_persona",
  "ledger_generation",
  "ledger_status",
] as const satisfies readonly (keyof AgentAuthorizationBinding)[];

function agentBindingsEqual(
  left: AgentAuthorizationBinding,
  right: AgentAuthorizationBinding,
): boolean {
  return AGENT_BINDING_FIELDS.every((field) => left[field] === right[field])
    && exactStringArray(left.source_claim_ids, right.source_claim_ids)
    && left.ledger_checkpoint.event_id === right.ledger_checkpoint.event_id
    && left.ledger_checkpoint.sequence === right.ledger_checkpoint.sequence;
}

const AGENT_PUBLICATION_SCOPE = "heterodyne:agent:publish";

function exactStringArray(left: string[], right: string[]): boolean {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
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
  if (!input.active_invite) {
    return denied("control-enrollment-bootstrap-invalid");
  }
  const identityDecision = evaluateEnrollmentIdentityJoin(input.identity_join);
  if (identityDecision.verdict === "reject") return identityDecision;
  if (input.now >= input.pending_expires_at) {
    return denied("control-request-expired");
  }
  const bootstrapDecision = evaluateEnrollmentBootstrap(
    input.bootstrap_evidence,
    input.now,
  );
  if (bootstrapDecision.verdict === "reject") return bootstrapDecision;
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

const ENROLLMENT_IDENTITY_JOIN_FIELDS = [
  "invite_event_id",
  "enrollee_key",
  "dr_transcript_hash",
  "dr_session_id",
  "delegation_address",
  "delegation_event_id",
  "grant_subject",
  "executor_nid",
  "executor_device_key",
  "negotiated_protocol",
  "negotiated_version",
] as const satisfies readonly (keyof EnrollmentIdentityJoin)[];

export function evaluateEnrollmentIdentityJoin(input: {
  expected: EnrollmentIdentityJoin;
  presented: EnrollmentIdentityJoin;
}): EnrollmentIdentityJoinDecision {
  const matches = ENROLLMENT_IDENTITY_JOIN_FIELDS.every(
    (field) => input.expected[field] === input.presented[field],
  );
  if (!matches) {
    return {
      verdict: "reject",
      reason_code: "control-enrollment-identity-join-mismatch",
    };
  }
  return {
    verdict: "accept",
    normalized: {
      all_identity_joins_match: true,
    },
  };
}

export function evaluateEnrollmentBootstrap(
  evidence: EnrollmentBootstrapEvidence,
  now: number,
): { verdict: "accept" } | { verdict: "reject"; reason_code: string } {
  if (evidence.mode === "token") {
    if (
      evidence.token_state !== "spent"
      || evidence.token_redeemed_at > now
    ) {
      return denied("control-enrollment-bootstrap-invalid");
    }
    return { verdict: "accept" };
  }
  if (
    !evidence.credential_valid
    || evidence.credential_validated_at < 0
    || evidence.credential_validated_at >= evidence.ceremony_prompted_at
    || evidence.ceremony_prompted_at > evidence.ceremony_completed_at
    || evidence.ceremony_completed_at > now
  ) {
    return denied("control-enrollment-bootstrap-invalid");
  }
  if (!evidence.ceremony_authorized) {
    return denied("control-fresh-authorization-required");
  }
  return { verdict: "accept" };
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
  if (input.redeeming_device !== token.minting_device) {
    return denied("control-enrollment-token-issuer-mismatch");
  }
  if (input.now < token.issued_at || input.now >= token.expires_at) {
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
  if (
    token.ledger_finality !== "repository-final"
    || token.ledger_decision !== "active"
    || token.persona !== input.current_persona
    || token.epoch_key !== input.current_epoch_key
    || token.kel_head.event_id !== input.current_kel_head.event_id
    || token.kel_head.sequence !== input.current_kel_head.sequence
  ) {
    return denied("control-enrollment-token-authority-invalid");
  }
  if (token.state === "spent") {
    if (
      token.enrolling_key !== input.enrolling_key
      || token.recorded_delegation_id === undefined
    ) {
      return denied("control-enrollment-token-conflict");
    }
    return {
      verdict: "accept",
      action: "replay",
      grant_tier: token.grant_tier,
      delegation_id: token.recorded_delegation_id,
      next: token,
    };
  }
  if (input.delegation_id === undefined || input.delegation_id.length === 0) {
    return denied("control-enrollment-token-authority-invalid");
  }
  return {
    verdict: "accept",
    action: "redeem",
    grant_tier: token.grant_tier,
    delegation_id: input.delegation_id,
    next: {
      ...token,
      state: "spent",
      enrolling_key: input.enrolling_key,
      recorded_delegation_id: input.delegation_id,
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

type ControlObjectType = ControlMethodAuthorizationInput["object_type"];

const METHOD_OBJECT_TYPES = new Map<string, ControlObjectType>([
  ["ping", "none"],
  ["get_public_key", "none"],
  ["dm.read", "session"],
  ["dm.write", "session"],
  ["dm.sign", "session"],
  ["nip44_encrypt", "session"],
  ["nip44_decrypt", "session"],
  ["decrypt", "session"],
  ["session.self_revoke", "session"],
  ["sign_event", "session"],
  ["publish", "session"],
  ["repo.write", "repository"],
  ["feed.update", "repository"],
  ["config.get", "config_namespace"],
  ["config.put", "config_namespace"],
  ["device.activate", "session"],
  ["device.cross_sign", "session"],
  ["token.mint", "session"],
  ["session.unlock", "session"],
  ["media.upload", "session"],
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

  const requiredObjectType = METHOD_OBJECT_TYPES.get(input.method);
  if (
    requiredObjectType === undefined
    || input.object_type !== requiredObjectType
  ) {
    return denied("control-object-not-authorized");
  }
  const objectAllowed = (
    input.object_type === "none"
    && input.object_id.length === 0
  )
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
    if (
      input.side_effect_state === "committed"
      || input.side_effect_state === "completed"
    ) {
      return {
        verdict: "accept",
        action: "ignore-cancellation",
        tool: input.tool,
      };
    }
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
