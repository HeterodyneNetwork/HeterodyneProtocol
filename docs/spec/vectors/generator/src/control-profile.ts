import { createHash } from "node:crypto";
import { jcsCanonicalize } from "./jcs.js";

type Reject = { verdict: "reject"; reason_code: string };

export type InvitationInput = {
  invitation_mode: "off" | "temporary" | "permanent";
  temporary_expires_at: number | null;
  now: number;
  keypackage_valid: boolean;
  keypackage_last_resort: boolean;
  member_count: number;
  node_account_matches: boolean;
  entitlement_state: "none" | "active" | "revoked";
  method: string;
  purpose_bound_invite_valid: boolean;
  explicitly_approved: boolean;
  pending_for_account: number;
  global_pending: number;
  global_pending_cap: number;
  welcome_rate_remaining: number;
  replenishment_rate_remaining: number;
  public_pool_replenishment_requested: boolean;
  reserved_slot_available: boolean;
};

export function authorizeInvitation(input: InvitationInput):
  | { verdict: "accept"; state: "enrollment-only" | "active"; authority: boolean }
  | Reject {
  if (!input.keypackage_valid || input.member_count !== 2 || !input.node_account_matches) {
    return { verdict: "reject", reason_code: "control-keypackage-invalid" };
  }
  if (input.entitlement_state === "revoked") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  const entitledOrApproved = input.entitlement_state === "active" || input.explicitly_approved;
  if (entitledOrApproved && !input.reserved_slot_available) {
    return { verdict: "reject", reason_code: "control-enrollment-unavailable" };
  }
  const open = input.invitation_mode === "permanent"
    || (input.invitation_mode === "temporary"
      && input.temporary_expires_at !== null
      && input.now < input.temporary_expires_at);
  if (!entitledOrApproved && !input.purpose_bound_invite_valid && !open) {
    return { verdict: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (input.public_pool_replenishment_requested
    && input.global_pending >= input.global_pending_cap) {
    return { verdict: "reject", reason_code: "control-keypackage-replenishment-paused" };
  }
  if (input.welcome_rate_remaining <= 0
    || (input.public_pool_replenishment_requested && input.replenishment_rate_remaining <= 0)) {
    return { verdict: "reject", reason_code: "control-enrollment-rate-limited" };
  }
  if (input.pending_for_account >= 1
    || (!entitledOrApproved && input.global_pending >= input.global_pending_cap)) {
    return { verdict: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (input.entitlement_state === "active") {
    return { verdict: "accept", state: "active", authority: true };
  }
  if (input.method !== "control.enrollment.start" && input.method !== "control.initialize") {
    return { verdict: "reject", reason_code: "control-enrollment-required" };
  }
  return { verdict: "accept", state: "enrollment-only", authority: false };
}

export function evaluatePendingEnrollment(input: {
  created_at: number;
  now: number;
}): { verdict: "accept"; state: "enrollment-only"; expires_at: number } | Reject {
  const expiresAt = input.created_at + 1_800;
  return input.now < expiresAt
    ? { verdict: "accept", state: "enrollment-only", expires_at: expiresAt }
    : { verdict: "reject", reason_code: "control-enrollment-unavailable" };
}

export type Entitlement = {
  record_id: string;
  client_key: string;
  predecessor: string | null;
  state: "active" | "revoked";
  methods: string[];
  objects: string[];
  authorized_writer: boolean;
  explicit_consent: boolean;
};

export function evaluateEntitlementUpdate(
  current: Entitlement | null,
  next: Entitlement,
): ({ verdict: "accept" } & Entitlement) | Reject {
  if (!next.authorized_writer || (current !== null && next.predecessor !== current.record_id)) {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  if (current?.state === "revoked" && next.state !== "revoked") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  const expands = current !== null && (
    next.methods.some((value) => !current.methods.includes(value))
    || next.objects.some((value) => !current.objects.includes(value))
  );
  if (expands && !next.explicit_consent) {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  return {
    verdict: "accept",
    ...next,
    methods: next.state === "revoked" ? [] : [...next.methods].sort(),
    objects: next.state === "revoked" ? [] : [...next.objects].sort(),
  };
}

export type ControlToken = {
  typ: "at+jwt";
  iss: string;
  aud: string;
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  cnf: { jkt: string };
  group_id: string;
  authorization_id: string;
  client_id: string;
  client_class: "human-light" | "automated";
  scope: string;
  methods: string[];
  objects: string[];
  limits: Record<string, number>;
  registry_checkpoint: string;
  agent_role?: string;
  node_key: string;
};

export type TokenEntitlementState = {
  record_id: string;
  state: "active" | "revoked";
  client_key: string;
  client_id: string;
  client_class: "human-light" | "automated";
  scopes: string[];
  methods: string[];
  objects: string[];
  limits: Record<string, number>;
  registry_checkpoint: string;
  agent_role: string | null;
  max_token_lifetime_seconds: number;
};

export type TokenIssuanceInput = {
  entitlement: TokenEntitlementState;
  client_jkt: string;
  group_id: string;
  issuer: string;
  audience: string;
  node_key: string;
  requested_lifetime_seconds: number;
  node_policy_max_seconds: number;
  extended_capability: boolean;
  now: number;
  authorization_view_authenticated: boolean;
  authorization_view_conflicted: boolean;
  authorization_view_age_seconds: number;
  scopes: string[];
  methods: string[];
  objects: string[];
  limits: Record<string, number>;
  agent_role: string | null;
};

function normalizedValues(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function normalizedLimits(limits: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(limits).sort(([left], [right]) => left.localeCompare(right)));
}

function valuesAreAuthorized(requested: string[], authorized: string[]): boolean {
  return requested.length > 0 && requested.every((value) => authorized.includes(value));
}

function limitsAreFinite(limits: Record<string, number>): boolean {
  const entries = Object.entries(limits);
  return entries.length > 0 && entries.every(([name, value]) =>
    name.length > 0 && Number.isFinite(value) && Number.isInteger(value) && value > 0);
}

function limitsAreAuthorized(
  requested: Record<string, number>,
  authorized: Record<string, number>,
): boolean {
  return limitsAreFinite(requested) && Object.entries(requested).every(([name, value]) => {
    const ceiling = authorized[name];
    return ceiling !== undefined && Number.isFinite(ceiling) && value <= ceiling;
  });
}

export function issueControlToken(input: TokenIssuanceInput):
  | { verdict: "accept"; lifetime_seconds: number; refresh_token: null; token: ControlToken }
  | Reject {
  const entitlement = input.entitlement;
  if (entitlement.state !== "active") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  const freshness = evaluateAuthorizationFreshness({
    authenticated: input.authorization_view_authenticated,
    conflicted: input.authorization_view_conflicted,
    age_seconds: input.authorization_view_age_seconds,
    mutation: false,
    immediate_sync_succeeded: false,
  });
  if (freshness.verdict === "reject") return freshness;
  if (!valuesAreAuthorized(input.scopes, entitlement.scopes)
    || !valuesAreAuthorized(input.methods, entitlement.methods)
    || !valuesAreAuthorized(input.objects, entitlement.objects)
    || !limitsAreAuthorized(input.limits, entitlement.limits)
    || input.agent_role !== entitlement.agent_role
    || (entitlement.client_class === "automated" && input.agent_role === null)
    || (entitlement.client_class === "human-light" && input.agent_role !== null)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const ceiling = Math.min(
    entitlement.max_token_lifetime_seconds,
    input.node_policy_max_seconds,
    3_600,
  );
  const allowed = input.extended_capability ? ceiling : Math.min(300, ceiling);
  if (input.requested_lifetime_seconds <= 0 || input.requested_lifetime_seconds > allowed) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const jti = sha256(jcsCanonicalize({
    authorization_id: entitlement.record_id,
    audience: input.audience,
    client_key: entitlement.client_key,
    group_id: input.group_id,
    issued_at: input.now,
    node_key: input.node_key,
    registry_checkpoint: entitlement.registry_checkpoint,
  }));
  const token = {
    typ: "at+jwt" as const,
    iss: input.issuer,
    aud: input.audience,
    sub: entitlement.client_key,
    jti,
    iat: input.now,
    exp: input.now + input.requested_lifetime_seconds,
    cnf: { jkt: input.client_jkt },
    group_id: input.group_id,
    authorization_id: entitlement.record_id,
    client_id: entitlement.client_id,
    client_class: entitlement.client_class,
    scope: normalizedValues(input.scopes).join(" "),
    methods: normalizedValues(input.methods),
    objects: normalizedValues(input.objects),
    limits: normalizedLimits(input.limits),
    registry_checkpoint: entitlement.registry_checkpoint,
    node_key: input.node_key,
    ...(input.agent_role === null ? {} : { agent_role: input.agent_role }),
  };
  return {
    verdict: "accept",
    lifetime_seconds: input.requested_lifetime_seconds,
    refresh_token: null,
    token,
  };
}

export type TokenUseInput = {
  token: ControlToken;
  signature_valid: boolean;
  now: number;
  expected_issuer: string;
  expected_audience: string;
  expected_node_key: string;
  authenticated_sender_jkt: string;
  group_id: string;
  current_entitlement: TokenEntitlementState;
  authorization_view_authenticated: boolean;
  authorization_view_conflicted: boolean;
  authorization_view_age_seconds: number;
  required_scope: string;
  method: string;
  object: string;
  usage: Record<string, number>;
  required_agent_role: string | null;
};

export function validateControlTokenUse(input: TokenUseInput): { verdict: "accept" } | Reject {
  const token = input.token;
  if (!input.signature_valid || token.typ !== "at+jwt" || token.iss !== input.expected_issuer) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (input.now < token.iat || input.now >= token.exp
    || token.exp <= token.iat || token.exp - token.iat > 3_600) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (token.aud !== input.expected_audience || token.node_key !== input.expected_node_key) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (token.cnf.jkt !== input.authenticated_sender_jkt || token.sub.length !== 64) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (token.group_id !== input.group_id) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const entitlement = input.current_entitlement;
  if (entitlement.state !== "active") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  const freshness = evaluateAuthorizationFreshness({
    authenticated: input.authorization_view_authenticated,
    conflicted: input.authorization_view_conflicted,
    age_seconds: input.authorization_view_age_seconds,
    mutation: false,
    immediate_sync_succeeded: false,
  });
  if (freshness.verdict === "reject") return freshness;
  const scopes = token.scope.split(" ");
  const tokenRole = token.agent_role ?? null;
  if (token.authorization_id !== entitlement.record_id
    || token.sub !== entitlement.client_key
    || token.client_id !== entitlement.client_id
    || token.client_class !== entitlement.client_class
    || token.registry_checkpoint !== entitlement.registry_checkpoint
    || token.exp - token.iat > entitlement.max_token_lifetime_seconds
    || normalizedValues(scopes).join(" ") !== token.scope
    || !valuesAreAuthorized(scopes, entitlement.scopes)
    || !valuesAreAuthorized(token.methods, entitlement.methods)
    || !valuesAreAuthorized(token.objects, entitlement.objects)
    || !limitsAreAuthorized(token.limits, entitlement.limits)
    || tokenRole !== entitlement.agent_role
    || tokenRole !== input.required_agent_role
    || !scopes.includes(input.required_scope)
    || !token.methods.includes(input.method)
    || !token.objects.includes(input.object)
    || !limitsAreAuthorized(input.usage, token.limits)
    || !limitsAreAuthorized(input.usage, entitlement.limits)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  return { verdict: "accept" };
}

export function evaluateAuthorizationFreshness(input: {
  authenticated: boolean;
  conflicted: boolean;
  age_seconds: number;
  mutation: boolean;
  immediate_sync_succeeded: boolean;
}): { verdict: "accept" } | Reject {
  if (!input.authenticated || input.conflicted || input.age_seconds > 300
    || input.age_seconds < 0 || (input.mutation && !input.immediate_sync_succeeded)) {
    return { verdict: "reject", reason_code: "control-authorization-view-stale" };
  }
  return { verdict: "accept" };
}

export function evaluateDeviceAuthorizationAttempt(input: {
  device_code_entropy_bits: number;
  user_code_entropy_bits: number;
  failed_guesses: number;
  per_code_rate_allowed: boolean;
  node_rate_allowed: boolean;
  normalized_constant_time_match: boolean;
  display_code_matches: boolean;
  display_fingerprint_matches: boolean;
  poll_interval_observed: boolean;
  slow_down_observed: boolean;
  terminal_state: "pending" | "success" | "denied" | "expired";
}): { verdict: "accept"; state: "pending" | "invalidated" }
  | Reject & { state: "pending" | "invalidated" } {
  if (input.device_code_entropy_bits < 128 || input.user_code_entropy_bits < 34.5
    || !input.normalized_constant_time_match) {
    return { verdict: "reject", reason_code: "control-device-code-invalid", state: "invalidated" };
  }
  if (input.failed_guesses >= 5) {
    return { verdict: "reject", reason_code: "control-device-code-invalid", state: "invalidated" };
  }
  if (!input.per_code_rate_allowed || !input.node_rate_allowed
    || !input.poll_interval_observed || !input.slow_down_observed) {
    return { verdict: "reject", reason_code: "control-device-code-rate-limited", state: "pending" };
  }
  if (!input.display_code_matches || !input.display_fingerprint_matches) {
    return { verdict: "reject", reason_code: "control-device-code-display-mismatch", state: "pending" };
  }
  return {
    verdict: "accept",
    state: input.terminal_state === "pending" ? "pending" : "invalidated",
  };
}

export function evaluateInvitePreauthorization(input: {
  purpose: "control-enrollment" | "device-enrollment";
  approval_mode: "interactive" | "preauthorized";
  client_class: "human-light" | "automated" | "light-device" | "full-device" | "recovery-device";
  expected_client_pubkey: string | null;
  unbound_bearer_enabled: boolean;
  node_allows_unbound_bearer: boolean;
  methods: string[];
  objects: string[];
  limits: Record<string, number>;
  agent_role: string | null;
  token_lifetime_ceiling_seconds: number;
  keri_authorized_device: boolean;
}):
  | { verdict: "accept"; prompt_free: boolean; risk: "normal" | "higher" }
  | Reject {
  if (input.approval_mode === "interactive") {
    return { verdict: "accept", prompt_free: false, risk: "normal" };
  }
  const privateControlClass = input.client_class === "human-light"
    || input.client_class === "automated";
  const finite = input.methods.length > 0
    && input.objects.length > 0
    && Object.keys(input.limits).length > 0
    && Object.values(input.limits).every((value) => Number.isInteger(value) && value > 0)
    && input.token_lifetime_ceiling_seconds > 0
    && input.token_lifetime_ceiling_seconds <= 3_600;
  if (input.purpose !== "control-enrollment" || !privateControlClass
    || input.keri_authorized_device || !finite) {
    return { verdict: "reject", reason_code: "invite-preauthorization-invalid" };
  }
  if (input.client_class === "automated" && input.agent_role === null) {
    return { verdict: "reject", reason_code: "invite-preauthorization-invalid" };
  }
  if (input.expected_client_pubkey === null) {
    if (!input.unbound_bearer_enabled || !input.node_allows_unbound_bearer) {
      return { verdict: "reject", reason_code: "invite-preauthorization-invalid" };
    }
    return { verdict: "accept", prompt_free: true, risk: "higher" };
  }
  return { verdict: "accept", prompt_free: true, risk: "normal" };
}

export type OperationInput = {
  node_key: string;
  group_id: string;
  request_id: string;
  operation_id: string;
  method: string;
  object: string;
  payload_digest: string;
  expires_at: number;
  now: number;
  mutation: boolean;
  inherently_idempotent: boolean;
  prior_result_proven: boolean;
};

export type OperationReservation = {
  node_key: string;
  group_id: string;
  request_id: string;
  operation_id: string;
  method: string;
  object: string;
  payload_digest: string;
  expires_at: number;
};

export function processControlOperation(input: OperationInput, prior?: OperationReservation):
  | { verdict: "accept"; action: "execute" | "join"; execute: boolean; reservation: OperationReservation }
  | Reject
  | { verdict: "indeterminate"; reason_code: "control-operation-indeterminate" } {
  if (input.now >= input.expires_at) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const reservation: OperationReservation = {
    node_key: input.node_key,
    group_id: input.group_id,
    request_id: input.request_id,
    operation_id: input.operation_id,
    method: input.method,
    object: input.object,
    payload_digest: input.payload_digest,
    expires_at: input.expires_at,
  };
  if (prior === undefined) {
    return { verdict: "accept", action: "execute", execute: true, reservation };
  }
  const sameRequest = prior.group_id === input.group_id
    && prior.request_id === input.request_id
    && prior.operation_id === input.operation_id;
  const sameBytes = prior.method === input.method
    && prior.object === input.object
    && prior.payload_digest === input.payload_digest;
  if (sameRequest && !sameBytes) {
    return { verdict: "reject", reason_code: "control-operation-conflict" };
  }
  if (sameRequest && prior.node_key === input.node_key) {
    return { verdict: "accept", action: "join", execute: false, reservation: prior };
  }
  if (!input.mutation || input.inherently_idempotent || input.prior_result_proven) {
    return { verdict: "accept", action: "execute", execute: true, reservation };
  }
  return { verdict: "indeterminate", reason_code: "control-operation-indeterminate" };
}

export function retentionDecision(input: {
  created_at: number;
  requested_retention_seconds: number;
  request_expires_at: number;
}): {
  expires_at: number;
  retention_seconds: number;
  excluded_from_backup: string[];
} {
  const retentionSeconds = Math.min(Math.max(input.requested_retention_seconds, 0), 86_400);
  return {
    expires_at: Math.min(input.created_at + retentionSeconds, input.request_expires_at),
    retention_seconds: retentionSeconds,
    excluded_from_backup: ["access_tokens", "control_frames", "device_codes", "mls_state", "transcripts"],
  };
}

type RecoverySet = {
  repositories: Array<{ rid: string; head: string }>;
  portable_manifest_id: string;
  object_digests: string[];
};

export function evaluateEpochActivation(input: {
  epoch_unlocked: boolean;
  registration_valid: boolean;
  prepared: boolean;
  epoch_relocked_before_transfer: boolean;
  expected: RecoverySet;
  completion: RecoverySet | null;
}): { verdict: "accept"; action: "prepare-and-relock" | "activate" } | Reject {
  if (!input.registration_valid) {
    return { verdict: "reject", reason_code: "control-registration-invalid" };
  }
  if (!input.prepared) {
    return input.epoch_unlocked
      ? { verdict: "accept", action: "prepare-and-relock" }
      : { verdict: "reject", reason_code: "control-recovery-locked" };
  }
  if (input.epoch_unlocked || !input.epoch_relocked_before_transfer) {
    return { verdict: "reject", reason_code: "control-recovery-locked" };
  }
  if (input.completion === null || jcsCanonicalize(input.expected) !== jcsCanonicalize(input.completion)) {
    return { verdict: "reject", reason_code: "control-activation-mismatch" };
  }
  return { verdict: "accept", action: "activate" };
}

export type RecoveryGrant = {
  prospective_nid: string;
  repositories: string[];
  direction: "fetch" | "push";
  byte_ceiling: number;
  expires_at: number;
};

export function evaluateRecoveryAccess(input: {
  grant: RecoveryGrant;
  nid: string;
  repository: string;
  direction: "fetch" | "push";
  bytes: number;
  now: number;
}): { verdict: "accept" } | Reject {
  const valid = input.now < input.grant.expires_at
    && input.nid === input.grant.prospective_nid
    && input.grant.repositories.includes(input.repository)
    && input.direction === input.grant.direction
    && input.bytes >= 0
    && input.bytes <= input.grant.byte_ceiling;
  return valid
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "control-recovery-grant-invalid" };
}

export type SftpGrant = {
  onion_address: string;
  radicle_onion_address: string;
  service_process_id: string;
  radicle_process_id: string;
  tor_client_key: string;
  ssh_client_key: string;
  ssh_host_key: string;
  root: string;
  resources: Array<{ path: string; direction: "read" | "write"; size: number }>;
  byte_ceiling: number;
  expires_at: number;
  channels_disabled: boolean;
  renewal_overlap_seconds: number;
  prior_endpoint_read_only: boolean;
};

export function evaluateSftpAccess(input: {
  grant: SftpGrant;
  onion_address: string;
  tor_client_key: string;
  ssh_client_key: string;
  ssh_host_key: string;
  path: string;
  direction: "read" | "write";
  bytes: number;
  now: number;
}): { verdict: "accept" } | Reject {
  const grant = input.grant;
  if (input.now >= grant.expires_at) {
    return { verdict: "reject", reason_code: "control-sftp-denied" };
  }
  const separated = grant.onion_address !== grant.radicle_onion_address
    && grant.service_process_id !== grant.radicle_process_id;
  const authenticated = separated
    && input.onion_address === grant.onion_address
    && input.tor_client_key === grant.tor_client_key
    && input.ssh_client_key === grant.ssh_client_key
    && input.ssh_host_key === grant.ssh_host_key;
  if (!authenticated) {
    return { verdict: "reject", reason_code: "control-sftp-denied" };
  }
  const resource = grant.resources.find(({ path, direction }) => path === input.path && direction === input.direction);
  const withinRoot = input.path === grant.root || input.path.startsWith(`${grant.root}/`);
  const confined = grant.channels_disabled
    && withinRoot
    && resource !== undefined
    && input.bytes >= 0
    && input.bytes <= resource.size
    && input.bytes <= grant.byte_ceiling;
  return confined
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "control-sftp-denied" };
}

export function controlPayloadDigest(payload: unknown): string {
  return sha256(jcsCanonicalize(payload));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
