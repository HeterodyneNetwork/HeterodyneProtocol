import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  revalidateAuthorizationViewAtEffect,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import { jcsCanonicalize } from "./jcs.js";
import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";

// This module remains the compatibility evaluator for the explicitly frozen
// pre-redesign Control topic source. Current signer-grant validation lives in
// control-signing.ts and uses the live closed schema.

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
  objects: ControlAuthorizationObject[];
  limits: Record<string, number>;
  registry_checkpoint: string;
  issuance_nonce: string;
  agent_role?: string;
  node_key: string;
};

export type ControlAuthorizationObject = {
  class:
    | "none"
    | "session"
    | "repository"
    | "config_namespace"
    | "marmot_group"
    | "feed"
    | "media"
    | "device";
  id: string;
};

export type ControlAuthorizationRecord = {
  record_id: string;
  persona: string;
  client_key: string;
  client_class: "human-light" | "automated";
  approving_node: string;
  approving_authority: string;
  methods: string[];
  objects: ControlAuthorizationObject[];
  limits: Record<string, number>;
  capabilities: Array<
    "control.token.extended" | "control.inbound-execution" | "control.approve"
  >;
  token_lifetime_default_seconds: 300;
  token_lifetime_max_seconds: number;
  inbound_execution: boolean;
  agent_role?: string;
  predecessor: string | null;
  state: "active" | "revoked";
  created_at: number;
  expires_at: number | null;
  signer: string;
  signature: string;
};

export type TokenIssuanceInput = {
  entitlement: ControlAuthorizationRecord;
  group_id: string;
  audience: string;
  node_key: string;
  issuance_nonce: string;
  requested_lifetime_seconds: number;
  node_policy_max_seconds: number;
  authorization_view: CurrentAuthorizationView;
  methods: string[];
  objects: ControlAuthorizationObject[];
  limits: Record<string, number>;
};

const TOKEN_ISSUANCE_INPUT_KEYS = [
  "entitlement",
  "group_id",
  "audience",
  "node_key",
  "issuance_nonce",
  "requested_lifetime_seconds",
  "node_policy_max_seconds",
  "authorization_view",
  "methods",
  "objects",
  "limits",
] as const;

const TOKEN_USE_INPUT_KEYS = [
  "token",
  "signature_valid",
  "expected_issuer",
  "expected_audience",
  "expected_node_key",
  "authenticated_sender_jkt",
  "group_id",
  "current_entitlement",
  "authorization_view",
  "required_scope",
  "method",
  "object",
  "usage",
  "required_agent_role",
] as const;

function snapshotEffectInput<T extends { authorization_view: CurrentAuthorizationView }>(
  input: T,
  keys: readonly string[],
  label: string,
): T {
  const captured = captureExactDataObject(input, [keys], label);
  const snapshot: Record<string, unknown> = {};
  for (const key of keys) {
    snapshot[key] = key === "authorization_view"
      ? captured[key]
      : snapshotClosedDataTree(captured[key], `${label}.${key}`);
  }
  return Object.freeze(snapshot) as T;
}

function normalizedValues(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function normalizedLimits(limits: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(limits).sort(([left], [right]) => left.localeCompare(right)));
}

function objectKey(value: ControlAuthorizationObject): string {
  return jcsCanonicalize(value);
}

function normalizedObjects(values: ControlAuthorizationObject[]): ControlAuthorizationObject[] {
  return [...values]
    .sort((left, right) => objectKey(left).localeCompare(objectKey(right)))
    .map((value) => ({ ...value }));
}

function valuesAreAuthorized(requested: string[], authorized: string[]): boolean {
  return requested.length > 0
    && new Set(requested).size === requested.length
    && requested.every((value) => authorized.includes(value));
}

function objectsAreAuthorized(
  requested: ControlAuthorizationObject[],
  authorized: ControlAuthorizationObject[],
): boolean {
  const requestedKeys = requested.map(objectKey);
  const authorizedKeys = new Set(authorized.map(objectKey));
  return requestedKeys.length > 0
    && new Set(requestedKeys).size === requestedKeys.length
    && requestedKeys.every((value) => authorizedKeys.has(value));
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

function validAuthorization(
  authorization: ControlAuthorizationRecord,
  now: number,
): boolean {
  const hex256 = (value: string) => /^[0-9a-f]{64}$/.test(value);
  const hex512 = (value: string) => /^[0-9a-f]{128}$/.test(value);
  return hex256(authorization.record_id)
    && hex256(authorization.persona)
    && hex256(authorization.client_key)
    && hex256(authorization.approving_node)
    && hex256(authorization.signer)
    && hex512(authorization.signature)
    && authorization.approving_authority.length > 0
    && authorization.methods.length > 0
    && authorization.objects.length > 0
    && limitsAreFinite(authorization.limits)
    && authorization.token_lifetime_default_seconds === 300
    && Number.isSafeInteger(authorization.token_lifetime_max_seconds)
    && authorization.token_lifetime_max_seconds >= 300
    && authorization.token_lifetime_max_seconds <= 3_600
    && Number.isSafeInteger(authorization.created_at)
    && authorization.created_at >= 0
    && (authorization.expires_at === null || (
      Number.isSafeInteger(authorization.expires_at)
      && authorization.expires_at >= 0
      && authorization.expires_at > authorization.created_at
    ))
    && authorization.state === "active"
    && authorization.created_at <= now
    && (authorization.expires_at === null || now < authorization.expires_at);
}

function authorizationScope(authorization: ControlAuthorizationRecord): string {
  return normalizedValues(["control", ...authorization.capabilities]).join(" ");
}

function controlClientJkt(clientKey: string): string | null {
  if (!/^[0-9a-f]{64}$/.test(clientKey)) return null;
  try {
    const point = secp256k1.ProjectivePoint.fromHex(`02${clientKey}`);
    const uncompressed = Buffer.from(point.toRawBytes(false));
    if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) return null;
    const jwk = {
      crv: "secp256k1",
      kty: "EC",
      x: uncompressed.subarray(1, 33).toString("base64url"),
      y: uncompressed.subarray(33, 65).toString("base64url"),
    };
    return createHash("sha256")
      .update(jcsCanonicalize(jwk))
      .digest("base64url");
  } catch {
    return null;
  }
}

function canonicalBase64urlSha256(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function canonicalHex256(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

type ControlTokenIdentityClaims = Omit<ControlToken, "jti">;

function controlTokenIdentityClaims(token: ControlToken): ControlTokenIdentityClaims {
  const { jti: _jti, ...claims } = token;
  return claims;
}

function controlTokenJti(claims: ControlTokenIdentityClaims): string {
  return sha256(`heterodyne-control-token-jti-v1\0${jcsCanonicalize(claims)}`);
}

export function issueControlToken(input: TokenIssuanceInput):
  | { verdict: "accept"; lifetime_seconds: number; refresh_token: null; token: ControlToken }
  | Reject {
  let request: TokenIssuanceInput;
  try {
    request = snapshotEffectInput(input, TOKEN_ISSUANCE_INPUT_KEYS, "Control token issuance input");
  } catch {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (!Number.isSafeInteger(request.requested_lifetime_seconds)
    || request.requested_lifetime_seconds <= 0
    || !Number.isSafeInteger(request.node_policy_max_seconds)
    || request.node_policy_max_seconds <= 0) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const currentView = revalidateAuthorizationViewAtEffect(request.authorization_view);
  if (currentView.verdict === "reject") {
    return { verdict: "reject", reason_code: currentView.reason };
  }
  const now = currentView.evaluated_at;
  const entitlement = request.entitlement;
  if (!Number.isSafeInteger(now) || now < 0 || !validAuthorization(entitlement, now)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const clientJkt = controlClientJkt(entitlement.client_key);
  if (clientJkt === null
    || entitlement.persona !== currentView.persona_key
    || !canonicalHex256(request.group_id)
    || !canonicalHex256(request.node_key)
    || !canonicalHex256(currentView.checkpoint.commit_oid)
    || !canonicalHex256(request.issuance_nonce)
    || currentView.issuer.length === 0
    || request.audience.length === 0
    || !valuesAreAuthorized(request.methods, entitlement.methods)
    || !objectsAreAuthorized(request.objects, entitlement.objects)
    || !limitsAreAuthorized(request.limits, entitlement.limits)
    || (entitlement.client_class === "automated" && entitlement.agent_role === undefined)
    || (entitlement.client_class === "human-light" && entitlement.agent_role !== undefined)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const ceiling = Math.min(
    entitlement.token_lifetime_max_seconds,
    request.node_policy_max_seconds,
    3_600,
  );
  const extended = entitlement.capabilities.includes("control.token.extended");
  const allowed = extended ? ceiling : Math.min(300, ceiling);
  if (request.requested_lifetime_seconds > allowed
    || now > Number.MAX_SAFE_INTEGER - request.requested_lifetime_seconds) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const expiresAt = now + request.requested_lifetime_seconds;
  const claims: ControlTokenIdentityClaims = {
    typ: "at+jwt",
    iss: currentView.issuer,
    aud: request.audience,
    sub: entitlement.client_key,
    iat: now,
    exp: expiresAt,
    cnf: { jkt: clientJkt },
    group_id: request.group_id,
    authorization_id: entitlement.record_id,
    client_id: entitlement.client_key,
    client_class: entitlement.client_class,
    scope: authorizationScope(entitlement),
    methods: normalizedValues(request.methods),
    objects: normalizedObjects(request.objects),
    limits: normalizedLimits(request.limits),
    registry_checkpoint: currentView.checkpoint.commit_oid,
    issuance_nonce: request.issuance_nonce,
    node_key: request.node_key,
    ...(entitlement.agent_role === undefined ? {} : { agent_role: entitlement.agent_role }),
  };
  const token = {
    ...claims,
    jti: controlTokenJti(claims),
  };
  return {
    verdict: "accept",
    lifetime_seconds: request.requested_lifetime_seconds,
    refresh_token: null,
    token,
  };
}

export type TokenUseInput = {
  token: ControlToken;
  signature_valid: boolean;
  expected_issuer: string;
  expected_audience: string;
  expected_node_key: string;
  authenticated_sender_jkt: string;
  group_id: string;
  current_entitlement: ControlAuthorizationRecord;
  authorization_view: CurrentAuthorizationView;
  required_scope: string;
  method: string;
  object: ControlAuthorizationObject;
  usage: Record<string, number>;
  required_agent_role: string | null;
};

export function validateControlTokenUse(input: TokenUseInput): { verdict: "accept" } | Reject {
  let request: TokenUseInput;
  try {
    request = snapshotEffectInput(input, TOKEN_USE_INPUT_KEYS, "Control token use input");
  } catch {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const currentView = revalidateAuthorizationViewAtEffect(request.authorization_view);
  if (currentView.verdict === "reject") {
    return { verdict: "reject", reason_code: currentView.reason };
  }
  const now = currentView.evaluated_at;
  const token = request.token;
  if (!Number.isSafeInteger(now) || now < 0
    || !request.signature_valid || token.typ !== "at+jwt" || token.iss !== request.expected_issuer) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (!Number.isSafeInteger(token.iat) || token.iat < 0
    || !Number.isSafeInteger(token.exp) || token.exp < 0
    || now < token.iat || now >= token.exp
    || token.exp <= token.iat || token.exp - token.iat > 3_600) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (token.aud !== request.expected_audience || token.node_key !== request.expected_node_key) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (!canonicalHex256(token.issuance_nonce)
    || !canonicalHex256(token.jti)
    || controlTokenJti(controlTokenIdentityClaims(token)) !== token.jti) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (token.group_id !== request.group_id) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const entitlement = request.current_entitlement;
  if (!validAuthorization(entitlement, now)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  const clientJkt = controlClientJkt(entitlement.client_key);
  const scopes = token.scope.split(" ");
  const tokenRole = token.agent_role ?? null;
  const entitlementRole = entitlement.agent_role ?? null;
  const tokenObjectKeys = token.objects.map(objectKey);
  const normalizedTokenObjectKeys = normalizedObjects(token.objects).map(objectKey);
  if (clientJkt === null
    || entitlement.persona !== currentView.persona_key
    || token.iss !== currentView.issuer
    || !canonicalBase64urlSha256(token.cnf.jkt)
    || token.cnf.jkt !== clientJkt
    || request.authenticated_sender_jkt !== clientJkt
    || token.authorization_id !== entitlement.record_id
    || token.sub !== entitlement.client_key
    || token.client_id !== entitlement.client_key
    || token.client_class !== entitlement.client_class
    || token.registry_checkpoint !== currentView.checkpoint.commit_oid
    || !canonicalHex256(currentView.checkpoint.commit_oid)
    || token.exp - token.iat > entitlement.token_lifetime_max_seconds
    || (token.exp - token.iat > 300
      && !entitlement.capabilities.includes("control.token.extended"))
    || token.scope !== authorizationScope(entitlement)
    || normalizedValues(scopes).join(" ") !== token.scope
    || !valuesAreAuthorized(token.methods, entitlement.methods)
    || normalizedValues(token.methods).join("\0") !== token.methods.join("\0")
    || !objectsAreAuthorized(token.objects, entitlement.objects)
    || normalizedTokenObjectKeys.join("\0") !== tokenObjectKeys.join("\0")
    || !limitsAreAuthorized(token.limits, entitlement.limits)
    || tokenRole !== entitlementRole
    || tokenRole !== request.required_agent_role
    || !scopes.includes(request.required_scope)
    || !token.methods.includes(request.method)
    || !tokenObjectKeys.includes(objectKey(request.object))
    || !limitsAreAuthorized(request.usage, token.limits)
    || !limitsAreAuthorized(request.usage, entitlement.limits)) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  return { verdict: "accept" };
}

export type ControlEnrollmentCommitInput = {
  enrollment_id: string;
  group_id: string;
  client_key: string;
  authorization_view: CurrentAuthorizationView;
};

export type CommittedControlEnrollment = Readonly<{
  enrollment_id: string;
  group_id: string;
  client_key: string;
  state: "enrollment-only";
  authority: false;
  committed_at: number;
  registry_checkpoint: string;
  repository_rid: string;
  persona_key: string;
  manifest_digest: string;
  issuer: string;
}>;

const CONTROL_ENROLLMENT_COMMIT_INPUT_KEYS = [
  "enrollment_id", "group_id", "client_key", "authorization_view",
] as const;

export function commitControlEnrollment(input: ControlEnrollmentCommitInput):
  | Readonly<{ verdict: "accept"; enrollment: CommittedControlEnrollment }>
  | Reject {
  let request: ControlEnrollmentCommitInput;
  try {
    request = snapshotEffectInput(
      input,
      CONTROL_ENROLLMENT_COMMIT_INPUT_KEYS,
      "Control enrollment commit input",
    );
  } catch {
    return { verdict: "reject", reason_code: "control-enrollment-invalid" };
  }
  if (!canonicalHex256(request.enrollment_id)
    || !canonicalHex256(request.group_id)
    || !canonicalHex256(request.client_key)) {
    return { verdict: "reject", reason_code: "control-enrollment-invalid" };
  }
  const currentView = revalidateAuthorizationViewAtEffect(request.authorization_view);
  if (currentView.verdict === "reject") {
    return { verdict: "reject", reason_code: currentView.reason };
  }
  if (!Number.isSafeInteger(currentView.evaluated_at) || currentView.evaluated_at < 0
    || !canonicalHex256(currentView.checkpoint.commit_oid)) {
    return { verdict: "reject", reason_code: "control-enrollment-invalid" };
  }
  return {
    verdict: "accept",
    enrollment: Object.freeze({
      enrollment_id: request.enrollment_id,
      group_id: request.group_id,
      client_key: request.client_key,
      state: "enrollment-only",
      authority: false,
      committed_at: currentView.evaluated_at,
      registry_checkpoint: currentView.checkpoint.commit_oid,
      repository_rid: currentView.repository_rid,
      persona_key: currentView.persona_key,
      manifest_digest: currentView.manifest_digest,
      issuer: currentView.issuer,
    }),
  };
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
