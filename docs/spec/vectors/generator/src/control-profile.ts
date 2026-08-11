import { createHash } from "node:crypto";
import { jcsCanonicalize } from "./jcs.js";

type Reject = { verdict: "reject"; reason_code: string };

export type InvitationInput = {
  invitation_enabled: boolean;
  keypackage_valid: boolean;
  member_count: number;
  node_account_matches: boolean;
  entitlement_state: "none" | "active" | "revoked";
  method: string;
};

export function authorizeInvitation(input: InvitationInput):
  | { verdict: "accept"; state: "enrollment-only" | "active"; authority: boolean }
  | Reject {
  if (!input.invitation_enabled) {
    return { verdict: "reject", reason_code: "control-invitation-disabled" };
  }
  if (!input.keypackage_valid || input.member_count !== 2 || !input.node_account_matches) {
    return { verdict: "reject", reason_code: "control-keypackage-invalid" };
  }
  if (input.entitlement_state === "revoked") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  if (input.entitlement_state === "active") {
    return { verdict: "accept", state: "active", authority: true };
  }
  if (input.method !== "control.enrollment.start" && input.method !== "control.initialize") {
    return { verdict: "reject", reason_code: "control-enrollment-required" };
  }
  return { verdict: "accept", state: "enrollment-only", authority: false };
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
  methods: string[];
  objects: string[];
  node_key: string;
};

export type TokenIssuanceInput = {
  entitlement_state: "active" | "revoked";
  client_key: string;
  client_jkt: string;
  group_id: string;
  issuer: string;
  audience: string;
  node_key: string;
  authorization_id: string;
  requested_lifetime_seconds: number;
  entitlement_max_seconds: number;
  node_policy_max_seconds: number;
  extended_capability: boolean;
  now: number;
  methods: string[];
  objects: string[];
};

export function issueControlToken(input: TokenIssuanceInput):
  | { verdict: "accept"; lifetime_seconds: number; refresh_token: null; token: ControlToken }
  | Reject {
  if (input.entitlement_state !== "active") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  const ceiling = Math.min(input.entitlement_max_seconds, input.node_policy_max_seconds, 3_600);
  const allowed = input.extended_capability ? ceiling : Math.min(300, ceiling);
  if (input.requested_lifetime_seconds <= 0 || input.requested_lifetime_seconds > allowed) {
    return { verdict: "reject", reason_code: "control-token-expired" };
  }
  const jti = sha256(jcsCanonicalize({
    authorization_id: input.authorization_id,
    audience: input.audience,
    client_key: input.client_key,
    group_id: input.group_id,
    issued_at: input.now,
    node_key: input.node_key,
  }));
  return {
    verdict: "accept",
    lifetime_seconds: input.requested_lifetime_seconds,
    refresh_token: null,
    token: {
      typ: "at+jwt",
      iss: input.issuer,
      aud: input.audience,
      sub: input.client_key,
      jti,
      iat: input.now,
      exp: input.now + input.requested_lifetime_seconds,
      cnf: { jkt: input.client_jkt },
      group_id: input.group_id,
      authorization_id: input.authorization_id,
      methods: [...input.methods].sort(),
      objects: [...input.objects].sort(),
      node_key: input.node_key,
    },
  };
}

export type TokenUseInput = {
  token: ControlToken;
  signature_valid: boolean;
  now: number;
  expected_issuer: string;
  expected_audience: string;
  authenticated_sender_jkt: string;
  group_id: string;
  entitlement_state: "active" | "revoked";
  method: string;
  object: string;
};

export function validateControlTokenUse(input: TokenUseInput): { verdict: "accept" } | Reject {
  const token = input.token;
  if (!input.signature_valid || token.typ !== "at+jwt" || token.iss !== input.expected_issuer) {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  if (input.now < token.iat || input.now >= token.exp) {
    return { verdict: "reject", reason_code: "control-token-expired" };
  }
  if (token.aud !== input.expected_audience) {
    return { verdict: "reject", reason_code: "control-token-audience-invalid" };
  }
  if (token.cnf.jkt !== input.authenticated_sender_jkt || token.sub.length !== 64) {
    return { verdict: "reject", reason_code: "control-token-sender-invalid" };
  }
  if (token.group_id !== input.group_id) {
    return { verdict: "reject", reason_code: "control-token-group-invalid" };
  }
  if (input.entitlement_state !== "active") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  if (!token.methods.includes(input.method) || !token.objects.includes(input.object)) {
    return { verdict: "reject", reason_code: "control-token-scope-invalid" };
  }
  return { verdict: "accept" };
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
    return { verdict: "reject", reason_code: "control-token-expired" };
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
    return { verdict: "reject", reason_code: "control-sftp-expired" };
  }
  const separated = grant.onion_address !== grant.radicle_onion_address
    && grant.service_process_id !== grant.radicle_process_id;
  const authenticated = separated
    && input.onion_address === grant.onion_address
    && input.tor_client_key === grant.tor_client_key
    && input.ssh_client_key === grant.ssh_client_key
    && input.ssh_host_key === grant.ssh_host_key;
  if (!authenticated) {
    return { verdict: "reject", reason_code: "control-sftp-auth-invalid" };
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
    : { verdict: "reject", reason_code: "control-sftp-resource-denied" };
}

export function controlPayloadDigest(payload: unknown): string {
  return sha256(jcsCanonicalize(payload));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
