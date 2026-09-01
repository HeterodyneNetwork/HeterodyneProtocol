import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { Ajv } from "ajv";
import deviceAuthorizationSchema from "../../../schemas/control/control-device-authorization-state-v1.schema.json" with { type: "json" };
import agentPublishSchema from "../../../schemas/control/control-agent-publish-v1.schema.json" with { type: "json" };
import signerGrantSchema from "../../../schemas/control/control-client-authorization-v1.schema.json" with { type: "json" };
import recoveryCompletionSchema from "../../../schemas/control/control-recovery-completion-v1.schema.json" with { type: "json" };
import recoveryGrantSchema from "../../../schemas/control/control-recovery-grant-v1.schema.json" with { type: "json" };
import { injectAgentAttribution, matchesAgentAttributionProfile } from "./agent-authorship.js";
import { hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { snapshotAndVerifyNostrEvent, type VerifiedNostrEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";

type KeyClass = "persona" | "agent";
type Custody = "local" | "nip46";
type Reject = { verdict: "reject"; reason_code: string };

export type SigningGrant = {
  profile: "heterodyne.control.signer-grant.v1";
  spec_version: "heterodyne/0.6.0";
  grant_id: string;
  vault_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  persona_signing_authorized: boolean;
  allowed_methods: string[];
  allowed_event_kinds: number[];
  limits: {
    request_window_seconds: number;
    request_count: number;
    max_event_bytes: number;
    max_value_msats: number;
  };
  oidc_authorization_id: string;
  connection_secret_sha256: string;
  automation_policy?: {
    workload_id: string;
    agent_class: "ai" | "programmatic";
    agent_association: { kind: "key" | "role"; value: string } | null;
    tier: 1 | 2 | 3;
    oidc_scopes: string[];
  };
  issued_at: number;
  expires_at: number;
  predecessor: string | null;
  state: "active" | "revoked";
  revoked_at: number | null;
  authorizing_pubkey: string;
  signature: string;
};

export type PersonaVault = {
  vault_id: string;
  persona_active_key: string;
  signers: Array<{
    public_key: string;
    key_class: KeyClass;
    custody: Custody;
  }>;
};

export type Nip46SigningRequest = {
  grant_id: string;
  vault_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  rpc_request: {
    id: string;
    method: string;
    params: string[];
  };
  value_msats: number;
  now: number;
};

export type GrantUsageState = {
  grant_id: string;
  grant_digest: string;
  authority: GrantAuthorityBinding;
  window_started_at: number;
  consumed_request_count: number;
  revision: number;
  reservations: Array<{
    operation_id: string;
    request_id: string;
    request_digest: string;
    rpc_request: Nip46SigningRequest["rpc_request"];
    value_msats: number;
    window_started_at: number;
    reserved_at: number;
    claimed_at: number | null;
    executing_at: number | null;
    completed_at: number | null;
    state: "reserved" | "claimed" | "executing" | "committed" | "indeterminate";
    execution_token: string | null;
    result_event_id: string | null;
    failure_digest: string | null;
  }>;
};

export type GrantUsageTransition = {
  operation_id: string;
  grant_id: string;
  grant_digest: string;
  authority: GrantAuthorityBinding;
  request_id: string;
  request_digest: string;
  rpc_request: Nip46SigningRequest["rpc_request"];
  value_msats: number;
  expected_revision: number;
  next_revision: number;
  prior_window_started_at: number;
  window_started_at: number;
  prior_consumed_request_count: number;
  consumed_request_count: number;
  reserved_at: number;
  reservation_state: "reserved";
};

export type GrantClaimTransition = {
  operation_id: string;
  grant_id: string;
  grant_digest: string;
  authority: GrantAuthorityBinding;
  request_id: string;
  request_digest: string;
  expected_revision: number;
  next_revision: number;
  prior_reservation_state: "reserved";
  reservation_state: "claimed";
  claimed_at: number;
};

export type GrantExecutionTransition = {
  operation_id: string;
  grant_id: string;
  grant_digest: string;
  authority: GrantAuthorityBinding;
  request_id: string;
  request_digest: string;
  execution_token: string;
  expected_revision: number;
  next_revision: number;
  prior_reservation_state: "claimed";
  reservation_state: "executing";
  executing_at: number;
};

export type GrantAuthorityBinding = {
  vault_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
};

export type Nip46ClientMetadata = {
  requested_methods: string[];
  requested_event_kinds: number[];
  requested_signer_audiences: string[];
};

export type Nip46AuthorizationInput = {
  grant_candidates: SigningGrant[];
  usage_state: GrantUsageState;
  presented_grant: SigningGrant;
  vaults: PersonaVault[];
  request: Nip46SigningRequest;
  client_metadata: Nip46ClientMetadata;
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateSignerGrant = ajv.compile<SigningGrant>(signerGrantSchema);
const validateDeviceAuthorization = ajv.compile<Nip46ConnectionState>(
  deviceAuthorizationSchema,
);
const validateAutomatedPublication = ajv.compile<AutomatedPublication>(agentPublishSchema);
const validateRecoveryGrantSchema = ajv.compile<CompromiseResetGrant>(recoveryGrantSchema);
const validateRecoveryCompletionSchema = ajv.compile<CompromiseResetCompletion>(
  recoveryCompletionSchema,
);

function reject(reason_code: string): Reject {
  return { verdict: "reject", reason_code };
}

function finiteSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function exactSet<T extends string | number>(actual: T[], expected: T[]): boolean {
  return actual.length === expected.length
    && [...actual].sort().join("\0") === [...expected].sort().join("\0");
}

function hasExactKeys(value: object, expected: string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

export function signerGrantProofBytes(
  value: Omit<SigningGrant, "signature"> | SigningGrant,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as SigningGrant;
  return proofBytes("heterodyne-control-signer-grant-v1", unsigned);
}

export function signerGrantStateDigest(grant: SigningGrant): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-signer-grant-state-v1", grant))
    .digest("hex");
}

function grantAuthorityBinding(grant: SigningGrant): GrantAuthorityBinding {
  return {
    vault_id: grant.vault_id,
    persona_active_key: grant.persona_active_key,
    nip46_client_pubkey: grant.nip46_client_pubkey,
    signer_audience: grant.signer_audience,
    selected_signing_pubkey: grant.selected_signing_pubkey,
    key_class: grant.key_class,
  };
}

type ValidatedNip46Request = {
  operation_id: string;
  request_id: string;
  request_digest: string;
  method: string;
  event_kind: number | null;
  event_bytes: number;
  normalized_event: UnsignedEvent | null;
};

function topLevelJsonObjectKeys(source: string): string[] | undefined {
  let index = 0;
  const skipWhitespace = () => {
    while (/\s/.test(source[index] ?? "")) index += 1;
  };
  const scanString = (): string | undefined => {
    const start = index;
    if (source[index] !== '"') return undefined;
    index += 1;
    while (index < source.length) {
      if (source[index] === "\\") {
        index += 2;
      } else if (source[index] === '"') {
        index += 1;
        try {
          return JSON.parse(source.slice(start, index)) as string;
        } catch {
          return undefined;
        }
      } else {
        index += 1;
      }
    }
    return undefined;
  };
  const skipValue = (): boolean => {
    let objectDepth = 0;
    let arrayDepth = 0;
    let inString = false;
    let escaped = false;
    for (; index < source.length; index += 1) {
      const character = source[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{") objectDepth += 1;
      else if (character === "[") arrayDepth += 1;
      else if (character === "}") {
        if (objectDepth === 0 && arrayDepth === 0) return true;
        objectDepth -= 1;
      } else if (character === "]") arrayDepth -= 1;
      else if (character === "," && objectDepth === 0 && arrayDepth === 0) return true;
      if (objectDepth < 0 || arrayDepth < 0) return false;
    }
    return true;
  };
  skipWhitespace();
  if (source[index] !== "{") return undefined;
  index += 1;
  const keys: string[] = [];
  for (;;) {
    skipWhitespace();
    if (source[index] === "}") {
      index += 1;
      skipWhitespace();
      return index === source.length ? keys : undefined;
    }
    const key = scanString();
    if (key === undefined || keys.includes(key)) return undefined;
    keys.push(key);
    skipWhitespace();
    if (source[index] !== ":") return undefined;
    index += 1;
    skipWhitespace();
    if (!skipValue()) return undefined;
    skipWhitespace();
    if (source[index] === ",") {
      index += 1;
      continue;
    }
    if (source[index] !== "}") return undefined;
  }
}

function parseNip46EventTemplate(
  grant: SigningGrant,
  param: string,
): UnsignedEvent | undefined {
  const keys = topLevelJsonObjectKeys(param);
  let event: unknown;
  try {
    event = JSON.parse(param);
  } catch {
    return undefined;
  }
  if (
    keys === undefined
    || event === null
    || typeof event !== "object"
    || Array.isArray(event)
    || !hasExactKeys(event, ["content", "created_at", "kind", "tags"])
  ) return undefined;
  const template = event as Record<string, unknown>;
  if (
    typeof template.content !== "string"
    || !finiteSafeInteger(template.created_at as number)
    || !finiteSafeInteger(template.kind as number)
    || (template.kind as number) > 65535
    || !Array.isArray(template.tags)
    || template.tags.some((tag) =>
      !Array.isArray(tag) || tag.length < 1 || tag.some((member) =>
        typeof member !== "string"
      )
    )
  ) return undefined;
  return {
    pubkey: grant.selected_signing_pubkey,
    created_at: template.created_at as number,
    kind: template.kind as number,
    tags: template.tags as string[][],
    content: template.content,
  };
}

export function nip46RequestDigest(
  grant: SigningGrant,
  request: Nip46SigningRequest,
): string {
  const normalizedEvent = request.rpc_request.method === "sign_event"
    && request.rpc_request.params.length === 1
    ? parseNip46EventTemplate(grant, request.rpc_request.params[0]) ?? null
    : null;
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-nip46-request-v1", {
      grant_digest: signerGrantStateDigest(grant),
      authority: grantAuthorityBinding(grant),
      rpc_request: request.rpc_request,
      normalized_event: normalizedEvent,
      value_msats: request.value_msats,
    }))
    .digest("hex");
}

export function nip46OperationId(
  grant: SigningGrant,
  requestId: string,
): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-nip46-operation-id-v1", {
      grant_digest: signerGrantStateDigest(grant),
      authority: grantAuthorityBinding(grant),
      wire_request_id: requestId,
    }))
    .digest("hex");
}

function validateCanonicalNip46Request(
  grant: SigningGrant,
  request: Nip46SigningRequest,
): ValidatedNip46Request | Reject {
  if (
    Object.keys(request).sort().join("\0") !== [
      "grant_id", "key_class", "nip46_client_pubkey", "now",
      "persona_active_key", "rpc_request", "selected_signing_pubkey",
      "signer_audience", "value_msats", "vault_id",
    ].join("\0")
    || request.rpc_request === null
    || typeof request.rpc_request !== "object"
    || Object.keys(request.rpc_request).sort().join("\0")
      !== ["id", "method", "params"].join("\0")
    || typeof request.rpc_request.id !== "string"
    || !/^[\x20-\x7e]{1,128}$/.test(request.rpc_request.id)
    || !/^[a-z][a-z0-9_]{0,63}$/.test(request.rpc_request.method)
    || !Array.isArray(request.rpc_request.params)
    || request.rpc_request.params.length > 64
    || request.rpc_request.params.some((param) =>
      typeof param !== "string" || Buffer.byteLength(param, "utf8") > 1_048_576
    )
  ) {
    return reject("control-nip46-request-invalid");
  }
  let eventKind: number | null = null;
  let eventBytes = Buffer.byteLength(jcsCanonicalize(request.rpc_request), "utf8");
  let normalizedEvent: UnsignedEvent | null = null;
  if (request.rpc_request.method === "sign_event") {
    if (request.rpc_request.params.length !== 1) {
      return reject("control-nip46-request-invalid");
    }
    const param = request.rpc_request.params[0];
    normalizedEvent = parseNip46EventTemplate(grant, param) ?? null;
    if (normalizedEvent === null) {
      return reject("control-nip46-request-invalid");
    }
    eventKind = normalizedEvent.kind;
    eventBytes = Buffer.byteLength(param, "utf8");
  }
  return {
    operation_id: nip46OperationId(grant, request.rpc_request.id),
    request_id: request.rpc_request.id,
    request_digest: nip46RequestDigest(grant, request),
    method: request.rpc_request.method,
    event_kind: eventKind,
    event_bytes: eventBytes,
    normalized_event: normalizedEvent,
  };
}

function verifySignerGrantSignature(grant: SigningGrant): boolean {
  try {
    return schnorr.verify(
      hexToBytes(grant.signature),
      signerGrantProofBytes(grant),
      hexToBytes(grant.authorizing_pubkey),
    );
  } catch {
    return false;
  }
}

function currentSignerGrant(candidates: SigningGrant[]): SigningGrant | Reject {
  if (candidates.length === 0 || candidates.some((grant) => !validateSignerGrant(grant))) {
    return reject("control-signing-grant-invalid");
  }
  if (candidates.some((grant) =>
    grant.expires_at <= grant.issued_at
    || grant.state === "revoked"
      && (grant.revoked_at as number) < grant.issued_at
  )) {
    return reject("control-signing-grant-invalid");
  }
  if (candidates.some((grant) => !verifySignerGrantSignature(grant))) {
    return reject("control-signing-grant-unauthenticated");
  }
  if (candidates.some(({ authorizing_pubkey, persona_active_key }) =>
    authorizing_pubkey !== persona_active_key
  )) {
    return reject("control-signing-grant-unauthenticated");
  }
  const byId = new Map(candidates.map((grant) => [grant.grant_id, grant]));
  if (byId.size !== candidates.length) {
    return reject("control-signing-grant-stale");
  }
  const referenced = new Set<string>();
  for (const candidate of candidates) {
    if (candidate.predecessor !== null) {
      const predecessor = byId.get(candidate.predecessor);
      if (
        predecessor === undefined
        || referenced.has(candidate.predecessor)
      ) {
        return reject("control-signing-grant-stale");
      }
      if (
        candidate.persona_active_key !== predecessor.persona_active_key
        || candidate.vault_id !== predecessor.vault_id
      ) {
        return reject("control-signing-grant-unauthenticated");
      }
      if (predecessor.state === "revoked") {
        return reject("control-signing-grant-stale");
      }
      if (candidate.issued_at < predecessor.issued_at) {
        return reject("control-signing-grant-stale");
      }
      referenced.add(candidate.predecessor);
    }
  }
  const heads = candidates.filter(({ grant_id }) => !referenced.has(grant_id));
  if (heads.length !== 1) return reject("control-signing-grant-stale");
  const visited = new Set<string>();
  let cursor: SigningGrant | undefined = heads[0];
  while (cursor !== undefined) {
    if (visited.has(cursor.grant_id)) return reject("control-signing-grant-stale");
    visited.add(cursor.grant_id);
    cursor = cursor.predecessor === null ? undefined : byId.get(cursor.predecessor);
  }
  return visited.size === candidates.length
    ? heads[0]
    : reject("control-signing-grant-stale");
}

type AuthorizedSigner = {
  verdict: "accept";
  vault_id: string;
  persona_active_key: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  custody: Custody;
};

function validateNip46Authority(input: Nip46AuthorizationInput): AuthorizedSigner | Reject {
  const selected = currentSignerGrant(input.grant_candidates);
  if ("verdict" in selected) return selected;
  const grant = selected;
  const requestBinding = validateCanonicalNip46Request(grant, input.request);
  if ("verdict" in requestBinding) return requestBinding;
  if (
    grant.key_class === "persona"
    && (
      !grant.persona_signing_authorized
      || grant.selected_signing_pubkey !== grant.persona_active_key
    )
  ) {
    return reject("control-persona-authority-required");
  }
  if (jcsCanonicalize(input.presented_grant) !== jcsCanonicalize(grant)) {
    return reject(input.presented_grant.grant_id === grant.grant_id
      ? "control-signer-binding-mismatch"
      : "control-signing-grant-stale");
  }
  if (
    !finiteSafeInteger(input.request.now)
    || (
      grant.key_class === "agent"
      && grant.selected_signing_pubkey === grant.persona_active_key
    )
  ) {
    return reject(
      grant.key_class === "agent"
        && grant.selected_signing_pubkey === grant.persona_active_key
      ? "control-signer-binding-mismatch"
      : "control-signing-grant-invalid",
    );
  }
  if (
    grant.state !== "active"
    || grant.revoked_at !== null
    || grant.expires_at <= grant.issued_at
    || input.request.now < grant.issued_at
    || input.request.now >= grant.expires_at
  ) {
    return reject("control-signing-grant-inactive");
  }

  const selectedVaults = input.vaults.filter(({ vault_id }) =>
    vault_id === input.request.vault_id
  );
  if (
    selectedVaults.length !== 1
    || input.request.vault_id !== grant.vault_id
    || input.request.persona_active_key !== grant.persona_active_key
    || selectedVaults[0].persona_active_key !== grant.persona_active_key
  ) {
    return reject("control-vault-isolation-failed");
  }
  if (
    input.request.grant_id !== grant.grant_id
    || input.request.nip46_client_pubkey !== grant.nip46_client_pubkey
    || input.request.signer_audience !== grant.signer_audience
    || input.request.selected_signing_pubkey !== grant.selected_signing_pubkey
    || input.request.key_class !== grant.key_class
  ) {
    return reject("control-signer-binding-mismatch");
  }
  if (
    grant.authorizing_pubkey !== grant.persona_active_key
  ) {
    return reject("control-persona-authority-required");
  }

  const signers = selectedVaults[0].signers.filter((candidate) =>
    candidate.public_key === grant.selected_signing_pubkey
    && candidate.key_class === grant.key_class
  );
  if (signers.length !== 1) {
    return reject("control-signer-unavailable");
  }

  const metadataWithinGrant = input.client_metadata.requested_methods.every((method) =>
    grant.allowed_methods.includes(method)
  ) && input.client_metadata.requested_event_kinds.every((kind) =>
    grant.allowed_event_kinds.includes(kind)
  ) && input.client_metadata.requested_signer_audiences.every((candidate) =>
    candidate === grant.signer_audience
  );
  if (!metadataWithinGrant) {
    return reject("control-client-metadata-widening");
  }

  if (
    !grant.allowed_methods.includes(requestBinding.method)
    || requestBinding.event_kind !== null
      && !grant.allowed_event_kinds.includes(requestBinding.event_kind)
    || requestBinding.event_bytes < 1
    || requestBinding.event_bytes > grant.limits.max_event_bytes
    || !finiteSafeInteger(input.request.value_msats)
    || input.request.value_msats > grant.limits.max_value_msats
  ) {
    return reject("control-signing-grant-invalid");
  }

  return {
    verdict: "accept",
    vault_id: grant.vault_id,
    persona_active_key: grant.persona_active_key,
    selected_signing_pubkey: grant.selected_signing_pubkey,
    key_class: grant.key_class,
    custody: signers[0].custody,
  };
}

export function authorizeNip46Signing(input: Nip46AuthorizationInput):
  | (AuthorizedSigner & {
      authorization_mode: "reserved";
      usage_transition: GrantUsageTransition;
    })
  | { verdict: "replay"; event_id: string }
  | Reject {
  const authorized = validateNip46Authority(input);
  if (authorized.verdict !== "accept") return authorized;
  const selected = currentSignerGrant(input.grant_candidates);
  if ("verdict" in selected) return selected;
  const usage = reserveGrantUsage(selected, input.request, input.usage_state);
  if ("verdict" in usage) return usage;
  return {
    ...authorized,
    authorization_mode: "reserved",
    usage_transition: usage,
  };
}

function reserveGrantUsage(
  grant: SigningGrant,
  request: Nip46SigningRequest,
  usage: GrantUsageState,
): GrantUsageTransition | { verdict: "replay"; event_id: string } | Reject {
  const requestBinding = validateCanonicalNip46Request(grant, request);
  if ("verdict" in requestBinding) return requestBinding;
  if (!grantUsageBindingMatches(grant, usage)) {
    return reject("control-usage-binding-mismatch");
  }
  if (!grantUsageStateIsValid(grant, request, usage)) {
    return reject("control-signing-grant-invalid");
  }
  const prior = usage.reservations.find(({ operation_id }) =>
    operation_id === requestBinding.operation_id
  );
  if (prior !== undefined) {
    if (
      prior.request_digest !== requestBinding.request_digest
      || jcsCanonicalize(prior.rpc_request) !== jcsCanonicalize(request.rpc_request)
      || prior.value_msats !== request.value_msats
    ) {
      return reject("control-operation-conflict");
    }
    return prior.state === "committed"
      ? { verdict: "replay", event_id: prior.result_event_id as string }
      : reject("control-operation-indeterminate");
  }
  const windowExpired = request.now - usage.window_started_at
    >= grant.limits.request_window_seconds;
  const windowStartedAt = windowExpired ? request.now : usage.window_started_at;
  const priorCount = windowExpired ? 0 : usage.consumed_request_count;
  if (priorCount >= grant.limits.request_count) {
    return reject("control-signing-rate-limited");
  }
  return {
    operation_id: requestBinding.operation_id,
    grant_id: grant.grant_id,
    grant_digest: usage.grant_digest,
    authority: usage.authority,
    request_id: requestBinding.request_id,
    request_digest: requestBinding.request_digest,
    rpc_request: request.rpc_request,
    value_msats: request.value_msats,
    expected_revision: usage.revision,
    next_revision: usage.revision + 1,
    prior_window_started_at: usage.window_started_at,
    window_started_at: windowStartedAt,
    prior_consumed_request_count: usage.consumed_request_count,
    consumed_request_count: priorCount + 1,
    reserved_at: request.now,
    reservation_state: "reserved",
  };
}

function grantUsageBindingMatches(
  grant: SigningGrant,
  usage: GrantUsageState,
): boolean {
  return usage !== null
    && typeof usage === "object"
    && usage.authority !== null
    && typeof usage.authority === "object"
    && Object.keys(usage.authority).sort().join("\0") === [
      "key_class", "nip46_client_pubkey", "persona_active_key",
      "selected_signing_pubkey", "signer_audience", "vault_id",
    ].join("\0")
    && usage.grant_id === grant.grant_id
    && usage.grant_digest === signerGrantStateDigest(grant)
    && usage.authority.vault_id === grant.vault_id
    && usage.authority.persona_active_key === grant.persona_active_key
    && usage.authority.nip46_client_pubkey === grant.nip46_client_pubkey
    && usage.authority.signer_audience === grant.signer_audience
    && usage.authority.selected_signing_pubkey === grant.selected_signing_pubkey
    && usage.authority.key_class === grant.key_class;
}

function grantUsageStateIsValid(
  grant: SigningGrant,
  request: Nip46SigningRequest,
  usage: GrantUsageState,
): boolean {
  const requestBinding = validateCanonicalNip46Request(grant, request);
  if ("verdict" in requestBinding) return false;
  const validReservation = (candidate: GrantUsageState["reservations"][number]) => {
    if (
      candidate === null
      || typeof candidate !== "object"
      || Object.keys(candidate).sort().join("\0") !== [
        "claimed_at", "completed_at", "executing_at", "execution_token",
        "failure_digest", "operation_id", "request_digest",
        "request_id", "reserved_at", "result_event_id", "rpc_request",
        "state", "value_msats", "window_started_at",
      ].join("\0")
    ) return false;
    const storedRequest: Nip46SigningRequest = {
      grant_id: grant.grant_id,
      ...grantAuthorityBinding(grant),
      rpc_request: candidate.rpc_request,
      value_msats: candidate.value_msats,
      now: candidate.reserved_at,
    };
    const storedBinding = validateCanonicalNip46Request(grant, storedRequest);
    return !("verdict" in storedBinding)
    && storedBinding.request_id === candidate.request_id
    && storedBinding.operation_id === candidate.operation_id
    && storedBinding.request_digest === candidate.request_digest
    && (candidate.execution_token === null
      || candidate.execution_token === signingExecutionToken(
        grant,
        candidate.request_digest,
      ))
    && /^[0-9a-f]{64}$/.test(candidate.operation_id)
    && typeof candidate.request_id === "string"
    && /^[\x20-\x7e]{1,128}$/.test(candidate.request_id)
    && /^[0-9a-f]{64}$/.test(candidate.request_digest)
    && ["reserved", "claimed", "executing", "committed", "indeterminate"].includes(candidate.state)
    && jcsCanonicalize(candidate.rpc_request).length > 0
    && finiteSafeInteger(candidate.value_msats)
    && finiteSafeInteger(candidate.window_started_at)
    && finiteSafeInteger(candidate.reserved_at)
    && candidate.reserved_at >= candidate.window_started_at
    && candidate.reserved_at <= request.now
    && (candidate.claimed_at === null || finiteSafeInteger(candidate.claimed_at))
    && (candidate.executing_at === null || finiteSafeInteger(candidate.executing_at))
    && (candidate.completed_at === null || finiteSafeInteger(candidate.completed_at))
    && (candidate.claimed_at === null || candidate.claimed_at >= candidate.reserved_at)
    && (candidate.executing_at === null
      || candidate.claimed_at !== null && candidate.executing_at >= candidate.claimed_at)
    && (candidate.completed_at === null
      || candidate.executing_at !== null && candidate.completed_at >= candidate.executing_at)
    && (candidate.completed_at === null || candidate.completed_at <= request.now)
    && (candidate.state === "reserved"
      ? candidate.claimed_at === null
        && candidate.completed_at === null
        && candidate.executing_at === null
        && candidate.execution_token === null
        && candidate.result_event_id === null
        && candidate.failure_digest === null
      : candidate.state === "claimed"
      ? candidate.claimed_at !== null
        && candidate.completed_at === null
        && candidate.executing_at === null
        && candidate.execution_token === null
        && candidate.result_event_id === null
        && candidate.failure_digest === null
      : candidate.state === "executing"
      ? candidate.claimed_at !== null
        && candidate.executing_at !== null
        && candidate.completed_at === null
        && /^[0-9a-f]{64}$/.test(candidate.execution_token ?? "")
        && candidate.result_event_id === null
        && candidate.failure_digest === null
      : candidate.state === "committed"
      ? candidate.executing_at !== null
        && candidate.completed_at !== null
        && /^[0-9a-f]{64}$/.test(candidate.execution_token ?? "")
        && /^[0-9a-f]{64}$/.test(candidate.result_event_id ?? "")
        && candidate.failure_digest === null
      : candidate.executing_at !== null
        && candidate.completed_at !== null
        && /^[0-9a-f]{64}$/.test(candidate.execution_token ?? "")
        && candidate.result_event_id === null
        && /^[0-9a-f]{64}$/.test(candidate.failure_digest ?? ""));
  };
  return !(
    Object.keys(usage).sort().join("\0") !== [
      "authority", "consumed_request_count", "grant_digest", "grant_id",
      "reservations", "revision", "window_started_at",
    ].join("\0")
    || usage.grant_id !== grant.grant_id
    || !finiteSafeInteger(usage.window_started_at)
    || usage.window_started_at > request.now
    || !finiteSafeInteger(usage.consumed_request_count)
    || !finiteSafeInteger(usage.revision)
    || usage.revision === Number.MAX_SAFE_INTEGER
    || !Array.isArray(usage.reservations)
    || usage.reservations.some((candidate) => !validReservation(candidate))
    || usage.consumed_request_count !== usage.reservations.filter((candidate) =>
      candidate.window_started_at === usage.window_started_at
    ).length
    || new Set(usage.reservations.map(({ operation_id }) => operation_id)).size
      !== usage.reservations.length
    || typeof requestBinding.request_id !== "string"
    || !/^[\x20-\x7e]{1,128}$/.test(requestBinding.request_id)
    || !/^[0-9a-f]{64}$/.test(requestBinding.request_digest)
  );
}

export type Nip46ConnectionState = {
  profile: "heterodyne.control.device-authorization-state.v1";
  spec_version: "heterodyne/0.6.0";
  transaction_id: string;
  grant_id: string;
  oidc_authorization_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  requested_methods: string[];
  requested_event_kinds: number[];
  requested_limits: SigningGrant["limits"];
  connection_secret_sha256: string;
  connection_secret_state: "pending" | "consumed";
  device_code_sha256: string;
  device_code_entropy_bits: number;
  user_code_sha256: string;
  user_code_entropy_bits: number;
  normalization: "uppercase-ascii-remove-hyphen";
  client_fingerprint: string;
  failed_guesses: number;
  max_failed_guesses: 5;
  interval_seconds: number;
  issued_at: number;
  expires_at: number;
  state: "pending" | "approved" | "denied" | "expired" | "exhausted" | "consumed";
  revision: number;
};

export type Nip46Activation = {
  transaction_id: string;
  grant_id: string;
  oidc_authorization_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  presented_connection_secret: string;
};

export function consumeNip46ConnectionSecret(
  input: {
    current_state: Nip46ConnectionState;
    grant_candidates: SigningGrant[];
    activation: Nip46Activation;
    now: number;
  },
): {
    verdict: "accept";
    state: Nip46ConnectionState;
    activation_transition: {
      transaction_id: string;
      grant_id: string;
      oidc_authorization_id: string;
      expected_revision: number;
      next_revision: number;
      prior_connection_secret_state: "pending";
      connection_secret_state: "consumed";
      prior_state: "approved";
      state: "consumed";
    };
  } | Reject {
  const state = input.current_state;
  if (state.connection_secret_state === "consumed" || state.state === "consumed") {
    return reject("control-connection-secret-reused");
  }
  const selected = currentSignerGrant(input.grant_candidates);
  if ("verdict" in selected) return selected;
  const grant = selected;
  const activation = input.activation;
  if (
    !validateDeviceAuthorization(state)
    || !finiteSafeInteger(input.now)
    || state.state !== "approved"
    || state.connection_secret_state !== "pending"
    || state.revision === Number.MAX_SAFE_INTEGER
    || input.now < state.issued_at
    || input.now >= state.expires_at
    || input.now < grant.issued_at
    || input.now >= grant.expires_at
    || grant.state !== "active"
    || grant.revoked_at !== null
  ) {
    return reject("control-connection-secret-invalid");
  }
  const bindingsMatch = state.grant_id === grant.grant_id
    && state.oidc_authorization_id === grant.oidc_authorization_id
    && state.persona_active_key === grant.persona_active_key
    && state.nip46_client_pubkey === grant.nip46_client_pubkey
    && state.signer_audience === grant.signer_audience
    && state.selected_signing_pubkey === grant.selected_signing_pubkey
    && state.key_class === grant.key_class
    && jcsCanonicalize(state.requested_methods) === jcsCanonicalize(grant.allowed_methods)
    && jcsCanonicalize(state.requested_event_kinds)
      === jcsCanonicalize(grant.allowed_event_kinds)
    && jcsCanonicalize(state.requested_limits) === jcsCanonicalize(grant.limits)
    && state.connection_secret_sha256 === grant.connection_secret_sha256
    && activation.transaction_id === state.transaction_id
    && activation.grant_id === grant.grant_id
    && activation.oidc_authorization_id === grant.oidc_authorization_id
    && activation.persona_active_key === grant.persona_active_key
    && activation.nip46_client_pubkey === grant.nip46_client_pubkey
    && activation.signer_audience === grant.signer_audience
    && activation.selected_signing_pubkey === grant.selected_signing_pubkey
    && activation.key_class === grant.key_class;
  if (!bindingsMatch) return reject("control-activation-binding-mismatch");
  if (!/^[0-9a-f]{64}$/.test(activation.presented_connection_secret)) {
    return reject("control-connection-secret-invalid");
  }
  const presentedDigest = createHash("sha256")
    .update(hexToBytes(activation.presented_connection_secret))
    .digest("hex");
  if (presentedDigest !== state.connection_secret_sha256) {
    return reject("control-connection-secret-invalid");
  }
  const nextRevision = state.revision + 1;
  return {
    verdict: "accept",
    state: {
      ...state,
      connection_secret_state: "consumed",
      state: "consumed",
      revision: nextRevision,
    },
    activation_transition: {
      transaction_id: state.transaction_id,
      grant_id: grant.grant_id,
      oidc_authorization_id: grant.oidc_authorization_id,
      expected_revision: state.revision,
      next_revision: nextRevision,
      prior_connection_secret_state: "pending",
      connection_secret_state: "consumed",
      prior_state: "approved",
      state: "consumed",
    },
  };
}

export type AutomatedPublication = {
  profile: "heterodyne.control.agent-publish-intent.v1";
  spec_version: "heterodyne/0.6.0";
  grant_id: string;
  vault_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  value_msats: number;
  agent_class: "ai" | "programmatic";
  agent_association: { kind: "key" | "role"; value: string } | null;
  tier: 1 | 2 | 3;
};

export type UnsignedEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export type SignerExecutionOutcome<T> =
  | { verdict: "accept"; disposition: "executed" | "cached"; event: T }
  | {
      verdict: "indeterminate";
      disposition: "executed" | "cached";
      failure_digest: string;
    }
  | { verdict: "reconciliation"; failure_digest: string }
  | { verdict: "conflict" };

export interface DurableSignerExecutionCapability<T> {
  executeOnce(
    executionToken: string,
    unsignedEvent: UnsignedEvent,
    requestDigest: string,
  ): SignerExecutionOutcome<T>;
}

type SignerExecutionTerminal<T> =
  | { state: "completed"; event: T }
  | { state: "indeterminate"; failure_digest: string };

type SignerExecutionStoreRecord<T> = {
  binding_digest: string;
  terminal: SignerExecutionTerminal<T> | null;
};

function cloneSerialized<T>(value: T): T {
  return JSON.parse(jcsCanonicalize(value)) as T;
}

export interface DurableSignerExecutionStore<T> {
  /** Atomically installs an irreversible binding before returning acquired. */
  acquire(
    executionToken: string,
    bindingDigest: string,
  ):
    | { verdict: "acquired" }
    | { verdict: "cached"; terminal: SignerExecutionTerminal<T> }
    | { verdict: "reconciliation" }
    | { verdict: "conflict" };
  /** A false/throw leaves the acquired binding non-reacquirable for reconciliation. */
  persistTerminal(
    executionToken: string,
    bindingDigest: string,
    terminal: SignerExecutionTerminal<T>,
  ): boolean;
}

/** Process-local conformance store; production hosts must provide durable cross-process storage. */
export class ReferenceSignerExecutionStore<T> implements DurableSignerExecutionStore<T> {
  readonly #records = new Map<string, SignerExecutionStoreRecord<T>>();

  acquire(
    executionToken: string,
    bindingDigest: string,
  ):
    | { verdict: "acquired" }
    | { verdict: "cached"; terminal: SignerExecutionTerminal<T> }
    | { verdict: "reconciliation" }
    | { verdict: "conflict" } {
    const existing = this.#records.get(executionToken);
    if (existing === undefined) {
      this.#records.set(executionToken, { binding_digest: bindingDigest, terminal: null });
      return { verdict: "acquired" };
    }
    if (existing.binding_digest !== bindingDigest) return { verdict: "conflict" };
    if (existing.terminal === null) return { verdict: "reconciliation" };
    return { verdict: "cached", terminal: cloneSerialized(existing.terminal) };
  }

  persistTerminal(
    executionToken: string,
    bindingDigest: string,
    terminal: SignerExecutionTerminal<T>,
  ): boolean {
    const existing = this.#records.get(executionToken);
    if (
      existing === undefined
      || existing.binding_digest !== bindingDigest
      || existing.terminal !== null
    ) return false;
    existing.terminal = cloneSerialized(terminal);
    return true;
  }
}

function signerExecutionBindingDigest(
  requestDigest: string,
  unsignedEvent: UnsignedEvent,
): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-signer-execution-binding-v1", {
      request_digest: requestDigest,
      unsigned_event: unsignedEvent,
    }))
    .digest("hex");
}

function signerExecutionReconciliationDigest(bindingDigest: string): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-signer-reconciliation-v1", {
      binding_digest: bindingDigest,
    }))
    .digest("hex");
}

function deepFreezeSnapshot<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreezeSnapshot(member);
    Object.freeze(value);
  }
  return value;
}

function immutableUnsignedEventSnapshot(unsignedEvent: UnsignedEvent): UnsignedEvent {
  return deepFreezeSnapshot(cloneSerialized(unsignedEvent));
}

export class ReferenceSignerExecutionFence<
  T extends UnsignedEvent & { id: string; sig: string },
> implements DurableSignerExecutionCapability<T> {
  readonly #store: DurableSignerExecutionStore<T>;
  readonly #keyOperation: (event: UnsignedEvent) => T;

  constructor(
    store: DurableSignerExecutionStore<T>,
    keyOperation: (event: UnsignedEvent) => T,
  ) {
    this.#store = store;
    this.#keyOperation = keyOperation;
  }

  executeOnce(
    executionToken: string,
    unsignedEvent: UnsignedEvent,
    requestDigest: string,
  ): SignerExecutionOutcome<T> {
    const immutableEvent = immutableUnsignedEventSnapshot(unsignedEvent);
    const bindingDigest = signerExecutionBindingDigest(requestDigest, immutableEvent);
    const acquired = this.#store.acquire(executionToken, bindingDigest);
    if (acquired.verdict === "conflict") return acquired;
    if (acquired.verdict === "reconciliation") {
      return {
        verdict: "reconciliation",
        failure_digest: signerExecutionReconciliationDigest(bindingDigest),
      };
    }
    if (acquired.verdict === "cached") {
      return acquired.terminal.state === "completed"
        ? {
            verdict: "accept",
            disposition: "cached",
            event: cloneSerialized(acquired.terminal.event),
          }
        : {
            verdict: "indeterminate",
            disposition: "cached",
            failure_digest: acquired.terminal.failure_digest,
          };
    }
    let event: T;
    try {
      event = this.#keyOperation(cloneSerialized(immutableEvent));
    } catch (error) {
      const failureDigest = createHash("sha256")
        .update(proofBytes("heterodyne-control-signer-execution-failure-v1", {
          binding_digest: bindingDigest,
          failure_class: error instanceof Error ? error.name : "unknown",
        }))
        .digest("hex");
      let persisted = false;
      try {
        persisted = this.#store.persistTerminal(executionToken, bindingDigest, {
          state: "indeterminate",
          failure_digest: failureDigest,
        });
      } catch {
        persisted = false;
      }
      return persisted
        ? {
            verdict: "indeterminate",
            disposition: "executed",
            failure_digest: failureDigest,
          }
        : {
            verdict: "reconciliation",
            failure_digest: signerExecutionReconciliationDigest(bindingDigest),
          };
    }
    let persisted = false;
    try {
      persisted = this.#store.persistTerminal(executionToken, bindingDigest, {
        state: "completed",
        event,
      });
    } catch {
      persisted = false;
    }
    if (!persisted) {
      return {
        verdict: "reconciliation",
        failure_digest: signerExecutionReconciliationDigest(bindingDigest),
      };
    }
    return {
      verdict: "accept",
      disposition: "executed",
      event: cloneSerialized(event),
    };
  }
}

function requirePersistedReservation(
  input: Nip46AuthorizationInput,
  requiredState: "reserved" | "claimed" | "executing",
):
  | { verdict: "accept"; reservation_revision: number; execution_token: string | null }
  | { verdict: "replay"; event_id: string }
  | Reject {
  const grant = input.presented_grant;
  const usage = input.usage_state;
  const request = input.request;
  const requestBinding = validateCanonicalNip46Request(grant, request);
  if ("verdict" in requestBinding) return requestBinding;
  if (!grantUsageBindingMatches(grant, usage)) {
    return reject("control-usage-binding-mismatch");
  }
  if (!grantUsageStateIsValid(grant, request, usage)) {
    return reject("control-signing-grant-invalid");
  }
  const reservation = usage.reservations.find(({ operation_id }) =>
    operation_id === requestBinding.operation_id
  );
  if (reservation === undefined || usage.consumed_request_count < 1) {
    return reject("control-operation-reservation-required");
  }
  if (reservation.request_digest !== requestBinding.request_digest) {
    return reject("control-operation-conflict");
  }
  if (reservation.state === "committed") {
    return { verdict: "replay", event_id: reservation.result_event_id as string };
  }
  if (reservation.state !== requiredState) {
    return reject("control-operation-indeterminate");
  }
  return {
    verdict: "accept",
    reservation_revision: usage.revision,
    execution_token: reservation.execution_token,
  };
}

type ValidatedAutomatedSigning = {
  grant: SigningGrant;
  request_binding: ValidatedNip46Request;
  unsigned_event: UnsignedEvent;
};

function validateAutomatedSigningIntent(input: {
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
}): ValidatedAutomatedSigning | Reject {
  const publication = input.publication;
  if (!validateAutomatedPublication(publication)) {
    return reject("control-agent-intent-invalid");
  }
  const authorized = validateNip46Authority(input.authorization);
  if (authorized.verdict !== "accept") return authorized;
  const grant = input.authorization.presented_grant;
  const requestBinding = validateCanonicalNip46Request(
    grant,
    input.authorization.request,
  );
  if ("verdict" in requestBinding) return requestBinding;
  const policy = grant.automation_policy;
  if (policy === undefined) return reject("control-attribution-required");
  if (
    grant.key_class === "persona"
    && !policy.oidc_scopes.includes("heterodyne:agent:sign:persona")
  ) {
    return reject("control-persona-authority-required");
  }
  if (
    publication.grant_id !== grant.grant_id
    || publication.vault_id !== grant.vault_id
    || publication.persona_active_key !== grant.persona_active_key
    || publication.nip46_client_pubkey !== grant.nip46_client_pubkey
    || publication.signer_audience !== grant.signer_audience
    || publication.selected_signing_pubkey !== grant.selected_signing_pubkey
    || publication.key_class !== grant.key_class
    || publication.kind !== requestBinding.event_kind
    || publication.value_msats !== input.authorization.request.value_msats
  ) {
    return reject("control-signer-binding-mismatch");
  }
  if (
    publication.agent_class !== policy.agent_class
    || publication.tier !== policy.tier
    || jcsCanonicalize(publication.agent_association)
      !== jcsCanonicalize(policy.agent_association)
  ) {
    return reject("control-attribution-binding-mismatch");
  }
  const attributed = injectAgentAttribution({
    kind: publication.kind,
    tags: publication.tags,
    agent_class: policy.agent_class,
    persona: authorized.persona_active_key,
    signer: authorized.selected_signing_pubkey,
    expected_signer: authorized.selected_signing_pubkey,
    signer_key_class: authorized.key_class,
    oidc_scopes: policy.oidc_scopes,
    agent_association: policy.agent_association ?? undefined,
    expected_agent_association: policy.agent_association ?? undefined,
    tier: policy.tier,
  });
  if (
    attributed.verdict !== "accept"
    || !matchesAgentAttributionProfile(attributed.tags)
  ) {
    return reject("control-attribution-required");
  }
  const unsigned: UnsignedEvent = {
    pubkey: attributed.author,
    created_at: publication.created_at,
    kind: publication.kind,
    tags: attributed.tags,
    content: publication.content,
  };
  if (
    input.authorization.request.rpc_request.method !== "sign_event"
    || input.authorization.request.rpc_request.params.length !== 1
    || requestBinding.normalized_event === null
    || jcsCanonicalize(requestBinding.normalized_event) !== jcsCanonicalize(unsigned)
  ) {
    return reject("control-operation-conflict");
  }
  if (
    Buffer.byteLength(jcsCanonicalize(unsigned), "utf8")
      > input.authorization.presented_grant.limits.max_event_bytes
  ) {
    return reject("control-signing-grant-invalid");
  }
  return {
    grant,
    request_binding: requestBinding,
    unsigned_event: unsigned,
  };
}

export function prepareAutomatedSigning(input: {
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
}):
  | {
      verdict: "accept";
      authorization_mode: "claim-required";
      unsigned_event: UnsignedEvent;
      claim_transition: GrantClaimTransition;
    }
  | { verdict: "replay"; event_id: string }
  | Reject {
  const validated = validateAutomatedSigningIntent(input);
  if ("verdict" in validated) return validated;
  const persisted = requirePersistedReservation(input.authorization, "reserved");
  if (persisted.verdict !== "accept") return persisted;
  return {
    verdict: "accept",
    authorization_mode: "claim-required",
    unsigned_event: validated.unsigned_event,
    claim_transition: {
      operation_id: validated.request_binding.operation_id,
      grant_id: validated.grant.grant_id,
      grant_digest: signerGrantStateDigest(validated.grant),
      authority: grantAuthorityBinding(validated.grant),
      request_id: validated.request_binding.request_id,
      request_digest: validated.request_binding.request_digest,
      expected_revision: persisted.reservation_revision,
      next_revision: persisted.reservation_revision + 1,
      prior_reservation_state: "reserved",
      reservation_state: "claimed",
      claimed_at: input.authorization.request.now,
    },
  };
}

export function signingExecutionToken(
  grant: SigningGrant,
  requestDigest: string,
): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-signing-execution-token-v1", {
      grant_digest: signerGrantStateDigest(grant),
      authority: grantAuthorityBinding(grant),
      request_digest: requestDigest,
    }))
    .digest("hex");
}

export function prepareAutomatedExecution(input: {
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
}):
  | {
      verdict: "accept";
      authorization_mode: "execution-fence-required";
      unsigned_event: UnsignedEvent;
      execution_transition: GrantExecutionTransition;
    }
  | { verdict: "replay"; event_id: string }
  | Reject {
  const validated = validateAutomatedSigningIntent(input);
  if ("verdict" in validated) return validated;
  const persisted = requirePersistedReservation(input.authorization, "claimed");
  if (persisted.verdict !== "accept") return persisted;
  const executionToken = signingExecutionToken(
    validated.grant,
    validated.request_binding.request_digest,
  );
  return {
    verdict: "accept",
    authorization_mode: "execution-fence-required",
    unsigned_event: validated.unsigned_event,
    execution_transition: {
      operation_id: validated.request_binding.operation_id,
      grant_id: validated.grant.grant_id,
      grant_digest: signerGrantStateDigest(validated.grant),
      authority: grantAuthorityBinding(validated.grant),
      request_id: validated.request_binding.request_id,
      request_digest: validated.request_binding.request_digest,
      execution_token: executionToken,
      expected_revision: persisted.reservation_revision,
      next_revision: persisted.reservation_revision + 1,
      prior_reservation_state: "claimed",
      reservation_state: "executing",
      executing_at: input.authorization.request.now,
    },
  };
}

export type PersistedAutomatedSigningInput<
  T extends UnsignedEvent & { id: string; sig: string },
> = Readonly<{
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
  signer_execution: DurableSignerExecutionCapability<T>;
}>;

export function executePersistedAutomatedSigning<
  T extends UnsignedEvent & { id: string; sig: string },
>(input: PersistedAutomatedSigningInput<T>):
  | {
      verdict: "accept";
      event: T;
      signer_execution_disposition: "executed" | "cached";
      completion_transition: {
        operation_id: string;
        grant_id: string;
        grant_digest: string;
        authority: GrantAuthorityBinding;
        request_id: string;
        request_digest: string;
        expected_revision: number;
        next_revision: number;
        prior_reservation_state: "executing";
        reservation_state: "committed";
        completed_at: number;
        event_id: string;
      };
    }
  | {
      verdict: "indeterminate";
      reason_code: "control-signer-effect-indeterminate";
      signer_execution_disposition: "executed" | "cached" | "reconciliation";
      completion_transition: {
        operation_id: string;
        grant_id: string;
        grant_digest: string;
        authority: GrantAuthorityBinding;
        request_id: string;
        request_digest: string;
        expected_revision: number;
        next_revision: number;
        prior_reservation_state: "executing";
        reservation_state: "indeterminate";
        completed_at: number;
        failure_digest: string;
      };
    }
  | { verdict: "replay"; event_id: string }
  | Reject {
  if (!hasExactKeys(input, ["authorization", "publication", "signer_execution"])) {
    return reject("control-operation-execution-fence-required");
  }
  const validated = validateAutomatedSigningIntent(input);
  if ("verdict" in validated) return validated;
  const persisted = requirePersistedReservation(input.authorization, "executing");
  if (persisted.verdict !== "accept") {
    return persisted.verdict === "reject"
      && persisted.reason_code === "control-operation-indeterminate"
      ? reject("control-operation-execution-fence-required")
      : persisted;
  }
  if (persisted.execution_token === null) {
    return reject("control-operation-execution-fence-required");
  }
  const authoritativeUnsignedEvent = immutableUnsignedEventSnapshot(
    validated.unsigned_event,
  );
  let event: T | undefined;
  let executionDisposition: "executed" | "cached" | "reconciliation" = "reconciliation";
  let boundaryFailureDigest: string | undefined;
  let failureClass = "execution-capability-threw";
  try {
    const outcome = input.signer_execution.executeOnce(
      persisted.execution_token,
      authoritativeUnsignedEvent,
      validated.request_binding.request_digest,
    );
    if (outcome.verdict === "conflict") {
      return reject("control-operation-conflict");
    }
    if (outcome.verdict === "reconciliation") {
      boundaryFailureDigest = outcome.failure_digest;
    } else {
      executionDisposition = outcome.disposition;
    }
    if (outcome.verdict === "indeterminate") {
      boundaryFailureDigest = outcome.failure_digest;
    } else if (outcome.verdict === "accept") {
      event = outcome.event;
    }
    failureClass = "invalid-signed-event";
  } catch {
    event = undefined;
  }
  const common = {
    operation_id: validated.request_binding.operation_id,
    grant_id: validated.grant.grant_id,
    grant_digest: signerGrantStateDigest(validated.grant),
    authority: grantAuthorityBinding(validated.grant),
    request_id: validated.request_binding.request_id,
    request_digest: validated.request_binding.request_digest,
    expected_revision: persisted.reservation_revision,
    next_revision: persisted.reservation_revision + 1,
    completed_at: input.authorization.request.now,
  };
  let eventValid = false;
  let verifiedEvent: VerifiedNostrEvent | null = null;
  try {
    verifiedEvent = event === undefined ? null : snapshotAndVerifyNostrEvent(event);
    eventValid = verifiedEvent !== null
      && verifiedEvent.pubkey === authoritativeUnsignedEvent.pubkey
      && verifiedEvent.created_at === authoritativeUnsignedEvent.created_at
      && verifiedEvent.kind === authoritativeUnsignedEvent.kind
      && verifiedEvent.content === authoritativeUnsignedEvent.content
      && jcsCanonicalize(verifiedEvent.tags) === jcsCanonicalize(authoritativeUnsignedEvent.tags);
  } catch {
    eventValid = false;
  }
  if (!eventValid || executionDisposition === "reconciliation") {
    return {
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
      signer_execution_disposition: executionDisposition,
      completion_transition: {
        ...common,
        prior_reservation_state: "executing",
        reservation_state: "indeterminate",
        failure_digest: boundaryFailureDigest ?? createHash("sha256")
          .update(proofBytes("heterodyne-control-signing-failure-v1", {
            request_digest: validated.request_binding.request_digest,
            failure_class: failureClass,
          }))
          .digest("hex"),
      },
    };
  }
  const validEvent = verifiedEvent as unknown as T;
  return {
    verdict: "accept",
    event: validEvent,
    signer_execution_disposition: executionDisposition,
    completion_transition: {
      ...common,
      prior_reservation_state: "executing",
      reservation_state: "committed",
      event_id: validEvent.id,
    },
  };
}

export type CompromiseResetGrant = {
  profile: "heterodyne.control.compromise-reset-grant.v1";
  spec_version: "heterodyne/0.6.0";
  recovery_id: string;
  persona_active_key: string;
  successor_active_key: string;
  authorization_class: "active-account" | "assurance-recovery";
  authorizing_pubkey: string;
  assurance_head: string | null;
  inventory_id: string;
  inventory_revision: number;
  inventory_digest: string;
  compromise_at: number;
  required_reset: {
    nip46_oidc_grant_ids: string[];
    client_ids: string[];
    repository_ids: string[];
    delegate_ids: string[];
    node_ids: string[];
    agent_ids: string[];
    trusted_seed_nids: string[];
    marmot_leaf_ids: string[];
    reachable_groups: Array<{ group_id: string; epoch: number }>;
    unreachable_group_ids: string[];
    subordinate_authority_ids: string[];
  };
  issued_at: number;
  expires_at: number;
  state: "active" | "revoked";
  revoked_at: number | null;
  signature: string;
};

export type CompromiseResetCompletion = {
  profile: "heterodyne.control.compromise-reset-completion.v1";
  spec_version: "heterodyne/0.6.0";
  recovery_id: string;
  persona_active_key: string;
  successor_active_key: string;
  inventory_id: string;
  inventory_revision: number;
  inventory_digest: string;
  evidence_revision: number;
  revoked_nip46_oidc_grant_ids: string[];
  invalidated_client_ids: string[];
  invalidated_repository_ids: string[];
  invalidated_delegate_ids: string[];
  invalidated_node_ids: string[];
  invalidated_agent_ids: string[];
  invalidated_trusted_seed_nids: string[];
  removed_marmot_leaf_ids: string[];
  advanced_group_ids: string[];
  stalled_group_ids: string[];
  fresh_keypackages: Array<{
    keypackage_id: string;
    account_key: string;
    group_id: string;
    event_id: string;
    event: {
      id: string;
      pubkey: string;
      created_at: number;
      kind: 30443;
      tags: string[][];
      content: string;
      sig: string;
    };
    content_sha256: string;
    mls_verifier_pubkey: string;
    verification_signature: string;
  }>;
  subordinate_reauthorizations: Array<{
    prior_authority_id: string;
    authorization_id: string;
    authority_class: "client" | "repository" | "delegate" | "node" | "agent" | "trusted-seed";
    successor_active_key: string;
    issued_at: number;
    expires_at: number;
    permissions_digest: string;
    contract_digest: string;
  }>;
  transition_evidence: {
    nip46_oidc_grants: HexTransitionEvidence[];
    clients: HexTransitionEvidence[];
    repositories: HexTransitionEvidence[];
    delegates: HexTransitionEvidence[];
    nodes: HexTransitionEvidence[];
    agents: HexTransitionEvidence[];
    trusted_seeds: Array<{ subject_nid: string; evidence_id: string }>;
    marmot_leaves: HexTransitionEvidence[];
    groups: Array<{
      group_id: string;
      prior_epoch: number;
      next_epoch: number;
      evidence_id: string;
    }>;
    stalled_groups: HexTransitionEvidence[];
  };
  evidence_bundle_digest: string;
  completed_at: number;
  signer: string;
  signature: string;
};

type HexTransitionEvidence = { subject_id: string; evidence_id: string };

export type CompromiseResetInventory = {
  inventory_id: string;
  revision: number;
  observed_at: number;
  persona_active_key: string;
  nip46_oidc_grant_ids: string[];
  client_ids: string[];
  repository_ids: string[];
  delegate_ids: string[];
  node_ids: string[];
  agent_ids: string[];
  trusted_seed_nids: string[];
  marmot_leaf_ids: string[];
  reachable_groups: Array<{
    group_id: string;
    epoch: number;
    state_digest: string;
    mls_verifier_pubkey: string;
    leaves: Array<{
      leaf_id: string;
      leaf_index: number;
      account_key: string;
      keypackage_id: string;
    }>;
  }>;
  unreachable_group_ids: string[];
  subordinate_authority_ids: string[];
  existing_transition_ids: string[];
  existing_keypackage_event_ids: string[];
  authorization_records: Array<{
    authority_class: "nip46-oidc-grant" | "client" | "repository" | "delegate" | "node" | "agent" | "trusted-seed";
    subject_id: string;
    authorization_id: string;
    authorization_digest: string;
  }>;
};

export type ResetStateEvidence = {
  evidence_id: string;
  authority_class: "nip46-oidc-grant" | "client" | "repository" | "delegate" | "node" | "agent" | "trusted-seed" | "stalled-group";
  subject_id: string;
  prior_authorization_digest: string;
  action: "revoked" | "invalidated" | "stalled";
  effective_at: number;
  recovery_id: string;
  signer: string;
  signature: string;
};

export type MlsCommitEvidence = {
  evidence_id: string;
  recovery_id: string;
  group_id: string;
  prior_epoch: number;
  next_epoch: number;
  prior_state_digest: string;
  next_state_digest: string;
  commit_bytes_base64: string;
  commit_sha256: string;
  removed_leaf_ids: string[];
  continuing_leaf_ids: string[];
  successor_leaves: Array<{
    leaf_id: string;
    leaf_index: number;
    account_key: string;
    keypackage_id: string;
  }>;
  verified_at: number;
  mls_verifier_pubkey: string;
  verification_signature: string;
};

export type CompromiseResetEvidence = {
  inventory_id: string;
  inventory_revision: number;
  evidence_revision: number;
  observed_at: number;
  transition_evidence: CompromiseResetCompletion["transition_evidence"];
  fresh_keypackages: CompromiseResetCompletion["fresh_keypackages"];
  subordinate_reauthorizations: CompromiseResetCompletion["subordinate_reauthorizations"];
  evidence_bundle: {
    state_transitions: ResetStateEvidence[];
    group_commits: MlsCommitEvidence[];
  };
};

export type PinnedAssuranceAuthority = {
  head_id: string;
  authority_pubkey: string;
};

export function compromiseResetInventoryDigest(
  inventory: CompromiseResetInventory,
): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-compromise-reset-inventory-v1", inventory))
    .digest("hex");
}

export function compromiseResetGrantProofBytes(
  value: Omit<CompromiseResetGrant, "signature"> | CompromiseResetGrant,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as CompromiseResetGrant;
  return proofBytes("heterodyne-control-compromise-reset-grant-v1", unsigned);
}

export function compromiseResetCompletionProofBytes(
  value: Omit<CompromiseResetCompletion, "signature"> | CompromiseResetCompletion,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as CompromiseResetCompletion;
  return proofBytes("heterodyne-control-compromise-reset-completion-v1", unsigned);
}

function subordinateContractDigest(
  contract: CompromiseResetCompletion["subordinate_reauthorizations"][number],
): string {
  const { contract_digest: _digest, ...unsigned } = contract;
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-subordinate-authorization-v1", unsigned))
    .digest("hex");
}

export function resetStateEvidenceProofBytes(
  value: Omit<ResetStateEvidence, "signature"> | ResetStateEvidence,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as ResetStateEvidence;
  return proofBytes("heterodyne-control-reset-state-evidence-v1", unsigned);
}

export function mlsCommitEvidenceProofBytes(
  value: Omit<MlsCommitEvidence, "verification_signature"> | MlsCommitEvidence,
): Uint8Array {
  const { verification_signature: _signature, ...unsigned } = value as MlsCommitEvidence;
  return proofBytes("heterodyne-control-mls-commit-evidence-v1", unsigned);
}

export function keyPackageVerificationProofBytes(
  value: CompromiseResetCompletion["fresh_keypackages"][number],
): Uint8Array {
  const { verification_signature: _signature, ...unsigned } = value;
  return proofBytes("heterodyne-control-mls-keypackage-evidence-v1", unsigned);
}

export function compromiseResetEvidenceBundleDigest(
  bundle: CompromiseResetEvidence["evidence_bundle"],
): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-compromise-reset-evidence-bundle-v1", bundle))
    .digest("hex");
}

export type CompromiseResetValidationInput = Readonly<{
  grant: CompromiseResetGrant;
  completion: CompromiseResetCompletion;
  authoritative_inventory: CompromiseResetInventory;
  authoritative_evidence: CompromiseResetEvidence;
  pinned_assurance_authority: PinnedAssuranceAuthority | null;
  now: number;
}>;

export function validateCompromiseReset(input: CompromiseResetValidationInput): {
  verdict: "accept";
  reset_transition: {
    inventory_id: string;
    recovery_id: string;
    expected_inventory_revision: number;
    next_inventory_revision: number;
    evidence_revision: number;
    completion_digest: string;
  };
} | Reject {
  if (!validateRecoveryGrantSchema(input.grant)) {
    return reject("control-compromise-reset-incomplete");
  }
  if (!validateRecoveryCompletionSchema(input.completion)) {
    return reject("control-compromise-reset-incomplete");
  }
  const grant = input.grant;
  const completion = input.completion;
  const inventory = input.authoritative_inventory;
  const evidence = input.authoritative_evidence;
  if (
    inventory === null
    || typeof inventory !== "object"
    || evidence === null
    || typeof evidence !== "object"
    || !Array.isArray(inventory.authorization_records)
    || !Array.isArray(inventory.reachable_groups)
    || !Array.isArray(inventory.nip46_oidc_grant_ids)
    || !Array.isArray(inventory.client_ids)
    || !Array.isArray(inventory.repository_ids)
    || !Array.isArray(inventory.delegate_ids)
    || !Array.isArray(inventory.node_ids)
    || !Array.isArray(inventory.agent_ids)
    || !Array.isArray(inventory.trusted_seed_nids)
    || !Array.isArray(inventory.marmot_leaf_ids)
    || !Array.isArray(inventory.unreachable_group_ids)
    || !Array.isArray(inventory.subordinate_authority_ids)
    || !Array.isArray(inventory.existing_transition_ids)
    || !Array.isArray(inventory.existing_keypackage_event_ids)
    || evidence.evidence_bundle === null
    || typeof evidence.evidence_bundle !== "object"
    || !Array.isArray(evidence.evidence_bundle.group_commits)
    || !Array.isArray(evidence.evidence_bundle.state_transitions)
    || !hasExactKeys(inventory, [
      "agent_ids", "authorization_records", "client_ids", "delegate_ids",
      "existing_keypackage_event_ids",
      "existing_transition_ids", "inventory_id", "marmot_leaf_ids", "node_ids",
      "observed_at", "persona_active_key", "reachable_groups", "repository_ids",
      "revision", "subordinate_authority_ids", "trusted_seed_nids",
      "unreachable_group_ids", "nip46_oidc_grant_ids",
    ])
    || inventory.authorization_records.some((record) =>
      record === null || typeof record !== "object" || !hasExactKeys(record, [
        "authority_class", "subject_id", "authorization_id", "authorization_digest",
      ])
    )
    || inventory.reachable_groups.some((group) =>
      group === null
      || typeof group !== "object"
      || !Array.isArray(group.leaves)
      || !hasExactKeys(group, [
        "epoch", "group_id", "leaves", "mls_verifier_pubkey", "state_digest",
      ])
      || group.leaves.some((leaf) =>
        leaf === null || typeof leaf !== "object" || !hasExactKeys(leaf, [
        "account_key", "keypackage_id", "leaf_id", "leaf_index",
        ])
      )
    )
    || !authorizationInventoryIsExact(inventory)
    || !exactSet(
      inventory.marmot_leaf_ids,
      inventory.reachable_groups.flatMap(({ leaves }) =>
        leaves
          .filter(({ account_key }) => account_key === inventory.persona_active_key)
          .map(({ leaf_id }) => leaf_id)
      ),
    )
    || !hasExactKeys(evidence, [
      "evidence_bundle", "evidence_revision", "fresh_keypackages", "inventory_id",
      "inventory_revision", "observed_at", "subordinate_reauthorizations",
      "transition_evidence",
    ])
    || !hasExactKeys(evidence.evidence_bundle, ["group_commits", "state_transitions"])
  ) {
    return reject("control-compromise-reset-evidence-invalid");
  }
  const grantSignatureValid = safeSchnorrVerify(
    grant.signature,
    compromiseResetGrantProofBytes(grant),
    grant.authorizing_pubkey,
  );
  const completionSignatureValid = safeSchnorrVerify(
    completion.signature,
    compromiseResetCompletionProofBytes(completion),
    completion.signer,
  );
  if (!grantSignatureValid || !completionSignatureValid) {
    return reject("control-compromise-reset-unauthenticated");
  }
  const authorityValid = grant.authorization_class === "active-account"
    ? grant.authorizing_pubkey === grant.persona_active_key
      && grant.assurance_head === null
    : input.pinned_assurance_authority !== null
      && grant.authorizing_pubkey === input.pinned_assurance_authority.authority_pubkey
      && grant.assurance_head === input.pinned_assurance_authority.head_id;
  if (!authorityValid) return reject("control-compromise-reset-unauthenticated");
  const inventoryDigest = compromiseResetInventoryDigest(inventory);
  const inventoryRequired = {
    nip46_oidc_grant_ids: inventory.nip46_oidc_grant_ids,
    client_ids: inventory.client_ids,
    repository_ids: inventory.repository_ids,
    delegate_ids: inventory.delegate_ids,
    node_ids: inventory.node_ids,
    agent_ids: inventory.agent_ids,
    trusted_seed_nids: inventory.trusted_seed_nids,
    marmot_leaf_ids: inventory.marmot_leaf_ids,
    reachable_groups: inventory.reachable_groups.map(({ group_id, epoch }) => ({
      group_id,
      epoch,
    })),
    unreachable_group_ids: inventory.unreachable_group_ids,
    subordinate_authority_ids: inventory.subordinate_authority_ids,
  };
  if (
    inventory.persona_active_key !== grant.persona_active_key
    || inventory.inventory_id !== grant.inventory_id
    || inventory.revision !== grant.inventory_revision
    || inventoryDigest !== grant.inventory_digest
    || jcsCanonicalize(inventoryRequired) !== jcsCanonicalize(grant.required_reset)
  ) {
    return reject("control-compromise-reset-inventory-mismatch");
  }
  if (
    !finiteSafeInteger(input.now)
    || grant.persona_active_key === grant.successor_active_key
    || grant.state !== "active"
    || grant.revoked_at !== null
    || grant.compromise_at > grant.issued_at
    || grant.expires_at <= grant.issued_at
    || input.now < grant.issued_at
    || input.now >= grant.expires_at
    || completion.completed_at < grant.issued_at
    || completion.completed_at > input.now
    || completion.recovery_id !== grant.recovery_id
    || completion.persona_active_key !== grant.persona_active_key
    || completion.successor_active_key !== grant.successor_active_key
    || completion.inventory_id !== grant.inventory_id
    || completion.inventory_revision !== grant.inventory_revision
    || completion.inventory_digest !== grant.inventory_digest
    || completion.signer !== grant.successor_active_key
    || !finiteSafeInteger(inventory.revision)
    || !finiteSafeInteger(inventory.observed_at)
    || inventory.observed_at < grant.compromise_at
    || inventory.observed_at > grant.issued_at
  ) {
    return reject("control-compromise-reset-incomplete");
  }
  const required = grant.required_reset;
  const complete = exactSet(
    completion.revoked_nip46_oidc_grant_ids,
    required.nip46_oidc_grant_ids,
  ) && exactSet(completion.invalidated_client_ids, required.client_ids)
    && exactSet(completion.invalidated_repository_ids, required.repository_ids)
    && exactSet(completion.invalidated_delegate_ids, required.delegate_ids)
    && exactSet(completion.invalidated_node_ids, required.node_ids)
    && exactSet(completion.invalidated_agent_ids, required.agent_ids)
    && exactSet(completion.invalidated_trusted_seed_nids, required.trusted_seed_nids)
    && exactSet(completion.removed_marmot_leaf_ids, required.marmot_leaf_ids)
    && exactSet(
      completion.advanced_group_ids,
      required.reachable_groups.map(({ group_id }) => group_id),
    )
    && exactSet(completion.stalled_group_ids, required.unreachable_group_ids)
    && completion.stalled_group_ids.every((groupId) =>
      !completion.advanced_group_ids.includes(groupId)
    )
    && completion.fresh_keypackages.length > 0;
  if (!complete) {
    return reject("control-compromise-reset-incomplete");
  }
  const reauthorized = completion.subordinate_reauthorizations.map(
    ({ prior_authority_id }) => prior_authority_id,
  );
  if (!exactSet(reauthorized, required.subordinate_authority_ids)) {
    return reject("control-subordinate-reauthorization-required");
  }
  const expectedEvidence = {
    inventory_id: completion.inventory_id,
    inventory_revision: completion.inventory_revision,
    evidence_revision: completion.evidence_revision,
    transition_evidence: completion.transition_evidence,
    fresh_keypackages: completion.fresh_keypackages,
    subordinate_reauthorizations: completion.subordinate_reauthorizations,
    evidence_bundle_digest: completion.evidence_bundle_digest,
  };
  const presentedEvidence = {
    inventory_id: evidence.inventory_id,
    inventory_revision: evidence.inventory_revision,
    evidence_revision: evidence.evidence_revision,
    transition_evidence: evidence.transition_evidence,
    fresh_keypackages: evidence.fresh_keypackages,
    subordinate_reauthorizations: evidence.subordinate_reauthorizations,
    evidence_bundle_digest: compromiseResetEvidenceBundleDigest(evidence.evidence_bundle),
  };
  if (
    !finiteSafeInteger(evidence.evidence_revision)
    || evidence.evidence_revision !== inventory.revision + 1
    || !finiteSafeInteger(evidence.observed_at)
    || evidence.observed_at < completion.completed_at
    || evidence.observed_at > input.now
    || jcsCanonicalize(presentedEvidence) !== jcsCanonicalize(expectedEvidence)
    || !transitionSubjectsMatch(completion, inventory)
    || !groupEvidenceAdvancesExactly(completion, inventory)
    || !authenticatedResetStateEvidenceIsExact(completion, inventory, evidence, grant)
    || !authenticatedMlsEvidenceIsExact(completion, inventory, evidence, grant)
    || !freshKeyPackagesAreAuthentic(completion, inventory, grant)
    || !subordinateContractsAreExact(completion, inventory, grant)
    || completion.fresh_keypackages.some(({ account_key }) =>
      account_key !== grant.successor_active_key
    )
    || !replacementIdsAreFresh(completion, inventory, evidence, grant.recovery_id)
  ) {
    return reject("control-compromise-reset-evidence-invalid");
  }
  const completionDigest = createHash("sha256")
    .update(proofBytes("heterodyne-control-compromise-reset-completion-state-v1", completion))
    .digest("hex");
  return {
    verdict: "accept",
    reset_transition: {
      inventory_id: inventory.inventory_id,
      recovery_id: grant.recovery_id,
      expected_inventory_revision: inventory.revision,
      next_inventory_revision: evidence.evidence_revision,
      evidence_revision: evidence.evidence_revision,
      completion_digest: completionDigest,
    },
  };
}

function authorizationInventoryIsExact(inventory: CompromiseResetInventory): boolean {
  const expected = [
    ...inventory.nip46_oidc_grant_ids.map((subject_id) => ({ authority_class: "nip46-oidc-grant", subject_id })),
    ...inventory.client_ids.map((subject_id) => ({ authority_class: "client", subject_id })),
    ...inventory.repository_ids.map((subject_id) => ({ authority_class: "repository", subject_id })),
    ...inventory.delegate_ids.map((subject_id) => ({ authority_class: "delegate", subject_id })),
    ...inventory.node_ids.map((subject_id) => ({ authority_class: "node", subject_id })),
    ...inventory.agent_ids.map((subject_id) => ({ authority_class: "agent", subject_id })),
    ...inventory.trusted_seed_nids.map((subject_id) => ({ authority_class: "trusted-seed", subject_id })),
  ];
  return inventory.authorization_records.length === expected.length
    && expected.every((candidate) => inventory.authorization_records.filter((record) =>
      record.authority_class === candidate.authority_class
      && record.subject_id === candidate.subject_id
    ).length === 1)
    && inventory.authorization_records.every((record) =>
      /^[0-9a-f]{64}$/.test(record.authorization_id)
      && /^[0-9a-f]{64}$/.test(record.authorization_digest)
    )
    && new Set(inventory.authorization_records.map(({ authorization_id }) => authorization_id)).size
      === inventory.authorization_records.length
    && inventory.subordinate_authority_ids.every((authorizationId) =>
      inventory.authorization_records.some(({ authorization_id, authority_class }) =>
        authorization_id === authorizationId
        && authority_class !== "nip46-oidc-grant"
      )
    );
}

function safeSchnorrVerify(signature: string, message: Uint8Array, pubkey: string): boolean {
  try {
    return schnorr.verify(hexToBytes(signature), message, hexToBytes(pubkey));
  } catch {
    return false;
  }
}

function transitionSubjectsMatch(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
): boolean {
  const evidence = completion.transition_evidence;
  return exactSet(evidence.nip46_oidc_grants.map(({ subject_id }) => subject_id), inventory.nip46_oidc_grant_ids)
    && exactSet(evidence.clients.map(({ subject_id }) => subject_id), inventory.client_ids)
    && exactSet(evidence.repositories.map(({ subject_id }) => subject_id), inventory.repository_ids)
    && exactSet(evidence.delegates.map(({ subject_id }) => subject_id), inventory.delegate_ids)
    && exactSet(evidence.nodes.map(({ subject_id }) => subject_id), inventory.node_ids)
    && exactSet(evidence.agents.map(({ subject_id }) => subject_id), inventory.agent_ids)
    && exactSet(evidence.trusted_seeds.map(({ subject_nid }) => subject_nid), inventory.trusted_seed_nids)
    && exactSet(evidence.marmot_leaves.map(({ subject_id }) => subject_id), inventory.marmot_leaf_ids)
    && evidence.marmot_leaves.every((leafEvidence) => {
      const group = inventory.reachable_groups.find(({ leaves }) =>
        leaves.some(({ leaf_id }) => leaf_id === leafEvidence.subject_id)
      );
      return group !== undefined
        && evidence.groups.some(({ group_id, evidence_id }) =>
          group_id === group.group_id && evidence_id === leafEvidence.evidence_id
        );
    })
    && exactSet(evidence.groups.map(({ group_id }) => group_id), inventory.reachable_groups.map(({ group_id }) => group_id))
    && exactSet(evidence.stalled_groups.map(({ subject_id }) => subject_id), inventory.unreachable_group_ids);
}

function authenticatedResetStateEvidenceIsExact(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
  authoritative: CompromiseResetEvidence,
  grant: CompromiseResetGrant,
): boolean {
  const summaries = completion.transition_evidence;
  const expected = [
    ...summaries.nip46_oidc_grants.map((record) => ({ ...record, authority_class: "nip46-oidc-grant" as const, action: "revoked" as const })),
    ...summaries.clients.map((record) => ({ ...record, authority_class: "client" as const, action: "invalidated" as const })),
    ...summaries.repositories.map((record) => ({ ...record, authority_class: "repository" as const, action: "invalidated" as const })),
    ...summaries.delegates.map((record) => ({ ...record, authority_class: "delegate" as const, action: "invalidated" as const })),
    ...summaries.nodes.map((record) => ({ ...record, authority_class: "node" as const, action: "invalidated" as const })),
    ...summaries.agents.map((record) => ({ ...record, authority_class: "agent" as const, action: "invalidated" as const })),
    ...summaries.trusted_seeds.map(({ subject_nid, evidence_id }) => ({ subject_id: subject_nid, evidence_id, authority_class: "trusted-seed" as const, action: "invalidated" as const })),
    ...summaries.stalled_groups.map((record) => ({ ...record, authority_class: "stalled-group" as const, action: "stalled" as const })),
  ];
  const records = authoritative.evidence_bundle.state_transitions;
  if (
    records.length !== expected.length
    || records.some((record) => record === null || typeof record !== "object")
  ) return false;
  return expected.every((summary) => {
    const matches = records.filter((record) =>
      record.evidence_id === summary.evidence_id
      && record.subject_id === summary.subject_id
      && record.authority_class === summary.authority_class
      && record.action === summary.action
    );
    if (matches.length !== 1) return false;
    const record = matches[0];
    const priorDigest = record.authority_class === "stalled-group"
      ? inventory.unreachable_group_ids.includes(record.subject_id)
        ? inventory.inventory_id
        : undefined
      : inventory.authorization_records.find((candidate) =>
        candidate.authority_class === record.authority_class
        && candidate.subject_id === record.subject_id
      )?.authorization_digest;
    return hasExactKeys(record, [
      "action", "authority_class", "effective_at", "evidence_id",
      "prior_authorization_digest", "recovery_id", "signature", "signer",
      "subject_id",
    ])
      && priorDigest !== undefined
      && record.prior_authorization_digest === priorDigest
      && record.recovery_id === grant.recovery_id
      && record.signer === grant.authorizing_pubkey
      && record.effective_at >= grant.issued_at
      && record.effective_at <= completion.completed_at
      && safeSchnorrVerify(
        record.signature,
        resetStateEvidenceProofBytes(record),
        record.signer,
      );
  });
}

function decodeStrictBase64(value: string): Uint8Array | undefined {
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.length > 0 && decoded.toString("base64") === value
      ? decoded
      : undefined;
  } catch {
    return undefined;
  }
}

function authenticatedMlsEvidenceIsExact(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
  authoritative: CompromiseResetEvidence,
  grant: CompromiseResetGrant,
): boolean {
  const commits = authoritative.evidence_bundle.group_commits;
  if (
    commits.length !== inventory.reachable_groups.length
    || commits.some((commit) =>
      commit === null
      || typeof commit !== "object"
      || !Array.isArray(commit.removed_leaf_ids)
      || !Array.isArray(commit.continuing_leaf_ids)
      || !Array.isArray(commit.successor_leaves)
    )
  ) return false;
  return inventory.reachable_groups.every((prior) => {
    const summary = completion.transition_evidence.groups.find(({ group_id }) =>
      group_id === prior.group_id
    );
    const matches = commits.filter(({ group_id }) => group_id === prior.group_id);
    if (summary === undefined || matches.length !== 1) return false;
    const commit = matches[0];
    const rawCommit = decodeStrictBase64(commit.commit_bytes_base64);
    const removed = prior.leaves
      .filter(({ account_key }) => account_key === inventory.persona_active_key)
      .map(({ leaf_id }) => leaf_id);
    const continuing = prior.leaves
      .filter(({ leaf_id }) => !removed.includes(leaf_id))
      .map(({ leaf_id }) => leaf_id);
    const freshForGroup = completion.fresh_keypackages.filter(({ group_id }) =>
      group_id === prior.group_id
    );
    return hasExactKeys(commit, [
      "commit_bytes_base64", "commit_sha256", "continuing_leaf_ids",
      "evidence_id", "group_id", "mls_verifier_pubkey", "next_epoch",
      "next_state_digest", "prior_epoch", "prior_state_digest", "recovery_id",
      "removed_leaf_ids", "successor_leaves", "verification_signature",
      "verified_at",
    ])
      && commit.successor_leaves.every((leaf) => hasExactKeys(leaf, [
        "account_key", "keypackage_id", "leaf_id", "leaf_index",
      ]))
      && rawCommit !== undefined
      && commit.evidence_id === summary.evidence_id
      && commit.recovery_id === grant.recovery_id
      && commit.prior_epoch === prior.epoch
      && commit.next_epoch === prior.epoch + 1
      && commit.prior_state_digest === prior.state_digest
      && /^[0-9a-f]{64}$/.test(commit.next_state_digest)
      && commit.next_state_digest !== prior.state_digest
      && commit.commit_sha256 === createHash("sha256").update(rawCommit).digest("hex")
      && exactSet(commit.removed_leaf_ids, removed)
      && exactSet(commit.continuing_leaf_ids, continuing)
      && freshForGroup.length > 0
      && commit.successor_leaves.length === freshForGroup.length
      && exactSet(
        commit.successor_leaves.map(({ keypackage_id }) => keypackage_id),
        freshForGroup.map(({ keypackage_id }) => keypackage_id),
      )
      && new Set(commit.successor_leaves.map(({ leaf_id }) => leaf_id)).size
        === commit.successor_leaves.length
      && new Set(commit.successor_leaves.map(({ leaf_index }) => leaf_index)).size
        === commit.successor_leaves.length
      && commit.successor_leaves.every((leaf) =>
        leaf.account_key === grant.successor_active_key
        && finiteSafeInteger(leaf.leaf_index)
        && !prior.leaves.some(({ leaf_id, leaf_index }) =>
          leaf_id === leaf.leaf_id || leaf_index === leaf.leaf_index
        )
        && freshForGroup.some(({ keypackage_id }) =>
          keypackage_id === leaf.keypackage_id
        )
      )
      && commit.verified_at >= grant.issued_at
      && commit.verified_at <= completion.completed_at
      && commit.mls_verifier_pubkey === prior.mls_verifier_pubkey
      && safeSchnorrVerify(
        commit.verification_signature,
        mlsCommitEvidenceProofBytes(commit),
        commit.mls_verifier_pubkey,
      );
  });
}

function freshKeyPackagesAreAuthentic(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
  grant: CompromiseResetGrant,
): boolean {
  return completion.fresh_keypackages.every((candidate) => {
    const event = snapshotAndVerifyNostrEvent(candidate.event);
    if (event === null) return false;
    const content = decodeStrictBase64(event.content);
    const group = inventory.reachable_groups.find(({ group_id }) =>
      group_id === candidate.group_id
    );
    const tags = new Map<string, string[]>();
    for (const tag of event.tags) {
      if (tag.length < 2 || tags.has(tag[0])) return false;
      tags.set(tag[0], tag);
    }
    const singleton = (name: string, pattern: RegExp) => {
      const tag = tags.get(name);
      return tag !== undefined && tag.length === 2 && pattern.test(tag[1]);
    };
    const idList = (name: string) => {
      const tag = tags.get(name);
      return tag !== undefined
        && tag.length >= 2
        && tag.slice(1).every((value) => /^0x[0-9a-f]{4}$/.test(value))
        && new Set(tag.slice(1)).size === tag.length - 1;
    };
    return content !== undefined
      && event.id === candidate.event_id
      && event.pubkey === grant.successor_active_key
      && event.kind === 30443
      && event.created_at >= grant.issued_at
      && event.created_at <= completion.completed_at
      && tags.size === 7
      && singleton("d", /^[0-9a-f]{64}$/)
      && singleton("mls_protocol_version", /^1\.0$/)
      && singleton("i", /^[0-9a-f]+$/)
      && tags.get("i")?.[1] === candidate.keypackage_id
      && idList("mls_ciphersuite")
      && idList("mls_extensions")
      && idList("mls_proposals")
      && idList("app_components")
      && tags.get("app_components")?.slice(1).includes("0x8009")
      && candidate.content_sha256
        === createHash("sha256").update(content).digest("hex")
      && group !== undefined
      && candidate.mls_verifier_pubkey === group.mls_verifier_pubkey
      && safeSchnorrVerify(
        candidate.verification_signature,
        keyPackageVerificationProofBytes(candidate),
        candidate.mls_verifier_pubkey,
      );
  });
}

function groupEvidenceAdvancesExactly(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
): boolean {
  return completion.transition_evidence.groups.every((candidate) => {
    const prior = inventory.reachable_groups.find(({ group_id }) =>
      group_id === candidate.group_id
    );
    return prior !== undefined
      && candidate.prior_epoch === prior.epoch
      && candidate.next_epoch === prior.epoch + 1;
  });
}

function subordinateContractsAreExact(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
  grant: CompromiseResetGrant,
): boolean {
  const expectedClass = (priorId: string) => {
    const record = inventory.authorization_records.find(({ authorization_id }) =>
      authorization_id === priorId
    );
    return record?.authority_class === "nip46-oidc-grant"
      ? undefined
      : record?.authority_class;
  };
  return completion.subordinate_reauthorizations.every((contract) =>
    expectedClass(contract.prior_authority_id) === contract.authority_class
    && contract.successor_active_key === grant.successor_active_key
    && contract.issued_at >= grant.issued_at
    && contract.issued_at <= completion.completed_at
    && contract.expires_at > completion.completed_at
    && contract.authorization_id !== contract.prior_authority_id
    && contract.contract_digest === subordinateContractDigest(contract)
  );
}

function replacementIdsAreFresh(
  completion: CompromiseResetCompletion,
  inventory: CompromiseResetInventory,
  evidence: CompromiseResetEvidence,
  recoveryId: string,
): boolean {
  const oldIds = new Set([
    recoveryId,
    inventory.inventory_id,
    ...inventory.nip46_oidc_grant_ids,
    ...inventory.client_ids,
    ...inventory.repository_ids,
    ...inventory.delegate_ids,
    ...inventory.node_ids,
    ...inventory.agent_ids,
    ...inventory.marmot_leaf_ids,
    ...inventory.reachable_groups.map(({ group_id }) => group_id),
    ...inventory.unreachable_group_ids,
    ...inventory.subordinate_authority_ids,
    ...inventory.existing_transition_ids,
    ...inventory.existing_keypackage_event_ids,
    ...inventory.reachable_groups.flatMap(({ leaves }) =>
      leaves.map(({ keypackage_id }) => keypackage_id)
    ),
    ...inventory.authorization_records.map(({ authorization_id }) => authorization_id),
  ]);
  const transitionEvidence = completion.transition_evidence;
  const newIds = [
    ...transitionEvidence.nip46_oidc_grants.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.clients.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.repositories.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.delegates.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.nodes.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.agents.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.trusted_seeds.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.groups.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.stalled_groups.map(({ evidence_id }) => evidence_id),
    ...evidence.evidence_bundle.group_commits.flatMap(({ successor_leaves }) =>
      successor_leaves.map(({ leaf_id }) => leaf_id)
    ),
    ...completion.fresh_keypackages.flatMap(({ keypackage_id, event_id }) => [keypackage_id, event_id]),
    ...completion.subordinate_reauthorizations.map(({ authorization_id }) => authorization_id),
  ];
  return new Set(newIds).size === newIds.length
    && newIds.every((candidate) => !oldIds.has(candidate));
}
