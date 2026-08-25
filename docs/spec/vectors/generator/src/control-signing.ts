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
import { verifyEventSignature } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";

type KeyClass = "persona" | "agent";
type Custody = "local" | "nip46";
type Reject = { verdict: "reject"; reason_code: string };

export type SigningGrant = {
  profile: "heterodyne.control.signer-grant.v1";
  spec_version: "heterodyne/0.5.0";
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
  request_id: string;
  request_digest: string;
  grant_id: string;
  vault_id: string;
  persona_active_key: string;
  nip46_client_pubkey: string;
  signer_audience: string;
  selected_signing_pubkey: string;
  key_class: KeyClass;
  method: string;
  event_kind: number;
  event_bytes: number;
  value_msats: number;
  now: number;
};

export type GrantUsageState = {
  grant_id: string;
  window_started_at: number;
  consumed_request_count: number;
  revision: number;
  reservations: Array<{
    request_id: string;
    request_digest: string;
    state: "reserved" | "committed";
    result_event_id: string | null;
  }>;
};

export type GrantUsageTransition = {
  grant_id: string;
  request_id: string;
  request_digest: string;
  expected_revision: number;
  next_revision: number;
  prior_window_started_at: number;
  window_started_at: number;
  prior_consumed_request_count: number;
  consumed_request_count: number;
  reservation_state: "reserved";
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

export function signerGrantProofBytes(
  value: Omit<SigningGrant, "signature"> | SigningGrant,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as SigningGrant;
  return proofBytes("heterodyne-control-signer-grant-v1", unsigned);
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
    !grant.allowed_methods.includes(input.request.method)
    || !grant.allowed_event_kinds.includes(input.request.event_kind)
    || !finiteSafeInteger(input.request.event_bytes)
    || input.request.event_bytes < 1
    || input.request.event_bytes > grant.limits.max_event_bytes
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
  if (!grantUsageStateIsValid(grant, request, usage)) {
    return reject("control-signing-grant-invalid");
  }
  const prior = usage.reservations.find(({ request_id }) =>
    request_id === request.request_id
  );
  if (prior !== undefined) {
    if (prior.request_digest !== request.request_digest) {
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
    grant_id: grant.grant_id,
    request_id: request.request_id,
    request_digest: request.request_digest,
    expected_revision: usage.revision,
    next_revision: usage.revision + 1,
    prior_window_started_at: usage.window_started_at,
    window_started_at: windowStartedAt,
    prior_consumed_request_count: usage.consumed_request_count,
    consumed_request_count: priorCount + 1,
    reservation_state: "reserved",
  };
}

function grantUsageStateIsValid(
  grant: SigningGrant,
  request: Nip46SigningRequest,
  usage: GrantUsageState,
): boolean {
  const validReservation = (candidate: GrantUsageState["reservations"][number]) =>
    /^[0-9a-f]{64}$/.test(candidate.request_id)
    && /^[0-9a-f]{64}$/.test(candidate.request_digest)
    && ["reserved", "committed"].includes(candidate.state)
    && (candidate.state === "reserved"
      ? candidate.result_event_id === null
      : /^[0-9a-f]{64}$/.test(candidate.result_event_id ?? ""));
  return !(
    usage.grant_id !== grant.grant_id
    || !finiteSafeInteger(usage.window_started_at)
    || usage.window_started_at > request.now
    || !finiteSafeInteger(usage.consumed_request_count)
    || !finiteSafeInteger(usage.revision)
    || usage.revision === Number.MAX_SAFE_INTEGER
    || !Array.isArray(usage.reservations)
    || usage.reservations.some((candidate) => !validReservation(candidate))
    || new Set(usage.reservations.map(({ request_id }) => request_id)).size
      !== usage.reservations.length
    || !/^[0-9a-f]{64}$/.test(request.request_id)
    || !/^[0-9a-f]{64}$/.test(request.request_digest)
  );
}

export type Nip46ConnectionState = {
  profile: "heterodyne.control.device-authorization-state.v1";
  spec_version: "heterodyne/0.5.0";
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
  spec_version: "heterodyne/0.5.0";
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

type UnsignedEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export function automatedPublicationDigest(publication: AutomatedPublication): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-agent-publish-intent-v1", publication))
    .digest("hex");
}

function requirePersistedReservation(input: Nip46AuthorizationInput):
  | { verdict: "accept"; reservation_revision: number }
  | { verdict: "replay"; event_id: string }
  | Reject {
  const grant = input.presented_grant;
  const usage = input.usage_state;
  const request = input.request;
  if (!grantUsageStateIsValid(grant, request, usage)) {
    return reject("control-signing-grant-invalid");
  }
  const reservation = usage.reservations.find(({ request_id }) =>
    request_id === request.request_id
  );
  if (reservation === undefined || usage.consumed_request_count < 1) {
    return reject("control-operation-reservation-required");
  }
  if (reservation.request_digest !== request.request_digest) {
    return reject("control-operation-conflict");
  }
  if (reservation.state === "committed") {
    return { verdict: "replay", event_id: reservation.result_event_id as string };
  }
  return { verdict: "accept", reservation_revision: usage.revision };
}

export function prepareAutomatedSigning<T extends UnsignedEvent & { id: string; sig: string }>(input: {
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
  sign: (event: UnsignedEvent) => T;
}):
  | {
      verdict: "accept";
      event: T;
      reservation_revision: number;
      commit_transition: {
        grant_id: string;
        request_id: string;
        request_digest: string;
        expected_revision: number;
        next_revision: number;
        prior_reservation_state: "reserved";
        reservation_state: "committed";
        event_id: string;
      };
    }
  | { verdict: "replay"; event_id: string }
  | Reject {
  const publication = input.publication;
  if (!validateAutomatedPublication(publication)) {
    return reject("control-agent-intent-invalid");
  }
  if (
    input.authorization.request.request_digest
      !== automatedPublicationDigest(publication)
  ) {
    return reject("control-operation-conflict");
  }
  const authorized = validateNip46Authority(input.authorization);
  if (authorized.verdict !== "accept") return authorized;
  const grant = input.authorization.presented_grant;
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
    || publication.kind !== input.authorization.request.event_kind
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
    Buffer.byteLength(jcsCanonicalize(unsigned), "utf8")
      > input.authorization.presented_grant.limits.max_event_bytes
  ) {
    return reject("control-signing-grant-invalid");
  }
  const persistedReservation = requirePersistedReservation(input.authorization);
  if (persistedReservation.verdict !== "accept") return persistedReservation;
  const event = input.sign(unsigned);
  if (
    Object.keys(event).sort().join("\0")
      !== ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"].join("\0")
    || event.pubkey !== unsigned.pubkey
    || event.created_at !== unsigned.created_at
    || event.kind !== unsigned.kind
    || event.content !== unsigned.content
    || jcsCanonicalize(event.tags) !== jcsCanonicalize(unsigned.tags)
    || !/^[0-9a-f]{64}$/.test(event.id)
    || !/^[0-9a-f]{128}$/.test(event.sig)
    || !verifyEventSignature(event)
  ) {
    return reject("control-signed-event-invalid");
  }
  return {
    verdict: "accept",
    event,
    reservation_revision: persistedReservation.reservation_revision,
    commit_transition: {
      grant_id: grant.grant_id,
      request_id: input.authorization.request.request_id,
      request_digest: input.authorization.request.request_digest,
      expected_revision: persistedReservation.reservation_revision,
      next_revision: persistedReservation.reservation_revision + 1,
      prior_reservation_state: "reserved",
      reservation_state: "committed",
      event_id: event.id,
    },
  };
}

export type CompromiseResetGrant = {
  profile: "heterodyne.control.compromise-reset-grant.v1";
  spec_version: "heterodyne/0.5.0";
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
  spec_version: "heterodyne/0.5.0";
  recovery_id: string;
  persona_active_key: string;
  successor_active_key: string;
  inventory_id: string;
  inventory_revision: number;
  inventory_digest: string;
  evidence_revision: number;
  revoked_nip46_oidc_grant_ids: string[];
  invalidated_client_ids: string[];
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
    event_id: string;
  }>;
  subordinate_reauthorizations: Array<{
    prior_authority_id: string;
    authorization_id: string;
    authority_class: "client" | "delegate" | "node" | "agent";
    successor_active_key: string;
    issued_at: number;
    expires_at: number;
    permissions_digest: string;
    contract_digest: string;
  }>;
  transition_evidence: {
    nip46_oidc_grants: HexTransitionEvidence[];
    clients: HexTransitionEvidence[];
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
  delegate_ids: string[];
  node_ids: string[];
  agent_ids: string[];
  trusted_seed_nids: string[];
  marmot_leaf_ids: string[];
  reachable_groups: Array<{ group_id: string; epoch: number }>;
  unreachable_group_ids: string[];
  subordinate_authority_ids: string[];
  existing_transition_ids: string[];
  existing_keypackage_event_ids: string[];
};

export type CompromiseResetEvidence = {
  inventory_id: string;
  inventory_revision: number;
  evidence_revision: number;
  observed_at: number;
  transition_evidence: CompromiseResetCompletion["transition_evidence"];
  fresh_keypackages: CompromiseResetCompletion["fresh_keypackages"];
  subordinate_reauthorizations: CompromiseResetCompletion["subordinate_reauthorizations"];
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

export function validateCompromiseReset(input: {
  grant: CompromiseResetGrant;
  completion: CompromiseResetCompletion;
  authoritative_inventory: CompromiseResetInventory;
  authoritative_evidence: CompromiseResetEvidence;
  pinned_assurance_authority: PinnedAssuranceAuthority | null;
  now: number;
}): {
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
    delegate_ids: inventory.delegate_ids,
    node_ids: inventory.node_ids,
    agent_ids: inventory.agent_ids,
    trusted_seed_nids: inventory.trusted_seed_nids,
    marmot_leaf_ids: inventory.marmot_leaf_ids,
    reachable_groups: inventory.reachable_groups,
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
  };
  const presentedEvidence = {
    inventory_id: evidence.inventory_id,
    inventory_revision: evidence.inventory_revision,
    evidence_revision: evidence.evidence_revision,
    transition_evidence: evidence.transition_evidence,
    fresh_keypackages: evidence.fresh_keypackages,
    subordinate_reauthorizations: evidence.subordinate_reauthorizations,
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
    || !subordinateContractsAreExact(completion, inventory, grant)
    || completion.fresh_keypackages.some(({ account_key }) =>
      account_key !== grant.successor_active_key
    )
    || !replacementIdsAreFresh(completion, inventory, grant.recovery_id)
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
    && exactSet(evidence.delegates.map(({ subject_id }) => subject_id), inventory.delegate_ids)
    && exactSet(evidence.nodes.map(({ subject_id }) => subject_id), inventory.node_ids)
    && exactSet(evidence.agents.map(({ subject_id }) => subject_id), inventory.agent_ids)
    && exactSet(evidence.trusted_seeds.map(({ subject_nid }) => subject_nid), inventory.trusted_seed_nids)
    && exactSet(evidence.marmot_leaves.map(({ subject_id }) => subject_id), inventory.marmot_leaf_ids)
    && exactSet(evidence.groups.map(({ group_id }) => group_id), inventory.reachable_groups.map(({ group_id }) => group_id))
    && exactSet(evidence.stalled_groups.map(({ subject_id }) => subject_id), inventory.unreachable_group_ids);
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
    const memberships = ([
      ["client", inventory.client_ids],
      ["delegate", inventory.delegate_ids],
      ["node", inventory.node_ids],
      ["agent", inventory.agent_ids],
    ] as const).filter(([, ids]) => ids.includes(priorId));
    return memberships.length === 1 ? memberships[0][0] : undefined;
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
  recoveryId: string,
): boolean {
  const oldIds = new Set([
    recoveryId,
    inventory.inventory_id,
    ...inventory.nip46_oidc_grant_ids,
    ...inventory.client_ids,
    ...inventory.delegate_ids,
    ...inventory.node_ids,
    ...inventory.agent_ids,
    ...inventory.marmot_leaf_ids,
    ...inventory.reachable_groups.map(({ group_id }) => group_id),
    ...inventory.unreachable_group_ids,
    ...inventory.subordinate_authority_ids,
    ...inventory.existing_transition_ids,
    ...inventory.existing_keypackage_event_ids,
  ]);
  const transitionEvidence = completion.transition_evidence;
  const newIds = [
    ...transitionEvidence.nip46_oidc_grants.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.clients.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.delegates.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.nodes.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.agents.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.trusted_seeds.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.marmot_leaves.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.groups.map(({ evidence_id }) => evidence_id),
    ...transitionEvidence.stalled_groups.map(({ evidence_id }) => evidence_id),
    ...completion.fresh_keypackages.flatMap(({ keypackage_id, event_id }) => [keypackage_id, event_id]),
    ...completion.subordinate_reauthorizations.map(({ authorization_id }) => authorization_id),
  ];
  return new Set(newIds).size === newIds.length
    && newIds.every((candidate) => !oldIds.has(candidate));
}
