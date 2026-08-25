import { Ajv } from "ajv";
import signerGrantSchema from "../../../schemas/control/control-client-authorization-v1.schema.json" with { type: "json" };
import recoveryCompletionSchema from "../../../schemas/control/control-recovery-completion-v1.schema.json" with { type: "json" };
import recoveryGrantSchema from "../../../schemas/control/control-recovery-grant-v1.schema.json" with { type: "json" };
import { injectAgentAttribution, matchesAgentAttributionProfile } from "./agent-authorship.js";
import { jcsCanonicalize } from "./jcs.js";

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
  method: string;
  event_kind: number;
  request_count: number;
  event_bytes: number;
  value_msats: number;
  now: number;
};

export type Nip46ClientMetadata = {
  requested_methods: string[];
  requested_event_kinds: number[];
  requested_signer_audiences: string[];
};

export type Nip46AuthorizationInput = {
  stored_grant: SigningGrant;
  presented_grant: SigningGrant;
  vaults: PersonaVault[];
  request: Nip46SigningRequest;
  client_metadata: Nip46ClientMetadata;
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateSignerGrant = ajv.compile<SigningGrant>(signerGrantSchema);
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

export function authorizeNip46Signing(input: Nip46AuthorizationInput):
  | {
      verdict: "accept";
      vault_id: string;
      persona_active_key: string;
      selected_signing_pubkey: string;
      key_class: KeyClass;
      custody: Custody;
    }
  | Reject {
  const grant = input.stored_grant;
  if (
    grant.key_class === "persona"
    && (
      !grant.persona_signing_authorized
      || grant.selected_signing_pubkey !== grant.persona_active_key
    )
  ) {
    return reject("control-persona-authority-required");
  }
  if (!validateSignerGrant(grant)) {
    return reject("control-signing-grant-invalid");
  }
  if (jcsCanonicalize(input.presented_grant) !== jcsCanonicalize(grant)) {
    return reject("control-signer-binding-mismatch");
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
    || !finiteSafeInteger(input.request.request_count)
    || input.request.request_count < 1
    || input.request.request_count > grant.limits.request_count
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

export type Nip46ConnectionState = {
  transaction_id: string;
  connection_secret_sha256: string;
  connection_secret_state: "pending" | "consumed";
  state: "pending" | "approved" | "denied" | "expired" | "consumed";
};

export function consumeNip46ConnectionSecret(
  state: Nip46ConnectionState,
  presentedSecretSha256: string,
): { verdict: "accept"; state: Nip46ConnectionState } | Reject {
  if (state.connection_secret_state === "consumed") {
    return reject("control-connection-secret-reused");
  }
  if (
    state.state !== "approved"
    || presentedSecretSha256 !== state.connection_secret_sha256
    || !/^[0-9a-f]{64}$/.test(presentedSecretSha256)
  ) {
    return reject("control-connection-secret-invalid");
  }
  return {
    verdict: "accept",
    state: { ...state, connection_secret_state: "consumed" },
  };
}

type AutomatedPublication = {
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  value_msats: number;
  agent_class: "ai" | "programmatic";
  agent_association?: { kind: "key" | "role"; value: string };
  tier: 1 | 2 | 3;
};

type UnsignedEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export function prepareAutomatedSigning<T extends UnsignedEvent & { id: string; sig: string }>(input: {
  authorization: Nip46AuthorizationInput;
  publication: AutomatedPublication;
  sign: (event: UnsignedEvent) => T;
}): { verdict: "accept"; event: T } | Reject {
  const authorized = authorizeNip46Signing(input.authorization);
  if (authorized.verdict !== "accept") return authorized;
  const publication = input.publication;
  if (
    publication.kind !== input.authorization.request.event_kind
    || publication.value_msats !== input.authorization.request.value_msats
  ) {
    return reject("control-signer-binding-mismatch");
  }
  const attributed = injectAgentAttribution({
    kind: publication.kind,
    tags: publication.tags,
    agent_class: publication.agent_class,
    persona: authorized.persona_active_key,
    signer: authorized.selected_signing_pubkey,
    expected_signer: authorized.selected_signing_pubkey,
    signer_key_class: authorized.key_class,
    oidc_scopes: authorized.key_class === "persona"
      ? ["heterodyne:agent:sign:persona"]
      : [],
    agent_association: publication.agent_association,
    expected_agent_association: publication.agent_association,
    tier: publication.tier,
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
      > input.authorization.stored_grant.limits.max_event_bytes
  ) {
    return reject("control-signing-grant-invalid");
  }
  const event = input.sign(unsigned);
  if (
    event.pubkey !== unsigned.pubkey
    || event.created_at !== unsigned.created_at
    || event.kind !== unsigned.kind
    || event.content !== unsigned.content
    || jcsCanonicalize(event.tags) !== jcsCanonicalize(unsigned.tags)
    || !/^[0-9a-f]{64}$/.test(event.id)
    || !/^[0-9a-f]{128}$/.test(event.sig)
  ) {
    return reject("control-attribution-required");
  }
  return { verdict: "accept", event };
}

export type CompromiseResetGrant = {
  profile: "heterodyne.control.compromise-reset-grant.v1";
  spec_version: "heterodyne/0.5.0";
  recovery_id: string;
  persona_active_key: string;
  successor_active_key: string;
  authorization_class: "active-account" | "assurance-recovery";
  authorizing_pubkey: string;
  compromise_at: number;
  required_reset: {
    nip46_oidc_grant_ids: string[];
    client_ids: string[];
    delegate_ids: string[];
    node_ids: string[];
    agent_ids: string[];
    trusted_seed_nids: string[];
    marmot_leaf_ids: string[];
    reachable_group_ids: string[];
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
  revoked_nip46_oidc_grant_ids: string[];
  invalidated_client_ids: string[];
  invalidated_delegate_ids: string[];
  invalidated_node_ids: string[];
  invalidated_agent_ids: string[];
  invalidated_trusted_seed_nids: string[];
  removed_marmot_leaf_ids: string[];
  advanced_group_ids: string[];
  stalled_group_ids: string[];
  fresh_keypackages: Array<{ account_key: string; event_id: string }>;
  subordinate_reauthorizations: Array<{
    prior_authority_id: string;
    authorization_id: string;
  }>;
  completed_at: number;
  signer: string;
  signature: string;
};

export function validateCompromiseReset(input: {
  grant: CompromiseResetGrant;
  completion: CompromiseResetCompletion;
  now: number;
}): { verdict: "accept" } | Reject {
  if (!validateRecoveryGrantSchema(input.grant)) {
    return reject("control-compromise-reset-incomplete");
  }
  if (!validateRecoveryCompletionSchema(input.completion)) {
    return reject("control-compromise-reset-incomplete");
  }
  const grant = input.grant;
  const completion = input.completion;
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
    || completion.signer !== grant.successor_active_key
    || grant.authorization_class === "active-account"
      && grant.authorizing_pubkey !== grant.persona_active_key
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
    && exactSet(completion.advanced_group_ids, required.reachable_group_ids)
    && completion.stalled_group_ids.every((groupId) =>
      !completion.advanced_group_ids.includes(groupId)
    )
    && completion.fresh_keypackages.some(({ account_key }) =>
      account_key === grant.successor_active_key
    );
  if (!complete) {
    return reject("control-compromise-reset-incomplete");
  }
  const reauthorized = completion.subordinate_reauthorizations.map(
    ({ prior_authority_id }) => prior_authority_id,
  );
  if (!exactSet(reauthorized, required.subordinate_authority_ids)) {
    return reject("control-subordinate-reauthorization-required");
  }
  return { verdict: "accept" };
}
