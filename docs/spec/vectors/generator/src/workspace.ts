export type WorkspaceVerdict =
  | { verdict: "accept"; normalized: Record<string, unknown> }
  | { verdict: "reject"; reason_code: string };

const accepted = (normalized: Record<string, unknown>): WorkspaceVerdict => ({
  verdict: "accept",
  normalized,
});
const rejected = (reason_code: string): WorkspaceVerdict => ({
  verdict: "reject",
  reason_code,
});

const intersection = (sets: readonly string[][]): string[] => {
  if (sets.length === 0) return [];
  const remaining = new Set(sets[0]);
  for (const values of sets.slice(1)) {
    const current = new Set(values);
    for (const value of remaining) {
      if (!current.has(value)) remaining.delete(value);
    }
  }
  return [...remaining].sort();
};

const subset = (values: readonly string[], ceiling: readonly string[]): boolean => {
  const allowed = new Set(ceiling);
  return values.every((value) => allowed.has(value));
};

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

export function workspaceSigningPayload(object: Record<string, unknown>): Uint8Array {
  const unsigned = { ...object };
  delete unsigned.signature;
  // A bilateral relationship's receiving signature covers the same terms as
  // the source signature; neither signature can be part of that shared input.
  delete unsigned.receiving_signature;
  const body = { ...unsigned };
  for (const member of [
    "spec_version",
    "object_type",
    "workspace_key",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "repository_rid",
    "repository_head",
    "issued_at",
  ]) delete body[member];
  return proofBytes("heterodyne-workspace-object-v1", {
    authority_checkpoint: unsigned.authority_checkpoint,
    body,
    issued_at: unsigned.issued_at,
    object_type: unsigned.object_type,
    policy_head: unsigned.policy_head,
    predecessor: unsigned.predecessor,
    repository_head: unsigned.repository_head,
    repository_rid: unsigned.repository_rid,
    spec_version: unsigned.spec_version,
    workspace_key: unsigned.workspace_key,
  });
}

export function workspaceObjectId(object: Record<string, unknown>): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(object))));
}

export function signWorkspaceObject(
  object: Record<string, unknown>,
  secretKey: string,
  auxRand = "00".repeat(32),
): Record<string, unknown> {
  const workspace_key = bytesToHex(schnorr.getPublicKey(hexToBytes(secretKey)));
  const unsigned = { ...object, workspace_key };
  const signature = bytesToHex(schnorr.sign(
    workspaceSigningPayload(unsigned),
    hexToBytes(secretKey),
    hexToBytes(auxRand),
  ));
  return { ...unsigned, signature };
}

export function evaluateWorkspaceObject(input: {
  object: Record<string, unknown>;
  expected_object_id: string;
  active_workspace_key?: string;
  accepted_policy_head?: string;
  accepted_predecessor?: string | null;
  accepted_authority_checkpoint?: string;
  accepted_repository_rid?: string;
  accepted_repository_head?: string;
  authority_conflict?: boolean;
}): WorkspaceVerdict {
  if (input.authority_conflict) return rejected("authority_conflict");
  const object = snapshotJsonRecord(input.object);
  if (object === null) return rejected("workspace_schema_invalid");
  const objectType = object.object_type;
  if (typeof objectType !== "string" || WORKSPACE_SCHEMAS[objectType] === undefined) {
    return rejected("workspace_schema_invalid");
  }
  const validate = new Ajv({ allErrors: true, strict: false }).compile(WORKSPACE_SCHEMAS[objectType]);
  if (!validate(object)) return rejected("workspace_schema_invalid");
  const workspaceKey = object.workspace_key;
  const signatureValue = object.signature;
  if (typeof workspaceKey !== "string" || typeof signatureValue !== "string"
    || workspaceKey !== input.active_workspace_key
    || object.policy_head !== input.accepted_policy_head
    || object.predecessor !== input.accepted_predecessor
    || object.authority_checkpoint !== input.accepted_authority_checkpoint
    || object.repository_rid !== input.accepted_repository_rid
    || object.repository_head !== input.accepted_repository_head
    || !validWorkspaceSignature(object, workspaceKey, signatureValue)) {
    return rejected("workspace_signature_invalid");
  }
  const objectId = workspaceObjectId(object);
  if (objectId !== input.expected_object_id) return rejected("workspace_signature_invalid");
  return accepted({ object_id: objectId, object_type: objectType, workspace_key: workspaceKey });
}

function validWorkspaceSignature(
  object: Record<string, unknown>,
  key: string,
  signature: string,
): boolean {
  try {
    return schnorr.verify(signature, workspaceSigningPayload(object), key);
  } catch {
    return false;
  }
}

export function evaluateAuthorization(input: {
  requested: string[];
  workspace_ceiling: string[];
  role_path_ceilings: string[][];
  subject_capabilities: string[];
  device_active: boolean;
  denied: boolean;
  revoked: boolean;
  authority_conflict: boolean;
  carrier_only_evidence: boolean;
  authority_source?: "workspace-policy" | "host" | "seed" | "repository-writer" | "marmot-admin";
  revocation_effective_at?: number | null;
  now?: number;
}): WorkspaceVerdict {
  if (input.authority_conflict) return rejected("authority_conflict");
  if (!input.device_active) return rejected("device_revoked");
  if (input.authority_source !== undefined && input.authority_source !== "workspace-policy") {
    return rejected("policy_denied");
  }
  if ((input.revocation_effective_at !== undefined && input.revocation_effective_at !== null
    && (!Number.isSafeInteger(input.revocation_effective_at)
      || !Number.isSafeInteger(input.now)))) {
    return rejected("workspace_schema_invalid");
  }
  const revocationEffective = input.revoked && (
    input.revocation_effective_at === undefined
    || input.revocation_effective_at === null
    || (input.now as number) >= input.revocation_effective_at
  );
  if (input.denied || revocationEffective || input.carrier_only_evidence) {
    return rejected("policy_denied");
  }
  const effective = intersection([
    input.workspace_ceiling,
    ...input.role_path_ceilings,
    input.subject_capabilities,
  ]);
  if (!subset(input.requested, effective)) return rejected("capability_escalation");
  return accepted({ effective_capabilities: effective });
}

export function evaluateGrantActivation(input: {
  actor_capabilities: string[];
  grant_capabilities: string[];
  grant_delegable: boolean;
  required_approvals: number;
  valid_approval_actors: string[];
  subject_accepted: boolean;
  waiting_period_elapsed: boolean;
  invitation_nonce_unused: boolean;
  invitation_unexpired: boolean;
  workspace_key?: string;
  current_workspace_key?: string;
  policy_head?: string;
  current_policy_head?: string;
  subject_account?: string;
  authenticated_account?: string;
  target_device?: string;
  accepted_device?: string;
  target_leaf?: string;
  accepted_leaf?: string;
  successor_reauthorized?: boolean;
}): WorkspaceVerdict {
  if (typeof input.workspace_key !== "string"
    || !/^[0-9a-f]{64}$/.test(input.workspace_key)
    || typeof input.policy_head !== "string"
    || !/^[0-9a-f]{64}$/.test(input.policy_head)
    || typeof input.subject_account !== "string"
    || !/^[0-9a-f]{64}$/.test(input.subject_account)
    || input.workspace_key !== input.current_workspace_key
    || input.policy_head !== input.current_policy_head
    || input.subject_account !== input.authenticated_account
    || input.successor_reauthorized !== true) {
    return rejected("policy_denied");
  }
  if (typeof input.target_device !== "string"
    || !/^[0-9a-f]{64}$/.test(input.target_device)
    || input.target_device !== input.accepted_device
    || input.target_leaf !== input.accepted_leaf
    || typeof input.target_leaf !== "string"
    || !isCanonicalMarmotLeaf(input.target_leaf)) {
    return rejected("device_revoked");
  }
  if (!input.invitation_nonce_unused) return rejected("workspace_replay");
  if (!input.invitation_unexpired || !input.subject_accepted || !input.waiting_period_elapsed) {
    return rejected("policy_denied");
  }
  const mayGrant = input.actor_capabilities.includes("invite");
  const mayDelegate = input.actor_capabilities.includes("govern-delegation");
  const governanceRequested = input.grant_capabilities.some((capability) =>
    capability.startsWith("govern-"));
  if (!mayGrant || governanceRequested || (input.grant_delegable && !mayDelegate)) {
    return rejected("capability_escalation");
  }
  const distinctApprovals = new Set(input.valid_approval_actors).size;
  if (distinctApprovals < input.required_approvals) return rejected("policy_denied");
  return accepted({ active: true, approval_count: distinctApprovals });
}

export function evaluateAllowance(input: {
  /** Legacy frozen-topic input accepted only for source compatibility; never trusted. */
  signatures_match?: boolean;
  relationship?: Record<string, unknown>;
  active_source_workspace_key?: string;
  active_receiving_workspace_key?: string;
  accepted_source_policy_head?: string;
  accepted_source_checkpoint?: string;
  accepted_source_predecessor?: string | null;
  accepted_receiving_policy_head?: string;
  accepted_receiving_checkpoint?: string;
  accepted_receiving_predecessor?: string | null;
  receiving_policy_allows: boolean;
  revoked: boolean;
  now?: number;
  requested_capabilities: string[];
  proof_age: number;
}): WorkspaceVerdict {
  const relationship = snapshotJsonRecord(input.relationship);
  const relationshipSchema = WORKSPACE_SCHEMAS["workspace-relationship-v1"];
  if (relationship === null
    || !new Ajv({ allErrors: true, strict: false }).compile(relationshipSchema)(relationship)
    || relationship.workspace_key !== input.active_source_workspace_key
    || relationship.source_workspace_key !== input.active_source_workspace_key
    || relationship.receiving_workspace_key !== input.active_receiving_workspace_key
    || relationship.policy_head !== input.accepted_source_policy_head
    || relationship.authority_checkpoint !== input.accepted_source_checkpoint
    || relationship.predecessor !== input.accepted_source_predecessor
    || relationship.receiving_policy_head !== input.accepted_receiving_policy_head
    || relationship.receiving_authority_checkpoint !== input.accepted_receiving_checkpoint
    || relationship.receiving_predecessor !== input.accepted_receiving_predecessor
    || typeof relationship.signature !== "string"
    || typeof relationship.receiving_signature !== "string"
    || !validWorkspaceSignature(
      relationship,
      input.active_source_workspace_key ?? "",
      relationship.signature,
    )
    || !validWorkspaceSignature(
      relationship,
      input.active_receiving_workspace_key ?? "",
      relationship.receiving_signature,
    )) {
    return rejected("workspace_signature_invalid");
  }
  if (!Number.isSafeInteger(input.now)
    || typeof relationship.expires_at !== "number"
    || (input.now as number) >= relationship.expires_at
    || !input.receiving_policy_allows || input.revoked) {
    return rejected("policy_denied");
  }
  const capabilityCeiling = relationship.capability_ceiling;
  if (!Array.isArray(capabilityCeiling)
    || !capabilityCeiling.every((value) => typeof value === "string")
    || !subset(input.requested_capabilities, capabilityCeiling)
    || input.requested_capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejected("capability_escalation");
  }
  const proofMaxAge = relationship.proof_max_age;
  const gracePeriod = relationship.grace_period;
  if (typeof proofMaxAge !== "number" || typeof gracePeriod !== "number"
    || input.proof_age > proofMaxAge + gracePeriod) {
    return rejected("affiliation_stale");
  }
  return accepted({
    capabilities: [...input.requested_capabilities].sort(),
    provisional_grace: input.proof_age > proofMaxAge,
  });
}

export function evaluatePrivateProjection(input: {
  private_identifiers: string[];
  private_counts: number;
  encrypted_placeholders: number;
}): WorkspaceVerdict {
  const disclosed = input.private_identifiers.length
    + input.private_counts
    + input.encrypted_placeholders;
  return disclosed === 0
    ? accepted({ disclosed_private_references: 0 })
    : rejected("private_topology_disclosed");
}

export function evaluateJointGovernance(input: {
  independent_joint_identity: boolean;
  valid_distinct_delegates: number;
  threshold: number;
  host_signatures_counted: number;
}): WorkspaceVerdict {
  if (!input.independent_joint_identity
    || input.host_signatures_counted !== 0
    || input.valid_distinct_delegates < input.threshold) {
    return rejected("policy_denied");
  }
  return accepted({ threshold_met: true, counted_delegates: input.valid_distinct_delegates });
}

export type WorkspaceHost = {
  host_id: string;
  priority: number;
  radicle_locators: string[];
  radicle_backed_relay: boolean;
};

export function resolveEffectiveHosts(input: {
  inherited: WorkspaceHost[];
  mode: "default" | "supplement" | "replace";
  configured: WorkspaceHost[];
  last_responsive: string | null;
}): WorkspaceVerdict {
  const selected = input.mode === "replace"
    ? input.configured
    : input.mode === "supplement"
      ? [...input.inherited, ...input.configured]
      : input.inherited;
  const byId = new Map(selected.map((host) => [host.host_id, host]));
  const hosts = [...byId.values()].sort((left, right) =>
    left.priority - right.priority || left.host_id.localeCompare(right.host_id));
  if (!hosts.some((host) => host.radicle_backed_relay && host.radicle_locators.length > 0)) {
    return rejected("policy_denied");
  }
  if (input.last_responsive !== null) {
    const index = hosts.findIndex((host) => host.host_id === input.last_responsive);
    if (index > 0) hosts.unshift(...hosts.splice(index, 1));
  }
  return accepted({ host_ids: hosts.map((host) => host.host_id), radicle_backstop: true });
}

export function evaluateRoleLeafChange(input: {
  persona_removed: boolean;
  removed_device: string | null;
  active_devices: string[];
  current_epoch: number;
}): WorkspaceVerdict {
  const removed = input.persona_removed
    ? [...input.active_devices].sort()
    : input.removed_device === null || !input.active_devices.includes(input.removed_device)
      ? []
      : [input.removed_device];
  if (removed.length === 0) return rejected("device_revoked");
  const removedSet = new Set(removed);
  return accepted({
    next_epoch: input.current_epoch + 1,
    removed_devices: removed,
    remaining_devices: input.active_devices.filter((device) => !removedSet.has(device)).sort(),
  });
}

export function evaluateKeyRequest(input: {
  resource_known: boolean;
  host_authorized: boolean;
  device_active: boolean;
  membership_active: boolean;
  checkpoint_age: number;
  requested_epoch: number;
  current_epoch: number;
  admission_epoch: number;
  history_mode: "full" | "from-admission" | "selected-snapshots";
  selected_epochs: number[];
  target_device: string;
  target_account?: string;
  authenticated_account?: string;
  authorized_device?: string;
  recipient: { type: string; value: string };
  authorized_recipient?: string;
  successor_reauthorized?: boolean;
}): WorkspaceVerdict {
  if (!/^[0-9a-f]{64}$/.test(input.target_device)
    || input.recipient.type !== "marmot-mls-leaf"
    || !isCanonicalMarmotLeaf(input.recipient.value)) {
    return rejected("workspace_schema_invalid");
  }
  if (!input.resource_known) return rejected("resource_unknown");
  if (!input.host_authorized) return rejected("host_unauthorized");
  if (typeof input.target_account !== "string"
    || !/^[0-9a-f]{64}$/.test(input.target_account)
    || input.target_account !== input.authenticated_account
    || input.successor_reauthorized !== true) return rejected("policy_denied");
  if (input.target_device !== input.authorized_device
    || input.recipient.value !== input.authorized_recipient) return rejected("device_revoked");
  if (!input.device_active) return rejected("device_revoked");
  if (!input.membership_active) return rejected("policy_denied");
  if (input.checkpoint_age > 300) return rejected("checkpoint_stale");
  if (input.requested_epoch > input.current_epoch) return rejected("resource_unknown");
  const historyAllowed = input.history_mode === "full"
    || (input.history_mode === "from-admission" && input.requested_epoch >= input.admission_epoch)
    || (input.history_mode === "selected-snapshots" && input.selected_epochs.includes(input.requested_epoch));
  if (!historyAllowed) return rejected("history_denied");
  return accepted({
    key_epoch: input.requested_epoch,
    target_device: input.target_device,
    recipient: { ...input.recipient },
    device_bound: true,
    idempotent: true,
  });
}

function isCanonicalMarmotLeaf(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

export function evaluateFreshness(input: {
  operation_class: "ordinary" | "authority";
  checkpoint_age: number;
  policy_max_age: number;
}): WorkspaceVerdict {
  const protocolMaximum = input.operation_class === "ordinary" ? 86_400 : 300;
  if (input.policy_max_age < 0 || input.policy_max_age > protocolMaximum) {
    return rejected("workspace_schema_invalid");
  }
  return input.checkpoint_age <= input.policy_max_age
    ? accepted({ maximum_age: input.policy_max_age, age: input.checkpoint_age })
    : rejected("checkpoint_stale");
}

export function selectEventRepository(input: {
  active_rid: string;
  active_mls_epoch: number;
  current_mls_epoch: number;
  size_bytes: number;
  max_size_bytes: number;
  next_rid: string;
}): WorkspaceVerdict {
  const reason = input.active_mls_epoch !== input.current_mls_epoch
    ? "mls-epoch"
    : input.size_bytes >= input.max_size_bytes
      ? "size"
      : null;
  if (reason === null) {
    return accepted({ active_rid: input.active_rid, overlap_rid: null, rotation_reason: null });
  }
  return accepted({
    active_rid: input.next_rid,
    overlap_rid: input.active_rid,
    rotation_reason: reason,
  });
}

export function eventsAreByteIdentical(events: string[]): WorkspaceVerdict {
  if (events.length === 0 || events.some((event) => event !== events[0])) {
    return rejected("workspace_signature_invalid");
  }
  return accepted({ byte_length: new TextEncoder().encode(events[0]).length });
}

export function evaluateWorkspacePrivateRelay(value: unknown): WorkspaceVerdict {
  const input = snapshotJsonRecord(value);
  if (input === null
    || !hasExactMembers(input, [
      "workspace_key",
      "private_rid",
      "role_authorized",
      "governance_requested",
      "seed_admission",
    ])
    || typeof input.workspace_key !== "string"
    || typeof input.private_rid !== "string"
    || typeof input.role_authorized !== "boolean"
    || typeof input.governance_requested !== "boolean"
    || !isRecord(input.seed_admission)) {
    return rejected("workspace_schema_invalid");
  }
  if (!input.role_authorized || input.governance_requested) return rejected("policy_denied");
  if (input.seed_admission.expected_administrator_account !== input.workspace_key
    || input.seed_admission.private_rid !== input.private_rid) {
    return rejected("host_unauthorized");
  }
  const admission = evaluateTrustedSeedAdmission(input.seed_admission);
  if (admission.verdict !== "accept") return rejected("host_unauthorized");
  return accepted({
    acl_digest: admission.acl_digest,
    private_rid: input.private_rid,
    seed_nid: admission.seed_nid,
    ...(admission.writer_ref === undefined ? {} : { writer_ref: admission.writer_ref }),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function snapshotJsonRecord(value: unknown): Record<string, unknown> | null {
  try {
    const snapshot = JSON.parse(jcsCanonicalize(value)) as unknown;
    return isRecord(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}

function hasExactMembers(value: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === members.length && members.every((member) => Object.hasOwn(value, member));
}
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { Ajv } from "ajv";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import { evaluateTrustedSeedAdmission } from "./trusted-seed.js";
import { WORKSPACE_SCHEMAS } from "./workspace-schemas.js";
