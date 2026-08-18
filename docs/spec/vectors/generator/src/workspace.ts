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
  return proofBytes("heterodyne-workspace-object-v1", { object: unsigned });
}

export function workspaceObjectId(object: Record<string, unknown>): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(object))));
}

export function signWorkspaceObject(
  object: Record<string, unknown>,
  secretKey: string,
  auxRand = "00".repeat(32),
): Record<string, unknown> {
  const actor = bytesToHex(schnorr.getPublicKey(hexToBytes(secretKey)));
  const unsigned = { ...object, actor };
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
  keri_authoritative: boolean;
  repository_reachable: boolean;
}): WorkspaceVerdict {
  const objectType = input.object.object_type;
  if (typeof objectType !== "string" || WORKSPACE_SCHEMAS[objectType] === undefined) {
    return rejected("workspace_schema_invalid");
  }
  const validate = new Ajv({ allErrors: true, strict: false }).compile(WORKSPACE_SCHEMAS[objectType]);
  if (!validate(input.object)) return rejected("workspace_schema_invalid");
  const actor = input.object.actor;
  const signatureValue = input.object.signature;
  if (typeof actor !== "string" || typeof signatureValue !== "string"
    || !schnorr.verify(signatureValue, workspaceSigningPayload(input.object), actor)
    || !input.keri_authoritative || !input.repository_reachable) {
    return rejected("workspace_signature_invalid");
  }
  const objectId = workspaceObjectId(input.object);
  if (objectId !== input.expected_object_id) return rejected("workspace_signature_invalid");
  return accepted({ object_id: objectId, object_type: objectType });
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
}): WorkspaceVerdict {
  if (input.authority_conflict) return rejected("authority_conflict");
  if (!input.device_active) return rejected("device_revoked");
  if (input.denied || input.revoked || input.carrier_only_evidence) {
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
}): WorkspaceVerdict {
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
  signatures_match: boolean;
  receiving_policy_allows: boolean;
  revoked: boolean;
  expired: boolean;
  requested_capabilities: string[];
  capability_ceiling: string[];
  proof_age: number;
  proof_max_age: number;
  grace_period: number;
}): WorkspaceVerdict {
  if (!input.signatures_match) return rejected("workspace_signature_invalid");
  if (!input.receiving_policy_allows || input.revoked || input.expired) {
    return rejected("policy_denied");
  }
  if (!subset(input.requested_capabilities, input.capability_ceiling)
    || input.requested_capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejected("capability_escalation");
  }
  if (input.proof_age > input.proof_max_age + input.grace_period) {
    return rejected("affiliation_stale");
  }
  return accepted({
    capabilities: [...input.requested_capabilities].sort(),
    provisional_grace: input.proof_age > input.proof_max_age,
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
  recipient: { type: string; value: string };
}): WorkspaceVerdict {
  if (!/^[0-9a-f]{64}$/.test(input.target_device)
    || input.recipient.type !== "marmot-mls-leaf"
    || !/^[A-Za-z0-9_-]{43}$/.test(input.recipient.value)) {
    return rejected("workspace_schema_invalid");
  }
  if (!input.resource_known) return rejected("resource_unknown");
  if (!input.host_authorized) return rejected("host_unauthorized");
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
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { Ajv } from "ajv";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import { WORKSPACE_SCHEMAS } from "./workspace-schemas.js";
