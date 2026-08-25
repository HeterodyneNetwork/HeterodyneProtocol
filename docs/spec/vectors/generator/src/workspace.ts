export type WorkspaceVerdict =
  | { verdict: "accept"; normalized: Record<string, unknown> }
  | { verdict: "reject"; reason_code: string };

const accepted = (normalized: Record<string, unknown>): WorkspaceVerdict => {
  const snapshot = snapshotJsonRecord(normalized);
  if (snapshot === null) throw new Error("invalid internal Workspace normalization");
  return { verdict: "accept", normalized: snapshot };
};
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

const H64_PATTERN = /^[0-9a-f]{64}$/;
const H40_PATTERN = /^[0-9a-f]{40}$/;
const RADICLE_RID_PATTERN = /^rad:[A-Za-z0-9]+$/;
const CAPABILITY_VALUES = new Set([
  "read", "write", "triage", "moderate", "admin", "invite",
  "govern-policy", "govern-subroles", "govern-thresholds",
  "govern-publicize", "govern-federation", "govern-delegation",
  "govern-lifecycle",
]);

type Validation<T> =
  | { ok: true; value: T }
  | { ok: false; reason_code: string };

declare const effectiveAuthorizationBrand: unique symbol;
type EffectiveAuthorization = Readonly<{
  actor_account: string;
  workspace_key: string;
  policy_head: string;
  predecessor: string | null;
  authority_checkpoint: string;
  operation_digest: string;
  effective_capabilities: readonly string[];
  effective_resources: readonly string[];
  effective_delegable: boolean;
  effective_approver_keys: readonly string[];
  [effectiveAuthorizationBrand]: true;
}>;
const effectiveAuthorizationResults = new WeakSet<object>();

declare const currentWorkspaceObjectBrand: unique symbol;
type CurrentWorkspaceObject = Readonly<{
  object: Readonly<Record<string, unknown>>;
  object_id: string;
  [currentWorkspaceObjectBrand]: true;
}>;
const currentWorkspaceObjects = new WeakSet<object>();

declare const currentRelationshipBrand: unique symbol;
type CurrentRelationship = Readonly<{
  relationship: Readonly<Record<string, unknown>>;
  source_current: CurrentWorkspaceState;
  receiving_current: CurrentWorkspaceState;
  [currentRelationshipBrand]: true;
}>;
const currentRelationships = new WeakSet<object>();

const isH64 = (value: unknown): value is string =>
  typeof value === "string" && H64_PATTERN.test(value);
const isH40 = (value: unknown): value is string =>
  typeof value === "string" && H40_PATTERN.test(value);
const isRadicleRid = (value: unknown): value is string =>
  typeof value === "string" && RADICLE_RID_PATTERN.test(value);
const isSafeNonNegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;
const isUniqueStringArray = (
  value: unknown,
  member: (candidate: unknown) => candidate is string,
): value is string[] => Array.isArray(value)
  && value.every(member)
  && new Set(value).size === value.length;
const isCapabilityArray = (value: unknown): value is string[] =>
  isUniqueStringArray(value, (candidate): candidate is string =>
    typeof candidate === "string" && CAPABILITY_VALUES.has(candidate));
const isH64Array = (value: unknown): value is string[] =>
  isUniqueStringArray(value, isH64);
const isH40Array = (value: unknown): value is string[] =>
  isUniqueStringArray(value, isH40);
const exactStringSet = (left: readonly string[], right: readonly string[]): boolean =>
  left.length === right.length && [...left].sort().every((value, index) =>
    value === [...right].sort()[index]);

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

export function evaluateWorkspaceObject(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "object",
    "expected_object_id",
    "current",
  ])
    || !isRecord(snapshot.object)
    || !isH64(snapshot.expected_object_id)
    || !isRecord(snapshot.current)) return rejected("workspace_schema_invalid");
  const currentObject = validateCurrentWorkspaceObjectSnapshot(
    snapshot.object,
    snapshot.current,
    snapshot.expected_object_id,
  );
  if (!currentObject.ok) return rejected(currentObject.reason_code);
  if (!currentWorkspaceObjects.has(currentObject.value)) {
    return rejected("workspace_schema_invalid");
  }
  return accepted({
    object_id: currentObject.value.object_id,
    object_type: currentObject.value.object.object_type,
    workspace_key: currentObject.value.object.workspace_key,
  });
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

type CurrentWorkspaceState = Readonly<{
  workspace_key: string;
  policy_head: string;
  predecessor: string | null;
  authority_checkpoint: string;
  repository_rid: string;
  repository_head: string;
  repository_ancestry: readonly string[];
  authority_checkpoint_candidates: readonly string[];
  competing_repository_heads: readonly string[];
}>;

function validateCurrentWorkspaceStateSnapshot(value: unknown): Validation<CurrentWorkspaceState> {
  if (!isRecord(value) || !hasExactMembers(value, [
    "workspace_key",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "repository_rid",
    "repository_head",
    "repository_ancestry",
    "authority_checkpoint_candidates",
    "competing_repository_heads",
  ])
    || !isH64(value.workspace_key)
    || !isH64(value.policy_head)
    || !(value.predecessor === null || isH64(value.predecessor))
    || !isH64(value.authority_checkpoint)
    || !isRadicleRid(value.repository_rid)
    || !isH40(value.repository_head)
    || !isH40Array(value.repository_ancestry)
    || value.repository_ancestry.length === 0
    || value.repository_ancestry[0] !== value.repository_head
    || !isH64Array(value.authority_checkpoint_candidates)
    || !isH40Array(value.competing_repository_heads)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  if (value.authority_checkpoint_candidates.length !== 1
    || value.authority_checkpoint_candidates[0] !== value.authority_checkpoint
    || value.competing_repository_heads.length !== 0) {
    return { ok: false, reason_code: "authority_conflict" };
  }
  return { ok: true, value: value as unknown as CurrentWorkspaceState };
}

function validateCurrentWorkspaceObjectSnapshot(
  objectValue: unknown,
  currentValue: unknown,
  expectedObjectId: string | null,
): Validation<CurrentWorkspaceObject> {
  if (!isRecord(objectValue)) return { ok: false, reason_code: "workspace_schema_invalid" };
  const current = validateCurrentWorkspaceStateSnapshot(currentValue);
  if (!current.ok) return current;
  const objectType = objectValue.object_type;
  if (typeof objectType !== "string" || WORKSPACE_SCHEMAS[objectType] === undefined) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  const validate = new Ajv({ allErrors: true, strict: false }).compile(WORKSPACE_SCHEMAS[objectType]);
  if (!validate(objectValue) || !isSafeNonNegativeInteger(objectValue.issued_at)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  if (objectValue.workspace_key !== current.value.workspace_key
    || objectValue.policy_head !== current.value.policy_head
    || objectValue.predecessor !== current.value.predecessor
    || objectValue.authority_checkpoint !== current.value.authority_checkpoint
    || objectValue.repository_rid !== current.value.repository_rid
    || objectValue.repository_head !== current.value.repository_head
    || typeof objectValue.signature !== "string"
    || !validWorkspaceSignature(objectValue, current.value.workspace_key, objectValue.signature)) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  const objectId = workspaceObjectId(objectValue);
  if (expectedObjectId !== null && (!isH64(expectedObjectId) || objectId !== expectedObjectId)) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  const result = deepFreeze({ object: objectValue, object_id: objectId }) as CurrentWorkspaceObject;
  currentWorkspaceObjects.add(result);
  return { ok: true, value: result };
}

function validateEffectiveAuthorizationSnapshot(value: unknown): Validation<EffectiveAuthorization> {
  if (!isRecord(value) || !hasExactMembers(value, [
    "workspace_key",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "authority_checkpoint_candidates",
    "actor_account",
    "operation_digest",
    "requested_capabilities",
    "capability_ceilings",
    "requested_resources",
    "resource_ceilings",
    "requested_delegable",
    "delegable_ceilings",
    "approval_key_ceilings",
    "device_active",
    "denial_ids",
    "revocation_effective_at",
    "authority_source",
    "now",
  ])
    || !isH64(value.workspace_key)
    || !isH64(value.policy_head)
    || !(value.predecessor === null || isH64(value.predecessor))
    || !isH64(value.authority_checkpoint)
    || !isH64Array(value.authority_checkpoint_candidates)
    || !isH64(value.actor_account)
    || !isH64(value.operation_digest)
    || !isCapabilityArray(value.requested_capabilities)
    || !Array.isArray(value.capability_ceilings)
    || value.capability_ceilings.length === 0
    || !value.capability_ceilings.every(isCapabilityArray)
    || !isH64Array(value.requested_resources)
    || !Array.isArray(value.resource_ceilings)
    || value.resource_ceilings.length === 0
    || !value.resource_ceilings.every(isH64Array)
    || typeof value.requested_delegable !== "boolean"
    || !Array.isArray(value.delegable_ceilings)
    || value.delegable_ceilings.length === 0
    || !value.delegable_ceilings.every((candidate) => typeof candidate === "boolean")
    || !Array.isArray(value.approval_key_ceilings)
    || value.approval_key_ceilings.length === 0
    || !value.approval_key_ceilings.every(isH64Array)
    || typeof value.device_active !== "boolean"
    || !isH64Array(value.denial_ids)
    || !Array.isArray(value.revocation_effective_at)
    || !value.revocation_effective_at.every(isSafeNonNegativeInteger)
    || typeof value.authority_source !== "string"
    || !isSafeNonNegativeInteger(value.now)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  if (value.authority_checkpoint_candidates.length !== 1
    || value.authority_checkpoint_candidates[0] !== value.authority_checkpoint) {
    return { ok: false, reason_code: "authority_conflict" };
  }
  if (value.authority_source !== "workspace-policy") {
    return { ok: false, reason_code: "policy_denied" };
  }
  if (!value.device_active) return { ok: false, reason_code: "device_revoked" };
  if (value.denial_ids.length > 0
    || value.revocation_effective_at.some((effectiveAt) => effectiveAt <= (value.now as number))) {
    return { ok: false, reason_code: "policy_denied" };
  }
  const effectiveCapabilities = intersection(value.capability_ceilings);
  const effectiveResources = intersection(value.resource_ceilings);
  const effectiveDelegable = value.delegable_ceilings.every((ceiling) => ceiling);
  const effectiveApproverKeys = intersection(value.approval_key_ceilings);
  if (!subset(value.requested_capabilities, effectiveCapabilities)
    || !subset(value.requested_resources, effectiveResources)
    || (value.requested_delegable && !effectiveDelegable)) {
    return { ok: false, reason_code: "capability_escalation" };
  }
  const result = deepFreeze({
    actor_account: value.actor_account,
    workspace_key: value.workspace_key,
    policy_head: value.policy_head,
    predecessor: value.predecessor,
    authority_checkpoint: value.authority_checkpoint,
    operation_digest: value.operation_digest,
    effective_capabilities: effectiveCapabilities,
    effective_resources: effectiveResources,
    effective_delegable: effectiveDelegable,
    effective_approver_keys: effectiveApproverKeys,
  }) as unknown as EffectiveAuthorization;
  effectiveAuthorizationResults.add(result);
  return { ok: true, value: result };
}

function grantOperationDigestSnapshot(grant: Readonly<Record<string, unknown>>): string {
  const operation = { ...grant };
  delete operation.signature;
  delete operation.approval_ids;
  return bytesToHex(sha256(proofBytes("heterodyne-workspace-grant-operation-v1", operation)));
}

function validateGrantApprovalSnapshot(
  value: unknown,
  expected: {
    workspace_key: string;
    policy_head: string;
    predecessor: string | null;
    authority_checkpoint: string;
    operation_digest: string;
    now: number;
  },
): Validation<Readonly<{ approver_key: string; approval_id: string }>> {
  if (!isRecord(value) || !hasExactMembers(value, [
    "profile",
    "spec_version",
    "workspace_key",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "operation_digest",
    "approver_key",
    "issued_at",
    "expires_at",
    "signature",
  ])
    || value.profile !== "heterodyne.workspace-grant-approval.v1"
    || value.spec_version !== "heterodyne/0.5.0"
    || !isH64(value.workspace_key)
    || !isH64(value.policy_head)
    || !(value.predecessor === null || isH64(value.predecessor))
    || !isH64(value.authority_checkpoint)
    || !isH64(value.operation_digest)
    || !isH64(value.approver_key)
    || !isSafeNonNegativeInteger(value.issued_at)
    || !isSafeNonNegativeInteger(value.expires_at)
    || value.issued_at >= value.expires_at
    || typeof value.signature !== "string"
    || !/^[0-9a-f]{128}$/.test(value.signature)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  if (value.workspace_key !== expected.workspace_key
    || value.policy_head !== expected.policy_head
    || value.predecessor !== expected.predecessor
    || value.authority_checkpoint !== expected.authority_checkpoint
    || value.operation_digest !== expected.operation_digest
    || value.issued_at > expected.now
    || expected.now >= value.expires_at) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  const unsigned = { ...value };
  delete unsigned.signature;
  if (!validRawSignature(
    value.signature,
    proofBytes("heterodyne-workspace-grant-approval-v1", unsigned),
    value.approver_key,
  )) return { ok: false, reason_code: "workspace_signature_invalid" };
  return {
    ok: true,
    value: deepFreeze({ approver_key: value.approver_key, approval_id: workspaceObjectId(value) }),
  };
}

function validRawSignature(signature: string, payload: Uint8Array, key: string): boolean {
  try {
    return schnorr.verify(signature, payload, key);
  } catch {
    return false;
  }
}

export function evaluateAuthorization(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null) return rejected("workspace_schema_invalid");
  const authorization = validateEffectiveAuthorizationSnapshot(snapshot);
  if (!authorization.ok) return rejected(authorization.reason_code);
  return accepted({
    actor_account: authorization.value.actor_account,
    authority_checkpoint: authorization.value.authority_checkpoint,
    effective_capabilities: [...authorization.value.effective_capabilities],
    effective_delegable: authorization.value.effective_delegable,
    effective_approver_keys: [...authorization.value.effective_approver_keys],
    effective_resources: [...authorization.value.effective_resources],
    operation_digest: authorization.value.operation_digest,
    policy_head: authorization.value.policy_head,
    predecessor: authorization.value.predecessor,
    workspace_key: authorization.value.workspace_key,
  });
}

export function evaluateGrantActivation(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "grant",
    "current",
    "authorization",
    "membership",
    "required_approvals",
    "approvals",
    "subject_acceptance_id",
    "consumed_invitation_grant_ids",
    "now",
  ])) return rejected("workspace_schema_invalid");
  if (!isRecord(snapshot.grant)
    || !isRecord(snapshot.current)
    || !isRecord(snapshot.authorization)
    || !isRecord(snapshot.membership)
    || !Array.isArray(snapshot.approvals)
    || !isSafeNonNegativeInteger(snapshot.required_approvals)
    || !(snapshot.subject_acceptance_id === null || isH64(snapshot.subject_acceptance_id))
    || !isH64Array(snapshot.consumed_invitation_grant_ids)
    || !isSafeNonNegativeInteger(snapshot.now)) return rejected("workspace_schema_invalid");

  const currentGrant = validateCurrentWorkspaceObjectSnapshot(
    snapshot.grant,
    snapshot.current,
    null,
  );
  if (!currentGrant.ok) return rejected(currentGrant.reason_code);
  if (!currentWorkspaceObjects.has(currentGrant.value)
    || currentGrant.value.object.object_type !== "role-grant-v1") {
    return rejected("workspace_schema_invalid");
  }
  const grant = currentGrant.value.object;
  const authorization = validateEffectiveAuthorizationSnapshot(snapshot.authorization);
  if (!authorization.ok) return rejected(authorization.reason_code);
  if (!effectiveAuthorizationResults.has(authorization.value)) {
    return rejected("workspace_schema_invalid");
  }
  const operationDigest = grantOperationDigestSnapshot(grant);
  if (authorization.value.workspace_key !== grant.workspace_key
    || authorization.value.policy_head !== grant.policy_head
    || authorization.value.predecessor !== grant.predecessor
    || authorization.value.authority_checkpoint !== grant.authority_checkpoint
    || authorization.value.operation_digest !== operationDigest) {
    return rejected("workspace_signature_invalid");
  }
  if (!hasExactMembers(snapshot.membership, [
    "authenticated_account",
    "accepted_device",
    "accepted_leaf",
    "successor_reauthorization_id",
  ])
    || !isH64(snapshot.membership.authenticated_account)
    || !isH64(snapshot.membership.accepted_device)
    || typeof snapshot.membership.accepted_leaf !== "string"
    || !isCanonicalMarmotLeaf(snapshot.membership.accepted_leaf)
    || !isH64(snapshot.membership.successor_reauthorization_id)) {
    return rejected("workspace_schema_invalid");
  }
  if (grant.subject_account !== snapshot.membership.authenticated_account) {
    return rejected("policy_denied");
  }
  if (grant.target_device !== snapshot.membership.accepted_device
    || !isRecord(grant.recipient)
    || grant.recipient.value !== snapshot.membership.accepted_leaf) {
    return rejected("device_revoked");
  }
  if (!isH64(grant.grant_id)
    || !isCapabilityArray(grant.capabilities)
    || !isH64Array(grant.resource_scope)
    || typeof grant.delegable !== "boolean"
    || !isSafeNonNegativeInteger(grant.issued_at)
    || !isSafeNonNegativeInteger(grant.activates_at)
    || !(grant.expires_at === null || isSafeNonNegativeInteger(grant.expires_at))
    || grant.issued_at > grant.activates_at
    || snapshot.now < grant.activates_at
    || (grant.expires_at !== null && snapshot.now >= grant.expires_at)
    || !isH64Array(grant.approval_ids)) return rejected("workspace_schema_invalid");
  if (snapshot.consumed_invitation_grant_ids.includes(grant.grant_id)) {
    return rejected("workspace_replay");
  }
  if (grant.activation === "subject-acceptance" && snapshot.subject_acceptance_id === null) {
    return rejected("policy_denied");
  }
  if (grant.invitation !== null) {
    if (!isRecord(grant.invitation)
      || !isSafeNonNegativeInteger(grant.invitation.expires_at)
      || snapshot.now >= grant.invitation.expires_at) return rejected("policy_denied");
  }
  if (!authorization.value.effective_capabilities.includes("invite")
    || !subset(grant.capabilities, authorization.value.effective_capabilities)
    || !subset(grant.resource_scope, authorization.value.effective_resources)
    || (grant.delegable && (!authorization.value.effective_delegable
      || !authorization.value.effective_capabilities.includes("govern-delegation")))
    || grant.capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejected("capability_escalation");
  }
  const approvals: Array<Readonly<{ approver_key: string; approval_id: string }>> = [];
  for (const candidate of snapshot.approvals) {
    const approval = validateGrantApprovalSnapshot(candidate, {
      workspace_key: String(grant.workspace_key),
      policy_head: String(grant.policy_head),
      predecessor: grant.predecessor as string | null,
      authority_checkpoint: String(grant.authority_checkpoint),
      operation_digest: operationDigest,
      now: snapshot.now,
    });
    if (!approval.ok) return rejected(approval.reason_code);
    approvals.push(approval.value);
  }
  const approvalIds = approvals.map(({ approval_id }) => approval_id);
  const approverKeys = approvals.map(({ approver_key }) => approver_key);
  if (!exactStringSet(approvalIds, grant.approval_ids)
    || new Set(approvalIds).size !== approvalIds.length
    || new Set(approverKeys).size !== approverKeys.length
    || !subset(approverKeys, authorization.value.effective_approver_keys)
    || approvals.length < snapshot.required_approvals) {
    return rejected("policy_denied");
  }
  return accepted({
    active: true,
    approval_count: approvals.length,
    approver_keys: [...approverKeys].sort(),
    grant_id: grant.grant_id,
    operation_digest: operationDigest,
  });
}

function validateCurrentRelationshipSnapshot(
  relationshipValue: unknown,
  expectedObjectId: string,
  sourceCurrentValue: unknown,
  receivingCurrentValue: unknown,
): Validation<CurrentRelationship> {
  const sourceCurrent = validateCurrentWorkspaceStateSnapshot(sourceCurrentValue);
  if (!sourceCurrent.ok) return sourceCurrent;
  const receivingCurrent = validateCurrentWorkspaceStateSnapshot(receivingCurrentValue);
  if (!receivingCurrent.ok) return receivingCurrent;
  const currentObject = validateCurrentWorkspaceObjectSnapshot(
    relationshipValue,
    sourceCurrent.value,
    expectedObjectId,
  );
  if (!currentObject.ok) return currentObject;
  const relationship = currentObject.value.object;
  if (!currentWorkspaceObjects.has(currentObject.value)
    || relationship.object_type !== "workspace-relationship-v1"
    || relationship.source_workspace_key !== sourceCurrent.value.workspace_key
    || relationship.receiving_workspace_key !== receivingCurrent.value.workspace_key
    || relationship.receiving_policy_head !== receivingCurrent.value.policy_head
    || relationship.receiving_predecessor !== receivingCurrent.value.predecessor
    || relationship.receiving_authority_checkpoint !== receivingCurrent.value.authority_checkpoint
    || typeof relationship.receiving_signature !== "string"
    || !validWorkspaceSignature(
      relationship,
      receivingCurrent.value.workspace_key,
      relationship.receiving_signature,
    )) return { ok: false, reason_code: "workspace_signature_invalid" };
  const result = deepFreeze({
    relationship,
    source_current: sourceCurrent.value,
    receiving_current: receivingCurrent.value,
  }) as CurrentRelationship;
  currentRelationships.add(result);
  return { ok: true, value: result };
}

function validateAffiliationEvidenceSnapshot(
  value: unknown,
  relationship: CurrentRelationship,
  expectedSourceAccount: string,
  now: number,
): Validation<Readonly<{ source_account: string; observed_at: number }>> {
  if (!isRecord(value) || !hasExactMembers(value, [
    "profile",
    "spec_version",
    "relationship_id",
    "source_workspace_key",
    "source_role_id",
    "source_account",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "repository_rid",
    "repository_head",
    "observed_at",
    "expires_at",
    "signature",
  ])
    || value.profile !== "heterodyne.workspace-affiliation-evidence.v1"
    || value.spec_version !== "heterodyne/0.5.0"
    || !isH64(value.relationship_id)
    || !isH64(value.source_workspace_key)
    || !isH64(value.source_role_id)
    || !isH64(value.source_account)
    || !isH64(value.policy_head)
    || !(value.predecessor === null || isH64(value.predecessor))
    || !isH64(value.authority_checkpoint)
    || !isRadicleRid(value.repository_rid)
    || !isH40(value.repository_head)
    || !isSafeNonNegativeInteger(value.observed_at)
    || !isSafeNonNegativeInteger(value.expires_at)
    || value.observed_at >= value.expires_at
    || typeof value.signature !== "string"
    || !/^[0-9a-f]{128}$/.test(value.signature)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  const object = relationship.relationship;
  if (value.relationship_id !== object.relationship_id
    || value.source_workspace_key !== relationship.source_current.workspace_key
    || value.source_role_id !== object.source_role_id
    || value.source_account !== expectedSourceAccount
    || value.policy_head !== relationship.source_current.policy_head
    || value.predecessor !== relationship.source_current.predecessor
    || value.authority_checkpoint !== relationship.source_current.authority_checkpoint
    || value.repository_rid !== relationship.source_current.repository_rid) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  if (value.repository_head !== relationship.source_current.repository_head
    || !relationship.source_current.repository_ancestry.includes(value.repository_head)) {
    return { ok: false, reason_code: "authority_conflict" };
  }
  if (value.observed_at > now || now >= value.expires_at
    || !isSafeNonNegativeInteger(object.issued_at)
    || value.observed_at < object.issued_at) {
    return { ok: false, reason_code: "affiliation_stale" };
  }
  const unsigned = { ...value };
  delete unsigned.signature;
  if (!validRawSignature(
    value.signature,
    proofBytes("heterodyne-workspace-affiliation-evidence-v1", unsigned),
    relationship.source_current.workspace_key,
  )) return { ok: false, reason_code: "workspace_signature_invalid" };
  return {
    ok: true,
    value: deepFreeze({ source_account: value.source_account, observed_at: value.observed_at }),
  };
}

export function evaluateAllowance(value: unknown): WorkspaceVerdict {
  const input = snapshotJsonRecord(value);
  if (input === null || !hasExactMembers(input, [
    "relationship",
    "expected_relationship_object_id",
    "source_current",
    "receiving_current",
    "affiliation",
    "expected_source_account",
    "requested_capabilities",
    "revocation_effective_at",
    "now",
  ])
    || !isRecord(input.relationship)
    || !isH64(input.expected_relationship_object_id)
    || !isRecord(input.source_current)
    || !isRecord(input.receiving_current)
    || !isRecord(input.affiliation)
    || !isH64(input.expected_source_account)
    || !isCapabilityArray(input.requested_capabilities)
    || !(input.revocation_effective_at === null
      || isSafeNonNegativeInteger(input.revocation_effective_at))
    || !isSafeNonNegativeInteger(input.now)) return rejected("workspace_schema_invalid");
  const relationship = validateCurrentRelationshipSnapshot(
    input.relationship,
    input.expected_relationship_object_id,
    input.source_current,
    input.receiving_current,
  );
  if (!relationship.ok) return rejected(relationship.reason_code);
  if (!currentRelationships.has(relationship.value)) return rejected("workspace_schema_invalid");
  const affiliation = validateAffiliationEvidenceSnapshot(
    input.affiliation,
    relationship.value,
    input.expected_source_account,
    input.now,
  );
  if (!affiliation.ok) return rejected(affiliation.reason_code);
  const object = relationship.value.relationship;
  if (!isSafeNonNegativeInteger(object.expires_at)
    || !isSafeNonNegativeInteger(object.proof_max_age)
    || !isSafeNonNegativeInteger(object.grace_period)) {
    return rejected("workspace_schema_invalid");
  }
  if (input.now >= object.expires_at
    || (input.revocation_effective_at !== null
      && input.now >= input.revocation_effective_at)) {
    return rejected("policy_denied");
  }
  if (!isCapabilityArray(object.capability_ceiling)
    || !subset(input.requested_capabilities, object.capability_ceiling)
    || input.requested_capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejected("capability_escalation");
  }
  const proofAge = input.now - affiliation.value.observed_at;
  if (!isSafeNonNegativeInteger(proofAge)) return rejected("workspace_schema_invalid");
  const maximumAge = object.proof_max_age + object.grace_period;
  if (!Number.isSafeInteger(maximumAge)) return rejected("workspace_schema_invalid");
  if (proofAge > maximumAge) return rejected("affiliation_stale");
  return accepted({
    capabilities: [...input.requested_capabilities].sort(),
    proof_age: proofAge,
    provisional_grace: proofAge > object.proof_max_age,
    relationship_id: object.relationship_id,
    source_account: affiliation.value.source_account,
  });
}

export function evaluatePrivateProjection(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "private_identifiers",
    "private_counts",
    "encrypted_placeholders",
  ])
    || !isUniqueStringArray(snapshot.private_identifiers, (candidate): candidate is string =>
      typeof candidate === "string")
    || !isSafeNonNegativeInteger(snapshot.private_counts)
    || !isSafeNonNegativeInteger(snapshot.encrypted_placeholders)) {
    return rejected("workspace_schema_invalid");
  }
  const disclosed = snapshot.private_identifiers.length
    + snapshot.private_counts
    + snapshot.encrypted_placeholders;
  if (!Number.isSafeInteger(disclosed)) return rejected("workspace_schema_invalid");
  return disclosed === 0
    ? accepted({ disclosed_private_references: 0 })
    : rejected("private_topology_disclosed");
}

function jointOperationDigestSnapshot(
  joint: Readonly<Record<string, unknown>>,
  resourceScope: readonly string[],
): string {
  return bytesToHex(sha256(proofBytes("heterodyne-workspace-joint-operation-v1", {
    relationship_id: joint.relationship_id,
    workspace_key: joint.workspace_key,
    policy_head: joint.policy_head,
    predecessor: joint.predecessor,
    authority_checkpoint: joint.authority_checkpoint,
    resource_scope: resourceScope,
  })));
}

function validateJointDelegateProofSnapshot(
  value: unknown,
  expected: {
    joint_workspace_key: string;
    relationship_id: string;
    policy_head: string;
    predecessor: string | null;
    authority_checkpoint: string;
    operation_digest: string;
    resource_scope: readonly string[];
    now: number;
  },
): Validation<Readonly<{ delegate_key: string }>> {
  if (!isRecord(value) || !hasExactMembers(value, [
    "profile",
    "spec_version",
    "joint_workspace_key",
    "relationship_id",
    "delegate_key",
    "policy_head",
    "predecessor",
    "authority_checkpoint",
    "operation_digest",
    "resource_scope",
    "issued_at",
    "expires_at",
    "signature",
  ])
    || value.profile !== "heterodyne.workspace-joint-delegate.v1"
    || value.spec_version !== "heterodyne/0.5.0"
    || !isH64(value.joint_workspace_key)
    || !isH64(value.relationship_id)
    || !isH64(value.delegate_key)
    || !isH64(value.policy_head)
    || !(value.predecessor === null || isH64(value.predecessor))
    || !isH64(value.authority_checkpoint)
    || !isH64(value.operation_digest)
    || !isH64Array(value.resource_scope)
    || !isSafeNonNegativeInteger(value.issued_at)
    || !isSafeNonNegativeInteger(value.expires_at)
    || value.issued_at >= value.expires_at
    || typeof value.signature !== "string"
    || !/^[0-9a-f]{128}$/.test(value.signature)) {
    return { ok: false, reason_code: "workspace_schema_invalid" };
  }
  if (value.joint_workspace_key !== expected.joint_workspace_key
    || value.relationship_id !== expected.relationship_id
    || value.policy_head !== expected.policy_head
    || value.predecessor !== expected.predecessor
    || value.authority_checkpoint !== expected.authority_checkpoint
    || value.operation_digest !== expected.operation_digest
    || !exactStringSet(value.resource_scope, expected.resource_scope)
    || value.issued_at > expected.now
    || expected.now >= value.expires_at) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  const unsigned = { ...value };
  delete unsigned.signature;
  if (!validRawSignature(
    value.signature,
    proofBytes("heterodyne-workspace-joint-delegate-v1", unsigned),
    value.delegate_key,
  )) return { ok: false, reason_code: "workspace_signature_invalid" };
  return { ok: true, value: deepFreeze({ delegate_key: value.delegate_key }) };
}

export function evaluateJointGovernance(value: unknown): WorkspaceVerdict {
  const input = snapshotJsonRecord(value);
  if (input === null || !hasExactMembers(input, [
    "joint",
    "expected_joint_object_id",
    "current",
    "configured_delegate_keys",
    "resource_scope",
    "delegate_proofs",
    "now",
  ])
    || !isRecord(input.joint)
    || !isH64(input.expected_joint_object_id)
    || !isRecord(input.current)
    || !isH64Array(input.configured_delegate_keys)
    || !isH64Array(input.resource_scope)
    || input.resource_scope.length === 0
    || !Array.isArray(input.delegate_proofs)
    || !isSafeNonNegativeInteger(input.now)) return rejected("workspace_schema_invalid");
  const currentJoint = validateCurrentWorkspaceObjectSnapshot(
    input.joint,
    input.current,
    input.expected_joint_object_id,
  );
  if (!currentJoint.ok) return rejected(currentJoint.reason_code);
  const joint = currentJoint.value.object;
  if (!currentWorkspaceObjects.has(currentJoint.value)
    || joint.object_type !== "joint-workspace-relationship-v1") {
    return rejected("workspace_schema_invalid");
  }
  if (joint.workspace_key !== joint.joint_workspace_key) {
    return rejected("workspace_signature_invalid");
  }
  if (!isH64(joint.relationship_id)
    || !isH64Array(joint.delegate_keys)
    || !isH64Array(joint.resource_scope)
    || !isSafeNonNegativeInteger(joint.threshold)
    || joint.threshold < 1
    || joint.threshold > joint.delegate_keys.length
    || !isSafeNonNegativeInteger(joint.effective_at)
    || !(joint.expires_at === null || isSafeNonNegativeInteger(joint.expires_at))
    || input.now < joint.effective_at
    || (joint.expires_at !== null && input.now >= joint.expires_at)) {
    return rejected("workspace_schema_invalid");
  }
  if (!exactStringSet(input.configured_delegate_keys, joint.delegate_keys)) {
    return rejected("policy_denied");
  }
  if (!subset(input.resource_scope, joint.resource_scope)) {
    return rejected("capability_escalation");
  }
  const operationDigest = jointOperationDigestSnapshot(joint, input.resource_scope);
  const countedKeys: string[] = [];
  for (const candidate of input.delegate_proofs) {
    const proof = validateJointDelegateProofSnapshot(candidate, {
      joint_workspace_key: String(joint.workspace_key),
      relationship_id: joint.relationship_id,
      policy_head: String(joint.policy_head),
      predecessor: joint.predecessor as string | null,
      authority_checkpoint: String(joint.authority_checkpoint),
      operation_digest: operationDigest,
      resource_scope: input.resource_scope,
      now: input.now,
    });
    if (!proof.ok) return rejected(proof.reason_code);
    if (!input.configured_delegate_keys.includes(proof.value.delegate_key)) {
      return rejected("policy_denied");
    }
    countedKeys.push(proof.value.delegate_key);
  }
  if (new Set(countedKeys).size !== countedKeys.length
    || countedKeys.length < joint.threshold) return rejected("policy_denied");
  return accepted({
    counted_delegate_keys: [...countedKeys].sort(),
    operation_digest: operationDigest,
    relationship_id: joint.relationship_id,
    threshold: joint.threshold,
    threshold_met: true,
  });
}

export type WorkspaceHost = {
  host_id: string;
  priority: number;
  radicle_locators: string[];
  radicle_backed_relay: boolean;
};

function isWorkspaceHost(value: unknown): value is WorkspaceHost {
  return isRecord(value)
    && hasExactMembers(value, [
      "host_id",
      "priority",
      "radicle_locators",
      "radicle_backed_relay",
    ])
    && isH64(value.host_id)
    && isSafeNonNegativeInteger(value.priority)
    && value.priority <= 65_535
    && isUniqueStringArray(value.radicle_locators, isRadicleRid)
    && typeof value.radicle_backed_relay === "boolean";
}

export function resolveEffectiveHosts(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "inherited",
    "mode",
    "configured",
    "last_responsive",
  ])
    || !Array.isArray(snapshot.inherited)
    || !snapshot.inherited.every(isWorkspaceHost)
    || !(snapshot.mode === "default"
      || snapshot.mode === "supplement"
      || snapshot.mode === "replace")
    || !Array.isArray(snapshot.configured)
    || !snapshot.configured.every(isWorkspaceHost)
    || !(snapshot.last_responsive === null || isH64(snapshot.last_responsive))) {
    return rejected("workspace_schema_invalid");
  }
  const input = snapshot as unknown as {
  inherited: WorkspaceHost[];
  mode: "default" | "supplement" | "replace";
  configured: WorkspaceHost[];
  last_responsive: string | null;
  };
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

export function evaluateRoleLeafChange(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "account_removed",
    "removed_device",
    "active_devices",
    "current_epoch",
  ])
    || typeof snapshot.account_removed !== "boolean"
    || !(snapshot.removed_device === null || isH64(snapshot.removed_device))
    || !isH64Array(snapshot.active_devices)
    || !isSafeNonNegativeInteger(snapshot.current_epoch)
    || snapshot.current_epoch === Number.MAX_SAFE_INTEGER) {
    return rejected("workspace_schema_invalid");
  }
  const input = snapshot as unknown as {
    account_removed: boolean;
    removed_device: string | null;
    active_devices: string[];
    current_epoch: number;
  };
  const removed = input.account_removed
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

export function evaluateKeyRequest(value: unknown): WorkspaceVerdict {
  const input = snapshotJsonRecord(value);
  if (input === null || !hasExactMembers(input, [
    "resource_known",
    "host_authorized",
    "device_active",
    "membership_active",
    "checkpoint_age",
    "requested_epoch",
    "current_epoch",
    "admission_epoch",
    "history_mode",
    "selected_epochs",
    "target_device",
    "target_account",
    "authenticated_account",
    "authorized_device",
    "recipient",
    "authorized_recipient",
    "successor_reauthorized",
  ])
    || typeof input.resource_known !== "boolean"
    || typeof input.host_authorized !== "boolean"
    || typeof input.device_active !== "boolean"
    || typeof input.membership_active !== "boolean"
    || !isSafeNonNegativeInteger(input.checkpoint_age)
    || !isSafeNonNegativeInteger(input.requested_epoch)
    || !isSafeNonNegativeInteger(input.current_epoch)
    || !isSafeNonNegativeInteger(input.admission_epoch)
    || input.admission_epoch > input.current_epoch
    || !(input.history_mode === "full"
      || input.history_mode === "from-admission"
      || input.history_mode === "selected-snapshots")
    || !Array.isArray(input.selected_epochs)
    || !input.selected_epochs.every(isSafeNonNegativeInteger)
    || new Set(input.selected_epochs).size !== input.selected_epochs.length
    || input.selected_epochs.some((epoch) => (epoch as number) > (input.current_epoch as number))
    || !isH64(input.target_device)
    || !isH64(input.target_account)
    || !isH64(input.authenticated_account)
    || !isH64(input.authorized_device)
    || typeof input.authorized_recipient !== "string"
    || typeof input.successor_reauthorized !== "boolean"
    || !isRecord(input.recipient)
    || !hasExactMembers(input.recipient, ["type", "value"])) {
    return rejected("workspace_schema_invalid");
  }
  if (!isH64(input.target_device)
    || input.recipient.type !== "marmot-mls-leaf"
    || typeof input.recipient.value !== "string"
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

export function evaluateFreshness(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "operation_class",
    "checkpoint_age",
    "policy_max_age",
  ])
    || !(snapshot.operation_class === "ordinary" || snapshot.operation_class === "authority")
    || !isSafeNonNegativeInteger(snapshot.checkpoint_age)
    || !isSafeNonNegativeInteger(snapshot.policy_max_age)) {
    return rejected("workspace_schema_invalid");
  }
  const input = snapshot as unknown as {
  operation_class: "ordinary" | "authority";
  checkpoint_age: number;
  policy_max_age: number;
  };
  const protocolMaximum = input.operation_class === "ordinary" ? 86_400 : 300;
  if (input.policy_max_age > protocolMaximum) {
    return rejected("workspace_schema_invalid");
  }
  return input.checkpoint_age <= input.policy_max_age
    ? accepted({ maximum_age: input.policy_max_age, age: input.checkpoint_age })
    : rejected("checkpoint_stale");
}

export function selectEventRepository(value: unknown): WorkspaceVerdict {
  const snapshot = snapshotJsonRecord(value);
  if (snapshot === null || !hasExactMembers(snapshot, [
    "active_rid",
    "active_mls_epoch",
    "current_mls_epoch",
    "size_bytes",
    "max_size_bytes",
    "next_rid",
  ])
    || !isRadicleRid(snapshot.active_rid)
    || !isSafeNonNegativeInteger(snapshot.active_mls_epoch)
    || !isSafeNonNegativeInteger(snapshot.current_mls_epoch)
    || snapshot.active_mls_epoch > snapshot.current_mls_epoch
    || !isSafeNonNegativeInteger(snapshot.size_bytes)
    || !isSafeNonNegativeInteger(snapshot.max_size_bytes)
    || snapshot.max_size_bytes === 0
    || !isRadicleRid(snapshot.next_rid)
    || snapshot.next_rid === snapshot.active_rid) {
    return rejected("workspace_schema_invalid");
  }
  const input = snapshot as unknown as {
  active_rid: string;
  active_mls_epoch: number;
  current_mls_epoch: number;
  size_bytes: number;
  max_size_bytes: number;
  next_rid: string;
  };
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

export function eventsAreByteIdentical(value: unknown): WorkspaceVerdict {
  const events = snapshotJsonArray(value);
  if (events === null || !events.every((event) => typeof event === "string")) {
    return rejected("workspace_schema_invalid");
  }
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
    || !isH64(input.workspace_key)
    || !isRadicleRid(input.private_rid)
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

function snapshotJsonRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  try {
    const copy = snapshotJsonValue(value, new Set<object>());
    const snapshot = JSON.parse(jcsCanonicalize(copy)) as unknown;
    return isRecord(snapshot) ? deepFreeze(snapshot) : null;
  } catch {
    return null;
  }
}

function snapshotJsonArray(value: unknown): readonly unknown[] | null {
  try {
    const copy = snapshotJsonValue(value, new Set<object>());
    const snapshot = JSON.parse(jcsCanonicalize(copy)) as unknown;
    return Array.isArray(snapshot) ? deepFreeze(snapshot) : null;
  } catch {
    return null;
  }
}

function snapshotJsonValue(value: unknown, ancestors: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite Workspace number");
    return value;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value) || ancestors.has(value)) {
    throw new Error("non-plain Workspace input");
  }
  ancestors.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) {
      throw new Error("symbol Workspace member");
    }
    if (Array.isArray(value)) {
      if (ownKeys.length !== value.length + 1 || !Object.hasOwn(descriptors, "length")) {
        throw new Error("non-dense Workspace array");
      }
      return Array.from({ length: value.length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new Error("accessor Workspace array member");
        }
        return snapshotJsonValue(descriptor.value, ancestors);
      });
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("non-plain Workspace object");
    }
    const result: Record<string, unknown> = {};
    for (const key of ownKeys as string[]) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("accessor Workspace member");
      }
      result[key] = snapshotJsonValue(descriptor.value, ancestors);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const member of Object.values(value as Record<string, unknown>)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function hasExactMembers(value: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === members.length && members.every((member) => Object.hasOwn(value, member));
}
function hasExactShape(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((member) => Object.hasOwn(value, member))
    && keys.every((member) => allowed.has(member));
}
import { types as utilTypes } from "node:util";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { Ajv } from "ajv";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import { evaluateTrustedSeedAdmission } from "./trusted-seed.js";
import { WORKSPACE_SCHEMAS } from "./workspace-schemas.js";
