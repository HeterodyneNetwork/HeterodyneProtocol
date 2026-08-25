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

declare const currentWorkspaceObjectBrand: unique symbol;
type CurrentWorkspaceObject = Readonly<{
  object: Readonly<Record<string, unknown>>;
  object_id: string;
  [currentWorkspaceObjectBrand]: true;
}>;
const currentWorkspaceObjects = new WeakSet<object>();

export type WorkspaceRepositoryTrustAnchor = Readonly<{
  suite: "ed25519" | "bip340";
  public_key: string;
}>;

declare const workspaceRepositoryResolverAuthorityBrand: unique symbol;
export type WorkspaceRepositoryResolverAuthority = Readonly<{
  [workspaceRepositoryResolverAuthorityBrand]: true;
}>;

declare const workspaceCurrentStateBrand: unique symbol;
export type WorkspaceCurrentState = Readonly<{
  [workspaceCurrentStateBrand]: true;
}>;

declare const workspaceEffectiveAuthorizationBrand: unique symbol;
export type WorkspaceEffectiveAuthorization = Readonly<{
  [workspaceEffectiveAuthorizationBrand]: true;
}>;

declare const workspaceCurrentRelationshipBrand: unique symbol;
export type WorkspaceCurrentRelationship = Readonly<{
  [workspaceCurrentRelationshipBrand]: true;
}>;

type WorkspaceResolverConfig = Readonly<{
  trust_anchors: readonly WorkspaceRepositoryTrustAnchor[];
  allowed_policies: readonly string[];
  minimum_version: readonly [number, number, number];
  max_ttl: number;
  max_view_age: number;
  repositories: readonly Readonly<{
    workspace_key: string;
    repository_rid: string;
    pinned_head: string;
  }>[];
  trusted_now: () => number;
  invitation_store: object | null;
  accepted_views: Map<string, Readonly<{
    head: string;
    observed_at: number;
    generation: number;
    state: WorkspaceCurrentState;
    view_id: string;
  }>>;
}>;

type WorkspaceCurrentStateRecord = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  state: CurrentWorkspaceState;
  view_id: string;
  observed_at: number;
  expires_at: number;
  generation: number;
  view_key: string;
  evidence: Readonly<Record<string, unknown>>;
  objects: readonly Readonly<Record<string, unknown>>[];
  policy: Readonly<Record<string, unknown>>;
  role: Readonly<Record<string, unknown>>;
  roles: readonly Readonly<Record<string, unknown>>[];
  grants: readonly Readonly<Record<string, unknown>>[];
  revocations: readonly Readonly<Record<string, unknown>>[];
  resources: readonly Readonly<Record<string, unknown>>[];
  checkpoint: Readonly<Record<string, unknown>>;
  checkpoints: readonly Readonly<Record<string, unknown>>[];
  relationships: readonly Readonly<Record<string, unknown>>[];
  joint_relationships: readonly Readonly<Record<string, unknown>>[];
  envelopes: readonly Readonly<Record<string, unknown>>[];
}>;

const WORKSPACE_RESOLVER_AUTHORITIES = new WeakMap<object, WorkspaceResolverConfig>();
const WORKSPACE_CURRENT_STATES = new WeakMap<object, WorkspaceCurrentStateRecord>();
type WorkspaceEffectiveAuthorizationRecord = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  current_state: WorkspaceCurrentState;
  actor_account: string;
  actor_device: string;
  actor_leaf: string;
  workspace_key: string;
  policy_head: string;
  predecessor: string | null;
  authority_checkpoint: string;
  operation_digest: string;
  requested_capabilities: readonly string[];
  requested_resources: readonly string[];
  requested_delegable: boolean;
  qualifying_grant_id: string;
  qualifying_role_path_ids: readonly string[];
  resolved_at: number;
  effective_capabilities: readonly string[];
  effective_resources: readonly string[];
  effective_delegable: boolean;
  effective_approver_keys: readonly string[];
  required_approvals: number;
}>;
const WORKSPACE_EFFECTIVE_AUTHORIZATIONS = new WeakMap<object, WorkspaceEffectiveAuthorizationRecord>();
type WorkspaceCurrentRelationshipRecord = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  source_state: WorkspaceCurrentState;
  receiving_state: WorkspaceCurrentState;
  relationship: Readonly<Record<string, unknown>>;
}>;
const WORKSPACE_CURRENT_RELATIONSHIPS = new WeakMap<object, WorkspaceCurrentRelationshipRecord>();

type WorkspaceInvitationReservation = {
  binding: string;
  status: "reserved" | "committed";
  holder: WorkspaceInvitationAcceptance;
  expires_at: number;
};
const WORKSPACE_INVITATION_STORES = new WeakMap<object, Map<string, WorkspaceInvitationReservation>>();

export class ReferenceWorkspaceInvitationAcceptanceStore {
  constructor() {
    WORKSPACE_INVITATION_STORES.set(this, new Map());
  }
}

declare const workspaceInvitationAcceptanceBrand: unique symbol;
export type WorkspaceInvitationAcceptance = Readonly<{
  [workspaceInvitationAcceptanceBrand]: true;
}>;
type WorkspaceInvitationAcceptanceRecord = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  current_state: WorkspaceCurrentState;
  grant_id: string;
  acceptance_id: string;
  store: object;
  token: string;
  expires_at: number;
}>;
const WORKSPACE_INVITATION_ACCEPTANCES = new WeakMap<object, WorkspaceInvitationAcceptanceRecord>();

declare const workspaceSuccessorReauthorizationBrand: unique symbol;
export type WorkspaceSuccessorReauthorization = Readonly<{
  [workspaceSuccessorReauthorizationBrand]: true;
}>;
type WorkspaceSuccessorReauthorizationRecord = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  current_state: WorkspaceCurrentState;
  object: Readonly<Record<string, unknown>>;
  prior_account: string;
  prior_device: string;
  prior_leaf: string;
  new_account: string;
  new_device: string;
  new_leaf: string;
  role_id: string;
  resource_id: string | null;
  scope: "role-membership" | "resource-key";
  prior_grant_id: string;
  pending_grant_id: string;
  pending_envelope_id: string | null;
  effective_at: number;
  expires_at: number;
}>;
const WORKSPACE_SUCCESSOR_REAUTHORIZATIONS = new WeakMap<object, WorkspaceSuccessorReauthorizationRecord>();

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
const exactStringArray = (left: readonly string[], right: readonly string[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);
const isByteSortedH64Array = (value: unknown): value is string[] =>
  isH64Array(value) && value.every((candidate, index) =>
    index === 0 || (value[index - 1] as string) < candidate);

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

export function createWorkspaceRepositoryResolverAuthority(
  value: unknown,
): WorkspaceRepositoryResolverAuthority {
  const captured = captureWorkspaceRequest(value, ["trusted_now"], [
    "trust_anchors",
    "allowed_policies",
    "minimum_version",
    "max_ttl",
    "max_view_age",
    "repositories",
  ], ["invitation_store"]);
  const input = captured?.data;
  const trustedNow = captured?.opaque.trusted_now;
  const invitationStore = captured?.opaque.invitation_store;
  const minimumVersion = parseWorkspaceSemver(input?.minimum_version);
  if (input === undefined
    || typeof trustedNow !== "function"
    || !Array.isArray(input.trust_anchors)
    || input.trust_anchors.length === 0
    || !input.trust_anchors.every(isWorkspaceRepositoryTrustAnchor)
    || new Set(input.trust_anchors.map((candidate) => {
      const anchor = candidate as WorkspaceRepositoryTrustAnchor;
      return `${anchor.suite}:${anchor.public_key}`;
    })).size !== input.trust_anchors.length
    || !isUniqueStringArray(input.allowed_policies, (candidate): candidate is string =>
      typeof candidate === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(candidate))
    || input.allowed_policies.length === 0
    || minimumVersion === null
    || !isSafeNonNegativeInteger(input.max_ttl)
    || input.max_ttl < 1
    || !isSafeNonNegativeInteger(input.max_view_age)
    || input.max_view_age < 1
    || !Array.isArray(input.repositories)
    || input.repositories.length === 0
    || !input.repositories.every((candidate) => isRecord(candidate)
      && hasExactMembers(candidate, ["workspace_key", "repository_rid", "pinned_head"])
      && isH64(candidate.workspace_key)
      && isRadicleRid(candidate.repository_rid)
      && isH40(candidate.pinned_head))
    || new Set(input.repositories.map((candidate) => {
      const repository = candidate as Record<string, unknown>;
      return `${repository.workspace_key}:${repository.repository_rid}`;
    })).size !== input.repositories.length
    || (invitationStore !== undefined
      && (invitationStore === null || typeof invitationStore !== "object"
        || !WORKSPACE_INVITATION_STORES.has(invitationStore)))) {
    throw new Error("workspace_repository_invalid");
  }
  const authority = Object.freeze({}) as WorkspaceRepositoryResolverAuthority;
  WORKSPACE_RESOLVER_AUTHORITIES.set(authority, {
    trust_anchors: input.trust_anchors as WorkspaceRepositoryTrustAnchor[],
    allowed_policies: input.allowed_policies,
    minimum_version: minimumVersion,
    max_ttl: input.max_ttl,
    max_view_age: input.max_view_age,
    repositories: input.repositories as WorkspaceResolverConfig["repositories"],
    trusted_now: trustedNow as () => number,
    invitation_store: invitationStore === undefined ? null : invitationStore as object,
    accepted_views: new Map(),
  });
  return authority;
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

export function authenticateWorkspaceRepositoryView(value: unknown):
  | { verdict: "accept"; state: WorkspaceCurrentState }
  | { verdict: "reject"; reason_code: string } {
  const captured = captureWorkspaceRequest(value, ["authority"], ["evidence", "objects"]);
  const authority = captured?.opaque.authority;
  if (captured === null || authority === null || typeof authority !== "object") {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  const config = WORKSPACE_RESOLVER_AUTHORITIES.get(authority);
  const evidence = captured.data.evidence;
  const objects = captured.data.objects;
  if (config === undefined || !isRecord(evidence) || !Array.isArray(objects)
    || !objects.every(isRecord)
    || !hasExactMembers(evidence, [
      "profile",
      "spec_version",
      "resolver_policy",
      "resolver_version",
      "workspace_key",
      "repository_rid",
      "canonical_head",
      "canonical_ancestry",
      "observed_heads",
      "fork_status",
      "policy_head",
      "predecessor",
      "authority_checkpoint",
      "object_ids",
      "object_set_digest",
      "observed_at",
      "expires_at",
      "signature",
    ])
    || evidence.profile !== "heterodyne.workspace-repository-view.v1"
    || evidence.spec_version !== "heterodyne/0.5.0"
    || typeof evidence.resolver_policy !== "string"
    || !config.allowed_policies.includes(evidence.resolver_policy)
    || compareWorkspaceSemver(evidence.resolver_version, config.minimum_version) < 0
    || !isH64(evidence.workspace_key)
    || !isRadicleRid(evidence.repository_rid)
    || !isH40(evidence.canonical_head)
    || !isH40Array(evidence.canonical_ancestry)
    || evidence.canonical_ancestry.length === 0
    || evidence.canonical_ancestry[0] !== evidence.canonical_head
    || !isH40Array(evidence.observed_heads)
    || typeof evidence.fork_status !== "string"
    || !isH64(evidence.policy_head)
    || !(evidence.predecessor === null || isH64(evidence.predecessor))
    || !isH64(evidence.authority_checkpoint)
    || !isByteSortedH64Array(evidence.object_ids)
    || !isH64(evidence.object_set_digest)
    || !isSafeNonNegativeInteger(evidence.observed_at)
    || !isSafeNonNegativeInteger(evidence.expires_at)
    || evidence.observed_at >= evidence.expires_at
    || evidence.expires_at - evidence.observed_at > config.max_ttl
    || typeof evidence.signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(evidence.signature)) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  const unsigned = { ...evidence };
  delete unsigned.signature;
  if (!verifyWorkspaceRepositoryAttestation(
    unsigned,
    evidence.signature,
    config,
  )) return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  if (evidence.fork_status !== "complete"
    || evidence.observed_heads.length !== 1
    || evidence.observed_heads[0] !== evidence.canonical_head) {
    return { verdict: "reject", reason_code: "authority_conflict" };
  }
  const repository = config.repositories.find((candidate) =>
    candidate.workspace_key === evidence.workspace_key
      && candidate.repository_rid === evidence.repository_rid);
  if (repository === undefined
    || !evidence.canonical_ancestry.includes(repository.pinned_head)) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  let now: number;
  try {
    now = config.trusted_now();
  } catch {
    return { verdict: "reject", reason_code: "checkpoint_stale" };
  }
  if (!isSafeNonNegativeInteger(now)
    || now < evidence.observed_at
    || now >= evidence.expires_at
    || now - evidence.observed_at > config.max_view_age) {
    return { verdict: "reject", reason_code: "checkpoint_stale" };
  }
  const objectIdsByIndex = objects.map((candidate) => workspaceObjectId(candidate));
  if (new Set(objectIdsByIndex).size !== objectIdsByIndex.length) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  const actualObjectIds = [...objectIdsByIndex].sort();
  const actualObjectSetDigest = bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-object-set-v1",
    { object_ids: evidence.object_ids },
  )));
  if (!exactStringArray(evidence.object_ids, actualObjectIds)
    || evidence.object_set_digest !== actualObjectSetDigest) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  const viewKey = `${evidence.workspace_key}:${evidence.repository_rid}`;
  const previous = config.accepted_views.get(viewKey);
  if (previous !== undefined
    && (evidence.observed_at < previous.observed_at
      || !evidence.canonical_ancestry.includes(previous.head))) {
    return { verdict: "reject", reason_code: "authority_conflict" };
  }
  const currentState = deepFreeze({
    workspace_key: evidence.workspace_key,
    policy_head: evidence.policy_head,
    predecessor: evidence.predecessor,
    authority_checkpoint: evidence.authority_checkpoint,
    repository_rid: evidence.repository_rid,
    repository_head: evidence.canonical_head,
    repository_ancestry: evidence.canonical_ancestry,
    authority_checkpoint_candidates: [evidence.authority_checkpoint],
    competing_repository_heads: [],
  }) as CurrentWorkspaceState;
  const validatedObjects: Readonly<Record<string, unknown>>[] = [];
  for (const [index, object] of objects.entries()) {
    const validated = validateCurrentWorkspaceObjectSnapshot(
      object,
      currentState,
      objectIdsByIndex[index],
    );
    if (!validated.ok) return { verdict: "reject", reason_code: validated.reason_code };
    validatedObjects.push(validated.value.object);
  }
  const complete = validateCompleteWorkspaceObjectSet(
    validatedObjects,
    currentState,
    evidence.observed_at,
  );
  if (!complete.ok) return { verdict: "reject", reason_code: complete.reason_code };
  const state = Object.freeze({}) as WorkspaceCurrentState;
  const viewId = workspaceObjectId(evidence);
  const generation = previous === undefined ? 1 : previous.generation + 1;
  WORKSPACE_CURRENT_STATES.set(state, deepFreeze({
    authority: authority as WorkspaceRepositoryResolverAuthority,
    state: currentState,
    view_id: viewId,
    observed_at: evidence.observed_at,
    expires_at: evidence.expires_at,
    generation,
    view_key: viewKey,
    evidence,
    objects: validatedObjects,
    ...complete.value,
  }));
  config.accepted_views.set(viewKey, {
    head: evidence.canonical_head,
    observed_at: evidence.observed_at,
    generation,
    state,
    view_id: viewId,
  });
  return { verdict: "accept", state };
}

function validateCompleteWorkspaceObjectSet(
  objects: readonly Readonly<Record<string, unknown>>[],
  current: CurrentWorkspaceState,
  effectTime: number,
): Validation<{
  policy: Readonly<Record<string, unknown>>;
  role: Readonly<Record<string, unknown>>;
  roles: readonly Readonly<Record<string, unknown>>[];
  grants: readonly Readonly<Record<string, unknown>>[];
  revocations: readonly Readonly<Record<string, unknown>>[];
  resources: readonly Readonly<Record<string, unknown>>[];
  checkpoint: Readonly<Record<string, unknown>>;
  checkpoints: readonly Readonly<Record<string, unknown>>[];
  relationships: readonly Readonly<Record<string, unknown>>[];
  joint_relationships: readonly Readonly<Record<string, unknown>>[];
  envelopes: readonly Readonly<Record<string, unknown>>[];
}> {
  const byType = (objectType: string): Readonly<Record<string, unknown>>[] =>
    objects.filter((object) => object.object_type === objectType);
  const policies = byType("workspace-policy-v1");
  const roles = byType("role-manifest-v1");
  const grants = byType("role-grant-v1");
  const revocations = byType("role-revocation-v1");
  const resources = byType("resource-advertisement-v1");
  const checkpoints = byType("role-checkpoint-v1");
  const relationships = byType("workspace-relationship-v1");
  const jointRelationships = byType("joint-workspace-relationship-v1");
  const envelopes = byType("resource-key-envelope-v1");
  if (policies.length !== 1 || roles.length === 0 || checkpoints.length !== roles.length
    || grants.length === 0 || resources.length === 0
    || objects.some((object) => ![
      "workspace-policy-v1",
      "role-manifest-v1",
      "role-grant-v1",
      "role-revocation-v1",
      "role-checkpoint-v1",
      "resource-advertisement-v1",
      "workspace-relationship-v1",
      "joint-workspace-relationship-v1",
      "resource-key-envelope-v1",
    ].includes(String(object.object_type)))) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  const policy = policies[0];
  const allowedRoleTypes = policy.allowed_role_types;
  const roleIds = roles.map((role) => String(role.role_id));
  const checkpointIds = checkpoints.map((checkpoint) => String(checkpoint.checkpoint_id));
  const relationshipIds = [...relationships, ...jointRelationships]
    .map((relationship) => String(relationship.relationship_id));
  if (policy.policy_id !== current.policy_head
    || !Array.isArray(allowedRoleTypes)
    || new Set(roleIds).size !== roleIds.length
    || new Set(checkpointIds).size !== checkpointIds.length
    || new Set(relationshipIds).size !== relationshipIds.length
    || !checkpoints.some((candidate) => candidate.checkpoint_id === current.authority_checkpoint)
    || roles.some((role) => !allowedRoleTypes.includes(role.role_type))
    || objects.some((object) => !isSafeNonNegativeInteger(object.issued_at)
      || object.issued_at > effectTime)) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  const rolesById = new Map(roles.map((role) => [String(role.role_id), role]));
  const checkpointsByRole = new Map<string, Readonly<Record<string, unknown>>>();
  for (const checkpoint of checkpoints) {
    if (!isH64(checkpoint.role_id)
      || checkpointsByRole.has(checkpoint.role_id)
      || !rolesById.has(checkpoint.role_id)
      || checkpoint.workspace_policy_head !== current.policy_head
      || !isH64Array(checkpoint.role_policy_heads)
      || !checkpoint.role_policy_heads.includes(current.policy_head)
      || !isH64Array(checkpoint.active_grant_ids)
      || !isH64Array(checkpoint.revocation_ids)
      || !isH64Array(checkpoint.resource_ids)
      || !isH64Array(checkpoint.relationship_ids)
      || !isSafeNonNegativeInteger(checkpoint.materialized_at)
      || checkpoint.materialized_at > effectTime) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
    checkpointsByRole.set(checkpoint.role_id, checkpoint);
  }
  const historyRank = (mode: unknown): number => mode === "full" ? 2
    : mode === "from-admission" ? 1
      : mode === "selected-snapshots" ? 0 : -1;
  const visibilityRank = (visibility: unknown): number => visibility === "public" ? 0
    : visibility === "selective" ? 1
      : visibility === "private" ? 2 : -1;
  for (const role of roles) {
    const chain = resolveWorkspaceRoleChain(roles, String(role.role_id));
    if (!chain.ok) return chain;
    for (let index = 1; index < chain.value.length; index += 1) {
      const parent = chain.value[index - 1];
      const child = chain.value[index];
      if (!isCapabilityArray(parent.allowed_capabilities)
        || !isCapabilityArray(child.allowed_capabilities)
        || !subset(child.allowed_capabilities, parent.allowed_capabilities)
        || historyRank(child.history_mode) > historyRank(parent.history_mode)
        || visibilityRank(child.visibility) < visibilityRank(parent.visibility)
        || (parent.history_mode === "selected-snapshots"
          && (!isH64Array(parent.selected_snapshots)
            || !isH64Array(child.selected_snapshots)
            || !subset(child.selected_snapshots, parent.selected_snapshots)))) {
        return { ok: false, reason_code: "workspace_repository_invalid" };
      }
    }
  }
  const grantIds = new Set(grants.map((grant) => grant.grant_id));
  const resourceIds = new Set(resources.map((resource) => resource.resource_id));
  if (grantIds.size !== grants.length || resourceIds.size !== resources.length) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  for (const grant of grants) {
    const chain = resolveWorkspaceRoleChain(roles, String(grant.role_id));
    const chainRoleIds = chain.ok ? new Set(chain.value.map((role) => role.role_id)) : new Set();
    if (!chain.ok || !isCapabilityArray(grant.capabilities)
      || !chain.value.every((role) => isCapabilityArray(role.allowed_capabilities)
        && subset(grant.capabilities as string[], role.allowed_capabilities))
      || !isH64Array(grant.resource_scope)
      || !grant.resource_scope.every((resourceId) => {
        const resource = resources.find((candidate) => candidate.resource_id === resourceId);
        return resource !== undefined && chainRoleIds.has(resource.role_id);
      })
      || (grant.delegable === true && !chain.value.every((role) =>
        isCapabilityArray(role.allowed_capabilities)
          && role.allowed_capabilities.includes("govern-delegation")))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  for (const resource of resources) {
    const chain = resolveWorkspaceRoleChain(roles, String(resource.role_id));
    if (!chain.ok || !isCapabilityArray(resource.required_capabilities)
      || !chain.value.every((role) => isCapabilityArray(role.allowed_capabilities)
        && subset(resource.required_capabilities as string[], role.allowed_capabilities))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  const allRevocationIds = revocations.map((revocation) => String(revocation.revocation_id));
  for (const role of roles) {
    const checkpoint = checkpointsByRole.get(String(role.role_id));
    if (checkpoint === undefined) return { ok: false, reason_code: "workspace_repository_invalid" };
    const roleGrantIds = grants.filter((grant) => grant.role_id === role.role_id)
      .map((grant) => String(grant.grant_id));
    const roleResourceIds = resources.filter((resource) => resource.role_id === role.role_id)
      .map((resource) => String(resource.resource_id));
    const roleRelationshipIds = relationships
      .filter((relationship) => relationship.source_role_id === role.role_id)
      .map((relationship) => String(relationship.relationship_id));
    if (checkpoint.checkpoint_id === current.authority_checkpoint) {
      roleRelationshipIds.push(...jointRelationships.map((relationship) =>
        String(relationship.relationship_id)));
    }
    if (!subset(checkpoint.active_grant_ids as string[], roleGrantIds)
      || !exactStringSet(checkpoint.revocation_ids as string[], allRevocationIds)
      || !exactStringSet(checkpoint.resource_ids as string[], roleResourceIds)
      || !exactStringSet(checkpoint.relationship_ids as string[], roleRelationshipIds)) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  for (const relationship of relationships) {
    if (!rolesById.has(String(relationship.source_role_id))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  for (const envelope of envelopes) {
    const resource = resources.find((candidate) => candidate.resource_id === envelope.resource_id);
    const checkpoint = checkpointsByRole.get(String(envelope.role_id));
    if (resource === undefined || checkpoint === undefined
      || resource.role_id !== envelope.role_id
      || checkpoint.checkpoint_id !== envelope.checkpoint_id
      || !isSafeNonNegativeInteger(envelope.key_epoch)
      || !isSafeNonNegativeInteger(resource.key_epoch)
      || envelope.key_epoch > resource.key_epoch) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  for (const revocation of revocations) {
    if ((revocation.target_type === "grant" && !grantIds.has(revocation.target_id))
      || (revocation.target_type === "resource" && !resourceIds.has(revocation.target_id))
      || (revocation.target_type === "relationship"
        && !relationshipIds.includes(String(revocation.target_id)))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
  }
  const checkpoint = checkpoints.find((candidate) =>
    candidate.checkpoint_id === current.authority_checkpoint) as Readonly<Record<string, unknown>>;
  const role = rolesById.get(String(checkpoint.role_id)) as Readonly<Record<string, unknown>>;
  return {
    ok: true,
    value: {
      policy,
      role,
      roles,
      grants,
      revocations,
      resources,
      checkpoint,
      checkpoints,
      relationships,
      joint_relationships: jointRelationships,
      envelopes,
    },
  };
}

function resolveWorkspaceRoleChain(
  roles: readonly Readonly<Record<string, unknown>>[],
  roleId: string,
): Validation<readonly Readonly<Record<string, unknown>>[]> {
  const byId = new Map(roles.map((role) => [String(role.role_id), role]));
  const reverseChain: Readonly<Record<string, unknown>>[] = [];
  const seen = new Set<string>();
  let cursor: string | null = roleId;
  while (cursor !== null) {
    if (seen.has(cursor)) return { ok: false, reason_code: "workspace_repository_invalid" };
    seen.add(cursor);
    const role = byId.get(cursor);
    if (role === undefined || !(role.parent_role_id === null || isH64(role.parent_role_id))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
    reverseChain.push(role);
    cursor = role.parent_role_id;
  }
  return { ok: true, value: reverseChain.reverse() };
}

function verifyWorkspaceRepositoryAttestation(
  envelope: Record<string, unknown>,
  signature: string,
  config: WorkspaceResolverConfig,
): boolean {
  const payload = proofBytes("heterodyne-workspace-repository-view-v1", envelope);
  for (const anchor of config.trust_anchors) {
    try {
      const valid = anchor.suite === "ed25519"
        ? ed25519.verify(hexToBytes(signature), payload, hexToBytes(anchor.public_key))
        : schnorr.verify(hexToBytes(signature), payload, hexToBytes(anchor.public_key));
      if (valid) return true;
    } catch {
      // Continue through configured anchors only.
    }
  }
  return false;
}

function readWorkspaceTrustedNow(
  authority: WorkspaceRepositoryResolverAuthority,
): Validation<Readonly<{ config: WorkspaceResolverConfig; now: number }>> {
  const config = WORKSPACE_RESOLVER_AUTHORITIES.get(authority);
  if (config === undefined) return { ok: false, reason_code: "workspace_repository_invalid" };
  let now: number;
  try {
    now = config.trusted_now();
  } catch {
    return { ok: false, reason_code: "checkpoint_stale" };
  }
  return isSafeNonNegativeInteger(now)
    ? { ok: true, value: { config, now } }
    : { ok: false, reason_code: "checkpoint_stale" };
}

function requireLatestCurrentView(
  authority: WorkspaceRepositoryResolverAuthority,
  handle: WorkspaceCurrentState,
  trustedNow: number,
): Validation<WorkspaceCurrentStateRecord> {
  const config = WORKSPACE_RESOLVER_AUTHORITIES.get(authority);
  const current = WORKSPACE_CURRENT_STATES.get(handle);
  if (config === undefined || current === undefined || current.authority !== authority) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  const latest = config.accepted_views.get(current.view_key);
  if (latest === undefined
    || latest.state !== handle
    || latest.generation !== current.generation
    || latest.head !== current.state.repository_head
    || latest.view_id !== current.view_id) {
    return { ok: false, reason_code: "checkpoint_stale" };
  }
  if (!isSafeNonNegativeInteger(trustedNow)
    || trustedNow < current.observed_at
    || trustedNow >= current.expires_at
    || trustedNow - current.observed_at > config.max_view_age) {
    return { ok: false, reason_code: "checkpoint_stale" };
  }
  try {
    const evidence = current.evidence;
    const unsignedEvidence = { ...evidence };
    delete unsignedEvidence.signature;
    if (typeof evidence.signature !== "string"
      || !verifyWorkspaceRepositoryAttestation(unsignedEvidence, evidence.signature, config)) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
    const objectIds = current.objects.map((object) => workspaceObjectId(object)).sort();
    if (!isByteSortedH64Array(evidence.object_ids)
      || !exactStringArray(evidence.object_ids, objectIds)
      || evidence.object_set_digest !== bytesToHex(sha256(proofBytes(
        "heterodyne-workspace-object-set-v1",
        { object_ids: evidence.object_ids },
      )))) {
      return { ok: false, reason_code: "workspace_repository_invalid" };
    }
    for (const object of current.objects) {
      const validated = validateCurrentWorkspaceObjectSnapshot(
        object,
        current.state,
        workspaceObjectId(object),
      );
      if (!validated.ok) return validated;
    }
    const complete = validateCompleteWorkspaceObjectSet(current.objects, current.state, trustedNow);
    if (!complete.ok) return complete;
  } catch {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  return { ok: true, value: current };
}

export function resolveWorkspaceEffectiveAuthorization(value: unknown):
  | {
    verdict: "accept";
    authorization: WorkspaceEffectiveAuthorization;
    normalized: Record<string, unknown>;
  }
  | { verdict: "reject"; reason_code: string } {
  const captured = captureWorkspaceRequest(value, ["authority", "current_state"], [
    "actor_account",
    "actor_device",
    "actor_leaf",
    "operation_digest",
    "requested_capabilities",
    "requested_resources",
    "requested_delegable",
  ]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const request = captured?.data;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || request === undefined
    || !isH64(request.actor_account)
    || !isH64(request.actor_device)
    || typeof request.actor_leaf !== "string"
    || !isCanonicalMarmotLeaf(request.actor_leaf)
    || !isH64(request.operation_digest)
    || !isCapabilityArray(request.requested_capabilities)
    || !isH64Array(request.requested_resources)
    || typeof request.requested_delegable !== "boolean") {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return { verdict: "reject", reason_code: trusted.reason_code };
  const latest = requireLatestCurrentView(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    trusted.value.now,
  );
  if (!latest.ok) return { verdict: "reject", reason_code: latest.reason_code };
  const current = latest.value;
  const now = trusted.value.now;
  const requestedResources = request.requested_resources as string[];
  const requestedCapabilities = request.requested_capabilities as string[];
  const actorGrants = current.grants.filter((grant) => {
    const checkpoint = current.checkpoints.find((candidate) => candidate.role_id === grant.role_id);
    return checkpoint !== undefined
      && isH64Array(checkpoint.active_grant_ids)
      && checkpoint.active_grant_ids.includes(String(grant.grant_id))
      && grant.subject_account === request.actor_account
      && grant.target_device === request.actor_device
      && isRecord(grant.recipient)
      && grant.recipient.type === "marmot-mls-leaf"
      && grant.recipient.value === request.actor_leaf
      && isSafeNonNegativeInteger(grant.activates_at)
      && grant.activates_at <= now
      && (grant.expires_at === null
        || (isSafeNonNegativeInteger(grant.expires_at) && now < grant.expires_at));
  });
  if (actorGrants.length === 0) {
    return { verdict: "reject", reason_code: "policy_denied" };
  }
  const effectiveRevocations = current.revocations.filter((revocation) =>
    isSafeNonNegativeInteger(revocation.effective_at) && revocation.effective_at <= now);
  if (effectiveRevocations.some((revocation) => revocation.target_type === "device"
    && revocation.target_id === request.actor_device)) {
    return { verdict: "reject", reason_code: "device_revoked" };
  }
  if (effectiveRevocations.some((revocation) =>
    (revocation.target_type === "account" && revocation.target_id === request.actor_account)
      || (revocation.target_type === "resource"
        && requestedResources.includes(String(revocation.target_id))))) {
    return { verdict: "reject", reason_code: "policy_denied" };
  }
  const revokedGrantIds = new Set(effectiveRevocations
    .filter((revocation) => revocation.target_type === "grant")
    .map((revocation) => revocation.target_id));
  const usableActorGrants = actorGrants.filter((grant) => !revokedGrantIds.has(grant.grant_id));
  if (usableActorGrants.length === 0) return { verdict: "reject", reason_code: "policy_denied" };
  const knownResources = new Set(current.resources.map((resource) => resource.resource_id));
  const selected = [...usableActorGrants]
    .sort((left, right) => String(left.grant_id).localeCompare(String(right.grant_id)))
    .find((grant) => {
      const rolePath = resolveWorkspaceRoleChain(current.roles, String(grant.role_id));
      if (!rolePath.ok) return false;
      const grantCapabilities = isCapabilityArray(grant.capabilities)
        ? grant.capabilities.filter((capability) => rolePath.value.every((role) =>
          isCapabilityArray(role.allowed_capabilities)
            && role.allowed_capabilities.includes(capability)))
        : [];
      const grantResources = isH64Array(grant.resource_scope)
        ? grant.resource_scope.filter((resourceId) => knownResources.has(resourceId))
        : [];
      const grantDelegable = grant.delegable === true
        && grantCapabilities.includes("govern-delegation");
      return subset(requestedCapabilities, grantCapabilities)
        && subset(requestedResources, grantResources)
        && (!request.requested_delegable || grantDelegable);
    });
  if (selected === undefined) {
    return { verdict: "reject", reason_code: "capability_escalation" };
  }
  const selectedRolePath = resolveWorkspaceRoleChain(current.roles, String(selected.role_id));
  if (!selectedRolePath.ok) return { verdict: "reject", reason_code: selectedRolePath.reason_code };
  const effectiveCapabilities = (isCapabilityArray(selected.capabilities)
    ? selected.capabilities : [])
    .filter((capability) => selectedRolePath.value.every((role) =>
      isCapabilityArray(role.allowed_capabilities)
        && role.allowed_capabilities.includes(capability)))
    .sort();
  const effectiveResources = (isH64Array(selected.resource_scope)
    ? selected.resource_scope : [])
    .filter((resourceId) => knownResources.has(resourceId))
    .sort();
  const effectiveDelegable = selected.delegable === true
    && effectiveCapabilities.includes("govern-delegation");
  const governance = current.policy.governance;
  if (!isRecord(governance)
    || !isH64Array(governance.controllers)
    || governance.controllers.length === 0
    || !isSafeNonNegativeInteger(governance.threshold)
    || governance.threshold < 1
    || governance.threshold > governance.controllers.length) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  const record = deepFreeze({
    authority: authority as WorkspaceRepositoryResolverAuthority,
    current_state: currentState as WorkspaceCurrentState,
    actor_account: request.actor_account,
    actor_device: request.actor_device,
    actor_leaf: request.actor_leaf,
    workspace_key: current.state.workspace_key,
    policy_head: current.state.policy_head,
    predecessor: current.state.predecessor,
    authority_checkpoint: current.state.authority_checkpoint,
    operation_digest: request.operation_digest,
    requested_capabilities: [...requestedCapabilities].sort(),
    requested_resources: [...requestedResources].sort(),
    requested_delegable: request.requested_delegable,
    qualifying_grant_id: String(selected.grant_id),
    qualifying_role_path_ids: selectedRolePath.value.map((role) => String(role.role_id)),
    resolved_at: now,
    effective_capabilities: effectiveCapabilities,
    effective_resources: effectiveResources,
    effective_delegable: effectiveDelegable,
    effective_approver_keys: [...governance.controllers].sort(),
    required_approvals: governance.threshold,
  }) as WorkspaceEffectiveAuthorizationRecord;
  const authorization = Object.freeze({}) as WorkspaceEffectiveAuthorization;
  WORKSPACE_EFFECTIVE_AUTHORIZATIONS.set(authorization, record);
  return {
    verdict: "accept",
    authorization,
    normalized: snapshotJsonRecord({
      actor_account: record.actor_account,
      authority_checkpoint: record.authority_checkpoint,
      effective_capabilities: record.effective_capabilities,
      effective_delegable: record.effective_delegable,
      effective_approver_keys: record.effective_approver_keys,
      effective_resources: record.effective_resources,
      operation_digest: record.operation_digest,
      policy_head: record.policy_head,
      predecessor: record.predecessor,
      qualifying_grant_id: record.qualifying_grant_id,
      qualifying_role_path_ids: record.qualifying_role_path_ids,
      required_approvals: record.required_approvals,
      workspace_key: record.workspace_key,
    }) as Record<string, unknown>,
  };
}

function requireEffectiveAuthorizationAtEffect(
  authority: WorkspaceRepositoryResolverAuthority,
  currentState: WorkspaceCurrentState,
  authorizationHandle: WorkspaceEffectiveAuthorization,
  trustedNow: number,
): Validation<Readonly<{
  current: WorkspaceCurrentStateRecord;
  authorization: WorkspaceEffectiveAuthorizationRecord;
  grant: Readonly<Record<string, unknown>>;
  role_path: readonly Readonly<Record<string, unknown>>[];
}>> {
  const latest = requireLatestCurrentView(authority, currentState, trustedNow);
  if (!latest.ok) return latest;
  const current = latest.value;
  const authorization = WORKSPACE_EFFECTIVE_AUTHORIZATIONS.get(authorizationHandle);
  if (authorization === undefined) return { ok: false, reason_code: "workspace_schema_invalid" };
  if (authorization.authority !== authority || authorization.current_state !== currentState) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  const grant = current.grants.find((candidate) =>
    candidate.grant_id === authorization.qualifying_grant_id);
  if (grant === undefined) return { ok: false, reason_code: "policy_denied" };
  const checkpoint = current.checkpoints.find((candidate) => candidate.role_id === grant.role_id);
  const rolePath = resolveWorkspaceRoleChain(current.roles, String(grant.role_id));
  if (checkpoint === undefined || !rolePath.ok
    || !isH64Array(checkpoint.active_grant_ids)
    || !checkpoint.active_grant_ids.includes(authorization.qualifying_grant_id)
    || !exactStringArray(
      rolePath.value.map((role) => String(role.role_id)),
      authorization.qualifying_role_path_ids,
    )
    || grant.subject_account !== authorization.actor_account
    || grant.target_device !== authorization.actor_device
    || !isRecord(grant.recipient)
    || grant.recipient.value !== authorization.actor_leaf
    || !isSafeNonNegativeInteger(grant.issued_at)
    || !isSafeNonNegativeInteger(grant.activates_at)
    || grant.issued_at > grant.activates_at
    || trustedNow < grant.activates_at
    || (grant.expires_at !== null
      && (!isSafeNonNegativeInteger(grant.expires_at) || trustedNow >= grant.expires_at))) {
    return { ok: false, reason_code: "policy_denied" };
  }
  const effectiveRevocations = current.revocations.filter((revocation) =>
    isSafeNonNegativeInteger(revocation.effective_at) && revocation.effective_at <= trustedNow);
  if (effectiveRevocations.some((revocation) =>
    (revocation.target_type === "account" && revocation.target_id === authorization.actor_account)
      || (revocation.target_type === "device" && revocation.target_id === authorization.actor_device)
      || (revocation.target_type === "grant" && revocation.target_id === grant.grant_id)
      || (revocation.target_type === "resource"
        && authorization.requested_resources.includes(String(revocation.target_id))))) {
    return { ok: false, reason_code: "policy_denied" };
  }
  const currentCapabilities = isCapabilityArray(grant.capabilities)
    ? grant.capabilities.filter((capability) => rolePath.value.every((role) =>
      isCapabilityArray(role.allowed_capabilities)
        && role.allowed_capabilities.includes(capability))).sort()
    : [];
  const currentResourceIds = new Set(current.resources.map((resource) => resource.resource_id));
  const currentResources = isH64Array(grant.resource_scope)
    ? grant.resource_scope.filter((resourceId) => currentResourceIds.has(resourceId)).sort()
    : [];
  const currentDelegable = grant.delegable === true
    && currentCapabilities.includes("govern-delegation");
  const governance = current.policy.governance;
  if (!isRecord(governance)
    || !isH64Array(governance.controllers)
    || !isSafeNonNegativeInteger(governance.threshold)
    || governance.threshold < 1
    || governance.threshold > governance.controllers.length
    || !exactStringArray([...governance.controllers].sort(), authorization.effective_approver_keys)
    || governance.threshold !== authorization.required_approvals
    || !exactStringArray(currentCapabilities, authorization.effective_capabilities)
    || !exactStringArray(currentResources, authorization.effective_resources)
    || currentDelegable !== authorization.effective_delegable
    || !subset(authorization.requested_capabilities, currentCapabilities)
    || !subset(authorization.requested_resources, currentResources)
    || (authorization.requested_delegable && !currentDelegable)) {
    return { ok: false, reason_code: "capability_escalation" };
  }
  return {
    ok: true,
    value: { current, authorization, grant, role_path: rolePath.value },
  };
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
  const resolved = resolveWorkspaceEffectiveAuthorization(value);
  return resolved.verdict === "accept"
    ? accepted(resolved.normalized)
    : rejected(resolved.reason_code);
}

function abortWorkspaceInvitationReservation(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  const record = WORKSPACE_INVITATION_ACCEPTANCES.get(value);
  if (record === undefined) return;
  const store = WORKSPACE_INVITATION_STORES.get(record.store);
  const reservation = store?.get(record.token);
  if (reservation?.status === "reserved" && reservation.holder === value) {
    store?.delete(record.token);
  }
}

function commitWorkspaceInvitationReservation(value: WorkspaceInvitationAcceptance): boolean {
  const record = WORKSPACE_INVITATION_ACCEPTANCES.get(value);
  if (record === undefined) return false;
  const store = WORKSPACE_INVITATION_STORES.get(record.store);
  const reservation = store?.get(record.token);
  if (reservation?.status !== "reserved" || reservation.holder !== value) return false;
  reservation.status = "committed";
  return true;
}

export function evaluateGrantActivation(value: unknown): WorkspaceVerdict {
  const captured = captureWorkspaceRequest(value, [
    "authority",
    "current_state",
    "authorization",
    "invitation_acceptance",
    "successor_reauthorization",
  ], ["grant_id", "membership", "approvals"]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const authorizationValue = captured?.opaque.authorization;
  const invitationAcceptance = captured?.opaque.invitation_acceptance;
  const successorReauthorization = captured?.opaque.successor_reauthorization;
  const input = captured?.data;
  const rejectActivation = (reasonCode: string): WorkspaceVerdict => {
    abortWorkspaceInvitationReservation(invitationAcceptance);
    return rejected(reasonCode);
  };
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || authorizationValue === null || typeof authorizationValue !== "object"
    || input === undefined
    || !isH64(input.grant_id)
    || !isRecord(input.membership)
    || !hasExactMembers(input.membership, [
      "authenticated_account",
      "accepted_device",
      "accepted_leaf",
    ])
    || !isH64(input.membership.authenticated_account)
    || !isH64(input.membership.accepted_device)
    || typeof input.membership.accepted_leaf !== "string"
    || !isCanonicalMarmotLeaf(input.membership.accepted_leaf)
    || !Array.isArray(input.approvals)) return rejectActivation("workspace_schema_invalid");
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return rejectActivation(trusted.reason_code);
  const effective = requireEffectiveAuthorizationAtEffect(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    authorizationValue as WorkspaceEffectiveAuthorization,
    trusted.value.now,
  );
  if (!effective.ok) return rejectActivation(effective.reason_code);
  const { current, authorization } = effective.value;
  const now = trusted.value.now;
  const grant = current.grants.find((candidate) => candidate.grant_id === input.grant_id);
  if (grant === undefined) return rejectActivation("workspace_repository_invalid");
  const operationDigest = grantOperationDigestSnapshot(grant);
  if (authorization.workspace_key !== grant.workspace_key
    || authorization.policy_head !== grant.policy_head
    || authorization.predecessor !== grant.predecessor
    || authorization.authority_checkpoint !== grant.authority_checkpoint
    || authorization.operation_digest !== operationDigest) {
    return rejectActivation("workspace_signature_invalid");
  }
  if (grant.subject_account !== input.membership.authenticated_account) {
    if (successorReauthorization === null || typeof successorReauthorization !== "object") {
      return rejectActivation("policy_denied");
    }
    const currentSuccessor = requireSuccessorReauthorizationAtEffect(
      authority as WorkspaceRepositoryResolverAuthority,
      currentState as WorkspaceCurrentState,
      successorReauthorization as WorkspaceSuccessorReauthorization,
      now,
    );
    if (!currentSuccessor.ok) return rejectActivation(currentSuccessor.reason_code);
    const successor = currentSuccessor.value.reauthorization;
    if (successor.scope !== "role-membership"
      || successor.resource_id !== null
      || successor.prior_account !== input.membership.authenticated_account
      || successor.new_account !== grant.subject_account
      || successor.role_id !== grant.role_id
      || successor.new_device !== grant.target_device
      || !isRecord(grant.recipient)
      || successor.new_leaf !== grant.recipient.value
      || now >= successor.expires_at) return rejectActivation("policy_denied");
  } else if (successorReauthorization !== null) {
    return rejectActivation("policy_denied");
  }
  if (grant.target_device !== input.membership.accepted_device
    || !isRecord(grant.recipient)
    || grant.recipient.value !== input.membership.accepted_leaf) {
    return rejectActivation("device_revoked");
  }
  if (!isH64(grant.grant_id)
    || !isCapabilityArray(grant.capabilities)
    || !isH64Array(grant.resource_scope)
    || typeof grant.delegable !== "boolean"
    || !isSafeNonNegativeInteger(grant.issued_at)
    || !isSafeNonNegativeInteger(grant.activates_at)
    || !(grant.expires_at === null || isSafeNonNegativeInteger(grant.expires_at))
    || grant.issued_at > grant.activates_at
    || now < grant.activates_at
    || (grant.expires_at !== null && now >= grant.expires_at)
    || !isH64Array(grant.approval_ids)) return rejectActivation("workspace_schema_invalid");
  if (current.revocations.some((revocation) =>
    revocation.target_type === "grant"
      && revocation.target_id === grant.grant_id
      && isSafeNonNegativeInteger(revocation.effective_at)
      && revocation.effective_at <= now)) {
    return rejectActivation("policy_denied");
  }
  let executableInvitationAcceptance: object | null = null;
  if (grant.activation === "subject-acceptance") {
    if (invitationAcceptance === null) return rejectActivation("policy_denied");
    if (typeof invitationAcceptance !== "object") return rejectActivation("workspace_schema_invalid");
    const invitationRecord = WORKSPACE_INVITATION_ACCEPTANCES.get(invitationAcceptance);
    if (invitationRecord === undefined) return rejectActivation("workspace_schema_invalid");
    if (invitationRecord.authority !== authority
      || invitationRecord.current_state !== currentState
      || invitationRecord.grant_id !== grant.grant_id) {
      return rejectActivation("workspace_signature_invalid");
    }
    executableInvitationAcceptance = invitationAcceptance;
  } else if (invitationAcceptance !== null || grant.invitation !== null) {
    return rejectActivation("workspace_schema_invalid");
  }
  if (!authorization.effective_capabilities.includes("invite")
    || !subset(grant.capabilities, authorization.effective_capabilities)
    || !subset(grant.resource_scope, authorization.effective_resources)
    || (grant.delegable && (!authorization.effective_delegable
      || !authorization.effective_capabilities.includes("govern-delegation")))
    || grant.capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejectActivation("capability_escalation");
  }
  const approvals: Array<Readonly<{ approver_key: string; approval_id: string }>> = [];
  for (const candidate of input.approvals) {
    const approval = validateGrantApprovalSnapshot(candidate, {
      workspace_key: String(grant.workspace_key),
      policy_head: String(grant.policy_head),
      predecessor: grant.predecessor as string | null,
      authority_checkpoint: String(grant.authority_checkpoint),
      operation_digest: operationDigest,
      now,
    });
    if (!approval.ok) return rejectActivation(approval.reason_code);
    approvals.push(approval.value);
  }
  const approvalIds = approvals.map(({ approval_id }) => approval_id);
  const approverKeys = approvals.map(({ approver_key }) => approver_key);
  if (!exactStringSet(approvalIds, grant.approval_ids)
    || new Set(approvalIds).size !== approvalIds.length
    || new Set(approverKeys).size !== approverKeys.length
    || !subset(approverKeys, authorization.effective_approver_keys)
    || approvals.length < authorization.required_approvals) {
    return rejectActivation("policy_denied");
  }
  if (executableInvitationAcceptance !== null) {
    if (!commitWorkspaceInvitationReservation(
      executableInvitationAcceptance as WorkspaceInvitationAcceptance,
    )) return rejected("workspace_replay");
  }
  return accepted({
    active: true,
    approval_count: approvals.length,
    approver_keys: [...approverKeys].sort(),
    grant_id: grant.grant_id,
    operation_digest: operationDigest,
  });
}

function requireCurrentRelationshipAtEffect(
  authority: WorkspaceRepositoryResolverAuthority,
  sourceState: WorkspaceCurrentState,
  receivingState: WorkspaceCurrentState,
  relationshipId: string,
  trustedNow: number,
): Validation<Readonly<{
  source: WorkspaceCurrentStateRecord;
  receiving: WorkspaceCurrentStateRecord;
  relationship: Readonly<Record<string, unknown>>;
  source_role: Readonly<Record<string, unknown>>;
  receiving_role: Readonly<Record<string, unknown>>;
}>> {
  const sourceLatest = requireLatestCurrentView(authority, sourceState, trustedNow);
  if (!sourceLatest.ok) return sourceLatest;
  const receivingLatest = requireLatestCurrentView(authority, receivingState, trustedNow);
  if (!receivingLatest.ok) return receivingLatest;
  const source = sourceLatest.value;
  const receiving = receivingLatest.value;
  const relationshipObject = source.objects.find((object) =>
    object.object_type === "workspace-relationship-v1"
      && object.relationship_id === relationshipId);
  const sourceRole = source.roles.find((role) => role.role_id === relationshipObject?.source_role_id);
  const receivingRole = receiving.roles.find((role) =>
    role.role_id === relationshipObject?.receiving_role_id);
  const sourceCheckpoint = source.checkpoints.find((checkpoint) =>
    checkpoint.role_id === relationshipObject?.source_role_id);
  if (relationshipObject === undefined
    || sourceRole === undefined
    || receivingRole === undefined
    || sourceCheckpoint === undefined
    || relationshipObject.source_workspace_key !== source.state.workspace_key
    || relationshipObject.receiving_workspace_key !== receiving.state.workspace_key
    || relationshipObject.receiving_policy_head !== receiving.state.policy_head
    || relationshipObject.receiving_predecessor !== receiving.state.predecessor
    || relationshipObject.receiving_authority_checkpoint !== receiving.state.authority_checkpoint
    || typeof relationshipObject.receiving_signature !== "string"
    || !validWorkspaceSignature(
      relationshipObject,
      receiving.state.workspace_key,
      relationshipObject.receiving_signature,
    )
    || !isSafeNonNegativeInteger(relationshipObject.expires_at)
    || trustedNow >= relationshipObject.expires_at
    || !Array.isArray(sourceCheckpoint.relationship_ids)
    || !sourceCheckpoint.relationship_ids.includes(relationshipId)
    || source.policy.allow_bilateral_relationships !== true
    || receiving.policy.allow_bilateral_relationships !== true) {
    return { ok: false, reason_code: "workspace_signature_invalid" };
  }
  const revoked = [source, receiving].some((state) => state.revocations.some((revocation) =>
    revocation.target_type === "relationship"
      && revocation.target_id === relationshipId
      && isSafeNonNegativeInteger(revocation.effective_at)
      && revocation.effective_at <= trustedNow));
  if (revoked) return { ok: false, reason_code: "policy_denied" };
  return {
    ok: true,
    value: {
      source,
      receiving,
      relationship: relationshipObject,
      source_role: sourceRole,
      receiving_role: receivingRole,
    },
  };
}

export function resolveWorkspaceCurrentRelationship(value: unknown):
  | { verdict: "accept"; relationship: WorkspaceCurrentRelationship }
  | { verdict: "reject"; reason_code: string } {
  const captured = captureWorkspaceRequest(value, [
    "authority",
    "source_state",
    "receiving_state",
  ], ["relationship_id"]);
  const authority = captured?.opaque.authority;
  const sourceState = captured?.opaque.source_state;
  const receivingState = captured?.opaque.receiving_state;
  const relationshipId = captured?.data.relationship_id;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || sourceState === null || typeof sourceState !== "object"
    || receivingState === null || typeof receivingState !== "object"
    || !isH64(relationshipId)) {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return { verdict: "reject", reason_code: trusted.reason_code };
  const resolved = requireCurrentRelationshipAtEffect(
    authority as WorkspaceRepositoryResolverAuthority,
    sourceState as WorkspaceCurrentState,
    receivingState as WorkspaceCurrentState,
    relationshipId,
    trusted.value.now,
  );
  if (!resolved.ok) return { verdict: "reject", reason_code: resolved.reason_code };
  const record = deepFreeze({
    authority: authority as WorkspaceRepositoryResolverAuthority,
    source_state: sourceState as WorkspaceCurrentState,
    receiving_state: receivingState as WorkspaceCurrentState,
    relationship: resolved.value.relationship,
  }) as WorkspaceCurrentRelationshipRecord;
  const relationship = Object.freeze({}) as WorkspaceCurrentRelationship;
  WORKSPACE_CURRENT_RELATIONSHIPS.set(relationship, record);
  return { verdict: "accept", relationship };
}

export function consumeWorkspaceInvitationAcceptance(value: unknown):
  | { verdict: "accept"; acceptance: WorkspaceInvitationAcceptance }
  | { verdict: "reject"; reason_code: string } {
  const captured = captureWorkspaceRequest(value, ["authority", "current_state"], ["acceptance"]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const acceptanceValue = captured?.data.acceptance;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || !isRecord(acceptanceValue)
    || !hasExactMembers(acceptanceValue, [
      "profile",
      "spec_version",
      "grant_id",
      "grant_operation_digest",
      "workspace_key",
      "subject_account",
      "target_device",
      "target_leaf",
      "policy_head",
      "predecessor",
      "authority_checkpoint",
      "repository_view_id",
      "nonce_opening",
      "nonce_commitment",
      "issued_at",
      "expires_at",
      "signature",
    ])
    || acceptanceValue.profile !== "heterodyne.workspace-invitation-acceptance.v1"
    || acceptanceValue.spec_version !== "heterodyne/0.5.0"
    || !isH64(acceptanceValue.grant_id)
    || !isH64(acceptanceValue.grant_operation_digest)
    || !isH64(acceptanceValue.workspace_key)
    || !isH64(acceptanceValue.subject_account)
    || !isH64(acceptanceValue.target_device)
    || typeof acceptanceValue.target_leaf !== "string"
    || !isCanonicalMarmotLeaf(acceptanceValue.target_leaf)
    || !isH64(acceptanceValue.policy_head)
    || !(acceptanceValue.predecessor === null || isH64(acceptanceValue.predecessor))
    || !isH64(acceptanceValue.authority_checkpoint)
    || !isH64(acceptanceValue.repository_view_id)
    || !isH64(acceptanceValue.nonce_opening)
    || !isH64(acceptanceValue.nonce_commitment)
    || !isSafeNonNegativeInteger(acceptanceValue.issued_at)
    || !isSafeNonNegativeInteger(acceptanceValue.expires_at)
    || acceptanceValue.issued_at >= acceptanceValue.expires_at
    || typeof acceptanceValue.signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(acceptanceValue.signature)) {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return { verdict: "reject", reason_code: trusted.reason_code };
  const invitationStore = trusted.value.config.invitation_store;
  if (invitationStore === null) {
    return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  }
  const latest = requireLatestCurrentView(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    trusted.value.now,
  );
  if (!latest.ok) return { verdict: "reject", reason_code: latest.reason_code };
  const config = trusted.value.config;
  const current = latest.value;
  const now = trusted.value.now;
  const grant = current.grants.find((candidate) => candidate.grant_id === acceptanceValue.grant_id);
  const unsignedAcceptance = { ...acceptanceValue };
  delete unsignedAcceptance.signature;
  if (!validRawSignature(
    acceptanceValue.signature,
    proofBytes("heterodyne-workspace-invitation-acceptance-v1", unsignedAcceptance),
    acceptanceValue.subject_account,
  )) return { verdict: "reject", reason_code: "workspace_signature_invalid" };
  if (grant === undefined
    || grant.activation !== "subject-acceptance"
    || !isRecord(grant.invitation)
    || grantOperationDigestSnapshot(grant) !== acceptanceValue.grant_operation_digest
    || grant.workspace_key !== acceptanceValue.workspace_key
    || grant.subject_account !== acceptanceValue.subject_account
    || grant.target_device !== acceptanceValue.target_device
    || !isRecord(grant.recipient)
    || grant.recipient.value !== acceptanceValue.target_leaf
    || current.state.policy_head !== acceptanceValue.policy_head
    || current.state.predecessor !== acceptanceValue.predecessor
    || current.state.authority_checkpoint !== acceptanceValue.authority_checkpoint
    || current.view_id !== acceptanceValue.repository_view_id
    || grant.invitation.nonce_commitment !== acceptanceValue.nonce_commitment
    || !isSafeNonNegativeInteger(grant.invitation.expires_at)
    || acceptanceValue.expires_at > grant.invitation.expires_at
    || acceptanceValue.issued_at > now
    || now >= acceptanceValue.expires_at
    || now >= grant.invitation.expires_at) {
    return { verdict: "reject", reason_code: "workspace_signature_invalid" };
  }
  const expectedCommitment = bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-invitation-nonce-v1",
    {
      grant_id: acceptanceValue.grant_id,
      workspace_key: acceptanceValue.workspace_key,
      subject_account: acceptanceValue.subject_account,
      target_device: acceptanceValue.target_device,
      target_leaf: acceptanceValue.target_leaf,
      nonce_opening: acceptanceValue.nonce_opening,
    },
  )));
  if (expectedCommitment !== acceptanceValue.nonce_commitment) {
    return { verdict: "reject", reason_code: "workspace_signature_invalid" };
  }
  const store = WORKSPACE_INVITATION_STORES.get(invitationStore);
  if (store === undefined) return { verdict: "reject", reason_code: "workspace_repository_invalid" };
  const token = `${acceptanceValue.workspace_key}:${acceptanceValue.grant_id}:${acceptanceValue.nonce_commitment}`;
  const existingReservation = store.get(token);
  if (existingReservation !== undefined) {
    if (existingReservation.status === "reserved" && now >= existingReservation.expires_at) {
      store.delete(token);
    } else {
      return { verdict: "reject", reason_code: "workspace_replay" };
    }
  }
  const acceptanceId = workspaceObjectId(acceptanceValue);
  const acceptance = Object.freeze({}) as WorkspaceInvitationAcceptance;
  WORKSPACE_INVITATION_ACCEPTANCES.set(acceptance, deepFreeze({
    authority: authority as WorkspaceRepositoryResolverAuthority,
    current_state: currentState as WorkspaceCurrentState,
    grant_id: acceptanceValue.grant_id,
    acceptance_id: acceptanceId,
    store: invitationStore,
    token,
    expires_at: acceptanceValue.expires_at,
  }));
  store.set(token, {
    binding: acceptanceId,
    status: "reserved",
    holder: acceptance,
    expires_at: acceptanceValue.expires_at,
  });
  return { verdict: "accept", acceptance };
}

export function authenticateWorkspaceSuccessorReauthorization(value: unknown):
  | { verdict: "accept"; reauthorization: WorkspaceSuccessorReauthorization }
  | { verdict: "reject"; reason_code: string } {
  const captured = captureWorkspaceRequest(value, ["authority", "current_state"], ["reauthorization"]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const reauthorizationValue = captured?.data.reauthorization;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || !isRecord(reauthorizationValue)
    || !hasExactMembers(reauthorizationValue, [
      "profile",
      "spec_version",
      "workspace_key",
      "prior_account",
      "new_account",
      "prior_key",
      "new_key",
      "prior_device",
      "prior_leaf",
      "new_device",
      "new_leaf",
      "role_id",
      "resource_id",
      "scope",
      "prior_grant_id",
      "pending_grant_id",
      "pending_envelope_id",
      "policy_head",
      "predecessor",
      "authority_checkpoint",
      "repository_view_id",
      "issued_at",
      "effective_at",
      "expires_at",
      "workspace_signature",
      "new_account_signature",
    ])
    || reauthorizationValue.profile !== "heterodyne.workspace-successor-reauthorization.v1"
    || reauthorizationValue.spec_version !== "heterodyne/0.5.0"
    || !isH64(reauthorizationValue.workspace_key)
    || !isH64(reauthorizationValue.prior_account)
    || !isH64(reauthorizationValue.new_account)
    || !isH64(reauthorizationValue.prior_key)
    || !isH64(reauthorizationValue.new_key)
    || !isH64(reauthorizationValue.prior_device)
    || typeof reauthorizationValue.prior_leaf !== "string"
    || !isCanonicalMarmotLeaf(reauthorizationValue.prior_leaf)
    || !isH64(reauthorizationValue.new_device)
    || typeof reauthorizationValue.new_leaf !== "string"
    || !isCanonicalMarmotLeaf(reauthorizationValue.new_leaf)
    || !isH64(reauthorizationValue.role_id)
    || !(reauthorizationValue.resource_id === null || isH64(reauthorizationValue.resource_id))
    || !(reauthorizationValue.scope === "role-membership"
      || reauthorizationValue.scope === "resource-key")
    || !isH64(reauthorizationValue.prior_grant_id)
    || !isH64(reauthorizationValue.pending_grant_id)
    || !(reauthorizationValue.pending_envelope_id === null
      || isH64(reauthorizationValue.pending_envelope_id))
    || !isH64(reauthorizationValue.policy_head)
    || !(reauthorizationValue.predecessor === null || isH64(reauthorizationValue.predecessor))
    || !isH64(reauthorizationValue.authority_checkpoint)
    || !isH64(reauthorizationValue.repository_view_id)
    || !isSafeNonNegativeInteger(reauthorizationValue.issued_at)
    || !isSafeNonNegativeInteger(reauthorizationValue.effective_at)
    || !isSafeNonNegativeInteger(reauthorizationValue.expires_at)
    || reauthorizationValue.issued_at > reauthorizationValue.effective_at
    || reauthorizationValue.effective_at >= reauthorizationValue.expires_at
    || typeof reauthorizationValue.workspace_signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(reauthorizationValue.workspace_signature)
    || typeof reauthorizationValue.new_account_signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(reauthorizationValue.new_account_signature)) {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return { verdict: "reject", reason_code: trusted.reason_code };
  const latest = requireLatestCurrentView(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    trusted.value.now,
  );
  if (!latest.ok) return { verdict: "reject", reason_code: latest.reason_code };
  const current = latest.value;
  const now = trusted.value.now;
  const unsigned = { ...reauthorizationValue };
  delete unsigned.workspace_signature;
  delete unsigned.new_account_signature;
  const payload = proofBytes("heterodyne-workspace-successor-reauthorization-v1", unsigned);
  if (!validRawSignature(
    reauthorizationValue.workspace_signature,
    payload,
    current.state.workspace_key,
  ) || !validRawSignature(
    reauthorizationValue.new_account_signature,
    payload,
    reauthorizationValue.new_account,
  )) return { verdict: "reject", reason_code: "workspace_signature_invalid" };
  const checkpoint = current.checkpoints.find((candidate) =>
    candidate.role_id === reauthorizationValue.role_id);
  const activeGrantIds = new Set(checkpoint !== undefined && isH64Array(checkpoint.active_grant_ids)
    ? checkpoint.active_grant_ids : []);
  const priorGrant = current.grants.find((grant) =>
    grant.grant_id === reauthorizationValue.prior_grant_id);
  const pendingGrant = current.grants.find((grant) =>
    grant.grant_id === reauthorizationValue.pending_grant_id);
  const pendingEnvelope = reauthorizationValue.pending_envelope_id === null ? null
    : current.envelopes.find((envelope) =>
      envelope.envelope_id === reauthorizationValue.pending_envelope_id) ?? null;
  if (reauthorizationValue.workspace_key !== current.state.workspace_key
    || reauthorizationValue.prior_account !== reauthorizationValue.prior_key
    || reauthorizationValue.new_account !== reauthorizationValue.new_key
    || reauthorizationValue.prior_account === reauthorizationValue.new_account
    || reauthorizationValue.prior_device === reauthorizationValue.new_device
    || reauthorizationValue.prior_leaf === reauthorizationValue.new_leaf
    || reauthorizationValue.policy_head !== current.state.policy_head
    || reauthorizationValue.predecessor !== current.state.predecessor
    || reauthorizationValue.authority_checkpoint !== current.state.authority_checkpoint
    || reauthorizationValue.repository_view_id !== current.view_id
    || reauthorizationValue.effective_at > now
    || now >= reauthorizationValue.expires_at
    || checkpoint === undefined
    || priorGrant === undefined
    || !activeGrantIds.has(String(priorGrant.grant_id))
    || priorGrant.subject_account !== reauthorizationValue.prior_account
    || priorGrant.target_device !== reauthorizationValue.prior_device
    || !isRecord(priorGrant.recipient)
    || priorGrant.recipient.value !== reauthorizationValue.prior_leaf
    || priorGrant.role_id !== reauthorizationValue.role_id
    || !isSafeNonNegativeInteger(priorGrant.activates_at)
    || priorGrant.activates_at > reauthorizationValue.issued_at
    || (priorGrant.expires_at !== null
      && (!isSafeNonNegativeInteger(priorGrant.expires_at) || now >= priorGrant.expires_at))
    || pendingGrant === undefined
    || activeGrantIds.has(String(pendingGrant.grant_id))
    || pendingGrant.subject_account !== reauthorizationValue.new_account
    || pendingGrant.target_device !== reauthorizationValue.new_device
    || !isRecord(pendingGrant.recipient)
    || pendingGrant.recipient.value !== reauthorizationValue.new_leaf
    || pendingGrant.role_id !== reauthorizationValue.role_id
    || !isSafeNonNegativeInteger(pendingGrant.issued_at)
    || pendingGrant.issued_at > reauthorizationValue.effective_at
    || current.grants.some((grant) => activeGrantIds.has(String(grant.grant_id))
      && (grant.subject_account === reauthorizationValue.new_account
        || grant.target_device === reauthorizationValue.new_device
        || (isRecord(grant.recipient) && grant.recipient.value === reauthorizationValue.new_leaf)))
    || (reauthorizationValue.scope === "role-membership"
      && (reauthorizationValue.resource_id !== null
        || reauthorizationValue.pending_envelope_id !== null))
    || (reauthorizationValue.scope === "resource-key"
      && (reauthorizationValue.resource_id === null
        || pendingEnvelope === null
        || pendingEnvelope.resource_id !== reauthorizationValue.resource_id
        || pendingEnvelope.role_id !== reauthorizationValue.role_id
        || pendingEnvelope.target_account !== reauthorizationValue.new_account
        || pendingEnvelope.target_device !== reauthorizationValue.new_device
        || !isRecord(pendingEnvelope.recipient)
        || pendingEnvelope.recipient.value !== reauthorizationValue.new_leaf
        || pendingEnvelope.checkpoint_id !== checkpoint.checkpoint_id
        || !isSafeNonNegativeInteger(pendingEnvelope.issued_at)
        || pendingEnvelope.issued_at > reauthorizationValue.effective_at
        || !isH64Array(priorGrant.resource_scope)
        || !priorGrant.resource_scope.includes(reauthorizationValue.resource_id as string)
        || !isH64Array(pendingGrant.resource_scope)
        || !pendingGrant.resource_scope.includes(reauthorizationValue.resource_id as string)
        || !current.resources.some((resource) =>
          resource.resource_id === reauthorizationValue.resource_id)))
    || current.revocations.some((revocation) =>
      isSafeNonNegativeInteger(revocation.effective_at)
        && revocation.effective_at <= now
        && ((revocation.target_type === "account"
          && (revocation.target_id === reauthorizationValue.prior_account
            || revocation.target_id === reauthorizationValue.new_account))
          || (revocation.target_type === "device"
            && (revocation.target_id === reauthorizationValue.prior_device
              || revocation.target_id === reauthorizationValue.new_device))
          || (revocation.target_type === "grant"
            && (revocation.target_id === reauthorizationValue.prior_grant_id
              || revocation.target_id === reauthorizationValue.pending_grant_id))
          || (revocation.target_type === "resource"
            && revocation.target_id === reauthorizationValue.resource_id)))) {
    return { verdict: "reject", reason_code: "policy_denied" };
  }
  const record = deepFreeze({
    authority: authority as WorkspaceRepositoryResolverAuthority,
    current_state: currentState as WorkspaceCurrentState,
    object: reauthorizationValue,
    prior_account: reauthorizationValue.prior_account,
    prior_device: reauthorizationValue.prior_device,
    prior_leaf: reauthorizationValue.prior_leaf,
    new_account: reauthorizationValue.new_account,
    new_device: reauthorizationValue.new_device,
    new_leaf: reauthorizationValue.new_leaf,
    role_id: reauthorizationValue.role_id,
    resource_id: reauthorizationValue.resource_id,
    scope: reauthorizationValue.scope,
    prior_grant_id: reauthorizationValue.prior_grant_id,
    pending_grant_id: reauthorizationValue.pending_grant_id,
    pending_envelope_id: reauthorizationValue.pending_envelope_id,
    effective_at: reauthorizationValue.effective_at,
    expires_at: reauthorizationValue.expires_at,
  }) as WorkspaceSuccessorReauthorizationRecord;
  const reauthorization = Object.freeze({}) as WorkspaceSuccessorReauthorization;
  WORKSPACE_SUCCESSOR_REAUTHORIZATIONS.set(reauthorization, record);
  return { verdict: "accept", reauthorization };
}

function requireSuccessorReauthorizationAtEffect(
  authority: WorkspaceRepositoryResolverAuthority,
  currentState: WorkspaceCurrentState,
  handle: WorkspaceSuccessorReauthorization,
  trustedNow: number,
): Validation<Readonly<{
  current: WorkspaceCurrentStateRecord;
  reauthorization: WorkspaceSuccessorReauthorizationRecord;
}>> {
  const latest = requireLatestCurrentView(authority, currentState, trustedNow);
  if (!latest.ok) return latest;
  const current = latest.value;
  const record = WORKSPACE_SUCCESSOR_REAUTHORIZATIONS.get(handle);
  if (record === undefined) return { ok: false, reason_code: "workspace_schema_invalid" };
  if (record.authority !== authority || record.current_state !== currentState) {
    return { ok: false, reason_code: "workspace_repository_invalid" };
  }
  const object = record.object;
  const unsigned = { ...object };
  delete unsigned.workspace_signature;
  delete unsigned.new_account_signature;
  const payload = proofBytes("heterodyne-workspace-successor-reauthorization-v1", unsigned);
  const checkpoint = current.checkpoints.find((candidate) => candidate.role_id === record.role_id);
  const priorGrant = current.grants.find((grant) => grant.grant_id === record.prior_grant_id);
  const pendingGrant = current.grants.find((grant) => grant.grant_id === record.pending_grant_id);
  const activeGrantIds = new Set(checkpoint !== undefined && isH64Array(checkpoint.active_grant_ids)
    ? checkpoint.active_grant_ids : []);
  const pendingEnvelope = record.pending_envelope_id === null ? null
    : current.envelopes.find((envelope) => envelope.envelope_id === record.pending_envelope_id) ?? null;
  if (typeof object.workspace_signature !== "string"
    || typeof object.new_account_signature !== "string"
    || !validRawSignature(object.workspace_signature, payload, current.state.workspace_key)
    || !validRawSignature(object.new_account_signature, payload, record.new_account)
    || trustedNow < record.effective_at
    || trustedNow >= record.expires_at
    || checkpoint === undefined
    || priorGrant === undefined
    || pendingGrant === undefined
    || !activeGrantIds.has(record.prior_grant_id)
    || activeGrantIds.has(record.pending_grant_id)
    || priorGrant.subject_account !== record.prior_account
    || priorGrant.target_device !== record.prior_device
    || !isRecord(priorGrant.recipient)
    || priorGrant.recipient.value !== record.prior_leaf
    || priorGrant.role_id !== record.role_id
    || pendingGrant.subject_account !== record.new_account
    || pendingGrant.target_device !== record.new_device
    || !isRecord(pendingGrant.recipient)
    || pendingGrant.recipient.value !== record.new_leaf
    || pendingGrant.role_id !== record.role_id
    || current.grants.some((grant) => activeGrantIds.has(String(grant.grant_id))
      && (grant.subject_account === record.new_account
        || grant.target_device === record.new_device
        || (isRecord(grant.recipient) && grant.recipient.value === record.new_leaf)))
    || (record.scope === "resource-key" && (pendingEnvelope === null
      || pendingEnvelope.resource_id !== record.resource_id
      || pendingEnvelope.role_id !== record.role_id
      || pendingEnvelope.target_account !== record.new_account
      || pendingEnvelope.target_device !== record.new_device
      || !isRecord(pendingEnvelope.recipient)
      || pendingEnvelope.recipient.value !== record.new_leaf))
    || current.revocations.some((revocation) =>
      isSafeNonNegativeInteger(revocation.effective_at)
        && revocation.effective_at <= trustedNow
        && ((revocation.target_type === "account"
          && (revocation.target_id === record.prior_account
            || revocation.target_id === record.new_account))
          || (revocation.target_type === "device"
            && (revocation.target_id === record.prior_device
              || revocation.target_id === record.new_device))
          || (revocation.target_type === "grant"
            && (revocation.target_id === record.prior_grant_id
              || revocation.target_id === record.pending_grant_id))
          || (revocation.target_type === "resource"
            && revocation.target_id === record.resource_id)))) {
    return { ok: false, reason_code: "policy_denied" };
  }
  return { ok: true, value: { current, reauthorization: record } };
}

export function evaluateAllowance(value: unknown): WorkspaceVerdict {
  const captured = captureWorkspaceRequest(value, [
    "authority",
    "relationship",
    "source_state",
    "receiving_state",
  ], ["affiliation", "expected_source_account", "requested_capabilities"]);
  const authority = captured?.opaque.authority;
  const relationshipValue = captured?.opaque.relationship;
  const sourceState = captured?.opaque.source_state;
  const receivingState = captured?.opaque.receiving_state;
  const input = captured?.data;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || relationshipValue === null || typeof relationshipValue !== "object"
    || sourceState === null || typeof sourceState !== "object"
    || receivingState === null || typeof receivingState !== "object"
    || input === undefined
    || !isRecord(input.affiliation)
    || !isH64(input.expected_source_account)
    || !isCapabilityArray(input.requested_capabilities)) return rejected("workspace_schema_invalid");
  const relationship = WORKSPACE_CURRENT_RELATIONSHIPS.get(relationshipValue);
  if (relationship === undefined) return rejected("workspace_schema_invalid");
  if (relationship.authority !== authority
    || relationship.source_state !== sourceState
    || relationship.receiving_state !== receivingState) {
    return rejected("workspace_repository_invalid");
  }
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return rejected(trusted.reason_code);
  const currentRelationship = requireCurrentRelationshipAtEffect(
    authority as WorkspaceRepositoryResolverAuthority,
    sourceState as WorkspaceCurrentState,
    receivingState as WorkspaceCurrentState,
    String(relationship.relationship.relationship_id),
    trusted.value.now,
  );
  if (!currentRelationship.ok) return rejected(currentRelationship.reason_code);
  const { source, receiving, source_role: sourceRole, receiving_role: receivingRole } =
    currentRelationship.value;
  const object = currentRelationship.value.relationship;
  const now = trusted.value.now;
  const affiliation = input.affiliation;
  if (!hasExactMembers(affiliation, [
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
    || affiliation.profile !== "heterodyne.workspace-affiliation-evidence.v1"
    || affiliation.spec_version !== "heterodyne/0.5.0"
    || affiliation.relationship_id !== object.relationship_id
    || affiliation.source_workspace_key !== source.state.workspace_key
    || affiliation.source_role_id !== object.source_role_id
    || affiliation.source_account !== input.expected_source_account
    || affiliation.policy_head !== source.state.policy_head
    || affiliation.predecessor !== source.state.predecessor
    || affiliation.authority_checkpoint !== source.state.authority_checkpoint
    || affiliation.repository_rid !== source.state.repository_rid
    || affiliation.repository_head !== source.state.repository_head
    || !isSafeNonNegativeInteger(affiliation.observed_at)
    || !isSafeNonNegativeInteger(affiliation.expires_at)
    || affiliation.observed_at >= affiliation.expires_at
    || affiliation.observed_at > now
    || now >= affiliation.expires_at
    || !isSafeNonNegativeInteger(object.issued_at)
    || affiliation.observed_at < object.issued_at
    || typeof affiliation.signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(affiliation.signature)) {
    return rejected("affiliation_stale");
  }
  const unsignedAffiliation = { ...affiliation };
  delete unsignedAffiliation.signature;
  if (!validRawSignature(
    affiliation.signature,
    proofBytes("heterodyne-workspace-affiliation-evidence-v1", unsignedAffiliation),
    source.state.workspace_key,
  )) return rejected("workspace_signature_invalid");
  const sourceCheckpoint = source.checkpoints.find((checkpoint) =>
    checkpoint.role_id === object.source_role_id);
  if (sourceCheckpoint === undefined || !isH64Array(sourceCheckpoint.active_grant_ids)) {
    return rejected("workspace_repository_invalid");
  }
  const activeGrantIds = new Set(sourceCheckpoint.active_grant_ids);
  const affiliationGrants = source.grants.filter((grant) =>
    activeGrantIds.has(String(grant.grant_id))
      && grant.subject_account === input.expected_source_account
      && grant.role_id === object.source_role_id
      && isSafeNonNegativeInteger(grant.activates_at)
      && grant.activates_at <= now
      && (grant.expires_at === null
        || (isSafeNonNegativeInteger(grant.expires_at) && now < grant.expires_at)));
  const affiliationGrantIds = new Set(affiliationGrants.map((grant) => grant.grant_id));
  if (affiliationGrants.length === 0
    || source.revocations.some((revocation) =>
      isSafeNonNegativeInteger(revocation.effective_at)
        && revocation.effective_at <= now
        && ((revocation.target_type === "account"
          && revocation.target_id === input.expected_source_account)
          || (revocation.target_type === "grant"
            && affiliationGrantIds.has(revocation.target_id))))) {
    return rejected("policy_denied");
  }
  if (!isSafeNonNegativeInteger(object.expires_at)
    || !isSafeNonNegativeInteger(object.proof_max_age)
    || !isSafeNonNegativeInteger(object.grace_period)) {
    return rejected("workspace_schema_invalid");
  }
  if (now >= object.expires_at) return rejected("policy_denied");
  const sourceRolePath = resolveWorkspaceRoleChain(source.roles, String(sourceRole.role_id));
  const receivingRolePath = resolveWorkspaceRoleChain(
    receiving.roles,
    String(receivingRole.role_id),
  );
  if (!sourceRolePath.ok || !receivingRolePath.ok) return rejected("workspace_repository_invalid");
  const qualifyingGrant = affiliationGrants.find((grant) =>
    isCapabilityArray(grant.capabilities)
      && subset(input.requested_capabilities as string[], grant.capabilities)
      && sourceRolePath.value.every((role) => isCapabilityArray(role.allowed_capabilities)
        && subset(input.requested_capabilities as string[], role.allowed_capabilities))
      && receivingRolePath.value.every((role) => isCapabilityArray(role.allowed_capabilities)
        && subset(input.requested_capabilities as string[], role.allowed_capabilities)));
  if (!isCapabilityArray(object.capability_ceiling)
    || !subset(input.requested_capabilities, object.capability_ceiling)
    || qualifyingGrant === undefined
    || input.requested_capabilities.some((capability) => capability.startsWith("govern-"))) {
    return rejected("capability_escalation");
  }
  const proofAge = now - affiliation.observed_at;
  if (!isSafeNonNegativeInteger(proofAge)) return rejected("workspace_schema_invalid");
  const maximumAge = object.proof_max_age + object.grace_period;
  if (!Number.isSafeInteger(maximumAge)) return rejected("workspace_schema_invalid");
  if (proofAge > maximumAge) return rejected("affiliation_stale");
  return accepted({
    capabilities: [...input.requested_capabilities].sort(),
    proof_age: proofAge,
    provisional_grace: proofAge > object.proof_max_age,
    relationship_id: object.relationship_id,
    source_account: affiliation.source_account,
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
  const captured = captureWorkspaceRequest(value, ["authority", "current_state"], [
    "relationship_id",
    "resource_scope",
    "delegate_proofs",
  ]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const input = captured?.data;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || input === undefined
    || !isH64(input.relationship_id)
    || !isH64Array(input.resource_scope)
    || input.resource_scope.length === 0
    || !Array.isArray(input.delegate_proofs)) return rejected("workspace_schema_invalid");
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return rejected(trusted.reason_code);
  const latest = requireLatestCurrentView(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    trusted.value.now,
  );
  if (!latest.ok) return rejected(latest.reason_code);
  const current = latest.value;
  const now = trusted.value.now;
  const joint = current.joint_relationships.find((candidate) =>
    candidate.relationship_id === input.relationship_id);
  if (joint === undefined) return rejected("workspace_repository_invalid");
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
    || now < joint.effective_at
    || (joint.expires_at !== null && now >= joint.expires_at)) {
    return rejected("workspace_schema_invalid");
  }
  if (current.revocations.some((revocation) =>
    revocation.target_type === "relationship"
      && revocation.target_id === joint.relationship_id
      && isSafeNonNegativeInteger(revocation.effective_at)
      && revocation.effective_at <= now)) {
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
      now,
    });
    if (!proof.ok) return rejected(proof.reason_code);
    if (!joint.delegate_keys.includes(proof.value.delegate_key)) {
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
  const captured = captureWorkspaceRequest(value, [
    "authority",
    "current_state",
    "authorization",
    "successor_reauthorization",
  ], [
    "resource_id",
    "custody_host_id",
    "requested_epoch",
    "requested_snapshot_id",
    "target_account",
    "authenticated_account",
    "target_device",
    "recipient",
  ]);
  const authority = captured?.opaque.authority;
  const currentState = captured?.opaque.current_state;
  const authorizationValue = captured?.opaque.authorization;
  const successorValue = captured?.opaque.successor_reauthorization;
  const input = captured?.data;
  if (captured === null
    || authority === null || typeof authority !== "object"
    || currentState === null || typeof currentState !== "object"
    || authorizationValue === null || typeof authorizationValue !== "object"
    || input === undefined
    || !isH64(input.resource_id)
    || !isH64(input.custody_host_id)
    || !isSafeNonNegativeInteger(input.requested_epoch)
    || !(input.requested_snapshot_id === null || isH64(input.requested_snapshot_id))
    || !isH64(input.target_account)
    || !isH64(input.authenticated_account)
    || !isH64(input.target_device)
    || !isRecord(input.recipient)
    || !hasExactMembers(input.recipient, ["type", "value"])
    || input.recipient.type !== "marmot-mls-leaf"
    || typeof input.recipient.value !== "string"
    || !isCanonicalMarmotLeaf(input.recipient.value)) {
    return rejected("workspace_schema_invalid");
  }
  const resourceId = input.resource_id as string;
  const recipient = input.recipient as Readonly<Record<string, unknown>>;
  const trusted = readWorkspaceTrustedNow(authority as WorkspaceRepositoryResolverAuthority);
  if (!trusted.ok) return rejected(trusted.reason_code);
  const effective = requireEffectiveAuthorizationAtEffect(
    authority as WorkspaceRepositoryResolverAuthority,
    currentState as WorkspaceCurrentState,
    authorizationValue as WorkspaceEffectiveAuthorization,
    trusted.value.now,
  );
  if (!effective.ok) return rejected(effective.reason_code);
  const { current, authorization, grant, role_path: rolePath } = effective.value;
  const now = trusted.value.now;
  const resource = current.resources.find((candidate) => candidate.resource_id === resourceId);
  if (resource === undefined) return rejected("resource_unknown");
  if (!isH64Array(resource.key_custody_host_ids)
    || !resource.key_custody_host_ids.includes(input.custody_host_id)) {
    return rejected("host_unauthorized");
  }
  if (!isSafeNonNegativeInteger(resource.key_epoch)
    || input.requested_epoch > resource.key_epoch) return rejected("resource_unknown");
  const operationDigest = bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-key-request-v1",
    {
      authenticated_account: input.authenticated_account,
      custody_host_id: input.custody_host_id,
      recipient,
      requested_epoch: input.requested_epoch,
      requested_snapshot_id: input.requested_snapshot_id,
      resource_id: input.resource_id,
      target_account: input.target_account,
      target_device: input.target_device,
    },
  )));
  if (authorization.operation_digest !== operationDigest
    || authorization.actor_account !== input.authenticated_account
    || !authorization.effective_resources.includes(resourceId)
    || !isCapabilityArray(resource.required_capabilities)
    || !subset(resource.required_capabilities, authorization.effective_capabilities)
    || !isH64Array(grant.resource_scope)
    || !grant.resource_scope.includes(resourceId)
    || !rolePath.some((role) => role.role_id === resource.role_id)) {
    return rejected("capability_escalation");
  }
  if (input.target_account !== input.authenticated_account) {
    if (successorValue === null || typeof successorValue !== "object") {
      return rejected("policy_denied");
    }
    const currentSuccessor = requireSuccessorReauthorizationAtEffect(
      authority as WorkspaceRepositoryResolverAuthority,
      currentState as WorkspaceCurrentState,
      successorValue as WorkspaceSuccessorReauthorization,
      now,
    );
    if (!currentSuccessor.ok) return rejected(currentSuccessor.reason_code);
    const successor = currentSuccessor.value.reauthorization;
    if (successor.scope !== "resource-key"
      || successor.resource_id !== resourceId
      || successor.prior_account !== input.authenticated_account
      || successor.new_account !== input.target_account
      || successor.prior_device !== authorization.actor_device
      || successor.prior_leaf !== authorization.actor_leaf
      || successor.new_device !== input.target_device
      || successor.new_leaf !== recipient.value
      || now >= successor.expires_at) return rejected("policy_denied");
  } else {
    if (successorValue !== null) return rejected("policy_denied");
    if (authorization.actor_account !== input.target_account
      || authorization.actor_device !== input.target_device
      || authorization.actor_leaf !== recipient.value) return rejected("policy_denied");
  }
  const historyRank = (mode: unknown): number => mode === "full" ? 2
    : mode === "from-admission" ? 1
      : mode === "selected-snapshots" ? 0 : -1;
  const historySources = [...rolePath, resource];
  if (isRecord(grant.invitation)) historySources.push(grant.invitation);
  const ranks = historySources.map((source) => historyRank(source.history_mode));
  if (ranks.some((rank) => rank < 0)) return rejected("workspace_repository_invalid");
  const effectiveHistoryRank = Math.min(...ranks);
  const historyMode = effectiveHistoryRank === 2 ? "full"
    : effectiveHistoryRank === 1 ? "from-admission" : "selected-snapshots";
  const resourceEnvelopes = current.envelopes.filter((envelope) =>
    envelope.resource_id === resourceId && isSafeNonNegativeInteger(envelope.key_epoch));
  const resourceStartEpoch = resourceEnvelopes.length === 0
    ? resource.key_epoch as number
    : Math.min(...resourceEnvelopes.map((envelope) => envelope.key_epoch as number));
  const admissionEnvelopes = resourceEnvelopes.filter((envelope) =>
    envelope.target_account === input.target_account
      && envelope.target_device === input.target_device
      && isRecord(envelope.recipient)
      && envelope.recipient.value === recipient.value
      && envelope.role_id === grant.role_id);
  const admissionEpoch = admissionEnvelopes.length === 0
    ? resource.key_epoch as number
    : Math.min(...admissionEnvelopes.map((envelope) => envelope.key_epoch as number));
  const historyStartEpoch = historyMode === "full"
    ? resourceStartEpoch : Math.max(resourceStartEpoch, admissionEpoch);
  if (input.requested_epoch < historyStartEpoch) return rejected("history_denied");
  if (historyMode === "selected-snapshots") {
    const selectedSets = historySources
      .filter((source) => source.history_mode === "selected-snapshots")
      .map((source) => isH64Array(source.selected_snapshots) ? source.selected_snapshots : []);
    const snapshotId = input.requested_snapshot_id;
    const selectedEnvelope = snapshotId === null ? undefined : admissionEnvelopes.find((envelope) =>
      envelope.envelope_id === snapshotId && envelope.key_epoch === input.requested_epoch);
    if (snapshotId === null || selectedEnvelope === undefined
      || !selectedSets.every((selected) => selected.includes(snapshotId))) {
      return rejected("history_denied");
    }
  } else if (input.requested_snapshot_id !== null) {
    return rejected("history_denied");
  }
  return accepted({
    key_epoch: input.requested_epoch,
    target_device: input.target_device,
    recipient: { ...recipient },
    device_bound: true,
    history_start_epoch: historyStartEpoch,
    history_mode: historyMode,
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

function captureWorkspaceRequest(
  value: unknown,
  opaqueMembers: readonly string[],
  dataMembers: readonly string[],
  optionalOpaqueMembers: readonly string[] = [],
): {
  opaque: Readonly<Record<string, unknown>>;
  data: Readonly<Record<string, unknown>>;
} | null {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    const stringKeys = keys.filter((key): key is string => typeof key === "string");
    const presentOptionalMembers = optionalOpaqueMembers.filter((member) =>
      stringKeys.includes(member));
    const expectedMembers = [...opaqueMembers, ...dataMembers, ...presentOptionalMembers].sort();
    if (keys.some((key) => typeof key !== "string")
      || (keys as string[]).sort().join("\0") !== expectedMembers.join("\0")) return null;
    const opaque: Record<string, unknown> = {};
    const data: Record<string, unknown> = {};
    for (const member of expectedMembers) {
      const descriptor = descriptors[member];
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
      if (opaqueMembers.includes(member) || optionalOpaqueMembers.includes(member)) {
        opaque[member] = descriptor.value;
      }
      else data[member] = descriptor.value;
    }
    const snapshot = snapshotJsonRecord(data);
    return snapshot === null ? null : { opaque: Object.freeze(opaque), data: snapshot };
  } catch {
    return null;
  }
}

function isWorkspaceRepositoryTrustAnchor(
  value: unknown,
): value is WorkspaceRepositoryTrustAnchor {
  return isRecord(value)
    && hasExactMembers(value, ["suite", "public_key"])
    && (value.suite === "ed25519" || value.suite === "bip340")
    && isH64(value.public_key);
}

function parseWorkspaceSemver(value: unknown): [number, number, number] | null {
  if (typeof value !== "string"
    || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(value)) return null;
  const result = value.split(".").map(Number);
  return result.every(isSafeNonNegativeInteger)
    ? result as [number, number, number]
    : null;
}

function compareWorkspaceSemver(
  value: unknown,
  minimum: readonly [number, number, number],
): number {
  const parsed = parseWorkspaceSemver(value);
  if (parsed === null) return -1;
  for (let index = 0; index < parsed.length; index += 1) {
    if (parsed[index] !== minimum[index]) return parsed[index] - minimum[index];
  }
  return 0;
}
import { types as utilTypes } from "node:util";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { Ajv } from "ajv";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import { evaluateTrustedSeedAdmission } from "./trusted-seed.js";
import { WORKSPACE_SCHEMAS } from "./workspace-schemas.js";
