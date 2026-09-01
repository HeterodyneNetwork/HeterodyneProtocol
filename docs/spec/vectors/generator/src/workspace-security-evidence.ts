import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./hex.js";
import { proofBytes } from "./proof-bytes.js";
import {
  createWorkspaceRepositoryResolverAuthority,
  ReferenceWorkspaceInvitationAcceptanceStore,
  signWorkspaceObject,
  workspaceObjectId,
  workspaceSigningPayload,
  type WorkspaceRepositoryResolverAuthority,
} from "./workspace.js";

export type WorkspaceSecurityFixture = Readonly<{
  authority: WorkspaceRepositoryResolverAuthority;
  signed_repository_view: Readonly<Record<string, unknown>>;
  grant_id: string;
  subject: string;
  resource: string;
  action: string;
}>;

const WORKSPACE_SECRET = "01".repeat(32);
const SUBJECT_SECRET = "02".repeat(32);
const RESOLVER_SECRET = "07".repeat(32);
const WORKSPACE_KEY = bytesToHex(schnorr.getPublicKey(WORKSPACE_SECRET));
const SUBJECT = bytesToHex(schnorr.getPublicKey(SUBJECT_SECRET));
const RESOLVER_KEY = bytesToHex(schnorr.getPublicKey(RESOLVER_SECRET));
const POLICY_HEAD = "21".repeat(32);
const ROOT_ROLE_ID = "31".repeat(32);
const ROOT_CHECKPOINT_ID = "41".repeat(32);
const GRANT_ID = "51".repeat(32);
const RESOURCE_ID = "61".repeat(32);
const REVOCATION_ID = "71".repeat(32);
const RELATIONSHIP_ID = "72".repeat(32);
const DEVICE_ID = "81".repeat(32);
const HOST_ID = "91".repeat(32);
const REPOSITORY_HEAD = "a1".repeat(20);
const NOW = 1_720_000_400;
const OBSERVED_AT = 1_720_000_100;
const EXPIRES_AT = 1_720_000_700;
const LEAF = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const deepFreeze = <T>(value: T): T => {
  if (value !== null && typeof value === "object") {
    for (const member of Object.values(value as Record<string, unknown>)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
};

const invitationNonceCommitment = (nonceOpening: string): string => bytesToHex(sha256(proofBytes(
  "heterodyne-workspace-invitation-nonce-v1",
  {
    grant_id: GRANT_ID,
    workspace_key: WORKSPACE_KEY,
    subject_account: SUBJECT,
    target_device: DEVICE_ID,
    target_leaf: LEAF,
    nonce_opening: nonceOpening,
  },
)));

export function buildWorkspaceSecurityFixture(input: Readonly<{
  root_capabilities: readonly string[];
  ancestor_capabilities: readonly (readonly string[])[];
  grant_capabilities: readonly string[];
  revoked: boolean;
}>): WorkspaceSecurityFixture {
  const common = {
    spec_version: "heterodyne/0.6.0",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: null,
    authority_checkpoint: ROOT_CHECKPOINT_ID,
    repository_rid: "rad:zWorkspaceSecurityFixture",
    repository_head: REPOSITORY_HEAD,
    issued_at: OBSERVED_AT,
  };
  const policy = signWorkspaceObject({
    ...common,
    object_type: "workspace-policy-v1",
    policy_id: POLICY_HEAD,
    sequence: 1,
    governance: { threshold: 1, controllers: [WORKSPACE_KEY] },
    visibility_ceiling: "private",
    allowed_role_types: ["member"],
    allow_public_resources: false,
    allow_bilateral_relationships: true,
    default_host_ids: [HOST_ID],
    ordinary_write_max_age: 86_400,
    authority_mutation_max_age: 300,
  }, WORKSPACE_SECRET);
  const roleCapabilities = [input.root_capabilities, ...input.ancestor_capabilities];
  const roles = roleCapabilities.map((capabilities, index) => signWorkspaceObject({
    ...common,
    object_type: "role-manifest-v1",
    role_id: index === 0 ? ROOT_ROLE_ID : (31 + index).toString(16).padStart(2, "0").repeat(32),
    parent_role_id: index === 0
      ? null
      : index === 1
        ? ROOT_ROLE_ID
        : (30 + index).toString(16).padStart(2, "0").repeat(32),
    role_type: "member",
    visibility: "private",
    allowed_capabilities: [...capabilities],
    history_mode: index === 0 ? "full" : "from-admission",
    selected_snapshots: [],
    administrator_account: WORKSPACE_KEY,
    marmot_h: `synthetic-role-${index}`,
    active_event_repository: {
      repository_rid: `rad:zWorkspaceEvents${index}`,
      mls_epoch: 1,
    },
    overlap_event_repository: null,
    archived_event_repositories: [],
  }, WORKSPACE_SECRET));
  const grantRole = roles[roles.length - 1] as Record<string, unknown>;
  const nonceOpening = "b1".repeat(32);
  const unsignedGrant = {
    ...common,
    object_type: "role-grant-v1",
    grant_id: GRANT_ID,
    subject_account: SUBJECT,
    target_device: DEVICE_ID,
    recipient: { type: "marmot-mls-leaf", value: LEAF },
    role_id: grantRole.role_id,
    capabilities: [...input.grant_capabilities],
    resource_scope: [RESOURCE_ID],
    delegable: false,
    activation: "subject-acceptance",
    activates_at: OBSERVED_AT,
    expires_at: EXPIRES_AT,
    approval_ids: [],
    invitation: {
      nonce_commitment: invitationNonceCommitment(nonceOpening),
      expires_at: EXPIRES_AT,
      history_mode: "from-admission",
    },
    evidence_ids: [],
  };
  const grantOperation: Record<string, unknown> = { ...unsignedGrant };
  delete grantOperation.approval_ids;
  const grantOperationDigest = bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-grant-operation-v1",
    grantOperation,
  )));
  const unsignedApproval = {
    profile: "heterodyne.workspace-grant-approval.v1",
    spec_version: "heterodyne/0.6.0",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: null,
    authority_checkpoint: ROOT_CHECKPOINT_ID,
    operation_digest: grantOperationDigest,
    approver_key: WORKSPACE_KEY,
    issued_at: 1_720_000_200,
    expires_at: 1_720_000_650,
  };
  const approval = {
    ...unsignedApproval,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-grant-approval-v1", unsignedApproval),
      WORKSPACE_SECRET,
      "00".repeat(32),
    )),
  };
  const grant = signWorkspaceObject({
    ...unsignedGrant,
    approval_ids: [workspaceObjectId(approval)],
  }, WORKSPACE_SECRET);
  const revocation = signWorkspaceObject({
    ...common,
    object_type: "role-revocation-v1",
    revocation_id: REVOCATION_ID,
    target_type: "grant",
    target_id: GRANT_ID,
    effective_at: input.revoked ? NOW : EXPIRES_AT + 1,
    reason: "synthetic fixture revocation",
  }, WORKSPACE_SECRET);
  const resource = signWorkspaceObject({
    ...common,
    object_type: "resource-advertisement-v1",
    resource_id: RESOURCE_ID,
    role_id: grantRole.role_id,
    resource_type: "project",
    visibility: "private",
    locators: ["rad:zWorkspaceSecurityResource"],
    required_capabilities: [input.grant_capabilities.find((capability) =>
      capability === "read") ?? input.grant_capabilities[0] ?? "read"],
    key_epoch: 1,
    history_mode: "from-admission",
    selected_snapshots: [],
    retention_seconds: null,
    host_ids: [HOST_ID],
    key_custody_host_ids: [HOST_ID],
    repository_owner_key: WORKSPACE_KEY,
    repository_writer_nids: [],
    trusted_seed_nids: [],
  }, WORKSPACE_SECRET);
  const relationshipCapabilities = input.grant_capabilities.filter((capability) =>
    input.root_capabilities.includes(capability)
      && input.ancestor_capabilities.every((ancestor) => ancestor.includes(capability))
      && !capability.startsWith("govern-"));
  const relationship = signWorkspaceObject({
    ...common,
    object_type: "workspace-relationship-v1",
    relationship_id: RELATIONSHIP_ID,
    source_workspace_key: WORKSPACE_KEY,
    receiving_workspace_key: SUBJECT,
    source_role_id: grantRole.role_id,
    receiving_role_id: "a3".repeat(32),
    capability_ceiling: relationshipCapabilities,
    proof_max_age: 300,
    grace_period: 0,
    expires_at: EXPIRES_AT,
    independently_revocable: true,
    receiving_policy_head: "a4".repeat(32),
    receiving_predecessor: null,
    receiving_authority_checkpoint: "a5".repeat(32),
    receiving_signature: "00".repeat(64),
  }, WORKSPACE_SECRET);
  relationship.receiving_signature = bytesToHex(schnorr.sign(
    workspaceSigningPayload(relationship),
    SUBJECT_SECRET,
    "00".repeat(32),
  ));
  const checkpoints = roles.map((role, index) => {
    const roleId = String(role.role_id);
    const checkpointId = index === 0
      ? ROOT_CHECKPOINT_ID
      : (41 + index).toString(16).padStart(2, "0").repeat(32);
    return signWorkspaceObject({
      ...common,
      object_type: "role-checkpoint-v1",
      checkpoint_id: checkpointId,
      role_id: roleId,
      sequence: 1,
      materialized_at: OBSERVED_AT,
      workspace_policy_head: POLICY_HEAD,
      role_policy_heads: roles.slice(0, index + 1).map(workspaceObjectId).sort(),
      active_grant_ids: index === roles.length - 1 ? [GRANT_ID] : [],
      revocation_ids: [REVOCATION_ID],
      relationship_ids: index === roles.length - 1 ? [RELATIONSHIP_ID] : [],
      host_ids: [],
      resource_ids: index === roles.length - 1 ? [RESOURCE_ID] : [],
      seed_nids: [],
      previous_checkpoint: null,
    }, WORKSPACE_SECRET);
  });
  const objects = deepFreeze([
    policy,
    ...roles,
    grant,
    revocation,
    resource,
    relationship,
    ...checkpoints,
  ]);
  const objectIds = objects.map(workspaceObjectId).sort();
  const unsignedEvidence = {
    profile: "heterodyne.workspace-repository-view.v1",
    spec_version: "heterodyne/0.6.0",
    resolver_policy: "radicle-verified-complete-v1",
    resolver_version: "1.0.0",
    workspace_key: WORKSPACE_KEY,
    repository_rid: "rad:zWorkspaceSecurityFixture",
    canonical_head: REPOSITORY_HEAD,
    canonical_ancestry: [REPOSITORY_HEAD],
    observed_heads: [REPOSITORY_HEAD],
    fork_status: "complete",
    policy_head: POLICY_HEAD,
    predecessor: null,
    authority_checkpoint: ROOT_CHECKPOINT_ID,
    policy_history: [{
      policy_head: POLICY_HEAD,
      predecessor: null,
      assurance: null,
      authorization: null,
    }],
    object_ids: objectIds,
    object_set_digest: bytesToHex(sha256(proofBytes(
      "heterodyne-workspace-object-set-v1",
      { object_ids: objectIds },
    ))),
    observed_at: OBSERVED_AT,
    expires_at: EXPIRES_AT,
  };
  const evidence = deepFreeze({
    ...unsignedEvidence,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-repository-view-v1", unsignedEvidence),
      RESOLVER_SECRET,
      "00".repeat(32),
    )),
  });
  const authority = createWorkspaceRepositoryResolverAuthority({
    trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
    allowed_policies: ["radicle-verified-complete-v1"],
    minimum_version: "1.0.0",
    max_ttl: 600,
    max_view_age: 300,
    repositories: [{
      workspace_key: WORKSPACE_KEY,
      repository_rid: "rad:zWorkspaceSecurityFixture",
      pinned_head: REPOSITORY_HEAD,
    }],
    trusted_now: () => NOW,
    invitation_store: new ReferenceWorkspaceInvitationAcceptanceStore(),
  });
  const signedRepositoryView = Object.freeze({ authority, evidence, objects });
  return Object.freeze({
    authority,
    signed_repository_view: signedRepositoryView,
    grant_id: GRANT_ID,
    subject: SUBJECT,
    resource: RESOURCE_ID,
    action: input.grant_capabilities.find((capability) => capability !== "invite")
      ?? input.grant_capabilities[0] ?? "read",
  });
}
