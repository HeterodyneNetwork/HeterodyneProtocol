import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";
import { trustedSeedAclProofBytes } from "./trusted-seed.js";
import {
  authenticateWorkspaceRepositoryView,
  authenticateWorkspaceSuccessorReauthorization,
  consumeWorkspaceInvitationAcceptance,
  evaluateAllowance,
  evaluateAuthorization,
  evaluateFreshness,
  evaluateGrantActivation,
  evaluateJointGovernance,
  evaluateKeyRequest,
  evaluatePrivateProjection,
  evaluateRoleLeafChange,
  evaluateWorkspaceObject,
  evaluateWorkspacePrivateRelay,
  eventsAreByteIdentical,
  resolveEffectiveHosts,
  resolveWorkspaceCurrentRelationship,
  resolveWorkspaceEffectiveAuthorization,
  selectEventRepository,
  signWorkspaceObject,
  workspaceObjectId,
  workspaceSigningPayload,
} from "./workspace.js";

const H64 = "11".repeat(32);
const H40 = "33".repeat(20);
const WORKSPACE_SECRET = "01".repeat(32);
const WORKSPACE_KEY = bytesToHex(schnorr.getPublicKey(WORKSPACE_SECRET));
const OTHER_SECRET = "02".repeat(32);
const OTHER_KEY = bytesToHex(schnorr.getPublicKey(OTHER_SECRET));
const CHECKPOINT = "44".repeat(32);
const POLICY_HEAD = "55".repeat(32);
const PREDECESSOR = "66".repeat(32);
const LEAF = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NEW_DEVICE = "ab".repeat(32);
const NEW_LEAF = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const APPROVER_A_SECRET = "03".repeat(32);
const APPROVER_A_KEY = bytesToHex(schnorr.getPublicKey(APPROVER_A_SECRET));
const APPROVER_B_SECRET = "04".repeat(32);
const APPROVER_B_KEY = bytesToHex(schnorr.getPublicKey(APPROVER_B_SECRET));
const JOINT_SECRET = "05".repeat(32);
const JOINT_KEY = bytesToHex(schnorr.getPublicKey(JOINT_SECRET));
const UNAUTHORIZED_APPROVER_SECRET = "06".repeat(32);
const RESOLVER_SECRET = "07".repeat(32);
const RESOLVER_KEY = bytesToHex(schnorr.getPublicKey(RESOLVER_SECRET));
const RESOURCE_ID = "aa".repeat(32);
const ACTOR_GRANT_ID = "bb".repeat(32);
const REVOCATION_ID = "cc".repeat(32);

const currentState = (workspaceKey = WORKSPACE_KEY) => ({
  workspace_key: workspaceKey,
  policy_head: POLICY_HEAD,
  predecessor: PREDECESSOR,
  authority_checkpoint: CHECKPOINT,
  repository_rid: "rad:zWorkspace",
  repository_head: H40,
  repository_ancestry: [H40],
  authority_checkpoint_candidates: [CHECKPOINT],
  competing_repository_heads: [] as string[],
});

const objectDigest = (value: unknown): string => bytesToHex(
  sha256(utf8Bytes(jcsCanonicalize(value))),
);

const grantOperationDigest = (grant: Record<string, unknown>): string => {
  const operation = { ...grant };
  delete operation.signature;
  delete operation.approval_ids;
  return bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-grant-operation-v1",
    operation,
  )));
};

const grantApproval = (
  operationDigest: string,
  secretKey: string,
): Record<string, unknown> => {
  const approver_key = bytesToHex(schnorr.getPublicKey(secretKey));
  const unsigned = {
    profile: "heterodyne.workspace-grant-approval.v1",
    spec_version: "heterodyne/0.5.0",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    operation_digest: operationDigest,
    approver_key,
    issued_at: 1_720_000_000,
    expires_at: 1_720_001_000,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-grant-approval-v1", unsigned),
      secretKey,
    )),
  };
};

const invitationNonceCommitment = (
  grantId: string,
  nonceOpening: string,
): string => bytesToHex(sha256(proofBytes(
  "heterodyne-workspace-invitation-nonce-v1",
  {
    grant_id: grantId,
    workspace_key: WORKSPACE_KEY,
    subject_account: OTHER_KEY,
    target_device: H64,
    target_leaf: LEAF,
    nonce_opening: nonceOpening,
  },
)));

const invitationAcceptance = (
  grantId: string,
  operationDigest: string,
  viewId: string,
  nonceOpening: string,
  expiresAt = 1_720_000_600,
): Record<string, unknown> => {
  const unsigned = {
    profile: "heterodyne.workspace-invitation-acceptance.v1",
    spec_version: "heterodyne/0.5.0",
    grant_id: grantId,
    grant_operation_digest: operationDigest,
    workspace_key: WORKSPACE_KEY,
    subject_account: OTHER_KEY,
    target_device: H64,
    target_leaf: LEAF,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_view_id: viewId,
    nonce_opening: nonceOpening,
    nonce_commitment: invitationNonceCommitment(grantId, nonceOpening),
    issued_at: 1_720_000_200,
    expires_at: expiresAt,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-invitation-acceptance-v1", unsigned),
      OTHER_SECRET,
    )),
  };
};

const successorReauthorization = (
  viewId: string,
  scope: "role-membership" | "resource-key",
  pendingGrantId = "ac".repeat(32),
  pendingEnvelopeId: string | null = scope === "resource-key" ? "ad".repeat(32) : null,
  pendingBinding: Record<string, unknown> = {},
): Record<string, unknown> => {
  const unsigned = {
    profile: "heterodyne.workspace-successor-reauthorization.v1",
    spec_version: "heterodyne/0.5.0",
    workspace_key: WORKSPACE_KEY,
    prior_account: OTHER_KEY,
    new_account: APPROVER_A_KEY,
    prior_key: OTHER_KEY,
    new_key: APPROVER_A_KEY,
    prior_device: H64,
    prior_leaf: LEAF,
    new_device: NEW_DEVICE,
    new_leaf: NEW_LEAF,
    role_id: H64,
    resource_id: scope === "resource-key" ? RESOURCE_ID : null,
    scope,
    prior_grant_id: ACTOR_GRANT_ID,
    pending_grant_id: pendingGrantId,
    pending_envelope_id: pendingEnvelopeId,
    pending_key_epoch: scope === "resource-key" ? 1 : null,
    pending_custody_host_id: scope === "resource-key" ? "dd".repeat(32) : null,
    pending_checkpoint_id: scope === "resource-key" ? CHECKPOINT : null,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_view_id: viewId,
    issued_at: 1_720_000_200,
    effective_at: 1_720_000_300,
    expires_at: 1_720_000_600,
    ...pendingBinding,
  };
  const payload = proofBytes("heterodyne-workspace-successor-reauthorization-v1", unsigned);
  return {
    ...unsigned,
    workspace_signature: bytesToHex(schnorr.sign(payload, WORKSPACE_SECRET)),
    new_account_signature: bytesToHex(schnorr.sign(payload, APPROVER_A_SECRET)),
  };
};

const keyRequestDigest = (request: Record<string, unknown>): string => bytesToHex(sha256(proofBytes(
  "heterodyne-workspace-key-request-v1",
  {
    authenticated_account: request.authenticated_account,
    custody_host_id: request.custody_host_id,
    recipient: request.recipient,
    requested_epoch: request.requested_epoch,
    requested_snapshot_id: request.requested_snapshot_id,
    resource_id: request.resource_id,
    target_account: request.target_account,
    target_device: request.target_device,
  },
)));

const grantActivationFixture = () => {
  const unsignedGrant = {
    spec_version: "heterodyne/0.5.0",
    object_type: "role-grant-v1",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_rid: "rad:zWorkspace",
    repository_head: H40,
    issued_at: 1_720_000_010,
    grant_id: H64,
    subject_account: OTHER_KEY,
    target_device: H64,
    recipient: { type: "marmot-mls-leaf", value: LEAF },
    role_id: CHECKPOINT,
    capabilities: ["read"],
    resource_scope: [H64],
    delegable: false,
    activation: "subject-acceptance",
    activates_at: 1_720_000_010,
    expires_at: 1_720_001_000,
    approval_ids: [] as string[],
    invitation: {
      nonce_commitment: "77".repeat(32),
      expires_at: 1_720_001_000,
      history_mode: "from-admission",
    },
    evidence_ids: [] as string[],
  };
  const operationDigest = grantOperationDigest(unsignedGrant);
  const approvals = [
    grantApproval(operationDigest, APPROVER_A_SECRET),
    grantApproval(operationDigest, APPROVER_B_SECRET),
  ];
  const grant = signWorkspaceObject({
    ...unsignedGrant,
    approval_ids: approvals.map(objectDigest).sort(),
  }, WORKSPACE_SECRET);
  const authorization = {
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    authority_checkpoint_candidates: [CHECKPOINT],
    actor_account: OTHER_KEY,
    operation_digest: operationDigest,
    requested_capabilities: ["invite", "read"],
    capability_ceilings: [
      ["invite", "read", "write"],
      ["invite", "read"],
      ["invite", "read", "triage"],
    ],
    requested_resources: [H64],
    resource_ceilings: [[H64, CHECKPOINT], [H64]],
    requested_delegable: false,
    delegable_ceilings: [true, false],
    approval_key_ceilings: [
      [APPROVER_A_KEY, APPROVER_B_KEY],
      [APPROVER_B_KEY, APPROVER_A_KEY],
    ],
    device_active: true,
    denial_ids: [] as string[],
    revocation_effective_at: [] as number[],
    authority_source: "workspace-policy",
    now: 1_720_000_100,
  };
  return {
    grant,
    current: currentState(),
    authorization,
    membership: {
      authenticated_account: OTHER_KEY,
      accepted_device: H64,
      accepted_leaf: LEAF,
      successor_reauthorization_id: "88".repeat(32),
    },
    required_approvals: 2,
    approvals,
    subject_acceptance_id: "99".repeat(32),
    consumed_invitation_grant_ids: [] as string[],
    now: 1_720_000_100,
  };
};

const signedRelationship = (): Record<string, unknown> => {
  const relationship = signWorkspaceObject({
    spec_version: "heterodyne/0.5.0",
    object_type: "workspace-relationship-v1",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_rid: "rad:zWorkspace",
    repository_head: H40,
    issued_at: 1_720_000_000,
    relationship_id: H64,
    source_workspace_key: WORKSPACE_KEY,
    receiving_workspace_key: OTHER_KEY,
    source_role_id: H64,
    receiving_role_id: "22".repeat(32),
    capability_ceiling: ["read", "triage"],
    proof_max_age: 300,
    grace_period: 600,
    expires_at: 1_720_086_400,
    independently_revocable: true,
    receiving_policy_head: "77".repeat(32),
    receiving_predecessor: "88".repeat(32),
    receiving_authority_checkpoint: "99".repeat(32),
    receiving_signature: "00".repeat(64),
  }, WORKSPACE_SECRET);
  relationship.receiving_signature = bytesToHex(schnorr.sign(
    workspaceSigningPayload(relationship),
    OTHER_SECRET,
  ));
  return relationship;
};

const signedRelationshipReceipt = (
  relationship: Record<string, unknown>,
): Record<string, unknown> => signWorkspaceObject({
  spec_version: "heterodyne/0.5.0",
  object_type: "workspace-relationship-receipt-v1",
  workspace_key: OTHER_KEY,
  policy_head: "77".repeat(32),
  predecessor: "88".repeat(32),
  authority_checkpoint: "99".repeat(32),
  repository_rid: "rad:zReceiving",
  repository_head: H40,
  issued_at: 1_720_000_100,
  receipt_id: "d1".repeat(32),
  relationship_id: relationship.relationship_id,
  receiving_role_id: relationship.receiving_role_id,
  source_workspace_key: WORKSPACE_KEY,
  source_relationship_object_id: objectDigest(relationship),
  source_policy_head: POLICY_HEAD,
  source_predecessor: PREDECESSOR,
  source_authority_checkpoint: CHECKPOINT,
  source_repository_rid: "rad:zWorkspace",
  source_repository_head: H40,
  received_at: 1_720_000_100,
}, OTHER_SECRET);

const affiliationEvidence = (
  observedAt = 1_720_000_100,
  repositoryHead = H40,
): Record<string, unknown> => {
  const unsigned = {
    profile: "heterodyne.workspace-affiliation-evidence.v1",
    spec_version: "heterodyne/0.5.0",
    relationship_id: H64,
    source_workspace_key: WORKSPACE_KEY,
    source_role_id: H64,
    source_account: OTHER_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_rid: "rad:zWorkspace",
    repository_head: repositoryHead,
    observed_at: observedAt,
    expires_at: 1_720_010_000,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-affiliation-evidence-v1", unsigned),
      WORKSPACE_SECRET,
    )),
  };
};

const allowanceFixture = () => {
  const relationship = signedRelationship();
  return {
    relationship,
    expected_relationship_object_id: objectDigest(relationship),
    source_current: currentState(),
    receiving_current: {
      ...currentState(OTHER_KEY),
      policy_head: "77".repeat(32),
      predecessor: "88".repeat(32),
      authority_checkpoint: "99".repeat(32),
      authority_checkpoint_candidates: ["99".repeat(32)],
      repository_rid: "rad:zReceiving",
    },
    affiliation: affiliationEvidence(),
    expected_source_account: OTHER_KEY,
    requested_capabilities: ["read"],
    revocation_effective_at: null,
    now: 1_720_000_400,
  };
};

const jointOperationDigest = (resourceScope: string[]): string => bytesToHex(sha256(proofBytes(
  "heterodyne-workspace-joint-operation-v1",
  {
    relationship_id: H64,
    workspace_key: JOINT_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    resource_scope: resourceScope,
  },
)));

const jointDelegateProof = (
  resourceScope: string[],
  secretKey: string,
): Record<string, unknown> => {
  const delegate_key = bytesToHex(schnorr.getPublicKey(secretKey));
  const unsigned = {
    profile: "heterodyne.workspace-joint-delegate.v1",
    spec_version: "heterodyne/0.5.0",
    joint_workspace_key: JOINT_KEY,
    relationship_id: H64,
    delegate_key,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    operation_digest: jointOperationDigest(resourceScope),
    resource_scope: resourceScope,
    issued_at: 1_720_000_000,
    expires_at: 1_720_001_000,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-joint-delegate-v1", unsigned),
      secretKey,
    )),
  };
};

const jointGovernanceFixture = (threshold = 2) => {
  const joint = signWorkspaceObject({
    spec_version: "heterodyne/0.5.0",
    object_type: "joint-workspace-relationship-v1",
    workspace_key: JOINT_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_rid: "rad:zWorkspace",
    repository_head: H40,
    issued_at: 1_720_000_000,
    relationship_id: H64,
    joint_workspace_key: JOINT_KEY,
    participant_workspace_keys: [WORKSPACE_KEY, OTHER_KEY],
    delegate_keys: [APPROVER_A_KEY, APPROVER_B_KEY],
    threshold,
    resource_scope: [RESOURCE_ID],
    effective_at: 1_720_000_000,
    expires_at: 1_720_001_000,
  }, JOINT_SECRET);
  return {
    joint,
    expected_joint_object_id: objectDigest(joint),
    current: currentState(JOINT_KEY),
    configured_delegate_keys: [APPROVER_A_KEY, APPROVER_B_KEY],
    resource_scope: [RESOURCE_ID],
    delegate_proofs: [
      jointDelegateProof([RESOURCE_ID], APPROVER_A_SECRET),
      jointDelegateProof([RESOURCE_ID], APPROVER_B_SECRET),
    ],
    now: 1_720_000_100,
  };
};

const jointAuthorityObjects = (threshold = 2): Record<string, unknown>[] => {
  const base = currentAuthorityObjects().map((source) => {
    const unsigned: Record<string, unknown> = {
      ...source,
      workspace_key: JOINT_KEY,
      repository_rid: "rad:zJoint",
    };
    delete unsigned.signature;
    if (unsigned.object_type === "role-manifest-v1") {
      unsigned.administrator_account = JOINT_KEY;
    }
    if (unsigned.object_type === "resource-advertisement-v1") {
      unsigned.repository_owner_key = JOINT_KEY;
    }
    if (unsigned.object_type === "role-checkpoint-v1") {
      unsigned.relationship_ids = [H64];
    }
    return signWorkspaceObject(unsigned, JOINT_SECRET);
  });
  base[5] = signWorkspaceObject({
    ...base[5],
    role_policy_heads: [objectDigest(base[1])],
  }, JOINT_SECRET);
  base[3] = signWorkspaceObject({
    ...base[3],
    target_type: "resource",
    target_id: RESOURCE_ID,
    effective_at: 1_720_000_150,
  }, JOINT_SECRET);
  const fixture = jointGovernanceFixture(threshold).joint;
  const unsignedJoint = {
    ...fixture,
    repository_rid: "rad:zJoint",
  } as Record<string, unknown>;
  delete unsignedJoint.signature;
  base.push(signWorkspaceObject(unsignedJoint, JOINT_SECRET));
  return base;
};

const currentAuthorityObjects = (): Record<string, unknown>[] => {
  const common = {
    spec_version: "heterodyne/0.5.0",
    workspace_key: WORKSPACE_KEY,
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    repository_rid: "rad:zWorkspace",
    repository_head: H40,
    issued_at: 1_720_000_000,
  };
  const policy = signWorkspaceObject({
    ...common,
    object_type: "workspace-policy-v1",
    policy_id: POLICY_HEAD,
    sequence: 1,
    governance: {
      threshold: 2,
      controllers: [APPROVER_A_KEY, APPROVER_B_KEY],
    },
    visibility_ceiling: "private",
    allowed_role_types: ["member"],
    allow_public_resources: false,
    allow_bilateral_relationships: true,
    default_host_ids: ["dd".repeat(32)],
    ordinary_write_max_age: 86_400,
    authority_mutation_max_age: 300,
  }, WORKSPACE_SECRET);
  const role = signWorkspaceObject({
    ...common,
    object_type: "role-manifest-v1",
    role_id: H64,
    parent_role_id: null,
    role_type: "member",
    visibility: "private",
    allowed_capabilities: ["invite", "read", "write", "govern-delegation"],
    history_mode: "full",
    selected_snapshots: [],
    administrator_account: WORKSPACE_KEY,
    marmot_h: "role-routing-id",
    active_event_repository: { repository_rid: "rad:zEvents", mls_epoch: 7 },
    overlap_event_repository: null,
    archived_event_repositories: [],
  }, WORKSPACE_SECRET);
  const actorGrant = signWorkspaceObject({
    ...common,
    object_type: "role-grant-v1",
    grant_id: ACTOR_GRANT_ID,
    subject_account: OTHER_KEY,
    target_device: H64,
    recipient: { type: "marmot-mls-leaf", value: LEAF },
    role_id: H64,
    capabilities: ["invite", "read", "write", "govern-delegation"],
    resource_scope: [RESOURCE_ID],
    delegable: true,
    activation: "immediate",
    activates_at: 1_720_000_000,
    expires_at: null,
    approval_ids: [],
    invitation: null,
    evidence_ids: [],
  }, WORKSPACE_SECRET);
  const revocation = signWorkspaceObject({
    ...common,
    object_type: "role-revocation-v1",
    revocation_id: REVOCATION_ID,
    target_type: "grant",
    target_id: ACTOR_GRANT_ID,
    effective_at: 1_720_010_000,
    reason: "future authority removal",
  }, WORKSPACE_SECRET);
  const resource = signWorkspaceObject({
    ...common,
    object_type: "resource-advertisement-v1",
    resource_id: RESOURCE_ID,
    role_id: H64,
    resource_type: "project",
    visibility: "private",
    locators: ["rad:zResource"],
    required_capabilities: ["read"],
    key_epoch: 1,
    history_mode: "full",
    selected_snapshots: [],
    retention_seconds: null,
    host_ids: ["dd".repeat(32)],
    key_custody_host_ids: ["dd".repeat(32)],
    repository_owner_key: WORKSPACE_KEY,
    repository_writer_nids: [],
    trusted_seed_nids: [],
  }, WORKSPACE_SECRET);
  const checkpoint = signWorkspaceObject({
    ...common,
    object_type: "role-checkpoint-v1",
    checkpoint_id: CHECKPOINT,
    role_id: H64,
    sequence: 1,
    materialized_at: 1_720_000_000,
    workspace_policy_head: POLICY_HEAD,
    role_policy_heads: [objectDigest(role)],
    active_grant_ids: [ACTOR_GRANT_ID],
    revocation_ids: [REVOCATION_ID],
    relationship_ids: [],
    host_ids: [],
    resource_ids: [RESOURCE_ID],
    seed_nids: [],
    previous_checkpoint: null,
  }, WORKSPACE_SECRET);
  return [policy, role, actorGrant, revocation, resource, checkpoint];
};

const receivingAuthorityObjects = (): Record<string, unknown>[] => {
  const receivingPolicy = "77".repeat(32);
  const receivingPredecessor = "88".repeat(32);
  const receivingCheckpoint = "99".repeat(32);
  const receiving = currentAuthorityObjects().map((source) => {
    const unsigned: Record<string, unknown> = {
      ...source,
      workspace_key: OTHER_KEY,
      policy_head: receivingPolicy,
      predecessor: receivingPredecessor,
      authority_checkpoint: receivingCheckpoint,
      repository_rid: "rad:zReceiving",
    };
    delete unsigned.signature;
    if (unsigned.object_type === "workspace-policy-v1") {
      unsigned.policy_id = receivingPolicy;
    }
    if (unsigned.object_type === "role-manifest-v1") {
      unsigned.role_id = "22".repeat(32);
      unsigned.administrator_account = OTHER_KEY;
    }
    if (unsigned.object_type === "role-grant-v1") {
      unsigned.role_id = "22".repeat(32);
      unsigned.subject_account = WORKSPACE_KEY;
    }
    if (unsigned.object_type === "resource-advertisement-v1") {
      unsigned.role_id = "22".repeat(32);
      unsigned.repository_owner_key = OTHER_KEY;
    }
    if (unsigned.object_type === "role-checkpoint-v1") {
      unsigned.checkpoint_id = receivingCheckpoint;
      unsigned.role_id = "22".repeat(32);
      unsigned.workspace_policy_head = receivingPolicy;
    }
    return signWorkspaceObject(unsigned, OTHER_SECRET);
  });
  const receivingRole = receiving.find((object) => object.object_type === "role-manifest-v1");
  const checkpointIndex = receiving.findIndex((object) => object.object_type === "role-checkpoint-v1");
  receiving[checkpointIndex] = signWorkspaceObject({
    ...receiving[checkpointIndex],
    role_policy_heads: [objectDigest(receivingRole as Record<string, unknown>)],
  }, OTHER_SECRET);
  return receiving;
};

const repositoryViewEvidence = (
  objects: Record<string, unknown>[],
  changed: Record<string, unknown> = {},
): Record<string, unknown> => {
  const object_ids = objects.map(objectDigest).sort();
  const unsigned = {
    profile: "heterodyne.workspace-repository-view.v1",
    spec_version: "heterodyne/0.5.0",
    resolver_policy: "radicle-verified-complete-v1",
    resolver_version: "1.0.0",
    workspace_key: WORKSPACE_KEY,
    repository_rid: "rad:zWorkspace",
    canonical_head: H40,
    canonical_ancestry: [H40],
    observed_heads: [H40],
    fork_status: "complete",
    policy_head: POLICY_HEAD,
    predecessor: PREDECESSOR,
    authority_checkpoint: CHECKPOINT,
    object_ids,
    object_set_digest: bytesToHex(sha256(proofBytes(
      "heterodyne-workspace-object-set-v1",
      { object_ids },
    ))),
    observed_at: 1_720_000_100,
    expires_at: 1_720_000_700,
    ...changed,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-repository-view-v1", unsigned),
      RESOLVER_SECRET,
    )),
  };
};

describe("Workspace configured repository resolver", () => {
  it("mints current state only from configured, complete, current repository evidence", async () => {
    const api = await import("./workspace.js") as typeof import("./workspace.js") & {
      createWorkspaceRepositoryResolverAuthority?: (input: unknown) => object;
      authenticateWorkspaceRepositoryView?: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        state?: object;
      };
    };
    expect(api.createWorkspaceRepositoryResolverAuthority).toBeTypeOf("function");
    expect(api.authenticateWorkspaceRepositoryView).toBeTypeOf("function");
    const authority = api.createWorkspaceRepositoryResolverAuthority?.({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => 1_720_000_400,
    });
    const objects = currentAuthorityObjects();
    for (const object of objects) {
      expect(evaluateWorkspaceObject({
        object,
        expected_object_id: objectDigest(object),
        current: currentState(),
      }), String(object.object_type)).toMatchObject({ verdict: "accept" });
    }
    const evidence = repositoryViewEvidence(objects);
    const authenticated = api.authenticateWorkspaceRepositoryView?.({ authority, evidence, objects });
    expect(authenticated?.verdict, JSON.stringify(authenticated)).toBe("accept");
    expect(authenticated).toMatchObject({ state: expect.any(Object) });

    expect(api.authenticateWorkspaceRepositoryView?.({
      authority,
      evidence: { ...evidence, signature: "00".repeat(64) },
      objects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    expect(api.authenticateWorkspaceRepositoryView?.({
      authority,
      evidence,
      objects: objects.slice(1),
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const forkedEvidence = repositoryViewEvidence(objects, {
      observed_heads: [H40, "dd".repeat(20)],
    });
    expect(api.authenticateWorkspaceRepositoryView?.({
      authority,
      evidence: forkedEvidence,
      objects,
    })).toEqual({ verdict: "reject", reason_code: "authority_conflict" });

    const staleAuthority = api.createWorkspaceRepositoryResolverAuthority?.({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => 1_720_000_701,
    });
    expect(api.authenticateWorkspaceRepositoryView?.({
      authority: staleAuthority,
      evidence,
      objects,
    })).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("rejects non-canonical object-id attestations and superseded current-state handles", async () => {
    let trustedNow = 1_720_000_400;
    const api = await import("./workspace.js");
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => trustedNow,
    });
    const objects = currentAuthorityObjects();
    const canonical = repositoryViewEvidence(objects);
    const reversedIds = [...(canonical.object_ids as string[])].reverse();
    const unsorted = repositoryViewEvidence(objects, { object_ids: reversedIds });
    expect(api.authenticateWorkspaceRepositoryView({ authority, evidence: unsorted, objects }))
      .toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const first = api.authenticateWorkspaceRepositoryView({ authority, evidence: canonical, objects });
    expect(first.verdict).toBe("accept");
    if (first.verdict !== "accept") throw new Error("fixture first repository view rejected");
    const secondEvidence = repositoryViewEvidence(objects, {
      observed_at: 1_720_000_200,
      expires_at: 1_720_000_750,
    });
    const second = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: secondEvidence,
      objects,
    });
    expect(second.verdict).toBe("accept");
    if (second.verdict !== "accept") throw new Error("fixture latest repository view rejected");

    const request = {
      authority,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: "ee".repeat(32),
      requested_capabilities: ["read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    };
    expect(api.resolveWorkspaceEffectiveAuthorization({ ...request, current_state: first.state }))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(api.resolveWorkspaceEffectiveAuthorization({ ...request, current_state: second.state }))
      .toMatchObject({ verdict: "accept" });

    trustedNow = 1_720_000_751;
    expect(api.resolveWorkspaceEffectiveAuthorization({ ...request, current_state: second.state }))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("authenticates complete multi-role parent chains with one checkpoint per role", async () => {
    const api = await import("./workspace.js");
    const childRoleId = "12".repeat(32);
    const childCheckpointId = "13".repeat(32);
    const common = {
      spec_version: "heterodyne/0.5.0",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_050,
    };
    const childRole = signWorkspaceObject({
      ...common,
      object_type: "role-manifest-v1",
      role_id: childRoleId,
      parent_role_id: H64,
      role_type: "member",
      visibility: "private",
      allowed_capabilities: ["read"],
      history_mode: "from-admission",
      selected_snapshots: [],
      administrator_account: WORKSPACE_KEY,
      marmot_h: "child-role-routing-id",
      active_event_repository: { repository_rid: "rad:zChildEvents", mls_epoch: 7 },
      overlap_event_repository: null,
      archived_event_repositories: [],
    }, WORKSPACE_SECRET);
    const childCheckpoint = signWorkspaceObject({
      ...common,
      object_type: "role-checkpoint-v1",
      checkpoint_id: childCheckpointId,
      role_id: childRoleId,
      sequence: 1,
      materialized_at: 1_720_000_050,
      workspace_policy_head: POLICY_HEAD,
      role_policy_heads: [objectDigest(currentAuthorityObjects()[1]), objectDigest(childRole)].sort(),
      active_grant_ids: [],
      revocation_ids: [REVOCATION_ID],
      relationship_ids: [],
      host_ids: [],
      resource_ids: [],
      seed_nids: [],
      previous_checkpoint: null,
    }, WORKSPACE_SECRET);
    const objects = [...currentAuthorityObjects(), childRole, childCheckpoint];
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(objects),
      objects,
    })).toMatchObject({ verdict: "accept", state: expect.any(Object) });

    const phantomHeadObjects = [...objects];
    phantomHeadObjects[5] = signWorkspaceObject({
      ...phantomHeadObjects[5],
      role_policy_heads: [
        ...(phantomHeadObjects[5].role_policy_heads as string[]),
        "19".repeat(32),
      ].sort(),
    }, WORKSPACE_SECRET);
    const phantomAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: phantomAuthority,
      evidence: repositoryViewEvidence(phantomHeadObjects),
      objects: phantomHeadObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const publicObjects = currentAuthorityObjects();
    publicObjects[1] = signWorkspaceObject({
      ...publicObjects[1],
      visibility: "public",
    }, WORKSPACE_SECRET);
    publicObjects[4] = signWorkspaceObject({
      ...publicObjects[4],
      visibility: "public",
    }, WORKSPACE_SECRET);
    publicObjects[5] = signWorkspaceObject({
      ...publicObjects[5],
      role_policy_heads: [objectDigest(publicObjects[1])],
    }, WORKSPACE_SECRET);
    const publicAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: publicAuthority,
      evidence: repositoryViewEvidence(publicObjects),
      objects: publicObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const unrelatedRoleId = "15".repeat(32);
    const unrelatedGrantId = "16".repeat(32);
    const unrelatedCheckpointId = "17".repeat(32);
    const unrelatedRole = signWorkspaceObject({
      ...childRole,
      role_id: unrelatedRoleId,
      parent_role_id: null,
    }, WORKSPACE_SECRET);
    const unrelatedGrant = signWorkspaceObject({
      ...currentAuthorityObjects()[2],
      grant_id: unrelatedGrantId,
      role_id: unrelatedRoleId,
      capabilities: ["read"],
      resource_scope: [RESOURCE_ID],
      delegable: false,
    }, WORKSPACE_SECRET);
    const unrelatedCheckpoint = signWorkspaceObject({
      ...childCheckpoint,
      checkpoint_id: unrelatedCheckpointId,
      role_id: unrelatedRoleId,
      role_policy_heads: [objectDigest(unrelatedRole)],
      active_grant_ids: [unrelatedGrantId],
    }, WORKSPACE_SECRET);
    const crossRoleObjects = [
      ...currentAuthorityObjects(),
      unrelatedRole,
      unrelatedGrant,
      unrelatedCheckpoint,
    ];
    const crossRoleAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: crossRoleAuthority,
      evidence: repositoryViewEvidence(crossRoleObjects),
      objects: crossRoleObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const missingParent = signWorkspaceObject({
      ...childRole,
      parent_role_id: "14".repeat(32),
    }, WORKSPACE_SECRET);
    const invalidObjects = [...currentAuthorityObjects(), missingParent, childCheckpoint];
    const invalidAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: invalidAuthority,
      evidence: repositoryViewEvidence(invalidObjects),
      objects: invalidObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
  });
});

describe("Workspace evaluator input boundary", () => {
  it("rejects null and throwing accessors without any public evaluator throwing", () => {
    const evaluators = [
      authenticateWorkspaceRepositoryView,
      authenticateWorkspaceSuccessorReauthorization,
      consumeWorkspaceInvitationAcceptance,
      evaluateWorkspaceObject,
      evaluateAuthorization,
      evaluateGrantActivation,
      evaluateAllowance,
      evaluatePrivateProjection,
      evaluateJointGovernance,
      resolveEffectiveHosts,
      resolveWorkspaceCurrentRelationship,
      resolveWorkspaceEffectiveAuthorization,
      evaluateRoleLeafChange,
      evaluateKeyRequest,
      evaluateFreshness,
      selectEventRepository,
      eventsAreByteIdentical,
      evaluateWorkspacePrivateRelay,
    ] as Array<(value: unknown) => unknown>;
    for (const evaluator of evaluators) {
      for (const hostile of [
        null,
        Object.defineProperty({}, "value", {
          enumerable: true,
          get: () => { throw new Error("semantic read before snapshot"); },
        }),
      ]) {
        let result: unknown;
        expect(() => { result = evaluator(hostile); }, evaluator.name).not.toThrow();
        expect(result, evaluator.name)
          .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
      }
    }
  });
});

describe("Workspace signed objects", () => {
  it("accepts a bare active-key workspace and binds exact policy, predecessor, checkpoint, repository, and digest", () => {
    const object = signWorkspaceObject({
      spec_version: "heterodyne/0.5.0",
      object_type: "workspace-manifest-v1",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_000,
      root_policy_rid: "rad:zPolicy",
      root_policy_head: H64,
      visibility: "private",
      public_roles: [],
    }, WORKSPACE_SECRET);
    const input = {
      object,
      expected_object_id: workspaceObjectId(object),
      current: currentState(),
    };
    expect(evaluateWorkspaceObject(input)).toEqual({
      verdict: "accept",
      normalized: {
        object_id: workspaceObjectId(object),
        object_type: "workspace-manifest-v1",
        workspace_key: WORKSPACE_KEY,
      },
    });
    for (const current of [
      { ...currentState(), policy_head: H64 },
      { ...currentState(), predecessor: H64 },
      { ...currentState(), authority_checkpoint: H64, authority_checkpoint_candidates: [H64] },
      { ...currentState(), repository_head: "77".repeat(20), repository_ancestry: ["77".repeat(20)] },
    ]) {
      expect(evaluateWorkspaceObject({ ...input, current }))
        .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
    }
    expect(evaluateWorkspaceObject({
      ...input,
      current: {
        ...currentState(),
        authority_checkpoint_candidates: [CHECKPOINT, H64],
      },
    }))
      .toEqual({ verdict: "reject", reason_code: "authority_conflict" });
  });

  it("rejects delegate, host, seed, and repository-writer signatures as ambient governance", () => {
    const signedByCarrier = signWorkspaceObject({
      spec_version: "heterodyne/0.5.0",
      object_type: "workspace-manifest-v1",
      workspace_key: OTHER_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_000,
      root_policy_rid: "rad:zPolicy",
      root_policy_head: H64,
      visibility: "private",
      public_roles: [],
    }, OTHER_SECRET);
    expect(evaluateWorkspaceObject({
      object: signedByCarrier,
      expected_object_id: workspaceObjectId(signedByCarrier),
      current: currentState(),
    })).toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
  });

  it("fails closed without throwing when hostile object access cannot be snapshotted", () => {
    const hostile = new Proxy({}, {
      ownKeys: () => ["object_type"],
      getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }),
      get: () => { throw new Error("substituted during validation"); },
    });
    expect(() => evaluateWorkspaceObject({
      object: hostile,
      expected_object_id: H64,
      current: currentState(),
    })).not.toThrow();
    expect(evaluateWorkspaceObject({
      object: hostile,
      expected_object_id: H64,
      current: currentState(),
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects unsafe policy and joint thresholds at generic signed-object evaluation", () => {
    const policy = currentAuthorityObjects()[0];
    const unsafePolicy = signWorkspaceObject({
      ...policy,
      governance: {
        ...(policy.governance as Record<string, unknown>),
        threshold: Number.MAX_SAFE_INTEGER + 1,
      },
    }, WORKSPACE_SECRET);
    expect(evaluateWorkspaceObject({
      object: unsafePolicy,
      expected_object_id: objectDigest(unsafePolicy),
      current: currentState(),
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });

    const joint = jointGovernanceFixture().joint;
    const unsafeJoint = signWorkspaceObject({
      ...joint,
      threshold: Number.MAX_SAFE_INTEGER + 1,
    }, JOINT_SECRET);
    expect(evaluateWorkspaceObject({
      object: unsafeJoint,
      expected_object_id: objectDigest(unsafeJoint),
      current: currentState(JOINT_KEY),
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });
});

describe("Workspace role authorization", () => {
  it("derives effective authorization only from its configured current repository state", async () => {
    const api = await import("./workspace.js") as typeof import("./workspace.js") & {
      createWorkspaceRepositoryResolverAuthority: (input: unknown) => object;
      authenticateWorkspaceRepositoryView: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        state?: object;
      };
      resolveWorkspaceEffectiveAuthorization?: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        authorization?: object;
        normalized?: Record<string, unknown>;
      };
    };
    expect(api.resolveWorkspaceEffectiveAuthorization).toBeTypeOf("function");
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => 1_720_000_400,
    });
    const objects = currentAuthorityObjects();
    const authenticated = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(objects),
      objects,
    });
    expect(authenticated.verdict).toBe("accept");
    if (authenticated.verdict !== "accept") throw new Error("fixture repository view rejected");
    const request = {
      authority,
      current_state: authenticated.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: "ee".repeat(32),
      requested_capabilities: ["invite", "read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    };
    const resolved = api.resolveWorkspaceEffectiveAuthorization?.(request);
    expect(resolved).toMatchObject({
      verdict: "accept",
      authorization: expect.any(Object),
      normalized: {
        actor_account: OTHER_KEY,
        authority_checkpoint: CHECKPOINT,
        effective_capabilities: ["govern-delegation", "invite", "read", "write"],
        effective_delegable: true,
        effective_approver_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        effective_resources: [RESOURCE_ID],
        operation_digest: "ee".repeat(32),
        policy_head: POLICY_HEAD,
        predecessor: PREDECESSOR,
        required_approvals: 2,
        workspace_key: WORKSPACE_KEY,
      },
    });

    expect(api.resolveWorkspaceEffectiveAuthorization?.({
      ...request,
      requested_capabilities: ["admin"],
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    expect(api.resolveWorkspaceEffectiveAuthorization?.({
      ...request,
      capability_ceilings: [["admin"]],
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    const hostile = { ...request } as Record<string, unknown>;
    Object.defineProperty(hostile, "requested_capabilities", {
      enumerable: true,
      get: () => { throw new Error("must reject before semantic read"); },
    });
    expect(() => api.resolveWorkspaceEffectiveAuthorization?.(hostile)).not.toThrow();
    expect(api.resolveWorkspaceEffectiveAuthorization?.(hostile))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });

    const revokedObjects = currentAuthorityObjects();
    revokedObjects[3] = signWorkspaceObject({
      ...revokedObjects[3],
      effective_at: 1_720_000_300,
    }, WORKSPACE_SECRET);
    const revokedAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => 1_720_000_400,
    });
    const revokedState = api.authenticateWorkspaceRepositoryView({
      authority: revokedAuthority,
      evidence: repositoryViewEvidence(revokedObjects),
      objects: revokedObjects,
    });
    expect(revokedState.verdict).toBe("accept");
    if (revokedState.verdict !== "accept") throw new Error("fixture revoked repository view rejected");
    expect(api.resolveWorkspaceEffectiveAuthorization?.({
      ...request,
      authority: revokedAuthority,
      current_state: revokedState.state,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(api.resolveWorkspaceEffectiveAuthorization?.({
      ...request,
      current_state: revokedState.state,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const splitObjects = currentAuthorityObjects();
    splitObjects[2] = signWorkspaceObject({
      ...splitObjects[2],
      capabilities: ["invite"],
    }, WORKSPACE_SECRET);
    const splitGrant = signWorkspaceObject({
      ...splitObjects[2],
      grant_id: "ca".repeat(32),
      capabilities: ["read"],
    }, WORKSPACE_SECRET);
    splitObjects.push(splitGrant);
    splitObjects[5] = signWorkspaceObject({
      ...splitObjects[5],
      active_grant_ids: [ACTOR_GRANT_ID, splitGrant.grant_id].sort(),
    }, WORKSPACE_SECRET);
    const splitAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 300,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => 1_720_000_400,
    });
    const splitState = api.authenticateWorkspaceRepositoryView({
      authority: splitAuthority,
      evidence: repositoryViewEvidence(splitObjects),
      objects: splitObjects,
    });
    expect(splitState.verdict).toBe("accept");
    if (splitState.verdict !== "accept") throw new Error("fixture split-grant state rejected");
    expect(api.resolveWorkspaceEffectiveAuthorization?.({
      ...request,
      authority: splitAuthority,
      current_state: splitState.state,
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
  });

  it("activates a current signed grant with same-view authority and policy-derived approvals", async () => {
    const api = await import("./workspace.js");
    let trustedNow = 1_720_000_350;
    const unsignedGrant = {
      spec_version: "heterodyne/0.5.0",
      object_type: "role-grant-v1",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_050,
      grant_id: "ef".repeat(32),
      subject_account: OTHER_KEY,
      target_device: NEW_DEVICE,
      recipient: { type: "marmot-mls-leaf", value: NEW_LEAF },
      role_id: H64,
      capabilities: ["read"],
      resource_scope: [RESOURCE_ID],
      delegable: false,
      activation: "approval-threshold",
      activates_at: 1_720_000_100,
      expires_at: 1_720_000_650,
      approval_ids: [] as string[],
      invitation: null,
      evidence_ids: [] as string[],
    };
    const operationDigest = grantOperationDigest(unsignedGrant);
    const approvals = [
      grantApproval(operationDigest, APPROVER_A_SECRET),
      grantApproval(operationDigest, APPROVER_B_SECRET),
    ];
    const grant = signWorkspaceObject({
      ...unsignedGrant,
      approval_ids: approvals.map(objectDigest).sort(),
    }, WORKSPACE_SECRET);
    const authorityObjects = currentAuthorityObjects();
    authorityObjects[3] = signWorkspaceObject({
      ...authorityObjects[3],
      effective_at: 1_720_000_380,
    }, WORKSPACE_SECRET);
    const targetDeviceRevocation = signWorkspaceObject({
      ...authorityObjects[3],
      revocation_id: "d2".repeat(32),
      target_type: "device",
      target_id: NEW_DEVICE,
      effective_at: 1_720_000_360,
    }, WORKSPACE_SECRET);
    authorityObjects[5] = signWorkspaceObject({
      ...authorityObjects[5],
      revocation_ids: [REVOCATION_ID, targetDeviceRevocation.revocation_id].sort(),
    }, WORKSPACE_SECRET);
    const objects = [...authorityObjects, grant, targetDeviceRevocation];
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{
        workspace_key: WORKSPACE_KEY,
        repository_rid: "rad:zWorkspace",
        pinned_head: H40,
      }],
      trusted_now: () => trustedNow,
    });
    const state = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(objects),
      objects,
    });
    expect(state.verdict).toBe("accept");
    if (state.verdict !== "accept") throw new Error("fixture current state rejected");
    const resolved = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: operationDigest,
      requested_capabilities: ["invite", "read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(resolved.verdict).toBe("accept");
    if (resolved.verdict !== "accept") throw new Error("fixture authorization rejected");
    const activation = {
      authority,
      current_state: state.state,
      authorization: resolved.authorization,
      grant_id: grant.grant_id,
      membership: {
        authenticated_account: OTHER_KEY,
        accepted_device: NEW_DEVICE,
        accepted_leaf: NEW_LEAF,
      },
      approvals,
      invitation_acceptance: null,
      successor_reauthorization: null,
    };
    expect(evaluateGrantActivation(activation)).toEqual({
      verdict: "accept",
      normalized: {
        active: true,
        approval_count: 2,
        approver_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        grant_id: grant.grant_id,
        operation_digest: operationDigest,
      },
    });
    const emptyResourceAuthorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: operationDigest,
      requested_capabilities: ["invite", "read"],
      requested_resources: [],
      requested_delegable: false,
    });
    expect(emptyResourceAuthorization.verdict).toBe("accept");
    if (emptyResourceAuthorization.verdict !== "accept") {
      throw new Error("fixture empty-resource authorization rejected");
    }
    expect(evaluateGrantActivation({
      ...activation,
      authorization: emptyResourceAuthorization.authorization,
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    expect(evaluateGrantActivation({
      ...activation,
      required_approvals: 0,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateGrantActivation({
      ...activation,
      authorization: {},
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });

    trustedNow = 1_720_000_360;
    expect(evaluateGrantActivation(activation))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_401;
    expect(evaluateGrantActivation(activation))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("consumes one signed subject acceptance through the configured atomic replay store", async () => {
    const api = await import("./workspace.js") as typeof import("./workspace.js") & {
      ReferenceWorkspaceInvitationAcceptanceStore?: new () => object;
      consumeWorkspaceInvitationAcceptance?: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        acceptance?: object;
      };
    };
    expect(api.ReferenceWorkspaceInvitationAcceptanceStore).toBeTypeOf("function");
    expect(api.consumeWorkspaceInvitationAcceptance).toBeTypeOf("function");
    let trustedNow = 1_720_000_400;
    let commitClock: number[] | null = null;
    const grantId = "ed".repeat(32);
    const nonceOpening = "de".repeat(32);
    const unsignedGrant = {
      spec_version: "heterodyne/0.5.0",
      object_type: "role-grant-v1",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_050,
      grant_id: grantId,
      subject_account: OTHER_KEY,
      target_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
      role_id: H64,
      capabilities: ["read"],
      resource_scope: [RESOURCE_ID],
      delegable: false,
      activation: "subject-acceptance",
      activates_at: 1_720_000_100,
      expires_at: 1_720_000_650,
      approval_ids: [] as string[],
      invitation: {
        nonce_commitment: invitationNonceCommitment(grantId, nonceOpening),
        expires_at: 1_720_000_600,
        history_mode: "from-admission",
      },
      evidence_ids: [] as string[],
    };
    const operationDigest = grantOperationDigest(unsignedGrant);
    const approvals = [
      grantApproval(operationDigest, APPROVER_A_SECRET),
      grantApproval(operationDigest, APPROVER_B_SECRET),
    ];
    const grant = signWorkspaceObject({
      ...unsignedGrant,
      approval_ids: approvals.map(objectDigest).sort(),
    }, WORKSPACE_SECRET);
    const objects = [...currentAuthorityObjects(), grant];
    const evidence = repositoryViewEvidence(objects, { observed_at: 1_720_000_300 });
    const store = new api.ReferenceWorkspaceInvitationAcceptanceStore!();
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => commitClock?.shift() ?? trustedNow,
      invitation_store: store,
    });
    const state = api.authenticateWorkspaceRepositoryView({ authority, evidence, objects });
    expect(state.verdict).toBe("accept");
    if (state.verdict !== "accept") throw new Error("fixture invitation state rejected");
    const deniedObjects = [...objects];
    deniedObjects[3] = signWorkspaceObject({
      ...deniedObjects[3],
      target_type: "grant",
      target_id: grantId,
      effective_at: 1_720_000_350,
    }, WORKSPACE_SECRET);
    const deniedEvidence = repositoryViewEvidence(deniedObjects, { observed_at: 1_720_000_300 });
    const deniedAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
      invitation_store: new api.ReferenceWorkspaceInvitationAcceptanceStore!(),
    });
    const deniedState = api.authenticateWorkspaceRepositoryView({
      authority: deniedAuthority,
      evidence: deniedEvidence,
      objects: deniedObjects,
    });
    expect(deniedState.verdict).toBe("accept");
    if (deniedState.verdict !== "accept") throw new Error("fixture denied invitation state rejected");
    expect(api.consumeWorkspaceInvitationAcceptance?.({
      authority: deniedAuthority,
      current_state: deniedState.state,
      acceptance: invitationAcceptance(
        grantId,
        operationDigest,
        objectDigest(deniedEvidence),
        nonceOpening,
      ),
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    const signedAcceptance = invitationAcceptance(
      grantId,
      operationDigest,
      objectDigest(evidence),
      nonceOpening,
      1_720_000_450,
    );
    trustedNow = 1_720_000_601;
    expect(api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: signedAcceptance,
    })).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    trustedNow = 1_720_000_400;
    const first = api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: signedAcceptance,
    });
    expect(first).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    expect(api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: signedAcceptance,
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });
    expect(api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: { ...signedAcceptance, target_device: "ab".repeat(32) },
    })).toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
    if (first?.verdict !== "accept" || first.acceptance === undefined) {
      throw new Error("fixture signed acceptance rejected");
    }
    const expiryAuthorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: operationDigest,
      requested_capabilities: ["invite", "read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(expiryAuthorization.verdict).toBe("accept");
    if (expiryAuthorization.verdict !== "accept") {
      throw new Error("fixture expiry authorization rejected");
    }
    trustedNow = 1_720_000_450;
    expect(evaluateGrantActivation({
      authority,
      current_state: state.state,
      authorization: expiryAuthorization.authorization,
      grant_id: grantId,
      membership: {
        authenticated_account: OTHER_KEY,
        accepted_device: H64,
        accepted_leaf: LEAF,
      },
      approvals,
      invitation_acceptance: first.acceptance,
      successor_reauthorization: null,
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });
    trustedNow = 1_720_000_500;
    const retryableAcceptance = invitationAcceptance(
      grantId,
      operationDigest,
      objectDigest(evidence),
      nonceOpening,
    );
    const afterExpiredReservation = api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: retryableAcceptance,
    });
    expect(afterExpiredReservation)
      .toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (afterExpiredReservation?.verdict !== "accept"
      || afterExpiredReservation.acceptance === undefined) {
      throw new Error("fixture expired invitation reservation was not released");
    }
    const resolved = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: operationDigest,
      requested_capabilities: ["invite", "read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(resolved.verdict).toBe("accept");
    if (resolved.verdict !== "accept") throw new Error("fixture invitation authorization rejected");
    const activation = {
      authority,
      current_state: state.state,
      authorization: resolved.authorization,
      grant_id: grantId,
      membership: {
        authenticated_account: OTHER_KEY,
        accepted_device: H64,
        accepted_leaf: LEAF,
      },
      approvals,
      invitation_acceptance: afterExpiredReservation.acceptance,
      successor_reauthorization: null,
    };
    expect(evaluateGrantActivation({ ...activation, approvals: approvals.slice(0, 1) }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    const retry = api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: retryableAcceptance,
    });
    expect(retry).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (retry?.verdict !== "accept" || retry.acceptance === undefined) {
      throw new Error("fixture invitation reservation was not released");
    }
    commitClock = [1_720_000_500, 1_720_000_600];
    expect(evaluateGrantActivation({ ...activation, invitation_acceptance: retry.acceptance }))
      .toEqual({ verdict: "reject", reason_code: "workspace_replay" });
    commitClock = null;
    const finalRetry = api.consumeWorkspaceInvitationAcceptance?.({
      authority,
      current_state: state.state,
      acceptance: retryableAcceptance,
    });
    expect(finalRetry).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (finalRetry?.verdict !== "accept" || finalRetry.acceptance === undefined) {
      throw new Error("fixture atomic commit did not release expired reservation");
    }
    const committedActivation = {
      ...activation,
      invitation_acceptance: finalRetry.acceptance,
    };
    expect(evaluateGrantActivation(committedActivation)).toMatchObject({ verdict: "accept" });
    expect(evaluateGrantActivation(committedActivation))
      .toEqual({ verdict: "reject", reason_code: "workspace_replay" });
  });

  it("rejects legacy caller-authored authority ceilings, revocations, and activation context", () => {
    expect(evaluateAuthorization(grantActivationFixture().authorization))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateGrantActivation(grantActivationFixture()))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });
});

describe("Workspace relationships and privacy", () => {
  it("resolves bilateral allowance only from two same-authority current repository states", async () => {
    const api = await import("./workspace.js") as typeof import("./workspace.js") & {
      resolveWorkspaceCurrentRelationship?: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        relationship?: object;
      };
    };
    expect(api.resolveWorkspaceCurrentRelationship).toBeTypeOf("function");
    let trustedNow = 1_720_000_400;
    const relationship = signedRelationship();
    const sourceObjects = currentAuthorityObjects();
    sourceObjects[0] = signWorkspaceObject({
      ...sourceObjects[0],
      ordinary_write_max_age: 300,
    }, WORKSPACE_SECRET);
    sourceObjects[5] = signWorkspaceObject({
      ...sourceObjects[5],
      revocation_ids: [REVOCATION_ID, "d0".repeat(32)].sort(),
      relationship_ids: [H64],
    }, WORKSPACE_SECRET);
    sourceObjects.push(signWorkspaceObject({
      ...sourceObjects[3],
      revocation_id: "d0".repeat(32),
      target_type: "device",
      target_id: H64,
      effective_at: 1_720_000_450,
    }, WORKSPACE_SECRET));
    sourceObjects.push(relationship);
    const receivingObjects = receivingAuthorityObjects();
    receivingObjects[0] = signWorkspaceObject({
      ...receivingObjects[0],
      ordinary_write_max_age: 300,
    }, OTHER_SECRET);
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [
        { workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 },
        { workspace_key: OTHER_KEY, repository_rid: "rad:zReceiving", pinned_head: H40 },
      ],
      trusted_now: () => trustedNow,
    });
    const source = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(sourceObjects, { observed_at: 1_720_000_200 }),
      objects: sourceObjects,
    });
    const receivingWithoutReceipt = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(receivingObjects, {
        workspace_key: OTHER_KEY,
        repository_rid: "rad:zReceiving",
        policy_head: "77".repeat(32),
        predecessor: "88".repeat(32),
        authority_checkpoint: "99".repeat(32),
        observed_at: 1_720_000_200,
      }),
      objects: receivingObjects,
    });
    expect(source.verdict).toBe("accept");
    expect(receivingWithoutReceipt.verdict).toBe("accept");
    if (source.verdict !== "accept" || receivingWithoutReceipt.verdict !== "accept") {
      throw new Error("fixture relationship views rejected");
    }
    expect(api.resolveWorkspaceCurrentRelationship?.({
      authority,
      source_state: source.state,
      receiving_state: receivingWithoutReceipt.state,
      relationship_id: H64,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const receipt = signedRelationshipReceipt(relationship);
    const duplicateSemanticReceipt = signWorkspaceObject({
      ...receipt,
      receipt_id: "d2".repeat(32),
    }, OTHER_SECRET);
    const receivingObjectsWithDuplicateReceipt = [...receivingObjects];
    receivingObjectsWithDuplicateReceipt[5] = signWorkspaceObject({
      ...receivingObjectsWithDuplicateReceipt[5],
      relationship_ids: [receipt.receipt_id, duplicateSemanticReceipt.receipt_id].sort(),
    }, OTHER_SECRET);
    receivingObjectsWithDuplicateReceipt.push(receipt, duplicateSemanticReceipt);
    expect(api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(receivingObjectsWithDuplicateReceipt, {
        workspace_key: OTHER_KEY,
        repository_rid: "rad:zReceiving",
        policy_head: "77".repeat(32),
        predecessor: "88".repeat(32),
        authority_checkpoint: "99".repeat(32),
        observed_at: 1_720_000_201,
      }),
      objects: receivingObjectsWithDuplicateReceipt,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    const receivingObjectsWithReceipt = [...receivingObjects];
    receivingObjectsWithReceipt[5] = signWorkspaceObject({
      ...receivingObjectsWithReceipt[5],
      relationship_ids: [receipt.receipt_id],
    }, OTHER_SECRET);
    receivingObjectsWithReceipt.push(receipt);
    const receiving = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(receivingObjectsWithReceipt, {
        workspace_key: OTHER_KEY,
        repository_rid: "rad:zReceiving",
        policy_head: "77".repeat(32),
        predecessor: "88".repeat(32),
        authority_checkpoint: "99".repeat(32),
        observed_at: 1_720_000_201,
      }),
      objects: receivingObjectsWithReceipt,
    });
    expect(receiving.verdict).toBe("accept");
    if (receiving.verdict !== "accept") {
      throw new Error("fixture receiving relationship receipt rejected");
    }
    const resolved = api.resolveWorkspaceCurrentRelationship?.({
      authority,
      source_state: source.state,
      receiving_state: receiving.state,
      relationship_id: H64,
    });
    expect(resolved).toMatchObject({ verdict: "accept", relationship: expect.any(Object) });
    if (resolved?.verdict !== "accept" || resolved.relationship === undefined) {
      throw new Error("fixture relationship rejected");
    }
    const allowance = {
      authority,
      relationship: resolved.relationship,
      source_state: source.state,
      receiving_state: receiving.state,
      affiliation: affiliationEvidence(),
      expected_source_account: OTHER_KEY,
      requested_capabilities: ["read"],
    };
    expect(evaluateAllowance(allowance)).toEqual({
      verdict: "accept",
      normalized: {
        capabilities: ["read"],
        proof_age: 300,
        provisional_grace: false,
        relationship_id: H64,
        source_account: OTHER_KEY,
      },
    });
    const receivingRevokedObjects = [...receivingObjectsWithReceipt];
    receivingRevokedObjects[3] = signWorkspaceObject({
      ...receivingRevokedObjects[3],
      target_type: "relationship",
      target_id: receipt.receipt_id,
      effective_at: 1_720_000_430,
    }, OTHER_SECRET);
    const receivingRevoked = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(receivingRevokedObjects, {
        workspace_key: OTHER_KEY,
        repository_rid: "rad:zReceiving",
        policy_head: "77".repeat(32),
        predecessor: "88".repeat(32),
        authority_checkpoint: "99".repeat(32),
        observed_at: 1_720_000_202,
      }),
      objects: receivingRevokedObjects,
    });
    expect(receivingRevoked.verdict).toBe("accept");
    if (receivingRevoked.verdict !== "accept") throw new Error("fixture receipt revocation rejected");
    const resolvedAfterReceiptRevocation = api.resolveWorkspaceCurrentRelationship?.({
      authority,
      source_state: source.state,
      receiving_state: receivingRevoked.state,
      relationship_id: H64,
    });
    expect(resolvedAfterReceiptRevocation).toMatchObject({
      verdict: "accept",
      relationship: expect.any(Object),
    });
    if (resolvedAfterReceiptRevocation?.verdict !== "accept"
      || resolvedAfterReceiptRevocation.relationship === undefined) {
      throw new Error("fixture relationship receipt revocation handle rejected before effect");
    }
    const revokedAllowance = {
      ...allowance,
      relationship: resolvedAfterReceiptRevocation.relationship,
      receiving_state: receivingRevoked.state,
    };
    trustedNow = 1_720_000_430;
    expect(evaluateAllowance(revokedAllowance))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_450;
    expect(evaluateAllowance(revokedAllowance))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_501;
    expect(evaluateAllowance(revokedAllowance))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    trustedNow = 1_720_000_400;
    expect(evaluateAllowance({
      ...revokedAllowance,
      source_current: currentState(),
      revocation_effective_at: null,
      now: 1_720_000_400,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateAllowance({ ...revokedAllowance, relationship: {} }))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateAllowance({ ...revokedAllowance, requested_capabilities: ["triage"] }))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });

    const newerSource = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(sourceObjects, {
        observed_at: 1_720_000_200,
        expires_at: 1_720_000_750,
      }),
      objects: sourceObjects,
    });
    expect(newerSource.verdict).toBe("accept");
    expect(evaluateAllowance(revokedAllowance))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("rejects legacy raw bilateral heads, fork claims, revocation ages, and relationship objects", () => {
    expect(evaluateAllowance(allowanceFixture()))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects every stable public correlation to concealed topology", () => {
    expect(evaluatePrivateProjection({ private_identifiers: [], private_counts: 0, encrypted_placeholders: 0 }))
      .toEqual({ verdict: "accept", normalized: { disclosed_private_references: 0 } });
    expect(evaluatePrivateProjection({ private_identifiers: ["hidden"], private_counts: 0, encrypted_placeholders: 0 }))
      .toEqual({ verdict: "reject", reason_code: "private_topology_disclosed" });
  });

  it("fails closed on hostile bilateral input instead of trusting mutable proof data", () => {
    const hostileRelationship = new Proxy({}, {
      ownKeys: () => ["object_type"],
      getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }),
      get: () => { throw new Error("relationship substituted"); },
    });
    const input = {
      relationship: hostileRelationship,
      active_source_workspace_key: WORKSPACE_KEY,
      active_receiving_workspace_key: OTHER_KEY,
      accepted_source_policy_head: POLICY_HEAD,
      accepted_source_checkpoint: CHECKPOINT,
      accepted_source_predecessor: PREDECESSOR,
      accepted_receiving_policy_head: H64,
      accepted_receiving_checkpoint: H64,
      accepted_receiving_predecessor: H64,
      receiving_policy_allows: true,
      revoked: false,
      now: 1_720_000_100,
      requested_capabilities: ["read"],
      proof_age: 1,
    };
    expect(() => evaluateAllowance(input)).not.toThrow();
    expect(evaluateAllowance(input))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects alternating requested capabilities instead of returning unvalidated authority", () => {
    let reads = 0;
    const input = Object.defineProperty({
      relationship: signedRelationship(),
      active_source_workspace_key: WORKSPACE_KEY,
      active_receiving_workspace_key: OTHER_KEY,
      accepted_source_policy_head: POLICY_HEAD,
      accepted_source_checkpoint: CHECKPOINT,
      accepted_source_predecessor: PREDECESSOR,
      accepted_receiving_policy_head: "77".repeat(32),
      accepted_receiving_checkpoint: "99".repeat(32),
      accepted_receiving_predecessor: "88".repeat(32),
      receiving_policy_allows: true,
      revoked: false,
      now: 1_720_000_100,
      proof_age: 1,
    }, "requested_capabilities", {
      enumerable: true,
      get: () => {
        reads += 1;
        return reads < 3 ? ["read"] : ["govern-policy"];
      },
    });
    let result: unknown;
    expect(() => { result = evaluateAllowance(input); }).not.toThrow();
    expect(result)
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("requires latest resolver-derived joint state instead of host or caller authority", async () => {
    const api = await import("./workspace.js");
    let trustedNow = 1_720_000_100;
    const objects = jointAuthorityObjects();
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: JOINT_KEY, repository_rid: "rad:zJoint", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    const state = api.authenticateWorkspaceRepositoryView({
      authority,
      evidence: repositoryViewEvidence(objects, {
        workspace_key: JOINT_KEY,
        repository_rid: "rad:zJoint",
        observed_at: 1_720_000_050,
        expires_at: 1_720_000_650,
      }),
      objects,
    });
    expect(state.verdict).toBe("accept");
    if (state.verdict !== "accept") throw new Error("fixture joint current state rejected");
    const input = {
      authority,
      current_state: state.state,
      relationship_id: H64,
      resource_scope: [RESOURCE_ID],
      delegate_proofs: [
        jointDelegateProof([RESOURCE_ID], APPROVER_A_SECRET),
        jointDelegateProof([RESOURCE_ID], APPROVER_B_SECRET),
      ],
    };
    expect(evaluateJointGovernance(input)).toEqual({
      verdict: "accept",
      normalized: {
        counted_delegate_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        operation_digest: jointOperationDigest([RESOURCE_ID]),
        relationship_id: H64,
        threshold: 2,
        threshold_met: true,
      },
    });
    trustedNow = 1_720_000_150;
    expect(evaluateJointGovernance(input))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_351;
    expect(evaluateJointGovernance(input))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    trustedNow = 1_720_000_100;

    expect(evaluateJointGovernance({
      ...input,
      delegate_proofs: [input.delegate_proofs[0], input.delegate_proofs[0]],
    }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });

    expect(evaluateJointGovernance({
      ...input,
      delegate_proofs: [input.delegate_proofs[0], {
      ...input.delegate_proofs[1],
      signature: "00".repeat(64),
      }],
    }))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });

    expect(evaluateJointGovernance(jointGovernanceFixture())).toEqual({
      verdict: "reject",
      reason_code: "workspace_schema_invalid",
    });
    expect(evaluateJointGovernance({
      independent_joint_identity: true,
      valid_distinct_delegates: 2,
      threshold: 2,
      host_signatures_counted: 0,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });
});

describe("Workspace hosts, keys, repositories, and freshness", () => {
  const inherited = [
    { host_id: H64, priority: 20, radicle_locators: ["rad:zA"], radicle_backed_relay: true },
    { host_id: OTHER_KEY, priority: 10, radicle_locators: ["rad:zB"], radicle_backed_relay: true },
  ];

  it("delivers resource keys across account rotation only with exact signed successor reauthorization", async () => {
    const api = await import("./workspace.js") as typeof import("./workspace.js") & {
      authenticateWorkspaceSuccessorReauthorization?: (input: unknown) => {
        verdict: "accept" | "reject";
        reason_code?: string;
        reauthorization?: object;
      };
    };
    let trustedNow = 1_720_000_400;
    expect(api.authenticateWorkspaceSuccessorReauthorization).toBeTypeOf("function");
    const pendingGrantBase = {
      spec_version: "heterodyne/0.5.0",
      object_type: "role-grant-v1",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_050,
      grant_id: "ac".repeat(32),
      subject_account: APPROVER_A_KEY,
      target_device: NEW_DEVICE,
      recipient: { type: "marmot-mls-leaf", value: NEW_LEAF },
      role_id: H64,
      capabilities: ["read"],
      resource_scope: [RESOURCE_ID],
      delegable: false,
      activation: "approval-threshold",
      activates_at: 1_720_000_100,
      expires_at: 1_720_000_450,
      approval_ids: [] as string[],
      invitation: null,
      evidence_ids: [] as string[],
    };
    const pendingOperationDigest = grantOperationDigest(pendingGrantBase);
    const pendingApprovals = [
      grantApproval(pendingOperationDigest, APPROVER_A_SECRET),
      grantApproval(pendingOperationDigest, APPROVER_B_SECRET),
    ];
    const pendingGrant = signWorkspaceObject({
      ...pendingGrantBase,
      approval_ids: pendingApprovals.map(objectDigest).sort(),
    }, WORKSPACE_SECRET);
    const decoyPendingGrant = signWorkspaceObject({
      ...pendingGrant,
      grant_id: "af".repeat(32),
    }, WORKSPACE_SECRET);
    const decoyActorGrant = signWorkspaceObject({
      ...pendingGrant,
      grant_id: "b2".repeat(32),
      subject_account: OTHER_KEY,
      target_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
    }, WORKSPACE_SECRET);
    const pendingEnvelope = signWorkspaceObject({
      spec_version: "heterodyne/0.5.0",
      object_type: "resource-key-envelope-v1",
      workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      predecessor: PREDECESSOR,
      authority_checkpoint: CHECKPOINT,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_200,
      envelope_id: "ad".repeat(32),
      resource_id: RESOURCE_ID,
      grant_id: pendingGrant.grant_id,
      key_epoch: 1,
      admission_epoch: 1,
      target_account: APPROVER_A_KEY,
      target_device: NEW_DEVICE,
      recipient: { type: "marmot-mls-leaf", value: NEW_LEAF },
      role_id: H64,
      checkpoint_id: CHECKPOINT,
      custody_host_id: "dd".repeat(32),
      wrapping_profile: "marmot-mls-application-v1",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AQID",
      ciphertext_sha256: "ae".repeat(32),
      created_at: 1_720_000_200,
    }, WORKSPACE_SECRET);
    const decoyPendingEnvelope = signWorkspaceObject({
      ...pendingEnvelope,
      envelope_id: "b1".repeat(32),
      grant_id: decoyPendingGrant.grant_id,
    }, WORKSPACE_SECRET);
    const actorAdmissionEnvelope = signWorkspaceObject({
      ...pendingEnvelope,
      envelope_id: "b3".repeat(32),
      grant_id: ACTOR_GRANT_ID,
      key_epoch: 2,
      admission_epoch: 2,
      target_account: OTHER_KEY,
      target_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
    }, WORKSPACE_SECRET);
    const decoyActorEnvelope = signWorkspaceObject({
      ...actorAdmissionEnvelope,
      envelope_id: "b4".repeat(32),
      grant_id: decoyActorGrant.grant_id,
      key_epoch: 0,
      admission_epoch: 0,
    }, WORKSPACE_SECRET);
    const authorityObjects = currentAuthorityObjects();
    authorityObjects[0] = signWorkspaceObject({
      ...authorityObjects[0],
      ordinary_write_max_age: 300,
    }, WORKSPACE_SECRET);
    authorityObjects[3] = signWorkspaceObject({
      ...authorityObjects[3],
      effective_at: 1_720_000_480,
    }, WORKSPACE_SECRET);
    authorityObjects[4] = signWorkspaceObject({
      ...authorityObjects[4],
      key_epoch: 2,
      key_custody_host_ids: ["dd".repeat(32), "ee".repeat(32)],
    }, WORKSPACE_SECRET);
    const custodyHostRevocation = signWorkspaceObject({
      ...authorityObjects[3],
      revocation_id: "b5".repeat(32),
      target_type: "host",
      target_id: "dd".repeat(32),
      effective_at: 1_720_000_420,
    }, WORKSPACE_SECRET);
    authorityObjects[5] = signWorkspaceObject({
      ...authorityObjects[5],
      revocation_ids: [REVOCATION_ID, custodyHostRevocation.revocation_id].sort(),
    }, WORKSPACE_SECRET);
    const objects = [
      ...authorityObjects,
      custodyHostRevocation,
      pendingGrant,
      decoyPendingGrant,
      decoyActorGrant,
      pendingEnvelope,
      decoyPendingEnvelope,
      actorAdmissionEnvelope,
      decoyActorEnvelope,
    ];
    const duplicateEnvelope = signWorkspaceObject({
      ...pendingEnvelope,
      ciphertext: "BAUG",
      ciphertext_sha256: "af".repeat(32),
    }, WORKSPACE_SECRET);
    const duplicateObjects = [...objects, duplicateEnvelope];
    const duplicateAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: duplicateAuthority,
      evidence: repositoryViewEvidence(duplicateObjects, { observed_at: 1_720_000_300 }),
      objects: duplicateObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    const invalidAdmissionEnvelope = signWorkspaceObject({
      ...pendingEnvelope,
      envelope_id: "b0".repeat(32),
      admission_epoch: 2,
    }, WORKSPACE_SECRET);
    const invalidAdmissionObjects = [...objects, invalidAdmissionEnvelope];
    const invalidAdmissionAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: invalidAdmissionAuthority,
      evidence: repositoryViewEvidence(invalidAdmissionObjects, { observed_at: 1_720_000_300 }),
      objects: invalidAdmissionObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    const conflictingAdmissionEnvelope = signWorkspaceObject({
      ...actorAdmissionEnvelope,
      envelope_id: "b6".repeat(32),
      admission_epoch: 1,
    }, WORKSPACE_SECRET);
    const conflictingAdmissionObjects = [...objects, conflictingAdmissionEnvelope];
    const conflictingAdmissionAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: conflictingAdmissionAuthority,
      evidence: repositoryViewEvidence(conflictingAdmissionObjects, {
        observed_at: 1_720_000_300,
      }),
      objects: conflictingAdmissionObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    const evidence = repositoryViewEvidence(objects, { observed_at: 1_720_000_300 });
    const ancestryAuthority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: ancestryAuthority,
      evidence,
      objects,
    })).toMatchObject({ verdict: "accept", state: expect.any(Object) });
    const retainedEvidence = repositoryViewEvidence(objects, {
      observed_at: 1_720_000_301,
      expires_at: 1_720_000_701,
    });
    expect(api.authenticateWorkspaceRepositoryView({
      authority: ancestryAuthority,
      evidence: retainedEvidence,
      objects,
    })).toMatchObject({ verdict: "accept", state: expect.any(Object) });
    const withoutPendingEnvelope = objects.filter((object) =>
      object.envelope_id !== pendingEnvelope.envelope_id);
    expect(api.authenticateWorkspaceRepositoryView({
      authority: ancestryAuthority,
      evidence: repositoryViewEvidence(withoutPendingEnvelope, {
        observed_at: 1_720_000_302,
        expires_at: 1_720_000_702,
      }),
      objects: withoutPendingEnvelope,
    })).toMatchObject({ verdict: "accept", state: expect.any(Object) });
    const conflictingReuseObjects = objects.map((object) =>
      object.object_type === "resource-key-envelope-v1"
        && object.envelope_id === pendingEnvelope.envelope_id
        ? signWorkspaceObject({
          ...object,
          ciphertext: "BwgJ",
          ciphertext_sha256: "b7".repeat(32),
        }, WORKSPACE_SECRET)
        : object);
    expect(api.authenticateWorkspaceRepositoryView({
      authority: ancestryAuthority,
      evidence: repositoryViewEvidence(conflictingReuseObjects, {
        observed_at: 1_720_000_303,
        expires_at: 1_720_000_703,
      }),
      objects: conflictingReuseObjects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
    const authority = api.createWorkspaceRepositoryResolverAuthority({
      trust_anchors: [{ suite: "bip340", public_key: RESOLVER_KEY }],
      allowed_policies: ["radicle-verified-complete-v1"],
      minimum_version: "1.0.0",
      max_ttl: 600,
      max_view_age: 600,
      repositories: [{ workspace_key: WORKSPACE_KEY, repository_rid: "rad:zWorkspace", pinned_head: H40 }],
      trusted_now: () => trustedNow,
    });
    const state = api.authenticateWorkspaceRepositoryView({ authority, evidence, objects });
    expect(state.verdict).toBe("accept");
    if (state.verdict !== "accept") throw new Error("fixture successor state rejected");
    expect(api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: successorReauthorization(
        objectDigest(evidence),
        "resource-key",
        String(pendingGrant.grant_id),
        String(decoyPendingEnvelope.envelope_id),
      ),
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: successorReauthorization(
        objectDigest(evidence),
        "resource-key",
        String(pendingGrant.grant_id),
        String(pendingEnvelope.envelope_id),
        { pending_key_epoch: 2 },
      ),
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    const signed = successorReauthorization(
      objectDigest(evidence),
      "resource-key",
      String(pendingGrant.grant_id),
      String(pendingEnvelope.envelope_id),
    );
    trustedNow = 1_720_000_601;
    expect(api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: signed,
    })).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    trustedNow = 1_720_000_400;
    const successor = api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: signed,
    });
    expect(successor).toMatchObject({ verdict: "accept", reauthorization: expect.any(Object) });
    if (successor?.verdict !== "accept" || successor.reauthorization === undefined) {
      throw new Error("fixture successor reauthorization rejected");
    }
    const requestBody = {
      resource_id: RESOURCE_ID,
      custody_host_id: "dd".repeat(32),
      requested_epoch: 1,
      requested_snapshot_id: null,
      target_account: APPROVER_A_KEY,
      authenticated_account: OTHER_KEY,
      target_device: NEW_DEVICE,
      recipient: { type: "marmot-mls-leaf", value: NEW_LEAF },
    };
    const keyAuthorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: keyRequestDigest(requestBody),
      requested_capabilities: ["read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(keyAuthorization.verdict).toBe("accept");
    if (keyAuthorization.verdict !== "accept") throw new Error("fixture key authorization rejected");
    const request = {
      authority,
      current_state: state.state,
      authorization: keyAuthorization.authorization,
      successor_reauthorization: successor.reauthorization,
      ...requestBody,
    };
    expect(evaluateKeyRequest(request)).toEqual({
      verdict: "accept",
      normalized: {
        key_epoch: 1,
        target_device: NEW_DEVICE,
        recipient: { type: "marmot-mls-leaf", value: NEW_LEAF },
        device_bound: true,
        history_start_epoch: 1,
        history_mode: "full",
        idempotent: true,
      },
    });
    trustedNow = 1_720_000_419;
    expect(evaluateKeyRequest(request)).toMatchObject({ verdict: "accept" });
    trustedNow = 1_720_000_420;
    expect(evaluateKeyRequest(request))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_421;
    expect(evaluateKeyRequest(request))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_460;
    expect(evaluateKeyRequest(request))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_400;
    for (const changedRequest of [
      { ...requestBody, custody_host_id: "ee".repeat(32) },
      { ...requestBody, requested_epoch: 2 },
    ]) {
      const changedAuthorization = api.resolveWorkspaceEffectiveAuthorization({
        authority,
        current_state: state.state,
        actor_account: OTHER_KEY,
        actor_device: H64,
        actor_leaf: LEAF,
        operation_digest: keyRequestDigest(changedRequest),
        requested_capabilities: ["read"],
        requested_resources: [RESOURCE_ID],
        requested_delegable: false,
      });
      expect(changedAuthorization.verdict).toBe("accept");
      if (changedAuthorization.verdict !== "accept") {
        throw new Error("fixture changed-request authorization rejected");
      }
      expect(evaluateKeyRequest({
        authority,
        current_state: state.state,
        authorization: changedAuthorization.authorization,
        successor_reauthorization: successor.reauthorization,
        ...changedRequest,
      })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    }
    trustedNow = 1_720_000_601;
    expect(evaluateKeyRequest(request))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    trustedNow = 1_720_000_400;
    const emptyResourceAuthorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: keyRequestDigest(requestBody),
      requested_capabilities: ["read"],
      requested_resources: [],
      requested_delegable: false,
    });
    expect(emptyResourceAuthorization.verdict).toBe("accept");
    if (emptyResourceAuthorization.verdict !== "accept") {
      throw new Error("fixture empty-resource authorization rejected");
    }
    expect(evaluateKeyRequest({
      ...request,
      authorization: emptyResourceAuthorization.authorization,
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    const sameAccountRequest = {
      resource_id: RESOURCE_ID,
      custody_host_id: "dd".repeat(32),
      requested_epoch: 2,
      requested_snapshot_id: null,
      target_account: OTHER_KEY,
      authenticated_account: OTHER_KEY,
      target_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
    };
    const sameAccountAuthorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: keyRequestDigest(sameAccountRequest),
      requested_capabilities: ["read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(sameAccountAuthorization.verdict).toBe("accept");
    if (sameAccountAuthorization.verdict !== "accept") {
      throw new Error("fixture same-account authorization rejected");
    }
    const ordinaryRequest = {
      authority,
      current_state: state.state,
      authorization: sameAccountAuthorization.authorization,
      successor_reauthorization: null,
      ...sameAccountRequest,
    };
    trustedNow = 1_720_000_419;
    expect(evaluateKeyRequest(ordinaryRequest)).toMatchObject({ verdict: "accept" });
    trustedNow = 1_720_000_420;
    expect(evaluateKeyRequest(ordinaryRequest))
      .toEqual({ verdict: "reject", reason_code: "host_unauthorized" });
    trustedNow = 1_720_000_421;
    expect(evaluateKeyRequest(ordinaryRequest))
      .toEqual({ verdict: "reject", reason_code: "host_unauthorized" });
    trustedNow = 1_720_000_400;
    expect(evaluateKeyRequest({ ...request, successor_reauthorized: true }))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    let recipientReads = 0;
    const alternatingRecipient = Object.defineProperty(
      { type: "marmot-mls-leaf" },
      "value",
      {
        enumerable: true,
        get: () => {
          recipientReads += 1;
          return recipientReads === 1 ? LEAF : "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
        },
      },
    );
    expect(() => evaluateKeyRequest({ ...request, recipient: alternatingRecipient })).not.toThrow();
    expect(evaluateKeyRequest({ ...request, recipient: alternatingRecipient }))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: { ...signed, new_account_signature: "00".repeat(64) },
    })).toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
    expect(api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: successorReauthorization(
        objectDigest(evidence),
        "resource-key",
        String(pendingGrant.grant_id),
        String(pendingEnvelope.envelope_id),
      ),
    })).toMatchObject({ verdict: "accept" });

    trustedNow = 1_720_000_500;
    expect(evaluateKeyRequest(request))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    trustedNow = 1_720_000_400;

    const roleSuccessor = api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: successorReauthorization(
        objectDigest(evidence),
        "role-membership",
        String(pendingGrant.grant_id),
        null,
      ),
    });
    expect(roleSuccessor).toMatchObject({ verdict: "accept", reauthorization: expect.any(Object) });
    if (roleSuccessor?.verdict !== "accept" || roleSuccessor.reauthorization === undefined) {
      throw new Error("fixture role successor rejected");
    }
    const decoyRoleSuccessor = api.authenticateWorkspaceSuccessorReauthorization?.({
      authority,
      current_state: state.state,
      reauthorization: successorReauthorization(
        objectDigest(evidence),
        "role-membership",
        String(decoyPendingGrant.grant_id),
        null,
      ),
    });
    expect(decoyRoleSuccessor).toMatchObject({
      verdict: "accept",
      reauthorization: expect.any(Object),
    });
    if (decoyRoleSuccessor?.verdict !== "accept"
      || decoyRoleSuccessor.reauthorization === undefined) {
      throw new Error("fixture decoy successor rejected");
    }
    const authorization = api.resolveWorkspaceEffectiveAuthorization({
      authority,
      current_state: state.state,
      actor_account: OTHER_KEY,
      actor_device: H64,
      actor_leaf: LEAF,
      operation_digest: pendingOperationDigest,
      requested_capabilities: ["invite", "read"],
      requested_resources: [RESOURCE_ID],
      requested_delegable: false,
    });
    expect(authorization.verdict).toBe("accept");
    if (authorization.verdict !== "accept") throw new Error("fixture successor authorization rejected");
    expect(evaluateGrantActivation({
      authority,
      current_state: state.state,
      authorization: authorization.authorization,
      grant_id: pendingGrant.grant_id,
      membership: {
        authenticated_account: OTHER_KEY,
        accepted_device: NEW_DEVICE,
        accepted_leaf: NEW_LEAF,
      },
      approvals: pendingApprovals,
      invitation_acceptance: null,
      successor_reauthorization: roleSuccessor.reauthorization,
    })).toMatchObject({ verdict: "accept" });
    expect(evaluateGrantActivation({
      authority,
      current_state: state.state,
      authorization: authorization.authorization,
      grant_id: pendingGrant.grant_id,
      membership: {
        authenticated_account: OTHER_KEY,
        accepted_device: NEW_DEVICE,
        accepted_leaf: NEW_LEAF,
      },
      approvals: pendingApprovals,
      invitation_acceptance: null,
      successor_reauthorization: decoyRoleSuccessor.reauthorization,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("inherits or replaces ordered hosts while retaining a Radicle backstop", () => {
    expect(resolveEffectiveHosts({ inherited, mode: "default", configured: [], last_responsive: H64 }))
      .toEqual({ verdict: "accept", normalized: { host_ids: [H64, OTHER_KEY], radicle_backstop: true } });
    expect(resolveEffectiveHosts({ inherited, mode: "replace", configured: [{
      host_id: CHECKPOINT, priority: 1, radicle_locators: [], radicle_backed_relay: false,
    }], last_responsive: null })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("uses independent device leaves and rotates membership on removal", () => {
    expect(evaluateRoleLeafChange({ account_removed: false, removed_device: H64, active_devices: [H64, OTHER_KEY], current_epoch: 7 }))
      .toEqual({ verdict: "accept", normalized: { next_epoch: 8, removed_devices: [H64], remaining_devices: [OTHER_KEY] } });
    expect(evaluateRoleLeafChange({ account_removed: true, removed_device: null, active_devices: [H64, OTHER_KEY], current_epoch: 7 }))
      .toEqual({ verdict: "accept", normalized: { next_epoch: 8, removed_devices: [H64, OTHER_KEY].sort(), remaining_devices: [] } });
  });

  it("rejects unsafe, fractional, negative, and ill-ordered numeric state", () => {
    expect(evaluatePrivateProjection({
      private_identifiers: ["hidden"],
      private_counts: -1,
      encrypted_placeholders: 0,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(resolveEffectiveHosts({
      inherited: [{
        host_id: H64,
        priority: -1,
        radicle_locators: ["rad:zHost"],
        radicle_backed_relay: true,
      }],
      mode: "default",
      configured: [],
      last_responsive: null,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateRoleLeafChange({
      account_removed: true,
      removed_device: null,
      active_devices: [H64],
      current_epoch: Number.MAX_SAFE_INTEGER,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateKeyRequest({
      resource_known: true,
      host_authorized: true,
      device_active: true,
      membership_active: true,
      checkpoint_age: -1,
      requested_epoch: 1,
      current_epoch: 1,
      admission_epoch: 1,
      history_mode: "full",
      selected_epochs: [],
      target_device: H64,
      target_account: WORKSPACE_KEY,
      authenticated_account: WORKSPACE_KEY,
      authorized_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
      authorized_recipient: LEAF,
      successor_reauthorized: true,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateKeyRequest({
      resource_known: true,
      host_authorized: true,
      device_active: true,
      membership_active: true,
      checkpoint_age: 1,
      requested_epoch: 1,
      current_epoch: 1,
      admission_epoch: 1,
      history_mode: "selected-snapshots",
      selected_epochs: [2],
      target_device: H64,
      target_account: WORKSPACE_KEY,
      authenticated_account: WORKSPACE_KEY,
      authorized_device: H64,
      recipient: { type: "marmot-mls-leaf", value: LEAF },
      authorized_recipient: LEAF,
      successor_reauthorized: true,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateFreshness({
      operation_class: "authority",
      checkpoint_age: -1,
      policy_max_age: 300,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(selectEventRepository({
      active_rid: "rad:zOld",
      active_mls_epoch: 1,
      current_mls_epoch: 1,
      size_bytes: -1,
      max_size_bytes: 1,
      next_rid: "rad:zNew",
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(selectEventRepository({
      active_rid: "rad:zOld",
      active_mls_epoch: 2,
      current_mls_epoch: 1,
      size_bytes: 0,
      max_size_bytes: 1,
      next_rid: "rad:zNew",
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects legacy ambient key-delivery booleans and caller-authored epochs", () => {
    const base = {
      resource_known: true,
      host_authorized: true,
      device_active: true,
      membership_active: true,
      checkpoint_age: 300,
      requested_epoch: 4,
      current_epoch: 6,
      admission_epoch: 4,
      history_mode: "full" as const,
      selected_epochs: [] as number[],
      target_device: H64,
      target_account: WORKSPACE_KEY,
      authenticated_account: WORKSPACE_KEY,
      authorized_device: H64,
      recipient: {
        type: "marmot-mls-leaf",
        value: LEAF,
      },
      authorized_recipient: LEAF,
      successor_reauthorized: true,
    };
    expect(evaluateKeyRequest(base))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects an alternating recipient getter without returning substituted leaf data", () => {
    let reads = 0;
    const recipient = Object.defineProperty({ type: "marmot-mls-leaf" }, "value", {
      enumerable: true,
      get: () => {
        reads += 1;
        return reads < 3 ? LEAF : "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
      },
    });
    const input = {
      resource_known: true,
      host_authorized: true,
      device_active: true,
      membership_active: true,
      checkpoint_age: 1,
      requested_epoch: 1,
      current_epoch: 1,
      admission_epoch: 1,
      history_mode: "full" as const,
      selected_epochs: [] as number[],
      target_device: H64,
      target_account: WORKSPACE_KEY,
      authenticated_account: WORKSPACE_KEY,
      authorized_device: H64,
      recipient,
      authorized_recipient: LEAF,
      successor_reauthorized: true,
    };
    let result: unknown;
    expect(() => { result = evaluateKeyRequest(input); }).not.toThrow();
    expect(result)
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("composes the signed Task-5 trusted-seed ACL without granting governance", async () => {
    const workspace = await import("./workspace.js") as typeof import("./workspace.js") & {
      evaluateWorkspacePrivateRelay?: (input: unknown) => unknown;
    };
    expect(workspace.evaluateWorkspacePrivateRelay).toBeTypeOf("function");

    const seedNid = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
    const privateRid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
    const event = await signEvent({
      secretKey: OTHER_SECRET,
      created_at: 1_720_000_000,
      kind: 445,
      tags: [["h", "workspace-private-route"]],
      content: "ciphertext",
      auxRand: H64,
    });
    const aclBody = {
      profile: "heterodyne.trusted-seed-acl.v1",
      spec_version: "heterodyne/0.5.0",
      administrator_account: WORKSPACE_KEY,
      accounts: [{ account_key: OTHER_KEY, roles: ["read", "write"] }],
      h: "workspace-private-route",
      private_rid: privateRid,
      seed_grants: [{
        seed_nid: seedNid,
        relay_endpoint: "wss://seed.example/group",
        radicle_endpoint: privateRid,
        writer_ref: "refs/xyz.heterodyne.marmot/relays/workspace-seed",
        roles: ["read", "write"],
        state: "active",
      }],
      sequence: 0,
      predecessor: null,
      group_transition: {
        generation: 7,
        marmot_routing_event_id: "77".repeat(32),
        routing_binding_sha256: "88".repeat(32),
      },
      issued_at: 1_719_999_900,
      expires_at: 1_720_001_000,
    };
    const acl = {
      ...aclBody,
      signature: bytesToHex(schnorr.sign(
        trustedSeedAclProofBytes(aclBody),
        WORKSPACE_SECRET,
      )),
    };
    const admission = {
      acl_candidates: [acl],
      expected_administrator_account: WORKSPACE_KEY,
      authenticated_account: OTHER_KEY,
      nip42_authenticated: true,
      operation: "write",
      seed_nid: seedNid,
      h: "workspace-private-route",
      private_rid: privateRid,
      writer_ref: "refs/xyz.heterodyne.marmot/relays/workspace-seed",
      group_transition: aclBody.group_transition,
      now: 1_720_000_100,
      nip01_raw: JSON.stringify(event),
    };
    expect(workspace.evaluateWorkspacePrivateRelay?.({
      workspace_key: WORKSPACE_KEY,
      private_rid: privateRid,
      role_authorized: true,
      governance_requested: false,
      seed_admission: admission,
    })).toMatchObject({ verdict: "accept", normalized: { seed_nid: seedNid } });
    expect(workspace.evaluateWorkspacePrivateRelay?.({
      workspace_key: WORKSPACE_KEY,
      private_rid: privateRid,
      role_authorized: true,
      governance_requested: true,
      seed_admission: admission,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });

    const hostile = new Proxy({}, {
      ownKeys: () => { throw new Error("relay request substituted"); },
    });
    expect(() => workspace.evaluateWorkspacePrivateRelay?.(hostile)).not.toThrow();
    expect(workspace.evaluateWorkspacePrivateRelay?.(hostile))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("enforces exact 24-hour and five-minute checkpoint boundaries", () => {
    expect(evaluateFreshness({ operation_class: "ordinary", checkpoint_age: 86_400, policy_max_age: 86_400 })).toMatchObject({ verdict: "accept" });
    expect(evaluateFreshness({ operation_class: "ordinary", checkpoint_age: 86_401, policy_max_age: 86_400 }))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(evaluateFreshness({ operation_class: "authority", checkpoint_age: 300, policy_max_age: 300 })).toMatchObject({ verdict: "accept" });
    expect(evaluateFreshness({ operation_class: "authority", checkpoint_age: 301, policy_max_age: 300 }))
      .toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(evaluateFreshness({ operation_class: "authority", checkpoint_age: 1, policy_max_age: 301 }))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rotates event repositories at MLS membership or size boundaries", () => {
    expect(selectEventRepository({ active_rid: "rad:zOld", active_mls_epoch: 7, current_mls_epoch: 8, size_bytes: 1, max_size_bytes: 5_000_000_000, next_rid: "rad:zNew" }))
      .toEqual({ verdict: "accept", normalized: { active_rid: "rad:zNew", overlap_rid: "rad:zOld", rotation_reason: "mls-epoch" } });
    expect(selectEventRepository({ active_rid: "rad:zOld", active_mls_epoch: 8, current_mls_epoch: 8, size_bytes: 5_000_000_000, max_size_bytes: 5_000_000_000, next_rid: "rad:zNew" }))
      .toMatchObject({ normalized: { rotation_reason: "size" } });
  });

  it("requires exact event bytes across every carrier", () => {
    const event = "{\"id\":\"same\",\"content\":\"ciphertext\"}";
    expect(eventsAreByteIdentical([event, event, event])).toEqual({ verdict: "accept", normalized: { byte_length: event.length } });
    expect(eventsAreByteIdentical([event, `${event} `]))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
  });
});
