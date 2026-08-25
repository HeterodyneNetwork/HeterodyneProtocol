import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";
import { trustedSeedAclProofBytes } from "./trusted-seed.js";
import {
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
const APPROVER_A_SECRET = "03".repeat(32);
const APPROVER_A_KEY = bytesToHex(schnorr.getPublicKey(APPROVER_A_SECRET));
const APPROVER_B_SECRET = "04".repeat(32);
const APPROVER_B_KEY = bytesToHex(schnorr.getPublicKey(APPROVER_B_SECRET));
const JOINT_SECRET = "05".repeat(32);
const JOINT_KEY = bytesToHex(schnorr.getPublicKey(JOINT_SECRET));
const UNAUTHORIZED_APPROVER_SECRET = "06".repeat(32);

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
    resource_scope: [H64],
    effective_at: 1_720_000_000,
    expires_at: 1_720_001_000,
  }, JOINT_SECRET);
  return {
    joint,
    expected_joint_object_id: objectDigest(joint),
    current: currentState(JOINT_KEY),
    configured_delegate_keys: [APPROVER_A_KEY, APPROVER_B_KEY],
    resource_scope: [H64],
    delegate_proofs: [
      jointDelegateProof([H64], APPROVER_A_SECRET),
      jointDelegateProof([H64], APPROVER_B_SECRET),
    ],
    now: 1_720_000_100,
  };
};

describe("Workspace evaluator input boundary", () => {
  it("rejects null and throwing accessors without any public evaluator throwing", () => {
    const evaluators = [
      evaluateWorkspaceObject,
      evaluateAuthorization,
      evaluateGrantActivation,
      evaluateAllowance,
      evaluatePrivateProjection,
      evaluateJointGovernance,
      resolveEffectiveHosts,
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
});

describe("Workspace role authorization", () => {
  it("activates a grant only from branded effective authority and concrete signed approvals", () => {
    const input = grantActivationFixture();
    expect(evaluateGrantActivation(input)).toEqual({
      verdict: "accept",
      normalized: {
        active: true,
        approval_count: 2,
        approver_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        grant_id: H64,
        operation_digest: input.authorization.operation_digest,
      },
    });

    const widenedCapability = grantActivationFixture();
    widenedCapability.authorization.capability_ceilings[1] = ["invite"];
    expect(evaluateGrantActivation(widenedCapability))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });

    const widenedResource = grantActivationFixture();
    widenedResource.authorization.resource_ceilings[1] = [CHECKPOINT];
    expect(evaluateGrantActivation(widenedResource))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });
  });

  it("rejects duplicate, forged, or wrong-context grant approval records", () => {
    const duplicated = grantActivationFixture();
    duplicated.approvals = [duplicated.approvals[0], duplicated.approvals[0]];
    expect(evaluateGrantActivation(duplicated))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });

    const forged = grantActivationFixture();
    forged.approvals[1] = {
      ...forged.approvals[1],
      signature: "00".repeat(64),
    };
    expect(evaluateGrantActivation(forged))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });

    const wrongContext = grantActivationFixture();
    wrongContext.authorization = {
      ...wrongContext.authorization,
      predecessor: "aa".repeat(32),
    };
    expect(evaluateGrantActivation(wrongContext))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });

    const unauthorized = grantActivationFixture();
    unauthorized.approvals[1] = grantApproval(
      unauthorized.authorization.operation_digest,
      UNAUTHORIZED_APPROVER_SECRET,
    );
    unauthorized.grant = signWorkspaceObject({
      ...unauthorized.grant,
      approval_ids: unauthorized.approvals.map(objectDigest).sort(),
    }, WORKSPACE_SECRET);
    expect(evaluateGrantActivation(unauthorized))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("intersects every ceiling and makes denial and revocation absorbing", () => {
    const base = grantActivationFixture().authorization;
    expect(evaluateAuthorization(base)).toEqual({
      verdict: "accept",
      normalized: {
        actor_account: OTHER_KEY,
        authority_checkpoint: CHECKPOINT,
        effective_capabilities: ["invite", "read"],
        effective_delegable: false,
        effective_approver_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        effective_resources: [H64],
        operation_digest: base.operation_digest,
        policy_head: POLICY_HEAD,
        predecessor: PREDECESSOR,
        workspace_key: WORKSPACE_KEY,
      },
    });
    expect(evaluateAuthorization({ ...base, capability_ceilings: [["invite"]] }))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    expect(evaluateAuthorization({ ...base, denial_ids: [H64] }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    for (const authority_source of ["host", "seed", "repository-writer", "marmot-admin"]) {
      expect(evaluateAuthorization({ ...base, authority_source }))
        .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    }
  });

  it("makes revocation absorbing only from its effective time and never claims erasure", () => {
    const base = {
      ...grantActivationFixture().authorization,
      revocation_effective_at: [1_720_000_010],
      now: 1_720_000_009,
    };
    expect(evaluateAuthorization(base)).toMatchObject({ verdict: "accept" });
    expect(evaluateAuthorization({ ...base, now: 1_720_000_010 }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });
});

describe("Workspace relationships and privacy", () => {
  it("derives affiliation freshness from signed current canonical evidence", () => {
    const input = allowanceFixture();
    expect(evaluateAllowance(input)).toEqual({
      verdict: "accept",
      normalized: {
        capabilities: ["read"],
        proof_age: 300,
        provisional_grace: false,
        relationship_id: H64,
        source_account: OTHER_KEY,
      },
    });

    const grace = allowanceFixture();
    grace.now = 1_720_001_000;
    expect(evaluateAllowance(grace)).toMatchObject({
      verdict: "accept",
      normalized: { proof_age: 900, provisional_grace: true },
    });

    const stale = allowanceFixture();
    stale.now = 1_720_001_001;
    expect(evaluateAllowance(stale))
      .toEqual({ verdict: "reject", reason_code: "affiliation_stale" });

    expect(evaluateAllowance({ ...allowanceFixture(), proof_age: 0 }))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });

  it("rejects forged, forked, rolled-back, or wrong-policy affiliation state", () => {
    const forged = allowanceFixture();
    forged.affiliation = { ...forged.affiliation, signature: "00".repeat(64) };
    expect(evaluateAllowance(forged))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });

    const forked = allowanceFixture();
    forked.source_current.competing_repository_heads = ["aa".repeat(20)];
    expect(evaluateAllowance(forked))
      .toEqual({ verdict: "reject", reason_code: "authority_conflict" });

    const rolledBack = allowanceFixture();
    rolledBack.affiliation = affiliationEvidence(1_720_000_100, "bb".repeat(20));
    expect(evaluateAllowance(rolledBack))
      .toEqual({ verdict: "reject", reason_code: "authority_conflict" });

    const rolledBackAncestor = allowanceFixture();
    const ancestor = "cc".repeat(20);
    rolledBackAncestor.source_current.repository_ancestry = [H40, ancestor];
    rolledBackAncestor.affiliation = affiliationEvidence(1_720_000_100, ancestor);
    expect(evaluateAllowance(rolledBackAncestor))
      .toEqual({ verdict: "reject", reason_code: "authority_conflict" });

    const wrongPolicy = allowanceFixture();
    wrongPolicy.receiving_current.policy_head = H64;
    expect(evaluateAllowance(wrongPolicy))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
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

  it("requires threshold-governed joint identities instead of host authority", () => {
    const input = jointGovernanceFixture();
    expect(evaluateJointGovernance(input)).toEqual({
      verdict: "accept",
      normalized: {
        counted_delegate_keys: [APPROVER_A_KEY, APPROVER_B_KEY].sort(),
        operation_digest: jointOperationDigest([H64]),
        relationship_id: H64,
        threshold: 2,
        threshold_met: true,
      },
    });

    const duplicate = jointGovernanceFixture();
    duplicate.delegate_proofs = [duplicate.delegate_proofs[0], duplicate.delegate_proofs[0]];
    expect(evaluateJointGovernance(duplicate))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });

    const forged = jointGovernanceFixture();
    forged.delegate_proofs[1] = {
      ...forged.delegate_proofs[1],
      signature: "00".repeat(64),
    };
    expect(evaluateJointGovernance(forged))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });

    const impossibleThreshold = jointGovernanceFixture(3);
    expect(evaluateJointGovernance(impossibleThreshold))
      .toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });

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

  it("authorizes device-bound key recovery under all three history modes", () => {
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
    expect(evaluateKeyRequest(base)).toEqual({
      verdict: "accept",
      normalized: {
        key_epoch: 4,
        target_device: H64,
        recipient: {
          type: "marmot-mls-leaf",
          value: LEAF,
        },
        device_bound: true,
        idempotent: true,
      },
    });
    expect(evaluateKeyRequest({
      ...base,
      recipient: {
        type: "nostr-secp256k1",
        value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateKeyRequest({
      ...base,
      recipient: {
        type: "marmot-mls-leaf",
        value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      },
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateKeyRequest({
      ...base,
      recipient: {
        type: "marmot-mls-leaf",
        value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
      },
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
    expect(evaluateKeyRequest({ ...base, history_mode: "from-admission", requested_epoch: 3 }))
      .toEqual({ verdict: "reject", reason_code: "history_denied" });
    expect(evaluateKeyRequest({ ...base, history_mode: "selected-snapshots", requested_epoch: 3, selected_epochs: [3] }))
      .toMatchObject({ verdict: "accept" });
    expect(evaluateKeyRequest({ ...base, host_authorized: false }))
      .toEqual({ verdict: "reject", reason_code: "host_unauthorized" });
    expect(evaluateKeyRequest({ ...base, device_active: false }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateKeyRequest({ ...base, authenticated_account: OTHER_KEY }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateKeyRequest({ ...base, authorized_device: "77".repeat(32) }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateKeyRequest({ ...base, authorized_recipient: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA" }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateKeyRequest({ ...base, successor_reauthorized: false }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    const {
      target_account: _targetAccount,
      authenticated_account: _authenticatedAccount,
      ...missingAccountContext
    } = base;
    expect(evaluateKeyRequest(missingAccountContext))
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
