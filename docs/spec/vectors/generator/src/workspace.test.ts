import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";
import { signEvent } from "./nostr.js";
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
      active_workspace_key: WORKSPACE_KEY,
      accepted_policy_head: POLICY_HEAD,
      accepted_predecessor: PREDECESSOR,
      accepted_authority_checkpoint: CHECKPOINT,
      accepted_repository_rid: "rad:zWorkspace",
      accepted_repository_head: H40,
      authority_conflict: false,
    };
    expect(evaluateWorkspaceObject(input)).toEqual({
      verdict: "accept",
      normalized: {
        object_id: workspaceObjectId(object),
        object_type: "workspace-manifest-v1",
        workspace_key: WORKSPACE_KEY,
      },
    });
    for (const changed of [
      { accepted_policy_head: H64 },
      { accepted_predecessor: H64 },
      { accepted_authority_checkpoint: H64 },
      { accepted_repository_head: "77".repeat(20) },
    ]) {
      expect(evaluateWorkspaceObject({ ...input, ...changed }))
        .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
    }
    expect(evaluateWorkspaceObject({ ...input, authority_conflict: true }))
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
      active_workspace_key: WORKSPACE_KEY,
      accepted_policy_head: POLICY_HEAD,
      accepted_predecessor: PREDECESSOR,
      accepted_authority_checkpoint: CHECKPOINT,
      accepted_repository_rid: "rad:zWorkspace",
      accepted_repository_head: H40,
      authority_conflict: false,
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
      active_workspace_key: WORKSPACE_KEY,
      accepted_policy_head: POLICY_HEAD,
      accepted_predecessor: PREDECESSOR,
      accepted_authority_checkpoint: CHECKPOINT,
      accepted_repository_rid: "rad:zWorkspace",
      accepted_repository_head: H40,
      authority_conflict: false,
    })).not.toThrow();
    expect(evaluateWorkspaceObject({
      object: hostile,
      expected_object_id: H64,
      active_workspace_key: WORKSPACE_KEY,
      accepted_policy_head: POLICY_HEAD,
      accepted_predecessor: PREDECESSOR,
      accepted_authority_checkpoint: CHECKPOINT,
      accepted_repository_rid: "rad:zWorkspace",
      accepted_repository_head: H40,
      authority_conflict: false,
    })).toEqual({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  });
});

describe("Workspace role authorization", () => {
  it("intersects every ceiling and makes denial and revocation absorbing", () => {
    const base = {
      requested: ["read", "write"],
      workspace_ceiling: ["read", "write", "admin"],
      role_path_ceilings: [["read", "write"], ["read", "write", "triage"]],
      subject_capabilities: ["read", "write"],
      device_active: true,
      denied: false,
      revoked: false,
      authority_conflict: false,
      carrier_only_evidence: false,
      authority_source: "workspace-policy" as const,
      now: 1_720_000_000,
      revocation_effective_at: null,
      previously_disclosed: false,
    };
    expect(evaluateAuthorization(base)).toEqual({
      verdict: "accept",
      normalized: { effective_capabilities: ["read", "write"] },
    });
    expect(evaluateAuthorization({ ...base, role_path_ceilings: [["read"]] }))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    expect(evaluateAuthorization({ ...base, denied: true }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateAuthorization({ ...base, revoked: true }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateAuthorization({ ...base, carrier_only_evidence: true }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateAuthorization({ ...base, authority_conflict: true }))
      .toEqual({ verdict: "reject", reason_code: "authority_conflict" });
    for (const authority_source of ["host", "seed", "repository-writer", "marmot-admin"] as const) {
      expect(evaluateAuthorization({ ...base, authority_source }))
        .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    }
  });

  it("makes revocation absorbing only from its effective time and never claims erasure", () => {
    const base = {
      requested: ["read"],
      workspace_ceiling: ["read"],
      role_path_ceilings: [["read"]],
      subject_capabilities: ["read"],
      device_active: true,
      denied: false,
      revoked: true,
      revocation_effective_at: 1_720_000_010,
      now: 1_720_000_009,
      authority_conflict: false,
      carrier_only_evidence: false,
      authority_source: "workspace-policy" as const,
      previously_disclosed: true,
    };
    expect(evaluateAuthorization(base)).toMatchObject({ verdict: "accept" });
    expect(evaluateAuthorization({ ...base, now: 1_720_000_010 }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("keeps admin and invitation separate from governance", () => {
    const input = {
      actor_capabilities: ["admin", "invite"],
      grant_capabilities: ["read"],
      grant_delegable: false,
      required_approvals: 1,
      valid_approval_actors: ["actor-a"],
      subject_accepted: true,
      waiting_period_elapsed: true,
      invitation_nonce_unused: true,
      invitation_unexpired: true,
      workspace_key: WORKSPACE_KEY,
      current_workspace_key: WORKSPACE_KEY,
      policy_head: POLICY_HEAD,
      current_policy_head: POLICY_HEAD,
      subject_account: OTHER_KEY,
      authenticated_account: OTHER_KEY,
      target_device: H64,
      accepted_device: H64,
      target_leaf: LEAF,
      accepted_leaf: LEAF,
      successor_reauthorized: true,
    };
    expect(evaluateGrantActivation(input)).toEqual({
      verdict: "accept",
      normalized: { active: true, approval_count: 1 },
    });
    expect(evaluateGrantActivation({ ...input, grant_capabilities: ["govern-policy"] }))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });
    expect(evaluateGrantActivation({ ...input, invitation_nonce_unused: false }))
      .toEqual({ verdict: "reject", reason_code: "workspace_replay" });
    expect(evaluateGrantActivation({ ...input, required_approvals: 2 }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateGrantActivation({ ...input, authenticated_account: WORKSPACE_KEY }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateGrantActivation({ ...input, accepted_device: CHECKPOINT }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateGrantActivation({ ...input, accepted_leaf: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA" }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateGrantActivation({ ...input, successor_reauthorized: false }))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
    const {
      workspace_key: _workspaceKey,
      current_workspace_key: _currentWorkspaceKey,
      ...missingWorkspaceContext
    } = input;
    expect(evaluateGrantActivation(missingWorkspaceContext))
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });
});

describe("Workspace relationships and privacy", () => {
  it("verifies both active workspace signatures and a continuously fresh affiliation", () => {
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
    const base = {
      relationship,
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
      requested_capabilities: ["read"],
      proof_age: 300,
    };
    expect(evaluateAllowance(base)).toMatchObject({ verdict: "accept" });
    expect(evaluateAllowance({ ...base, proof_age: 900 })).toMatchObject({ verdict: "accept" });
    expect(evaluateAllowance({ ...base, proof_age: 901 }))
      .toEqual({ verdict: "reject", reason_code: "affiliation_stale" });
    expect(evaluateAllowance({
      ...base,
      relationship: { ...relationship, receiving_signature: "00".repeat(64) },
      signatures_match: true,
    }))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
    expect(evaluateAllowance({ ...base, requested_capabilities: ["govern-policy"] }))
      .toEqual({ verdict: "reject", reason_code: "capability_escalation" });
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
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
  });

  it("requires threshold-governed joint identities instead of host authority", () => {
    expect(evaluateJointGovernance({
      independent_joint_identity: true,
      valid_distinct_delegates: 2,
      threshold: 2,
      host_signatures_counted: 0,
    })).toMatchObject({ verdict: "accept" });
    expect(evaluateJointGovernance({
      independent_joint_identity: false,
      valid_distinct_delegates: 1,
      threshold: 2,
      host_signatures_counted: 1,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });
});

describe("Workspace hosts, keys, repositories, and freshness", () => {
  const inherited = [
    { host_id: "a", priority: 20, radicle_locators: ["rad:zA"], radicle_backed_relay: true },
    { host_id: "b", priority: 10, radicle_locators: ["rad:zB"], radicle_backed_relay: true },
  ];

  it("inherits or replaces ordered hosts while retaining a Radicle backstop", () => {
    expect(resolveEffectiveHosts({ inherited, mode: "default", configured: [], last_responsive: "a" }))
      .toEqual({ verdict: "accept", normalized: { host_ids: ["a", "b"], radicle_backstop: true } });
    expect(resolveEffectiveHosts({ inherited, mode: "replace", configured: [{
      host_id: "c", priority: 1, radicle_locators: [], radicle_backed_relay: false,
    }], last_responsive: null })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("uses independent device leaves and rotates membership on removal", () => {
    expect(evaluateRoleLeafChange({ persona_removed: false, removed_device: "d1", active_devices: ["d1", "d2"], current_epoch: 7 }))
      .toEqual({ verdict: "accept", normalized: { next_epoch: 8, removed_devices: ["d1"], remaining_devices: ["d2"] } });
    expect(evaluateRoleLeafChange({ persona_removed: true, removed_device: null, active_devices: ["d1", "d2"], current_epoch: 7 }))
      .toEqual({ verdict: "accept", normalized: { next_epoch: 8, removed_devices: ["d1", "d2"], remaining_devices: [] } });
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
      .toEqual({ verdict: "reject", reason_code: "policy_denied" });
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
