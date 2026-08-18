import { describe, expect, it } from "vitest";
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
} from "./workspace.js";

const H64 = "11".repeat(32);
const H40 = "33".repeat(20);

describe("Workspace signed objects", () => {
  it("verifies schema, signature, KERI and repository binding, and digest", () => {
    const object = signWorkspaceObject({
      spec_version: "heterodyne/0.5.0",
      object_type: "workspace-manifest-v1",
      workspace_id: H64,
      kel_head: H64,
      authority_sequence: 1,
      repository_rid: "rad:zWorkspace",
      repository_head: H40,
      issued_at: 1_720_000_000,
      root_policy_rid: "rad:zPolicy",
      root_policy_head: H64,
      visibility: "private",
      public_roles: [],
    }, "01".repeat(32));
    const input = {
      object,
      expected_object_id: workspaceObjectId(object),
      keri_authoritative: true,
      repository_reachable: true,
    };
    expect(evaluateWorkspaceObject(input)).toEqual({
      verdict: "accept",
      normalized: {
        object_id: workspaceObjectId(object),
        object_type: "workspace-manifest-v1",
      },
    });
    expect(evaluateWorkspaceObject({ ...input, repository_reachable: false }))
      .toEqual({ verdict: "reject", reason_code: "workspace_signature_invalid" });
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
  });
});

describe("Workspace relationships and privacy", () => {
  it("requires matching bilateral signatures and a continuously fresh affiliation", () => {
    const base = {
      signatures_match: true,
      receiving_policy_allows: true,
      revoked: false,
      expired: false,
      requested_capabilities: ["read"],
      capability_ceiling: ["read", "triage"],
      proof_age: 300,
      proof_max_age: 300,
      grace_period: 600,
    };
    expect(evaluateAllowance(base)).toMatchObject({ verdict: "accept" });
    expect(evaluateAllowance({ ...base, proof_age: 900 })).toMatchObject({ verdict: "accept" });
    expect(evaluateAllowance({ ...base, proof_age: 901 }))
      .toEqual({ verdict: "reject", reason_code: "affiliation_stale" });
    expect(evaluateAllowance({ ...base, signatures_match: false }))
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
      recipient: {
        type: "marmot-mls-leaf",
        value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    };
    expect(evaluateKeyRequest(base)).toEqual({
      verdict: "accept",
      normalized: {
        key_epoch: 4,
        target_device: H64,
        recipient: {
          type: "marmot-mls-leaf",
          value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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
    expect(evaluateKeyRequest({ ...base, history_mode: "from-admission", requested_epoch: 3 }))
      .toEqual({ verdict: "reject", reason_code: "history_denied" });
    expect(evaluateKeyRequest({ ...base, history_mode: "selected-snapshots", requested_epoch: 3, selected_epochs: [3] }))
      .toMatchObject({ verdict: "accept" });
    expect(evaluateKeyRequest({ ...base, host_authorized: false }))
      .toEqual({ verdict: "reject", reason_code: "host_unauthorized" });
    expect(evaluateKeyRequest({ ...base, device_active: false }))
      .toEqual({ verdict: "reject", reason_code: "device_revoked" });
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
