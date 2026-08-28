import { describe, expect, it } from "vitest";
import {
  evaluateWorkspaceAffiliationBoundary,
  evaluateWorkspaceCapabilityBoundary,
  evaluateWorkspaceResourceDeliveryBoundary,
  evaluateWorkspaceResourceKeySeparation,
  evaluateWorkspaceStateTransitionBoundary,
} from "./workspace-policy.js";

describe("current Workspace capability and resource-key boundaries", () => {
  const capability = {
    authenticated_current_state: true,
    explicit_grant: true,
    carrier_only_evidence: false,
    requested_capabilities: ["read"],
    workspace_ceiling: ["read", "write"],
    role_path_ceilings: [["read", "write"], ["read"]],
    grant_capabilities: ["read"],
    revoked_effective: false,
  };

  it("requires explicit current authority and intersects every ceiling", () => {
    expect(evaluateWorkspaceCapabilityBoundary(capability)).toEqual({
      verdict: "accept",
      normalized: { effective_capabilities: ["read"] },
    });
    expect(evaluateWorkspaceCapabilityBoundary({
      ...capability,
      explicit_grant: false,
      carrier_only_evidence: true,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    expect(evaluateWorkspaceCapabilityBoundary({
      ...capability,
      requested_capabilities: ["write"],
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
  });

  it("keeps role admission distinct from unique per-resource content keys", () => {
    expect(evaluateWorkspaceResourceKeySeparation({
      role_epoch_key_id: "role-epoch-7",
      resources: [
        { resource_id: "resource-a", content_key_id: "resource-a-4" },
        { resource_id: "resource-b", content_key_id: "resource-b-2" },
      ],
    })).toEqual({
      verdict: "accept",
      normalized: {
        resource_key_ids: ["resource-a-4", "resource-b-2"],
        role_key_used_as_content_key: false,
      },
    });
    expect(evaluateWorkspaceResourceKeySeparation({
      role_epoch_key_id: "role-epoch-7",
      resources: [{ resource_id: "resource-a", content_key_id: "role-epoch-7" }],
    })).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
  });

  it("rejects stale affiliation and conflicting/replayed state transitions", () => {
    expect(evaluateWorkspaceAffiliationBoundary({
      now: 1_000,
      observed_at: 699,
      expires_at: 1_100,
      maximum_age: 300,
    })).toEqual({ verdict: "reject", reason_code: "affiliation_stale" });
    expect(evaluateWorkspaceStateTransitionBoundary({
      prior_head: "head-a",
      asserted_predecessor: "head-b",
      device_active: true,
      invitation_nonce_unused: true,
    })).toEqual({ verdict: "reject", reason_code: "authority_conflict" });
    expect(evaluateWorkspaceStateTransitionBoundary({
      prior_head: "head-a",
      asserted_predecessor: "head-a",
      device_active: false,
      invitation_nonce_unused: true,
    })).toEqual({ verdict: "reject", reason_code: "device_revoked" });
    expect(evaluateWorkspaceStateTransitionBoundary({
      prior_head: "head-a",
      asserted_predecessor: "head-a",
      device_active: true,
      invitation_nonce_unused: false,
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });
  });

  it("enforces resource existence, custody-host authority, and history ceilings", () => {
    const delivery = {
      resource_id: "resource-a",
      known_resource_ids: ["resource-a"],
      custody_host_id: "host-a",
      authorized_custody_host_ids: ["host-a"],
      requested_epoch: 4,
      current_epoch: 4,
      admission_epoch: 3,
      history_mode: "from-admission" as const,
    };
    expect(evaluateWorkspaceResourceDeliveryBoundary({
      ...delivery,
      resource_id: "resource-b",
    })).toEqual({ verdict: "reject", reason_code: "resource_unknown" });
    expect(evaluateWorkspaceResourceDeliveryBoundary({
      ...delivery,
      custody_host_id: "host-b",
    })).toEqual({ verdict: "reject", reason_code: "host_unauthorized" });
    expect(evaluateWorkspaceResourceDeliveryBoundary({
      ...delivery,
      requested_epoch: 2,
    })).toEqual({ verdict: "reject", reason_code: "history_denied" });
  });
});
