import { describe, expect, it } from "vitest";
import {
  applySocialAdmission,
  controlGroupAdmission,
  ordinaryConversationAdmission,
} from "./marmot-admission.js";

const ordinary = {
  cryptographic_valid: true,
  inviter_account: "11".repeat(32),
  recipient_account: "22".repeat(32),
  group_id: "33".repeat(32),
  key_package_ref: "44".repeat(32),
  member_count: 2,
  supported_capabilities: true,
  prior_local_acceptance: false,
  one_time_dm_invite_valid: false,
  explicit_local_decision: "none" as const,
};

describe("ordinary Marmot conversation admission", () => {
  it("rejects authentication before invoking policy", () => {
    expect(ordinaryConversationAdmission({ ...ordinary, cryptographic_valid: false }))
      .toEqual({ outcome: "reject", policy_hook_invoked: false, reason_code: "bad_signature" });
  });

  it("holds an unknown valid Welcome without sender-observable signals", () => {
    expect(ordinaryConversationAdmission(ordinary)).toEqual({
      outcome: "hold-as-message-request",
      policy_hook_invoked: true,
      sender_observable_signals: [],
    });
  });

  it("accepts prior decisions and valid purpose-bound DM invites", () => {
    expect(ordinaryConversationAdmission({ ...ordinary, prior_local_acceptance: true }).outcome)
      .toBe("accept");
    expect(ordinaryConversationAdmission({ ...ordinary, one_time_dm_invite_valid: true }).outcome)
      .toBe("accept");
  });

  it("reports an explicit local rejection with the registered conversation reason", () => {
    expect(ordinaryConversationAdmission({ ...ordinary, explicit_local_decision: "reject" }))
      .toEqual({
        outcome: "reject",
        policy_hook_invoked: true,
        reason_code: "conversation-rejected",
      });
  });

  it("allows Social only to tighten and keeps reject absorbing", () => {
    expect(applySocialAdmission("accept", "hold-as-message-request", false, false))
      .toBe("hold-as-message-request");
    expect(applySocialAdmission("hold-as-message-request", "accept", false, false))
      .toBe("hold-as-message-request");
    expect(applySocialAdmission("reject", "accept", false, false)).toBe("reject");
    expect(applySocialAdmission("accept", "accept", true, false)).toBe("reject");
  });
});

describe("Control Marmot group admission", () => {
  const control = {
    cryptographic_valid: true,
    member_count: 2,
    node_account_matches: true,
    supported_control_profile: true,
    invitation_mode: "off" as const,
    temporary_mode_unexpired: false,
    resource_available: true,
    entitlement_state: "none" as const,
    purpose_bound_invite_valid: false,
    explicit_local_decision: "none" as const,
  };

  it("defaults unsolicited Control invitations to off", () => {
    expect(controlGroupAdmission(control)).toEqual({
      outcome: "reject",
      reason_code: "control-enrollment-unavailable",
    });
  });

  it("accepts only enrollment for open or purpose-bound invitation paths", () => {
    expect(controlGroupAdmission({ ...control, invitation_mode: "permanent" }).outcome)
      .toBe("accept-enrollment-only");
    expect(controlGroupAdmission({ ...control, purpose_bound_invite_valid: true }).outcome)
      .toBe("accept-enrollment-only");
  });

  it("requires active non-conflicted entitlement for authorized admission", () => {
    expect(controlGroupAdmission({ ...control, entitlement_state: "active" }).outcome)
      .toBe("accept-authorized");
    expect(controlGroupAdmission({ ...control, entitlement_state: "conflicted" }).outcome)
      .toBe("reject");
  });

  it("keeps explicit rejection and resource bounds absorbing", () => {
    expect(controlGroupAdmission({
      ...control,
      entitlement_state: "active",
      explicit_local_decision: "reject",
    })).toEqual({ outcome: "reject", reason_code: "control-enrollment-unavailable" });
    expect(controlGroupAdmission({
      ...control,
      entitlement_state: "active",
      resource_available: false,
    })).toEqual({ outcome: "reject", reason_code: "control-enrollment-unavailable" });
  });
});
