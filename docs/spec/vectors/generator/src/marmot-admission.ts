export type OrdinaryOutcome = "accept" | "hold-as-message-request" | "reject";
export type ControlOutcome = "accept-enrollment-only" | "accept-authorized" | "reject";

export type OrdinaryAdmissionInput = {
  cryptographic_valid: boolean;
  inviter_account: string;
  recipient_account: string;
  group_id: string;
  key_package_ref: string;
  member_count: number;
  supported_capabilities: boolean;
  prior_local_acceptance: boolean;
  one_time_dm_invite_valid: boolean;
  explicit_local_decision: "none" | "accept" | "reject";
};

export function ordinaryConversationAdmission(input: OrdinaryAdmissionInput):
  | { outcome: "reject"; policy_hook_invoked: boolean; reason_code?: string }
  | { outcome: "accept"; policy_hook_invoked: true }
  | { outcome: "hold-as-message-request"; policy_hook_invoked: true; sender_observable_signals: [] } {
  if (!input.cryptographic_valid) {
    return { outcome: "reject", policy_hook_invoked: false, reason_code: "bad_signature" };
  }
  if (input.member_count !== 2 || !input.supported_capabilities) {
    return { outcome: "reject", policy_hook_invoked: true };
  }
  if (input.explicit_local_decision === "reject") {
    return { outcome: "reject", policy_hook_invoked: true };
  }
  if (input.prior_local_acceptance
    || input.one_time_dm_invite_valid
    || input.explicit_local_decision === "accept") {
    return { outcome: "accept", policy_hook_invoked: true };
  }
  return {
    outcome: "hold-as-message-request",
    policy_hook_invoked: true,
    sender_observable_signals: [],
  };
}

const ORDER: Record<OrdinaryOutcome, number> = {
  accept: 2,
  "hold-as-message-request": 1,
  reject: 0,
};

export function applySocialAdmission(
  commsOutcome: OrdinaryOutcome,
  requestedSocialOutcome: OrdinaryOutcome,
  muted: boolean,
  blocked: boolean,
): OrdinaryOutcome {
  if (commsOutcome === "reject" || muted || blocked) return "reject";
  return ORDER[requestedSocialOutcome] < ORDER[commsOutcome]
    ? requestedSocialOutcome
    : commsOutcome;
}

export type ControlAdmissionInput = {
  cryptographic_valid: boolean;
  member_count: number;
  node_account_matches: boolean;
  supported_control_profile: boolean;
  invitation_mode: "off" | "temporary" | "permanent";
  temporary_mode_unexpired: boolean;
  resource_available: boolean;
  entitlement_state: "none" | "active" | "revoked" | "conflicted";
  purpose_bound_invite_valid: boolean;
  explicit_local_decision: "none" | "accept" | "reject";
};

export function controlGroupAdmission(input: ControlAdmissionInput): {
  outcome: ControlOutcome;
  reason_code?: string;
} {
  if (!input.cryptographic_valid
    || input.member_count !== 2
    || !input.node_account_matches
    || !input.supported_control_profile) {
    return { outcome: "reject", reason_code: "control-keypackage-invalid" };
  }
  if (input.explicit_local_decision === "reject") {
    return { outcome: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (input.entitlement_state === "revoked" || input.entitlement_state === "conflicted") {
    return { outcome: "reject", reason_code: "control-entitlement-conflict" };
  }
  if (!input.resource_available) {
    return { outcome: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (input.entitlement_state === "active") return { outcome: "accept-authorized" };
  const open = input.invitation_mode === "permanent"
    || (input.invitation_mode === "temporary" && input.temporary_mode_unexpired);
  if (input.purpose_bound_invite_valid || input.explicit_local_decision === "accept" || open) {
    return { outcome: "accept-enrollment-only" };
  }
  return { outcome: "reject", reason_code: "control-enrollment-unavailable" };
}
