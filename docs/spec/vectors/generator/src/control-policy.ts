export function evaluateControlEnrollmentBoundary(input: {
  keypackage_valid: boolean;
  member_count: number;
  node_account_matches: boolean;
  entitlement_state: "none" | "active" | "revoked" | "conflicted";
  resource_available: boolean;
  welcome_rate_remaining: number;
  replenishment_requested: boolean;
  replenishment_rate_remaining: number;
  pending_at_cap: boolean;
  method: string;
}): { verdict: "accept"; state: "enrollment-only" | "authorized" } | {
  verdict: "reject";
  reason_code:
    | "control-keypackage-invalid"
    | "control-entitlement-conflict"
    | "control-enrollment-unavailable"
    | "control-keypackage-replenishment-paused"
    | "control-enrollment-rate-limited"
    | "control-enrollment-required";
} {
  if (!input.keypackage_valid || input.member_count !== 2 || !input.node_account_matches) {
    return { verdict: "reject", reason_code: "control-keypackage-invalid" };
  }
  if (input.entitlement_state === "revoked" || input.entitlement_state === "conflicted") {
    return { verdict: "reject", reason_code: "control-entitlement-conflict" };
  }
  if (!input.resource_available) {
    return { verdict: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (input.replenishment_requested && input.pending_at_cap) {
    return { verdict: "reject", reason_code: "control-keypackage-replenishment-paused" };
  }
  if (input.welcome_rate_remaining <= 0 || input.replenishment_requested && input.replenishment_rate_remaining <= 0) {
    return { verdict: "reject", reason_code: "control-enrollment-rate-limited" };
  }
  if (input.pending_at_cap) {
    return { verdict: "reject", reason_code: "control-enrollment-unavailable" };
  }
  if (
    input.entitlement_state !== "active"
    && input.method !== "control.enrollment.start"
    && input.method !== "control.initialize"
  ) return { verdict: "reject", reason_code: "control-enrollment-required" };
  return {
    verdict: "accept",
    state: input.entitlement_state === "active" ? "authorized" : "enrollment-only",
  };
}

export function evaluateDeviceCodeBoundary(input: {
  entropy_valid: boolean;
  failed_guesses: number;
  rate_allowed: boolean;
  display_binding_matches: boolean;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "control-device-code-invalid" | "control-device-code-rate-limited" | "control-device-code-display-mismatch";
} {
  if (!input.entropy_valid || input.failed_guesses >= 5) {
    return { verdict: "reject", reason_code: "control-device-code-invalid" };
  }
  if (!input.rate_allowed) {
    return { verdict: "reject", reason_code: "control-device-code-rate-limited" };
  }
  return input.display_binding_matches
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "control-device-code-display-mismatch" };
}

export function validateInvitePreauthorizationBoundary(input: {
  purpose_bound: boolean;
  finite_template: boolean;
  client_bound: boolean;
}): { verdict: "accept" } | { verdict: "reject"; reason_code: "invite-preauthorization-invalid" } {
  return input.purpose_bound && input.finite_template && input.client_bound
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "invite-preauthorization-invalid" };
}

export function validateControlFrameBoundary(input: {
  closed_schema_valid: boolean;
  token_valid: boolean;
  refresh_requested: boolean;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "control-frame-invalid" | "control-token-invalid" | "control-refresh-prohibited";
} {
  if (!input.closed_schema_valid) return { verdict: "reject", reason_code: "control-frame-invalid" };
  if (input.refresh_requested) return { verdict: "reject", reason_code: "control-refresh-prohibited" };
  return input.token_valid
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "control-token-invalid" };
}

export function evaluateControlOperationRequest(input: {
  now: number;
  expires_at: number;
  request_id_reused: boolean;
  request_digest_matches: boolean;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "control-request-expired" | "control-request-id-conflict";
} {
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.expires_at) || input.now >= input.expires_at) {
    return { verdict: "reject", reason_code: "control-request-expired" };
  }
  if (input.request_id_reused && !input.request_digest_matches) {
    return { verdict: "reject", reason_code: "control-request-id-conflict" };
  }
  return { verdict: "accept" };
}

export function evaluateAutomatedControlGrant(input: {
  method_allowed: boolean;
  private_key_requested: boolean;
  human_key_profile_selected: boolean;
  attribution_canonical: boolean;
  resource_allowed: boolean;
  event_bytes: number;
  max_event_bytes: number;
  rate_remaining: number;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code:
    | "agent-method-prohibited"
    | "agent-key-access-prohibited"
    | "agent-human-profile-prohibited"
    | "agent-attribution-bypass-prohibited"
    | "agent-resource-denied"
    | "agent-size-exceeded"
    | "agent-rate-limited";
} {
  if (!input.method_allowed) return { verdict: "reject", reason_code: "agent-method-prohibited" };
  if (input.private_key_requested) return { verdict: "reject", reason_code: "agent-key-access-prohibited" };
  if (input.human_key_profile_selected) return { verdict: "reject", reason_code: "agent-human-profile-prohibited" };
  if (!input.attribution_canonical) return { verdict: "reject", reason_code: "agent-attribution-bypass-prohibited" };
  if (!input.resource_allowed) return { verdict: "reject", reason_code: "agent-resource-denied" };
  if (!Number.isSafeInteger(input.event_bytes) || input.event_bytes > input.max_event_bytes) {
    return { verdict: "reject", reason_code: "agent-size-exceeded" };
  }
  return input.rate_remaining > 0
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "agent-rate-limited" };
}

export function validateControlSignedEffect(input: {
  canonical_event_valid: boolean;
  fields_exact: boolean;
  effect_certain: boolean;
}): { verdict: "accept" } | {
  verdict: "reject" | "indeterminate";
  reason_code: "control-signed-event-invalid" | "control-signer-effect-indeterminate";
} {
  if (!input.canonical_event_valid || !input.fields_exact) {
    return { verdict: "reject", reason_code: "control-signed-event-invalid" };
  }
  return input.effect_certain
    ? { verdict: "accept" }
    : { verdict: "indeterminate", reason_code: "control-signer-effect-indeterminate" };
}

export function evaluateCompromiseResetBoundary(input: {
  authority_signature_valid: boolean;
  inventory_digest_matches: boolean;
  transition_evidence_valid: boolean;
  subordinate_reauthorized: boolean;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code:
    | "control-compromise-reset-unauthenticated"
    | "control-compromise-reset-inventory-mismatch"
    | "control-compromise-reset-evidence-invalid"
    | "control-subordinate-reauthorization-required";
} {
  if (!input.authority_signature_valid) {
    return { verdict: "reject", reason_code: "control-compromise-reset-unauthenticated" };
  }
  if (!input.inventory_digest_matches) {
    return { verdict: "reject", reason_code: "control-compromise-reset-inventory-mismatch" };
  }
  if (!input.transition_evidence_valid) {
    return { verdict: "reject", reason_code: "control-compromise-reset-evidence-invalid" };
  }
  return input.subordinate_reauthorized
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "control-subordinate-reauthorization-required" };
}
