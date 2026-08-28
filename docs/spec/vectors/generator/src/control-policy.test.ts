import { describe, expect, it } from "vitest";
import {
  evaluateAutomatedControlGrant,
  evaluateCompromiseResetBoundary,
  evaluateControlEnrollmentBoundary,
  evaluateControlOperationRequest,
  evaluateDeviceCodeBoundary,
  validateControlFrameBoundary,
  validateControlSignedEffect,
  validateInvitePreauthorizationBoundary,
} from "./control-policy.js";

describe("current Control semantic policy boundaries", () => {
  it("enforces enrollment capacity, device codes, and preauthorization", () => {
    expect(evaluateControlEnrollmentBoundary({ keypackage_valid: false, member_count: 2, node_account_matches: true, entitlement_state: "none", resource_available: true, welcome_rate_remaining: 1, replenishment_requested: false, replenishment_rate_remaining: 1, pending_at_cap: false, method: "control.enrollment.start" }))
      .toEqual({ verdict: "reject", reason_code: "control-keypackage-invalid" });
    expect(evaluateDeviceCodeBoundary({ entropy_valid: true, failed_guesses: 0, rate_allowed: true, display_binding_matches: false }))
      .toEqual({ verdict: "reject", reason_code: "control-device-code-display-mismatch" });
    expect(validateInvitePreauthorizationBoundary({ purpose_bound: false, finite_template: true, client_bound: true }))
      .toEqual({ verdict: "reject", reason_code: "invite-preauthorization-invalid" });
  });

  it("validates closed frames and replay-safe operations", () => {
    expect(validateControlFrameBoundary({ closed_schema_valid: false, token_valid: true, refresh_requested: false }))
      .toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
    expect(evaluateControlOperationRequest({ now: 100, expires_at: 100, request_id_reused: false, request_digest_matches: true }))
      .toEqual({ verdict: "reject", reason_code: "control-request-expired" });
  });

  it("confines automated grants, signed effects, and reset evidence", () => {
    expect(evaluateAutomatedControlGrant({ method_allowed: false, private_key_requested: false, human_key_profile_selected: false, attribution_canonical: true, resource_allowed: true, event_bytes: 100, max_event_bytes: 200, rate_remaining: 1 }))
      .toEqual({ verdict: "reject", reason_code: "agent-method-prohibited" });
    expect(validateControlSignedEffect({ canonical_event_valid: false, fields_exact: true, effect_certain: true }))
      .toEqual({ verdict: "reject", reason_code: "control-signed-event-invalid" });
    expect(evaluateCompromiseResetBoundary({ authority_signature_valid: true, inventory_digest_matches: true, transition_evidence_valid: false, subordinate_reauthorized: true }))
      .toEqual({ verdict: "reject", reason_code: "control-compromise-reset-evidence-invalid" });
  });
});
