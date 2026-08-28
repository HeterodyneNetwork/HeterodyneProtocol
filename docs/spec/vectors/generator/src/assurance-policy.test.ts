import { describe, expect, it } from "vitest";
import {
  evaluateAssuranceAssociatedKeyConsent,
  evaluateAssuranceCompromiseContinuation,
  evaluateAssuranceExport,
  evaluateAssurancePinPolicy,
  validateAssuranceWireFormat,
} from "./assurance-policy.js";

const pin = {
  active_key: "11".repeat(32),
  assurance_head: "22".repeat(32),
  recovery_authority: "33".repeat(32),
};

describe("current Assurance pin and export policy", () => {
  it("rejects KERI export bytes when presented as an Assurance wire record", () => {
    expect(validateAssuranceWireFormat({
      format: "keri10json",
      serialized_record: "{\"v\":\"KERI10JSON000000_\"}",
    })).toEqual({ verdict: "reject", reason_code: "keri_wire_format_rejected" });
  });

  it("rejects conflicting pins, unilateral downgrade, and duplicity", () => {
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: "44".repeat(32),
      downgrade: null,
      authorized_successors: [],
    })).toEqual({ verdict: "reject", reason_code: "assurance-pin-conflict" });
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: pin.assurance_head,
      downgrade: { active_key_consent: true, recovery_authority_proof: false },
      authorized_successors: [],
    })).toEqual({ verdict: "reject", reason_code: "assurance-downgrade-consent-required" });
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: pin.assurance_head,
      downgrade: null,
      authorized_successors: ["55".repeat(32), "66".repeat(32)],
    })).toEqual({ verdict: "reject", reason_code: "assurance-duplicity" });
  });

  it("exports only a complete lossless supported projection", () => {
    const input = {
      active_key: "11".repeat(32),
      requested_aid: "11".repeat(32),
      requested_suite: "Ed25519" as const,
      supported_suites: ["Ed25519"] as const,
      accepted_features: ["continuity", "associated-keys"] as const,
      mapped_features: ["associated-keys", "continuity"] as const,
      required_members: ["active_key", "head"] as const,
      mapped_members: { active_key: "11".repeat(32), head: "22".repeat(32) },
    };
    expect(evaluateAssuranceExport(input)).toMatchObject({ verdict: "accept" });
    expect(evaluateAssuranceExport({ ...input, requested_suite: "P-256" as never }))
      .toEqual({ verdict: "reject", reason_code: "export_unsupported_crypto_suite" });
    expect(evaluateAssuranceExport({ ...input, mapped_features: ["continuity"] }))
      .toEqual({ verdict: "reject", reason_code: "export_unmappable_feature" });
    expect(evaluateAssuranceExport({ ...input, mapped_members: { active_key: input.active_key } }))
      .toEqual({ verdict: "reject", reason_code: "export_incomplete" });
    expect(evaluateAssuranceExport({ ...input, requested_aid: "77".repeat(32) }))
      .toEqual({ verdict: "reject", reason_code: "export_aid_substituted_for_npub" });
  });

  it("keeps subject consent and compromise subordinate closure semantic", () => {
    expect(evaluateAssuranceAssociatedKeyConsent({
      state: "active",
      role: "agent",
      visibility: "public",
      subject_proof_present: false,
      subject_proof_valid: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-associated-key-subject-proof-required",
    });
    expect(evaluateAssuranceCompromiseContinuation({
      transition_class: "compromise",
      subordinate_reauthorization_ids: ["associated-key-1"],
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-subordinate-continuation-forbidden",
    });
  });
});
