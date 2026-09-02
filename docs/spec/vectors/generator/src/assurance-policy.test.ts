import { describe, expect, it } from "vitest";
import {
  evaluateAssuranceAssociatedKeyConsent,
  evaluateAssuranceCompromiseContinuation,
  evaluateAssuranceExport,
  evaluateAssurancePinPolicy,
  validateAssuranceWireFormat,
} from "./assurance-policy.js";
import { jcsCanonicalize } from "./jcs.js";
import { canonicalNip01, signEvent } from "./nostr.js";

const pin = {
  active_key: "11".repeat(32),
  assurance_head: "22".repeat(32),
  recovery_authority: "33".repeat(32),
};

describe("current Assurance pin and export policy", () => {
  it("classifies KERI and CESR from exact bytes despite crossed or absent labels", () => {
    const keri = "{\"v\":\"KERI10JSON000000_\"}";
    expect(validateAssuranceWireFormat({
      format: "nip01",
      serialized_record: keri,
    } as never)).toEqual({
      verdict: "reject",
      reason_code: "keri_wire_format_rejected",
    });
    expect(validateAssuranceWireFormat({ serialized_record: keri })).toEqual({
      verdict: "reject",
      reason_code: "keri_wire_format_rejected",
    });
    expect(validateAssuranceWireFormat({ serialized_record: "-FABB0KERICesrFixture" }))
      .toEqual({ verdict: "reject", reason_code: "keri_wire_format_rejected" });
  });

  it("classifies only complete small and large CESR count and native field-map prefixes", () => {
    for (const serialized_record of [
      "-FAAcurrent-cesr-count",
      "--FAAAAAcurrent-large-cesr-count",
      "-GAAcurrent-cesr-field-map",
      "--GAAAAAcurrent-large-cesr-field-map",
    ]) {
      expect(validateAssuranceWireFormat({ serialized_record }), serialized_record)
        .toEqual({ verdict: "reject", reason_code: "keri_wire_format_rejected" });
    }
    for (const serialized_record of [
      "-F",
      "-FA",
      "-F!A",
      "--F",
      "--FAAAA",
      "-G",
      "-GA",
      "-G?A",
      "--G",
      "--GAAAA",
      "-HAAnear-miss",
    ]) {
      expect(validateAssuranceWireFormat({ serialized_record }), serialized_record)
        .toEqual({ verdict: "reject", reason_code: "assurance-schema-invalid" });
    }
  });

  it("accepts only an exact canonical closed NIP-01 envelope", async () => {
    const event = await signEvent({
      secretKey: "41".repeat(32),
      created_at: 1800000000,
      kind: 31002,
      tags: [["d", "assurance-wire-profile"]],
      content: jcsCanonicalize({
        profile: "heterodyne.assurance.enrollment-inception.v1",
        spec_version: "heterodyne/0.6.0",
      }),
      auxRand: "00".repeat(32),
    });
    const serialized_record = jcsCanonicalize({
      event,
      nip01_raw: canonicalNip01(event),
    });

    expect(validateAssuranceWireFormat({ serialized_record })).toEqual({
      verdict: "accept",
      format: "nip01",
      event_id: event.id,
      event_kind: event.kind,
    });
    for (const malformed of [
      ` ${serialized_record}`,
      `{\"event\":${JSON.stringify(event)},\"event\":${JSON.stringify(event)},\"nip01_raw\":${JSON.stringify(canonicalNip01(event))}}`,
      jcsCanonicalize({ event, nip01_raw: canonicalNip01(event), v: "KERI10JSON000000_" }),
      "{\"event\":null,\"nip01_raw\":\"[]\"}",
      "{\"event\":{},\"nip01_raw\":\"[]\",\"__proto__\":{}}",
    ]) {
      expect(validateAssuranceWireFormat({ serialized_record: malformed }), malformed)
        .toEqual({ verdict: "reject", reason_code: "assurance-schema-invalid" });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects conflicting pins and duplicity without a boolean downgrade path", () => {
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: "44".repeat(32),
      authorized_successors: [],
    })).toEqual({ verdict: "reject", reason_code: "assurance-pin-conflict" });
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: pin.assurance_head,
      authorized_successors: [],
      downgrade: { active_key_consent: true, recovery_authority_proof: true },
    } as never)).toEqual({ verdict: "accept", state: "pinned" });
    expect(evaluateAssurancePinPolicy({
      retained_pin: pin,
      presented_head: pin.assurance_head,
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
