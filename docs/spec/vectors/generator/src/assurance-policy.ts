type AssurancePin = Readonly<{
  active_key: string;
  assurance_head: string;
  recovery_authority: string;
}>;

export function evaluateAssurancePinPolicy(input: Readonly<{
  retained_pin: AssurancePin;
  presented_head: string;
  downgrade: null | Readonly<{
    active_key_consent: boolean;
    recovery_authority_proof: boolean;
  }>;
  authorized_successors: readonly string[];
}>):
  | { verdict: "accept"; state: "pinned" | "downgraded" }
  | { verdict: "reject"; reason_code: "assurance-pin-conflict" | "assurance-downgrade-consent-required" | "assurance-duplicity" } {
  if (input.presented_head !== input.retained_pin.assurance_head) {
    return { verdict: "reject", reason_code: "assurance-pin-conflict" };
  }
  const successors = new Set(input.authorized_successors);
  if (successors.size > 1) {
    return { verdict: "reject", reason_code: "assurance-duplicity" };
  }
  if (input.downgrade !== null) {
    if (!input.downgrade.active_key_consent || !input.downgrade.recovery_authority_proof) {
      return { verdict: "reject", reason_code: "assurance-downgrade-consent-required" };
    }
    return { verdict: "accept", state: "downgraded" };
  }
  return { verdict: "accept", state: "pinned" };
}

export function evaluateAssuranceExport(input: Readonly<{
  active_key: string;
  requested_aid: string;
  requested_suite: string;
  supported_suites: readonly string[];
  accepted_features: readonly string[];
  mapped_features: readonly string[];
  required_members: readonly string[];
  mapped_members: Readonly<Record<string, unknown>>;
}>):
  | { verdict: "accept"; projection: Readonly<Record<string, unknown>> }
  | { verdict: "reject"; reason_code: "export_unsupported_crypto_suite" | "export_unmappable_feature" | "export_incomplete" | "export_aid_substituted_for_npub" } {
  if (!input.supported_suites.includes(input.requested_suite)) {
    return { verdict: "reject", reason_code: "export_unsupported_crypto_suite" };
  }
  const mappedFeatures = new Set(input.mapped_features);
  if (input.accepted_features.some((feature) => !mappedFeatures.has(feature))) {
    return { verdict: "reject", reason_code: "export_unmappable_feature" };
  }
  if (input.required_members.some((member) => !Object.hasOwn(input.mapped_members, member))) {
    return { verdict: "reject", reason_code: "export_incomplete" };
  }
  if (input.requested_aid !== input.active_key) {
    return { verdict: "reject", reason_code: "export_aid_substituted_for_npub" };
  }
  return {
    verdict: "accept",
    projection: structuredClone(input.mapped_members),
  };
}

/** Applies the public agent associated-key proof-of-possession requirement. */
export function evaluateAssuranceAssociatedKeyConsent(input: Readonly<{
  state: "active" | "revoked";
  role: string;
  visibility: "public" | "private";
  subject_proof_present: boolean;
  subject_proof_valid: boolean;
}>):
  | { verdict: "accept" }
  | {
      verdict: "reject";
      reason_code:
        | "assurance-associated-key-subject-proof-required"
        | "assurance-associated-key-subject-proof-invalid";
    } {
  const proofRequired = input.state === "active"
    && input.role === "agent"
    && input.visibility === "public";
  if (proofRequired && !input.subject_proof_present) {
    return {
      verdict: "reject",
      reason_code: "assurance-associated-key-subject-proof-required",
    };
  }
  if (proofRequired && !input.subject_proof_valid) {
    return {
      verdict: "reject",
      reason_code: "assurance-associated-key-subject-proof-invalid",
    };
  }
  return { verdict: "accept" };
}

/** Prevents compromise recovery from implicitly carrying subordinates forward. */
export function evaluateAssuranceCompromiseContinuation(input: Readonly<{
  transition_class: "routine" | "compromise";
  subordinate_reauthorization_ids: readonly string[];
}>):
  | { verdict: "accept" }
  | { verdict: "reject"; reason_code: "assurance-subordinate-continuation-forbidden" } {
  if (
    input.transition_class === "compromise"
    && input.subordinate_reauthorization_ids.length > 0
  ) {
    return {
      verdict: "reject",
      reason_code: "assurance-subordinate-continuation-forbidden",
    };
  }
  return { verdict: "accept" };
}

/** Enforces NIP-01 as the only Assurance wire and storage representation. */
export function validateAssuranceWireFormat(input: Readonly<{
  format: "nip01" | "keri10json" | "cesr";
  serialized_record: string;
}>):
  | { verdict: "accept"; format: "nip01" }
  | { verdict: "reject"; reason_code: "keri_wire_format_rejected" } {
  if (input.format !== "nip01") {
    return { verdict: "reject", reason_code: "keri_wire_format_rejected" };
  }
  return { verdict: "accept", format: "nip01" };
}
