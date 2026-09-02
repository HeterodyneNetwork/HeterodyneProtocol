import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";
import { validateCoreWireEnvelope } from "./core-policy.js";
import { jcsCanonicalize } from "./jcs.js";

type AssurancePin = Readonly<{
  active_key: string;
  assurance_head: string;
  recovery_authority: string;
}>;

export function evaluateAssurancePinPolicy(input: Readonly<{
  retained_pin: AssurancePin;
  presented_head: string;
  authorized_successors: readonly string[];
}>):
  | { verdict: "accept"; state: "pinned" }
  | { verdict: "reject"; reason_code: "assurance-pin-conflict" | "assurance-duplicity" } {
  if (input.presented_head !== input.retained_pin.assurance_head) {
    return { verdict: "reject", reason_code: "assurance-pin-conflict" };
  }
  const successors = new Set(input.authorized_successors);
  if (successors.size > 1) {
    return { verdict: "reject", reason_code: "assurance-duplicity" };
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

const CESR_WIRE_PREFIXES = [
  { selector: "-F", countWidth: 2 },
  { selector: "--F", countWidth: 5 },
  { selector: "-G", countWidth: 2 },
  { selector: "--G", countWidth: 5 },
] as const;

function isCesrBase64UrlCodeUnit(code: number): boolean {
  return (code >= 0x30 && code <= 0x39)
    || (code >= 0x41 && code <= 0x5a)
    || code === 0x2d
    || code === 0x5f
    || (code >= 0x61 && code <= 0x7a);
}

/** Classifies only the bounded selector and complete CESR counter bytes. */
function hasCompleteCesrWirePrefix(serialized: string): boolean {
  for (const { selector, countWidth } of CESR_WIRE_PREFIXES) {
    if (!serialized.startsWith(selector)) continue;
    const countEnd = selector.length + countWidth;
    if (serialized.length < countEnd) return false;
    for (let index = selector.length; index < countEnd; index += 1) {
      if (!isCesrBase64UrlCodeUnit(serialized.charCodeAt(index))) return false;
    }
    return true;
  }
  return false;
}

/** Enforces NIP-01 as the only Assurance wire and storage representation. */
export function validateAssuranceWireFormat(input: Readonly<{
  serialized_record: string;
}>):
  | {
      verdict: "accept";
      format: "nip01";
      event_id: string;
      event_kind: number;
    }
  | {
      verdict: "reject";
      reason_code: "keri_wire_format_rejected" | "assurance-schema-invalid";
    } {
  const serialized = input.serialized_record;
  if (typeof serialized !== "string" || serialized.length === 0 || serialized.length > 1_048_576) {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }
  if (hasCompleteCesrWirePrefix(serialized) || /^KERI\d/u.test(serialized)) {
    return { verdict: "reject", reason_code: "keri_wire_format_rejected" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized) as unknown;
    if (jcsCanonicalize(parsed) !== serialized) {
      return { verdict: "reject", reason_code: "assurance-schema-invalid" };
    }
  } catch {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }

  let snapshot: Readonly<Record<string, unknown>>;
  try {
    const closed = snapshotClosedDataTree(parsed, "Assurance serialized record");
    if (
      closed !== null
      && typeof closed === "object"
      && !Array.isArray(closed)
      && !Object.hasOwn(closed, "event")
      && !Object.hasOwn(closed, "nip01_raw")
      && typeof (closed as Readonly<Record<string, unknown>>).v === "string"
      && /^KERI\d/u.test((closed as Readonly<Record<string, string>>).v)
    ) {
      return { verdict: "reject", reason_code: "keri_wire_format_rejected" };
    }
    snapshot = captureExactDataObject(
      closed,
      [["event", "nip01_raw"]],
      "Assurance NIP-01 envelope",
    );
  } catch {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }
  if (typeof snapshot.nip01_raw !== "string") {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }

  let verified: ReturnType<typeof validateCoreWireEnvelope>;
  try {
    verified = validateCoreWireEnvelope({
      event: snapshot.event as Parameters<typeof validateCoreWireEnvelope>[0]["event"],
      nip01_raw: snapshot.nip01_raw,
      stamp_policy: "optional",
    });
  } catch {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }
  if (verified.verdict === "reject") {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }
  const eventKind = (snapshot.event as Readonly<{ kind?: unknown }>).kind;
  if (
    typeof eventKind !== "number"
    || ![31000, 31001, 31002, 31003, 31006].includes(eventKind)
  ) {
    return { verdict: "reject", reason_code: "assurance-schema-invalid" };
  }
  return {
    verdict: "accept",
    format: "nip01",
    event_id: verified.event_id,
    event_kind: eventKind,
  };
}
