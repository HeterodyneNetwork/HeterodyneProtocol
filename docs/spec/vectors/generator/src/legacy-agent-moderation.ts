// Frozen pre-redesign topic compatibility only. Current Social validation lives
// in agent-moderation.ts and requires an actual signed target event.
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";

export type LegacyAgentPolicyReason =
  | "agent-attribution-missing"
  | "agent-attribution-falsified"
  | "agent-publication-bypass";

export type LegacyAgentPolicyReceipt = {
  receipt_id: string;
  issuer: string;
  event_id: string;
  device_key: string;
  cold_root: string;
  reason: LegacyAgentPolicyReason;
  observed_at: number;
  evidence: string[];
  explanation: string;
  remediation: "rotate-device-key";
};

export type LegacyAgentPolicyList = {
  policy_persona: string;
  event_id: string;
  entries: Array<{
    device_key: string;
    receipt_id: string;
    reason: LegacyAgentPolicyReason;
  }>;
};

export type LegacyAgentPolicyInput = {
  subscribed: boolean;
  policy_persona: string;
  policy_current_canonical: boolean;
  repo_history_verified: boolean;
  candidate_source: "canonical" | "relay-only" | "pr";
  device_key: string;
  muted_device_keys: string[];
  default_subscription: boolean;
  default_visible: boolean;
  can_disable_default: boolean;
};

export type LegacyAgentCorrectionInput = {
  correction_valid: boolean;
  canonical_list_binding_removed: boolean;
  device_key: string;
  muted_device_keys: string[];
};

export type LegacyAgentPolicyDecision =
  | { visible: true; muted: false }
  | { visible: false; muted: true; source?: string; reason?: string };

const REASONS = new Set<LegacyAgentPolicyReason>([
  "agent-attribution-missing",
  "agent-attribution-falsified",
  "agent-publication-bypass",
]);
const HEX_32 = /^[0-9a-f]{64}$/;

export function validateLegacyAgentPolicyReceipt(
  event: NostrSignedEvent,
): LegacyAgentPolicyReceipt {
  if (event.kind !== 1985 || !validSignedEvent(event)) invalidReceipt();
  const namespaceTags = tags(event, "L");
  const labelTags = tags(event, "l");
  const eventTags = tags(event, "e");
  const deviceTags = tags(event, "p");
  if (
    namespaceTags.length !== 1
    || !equalTag(namespaceTags[0], ["L", "network.heterodyne.agent-policy"])
    || labelTags.length !== 1
    || labelTags[0].length !== 3
    || labelTags[0][2] !== "network.heterodyne.agent-policy"
    || !REASONS.has(labelTags[0][1] as LegacyAgentPolicyReason)
    || eventTags.length !== 1
    || ![2, 3].includes(eventTags[0].length)
    || deviceTags.length !== 1
    || ![2, 3].includes(deviceTags[0].length)
    || !HEX_32.test(eventTags[0][1])
    || !HEX_32.test(deviceTags[0][1])
  ) invalidReceipt();
  const value = parseRecord(event.content, [
    "cold_root", "device_key", "event_id", "evidence", "explanation",
    "observed_at", "profile", "reason", "remediation", "spec_version",
  ]);
  if (
    value.profile !== "heterodyne.social.agent-policy-receipt.v1"
    || value.spec_version !== "heterodyne/0.5.0"
    || value.event_id !== eventTags[0][1]
    || value.device_key !== deviceTags[0][1]
    || !HEX_32.test(stringValue(value.cold_root))
    || value.reason !== labelTags[0][1]
    || !REASONS.has(value.reason as LegacyAgentPolicyReason)
    || !Number.isSafeInteger(value.observed_at)
    || (value.observed_at as number) < 0
    || !validEvidence(value.evidence)
    || !validText(value.explanation, 4_096)
    || value.remediation !== "rotate-device-key"
  ) invalidReceipt();
  return {
    receipt_id: event.id,
    issuer: event.pubkey,
    event_id: value.event_id as string,
    device_key: value.device_key as string,
    cold_root: value.cold_root as string,
    reason: value.reason as LegacyAgentPolicyReason,
    observed_at: value.observed_at as number,
    evidence: value.evidence as string[],
    explanation: value.explanation as string,
    remediation: "rotate-device-key",
  };
}

export function validateLegacyAgentPolicyList(
  event: NostrSignedEvent,
  receipts: ReadonlyMap<string, LegacyAgentPolicyReceipt>,
): LegacyAgentPolicyList {
  if (
    event.kind !== 10000
    || event.content !== ""
    || !validSignedEvent(event)
    || countExactTag(event, ["heterodyne", "social-agent-policy-list-v1"]) !== 1
    || countExactTag(event, ["spec_version", "heterodyne/0.5.0"]) !== 1
  ) invalidBinding();
  const entries = tags(event, "agent_violation").map((tag) => {
    if (
      tag.length !== 4
      || !HEX_32.test(tag[1])
      || !HEX_32.test(tag[2])
      || !REASONS.has(tag[3] as LegacyAgentPolicyReason)
    ) invalidBinding();
    const receipt = receipts.get(tag[2]);
    if (
      receipt === undefined
      || receipt.device_key !== tag[1]
      || receipt.reason !== tag[3]
      || !tags(event, "p").some((candidate) => candidate[1] === tag[1])
      || !tags(event, "e").some((candidate) => candidate[1] === tag[2])
    ) invalidBinding();
    return {
      device_key: tag[1],
      receipt_id: tag[2],
      reason: tag[3] as LegacyAgentPolicyReason,
    };
  });
  if (entries.length === 0) invalidBinding();
  return { policy_persona: event.pubkey, event_id: event.id, entries };
}

export function applyLegacySubscribedAgentPolicy(
  input: LegacyAgentPolicyInput,
): LegacyAgentPolicyDecision {
  if (input.default_subscription && (!input.default_visible || !input.can_disable_default)) {
    invalidBinding();
  }
  if (
    !input.subscribed
    || !input.policy_current_canonical
    || !input.repo_history_verified
    || input.candidate_source !== "canonical"
    || !input.muted_device_keys.includes(input.device_key)
  ) return { visible: true, muted: false };
  return {
    visible: false,
    muted: true,
    source: input.policy_persona,
    reason: "subscribed-device-key-policy",
  };
}

export function validateLegacyAgentPolicyCorrection(event: NostrSignedEvent): {
  receipt_id: string;
  device_key: string;
  action: "retract";
} {
  if (event.kind !== 1985 || !validSignedEvent(event)) invalidReceipt();
  const namespaceTags = tags(event, "L");
  const labelTags = tags(event, "l");
  const receiptTags = tags(event, "e");
  const deviceTags = tags(event, "p");
  if (
    namespaceTags.length !== 1
    || !equalTag(namespaceTags[0], ["L", "network.heterodyne.agent-policy"])
    || labelTags.length !== 1
    || !equalTag(labelTags[0], ["l", "correction", "network.heterodyne.agent-policy"])
    || receiptTags.length !== 1
    || ![2, 3].includes(receiptTags[0].length)
    || deviceTags.length !== 1
    || ![2, 3].includes(deviceTags[0].length)
    || !HEX_32.test(receiptTags[0][1])
    || !HEX_32.test(deviceTags[0][1])
  ) invalidReceipt();
  const value = parseRecord(event.content, [
    "action", "corrected_at", "device_key", "explanation", "profile",
    "receipt_id", "spec_version",
  ]);
  if (
    value.profile !== "heterodyne.social.agent-policy-correction.v1"
    || value.spec_version !== "heterodyne/0.5.0"
    || value.receipt_id !== receiptTags[0][1]
    || value.device_key !== deviceTags[0][1]
    || !Number.isSafeInteger(value.corrected_at)
    || (value.corrected_at as number) < 0
    || !validText(value.explanation, 4_096)
    || value.action !== "retract"
  ) invalidReceipt();
  return {
    receipt_id: value.receipt_id as string,
    device_key: value.device_key as string,
    action: "retract",
  };
}

export function applyLegacyAgentPolicyCorrection(
  input: LegacyAgentCorrectionInput,
): LegacyAgentPolicyDecision {
  if (input.correction_valid && input.canonical_list_binding_removed) {
    return { visible: true, muted: false };
  }
  return input.muted_device_keys.includes(input.device_key)
    ? { visible: false, muted: true }
    : { visible: true, muted: false };
}

function tags(event: NostrSignedEvent, name: string): string[][] {
  return event.tags.filter((tag) => tag[0] === name);
}

function countExactTag(event: NostrSignedEvent, expected: string[]): number {
  return event.tags.filter((tag) => equalTag(tag, expected)).length;
}

function equalTag(actual: string[], expected: string[]): boolean {
  return actual.length === expected.length
    && actual.every((member, index) => member === expected[index]);
}

function parseRecord(content: string, members: string[]): Record<string, unknown> {
  try {
    const value = JSON.parse(content) as unknown;
    if (value === null || typeof value !== "object" || Array.isArray(value)) invalidReceipt();
    const record = value as Record<string, unknown>;
    if (Object.keys(record).sort().join("\0") !== [...members].sort().join("\0")) invalidReceipt();
    return record;
  } catch {
    invalidReceipt();
  }
}

function validEvidence(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.length >= 1
    && value.length <= 32
    && value.every((item) => validText(item, 512));
}

function validText(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maxLength;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function validSignedEvent(event: NostrSignedEvent): boolean {
  try {
    return verifyEventSignature(event);
  } catch {
    return false;
  }
}

function invalidReceipt(): never {
  throw new Error("agent-policy-receipt-invalid");
}

function invalidBinding(): never {
  throw new Error("agent-policy-binding-invalid");
}
