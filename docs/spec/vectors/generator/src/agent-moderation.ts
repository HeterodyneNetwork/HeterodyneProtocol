import { Ajv2020 } from "ajv/dist/2020.js";
import receiptSchema from "../../../schemas/social/agent-policy-receipt-v1.schema.json" with { type: "json" };
import correctionSchema from "../../../schemas/social/agent-policy-correction-v1.schema.json" with { type: "json" };
import {
  verifyEventSignature,
  type NostrSignedEvent,
} from "./nostr.js";

export type AgentPolicyReason =
  | "agent-attribution-missing"
  | "agent-attribution-falsified"
  | "agent-publication-bypass";

export type AgentPolicyReceipt = {
  receipt_id: string;
  issuer: string;
  event_id: string;
  device_key: string;
  cold_root: string;
  reason: AgentPolicyReason;
  observed_at: number;
  evidence: string[];
  explanation: string;
  remediation: "rotate-device-key";
};

export type AgentPolicyList = {
  policy_persona: string;
  event_id: string;
  entries: Array<{
    device_key: string;
    receipt_id: string;
    reason: AgentPolicyReason;
  }>;
};

export type AgentPolicyInput = {
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

export type AgentPolicyDecision =
  | {
      visible: true;
      muted: false;
    }
  | {
      visible: false;
      muted: true;
      source?: string;
      reason?: string;
    };

export type AgentCorrectionInput = {
  correction_valid: boolean;
  canonical_list_binding_removed: boolean;
  device_key: string;
  muted_device_keys: string[];
};

const ajv = new Ajv2020({ allErrors: true, strict: false });
const validateReceiptContent = ajv.compile(receiptSchema);
const validateCorrectionContent = ajv.compile(correctionSchema);
const POLICY_REASONS = new Set<AgentPolicyReason>([
  "agent-attribution-missing",
  "agent-attribution-falsified",
  "agent-publication-bypass",
]);

export function validateAgentPolicyReceipt(
  event: NostrSignedEvent,
): AgentPolicyReceipt {
  if (event.kind !== 1985 || !verifyEventSignature(event)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const namespaceTags = tags(event, "L");
  const labelTags = tags(event, "l");
  const eventTags = tags(event, "e");
  const deviceTags = tags(event, "p");
  if (
    namespaceTags.length !== 1
    || namespaceTags[0].length !== 2
    || namespaceTags[0][1] !== "network.heterodyne.agent-policy"
    || labelTags.length !== 1
    || labelTags[0].length !== 3
    || labelTags[0][2] !== "network.heterodyne.agent-policy"
    || !POLICY_REASONS.has(labelTags[0][1] as AgentPolicyReason)
    || eventTags.length !== 1
    || ![2, 3].includes(eventTags[0].length)
    || deviceTags.length !== 1
    || ![2, 3].includes(deviceTags[0].length)
    || !/^[0-9a-f]{64}$/.test(eventTags[0][1])
    || !/^[0-9a-f]{64}$/.test(deviceTags[0][1])
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  let content: unknown;
  try {
    content = JSON.parse(event.content);
  } catch {
    throw new Error("agent-policy-receipt-invalid");
  }
  if (!validateReceiptContent(content)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const value = content as {
    event_id: string;
    device_key: string;
    cold_root: string;
    reason: AgentPolicyReason;
    observed_at: number;
    evidence: string[];
    explanation: string;
    remediation: "rotate-device-key";
  };
  if (
    value.event_id !== eventTags[0][1]
    || value.device_key !== deviceTags[0][1]
    || value.reason !== labelTags[0][1]
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  return {
    receipt_id: event.id,
    issuer: event.pubkey,
    event_id: value.event_id,
    device_key: value.device_key,
    cold_root: value.cold_root,
    reason: value.reason,
    observed_at: value.observed_at,
    evidence: value.evidence,
    explanation: value.explanation,
    remediation: value.remediation,
  };
}

export function validateAgentPolicyList(
  event: NostrSignedEvent,
  receipts: ReadonlyMap<string, AgentPolicyReceipt>,
): AgentPolicyList {
  if (
    event.kind !== 10000
    || event.content !== ""
    || !verifyEventSignature(event)
    || countExactTag(event, ["heterodyne", "social-agent-policy-list-v1"]) !== 1
    || countExactTag(event, ["spec_version", "heterodyne/0.5.0"]) !== 1
  ) {
    throw new Error("agent-policy-binding-invalid");
  }
  const entries = tags(event, "agent_violation").map((tag) => {
    if (
      tag.length !== 4
      || !/^[0-9a-f]{64}$/.test(tag[1])
      || !/^[0-9a-f]{64}$/.test(tag[2])
      || !POLICY_REASONS.has(tag[3] as AgentPolicyReason)
    ) {
      throw new Error("agent-policy-binding-invalid");
    }
    const receipt = receipts.get(tag[2]);
    if (
      receipt === undefined
      || receipt.device_key !== tag[1]
      || receipt.reason !== tag[3]
      || !tags(event, "p").some((candidate) => candidate[1] === tag[1])
      || !tags(event, "e").some((candidate) => candidate[1] === tag[2])
    ) {
      throw new Error("agent-policy-binding-invalid");
    }
    return {
      device_key: tag[1],
      receipt_id: tag[2],
      reason: tag[3] as AgentPolicyReason,
    };
  });
  if (entries.length === 0) throw new Error("agent-policy-binding-invalid");
  return {
    policy_persona: event.pubkey,
    event_id: event.id,
    entries,
  };
}

export function applySubscribedAgentPolicy(
  input: AgentPolicyInput,
): AgentPolicyDecision {
  if (
    input.default_subscription
    && (!input.default_visible || !input.can_disable_default)
  ) {
    throw new Error("agent-policy-binding-invalid");
  }
  if (
    !input.subscribed
    || !input.policy_current_canonical
    || !input.repo_history_verified
    || input.candidate_source !== "canonical"
    || !input.muted_device_keys.includes(input.device_key)
  ) {
    return { visible: true, muted: false };
  }
  return {
    visible: false,
    muted: true,
    source: input.policy_persona,
    reason: "subscribed-device-key-policy",
  };
}

export function validateAgentPolicyCorrection(
  event: NostrSignedEvent,
): {
  receipt_id: string;
  device_key: string;
  action: "retract";
} {
  if (event.kind !== 1985 || !verifyEventSignature(event)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const namespaceTags = tags(event, "L");
  const labelTags = tags(event, "l");
  const receiptTags = tags(event, "e");
  const deviceTags = tags(event, "p");
  if (
    namespaceTags.length !== 1
    || namespaceTags[0].length !== 2
    || namespaceTags[0][1] !== "network.heterodyne.agent-policy"
    || labelTags.length !== 1
    || labelTags[0].length !== 3
    || labelTags[0][1] !== "correction"
    || labelTags[0][2] !== "network.heterodyne.agent-policy"
    || receiptTags.length !== 1
    || ![2, 3].includes(receiptTags[0].length)
    || deviceTags.length !== 1
    || ![2, 3].includes(deviceTags[0].length)
    || !/^[0-9a-f]{64}$/.test(receiptTags[0][1])
    || !/^[0-9a-f]{64}$/.test(deviceTags[0][1])
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  let content: unknown;
  try {
    content = JSON.parse(event.content);
  } catch {
    throw new Error("agent-policy-receipt-invalid");
  }
  if (!validateCorrectionContent(content)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const value = content as {
    receipt_id: string;
    device_key: string;
    action: "retract";
  };
  if (
    value.receipt_id !== receiptTags[0][1]
    || value.device_key !== deviceTags[0][1]
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  return value;
}

export function applyAgentPolicyCorrection(
  input: AgentCorrectionInput,
): AgentPolicyDecision {
  const currentlyMuted = input.muted_device_keys.includes(input.device_key);
  if (
    input.correction_valid
    && input.canonical_list_binding_removed
  ) {
    return { visible: true, muted: false };
  }
  return currentlyMuted
    ? { visible: false, muted: true }
    : { visible: true, muted: false };
}

function tags(event: NostrSignedEvent, name: string): string[][] {
  return event.tags.filter((tag) => tag[0] === name);
}

function countExactTag(event: NostrSignedEvent, expected: string[]): number {
  return event.tags.filter((tag) =>
    tag.length === expected.length
    && tag.every((value, index) => value === expected[index])).length;
}
