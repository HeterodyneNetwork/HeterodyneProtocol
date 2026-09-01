import { Ajv2020 } from "ajv/dist/2020.js";
import receiptSchema from "../../../schemas/social/agent-policy-receipt-v1.schema.json" with { type: "json" };
import correctionSchema from "../../../schemas/social/agent-policy-correction-v1.schema.json" with { type: "json" };
import {
  matchesAgentAttributionProfile,
  type AgentAssociation,
} from "./agent-authorship.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

export type AgentPolicyReason =
  | "agent-attribution-missing"
  | "agent-attribution-falsified"
  | "agent-publication-bypass";

export type AgentPolicyNostrSignedEvent = NostrSignedEvent;
export type VerifiedAgentPolicyEvent = VerifiedNostrEvent;

export type AgentPolicyReceipt = {
  receipt_id: string;
  issuer: string;
  event_id: string;
  event_author: string;
  agent_association: AgentAssociation | null;
  policy: { id: string; version: string };
  decision: "advisory-violation";
  reason: AgentPolicyReason;
  observed_at: number;
  evidence: string[];
  explanation: string;
  remediation: "correct-attribution" | "replace-signing-key";
};

export type AgentPolicyTarget = {
  event: NostrSignedEvent;
  verified_agent_association: AgentAssociation | null;
};

export type VerifiedAgentPolicyTarget = Readonly<{
  event: VerifiedNostrEvent;
  verified_agent_association: AgentAssociation | null;
}>;

export type AgentPolicyList = {
  policy_persona: string;
  event_id: string;
  entries: Array<{
    event_author: string;
    receipt_id: string;
    reason: AgentPolicyReason;
  }>;
};

/**
 * @deprecated Frozen current-vector adapter only. Current subscriber-local
 * evaluation uses the opaque authority in social-subscription-authority.ts.
 */
export type AgentPolicyInput = {
  subscribed: boolean;
  policy_persona: string;
  policy_event_selected: boolean;
  event_author: string;
  muted_event_authors: string[];
  default_subscription: boolean;
  default_visible: boolean;
  can_disable_default: boolean;
};

export type AgentPolicyDecision =
  | { visible: true; muted: false }
  | { visible: false; muted: true; source?: string; reason?: string };

/** @deprecated Frozen current-vector adapter only. */
export type AgentCorrectionInput = {
  correction_valid: boolean;
  current_list_binding_removed: boolean;
  event_author: string;
  muted_event_authors: string[];
};

export type AgentPolicyCorrection = {
  corrects_receipt_id: string;
  event_id: string;
  event_author: string;
  agent_association: AgentAssociation | null;
  policy: { id: string; version: string };
  decision: "retract";
  corrected_at: number;
  evidence: string[];
  explanation: string;
};

const ajv = new Ajv2020({ allErrors: true, strict: false });
const validateReceiptContent = ajv.compile(receiptSchema);
const validateCorrectionContent = ajv.compile(correctionSchema);
const POLICY_REASONS = new Set<AgentPolicyReason>([
  "agent-attribution-missing",
  "agent-attribution-falsified",
  "agent-publication-bypass",
]);
const HEX_32 = /^[0-9a-f]{64}$/;

export function snapshotAgentPolicyEvent(value: unknown): VerifiedNostrEvent | null {
  return snapshotAndVerifyNostrEvent(value);
}

export function snapshotAgentPolicyTarget(
  value: unknown,
): VerifiedAgentPolicyTarget | null {
  const event = snapshotAndVerifyNostrEvent(value);
  if (event === null) return null;
  const association = signedAgentAssociation(event);
  return association === undefined
    ? null
    : Object.freeze({ event, verified_agent_association: association });
}

export function validateAgentPolicyReceipt(
  event: NostrSignedEvent,
  target: AgentPolicyTarget,
): AgentPolicyReceipt {
  const receiptEvent = snapshotAndVerifyNostrEvent(event);
  const targetEvent = target === undefined
    ? null
    : snapshotAndVerifyNostrEvent(target.event);
  if (
    target === undefined
    || receiptEvent === null
    || targetEvent === null
    || receiptEvent.kind !== 1985
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const namespaceTags = tags(receiptEvent, "L");
  const labelTags = tags(receiptEvent, "l");
  const eventTags = tags(receiptEvent, "e");
  const authorTags = tags(receiptEvent, "p");
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
    || authorTags.length !== 1
    || ![2, 3].includes(authorTags[0].length)
    || !HEX_32.test(eventTags[0][1])
    || !HEX_32.test(authorTags[0][1])
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const content = parseJson(receiptEvent.content);
  if (!validateReceiptContent(content)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const value = content as Omit<AgentPolicyReceipt, "receipt_id" | "issuer">;
  if (
    value.event_id !== eventTags[0][1]
    || value.event_id !== targetEvent.id
    || value.event_author !== authorTags[0][1]
    || value.event_author !== targetEvent.pubkey
    || !equalAssociation(value.agent_association, target.verified_agent_association)
    || target.verified_agent_association?.kind === "key"
      && target.verified_agent_association.value !== targetEvent.pubkey
    || value.reason !== labelTags[0][1]
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  return { receipt_id: receiptEvent.id, issuer: receiptEvent.pubkey, ...value };
}

export function validateAgentPolicyList(
  event: NostrSignedEvent,
  receipts: ReadonlyMap<string, AgentPolicyReceipt>,
): AgentPolicyList {
  const verified = snapshotAndVerifyNostrEvent(event);
  if (
    verified === null
    || verified.kind !== 10000
    || verified.content !== ""
    || countExactTag(verified, ["heterodyne", "social-agent-policy-list-v1"]) !== 1
    || countExactTag(verified, ["spec_version", "heterodyne/0.6.0"]) !== 1
  ) {
    throw new Error("agent-policy-binding-invalid");
  }
  const violationTags = tags(verified, "agent_violation");
  const authorReferences = tags(verified, "p");
  const receiptReferences = tags(verified, "e");
  if (
    authorReferences.some((tag) => tag.length !== 2)
    || receiptReferences.some((tag) => tag.length !== 2)
    || authorReferences.length !== violationTags.length
    || receiptReferences.length !== violationTags.length
  ) throw new Error("agent-policy-binding-invalid");
  const authorReferenceCounts = countValues(authorReferences.map((tag) => tag[1]));
  const receiptReferenceCounts = countValues(receiptReferences.map((tag) => tag[1]));
  const entries = violationTags.map((tag) => {
    if (
      tag.length !== 4
      || !HEX_32.test(tag[1])
      || !HEX_32.test(tag[2])
      || !POLICY_REASONS.has(tag[3] as AgentPolicyReason)
    ) {
      throw new Error("agent-policy-binding-invalid");
    }
    const receipt = receipts.get(tag[2]);
    if (
      receipt === undefined
      || receipt.issuer !== verified.pubkey
      || receipt.event_author !== tag[1]
      || receipt.reason !== tag[3]
      || !authorReferenceCounts.has(tag[1])
      || !receiptReferenceCounts.has(tag[2])
    ) {
      throw new Error("agent-policy-binding-invalid");
    }
    return {
      event_author: tag[1],
      receipt_id: tag[2],
      reason: tag[3] as AgentPolicyReason,
    };
  });
  if (
    new Set(entries.map(({ receipt_id }) => receipt_id)).size !== entries.length
    || !sameMultiset(
      authorReferences.map((tag) => tag[1]),
      entries.map(({ event_author }) => event_author),
    )
    || !sameMultiset(
      receiptReferences.map((tag) => tag[1]),
      entries.map(({ receipt_id }) => receipt_id),
    )
  ) throw new Error("agent-policy-binding-invalid");
  return { policy_persona: verified.pubkey, event_id: verified.id, entries };
}

/** @deprecated Frozen current-vector adapter; not a live authority boundary. */
export function applySubscribedAgentPolicy(
  input: AgentPolicyInput,
): AgentPolicyDecision {
  if ("device_key" in input) throw new Error("agent-policy-binding-invalid");
  if (
    input.default_subscription
    && (!input.default_visible || !input.can_disable_default)
  ) {
    throw new Error("agent-policy-binding-invalid");
  }
  if (
    !input.subscribed
    || !input.policy_event_selected
    || !input.muted_event_authors.includes(input.event_author)
  ) {
    return { visible: true, muted: false };
  }
  return {
    visible: false,
    muted: true,
    source: input.policy_persona,
    reason: "subscribed-event-author-policy",
  };
}

export function validateAgentPolicyCorrection(
  event: NostrSignedEvent,
  receipt: AgentPolicyReceipt,
): AgentPolicyCorrection {
  const verified = snapshotAndVerifyNostrEvent(event);
  if (
    receipt === undefined
    || verified === null
    || verified.kind !== 1985
    || verified.pubkey !== receipt.issuer
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const namespaceTags = tags(verified, "L");
  const labelTags = tags(verified, "l");
  const receiptTags = tags(verified, "e");
  const authorTags = tags(verified, "p");
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
    || authorTags.length !== 1
    || ![2, 3].includes(authorTags[0].length)
    || !HEX_32.test(receiptTags[0][1])
    || !HEX_32.test(authorTags[0][1])
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const content = parseJson(verified.content);
  if (!validateCorrectionContent(content)) {
    throw new Error("agent-policy-receipt-invalid");
  }
  const value = content as AgentPolicyCorrection;
  if (
    value.corrects_receipt_id !== receiptTags[0][1]
    || value.corrects_receipt_id !== receipt.receipt_id
    || value.event_id !== receipt.event_id
    || value.event_author !== authorTags[0][1]
    || value.event_author !== receipt.event_author
    || !equalAssociation(value.agent_association, receipt.agent_association)
    || value.policy.id !== receipt.policy.id
    || value.policy.version !== receipt.policy.version
    || value.corrected_at !== verified.created_at
  ) {
    throw new Error("agent-policy-receipt-invalid");
  }
  return value;
}

/** @deprecated Frozen current-vector adapter; not a live authority boundary. */
export function applyAgentPolicyCorrection(
  input: AgentCorrectionInput,
): AgentPolicyDecision {
  if ("device_key" in input) throw new Error("agent-policy-binding-invalid");
  const currentlyMuted = input.muted_event_authors.includes(input.event_author);
  if (input.correction_valid && input.current_list_binding_removed) {
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

function sameMultiset(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const counts = new Map<string, number>();
  for (const value of left) counts.set(value, (counts.get(value) ?? 0) + 1);
  for (const value of right) {
    const count = counts.get(value);
    if (count === undefined) return false;
    if (count === 1) counts.delete(value);
    else counts.set(value, count - 1);
  }
  return counts.size === 0;
}

function countValues(values: readonly string[]): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return counts;
}

function equalAssociation(
  left: AgentAssociation | null,
  right: AgentAssociation | null,
): boolean {
  return left === null || right === null
    ? left === right
    : left.kind === right.kind && left.value === right.value;
}

function signedAgentAssociation(
  event: VerifiedNostrEvent,
): AgentAssociation | null | undefined {
  const reserved = event.tags.some((tag) =>
    tag[0] === "heterodyne_agent"
    || tag[0] === "agent_action"
    || tag[0] === "L" && tag[1] === "network.heterodyne.agent"
    || tag[0] === "l" && tag[2] === "network.heterodyne.agent");
  if (!reserved) return null;
  if (!matchesAgentAttributionProfile(event.tags)) return undefined;
  const tags = event.tags.filter((tag) => tag[0] === "heterodyne_agent");
  if (tags.length === 0) return null;
  if (tags.length !== 1) return undefined;
  const association = Object.freeze({
    kind: tags[0][2] as "key" | "role",
    value: tags[0][3],
  });
  if (association.kind === "key" && association.value !== event.pubkey) {
    return undefined;
  }
  return association;
}

function parseJson(content: string): unknown {
  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw new Error("agent-policy-receipt-invalid");
  }
}
