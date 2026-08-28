import {
  matchesAgentAttributionProfile,
  type AgentAssociation,
} from "./agent-authorship.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
} from "./nostr.js";

type SocialPolicyDecision =
  | { verdict: "accept"; normalized: Readonly<Record<string, unknown>> }
  | {
      verdict: "reject";
      reason_code:
        | "social-event-invalid"
        | "moderator_not_in_asof_declaration"
        | "agent-attribution-missing"
        | "agent-attribution-falsified"
        | "agent-publication-bypass";
    };

/**
 * Checks a NIP-72 approval against the moderator set in the declaration that
 * was already in force when the approval was created.
 */
export function evaluateModeratorAsOfDeclaration(input: Readonly<{
  declaration: NostrSignedEvent;
  approval: NostrSignedEvent;
}>): SocialPolicyDecision {
  const declaration = snapshotAndVerifyNostrEvent(input.declaration);
  const approval = snapshotAndVerifyNostrEvent(input.approval);
  if (
    declaration === null
    || approval === null
    || declaration.kind !== 34_550
    || approval.kind !== 4_550
  ) return { verdict: "reject", reason_code: "social-event-invalid" };

  const declaredModerators = new Set(declaration.tags
    .filter((tag) =>
      tag.length === 4
      && tag[0] === "p"
      && /^[0-9a-f]{64}$/u.test(tag[1])
      && tag[3] === "moderator")
    .map((tag) => tag[1]));
  if (
    approval.created_at < declaration.created_at
    || !declaredModerators.has(approval.pubkey)
  ) {
    return { verdict: "reject", reason_code: "moderator_not_in_asof_declaration" };
  }
  return {
    verdict: "accept",
    normalized: {
      approval_id: approval.id,
      declaration_id: declaration.id,
      moderator: approval.pubkey,
    },
  };
}

/**
 * Verifies the signed event and its canonical attribution profile before
 * deciding whether automated Social publication evidence is trustworthy.
 */
export function evaluateAgentModerationEvidence(input: Readonly<{
  event: NostrSignedEvent;
  automated: boolean;
  publication_path: "comms-authorized" | "direct";
  expected_agent_association: AgentAssociation | null;
}>): SocialPolicyDecision {
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null || typeof input.automated !== "boolean") {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  if (!input.automated) {
    return { verdict: "accept", normalized: { event_id: event.id, automated: false } };
  }
  if (!matchesAgentAttributionProfile(event.tags)) {
    return { verdict: "reject", reason_code: "agent-attribution-missing" };
  }
  const associationTag = event.tags.find((tag) => tag[0] === "heterodyne_agent");
  const actualAssociation = associationTag === undefined
    ? null
    : { kind: associationTag[2], value: associationTag[3] };
  const expected = input.expected_agent_association;
  if (
    actualAssociation === null || expected === null
      ? actualAssociation !== expected
      : actualAssociation.kind !== expected.kind || actualAssociation.value !== expected.value
  ) {
    return { verdict: "reject", reason_code: "agent-attribution-falsified" };
  }
  if (input.publication_path !== "comms-authorized") {
    return { verdict: "reject", reason_code: "agent-publication-bypass" };
  }
  return {
    verdict: "accept",
    normalized: {
      event_id: event.id,
      automated: true,
      agent_association: actualAssociation,
    },
  };
}
