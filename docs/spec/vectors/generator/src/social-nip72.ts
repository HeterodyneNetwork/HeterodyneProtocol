import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";
import {
  selectCurrentSocialEvent,
  type SocialEventCandidate,
} from "./social-events.js";

export type Nip72CuratedViewDecision =
  | {
      verdict: "accept" | "hold";
      counted_approval_ids: string[];
      audit_only_approval_ids: string[];
    }
  | { verdict: "reject"; reason_code: "social-event-invalid" };

const HEX_32 = /^[0-9a-f]{64}$/;

export function evaluateNip72CuratedView(input: {
  community: { pubkey: string; d: string };
  declaration_candidates: readonly SocialEventCandidate[];
  candidate: NostrSignedEvent;
  approvals: readonly NostrSignedEvent[];
  deletions?: readonly NostrSignedEvent[];
}): Nip72CuratedViewDecision {
  const candidate = snapshotAndVerifyNostrEvent(input.candidate);
  const coordinate = `34550:${input.community.pubkey}:${input.community.d}`;
  const declaration = selectCurrentSocialEvent({
    coordinate: {
      pubkey: input.community.pubkey,
      kind: 34550,
      d: input.community.d,
    },
    candidates: input.declaration_candidates,
  });
  if (
    declaration === null
    || candidate === null
    || !hasTagPrefix(candidate, ["a", coordinate])
  ) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  const currentModerators = new Set(
    declaration.tags
      .filter((tag) =>
        tag.length === 4
        && tag[0] === "p"
        && HEX_32.test(tag[1])
        && tag[3] === "moderator")
      .map((tag) => tag[1]),
  );
  const threshold = approvalThreshold(declaration);
  if (currentModerators.size === 0 || threshold === null) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }

  const counted: string[] = [];
  const auditOnly: string[] = [];
  const countedModerators = new Set<string>();
  const seenApprovals = new Set<string>();
  for (const sourceApproval of input.approvals) {
    const approval = snapshotAndVerifyNostrEvent(sourceApproval);
    if (
      approval === null
      ||
      seenApprovals.has(approval.id)
      || !validApproval(approval, candidate, coordinate)
    ) continue;
    seenApprovals.add(approval.id);
    if (isDeletedApproval(approval, input.deletions ?? [])) continue;
    if (
      approval.created_at >= declaration.created_at
      && currentModerators.has(approval.pubkey)
    ) {
      if (!countedModerators.has(approval.pubkey)) {
        countedModerators.add(approval.pubkey);
        counted.push(approval.id);
      }
    } else {
      auditOnly.push(approval.id);
    }
  }
  return {
    verdict: counted.length >= threshold ? "accept" : "hold",
    counted_approval_ids: counted,
    audit_only_approval_ids: auditOnly,
  };
}

function validApproval(
  approval: VerifiedNostrEvent,
  candidate: VerifiedNostrEvent,
  coordinate: string,
): boolean {
  if (
    approval.kind !== 4550
    || !hasTagPrefix(approval, ["a", coordinate])
    || !hasTagPrefix(approval, ["e", candidate.id])
    || !hasTagPrefix(approval, ["p", candidate.pubkey])
  ) return false;
  try {
    const embedded = JSON.parse(approval.content) as unknown;
    const verified = snapshotAndVerifyNostrEvent(embedded);
    return verified !== null && verified.id === candidate.id;
  } catch {
    return false;
  }
}

function approvalThreshold(declaration: NostrSignedEvent): number | null {
  const tags = declaration.tags.filter((tag) => tag[0] === "approvals_required");
  if (tags.length === 0) return 1;
  if (tags.length !== 1 || tags[0].length !== 2 || !/^[1-9][0-9]*$/.test(tags[0][1])) {
    return null;
  }
  const value = Number(tags[0][1]);
  return Number.isSafeInteger(value) ? value : null;
}

function isDeletedApproval(
  approval: VerifiedNostrEvent,
  deletions: readonly NostrSignedEvent[],
): boolean {
  return deletions.some((deletion) =>
    (() => {
      const verified = snapshotAndVerifyNostrEvent(deletion);
      return verified !== null
        && verified.kind === 5
        && verified.pubkey === approval.pubkey
        && verified.created_at >= approval.created_at
        && hasTagPrefix(verified, ["e", approval.id]);
    })());
}

function hasTagPrefix(event: VerifiedNostrEvent, expected: string[]): boolean {
  return event.tags.some((tag) =>
    tag.length >= expected.length
    && expected.every((member, index) => tag[index] === member));
}
