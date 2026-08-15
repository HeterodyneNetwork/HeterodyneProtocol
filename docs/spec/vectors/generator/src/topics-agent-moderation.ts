import {
  applyAgentPolicyCorrection,
  applySubscribedAgentPolicy,
  validateAgentPolicyCorrection,
  validateAgentPolicyList,
  validateAgentPolicyReceipt,
} from "./agent-moderation.js";
import { getPublicKey, signEvent } from "./nostr.js";
import { AUX_RAND, baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const moderatorPrivateKey = "0d".repeat(32);
const moderatorPublicKey = getPublicKey(moderatorPrivateKey);
const deviceKey = "11".repeat(32);
const replacementKey = "22".repeat(32);
const offendingEventId = "33".repeat(32);
const coldRoot = "44".repeat(32);
const reason = "agent-attribution-missing" as const;

export async function buildAgentModerationVectors(): Promise<AuthoredVector[]> {
  const vectors: AuthoredVector[] = [];
  const receiptEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_000,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", reason, "network.heterodyne.agent-policy"],
      ["e", offendingEventId, "wss://relay.example/"],
      ["p", deviceKey, "wss://relay.example/"],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-receipt.v1",
      spec_version: "heterodyne/0.5.0",
      event_id: offendingEventId,
      device_key: deviceKey,
      cold_root: coldRoot,
      reason,
      observed_at: 1_000,
      evidence: ["sha256:abcd"],
      explanation: "Automated publication omitted mandatory attribution.",
      remediation: "rotate-device-key",
    }),
    auxRand: AUX_RAND,
  });
  const receipt = validateAgentPolicyReceipt(receiptEvent);
  vectors.push(authored(
    "agent-moderation/001-receipt-valid.json",
    "agent-moderation/receipt-valid",
    "A signed NIP-32 agent-policy receipt has exact namespace, label, event, device-key, and closed body bindings.",
    { event: receiptEvent },
    { verdict: "accept", normalized: receipt },
    "round-trip",
  ));

  const malformedReceipt = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_001,
    kind: 1985,
    tags: receiptEvent.tags.filter(([name]) => name !== "p"),
    content: receiptEvent.content,
    auxRand: AUX_RAND,
  });
  vectors.push(authored(
    "agent-moderation/002-receipt-malformed.json",
    "agent-moderation/receipt-malformed",
    "An agent-policy receipt without its exact device-key target is rejected.",
    { event: malformedReceipt },
    { verdict: "reject", reason_code: "agent-policy-receipt-invalid" },
  ));

  const leakingReceipt = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_002,
    kind: 1985,
    tags: receiptEvent.tags,
    content: JSON.stringify({
      ...JSON.parse(receiptEvent.content),
      raw_token: "forbidden",
    }),
    auxRand: AUX_RAND,
  });
  vectors.push(authored(
    "agent-moderation/003-receipt-private-leakage.json",
    "agent-moderation/receipt-private-leakage",
    "A public policy receipt that leaks a raw workload token fails its closed schema.",
    { event: leakingReceipt },
    { verdict: "reject", reason_code: "agent-policy-receipt-invalid" },
  ));

  const listEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_003,
    kind: 10000,
    tags: [
      ["heterodyne", "social-agent-policy-list-v1"],
      ["spec_version", "heterodyne/0.5.0"],
      ["p", deviceKey],
      ["e", receiptEvent.id],
      ["agent_violation", deviceKey, receiptEvent.id, reason],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  const parsedList = validateAgentPolicyList(
    listEvent,
    new Map([[receiptEvent.id, receipt]]),
  );
  vectors.push(authored(
    "agent-moderation/004-policy-list-valid.json",
    "agent-moderation/policy-list-valid",
    "A current NIP-51 agent policy list binds each device-key mute to one verified receipt and reason.",
    { event: listEvent, receipts: [receiptEvent] },
    { verdict: "accept", normalized: parsedList },
    "round-trip",
  ));

  const mismatchedList = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_004,
    kind: 10000,
    tags: listEvent.tags.map((tag) =>
      tag[0] === "agent_violation"
        ? ["agent_violation", replacementKey, receiptEvent.id, reason]
        : tag),
    content: "",
    auxRand: AUX_RAND,
  });
  vectors.push(authored(
    "agent-moderation/005-policy-binding-mismatch.json",
    "agent-moderation/policy-binding-mismatch",
    "A policy list whose agent_violation key disagrees with its receipt and p tag is rejected.",
    { event: mismatchedList, receipts: [receiptEvent] },
    { verdict: "reject", reason_code: "agent-policy-binding-invalid" },
  ));

  const subscribedInput = {
    subscribed: true,
    policy_persona: moderatorPublicKey,
    policy_current_canonical: true,
    repo_history_verified: true,
    candidate_source: "canonical" as const,
    device_key: deviceKey,
    muted_device_keys: [deviceKey],
    default_subscription: true,
    default_visible: true,
    can_disable_default: true,
  };
  vectors.push(authored(
    "agent-moderation/006-subscribed-canonical-mutes.json",
    "agent-moderation/subscribed-canonical-mutes",
    "An explicitly subscribed, verified current canonical list mutes exactly the listed device key.",
    subscribedInput,
    applySubscribedAgentPolicy(subscribedInput),
  ));
  vectors.push(authored(
    "agent-moderation/007-unsubscribed-no-effect.json",
    "agent-moderation/unsubscribed-no-effect",
    "A valid but unsubscribed agent-policy list remains informational and does not alter visibility.",
    { ...subscribedInput, subscribed: false },
    applySubscribedAgentPolicy({ ...subscribedInput, subscribed: false }),
  ));
  vectors.push(authored(
    "agent-moderation/008-relay-only-no-effect.json",
    "agent-moderation/relay-only-no-effect",
    "A relay-only candidate cannot change subscriber-local policy without canonical repository history.",
    { ...subscribedInput, candidate_source: "relay-only" },
    applySubscribedAgentPolicy({ ...subscribedInput, candidate_source: "relay-only" }),
  ));
  vectors.push(authored(
    "agent-moderation/009-unmerged-pr-no-effect.json",
    "agent-moderation/unmerged-pr-no-effect",
    "An unmerged policy-repository pull request has no filtering effect.",
    { ...subscribedInput, candidate_source: "pr" },
    applySubscribedAgentPolicy({ ...subscribedInput, candidate_source: "pr" }),
  ));
  vectors.push(authored(
    "agent-moderation/010-default-visible-removable.json",
    "agent-moderation/default-visible-removable",
    "A default policy subscription is conforming only when its source is visible and the user can disable it.",
    subscribedInput,
    {
      verdict: "accept",
      normalized: {
        default_visible: true,
        can_disable_default: true,
        source_disclosed: moderatorPublicKey,
      },
    },
  ));
  vectors.push(authored(
    "agent-moderation/011-replacement-key-independent.json",
    "agent-moderation/replacement-key-independent",
    "Replacing an offending role key leaves the old key muted while the replacement is evaluated independently without epoch rotation.",
    {
      ...subscribedInput,
      old_device_key: deviceKey,
      replacement_device_key: replacementKey,
    },
    {
      verdict: "accept",
      normalized: {
        old_key: applySubscribedAgentPolicy(subscribedInput),
        replacement_key: applySubscribedAgentPolicy({
          ...subscribedInput,
          device_key: replacementKey,
        }),
        epoch_key_rotated: false,
      },
    },
  ));

  const correctionEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_005,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", "correction", "network.heterodyne.agent-policy"],
      ["e", receiptEvent.id],
      ["p", deviceKey],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-correction.v1",
      spec_version: "heterodyne/0.5.0",
      receipt_id: receiptEvent.id,
      device_key: deviceKey,
      corrected_at: 1_005,
      explanation: "The original evidence was misclassified.",
      action: "retract",
    }),
    auxRand: AUX_RAND,
  });
  vectors.push(authored(
    "agent-moderation/012-correction-valid.json",
    "agent-moderation/correction-valid",
    "A correction receipt exactly binds the original receipt and offending device key.",
    { event: correctionEvent },
    { verdict: "accept", normalized: validateAgentPolicyCorrection(correctionEvent) },
    "round-trip",
  ));
  vectors.push(authored(
    "agent-moderation/013-correction-list-retained.json",
    "agent-moderation/correction-list-retained",
    "A valid correction alone does not restore visibility while the canonical list retains the binding.",
    {
      correction_valid: true,
      canonical_list_binding_removed: false,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    },
    applyAgentPolicyCorrection({
      correction_valid: true,
      canonical_list_binding_removed: false,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    }),
  ));
  vectors.push(authored(
    "agent-moderation/014-correction-list-removed.json",
    "agent-moderation/correction-list-removed",
    "A valid correction plus canonical list removal restores subscriber-local visibility.",
    {
      correction_valid: true,
      canonical_list_binding_removed: true,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    },
    applyAgentPolicyCorrection({
      correction_valid: true,
      canonical_list_binding_removed: true,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    }),
  ));
  return vectors;
}

function authored(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  expectedOutput: Record<string, unknown>,
  direction: "consume" | "round-trip" = "consume",
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-agent-policy-anchor"],
      description,
      direction,
      input,
      expected_output: expectedOutput,
    }),
  };
}
