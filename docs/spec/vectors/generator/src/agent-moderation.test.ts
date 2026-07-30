import { beforeAll, describe, expect, it } from "vitest";
import {
  applyAgentPolicyCorrection,
  applySubscribedAgentPolicy,
  validateAgentPolicyCorrection,
  validateAgentPolicyList,
  validateAgentPolicyReceipt,
  type AgentPolicyReceipt,
} from "./agent-moderation.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND } from "./vector-helpers.js";

const moderatorPrivateKey = "0d".repeat(32);
const moderatorPublicKey = getPublicKey(moderatorPrivateKey);
const deviceKey = "11".repeat(32);
const replacementKey = "22".repeat(32);
const eventId = "33".repeat(32);
const coldRoot = "44".repeat(32);
const reason = "agent-attribution-missing";
let receiptEvent: NostrSignedEvent;
let receipt: AgentPolicyReceipt;
let listEvent: NostrSignedEvent;

beforeAll(async () => {
  receiptEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_000,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", reason, "network.heterodyne.agent-policy"],
      ["e", eventId, "wss://relay.example/"],
      ["p", deviceKey, "wss://relay.example/"],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-receipt.v1",
      spec_version: "social/0.5.0",
      event_id: eventId,
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
  receipt = validateAgentPolicyReceipt(receiptEvent);
  listEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_001,
    kind: 10000,
    tags: [
      ["heterodyne", "social-agent-policy-list-v1"],
      ["spec_version", "social/0.5.0"],
      ["p", deviceKey],
      ["e", receiptEvent.id],
      ["agent_violation", deviceKey, receiptEvent.id, reason],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
});

describe("agent-policy receipt", () => {
  it("validates exact L/l, one event, one device key, and closed public content", () => {
    expect(receipt).toMatchObject({
      receipt_id: receiptEvent.id,
      event_id: eventId,
      device_key: deviceKey,
      cold_root: coldRoot,
      reason,
      remediation: "rotate-device-key",
    });
  });

  it("accepts all three closed reason codes", async () => {
    for (const candidateReason of [
      "agent-attribution-missing",
      "agent-attribution-falsified",
      "agent-publication-bypass",
    ] as const) {
      const event = await signEvent({
        secretKey: moderatorPrivateKey,
        created_at: 1_002,
        kind: 1985,
        tags: [
          ["L", "network.heterodyne.agent-policy"],
          ["l", candidateReason, "network.heterodyne.agent-policy"],
          ["e", eventId],
          ["p", deviceKey],
        ],
        content: JSON.stringify({
          ...JSON.parse(receiptEvent.content),
          reason: candidateReason,
        }),
        auxRand: AUX_RAND,
      });
      expect(validateAgentPolicyReceipt(event).reason).toBe(candidateReason);
    }
  });

  it("rejects malformed tags and token, secret, or private-claim leakage", async () => {
    const malformed = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_003,
      kind: 1985,
      tags: receiptEvent.tags.filter(([name]) => name !== "p"),
      content: receiptEvent.content,
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyReceipt(malformed))
      .toThrow(/agent-policy-receipt-invalid/);
    for (const leaked of [
      { raw_token: "secret" },
      { private_claim: "claim-1" },
      { device_private_key: "secret" },
    ]) {
      const event = await signEvent({
        secretKey: moderatorPrivateKey,
        created_at: 1_004,
        kind: 1985,
        tags: receiptEvent.tags,
        content: JSON.stringify({ ...JSON.parse(receiptEvent.content), ...leaked }),
        auxRand: AUX_RAND,
      });
      expect(() => validateAgentPolicyReceipt(event))
        .toThrow(/agent-policy-receipt-invalid/);
    }
  });
});

describe("agent policy list and subscriber-local enforcement", () => {
  it("requires exact p, e, and agent_violation binding to a valid receipt", () => {
    const parsed = validateAgentPolicyList(
      listEvent,
      new Map([[receiptEvent.id, receipt]]),
    );
    expect(parsed.entries).toEqual([{
      device_key: deviceKey,
      receipt_id: receiptEvent.id,
      reason,
    }]);
  });

  it("rejects a mismatched key, receipt, or reason binding", async () => {
    const bad = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_005,
      kind: 10000,
      tags: listEvent.tags.map((tag) =>
        tag[0] === "agent_violation"
          ? ["agent_violation", replacementKey, receiptEvent.id, reason]
          : tag),
      content: "",
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyList(bad, new Map([[receiptEvent.id, receipt]])))
      .toThrow(/agent-policy-binding-invalid/);
  });

  it("mutes only for an explicitly subscribed verified canonical policy", () => {
    const base = {
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
    expect(applySubscribedAgentPolicy(base)).toEqual({
      visible: false,
      muted: true,
      source: moderatorPublicKey,
      reason: "subscribed-device-key-policy",
    });
    expect(applySubscribedAgentPolicy({ ...base, subscribed: false })).toEqual({
      visible: true,
      muted: false,
    });
    expect(applySubscribedAgentPolicy({ ...base, candidate_source: "relay-only" }))
      .toEqual({ visible: true, muted: false });
    expect(applySubscribedAgentPolicy({ ...base, candidate_source: "pr" }))
      .toEqual({ visible: true, muted: false });
  });

  it("keeps the default subscription visible and removable", () => {
    expect(() => applySubscribedAgentPolicy({
      subscribed: true,
      policy_persona: moderatorPublicKey,
      policy_current_canonical: true,
      repo_history_verified: true,
      candidate_source: "canonical",
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
      default_subscription: true,
      default_visible: false,
      can_disable_default: true,
    })).toThrow(/agent-policy-binding-invalid/);
  });

  it("keeps the old key muted while accepting a replacement at the same role", () => {
    const base = {
      subscribed: true,
      policy_persona: moderatorPublicKey,
      policy_current_canonical: true,
      repo_history_verified: true,
      candidate_source: "canonical" as const,
      muted_device_keys: [deviceKey],
      default_subscription: false,
      default_visible: true,
      can_disable_default: true,
    };
    expect(applySubscribedAgentPolicy({ ...base, device_key: deviceKey }).muted).toBe(true);
    expect(applySubscribedAgentPolicy({ ...base, device_key: replacementKey })).toEqual({
      visible: true,
      muted: false,
    });
  });
});

describe("correction and canonical list removal", () => {
  it("requires exact signed correction tags and body binding", async () => {
    const correction = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_006,
      kind: 1985,
      tags: [
        ["L", "network.heterodyne.agent-policy"],
        ["l", "correction", "network.heterodyne.agent-policy"],
        ["e", receiptEvent.id],
        ["p", deviceKey],
      ],
      content: JSON.stringify({
        profile: "heterodyne.social.agent-policy-correction.v1",
        spec_version: "social/0.5.0",
        receipt_id: receiptEvent.id,
        device_key: deviceKey,
        corrected_at: 1_006,
        explanation: "The original evidence was misclassified.",
        action: "retract",
      }),
      auxRand: AUX_RAND,
    });
    expect(validateAgentPolicyCorrection(correction)).toMatchObject({
      receipt_id: receiptEvent.id,
      device_key: deviceKey,
      action: "retract",
    });
    const mismatched = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_007,
      kind: 1985,
      tags: correction.tags,
      content: JSON.stringify({
        ...JSON.parse(correction.content),
        device_key: replacementKey,
      }),
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyCorrection(mismatched))
      .toThrow(/agent-policy-receipt-invalid/);
  });

  it("requires both a signed correction and current canonical list removal", () => {
    expect(applyAgentPolicyCorrection({
      correction_valid: true,
      canonical_list_binding_removed: true,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    })).toEqual({ visible: true, muted: false });
    expect(applyAgentPolicyCorrection({
      correction_valid: true,
      canonical_list_binding_removed: false,
      device_key: deviceKey,
      muted_device_keys: [deviceKey],
    })).toEqual({ visible: false, muted: true });
  });
});
