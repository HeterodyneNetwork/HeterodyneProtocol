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
const devicePrivateKey = "0e".repeat(32);
const deviceKey = getPublicKey(devicePrivateKey);
const replacementKey = "22".repeat(32);
const agentAssociation = { kind: "key", value: deviceKey } as const;
const reason = "agent-attribution-missing";
let offendingEvent: NostrSignedEvent;
let receiptEvent: NostrSignedEvent;
let receipt: AgentPolicyReceipt;
let listEvent: NostrSignedEvent;

beforeAll(async () => {
  offendingEvent = await signEvent({
    secretKey: devicePrivateKey,
    created_at: 999,
    kind: 1,
    tags: [],
    content: "Automated publication omitted mandatory attribution.",
    auxRand: AUX_RAND,
  });
  receiptEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_000,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", reason, "network.heterodyne.agent-policy"],
      ["e", offendingEvent.id, "wss://relay.example/"],
      ["p", deviceKey, "wss://relay.example/"],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-receipt.v1",
      spec_version: "heterodyne/0.5.0",
      event_id: offendingEvent.id,
      event_author: deviceKey,
      agent_association: agentAssociation,
      policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
      decision: "advisory-violation",
      reason,
      observed_at: 1_000,
      evidence: ["sha256:abcd"],
      explanation: "Automated publication omitted mandatory attribution.",
      remediation: "replace-signing-key",
    }),
    auxRand: AUX_RAND,
  });
  receipt = validateAgentPolicyReceipt(receiptEvent, {
    event: offendingEvent,
    verified_agent_association: agentAssociation,
  });
  listEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 1_001,
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
});

describe("agent-policy receipt", () => {
  it("binds the actual signed event author, verified agent association, policy, and decision", () => {
    expect(receipt).toMatchObject({
      receipt_id: receiptEvent.id,
      event_id: offendingEvent.id,
      event_author: deviceKey,
      agent_association: agentAssociation,
      policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
      decision: "advisory-violation",
      reason,
      remediation: "replace-signing-key",
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
          ["e", offendingEvent.id],
          ["p", deviceKey],
        ],
        content: JSON.stringify({
          ...JSON.parse(receiptEvent.content),
          reason: candidateReason,
        }),
        auxRand: AUX_RAND,
      });
      expect(validateAgentPolicyReceipt(event, {
        event: offendingEvent,
        verified_agent_association: agentAssociation,
      }).reason).toBe(candidateReason);
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
    expect(() => validateAgentPolicyReceipt(malformed, {
      event: offendingEvent,
      verified_agent_association: agentAssociation,
    }))
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
      expect(() => validateAgentPolicyReceipt(event, {
        event: offendingEvent,
        verified_agent_association: agentAssociation,
      }))
        .toThrow(/agent-policy-receipt-invalid/);
    }
  });

  it("rejects a receipt whose claimed author or association does not match the actual event", async () => {
    for (const patch of [
      { event_author: replacementKey },
      { agent_association: { kind: "key", value: replacementKey } },
    ]) {
      const event = await signEvent({
        secretKey: moderatorPrivateKey,
        created_at: 1_004,
        kind: 1985,
        tags: receiptEvent.tags,
        content: JSON.stringify({ ...JSON.parse(receiptEvent.content), ...patch }),
        auxRand: AUX_RAND,
      });
      expect(() => validateAgentPolicyReceipt(event, {
        event: offendingEvent,
        verified_agent_association: agentAssociation,
      })).toThrow(/agent-policy-receipt-invalid/);
    }
  });

  it("rejects a key association that does not name the actual event signer", async () => {
    const wrongAssociation = { kind: "key", value: replacementKey } as const;
    const event = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_004,
      kind: 1985,
      tags: receiptEvent.tags,
      content: JSON.stringify({
        ...JSON.parse(receiptEvent.content),
        agent_association: wrongAssociation,
      }),
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyReceipt(event, {
      event: offendingEvent,
      verified_agent_association: wrongAssociation,
    })).toThrow(/agent-policy-receipt-invalid/);
  });
});

describe("agent policy list and subscriber-local enforcement", () => {
  it("requires exact p, e, and agent_violation binding to a valid receipt", () => {
    const parsed = validateAgentPolicyList(
      listEvent,
      new Map([[receiptEvent.id, receipt]]),
    );
    expect(parsed.entries).toEqual([{
      event_author: deviceKey,
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
      policy_event_selected: true,
      event_author: deviceKey,
      muted_event_authors: [deviceKey],
      default_subscription: true,
      default_visible: true,
      can_disable_default: true,
    };
    expect(applySubscribedAgentPolicy(base)).toEqual({
      visible: false,
      muted: true,
      source: moderatorPublicKey,
      reason: "subscribed-event-author-policy",
    });
    expect(applySubscribedAgentPolicy({ ...base, subscribed: false })).toEqual({
      visible: true,
      muted: false,
    });
    expect(applySubscribedAgentPolicy({ ...base, policy_event_selected: false }))
      .toEqual({ visible: true, muted: false });
  });

  it("keeps the default subscription visible and removable", () => {
    expect(() => applySubscribedAgentPolicy({
      subscribed: true,
      policy_persona: moderatorPublicKey,
      policy_event_selected: true,
      event_author: deviceKey,
      muted_event_authors: [deviceKey],
      default_subscription: true,
      default_visible: false,
      can_disable_default: true,
    })).toThrow(/agent-policy-binding-invalid/);
  });

  it("keeps the old key muted while accepting a replacement at the same role", () => {
    const base = {
      subscribed: true,
      policy_persona: moderatorPublicKey,
      policy_event_selected: true,
      muted_event_authors: [deviceKey],
      default_subscription: false,
      default_visible: true,
      can_disable_default: true,
    };
    expect(applySubscribedAgentPolicy({ ...base, event_author: deviceKey }).muted).toBe(true);
    expect(applySubscribedAgentPolicy({ ...base, event_author: replacementKey })).toEqual({
      visible: true,
      muted: false,
    });
  });
});

describe("correction and current list removal", () => {
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
        spec_version: "heterodyne/0.5.0",
        corrects_receipt_id: receiptEvent.id,
        event_id: offendingEvent.id,
        event_author: deviceKey,
        agent_association: agentAssociation,
        policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
        decision: "retract",
        corrected_at: 1_006,
        evidence: ["sha256:dcba"],
        explanation: "The original evidence was misclassified.",
      }),
      auxRand: AUX_RAND,
    });
    expect(validateAgentPolicyCorrection(correction, receipt)).toMatchObject({
      corrects_receipt_id: receiptEvent.id,
      event_id: offendingEvent.id,
      event_author: deviceKey,
      agent_association: agentAssociation,
      decision: "retract",
    });
    const mismatched = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_007,
      kind: 1985,
      tags: correction.tags,
      content: JSON.stringify({
        ...JSON.parse(correction.content),
        event_author: replacementKey,
      }),
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyCorrection(mismatched, receipt))
      .toThrow(/agent-policy-receipt-invalid/);
  });

  it("requires both a signed correction and source-neutrally selected current list removal", () => {
    expect(applyAgentPolicyCorrection({
      correction_valid: true,
      current_list_binding_removed: true,
      event_author: deviceKey,
      muted_event_authors: [deviceKey],
    })).toEqual({ visible: true, muted: false });
    expect(applyAgentPolicyCorrection({
      correction_valid: true,
      current_list_binding_removed: false,
      event_author: deviceKey,
      muted_event_authors: [deviceKey],
    })).toEqual({ visible: false, muted: true });
  });
});
