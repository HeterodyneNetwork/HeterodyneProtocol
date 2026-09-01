import { beforeAll, describe, expect, it } from "vitest";
import {
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
let legacyReceiptEvent: NostrSignedEvent;
let legacyCorrectionEvent: NostrSignedEvent;
let legacyListEvent: NostrSignedEvent;
const legacyEventId = "33".repeat(32);
const legacyDeviceKey = "11".repeat(32);
const legacyColdRoot = "44".repeat(32);

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
      spec_version: "heterodyne/0.6.0",
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
      ["spec_version", "heterodyne/0.6.0"],
      ["p", deviceKey],
      ["e", receiptEvent.id],
      ["agent_violation", deviceKey, receiptEvent.id, reason],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  legacyReceiptEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 900,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", reason, "network.heterodyne.agent-policy"],
      ["e", legacyEventId],
      ["p", legacyDeviceKey],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-receipt.v1",
      spec_version: "heterodyne/0.6.0",
      event_id: legacyEventId,
      device_key: legacyDeviceKey,
      cold_root: legacyColdRoot,
      reason,
      observed_at: 900,
      evidence: ["sha256:legacy"],
      explanation: "Frozen pre-redesign receipt.",
      remediation: "rotate-device-key",
    }),
    auxRand: AUX_RAND,
  });
  legacyListEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 901,
    kind: 10000,
    tags: [
      ["heterodyne", "social-agent-policy-list-v1"],
      ["spec_version", "heterodyne/0.6.0"],
      ["p", legacyDeviceKey],
      ["e", legacyReceiptEvent.id],
      ["agent_violation", legacyDeviceKey, legacyReceiptEvent.id, reason],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  legacyCorrectionEvent = await signEvent({
    secretKey: moderatorPrivateKey,
    created_at: 902,
    kind: 1985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", "correction", "network.heterodyne.agent-policy"],
      ["e", legacyReceiptEvent.id],
      ["p", legacyDeviceKey],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-correction.v1",
      spec_version: "heterodyne/0.6.0",
      receipt_id: legacyReceiptEvent.id,
      device_key: legacyDeviceKey,
      corrected_at: 902,
      explanation: "Frozen pre-redesign correction.",
      action: "retract",
    }),
    auxRand: AUX_RAND,
  });
});

describe("live moderation API quarantine", () => {
  it("requires an actual signed target instead of accepting a one-argument legacy receipt", () => {
    const call = validateAgentPolicyReceipt as unknown as (
      event: NostrSignedEvent,
    ) => unknown;
    expect(() => call(legacyReceiptEvent)).toThrow(/agent-policy-receipt-invalid/);
  });

  it("requires the current receipt when validating a correction", () => {
    const call = validateAgentPolicyCorrection as unknown as (
      event: NostrSignedEvent,
    ) => unknown;
    expect(() => call(legacyCorrectionEvent)).toThrow(/agent-policy-receipt-invalid/);
  });

  it("does not select a legacy list validator from the map's first value", () => {
    const legacyReceipt = {
      receipt_id: legacyReceiptEvent.id,
      issuer: moderatorPublicKey,
      event_id: legacyEventId,
      device_key: legacyDeviceKey,
      cold_root: legacyColdRoot,
      reason,
      observed_at: 900,
      evidence: ["sha256:legacy"],
      explanation: "Frozen pre-redesign receipt.",
      remediation: "rotate-device-key" as const,
    };
    const call = validateAgentPolicyList as unknown as (
      event: NostrSignedEvent,
      receipts: ReadonlyMap<string, unknown>,
    ) => unknown;
    expect(() => call(
      legacyListEvent,
      new Map([[legacyReceiptEvent.id, legacyReceipt]]),
    )).toThrow(/agent-policy-binding-invalid/);
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

  it("rejects a signed receipt with an invalid NIP-01 tag structure", async () => {
    const malformed = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: receiptEvent.created_at,
      kind: receiptEvent.kind,
      tags: [...receiptEvent.tags, []],
      content: receiptEvent.content,
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyReceipt(malformed, {
      event: offendingEvent,
      verified_agent_association: agentAssociation,
    })).toThrow(/agent-policy-receipt-invalid/);
  });

  it("rejects a cryptographically signed target with an invalid NIP-01 structure", async () => {
    const malformedTarget = await signEvent({
      secretKey: devicePrivateKey,
      created_at: offendingEvent.created_at,
      kind: offendingEvent.kind,
      tags: [[]],
      content: offendingEvent.content,
      auxRand: AUX_RAND,
    });
    const targetReceipt = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: receiptEvent.created_at,
      kind: receiptEvent.kind,
      tags: receiptEvent.tags.map((tag) =>
        tag[0] === "e" ? ["e", malformedTarget.id] : tag),
      content: JSON.stringify({
        ...JSON.parse(receiptEvent.content),
        event_id: malformedTarget.id,
      }),
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyReceipt(targetReceipt, {
      event: malformedTarget,
      verified_agent_association: agentAssociation,
    })).toThrow(/agent-policy-receipt-invalid/);
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

  it("rejects a signed policy list with an invalid NIP-01 tag structure", async () => {
    const malformed = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: listEvent.created_at,
      kind: listEvent.kind,
      tags: [...listEvent.tags, []],
      content: listEvent.content,
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyList(
      malformed,
      new Map([[receiptEvent.id, receipt]]),
    )).toThrow(/agent-policy-binding-invalid/);
  });

  it("accepts a signed empty replacement as an exact removal list", async () => {
    const removed = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_009,
      kind: 10000,
      tags: [
        ["heterodyne", "social-agent-policy-list-v1"],
        ["spec_version", "heterodyne/0.6.0"],
      ],
      content: "",
      auxRand: AUX_RAND,
    });
    expect(validateAgentPolicyList(removed, new Map())).toEqual({
      policy_persona: moderatorPublicKey,
      event_id: removed.id,
      entries: [],
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects duplicate or unbound policy-list references", async () => {
    for (const extraTag of [
      ["p", deviceKey],
      ["e", receiptEvent.id],
      ["p", replacementKey],
    ]) {
      const malformed = await signEvent({
        secretKey: moderatorPrivateKey,
        created_at: 1_010,
        kind: 10000,
        tags: [...listEvent.tags, extraTag],
        content: "",
        auxRand: AUX_RAND,
      });
      expect(() => validateAgentPolicyList(
        malformed,
        new Map([[receiptEvent.id, receipt]]),
      )).toThrow(/agent-policy-binding-invalid/);
    }
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
        spec_version: "heterodyne/0.6.0",
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

  it("does not reread a mutable correction source after verification", async () => {
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
        spec_version: "heterodyne/0.6.0",
        corrects_receipt_id: receiptEvent.id,
        event_id: offendingEvent.id,
        event_author: deviceKey,
        agent_association: agentAssociation,
        policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
        decision: "retract",
        corrected_at: 1_007,
        evidence: ["sha256:chronology"],
        explanation: "Synthetic boundary validation only.",
      }),
      auxRand: AUX_RAND,
    });
    const mutatingReceipt = { ...receipt };
    Object.defineProperty(mutatingReceipt, "issuer", {
      enumerable: true,
      get() {
        correction.created_at = 1_007;
        return receipt.issuer;
      },
    });
    expect(() => validateAgentPolicyCorrection(correction, mutatingReceipt))
      .toThrow(/agent-policy-receipt-invalid/);
  });

  it("rejects a signed correction with an invalid NIP-01 tag structure", async () => {
    const correction = await signEvent({
      secretKey: moderatorPrivateKey,
      created_at: 1_008,
      kind: 1985,
      tags: [
        ["L", "network.heterodyne.agent-policy"],
        ["l", "correction", "network.heterodyne.agent-policy"],
        ["e", receiptEvent.id],
        ["p", deviceKey],
        [],
      ],
      content: JSON.stringify({
        profile: "heterodyne.social.agent-policy-correction.v1",
        spec_version: "heterodyne/0.6.0",
        corrects_receipt_id: receiptEvent.id,
        event_id: offendingEvent.id,
        event_author: deviceKey,
        agent_association: agentAssociation,
        policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
        decision: "retract",
        corrected_at: 1_008,
        evidence: ["sha256:dcba"],
        explanation: "The original evidence was misclassified.",
      }),
      auxRand: AUX_RAND,
    });
    expect(() => validateAgentPolicyCorrection(correction, receipt))
      .toThrow(/agent-policy-receipt-invalid/);
  });

});
