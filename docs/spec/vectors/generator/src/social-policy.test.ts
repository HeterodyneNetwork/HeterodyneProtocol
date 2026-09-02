import { describe, expect, it } from "vitest";
import { getPublicKey, signEvent } from "./nostr.js";
import {
  evaluateAgentModerationEvidence,
  evaluateModeratorAsOfDeclaration,
} from "./social-policy.js";

const AUX_RAND = "00".repeat(32);
const MODERATOR_SECRET = "31".repeat(32);
const OUTSIDER_SECRET = "32".repeat(32);
const AGENT_SECRET = "33".repeat(32);

describe("current Social moderation semantic boundaries", () => {
  it("requires a moderator to appear in the declaration effective for an approval", async () => {
    const declaration = await signEvent({
      secretKey: MODERATOR_SECRET,
      created_at: 1_000,
      kind: 34_550,
      tags: [
        ["d", "current-community"],
        ["p", getPublicKey(MODERATOR_SECRET), "", "moderator"],
      ],
      content: "",
      auxRand: AUX_RAND,
    });
    const approval = await signEvent({
      secretKey: OUTSIDER_SECRET,
      created_at: 1_001,
      kind: 4_550,
      tags: [],
      content: "",
      auxRand: AUX_RAND,
    });

    expect(evaluateModeratorAsOfDeclaration({ declaration, approval })).toEqual({
      verdict: "reject",
      reason_code: "moderator_not_in_asof_declaration",
    });
  });

  it("distinguishes missing, falsified, and bypassed automated attribution", async () => {
    const agent = getPublicKey(AGENT_SECRET);
    const unsigned = {
      secretKey: AGENT_SECRET,
      created_at: 1_100,
      kind: 1,
      content: "bounded automated publication",
      auxRand: AUX_RAND,
    };
    const missing = await signEvent({ ...unsigned, tags: [] });
    const attributed = await signEvent({
      ...unsigned,
      tags: [
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["heterodyne_agent", "v1", "key", agent],
        ["agent_action", "publish"],
      ],
    });
    const expected = { kind: "key" as const, value: agent };

    expect(evaluateAgentModerationEvidence({
      event: missing,
      automated: true,
      publication_path: "comms-authorized",
      expected_agent_association: expected,
    })).toEqual({ verdict: "reject", reason_code: "agent-attribution-missing" });
    expect(evaluateAgentModerationEvidence({
      event: attributed,
      automated: true,
      publication_path: "comms-authorized",
      expected_agent_association: { kind: "key", value: getPublicKey(OUTSIDER_SECRET) },
    })).toEqual({ verdict: "reject", reason_code: "agent-attribution-falsified" });
    expect(evaluateAgentModerationEvidence({
      event: attributed,
      automated: true,
      publication_path: "direct",
      expected_agent_association: expected,
    })).toEqual({ verdict: "reject", reason_code: "agent-publication-bypass" });
  });
});
