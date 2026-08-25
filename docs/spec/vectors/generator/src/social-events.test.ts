import { beforeAll, describe, expect, it } from "vitest";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND } from "./vector-helpers.js";

type AgentAssociation = { kind: "key" | "role"; value: string };
type SocialEventsModule = {
  validateSocialAuthorship?: (input: {
    event: NostrSignedEvent;
    persona_active_key?: string;
    comms_authorized_signers?: Array<{
      pubkey: string;
      agent_association: AgentAssociation | null;
    }>;
  }) => {
    verdict: "accept" | "reject";
    event_author?: string;
    represented_persona?: string;
    agent_association?: AgentAssociation;
    reason_code?: string;
  };
  selectCurrentSocialEvent?: (input: {
    coordinate: { pubkey: string; kind: number; d?: string };
    candidates: Array<{
      carrier: "relay" | "repository";
      event: NostrSignedEvent;
    }>;
  }) => NostrSignedEvent | null;
  validateSocialReplaceableCandidate?: (input: {
    coordinate: { pubkey: string; kind: number; d?: string };
    event: NostrSignedEvent;
  }) => {
    verdict: "accept" | "reject";
    reason_code?: string;
  };
  assessSocialStateFreshness?: (
    event: NostrSignedEvent,
    now: number,
  ) => { valid: boolean; warning: "stale" | null };
};

async function loadSocialEvents(): Promise<SocialEventsModule> {
  return await import("./social-events.js").catch(() => ({}));
}

const personaSecret = "15".repeat(32);
const personaKey = getPublicKey(personaSecret);
const agentSecret = "16".repeat(32);
const agentKey = getPublicKey(agentSecret);
const association = { kind: "key", value: agentKey } as const;
let bareReply: NostrSignedEvent;
let profileState: NostrSignedEvent;
let directOrganizationPost: NostrSignedEvent;
let attributedAgentPost: NostrSignedEvent;

beforeAll(async () => {
  bareReply = await signEvent({
    secretKey: personaSecret,
    created_at: 1_000,
    kind: 1,
    tags: [
      ["e", "21".repeat(32), "wss://relay.example/", "root"],
      ["p", "22".repeat(32)],
    ],
    content: "ordinary NIP-10 reply",
    auxRand: AUX_RAND,
  });
  profileState = await signEvent({
    secretKey: personaSecret,
    created_at: 1_000,
    kind: 0,
    tags: [],
    content: JSON.stringify({ name: "example" }),
    auxRand: AUX_RAND,
  });
  directOrganizationPost = await signEvent({
    secretKey: personaSecret,
    created_at: 1_001,
    kind: 1,
    tags: [],
    content: "organization post",
    auxRand: AUX_RAND,
  });
  attributedAgentPost = await signEvent({
    secretKey: agentSecret,
    created_at: 1_002,
    kind: 1,
    tags: [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["heterodyne_agent", "v1", association.kind, association.value],
      ["agent_action", "publish"],
    ],
    content: "attributed organization automation",
    auxRand: AUX_RAND,
  });
});

describe("ordinary Social authorship", () => {
  it("accepts a valid bare-key NIP-10 event without Assurance or KEL context", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({ event: bareReply })).toEqual({
      verdict: "accept",
      event_author: personaKey,
      represented_persona: personaKey,
    });
  });

  it("rejects a cryptographically signed event whose NIP-01 tag structure is invalid", async () => {
    const social = await loadSocialEvents();
    const malformed = await signEvent({
      secretKey: personaSecret,
      created_at: 1_000,
      kind: 1,
      tags: [[]],
      content: "empty tag name",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({ event: malformed })).toEqual({
      verdict: "reject",
      reason_code: "social-event-invalid",
    });
  });

  it("keeps the actual signer authoritative for direct and attributed organization posts", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: directOrganizationPost,
      persona_active_key: personaKey,
    })).toEqual({
      verdict: "accept",
      event_author: personaKey,
      represented_persona: personaKey,
    });
    expect(social.validateSocialAuthorship?.({
      event: attributedAgentPost,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({
      verdict: "accept",
      event_author: agentKey,
      represented_persona: personaKey,
      agent_association: association,
    });
  });

  it("rejects an agent association that is missing, unauthorized, or not signed into the event", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: attributedAgentPost,
      persona_active_key: personaKey,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });

    const unattributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_003,
      kind: 7,
      tags: [["e", bareReply.id], ["p", personaKey]],
      content: "+",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({
      event: unattributed,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
  });

  it("rejects a role association that is authorized for a different signer", async () => {
    const social = await loadSocialEvents();
    const roleAssociation = { kind: "role", value: "publisher" } as const;
    const roleAttributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_004,
      kind: 1,
      tags: [
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["heterodyne_agent", "v1", roleAssociation.kind, roleAssociation.value],
        ["agent_action", "publish"],
      ],
      content: "forged role association",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({
      event: roleAttributed,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: personaKey,
        agent_association: roleAssociation,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
  });

  it("accepts an exact authorized signer when the Comms association is explicitly absent", async () => {
    const social = await loadSocialEvents();
    const attributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_005,
      kind: 1,
      tags: [
        ["L", "network.heterodyne.agent"],
        ["l", "programmatic", "network.heterodyne.agent"],
        ["agent_action", "publish"],
      ],
      content: "association-free attributed automation",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({
      event: attributed,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: null,
      }],
    })).toEqual({
      verdict: "accept",
      event_author: agentKey,
      represented_persona: personaKey,
    });
  });

  it("rejects a forged NIP-01 author instead of trusting persona metadata", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: { ...bareReply, pubkey: agentKey },
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-event-invalid" });
  });
});

describe("source-neutral Social state", () => {
  it("selects the newest valid replaceable event regardless of relay or repository carrier", async () => {
    const social = await loadSocialEvents();
    const oldRepository = await signEvent({
      secretKey: personaSecret,
      created_at: 2_000,
      kind: 10000,
      tags: [["p", agentKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const newRelay = await signEvent({
      secretKey: personaSecret,
      created_at: 2_001,
      kind: 10000,
      tags: [],
      content: "",
      auxRand: AUX_RAND,
    });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 10000 },
      candidates: [
        { carrier: "repository", event: oldRepository },
        { carrier: "relay", event: newRelay },
      ],
    })?.id).toBe(newRelay.id);
  });

  it("uses the lowest event id for a created_at tie and ignores invalid or wrong-coordinate candidates", async () => {
    const social = await loadSocialEvents();
    const left = await signEvent({
      secretKey: personaSecret,
      created_at: 2_100,
      kind: 30000,
      tags: [["d", "team"], ["p", agentKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const right = await signEvent({
      secretKey: personaSecret,
      created_at: 2_100,
      kind: 30000,
      tags: [["d", "team"], ["p", personaKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const wrongCoordinate = await signEvent({
      secretKey: personaSecret,
      created_at: 2_200,
      kind: 30000,
      tags: [["d", "other"]],
      content: "",
      auxRand: AUX_RAND,
    });
    const expected = [left, right].sort((a, b) => a.id.localeCompare(b.id))[0];
    expect(social.validateSocialReplaceableCandidate?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      event: wrongCoordinate,
    })).toEqual({
      verdict: "reject",
      reason_code: "social-replaceable-coordinate-mismatch",
    });
    expect(social.validateSocialReplaceableCandidate?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      event: { ...left, sig: "00".repeat(64) },
    })).toEqual({ verdict: "reject", reason_code: "social-event-invalid" });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      candidates: [
        { carrier: "relay", event: right },
        { carrier: "repository", event: wrongCoordinate },
        { carrier: "repository", event: left },
        { carrier: "relay", event: { ...left, sig: "00".repeat(64) } },
      ],
    })?.id).toBe(expected.id);
  });

  it("uses the second d-tag member as the coordinate and permits trailing members", async () => {
    const social = await loadSocialEvents();
    const event = await signEvent({
      secretKey: personaSecret,
      created_at: 2_300,
      kind: 30000,
      tags: [["d", "team", "extension"]],
      content: "",
      auxRand: AUX_RAND,
    });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      candidates: [{ carrier: "relay", event }],
    })?.id).toBe(event.id);
  });

  it("reports seven-day staleness as a warning without invalidating signed state", async () => {
    const social = await loadSocialEvents();
    expect(social.assessSocialStateFreshness?.(profileState, 1_000 + 7 * 86_400 + 1))
      .toEqual({ valid: true, warning: "stale" });
  });
});
