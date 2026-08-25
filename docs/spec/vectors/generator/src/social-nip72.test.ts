import { beforeAll, describe, expect, it } from "vitest";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND } from "./vector-helpers.js";

type Nip72Module = {
  evaluateNip72CuratedView?: (input: {
    community: { pubkey: string; d: string };
    declaration_candidates: Array<{
      carrier: "relay" | "repository";
      event: NostrSignedEvent;
    }>;
    candidate: NostrSignedEvent;
    approvals: NostrSignedEvent[];
    deletions?: NostrSignedEvent[];
  }) => {
    verdict: "accept" | "hold" | "reject";
    counted_approval_ids?: string[];
    audit_only_approval_ids?: string[];
    reason_code?: string;
  };
};

const communitySecret = "18".repeat(32);
const communityKey = getPublicKey(communitySecret);
const moderatorASecret = "19".repeat(32);
const moderatorAKey = getPublicKey(moderatorASecret);
const moderatorBSecret = "1a".repeat(32);
const moderatorBKey = getPublicKey(moderatorBSecret);
const authorSecret = "1b".repeat(32);
const authorKey = getPublicKey(authorSecret);
const coordinate = `34550:${communityKey}:garden`;
let oldDeclaration: NostrSignedEvent;
let currentDeclaration: NostrSignedEvent;
let candidate: NostrSignedEvent;
let oldModeratorApproval: NostrSignedEvent;
let currentModeratorApproval: NostrSignedEvent;

beforeAll(async () => {
  oldDeclaration = await signEvent({
    secretKey: communitySecret,
    created_at: 1_000,
    kind: 34550,
    tags: [
      ["d", "garden"],
      ["p", moderatorAKey, "wss://relay.example/", "moderator"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  currentDeclaration = await signEvent({
    secretKey: communitySecret,
    created_at: 1_100,
    kind: 34550,
    tags: [
      ["d", "garden"],
      ["p", moderatorBKey, "wss://relay.example/", "moderator"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  candidate = await signEvent({
    secretKey: authorSecret,
    created_at: 1_010,
    kind: 1,
    tags: [["a", coordinate]],
    content: "community contribution",
    auxRand: AUX_RAND,
  });
  oldModeratorApproval = await approval(moderatorASecret, 1_020);
  currentModeratorApproval = await approval(moderatorBSecret, 1_120);
});

async function approval(secretKey: string, created_at: number): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey,
    created_at,
    kind: 4550,
    tags: [
      ["a", coordinate],
      ["e", candidate.id],
      ["p", authorKey],
    ],
    content: JSON.stringify(candidate),
    auxRand: AUX_RAND,
  });
}

async function loadNip72(): Promise<Nip72Module> {
  return await import("./social-nip72.js").catch(() => ({}));
}

describe("NIP-72 live curated view", () => {
  it("treats a removed moderator's old approval as audit-only", async () => {
    const nip72 = await loadNip72();
    expect(nip72.evaluateNip72CuratedView?.({
      community: { pubkey: communityKey, d: "garden" },
      declaration_candidates: [
        { carrier: "repository", event: oldDeclaration },
        { carrier: "relay", event: currentDeclaration },
      ],
      candidate,
      approvals: [oldModeratorApproval],
    })).toEqual({
      verdict: "hold",
      counted_approval_ids: [],
      audit_only_approval_ids: [oldModeratorApproval.id],
    });
  });

  it("requires reapproval by the currently selected moderator set", async () => {
    const nip72 = await loadNip72();
    expect(nip72.evaluateNip72CuratedView?.({
      community: { pubkey: communityKey, d: "garden" },
      declaration_candidates: [
        { carrier: "relay", event: currentDeclaration },
        { carrier: "repository", event: oldDeclaration },
      ],
      candidate,
      approvals: [oldModeratorApproval, currentModeratorApproval],
    })).toEqual({
      verdict: "accept",
      counted_approval_ids: [currentModeratorApproval.id],
      audit_only_approval_ids: [oldModeratorApproval.id],
    });
  });

  it("accepts upstream candidate and approval tag prefixes with trailing relay hints", async () => {
    const hintedCandidate = await signEvent({
      secretKey: authorSecret,
      created_at: 1_115,
      kind: 1,
      tags: [["a", coordinate, "wss://community.example/"]],
      content: "hinted contribution",
      auxRand: AUX_RAND,
    });
    const hintedApproval = await signEvent({
      secretKey: moderatorBSecret,
      created_at: 1_120,
      kind: 4550,
      tags: [
        ["a", coordinate, "wss://community.example/"],
        ["e", hintedCandidate.id, "wss://author.example/"],
        ["p", authorKey, "wss://author.example/"],
      ],
      content: JSON.stringify(hintedCandidate),
      auxRand: AUX_RAND,
    });
    const nip72 = await loadNip72();
    expect(nip72.evaluateNip72CuratedView?.({
      community: { pubkey: communityKey, d: "garden" },
      declaration_candidates: [{ carrier: "relay", event: currentDeclaration }],
      candidate: hintedCandidate,
      approvals: [hintedApproval],
    })).toMatchObject({
      verdict: "accept",
      counted_approval_ids: [hintedApproval.id],
    });
  });

  it("requires an approval at or after the selected declaration revision", async () => {
    const preRevisionApproval = await approval(moderatorBSecret, 1_050);
    const nip72 = await loadNip72();
    expect(nip72.evaluateNip72CuratedView?.({
      community: { pubkey: communityKey, d: "garden" },
      declaration_candidates: [
        { carrier: "repository", event: oldDeclaration },
        { carrier: "relay", event: currentDeclaration },
      ],
      candidate,
      approvals: [preRevisionApproval],
    })).toEqual({
      verdict: "hold",
      counted_approval_ids: [],
      audit_only_approval_ids: [preRevisionApproval.id],
    });
  });

  it("excludes only a strict same-author NIP-09 deletion of the approval", async () => {
    const validDeletion = await signEvent({
      secretKey: moderatorBSecret,
      created_at: 1_130,
      kind: 5,
      tags: [["e", currentModeratorApproval.id, "wss://relay.example/"]],
      content: "withdraw approval",
      auxRand: AUX_RAND,
    });
    const wrongAuthorDeletion = await signEvent({
      secretKey: moderatorASecret,
      created_at: 1_130,
      kind: 5,
      tags: [["e", currentModeratorApproval.id]],
      content: "forged withdrawal",
      auxRand: AUX_RAND,
    });
    const malformedDeletion = await signEvent({
      secretKey: moderatorBSecret,
      created_at: 1_130,
      kind: 5,
      tags: [[]],
      content: "malformed withdrawal",
      auxRand: AUX_RAND,
    });
    const nip72 = await loadNip72();
    const base = {
      community: { pubkey: communityKey, d: "garden" },
      declaration_candidates: [{ carrier: "relay" as const, event: currentDeclaration }],
      candidate,
      approvals: [currentModeratorApproval],
    };
    expect(nip72.evaluateNip72CuratedView?.({
      ...base,
      deletions: [wrongAuthorDeletion, malformedDeletion],
    })).toMatchObject({ verdict: "accept" });
    expect(nip72.evaluateNip72CuratedView?.({
      ...base,
      deletions: [validDeletion],
    })).toEqual({
      verdict: "hold",
      counted_approval_ids: [],
      audit_only_approval_ids: [],
    });
  });
});
