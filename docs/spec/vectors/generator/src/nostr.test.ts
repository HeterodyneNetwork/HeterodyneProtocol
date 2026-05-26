import { describe, expect, it } from "vitest";
import {
  canonicalNip01,
  getEventId,
  signEvent,
  verifyEventSignature,
} from "./nostr.js";

describe("NIP-01 canonical event primitives", () => {
  it("serializes the exact array that is hashed for event ids", () => {
    const serialized = canonicalNip01({
      pubkey: "f".repeat(64),
      created_at: 1767225600,
      kind: 1,
      tags: [["client", "heterodyne"], ["emoji", "snowman", "\u2603"]],
      content: "hello / \"world\"\n",
    });

    expect(serialized).toBe(
      '[0,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",1767225600,1,[["client","heterodyne"],["emoji","snowman","☃"]],"hello / \\"world\\"\\n"]',
    );
  });

  it("computes and verifies deterministic Schnorr signatures with fixed aux_rand", async () => {
    const event = await signEvent({
      secretKey: "01".padStart(64, "0"),
      created_at: 1767225600,
      kind: 1,
      tags: [["t", "determinism"]],
      content: "deterministic heterodyne test",
      auxRand: "00".repeat(32),
    });

    expect(event.id).toBe(getEventId(event));
    expect(event.sig).toHaveLength(128);
    expect(verifyEventSignature(event)).toBe(true);

    const repeated = await signEvent({
      secretKey: "01".padStart(64, "0"),
      created_at: 1767225600,
      kind: 1,
      tags: [["t", "determinism"]],
      content: "deterministic heterodyne test",
      auxRand: "00".repeat(32),
    });
    expect(repeated).toEqual(event);
  });
});
