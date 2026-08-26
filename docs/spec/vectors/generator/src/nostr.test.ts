import { describe, expect, it } from "vitest";
import {
  canonicalNip01,
  getEventId,
  signEvent,
  verifyEventSignature,
} from "./nostr.js";
import * as nostr from "./nostr.js";

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

  it("strictly validates the complete signed NIP-01 structure before cryptography", async () => {
    const validate = (nostr as typeof nostr & {
      isStrictNostrSignedEvent?: (value: unknown) => boolean;
    }).isStrictNostrSignedEvent;
    const valid = await signEvent({
      secretKey: "02".padStart(64, "0"),
      created_at: 1_000,
      kind: 1,
      tags: [["t", "strict"]],
      content: "strict event",
      auxRand: "00".repeat(32),
    });
    const emptyTag = await signEvent({
      secretKey: "02".padStart(64, "0"),
      created_at: 1_000,
      kind: 1,
      tags: [[]],
      content: "empty tag",
      auxRand: "00".repeat(32),
    });
    const negativeTime = await signEvent({
      secretKey: "02".padStart(64, "0"),
      created_at: -1,
      kind: 1,
      tags: [],
      content: "negative time",
      auxRand: "00".repeat(32),
    });
    const outOfRangeKind = await signEvent({
      secretKey: "02".padStart(64, "0"),
      created_at: 1_000,
      kind: 65_536,
      tags: [],
      content: "out of range kind",
      auxRand: "00".repeat(32),
    });

    expect(validate?.(valid)).toBe(true);
    for (const malformed of [
      emptyTag,
      negativeTime,
      outOfRangeKind,
      { ...valid, pubkey: valid.pubkey.toUpperCase() },
      { ...valid, id: valid.id.toUpperCase() },
      { ...valid, sig: valid.sig.toUpperCase() },
      { ...valid, content: 7 },
      { ...valid, tags: [["t", 7]] },
    ]) {
      expect(validate?.(malformed)).toBe(false);
    }
  });

  it("captures one immutable branded event without invoking accessors or proxy traps", async () => {
    const api = nostr as typeof nostr & {
      snapshotAndVerifyNostrEvent?: (value: unknown) => Readonly<{
        id: string;
        pubkey: string;
        created_at: number;
        kind: number;
        tags: readonly (readonly string[])[];
        content: string;
        sig: string;
      }> | null;
      isVerifiedNostrEvent?: (value: unknown) => boolean;
    };
    expect(api.snapshotAndVerifyNostrEvent).toBeTypeOf("function");
    expect(api.isVerifiedNostrEvent).toBeTypeOf("function");

    const source = await signEvent({
      secretKey: "03".padStart(64, "0"),
      created_at: 2_000,
      kind: 1,
      tags: [["t", "captured"]],
      content: "captured event",
      auxRand: "00".repeat(32),
    });
    const verified = api.snapshotAndVerifyNostrEvent?.(source);
    expect(verified).not.toBeNull();
    expect(verified).not.toBe(source);
    expect(Object.keys(verified ?? {}).sort()).toEqual(
      ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"],
    );
    expect(api.isVerifiedNostrEvent?.(verified)).toBe(true);
    expect(api.isVerifiedNostrEvent?.(source)).toBe(false);
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified?.tags)).toBe(true);
    expect(Object.isFrozen(verified?.tags[0])).toBe(true);

    source.tags[0]![1] = "mutated source";
    expect(verified?.tags).toEqual([["t", "captured"]]);

    let getterCalls = 0;
    const accessor = { ...source } as Record<string, unknown>;
    Object.defineProperty(accessor, "content", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "captured event";
      },
    });
    expect(api.snapshotAndVerifyNostrEvent?.(accessor)).toBeNull();
    expect(getterCalls).toBe(0);

    let proxyTraps = 0;
    const proxy = new Proxy(source, {
      ownKeys() {
        proxyTraps += 1;
        return Reflect.ownKeys(source);
      },
      getOwnPropertyDescriptor(_target, member) {
        proxyTraps += 1;
        return Object.getOwnPropertyDescriptor(source, member);
      },
      getPrototypeOf() {
        proxyTraps += 1;
        return Object.prototype;
      },
    });
    expect(api.snapshotAndVerifyNostrEvent?.(proxy)).toBeNull();
    expect(proxyTraps).toBe(0);
  });
});
