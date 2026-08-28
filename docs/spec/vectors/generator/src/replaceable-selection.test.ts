import { describe, expect, it, vi } from "vitest";
import { signEvent, type NostrSignedEvent } from "./nostr.js";
import type { ReplaceableSelectionAuthority } from "./replaceable-selection.js";
import { AUX_RAND } from "./vector-helpers.js";

type ReplaceableSelectionResult = {
  selected: NostrSignedEvent | null;
  quarantined: Array<{
    event_id: string;
    reason_code: "core-created-at-premature";
  }>;
};
type ReplaceableSelectionModule = {
  createReplaceableSelectionAuthority?: (input: {
    trusted_now: () => number;
  }) => ReplaceableSelectionAuthority;
  selectCurrentReplaceableEvent?: (
    authority: ReplaceableSelectionAuthority,
    candidates: readonly NostrSignedEvent[],
  ) => ReplaceableSelectionResult;
};

const SECRET = "19".repeat(32);
const MISSING_AUTHORITY = Object.freeze({}) as ReplaceableSelectionAuthority;

async function loadReplaceableSelection(): Promise<ReplaceableSelectionModule> {
  return await import("./replaceable-selection.js").catch(() => ({}));
}

async function signedReplaceable(input: {
  created_at: number;
  content?: string;
}): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey: SECRET,
    created_at: input.created_at,
    kind: 30_000,
    tags: [["d", "selection"]],
    content: input.content ?? "candidate",
    auxRand: AUX_RAND,
  });
}

describe("replaceable-event selection authority", () => {
  it("quarantines then reconsiders at the 900-second boundary", async () => {
    const selection = await loadReplaceableSelection();
    let now = 1_000;
    const authority = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => now,
    }) ?? MISSING_AUTHORITY;
    const future = await signedReplaceable({ created_at: 1_901 });

    expect(selection.selectCurrentReplaceableEvent?.(authority, [future])).toEqual({
      selected: null,
      quarantined: [{
        event_id: future.id,
        reason_code: "core-created-at-premature",
      }],
    });

    now = 1_001;
    expect(selection.selectCurrentReplaceableEvent?.(authority, [future]).selected?.id)
      .toBe(future.id);
  });

  it("does not let advisory kind-1040 evidence change NIP-01 selection", async () => {
    const selection = await loadReplaceableSelection();
    const authority = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => 3_000,
    }) ?? MISSING_AUTHORITY;
    const older = await signedReplaceable({ created_at: 2_000, content: "older" });
    const newer = await signedReplaceable({ created_at: 2_001, content: "newer" });
    const advisory = await signEvent({
      secretKey: SECRET,
      created_at: 2_500,
      kind: 1_040,
      tags: [["e", older.id]],
      content: "synthetic advisory timestamp evidence",
      auxRand: AUX_RAND,
    });

    expect(selection.selectCurrentReplaceableEvent?.(
      authority,
      [older, advisory, newer],
    ).selected?.id).toBe(newer.id);
  });

  it("fails closed when the trusted clock is uncertain or throws", async () => {
    const selection = await loadReplaceableSelection();
    const candidate = await signedReplaceable({ created_at: 1_000 });
    const uncertain = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => Number.NaN,
    }) ?? MISSING_AUTHORITY;
    const throwing = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => {
        throw new Error("clock unavailable");
      },
    }) ?? MISSING_AUTHORITY;

    expect(selection.selectCurrentReplaceableEvent?.(uncertain, [candidate]))
      .toEqual({ selected: null, quarantined: [] });
    expect(selection.selectCurrentReplaceableEvent?.(throwing, [candidate]))
      .toEqual({ selected: null, quarantined: [] });
  });

  it("captures the configured trusted-clock callback exactly once", async () => {
    const selection = await loadReplaceableSelection();
    let callbackReads = 0;
    const config = Object.create(null) as { trusted_now: () => number };
    Object.defineProperty(config, "trusted_now", {
      enumerable: true,
      get: () => {
        callbackReads += 1;
        return callbackReads === 1 ? () => 1_000 : () => 100_000;
      },
    });
    const authority = selection.createReplaceableSelectionAuthority?.(config)
      ?? MISSING_AUTHORITY;
    const future = await signedReplaceable({ created_at: 2_000 });

    expect(selection.selectCurrentReplaceableEvent?.(authority, [future])).toEqual({
      selected: null,
      quarantined: [{
        event_id: future.id,
        reason_code: "core-created-at-premature",
      }],
    });
    expect(callbackReads).toBe(1);
  });

  it("returns a verified frozen snapshot independent of its mutable source", async () => {
    const selection = await loadReplaceableSelection();
    const authority = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => 1_000,
    }) ?? MISSING_AUTHORITY;
    const source = await signedReplaceable({ created_at: 1_000, content: "original" });
    const result = selection.selectCurrentReplaceableEvent?.(authority, [source]);

    expect(result?.selected).not.toBe(source);
    expect(Object.isFrozen(result?.selected)).toBe(true);
    expect(Object.isFrozen(result?.selected?.tags)).toBe(true);
    expect(Object.isFrozen(result?.selected?.tags[0])).toBe(true);
    source.content = "mutated";
    source.tags[0][1] = "mutated";
    expect(result?.selected?.content).toBe("original");
    expect(result?.selected?.tags).toEqual([["d", "selection"]]);
  });

  it("verifies before sorting and uses the lowest id for equal created_at", async () => {
    const selection = await loadReplaceableSelection();
    const authority = selection.createReplaceableSelectionAuthority?.({
      trusted_now: () => 2_000,
    }) ?? MISSING_AUTHORITY;
    const left = await signedReplaceable({ created_at: 2_000, content: "left" });
    const right = await signedReplaceable({ created_at: 2_000, content: "right" });
    const invalid = {
      ...await signedReplaceable({ created_at: 2_001, content: "invalid" }),
      sig: "00".repeat(64),
    };
    const lower = left.id < right.id ? left : right;
    const higher = lower === left ? right : left;
    const localeCompare = vi.spyOn(String.prototype, "localeCompare")
      .mockReturnValue(1);
    try {
      expect(selection.selectCurrentReplaceableEvent?.(
        authority,
        [higher, invalid, lower],
      )).toMatchObject({
        selected: { id: lower.id },
        quarantined: [],
      });
    } finally {
      localeCompare.mockRestore();
    }
  });
});
