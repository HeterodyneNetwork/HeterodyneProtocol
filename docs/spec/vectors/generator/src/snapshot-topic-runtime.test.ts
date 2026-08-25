import { describe, expect, it } from "vitest";
import { buildAgentModerationVectors } from "./topics-agent-moderation.js";

describe("snapshot-only frozen topic runtime", () => {
  it("executes the frozen legacy moderation builder through the isolated adapter", async () => {
    await expect(buildAgentModerationVectors())
      .rejects.toThrow(/agent-policy-receipt-invalid/);

    const runtime = await import("./snapshot-topic-runtime.js").catch(() => ({}));
    const build = (runtime as {
      buildSnapshotAgentModerationVectors?: () => ReturnType<
        typeof buildAgentModerationVectors
      >;
    }).buildSnapshotAgentModerationVectors;
    const vectors = await build?.();
    expect(vectors?.find(({ vector }) =>
      vector.vector_id === "agent-moderation/receipt-valid")?.vector)
      .toEqual(expect.objectContaining({
      vector_id: "agent-moderation/receipt-valid",
      expected_output: expect.objectContaining({ verdict: "accept" }),
      }));
  });
});
