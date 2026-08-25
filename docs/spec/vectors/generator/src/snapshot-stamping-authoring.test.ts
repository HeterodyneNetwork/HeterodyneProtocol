import { describe, expect, it } from "vitest";
import { QUALIFIED_VERSION } from "./family.js";
import { buildFixtures } from "./fixtures.js";
import { buildSplitVectors } from "./topics-split.js";

describe("snapshot stamping vector authoring", () => {
  it("carries the historical family version for every stamped ownership class", async () => {
    const vectors = (await buildSplitVectors(buildFixtures()))
      .map(({ vector }) => vector)
      .filter(({ vector_id }) => vector_id.startsWith("stamping/"));
    const stamped = vectors.filter(({ expected_output }) =>
      typeof expected_output.owner === "string");

    expect(stamped.map(({ vector_id }) => vector_id)).toEqual([
      "stamping/heterodyne-json-content-owner",
      "stamping/heterodyne-empty-content-tag-owner",
      "stamping/upstream-profile-owner",
      "stamping/tier3-profile-owner",
    ]);
    for (const vector of stamped) {
      expect(vector.expected_output).toMatchObject({ value: QUALIFIED_VERSION });
      expect(vector.expected_output.value).not.toMatch(/^(?:core|comms|social)\//);
    }
  });
});
