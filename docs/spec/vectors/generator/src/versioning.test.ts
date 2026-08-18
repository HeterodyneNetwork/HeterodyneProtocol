import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { buildAllVectors } from "./topics.js";

describe("authored versioning vectors", () => {
  it("uses only single-family version behavior", async () => {
    const versionVectors = (await buildAllVectors(buildFixtures()))
      .map(({ vector }) => vector)
      .filter(({ vector_id }) => vector_id.startsWith("versioning/"));
    const byId = (vector_id: string) => {
      const vector = versionVectors.find((entry) => entry.vector_id === vector_id);
      if (!vector) throw new Error(`missing vector: ${vector_id}`);
      return vector;
    };

    expect(byId("versioning/qualified-version-valid").expected_output)
      .toEqual({ valid: true, semver: "0.5.0" });
    expect(byId("versioning/exact-family-version-negotiation").input)
      .toEqual({ local: ["heterodyne/0.5.0"], remote: ["heterodyne/0.5.0"] });
    expect(JSON.stringify(versionVectors)).not.toMatch(
      /(?:core|comms|control|social|workspace)\/[0-9]/,
    );
  }, 30_000);
});
