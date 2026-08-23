import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { SCHEMA_VERSION } from "./vector-helpers.js";

describe("fixture metadata", () => {
  it("tracks the current draft vector schema version", () => {
    expect(buildFixtures().vector_schema_version).toBe(SCHEMA_VERSION);
  });
});
