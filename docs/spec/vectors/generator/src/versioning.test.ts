import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./snapshot-fixtures-adapter.js";
import { loadRegistry } from "./registry.js";
import { buildAllVectors } from "./topics.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");

function capabilityFixtures(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) return value.flatMap(capabilityFixtures);
  if (value === null || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  return [
    ...(record.descriptor === "heterodyne-capabilities-v1" ? [record] : []),
    ...Object.values(record).flatMap(capabilityFixtures),
  ];
}

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
    expect(byId("versioning/qualified-version-unqualified-rejected").input)
      .toEqual({ values: ["0.5.0", "core/0.5.0"] });
    expect(JSON.stringify(versionVectors.filter(
      ({ vector_id }) => vector_id !== "versioning/qualified-version-unqualified-rejected",
    ))).not.toMatch(
      /(?:core|comms|control|social|workspace)\/[0-9]/,
    );
  }, 30_000);

  it("pins every capability fixture to the authoritative registry entry set", async () => {
    const digest = loadRegistry(repositoryRoot).manifest.entry_set_sha256;
    const capabilities = capabilityFixtures(await buildAllVectors(buildFixtures()));

    expect(capabilities.length).toBeGreaterThanOrEqual(2);
    for (const capability of capabilities) {
      expect(capability.registry_sha256).toBe(digest);
    }
  }, 30_000);

  it("describes registry downrefs in terms of the family release", async () => {
    const vector = (await buildAllVectors(buildFixtures()))
      .map(({ vector }) => vector)
      .find(({ vector_id }) => vector_id === "registry/downref-nonfrozen-rejected");

    expect(vector).toBeDefined();
    expect(vector?.description).toContain("1.0 family release");
    expect(vector?.input).toEqual({
      family_version: "heterodyne/1.0.0",
      required_entry_status: "stable",
    });
  }, 30_000);
});
