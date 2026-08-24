import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { QUALIFIED_VERSION } from "./family.js";
import { buildFixtures } from "./fixtures.js";
import { loadRegistry } from "./registry.js";
import { stampOwner, type StampInput } from "./stamping.js";
import { buildSplitVectors } from "./topics-split.js";

const here = dirname(fileURLToPath(import.meta.url));
const registry = loadRegistry(resolve(here, "../../../../../"));

const input = (overrides: Partial<StampInput>): StampInput => ({
  kind: 31001,
  content_is_heterodyne_json: true,
  is_dr_outer: false,
  ...overrides,
});

describe("registry-driven owner stamping", () => {
  it.each([
    ["kind:31001 base", input({}), "assurance"],
    [
      "registered Social NIP-51 profile",
      input({ kind: 10000, profile_id: "heterodyne-social-mute-list-v1" }),
      "social",
    ],
    ["plain upstream NIP-51", input({ kind: 10000 }), null],
    [
      "registered Tier-3 wrapped upstream profile",
      input({
        kind: 1,
        profile_id: "heterodyne-comms-tier3-wrapped-content-kind-1-v1",
        content_is_heterodyne_json: false,
      }),
      "comms",
    ],
    [
      "non-stamping Core breadcrumb",
      input({
        kind: 0,
        profile_id: "heterodyne-core-rotation-breadcrumb-profile-v1",
      }),
      null,
    ],
    ["Marmot gift wrap remains upstream", input({ kind: 445 }), null],
    [
      "inner Control application event adds no standalone stamp",
      input({ kind: 31017, profile_id: "heterodyne-control-marmot-frame-v1" }),
      null,
    ],
    ["unknown kind", input({ kind: 65535 }), null],
    ["unknown profile on allocated kind", input({ profile_id: "unknown-profile" }), null],
    ["empty or non-JSON allocated kind uses owner tag", input({ content_is_heterodyne_json: false }), "assurance"],
  ])("classifies %s", (_name, stampInput, expected) => {
    expect(stampOwner(stampInput as StampInput, registry)).toBe(expected);
  });

  it("carries the exact family version for every stamped ownership class", async () => {
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
