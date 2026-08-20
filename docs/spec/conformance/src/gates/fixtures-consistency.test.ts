import { describe, expect, it } from "vitest";
import type { ArtifactCorpus } from "../types.js";
import { findFixturesConsistencyFailures } from "./fixtures-consistency.js";

const digest = "aa".repeat(32);

function completeFixtures(): Record<string, unknown> {
  return {
    audience_keys: {},
    category_keysets: {},
    device_publishing_keys: {},
    ed25519_nids: {},
    kel: {},
    personas: {},
    pinned_randomness: {},
    radicle_rids: {},
    registry_sha256: digest,
    spec_version: "heterodyne/0.5.0",
    test_epoch: 0,
    vector_schema_version: "1.1.0",
  };
}

function corpus(fixtures: Record<string, unknown>): ArtifactCorpus {
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: digest,
    specifications: new Map(),
    schemas: new Map(),
    vectors: [],
    fixtures,
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: digest },
      reason_codes: [],
      security_invariants: [],
    },
  };
}

describe("findFixturesConsistencyFailures", () => {
  it("reports exact pointers for family metadata drift and unexpected keys", () => {
    const fixtures = completeFixtures();
    fixtures.registry_sha256 = "bb".repeat(32);
    fixtures.unexpected = true;

    expect(findFixturesConsistencyFailures(corpus(fixtures))).toEqual([
      "/registry_sha256",
      "/unexpected",
    ]);
  });

  it("reports missing allowlisted keys and all mismatched pinned versions", () => {
    const fixtures = completeFixtures();
    delete fixtures.kel;
    fixtures.spec_version = "heterodyne/0.4.0";
    fixtures.vector_schema_version = "1.0.0";

    expect(findFixturesConsistencyFailures(corpus(fixtures))).toEqual([
      "/kel",
      "/spec_version",
      "/vector_schema_version",
    ]);
  });

  it("escapes unexpected fixture keys as RFC 6901 pointers", () => {
    const fixtures = completeFixtures();
    fixtures["unexpected/key~part"] = true;

    expect(findFixturesConsistencyFailures(corpus(fixtures))).toEqual([
      "/unexpected~1key~0part",
    ]);
  });
});
