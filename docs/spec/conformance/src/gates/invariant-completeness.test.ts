import { describe, expect, it } from "vitest";
import type { ArtifactCorpus } from "../types.js";
import { findInvariantCompletenessFailures } from "./invariant-completeness.js";

function corpus(coreSpecification: string): ArtifactCorpus {
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: "aa".repeat(32),
    specifications: new Map([["docs/spec/heterodyne-core.md", coreSpecification]]),
    schemas: new Map(),
    vectors: [],
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) },
      reason_codes: [],
      security_invariants: [
        { id: "CORE-I-CLAIMED", owner: "core" },
        { id: "CORE-I-UNCLAIMED", owner: "core" },
        { id: "CORE-I-FEATURE-BOUND", owner: "core", feature: "core.optional.v1" },
      ],
    },
  };
}

describe("findInvariantCompletenessFailures", () => {
  it("reports a registered baseline invariant absent from every strict-profile closure", () => {
    const input = corpus(`
<!-- fixture:core-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-base-strict-v1",
  "requires_profiles": [],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
<!-- fixture:core-dependent-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-dependent-strict-v1",
  "requires_profiles": ["heterodyne-core-base-strict-v1"],
  "adds_invariants": []
}
\`\`\`
`);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-UNCLAIMED"]);
  });
});
