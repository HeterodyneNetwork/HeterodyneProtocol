import { describe, expect, it } from "vitest";
import type { ArtifactCorpus } from "../types.js";
import { findInvariantCompletenessFailures } from "./invariant-completeness.js";

type Invariant = ArtifactCorpus["registry"]["security_invariants"][number];

function corpus(
  specifications: Record<string, string>,
  securityInvariants: readonly Invariant[],
): ArtifactCorpus {
  return {
    sourceRoot: "/synthetic/source",
    snapshotRoot: "/synthetic/snapshot",
    sourceCommit: "1".repeat(40),
    snapshotCommit: "2".repeat(40),
    vectorSchemaVersion: "2.0.0",
    specifications: new Map(Object.entries(specifications)),
    schemas: new Map(),
    vectorSchema: {},
    vectors: [],
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) },
      reason_codes: [],
      security_invariants: securityInvariants,
    },
  };
}

describe("findInvariantCompletenessFailures", () => {
  it("accepts an Assurance strict-profile closure for an Assurance invariant", () => {
    const input = corpus({ "docs/spec/heterodyne-assurance.md": `
<!-- fixture:assurance-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-assurance-strict-v1",
  "conformance_class": "Core+Assurance",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": ["ASSURANCE-I-CONTINUITY"]
}
\`\`\`
` }, [{ id: "ASSURANCE-I-CONTINUITY", owner: "assurance" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual([]);
  });

  it("reports a registered baseline invariant absent from every strict-profile closure", () => {
    const input = corpus({ "docs/spec/heterodyne-core.md": `
<!-- fixture:core-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-base-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
<!-- fixture:core-dependent-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-dependent-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": ["heterodyne-core-base-strict-v1"],
  "adds_invariants": []
}
\`\`\`
` }, [
      { id: "CORE-I-CLAIMED", owner: "core" },
      { id: "CORE-I-UNCLAIMED", owner: "core" },
      { id: "CORE-I-FEATURE-BOUND", owner: "core", feature: "core.optional.v1" },
    ]);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-UNCLAIMED"]);
  });

  it("does not let an unrelated owner profile claim an invariant", () => {
    const input = corpus({ "docs/spec/heterodyne-comms.md": `
<!-- fixture:comms-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-comms-strict-v1",
  "conformance_class": "Core+Comms",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
` }, [{ id: "CORE-I-CLAIMED", owner: "core" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-CLAIMED"]);
  });

  it("does not use a closure outside the invariant owner's conformance class", () => {
    const input = corpus({ "docs/spec/heterodyne-core.md": `
<!-- fixture:core-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-strict-v1",
  "conformance_class": "Comms",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
` }, [{ id: "CORE-I-CLAIMED", owner: "core" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-CLAIMED"]);
  });

  it("rejects a profile closure with a missing prerequisite", () => {
    const input = corpus({ "docs/spec/heterodyne-core.md": `
<!-- fixture:core-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": ["heterodyne-missing-strict-v1"],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
` }, [{ id: "CORE-I-CLAIMED", owner: "core" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-CLAIMED"]);
  });

  it("rejects every closure participating in a prerequisite cycle", () => {
    const input = corpus({ "docs/spec/heterodyne-core.md": `
<!-- fixture:core-a-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-a-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": ["heterodyne-core-b-strict-v1"],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
<!-- fixture:core-b-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-b-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": ["heterodyne-core-a-strict-v1"],
  "adds_invariants": []
}
\`\`\`
` }, [{ id: "CORE-I-CLAIMED", owner: "core" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual(["CORE-I-CLAIMED"]);
  });

  it("uses a prerequisite's transitive invariant set for an applicable closure", () => {
    const input = corpus({ "docs/spec/heterodyne-core.md": `
<!-- fixture:core-prerequisite-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-prerequisite-strict-v1",
  "conformance_class": "Prerequisite",
  "state": "active",
  "requires_profiles": [],
  "adds_invariants": ["CORE-I-CLAIMED"]
}
\`\`\`
<!-- fixture:core-strict-profile -->
\`\`\`json
{
  "profile_id": "heterodyne-core-strict-v1",
  "conformance_class": "Core",
  "state": "active",
  "requires_profiles": ["heterodyne-core-prerequisite-strict-v1"],
  "adds_invariants": []
}
\`\`\`
` }, [{ id: "CORE-I-CLAIMED", owner: "core" }]);

    expect(findInvariantCompletenessFailures(input)).toEqual([]);
  });
});
