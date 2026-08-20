import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findAnchorCoverageFailures } from "./anchor-coverage.js";
import { STATIC_GATES } from "./index.js";

function vector(vector_id: string, spec_refs: string[]): VectorDocument {
  return {
    vector_id,
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs,
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  };
}

function corpus(vectors: VectorDocument[]): ArtifactCorpus {
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: "aa".repeat(32),
    specifications: new Map([
      ["docs/spec/heterodyne-core.md", '<a id="core-covered"></a>\n<a id="core-uncovered"></a>\n'],
      ["docs/spec/heterodyne-comms.md", '<a id="comms-covered"></a>\n'],
      ["docs/spec/heterodyne-control.md", ""],
      ["docs/spec/heterodyne-social.md", ""],
      ["docs/spec/heterodyne-workspace.md", ""],
      ["docs/spec/not-family.md", '<a id="core-not-normative"></a>\n'],
    ]),
    schemas: new Map(),
    vectors: vectors.map((value) => ({ path: `${value.vector_id}.json`, value })),
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) },
      reason_codes: [],
      security_invariants: [],
    },
  };
}

describe("findAnchorCoverageFailures", () => {
  it("reports each family anchor that no vector references", () => {
    const input = corpus([
      vector("sample/covered", [
        "heterodyne:0.5.0#core-covered",
        "heterodyne:0.5.0#comms-covered",
        "heterodyne:0.5.0#comms-covered",
      ]),
    ]);

    expect(findAnchorCoverageFailures(input)).toEqual([
      "heterodyne:0.5.0#core-uncovered",
    ]);
  });
});

describe("STATIC_GATES", () => {
  it("registers G1 through G7 in gate order", () => {
    expect(STATIC_GATES.map(({ id }) => id)).toEqual([
      "G1", "G2", "G3", "G4", "G5", "G6", "G7",
    ]);
  });
});
