import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findAnchorResolutionFailures } from "./anchor-resolution.js";

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
      ["docs/spec/heterodyne-core.md", '<a id="core-present"></a>\n'],
      ["docs/spec/heterodyne-comms.md", '<a id="core-missing"></a>\n'],
    ]),
    schemas: new Map(),
    vectors: vectors.map((value) => ({ path: `${value.vector_id}.json`, value })),
    fixtures: {},
    registry: { manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) }, reason_codes: [], security_invariants: [] },
  };
}

describe("findAnchorResolutionFailures", () => {
  it("reports a stable key when a reference is absent from its owner specification", () => {
    const input = corpus([
      vector("sample/present", ["heterodyne:0.5.0#core-present"]),
      vector("sample/missing", [
        "heterodyne:0.5.0#core-missing",
        "heterodyne:0.5.0#core-missing",
      ]),
    ]);

    expect(findAnchorResolutionFailures(input)).toEqual([
      "sample/missing :: heterodyne:0.5.0#core-missing",
    ]);
  });
});
