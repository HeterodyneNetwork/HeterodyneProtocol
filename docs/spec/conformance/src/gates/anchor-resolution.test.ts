import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findAnchorResolutionFailures } from "./anchor-resolution.js";

function vector(vector_id: string, spec_refs: string[]): VectorDocument {
  return {
    vector_id,
    vector_schema_version: "2.0.0",
    owner_document: "core",
    spec_refs,
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  };
}

function corpus(vectors: VectorDocument[]): ArtifactCorpus {
  return {
    sourceRoot: "/synthetic/source",
    snapshotRoot: "/synthetic/snapshot",
    sourceCommit: "1".repeat(40),
    snapshotCommit: "2".repeat(40),
    vectorSchemaVersion: "2.0.0",
    specifications: new Map([
      ["docs/spec/heterodyne-core.md", '<a id="core-present"></a>\n'],
      ["docs/spec/heterodyne-comms.md", '<a id="core-missing"></a>\n'],
    ]),
    schemas: new Map(),
    vectorSchema: {},
    vectors: vectors.map((value) => ({ path: `${value.vector_id}.json`, value })),
    fixtures: {},
    registry: { manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) }, reason_codes: [], security_invariants: [] },
  };
}

describe("findAnchorResolutionFailures", () => {
  it("reports a stable key when a reference is absent from its owner specification", () => {
    const input = corpus([
      vector("sample/present", ["heterodyne:core#core-present"]),
      vector("sample/missing", [
        "heterodyne:core#core-missing",
        "heterodyne:core#core-missing",
      ]),
    ]);

    expect(findAnchorResolutionFailures(input)).toEqual([
      "sample/missing :: heterodyne:core#core-missing",
    ]);
  });

  it("uses the referenced document instead of inferring ownership from the anchor", () => {
    const input = corpus([
      vector("sample/wrong-document", ["heterodyne:comms#core-present"]),
      vector("sample/legacy", ["heterodyne:0.5.0#core-present"]),
    ]);

    expect(findAnchorResolutionFailures(input)).toEqual([
      "sample/legacy :: heterodyne:0.5.0#core-present",
      "sample/wrong-document :: heterodyne:comms#core-present",
    ]);
  });
});
