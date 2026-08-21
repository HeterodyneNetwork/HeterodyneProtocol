import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findDeadVocabularyFailures } from "./dead-vocabulary.js";

function vector(
  vector_id: string,
  expected_output: Record<string, unknown>,
): VectorDocument {
  return {
    vector_id,
    vector_schema_version: "2.0.0",
    owner_document: "core",
    spec_refs: [],
    direction: "consume",
    input: {},
    expected_output,
  };
}

function corpus(vectors: VectorDocument[]): ArtifactCorpus {
  const digest = "aa".repeat(32);
  return {
    sourceRoot: "/synthetic/source",
    snapshotRoot: "/synthetic/snapshot",
    sourceCommit: "1".repeat(40),
    snapshotCommit: "2".repeat(40),
    vectorSchemaVersion: "2.0.0",
    specifications: new Map(),
    schemas: new Map(),
    vectorSchema: {},
    vectors: vectors.map((value) => ({ path: `${value.vector_id}.json`, value })),
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: digest },
      reason_codes: [
        { code: "used_reason" },
        { code: "unused_reason" },
      ],
      security_invariants: [],
    },
  };
}

describe("findDeadVocabularyFailures", () => {
  it("reports registered reasons unused by rejecting vectors", () => {
    const input = corpus([
      vector("sample/reject", { verdict: "reject", reason_code: "used_reason" }),
      vector("sample/reject-duplicate", { verdict: "reject", reason_code: "used_reason" }),
    ]);

    expect(findDeadVocabularyFailures(input)).toEqual([
      "unused_reason",
    ]);
  });

  it("does not count a reason carried only by an accepting vector as used", () => {
    const input = corpus([
      vector("sample/accept", { verdict: "accept", reason_code: "unused_reason" }),
      vector("sample/reject", { verdict: "reject", reason_code: "used_reason" }),
    ]);

    expect(findDeadVocabularyFailures(input)).toEqual(["unused_reason"]);
  });
});
