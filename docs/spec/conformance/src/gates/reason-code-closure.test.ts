import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findReasonCodeClosureFailures } from "./reason-code-closure.js";

function vector(
  vector_id: string,
  direction: VectorDocument["direction"],
  expected_output: Record<string, unknown>,
): VectorDocument {
  return {
    vector_id,
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: [],
    direction,
    input: {},
    expected_output,
  };
}

function corpus(vectors: VectorDocument[]): ArtifactCorpus {
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: "aa".repeat(32),
    specifications: new Map(),
    schemas: new Map(),
    vectors: vectors.map((value) => ({ path: `${value.vector_id}.json`, value })),
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: "aa".repeat(32) },
      reason_codes: [{ code: "registered" }],
      security_invariants: [],
    },
  };
}

describe("findReasonCodeClosureFailures", () => {
  it("reports an exact stable key for an unregistered rejection reason", () => {
    const input = corpus([
      vector("sample/registered-produce", "produce", { verdict: "reject", reason_code: "registered" }),
      vector("sample/registered-round-trip", "round-trip", { verdict: "reject", reason_code: "registered" }),
      vector("sample/unregistered", "consume", { verdict: "reject", reason_code: "not_registered" }),
      vector("sample/accepted", "consume", { verdict: "accept", reason_code: "not_registered" }),
    ]);

    expect(findReasonCodeClosureFailures(input)).toEqual([
      "sample/unregistered :: not_registered",
    ]);
  });

  it("uses the stable missing marker when a rejecting vector has no reason code", () => {
    const input = corpus([
      vector("sample/missing", "round-trip", { verdict: "reject" }),
    ]);

    expect(findReasonCodeClosureFailures(input)).toEqual([
      "sample/missing :: <missing>",
    ]);
  });

  it("checks rejecting produce and round-trip vectors", () => {
    const input = corpus([
      vector("sample/produce", "produce", { verdict: "reject", reason_code: "produce_unregistered" }),
      vector("sample/round-trip", "round-trip", { verdict: "reject", reason_code: "round_trip_unregistered" }),
    ]);

    expect(findReasonCodeClosureFailures(input)).toEqual([
      "sample/produce :: produce_unregistered",
      "sample/round-trip :: round_trip_unregistered",
    ]);
  });
});
