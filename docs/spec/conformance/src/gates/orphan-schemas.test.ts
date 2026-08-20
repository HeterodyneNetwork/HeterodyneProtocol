import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, VectorDocument } from "../types.js";
import { findOrphanSchemaFailures } from "./orphan-schemas.js";

function vector(input: Record<string, unknown>): VectorDocument {
  return {
    vector_id: "sample/schema-binding",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: [],
    direction: "consume",
    input,
    expected_output: { verdict: "accept" },
  };
}

function corpus(
  specification: string,
  vectorInput: Record<string, unknown>,
): ArtifactCorpus {
  const digest = "aa".repeat(32);
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: digest,
    specifications: new Map([["docs/spec/heterodyne-core.md", specification]]),
    schemas: new Map([
      ["docs/spec/schemas/core/prose-bound-v1.schema.json", {}],
      ["docs/spec/schemas/core/vector-bound-v1.schema.json", {}],
      ["docs/spec/schemas/core/orphan-v1.schema.json", {}],
    ]),
    vectors: [{ path: "docs/spec/vectors/sample/schema-binding.json", value: vector(vectorInput) }],
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: digest },
      reason_codes: [],
      security_invariants: [],
    },
  };
}

describe("findOrphanSchemaFailures", () => {
  it("reports schemas absent as full paths from prose and vector values", () => {
    const input = corpus(
      "See [the schema](docs/spec/schemas/core/prose-bound-v1.schema.json).",
      { schema_path: "docs/spec/schemas/core/vector-bound-v1.schema.json" },
    );

    expect(findOrphanSchemaFailures(input)).toEqual([
      "docs/spec/schemas/core/orphan-v1.schema.json",
    ]);
  });

  it("does not accept basename-only prose or vector references", () => {
    const input = corpus(
      "The schemas are prose-bound-v1.schema.json and orphan-v1.schema.json.",
      {
        schema_path: "vector-bound-v1.schema.json",
        nested: ["orphan-v1.schema.json"],
      },
    );

    expect(findOrphanSchemaFailures(input)).toEqual([
      "docs/spec/schemas/core/orphan-v1.schema.json",
      "docs/spec/schemas/core/prose-bound-v1.schema.json",
      "docs/spec/schemas/core/vector-bound-v1.schema.json",
    ]);
  });
});
