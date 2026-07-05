import { describe, expect, it } from "vitest";
import { validateVectorOrThrow } from "./schema.js";

describe("vector schema", () => {
  it("accepts the ADR-024 vector envelope", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "identity/root-attestation-valid",
        vector_schema_version: "1.0.0",
        spec_version: "0.4.0",
        spec_refs: ["§3", "§14.5"],
        description: "root attestation is reproduced byte-identically",
        direction: "produce",
        input: { hello: "world" },
        expected_output: {
          canonical_wire: "[0,...]",
          decoded: {},
        },
      }),
    ).not.toThrow();
  });

  it("requires reason_code on consume rejects", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "verification/bad-sig-rejects",
        vector_schema_version: "1.0.0",
        spec_version: "0.4.0",
        spec_refs: ["§4.5", "§14.5"],
        description: "bad signature rejects",
        direction: "consume",
        input: { event: {} },
        expected_output: {
          verdict: "reject",
        },
      }),
    ).toThrow(/reason_code/);
  });
});
