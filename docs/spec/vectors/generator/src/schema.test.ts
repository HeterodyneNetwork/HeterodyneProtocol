import { describe, expect, it } from "vitest";
import { validateVectorOrThrow } from "./schema.js";

describe("vector schema", () => {
  it("accepts the qualified family vector envelope", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "identity/root-attestation-valid",
        vector_schema_version: "1.0.0",
        owner_document: "core",
        owner_version: "core/0.5.0",
        dependency_versions: {},
        registry_revision: 1,
        spec_refs: [
          "heterodyne:core/0.5.0#core-root-attestation",
          "heterodyne:core/0.5.0#core-conformance",
        ],
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

  it("rejects the removed scalar spec_version and bare references", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "legacy/scalar-version",
        vector_schema_version: "1.0.0",
        spec_version: "0.4.0",
        owner_document: "core",
        owner_version: "core/0.5.0",
        dependency_versions: {},
        registry_revision: 1,
        spec_refs: ["§3"],
        description: "legacy metadata is invalid after the family split",
        direction: "consume",
        input: {},
        expected_output: { verdict: "accept" },
      }),
    ).toThrow();
  });

  it("rejects forbidden and unqualified dependency versions", () => {
    const vector = {
      vector_id: "versioning/forbidden-dependency",
      vector_schema_version: "1.0.0",
      owner_document: "core",
      owner_version: "core/0.5.0",
      dependency_versions: { social: "social/0.5.0" },
      registry_revision: 1,
      spec_refs: ["heterodyne:core/0.5.0#core-versioning"],
      description: "Core cannot depend on Social",
      direction: "consume",
      input: {},
      expected_output: { verdict: "accept" },
    };
    expect(() => validateVectorOrThrow(vector)).toThrow(/dependency/);
    expect(() =>
      validateVectorOrThrow({
        ...vector,
        owner_document: "comms",
        owner_version: "comms/0.5.0",
        dependency_versions: { core: "0.5.0" },
        spec_refs: ["heterodyne:comms/0.5.0#comms-conformance"],
      }),
    ).toThrow(/dependency/);
  });

  it("rejects null for the optional profile field", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "stamping/null-profile",
        vector_schema_version: "1.0.0",
        owner_document: "core",
        owner_version: "core/0.5.0",
        dependency_versions: {},
        registry_revision: 1,
        profile: null,
        spec_refs: ["heterodyne:core/0.5.0#core-version-stamps"],
        description: "optional means absent, not null",
        direction: "round-trip",
        input: {},
        expected_output: {},
      }),
    ).toThrow();
  });

  it("requires reason_code on consume rejects", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "verification/bad-sig-rejects",
        vector_schema_version: "1.0.0",
        owner_document: "core",
        owner_version: "core/0.5.0",
        dependency_versions: {},
        registry_revision: 1,
        spec_refs: ["heterodyne:core/0.5.0#core-verification"],
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
