import { describe, expect, it } from "vitest";
import { validateVectorOrThrow } from "./schema.js";

describe("vector schema", () => {
  const valid = (owner: "core" | "comms" | "social" | "control") => ({
    vector_id: `versioning/${owner}-metadata`,
    vector_schema_version: "1.0.0",
    owner_document: owner,
    owner_version: `${owner}/0.5.0`,
    dependency_versions: owner === "core" ? {} : owner === "comms"
      ? { core: "core/0.5.0" }
      : owner === "social"
        ? { core: "core/0.5.0", comms: "comms/0.5.0" }
        : { comms: "comms/0.5.0" },
    registry_revision: 1,
    spec_refs: [`heterodyne:${owner}/0.5.0#${owner}-conformance`],
    description: "exact family metadata",
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  });

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

  it.each(["core", "comms", "social", "control"] as const)(
    "accepts the exact %s runtime metadata",
    (owner) => expect(() => validateVectorOrThrow(valid(owner))).not.toThrow(),
  );

  it("rejects missing, extra, or wrong exact dependencies and owner versions", () => {
    expect(() => validateVectorOrThrow({ ...valid("comms"), dependency_versions: {} }))
      .toThrow(/dependency/);
    expect(() => validateVectorOrThrow({
      ...valid("control"), dependency_versions: { comms: "comms/0.5.0", core: "core/0.5.0" },
    })).toThrow(/dependency/);
    expect(() => validateVectorOrThrow({
      ...valid("social"), dependency_versions: { core: "core/0.5.0", comms: "comms/0.4.0" },
    })).toThrow(/dependency/);
    expect(() => validateVectorOrThrow({ ...valid("core"), owner_version: "core/0.5.1" }))
      .toThrow(/owner_version/);
  });

  it("rejects references outside the owner and its declared dependencies", () => {
    expect(() => validateVectorOrThrow({
      ...valid("social"), spec_refs: ["heterodyne:control/0.5.0#control-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("comms"), spec_refs: ["heterodyne:social/0.5.0#social-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("social"), spec_refs: ["heterodyne:core/0.4.0#core-conformance"],
    })).toThrow(/spec_ref/);
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
