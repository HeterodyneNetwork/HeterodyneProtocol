import { describe, expect, it } from "vitest";
import {
  validateClaimRevocationSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
  validateVectorOrThrow,
} from "./schema.js";

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
        : { core: "core/0.5.0", comms: "comms/0.5.0" },
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
        spec_refs: ["heterodyne:core/0.5.0#core-root-attestation"],
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
      ...valid("control"), dependency_versions: { comms: "comms/0.5.0" },
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

  it("requires exactly one qualified permanent spec reference", () => {
    expect(() => validateVectorOrThrow({
      ...valid("core"),
      spec_refs: [
        "heterodyne:core/0.5.0#core-versioning",
        "heterodyne:core/0.5.0#core-conformance",
      ],
    })).toThrow(/spec_refs|one|item/i);
  });

  it("allows one Control reference to either exact direct dependency", () => {
    for (const specRef of [
      "heterodyne:core/0.5.0#core-version-stamps",
      "heterodyne:comms/0.5.0#comms-subprotocol-negotiation",
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("control"),
        spec_refs: [specRef],
      })).not.toThrow();
    }
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

describe("Comms claim schemas", () => {
  const key = { type: "nostr-secp256k1", value: "12".repeat(32) };
  const base = {
    claim_id: "ab".repeat(32),
    issuer: key,
    subject: { type: "radicle-ed25519-nid", value: "did:key:z6MkhM7qBMzbpZbpQeMVQW1H4KAKz7GgzGzHwGKYvEyt84qC" },
    claim_class: "authorization",
    namespace: "heterodyne.device",
    name: "claim-ledger-reader",
    value: true,
    issued_at: 1784390400,
    not_before: 1784390400,
    expires_at: 1784476800,
    visibility: "repository-private",
    comms_version: "comms/0.5.0",
    registry_revision: 2,
  };

  it("accepts exact claims and rejects extra properties", () => {
    expect(() => validateKeyClaimSchemaOrThrow(base)).not.toThrow();
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, extra: true })).toThrow(/additional/);
  });

  it("requires bounded authorization expiry and caps delegation depth at eight", () => {
    const { expires_at: _, ...withoutExpiry } = base;
    expect(() => validateKeyClaimSchemaOrThrow(withoutExpiry)).toThrow(/expires_at/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...base,
      constraints: { namespaces: [], audiences: [], resources: [], remaining_depth: 9 },
    })).toThrow(/remaining_depth|8/);
  });

  it("enforces time ordering beyond structural JSON Schema", () => {
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, not_before: base.issued_at - 1 })).toThrow(/not_before/);
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, expires_at: base.not_before - 1 })).toThrow(/expires_at/);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects non-finite numeric fields through the direct claim API: %s",
    (value) => expect(() => validateKeyClaimSchemaOrThrow({ ...base, issued_at: value })).toThrow(),
  );

  it("rejects non-finite values recursively through the direct claim API", () => {
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, value: { nested: [Number.NaN] } })).toThrow(/finite|JCS|number/);
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, value: [Number.POSITIVE_INFINITY] })).toThrow(/finite|JCS|number/);
  });

  it("accepts exact revocations and rejects unregistered reasons and extras", () => {
    const revocation = {
      claim_id: base.claim_id,
      revoked_at: 1784390500,
      reason_code: "claim-revoked",
      revoker: key,
      comms_version: "comms/0.5.0",
      registry_revision: 2,
    };
    expect(() => validateClaimRevocationSchemaOrThrow(revocation)).not.toThrow();
    const { comms_version: _version, ...missingVersion } = revocation;
    const { registry_revision: _revision, ...missingRevision } = revocation;
    expect(() => validateClaimRevocationSchemaOrThrow(missingVersion)).toThrow(/comms_version|required/);
    expect(() => validateClaimRevocationSchemaOrThrow(missingRevision)).toThrow(/registry_revision|required/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, comms_version: "comms/0.5.1" })).toThrow(/comms_version|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, registry_revision: 1 })).toThrow(/registry_revision|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, reason_code: "not-registered" })).toThrow(/reason_code/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, extra: true })).toThrow(/additional/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, revoked_at: Number.NEGATIVE_INFINITY })).toThrow();
  });
});
