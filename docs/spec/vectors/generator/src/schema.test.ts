import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_CONTINUITY_SCHEMA_FILES,
  CREDENTIAL_CONTINUITY_SCHEMAS,
  KEY_CLAIM_REVOCATION_SCHEMA,
  KEY_CLAIM_SCHEMA,
  validateClaimRevocationSchemaOrThrow,
  validateCredentialContinuitySchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
  validateOneTimeInviteResponseSchemaOrThrow,
  validateOneTimeInviteSchemaOrThrow,
  validateVectorOrThrow,
} from "./schema.js";

describe("claim profile revision schema documentation", () => {
  it("names the frozen profile revision without registry-revision or duplicated terminology", () => {
    for (const schema of [KEY_CLAIM_SCHEMA, KEY_CLAIM_REVOCATION_SCHEMA]) {
      const description = (schema as {
        properties: { profile_revision: { description: string } };
      }).properties.profile_revision.description;
      expect(description).toMatch(/profile revision/i);
      expect(description).not.toMatch(/profile_profile_revision|profile registry revision/i);
    }
  });
});

describe("one-time invite schemas", () => {
  const descriptor = {
    version: 1,
    purpose: "dm",
    inviter_account: "11".repeat(32),
    invite_id: "22".repeat(32),
    rendezvous_pubkey: "33".repeat(32),
    relay_hints: ["wss://relay.example"],
    issued_at: 1_000,
    expires_at: 2_000,
    secret_sha256: "44".repeat(32),
    approval_mode: "interactive",
  };

  it("accepts closed invite and response shapes", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor,
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).not.toThrow();
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.5.0",
      purpose: "dm",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: ["chat"],
      proof: "99".repeat(32),
    })).not.toThrow();
  });

  it("rejects extra authority and private-key members", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor,
      signature: "55".repeat(64),
      secret: "66".repeat(32),
      device_private_key: "77".repeat(32),
    })).toThrow(/additional/);
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.5.0",
      purpose: "dm",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: [],
      proof: "99".repeat(32),
      mls_leaf_private_key: "aa".repeat(32),
    })).toThrow(/additional/);
  });

  it("enforces purpose-specific authority and preauthorization", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor: { ...descriptor, purpose: "device-enrollment" },
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).toThrow();
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor: { ...descriptor, approval_mode: "preauthorized" },
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).toThrow();
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.5.0",
      purpose: "device-enrollment",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: [],
      proof: "99".repeat(32),
    })).toThrow();
  });
});

describe("vector schema", () => {
  const valid = (owner: "core" | "comms" | "social" | "control") => ({
    vector_id: `versioning/${owner}-metadata`,
    vector_schema_version: "1.0.0",
    owner_document: owner,
    spec_version: "heterodyne/0.5.0",
    spec_refs: [`heterodyne:0.5.0#${owner}-conformance`],
    description: "exact family metadata",
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  });

  it("accepts only the closed Core signed-event checker declaration", () => {
    const check = {
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
      expected_terminal_stage: "signature",
    };
    expect(() => validateVectorOrThrow({
      ...valid("core"), vector_schema_version: "1.1.0", conformance_checks: [check],
    })).not.toThrow();
    for (const invalid of [
      { ...check, profile: "generator-v1" },
      { ...check, event_pointer: "input/event" },
      { ...check, inferred: true },
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("core"), vector_schema_version: "1.1.0", conformance_checks: [invalid],
      })).toThrow();
    }
    expect(() => validateVectorOrThrow({
      ...valid("core"), vector_schema_version: "1.1.0", conformance_checks: [check, check],
    })).toThrow();
  });

  it("accepts the qualified family vector envelope", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "identity/root-attestation-valid",
        vector_schema_version: "1.0.0",
        owner_document: "core",
        spec_version: "heterodyne/0.5.0",
        spec_refs: ["heterodyne:0.5.0#core-root-attestation"],
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

  it("rejects an unqualified version and a bare section reference", () => {
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_version: "0.5.0" }))
      .toThrow();
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_refs: ["§3"] }))
      .toThrow();
  });

  it.each(["core", "comms", "social", "control"] as const)(
    "accepts the exact %s runtime metadata",
    (owner) => expect(() => validateVectorOrThrow(valid(owner))).not.toThrow(),
  );

  it("rejects a version other than the current family release", () => {
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_version: "heterodyne/0.5.1" }))
      .toThrow();
    expect(() => validateVectorOrThrow({
      ...valid("core"), spec_refs: ["heterodyne:0.4.0#core-conformance"],
    })).toThrow();
  });

  it("rejects references above the owner in the layering", () => {
    expect(() => validateVectorOrThrow({
      ...valid("social"), spec_refs: ["heterodyne:0.5.0#control-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("comms"), spec_refs: ["heterodyne:0.5.0#social-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("core"), spec_refs: ["heterodyne:0.5.0#comms-conformance"],
    })).toThrow(/spec_ref/);
  });

  it("requires exactly one qualified permanent spec reference", () => {
    expect(() => validateVectorOrThrow({
      ...valid("core"),
      spec_refs: [
        "heterodyne:0.5.0#core-versioning",
        "heterodyne:0.5.0#core-conformance",
      ],
    })).toThrow(/spec_refs|one|item/i);
  });

  it("allows one Control reference to either document beneath it", () => {
    for (const specRef of [
      "heterodyne:0.5.0#core-version-stamps",
      "heterodyne:0.5.0#comms-subprotocol-negotiation",
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
        owner_version: "heterodyne/0.5.0",
        dependency_versions: {},
        profile_revision: 1,
        profile: null,
        spec_refs: ["heterodyne:0.5.0#core-version-stamps"],
        description: "optional means absent, not null",
        direction: "round-trip",
        input: {},
        expected_output: {},
      }),
    ).toThrow();
  });

  it.each(["consume", "produce", "round-trip"] as const)(
    "requires reason_code on %s rejects",
    (direction) => expect(() => validateVectorOrThrow({
      ...valid("core"),
      direction,
      expected_output: { verdict: "reject" },
    })).toThrow(/reason_code/),
  );
});

describe("credential-continuity schema registry", () => {
  it("loads the seventeen transport-independent Comms schemas", () => {
    expect(CREDENTIAL_CONTINUITY_SCHEMA_FILES).toHaveLength(17);
    for (const file of CREDENTIAL_CONTINUITY_SCHEMA_FILES) {
      expect(CREDENTIAL_CONTINUITY_SCHEMAS[file]).toMatchObject({
        $schema: "http://json-schema.org/draft-07/schema#",
        $id: `https://heterodyne.network/schemas/comms/${file}`,
      });
      expect(() =>
        validateCredentialContinuitySchemaOrThrow(file, {}),
      ).toThrow(/credential-continuity-schema-invalid/);
    }
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
    spec_version: "heterodyne/0.5.0",
    profile_revision: 2,
    credential_ledger_persona: "34".repeat(32),
    credential_ledger_generation: 0,
  };

  it("accepts exact claims and rejects extra properties", () => {
    expect(() => validateKeyClaimSchemaOrThrow(base)).not.toThrow();
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, extra: true })).toThrow(/additional/);
    const { spec_version: _version, ...missingVersion } = base;
    expect(() => validateKeyClaimSchemaOrThrow(missingVersion)).toThrow(/spec_version|required/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...missingVersion,
      comms_version: "heterodyne/0.5.0",
    })).toThrow(/spec_version|required|additional/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...base,
      spec_version: "heterodyne/0.5.1",
    })).toThrow(/spec_version|const/);
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
      spec_version: "heterodyne/0.5.0",
      profile_revision: 2,
    };
    expect(() => validateClaimRevocationSchemaOrThrow(revocation)).not.toThrow();
    const { spec_version: _version, ...missingVersion } = revocation;
    const { profile_revision: _revision, ...missingRevision } = revocation;
    expect(() => validateClaimRevocationSchemaOrThrow(missingVersion)).toThrow(/spec_version|required/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...missingVersion,
      comms_version: "heterodyne/0.5.0",
    })).toThrow(/spec_version|required|additional/);
    expect(() => validateClaimRevocationSchemaOrThrow(missingRevision)).toThrow(/profile_revision|required/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, spec_version: "heterodyne/0.5.1" })).toThrow(/spec_version|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, profile_revision: 1 })).toThrow(/profile_revision|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, reason_code: "not-registered" })).toThrow(/reason_code/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, extra: true })).toThrow(/additional/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, revoked_at: Number.NEGATIVE_INFINITY })).toThrow();
  });

  it("closes embedded public JWK profiles at the revocation schema boundary", () => {
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(43),
      alg: "EdDSA",
      use: "sig",
      key_ops: ["verify"],
      kid: "B".repeat(43),
    };
    const revocation = {
      claim_id: base.claim_id,
      revoked_at: 1784390500,
      reason_code: "claim-revoked",
      revoker: { type: "jwk-thumbprint", value: "B".repeat(43) },
      spec_version: "heterodyne/0.5.0",
      profile_revision: 2,
      proof: {
        type: "jwk-jws",
        jwk,
        protected: "AA",
        signature: "AA",
      },
    };
    expect(() => validateClaimRevocationSchemaOrThrow(revocation)).not.toThrow();
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, arbitrary: true } },
    })).toThrow(/additional|oneOf/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, alg: "RS256" } },
    })).toThrow(/alg|const|oneOf/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, d: "A".repeat(43) } },
    })).toThrow(/additional|oneOf/);
  });
});
