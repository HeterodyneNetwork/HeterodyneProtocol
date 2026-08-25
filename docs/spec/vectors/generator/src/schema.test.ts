import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema } from "ajv";
import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_CONTINUITY_SCHEMA_FILES,
  CREDENTIAL_CONTINUITY_SCHEMAS,
  KEY_CLAIM_REVOCATION_SCHEMA,
  KEY_CLAIM_SCHEMA,
  VECTOR_SCHEMA,
  validateClaimRevocationSchemaOrThrow,
  validateCredentialContinuitySchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
  validateOneTimeInviteResponseSchemaOrThrow,
  validateOneTimeInviteSchemaOrThrow,
  validateVectorOrThrow,
} from "./schema.js";

const assuranceSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/assurance",
);

function validateAssuranceSchema(name: string, value: unknown): string | null {
  const schema = JSON.parse(
    readFileSync(resolve(assuranceSchemasRoot, name), "utf8"),
  ) as AnySchema;
  const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

const h = (byte: string) => byte.repeat(64);
const sig = (byte: string) => byte.repeat(128);

const assuranceInception = {
  profile: "heterodyne.assurance.enrollment-inception.v1",
  spec_version: "heterodyne/0.5.0",
  active_key: h("1"),
  created_at: 1_785_000_000,
  predecessor: null,
  cold_root: h("2"),
  succession_authority: h("3"),
  epoch_policy: {
    mode: "pre-rotation",
    current_keys: [h("4")],
    next_key_commitments: [h("5")],
  },
  witnesses: [{ key: h("6"), weight: 1 }],
  thresholds: { epoch: 1, witness: 1 },
  associated_key_policy: {
    active_key: [{
      role: "agent",
      scope: ["nostr:kind:1", "nostr:kind:6"],
    }],
    epoch_threshold: [{
      role: "agent",
      scope: ["nostr:kind:1"],
    }],
  },
};

const assuranceAcceptance = {
  profile: "heterodyne.assurance.active-key-acceptance.v1",
  spec_version: "heterodyne/0.5.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 1,
  predecessor: h("7"),
  inception_event_id: h("7"),
  cold_root: assuranceInception.cold_root,
  cold_root_signature: sig("8"),
  assurance_head: h("7"),
  state: "assured",
};

const assuranceSuccession = {
  profile: "heterodyne.assurance.succession.v1",
  spec_version: "heterodyne/0.5.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 2,
  predecessor: h("7"),
  previous_active_key: assuranceInception.active_key,
  previous_head: h("7"),
  new_active_key: h("9"),
  authorizing_evidence: {
    authority_class: "succession",
    authority_proofs: [{
      authority_key: assuranceInception.succession_authority,
      signature: sig("a"),
    }],
    witness_receipts: [{ witness_key: h("6"), signature: sig("b") }],
  },
  new_key_acceptance: { key: h("9"), signature: sig("c") },
  class: "routine",
  next_succession_authority: h("b"),
  next_epoch_policy: {
    mode: "pre-rotation",
    current_keys: [h("9")],
    next_key_commitments: [h("a")],
  },
  witnesses: [{ key: h("6"), weight: 1 }],
  thresholds: { epoch: 1, witness: 1 },
  next_associated_key_policy: assuranceInception.associated_key_policy,
  subordinate_reauthorizations: [{
    role: "agent",
    subject_key: h("d"),
    scope: ["nostr:kind:1"],
    expires_at: assuranceInception.created_at + 3_600,
  }],
};

const assuranceAssociatedKey = {
  profile: "heterodyne.assurance.associated-key.v1",
  spec_version: "heterodyne/0.5.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 3,
  predecessor: h("e"),
  assurance_head: h("7"),
  role: "agent",
  scope: ["nostr:kind:1"],
  issuer: assuranceInception.active_key,
  issuer_authority: {
    class: "active-key",
    authority_proofs: [],
  },
  subject_key: h("f"),
  expires_at: assuranceInception.created_at + 3_600,
  visibility: "public",
  subject_proof: sig("0"),
  state: "active",
};

describe("Assurance record schemas", () => {
  const fixtures = [
    ["enrollment-inception-v1.schema.json", assuranceInception],
    ["active-key-acceptance-v1.schema.json", assuranceAcceptance],
    ["succession-v1.schema.json", assuranceSuccession],
    ["associated-key-v1.schema.json", assuranceAssociatedKey],
  ] as const;

  it.each(fixtures)("accepts the exact closed %s record", (name, value) => {
    expect(validateAssuranceSchema(name, value)).toBeNull();
    expect(validateAssuranceSchema(name, { ...value, unbound_authority: true }))
      .toMatch(/additionalProperties/);
  });

  it("requires reciprocal enrollment and recovery-authority downgrade consent", () => {
    const { associated_key_policy: _policy, ...withoutIssuancePolicy } = assuranceInception;
    expect(validateAssuranceSchema(
      "enrollment-inception-v1.schema.json",
      withoutIssuancePolicy,
    )).toMatch(/associated_key_policy|required/);
    expect(validateAssuranceSchema(
      "enrollment-inception-v1.schema.json",
      { ...assuranceInception, predecessor: h("7") },
    )).toMatch(/predecessor|type/);
    const { cold_root_signature: _signature, ...withoutColdRootSignature } = assuranceAcceptance;
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      withoutColdRootSignature,
    )).toMatch(/cold_root_signature|required/);
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      { ...assuranceAcceptance, state: "downgraded" },
    )).toMatch(/downgrade_consent|required/);
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      {
        ...assuranceAcceptance,
        state: "downgraded",
        downgrade_consent: {
          recovery_authority: assuranceInception.cold_root,
          signature: sig("1"),
        },
      },
    )).toBeNull();
  });

  it("binds succession to the prior head and closes compromise continuations", () => {
    const {
      next_associated_key_policy: _policy,
      ...withoutNextIssuancePolicy
    } = assuranceSuccession;
    expect(validateAssuranceSchema(
      "succession-v1.schema.json",
      withoutNextIssuancePolicy,
    )).toMatch(/next_associated_key_policy|required/);
    const {
      next_succession_authority: _authority,
      ...withoutNextSuccessionAuthority
    } = assuranceSuccession;
    expect(validateAssuranceSchema(
      "succession-v1.schema.json",
      withoutNextSuccessionAuthority,
    )).toMatch(/next_succession_authority|required/);
    const { previous_head: _head, ...withoutHead } = assuranceSuccession;
    expect(validateAssuranceSchema("succession-v1.schema.json", withoutHead))
      .toMatch(/previous_head|required/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "routine",
      compromise_time: assuranceSuccession.created_at - 60,
    })).toMatch(/compromise_time|not/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      subordinate_reauthorizations: [],
    })).toMatch(/compromise_time|required/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      compromise_time: assuranceSuccession.created_at - 60,
    })).toMatch(/subordinate_reauthorizations|maxItems/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      compromise_time: assuranceSuccession.created_at - 60,
      subordinate_reauthorizations: [],
      authorizing_evidence: {
        ...assuranceSuccession.authorizing_evidence,
        authority_class: "recovery",
      },
    })).toBeNull();
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      authorizing_evidence: {
        ...assuranceSuccession.authorizing_evidence,
        authority_class: "recovery",
      },
    })).toMatch(/authority_class|enum/);
  });

  it("requires subject proof only for active public-agent grants", () => {
    const { subject_proof: _proof, ...withoutSubjectProof } = assuranceAssociatedKey;
    expect(validateAssuranceSchema("associated-key-v1.schema.json", withoutSubjectProof))
      .toMatch(/subject_proof|required/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...withoutSubjectProof,
      visibility: "private",
    })).toBeNull();
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
    })).toMatch(/revocation|required/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...withoutSubjectProof,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
      },
    })).toBeNull();
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
      },
    })).toMatch(/subject_proof|not/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
        continue_authority: true,
      },
    })).toMatch(/additionalProperties/);
  });
});

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

  it("requires context for persona resolution and every later terminal stage", () => {
    const baseCheck = {
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
    };
    for (const expected_terminal_stage of [
      "persona_resolution",
      "version_stamp",
      "kel_head",
      "epoch_authority",
      "subtype_nid",
      "accept",
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("core"),
        vector_schema_version: "1.1.0",
        conformance_checks: [{ ...baseCheck, expected_terminal_stage }],
      })).toThrow(/context_pointer|required/);
      expect(() => validateVectorOrThrow({
        ...valid("core"),
        vector_schema_version: "1.1.0",
        conformance_checks: [{
          ...baseCheck,
          context_pointer: "/input/context",
          expected_terminal_stage,
        }],
      })).not.toThrow();
    }
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

  it("keeps the generator schema as the draft raw-authoring contract", () => {
    expect(VECTOR_SCHEMA.required).toContain("spec_version");
    expect((VECTOR_SCHEMA.properties.vector_schema_version as { pattern: string }).pattern)
      .toBe("^\\d+\\.\\d+\\.\\d+$");
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
