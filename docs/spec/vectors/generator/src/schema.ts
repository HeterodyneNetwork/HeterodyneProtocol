import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema, type ErrorObject, type JSONSchemaType } from "ajv";
import { reasonCodeValues } from "./reason-codes.js";
import { parseQualifiedVersion } from "./family.js";
import { jcsCanonicalize } from "./jcs.js";
import type { DocumentId, Vector } from "./types.js";

const REGISTRY_REASON_CODES = reasonCodeValues();

export const VECTOR_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "vector_id",
    "vector_schema_version",
    "owner_document",
    "owner_version",
    "dependency_versions",
    "registry_revision",
    "spec_refs",
    "description",
    "direction",
    "input",
    "expected_output",
  ],
  properties: {
    vector_id: { type: "string", minLength: 1 },
    vector_schema_version: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+$" },
    owner_document: { type: "string", enum: ["core", "comms", "control", "social"] },
    owner_version: {
      type: "string",
      enum: ["core/0.5.0", "comms/0.5.0", "control/0.5.0", "social/0.5.0"],
    },
    dependency_versions: {
      type: "object",
      required: [],
      additionalProperties: false,
      properties: {
        core: { type: "string", const: "core/0.5.0" },
        comms: { type: "string", const: "comms/0.5.0" },
        control: { type: "string", const: "control/0.5.0" },
        social: { type: "string", const: "social/0.5.0" },
      },
    },
    registry_revision: { type: "integer", minimum: 1 },
    profile: { type: "string", minLength: 1 },
    spec_refs: {
      type: "array",
      minItems: 1,
      maxItems: 1,
      items: {
        type: "string",
        pattern: "^heterodyne:(core|comms|control|social)/0\\.5\\.0#[a-z0-9]+(?:-[a-z0-9]+)*$",
      },
    },
    description: { type: "string", minLength: 1 },
    direction: { type: "string", enum: ["produce", "consume", "round-trip"] },
    input: { type: "object", additionalProperties: true, required: [] },
    expected_output: { type: "object", additionalProperties: true, required: [] },
  },
  allOf: [
    ...([
      ["core", "core/0.5.0", {}],
      ["comms", "comms/0.5.0", { core: "core/0.5.0" }],
      ["social", "social/0.5.0", { core: "core/0.5.0", comms: "comms/0.5.0" }],
      ["control", "control/0.5.0", { core: "core/0.5.0", comms: "comms/0.5.0" }],
    ] as const).map(([owner, ownerVersion, dependencies]) => ({
      if: { properties: { owner_document: { const: owner } }, required: ["owner_document"] },
      then: {
        properties: {
          owner_version: { const: ownerVersion },
          dependency_versions: { const: dependencies },
        },
      },
    })),
    {
      if: {
        properties: {
          direction: { const: "consume" },
          expected_output: {
            type: "object",
            properties: {
              verdict: { const: "reject" },
            },
            required: ["verdict"],
          },
        },
        required: ["direction", "expected_output"],
      },
      then: {
        properties: {
          expected_output: {
            type: "object",
            required: ["verdict", "reason_code"],
            properties: {
              verdict: { const: "reject" },
              reason_code: { type: "string", enum: REGISTRY_REASON_CODES },
            },
            additionalProperties: true,
          },
        },
      },
    },
  ],
} as unknown as JSONSchemaType<Vector>;

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(VECTOR_SCHEMA);

const schemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/comms",
);
const controlSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/control",
);

function readSchema(name: string): AnySchema {
  return JSON.parse(readFileSync(resolve(schemasRoot, name), "utf8")) as AnySchema;
}

function readControlSchema(name: string): AnySchema {
  return JSON.parse(
    readFileSync(resolve(controlSchemasRoot, name), "utf8"),
  ) as AnySchema;
}

export const KEY_CLAIM_SCHEMA = readSchema("key-claim-v1.schema.json");
export const KEY_CLAIM_REVOCATION_SCHEMA = readSchema("key-claim-revocation-v1.schema.json");
export const CLAIM_LEDGER_RECORD_SCHEMA = readSchema("claim-ledger-record-v1.schema.json");
export const OIDC_ISSUANCE_RECORD_SCHEMA = readSchema("oidc-issuance-record-v1.schema.json");
export const OIDC_ISSUER_METADATA_SCHEMA = readSchema("oidc-issuer-metadata-v1.schema.json");
export const OIDC_CONTINUITY_MANIFEST_SCHEMA = readSchema("oidc-continuity-manifest-v1.schema.json");
export const CONTROL_GRANT_SCHEMA = readControlSchema("control-grant-v1.schema.json");
export const CONTROL_ENROLLMENT_REQUEST_SCHEMA = readControlSchema("control-enrollment-request-v1.schema.json");
export const CONTROL_ENROLLMENT_TOKEN_SCHEMA = readControlSchema("control-enrollment-token-v1.schema.json");
export const CONTROL_CAPABILITY_SET_SCHEMA = readControlSchema("control-capability-set-v1.schema.json");
export const CONTROL_MCP_FRAME_SCHEMA = readControlSchema("control-mcp-frame-v1.schema.json");
export const CONTROL_RPC_REQUEST_SCHEMA = readControlSchema("control-rpc-request-v1.schema.json");
export const CONTROL_RPC_RESPONSE_SCHEMA = readControlSchema("control-rpc-response-v1.schema.json");

const commsSchemaAjv = new Ajv({ allErrors: true, strict: false });
commsSchemaAjv.addSchema(KEY_CLAIM_SCHEMA);
commsSchemaAjv.addSchema(KEY_CLAIM_REVOCATION_SCHEMA);
commsSchemaAjv.addSchema(OIDC_ISSUANCE_RECORD_SCHEMA);
const validateKeyClaim = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/key-claim-v1.schema.json")!;
const validateClaimRevocation = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/key-claim-revocation-v1.schema.json")!;
const validateClaimLedgerRecord = commsSchemaAjv.compile(CLAIM_LEDGER_RECORD_SCHEMA);
const validateOidcIssuanceRecord = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/oidc-issuance-record-v1.schema.json")!;
const validateOidcIssuerMetadata = commsSchemaAjv.compile(OIDC_ISSUER_METADATA_SCHEMA);
const validateOidcContinuityManifest = commsSchemaAjv.compile(OIDC_CONTINUITY_MANIFEST_SCHEMA);

const controlSchemaAjv = new Ajv({ allErrors: true, strict: false });
controlSchemaAjv.addSchema(CONTROL_GRANT_SCHEMA);
controlSchemaAjv.addSchema(CONTROL_CAPABILITY_SET_SCHEMA);
const validateControlGrant = controlSchemaAjv.getSchema(
  "https://heterodyne.network/schemas/control/control-grant-v1.schema.json",
)!;
const validateControlCapabilitySet = controlSchemaAjv.getSchema(
  "https://heterodyne.network/schemas/control/control-capability-set-v1.schema.json",
)!;
const validateControlEnrollmentRequest = controlSchemaAjv.compile(
  CONTROL_ENROLLMENT_REQUEST_SCHEMA,
);
const validateControlEnrollmentToken = controlSchemaAjv.compile(
  CONTROL_ENROLLMENT_TOKEN_SCHEMA,
);
const validateControlMcpFrame = controlSchemaAjv.compile(
  CONTROL_MCP_FRAME_SCHEMA,
);
const validateControlRpcRequest = controlSchemaAjv.compile(
  CONTROL_RPC_REQUEST_SCHEMA,
);
const validateControlRpcResponse = controlSchemaAjv.compile(
  CONTROL_RPC_RESPONSE_SCHEMA,
);

export function validateVectorOrThrow(value: unknown): asserts value is Vector {
  if (!validate(value)) {
    throw new Error(formatErrors(validate.errors ?? []));
  }
  validateFamilyMetadata(value);
}

export function validateKeyClaimSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateKeyClaim(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateKeyClaim.errors ?? [])}`);
  }
  const claim = value as { issued_at: number; not_before: number; expires_at?: number };
  if (claim.not_before < claim.issued_at) {
    throw new Error("claim-schema-invalid: not_before must be greater than or equal to issued_at");
  }
  if (claim.expires_at !== undefined && claim.expires_at <= claim.not_before) {
    throw new Error("claim-schema-invalid: expires_at must be greater than not_before");
  }
}

export function validateClaimRevocationSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateClaimRevocation(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateClaimRevocation.errors ?? [])}`);
  }
  const reasonCode = (value as { reason_code: string }).reason_code;
  if (!REGISTRY_REASON_CODES.includes(reasonCode)) {
    throw new Error(`claim-schema-invalid: reason_code is not registered: ${reasonCode}`);
  }
}

export function validateClaimLedgerRecordSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateClaimLedgerRecord(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateClaimLedgerRecord.errors ?? [])}`);
  }
}

export function validateOidcIssuanceRecordSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcIssuanceRecord(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcIssuanceRecord.errors ?? [])}`);
  }
}

export function validateOidcIssuerMetadataSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcIssuerMetadata(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcIssuerMetadata.errors ?? [])}`);
  }
}

export function validateOidcContinuityManifestSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcContinuityManifest(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcContinuityManifest.errors ?? [])}`);
  }
}

export function validateControlGrantSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlGrant);
}

export function validateControlEnrollmentRequestSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlEnrollmentRequest);
}

export function validateControlEnrollmentTokenSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlEnrollmentToken);
  const token = value as {
    issued_at: number;
    expires_at: number;
    grant: { tier: string };
  };
  if (token.expires_at <= token.issued_at) {
    throw new Error(
      "control-schema-invalid: expires_at must be greater than issued_at",
    );
  }
  if (token.grant.tier === "full") {
    throw new Error(
      "control-schema-invalid: an enrollment token cannot confer the full grant",
    );
  }
}

export function validateControlCapabilitySetSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlCapabilitySet);
  const names = (value as { tools: Array<{ name: string }> }).tools.map(
    ({ name }) => name,
  );
  if (new Set(names).size !== names.length) {
    throw new Error(
      "control-schema-invalid: capability tool names must be unique",
    );
  }
}

export function validateControlMcpFrameSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlMcpFrame);
}

export function validateControlRpcRequestSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRpcRequest);
}

export function validateControlRpcResponseSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRpcResponse);
}

function validateControlSchemaOrThrow(
  value: unknown,
  validator: {
    (data: unknown): boolean;
    errors?: ErrorObject[] | null;
  },
): void {
  try {
    jcsCanonicalize(value);
  } catch (error) {
    throw new Error(
      `control-schema-invalid: ${
        error instanceof Error ? error.message : "invalid JCS value"
      }`,
    );
  }
  if (!validator(value)) {
    throw new Error(
      `control-schema-invalid: ${formatErrors(validator.errors ?? [])}`,
    );
  }
}

function assertJcsInput(value: unknown): void {
  try {
    jcsCanonicalize(value);
  } catch (error) {
    throw new Error(`claim-schema-invalid: ${error instanceof Error ? error.message : "invalid JCS value"}`);
  }
}

function validateFamilyMetadata(vector: Vector): void {
  const exactDependencies: Record<DocumentId, Partial<Record<DocumentId, string>>> = {
    core: {},
    comms: { core: "core/0.5.0" },
    social: { core: "core/0.5.0", comms: "comms/0.5.0" },
    control: { core: "core/0.5.0", comms: "comms/0.5.0" },
  };
  const ownerVersion = parseQualifiedVersion(vector.owner_version);
  if (ownerVersion.document !== vector.owner_document || vector.owner_version !== `${vector.owner_document}/0.5.0`) {
    throw new Error("owner_version does not match owner_document");
  }
  const expected = exactDependencies[vector.owner_document];
  if (JSON.stringify(vector.dependency_versions) !== JSON.stringify(expected)) {
    throw new Error(`dependency_versions do not exactly match ${vector.owner_document}`);
  }
  const allowedRefs = new Set([vector.owner_document, ...Object.keys(expected)]);
  for (const ref of vector.spec_refs) {
    const match = /^heterodyne:(core|comms|control|social)\/0\.5\.0#[a-z0-9]+(?:-[a-z0-9]+)*$/.exec(ref);
    if (match === null || !allowedRefs.has(match[1])) {
      throw new Error(`spec_ref is outside the owner dependency closure: ${ref}`);
    }
  }
}

function formatErrors(errors: ErrorObject[]): string {
  return errors
    .map((error) => {
      const at = error.instancePath || "/";
      return `${at} ${error.message ?? "failed validation"}`;
    })
    .join("; ");
}
